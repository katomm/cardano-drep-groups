// The reference store of the incremental engine, in memory. Implements the Store contract
// plus driver hooks for raw input ingest, frontiers, completeness and the lease.
import { decodePayload } from '../payload.js';
import { afterTx, comparePos, endOf, minPos, type Pos, posOfCert } from '../position.js';
import type { GroupVersion, StoredInstance } from '../rules.js';
import { credKey, refKey } from '../state.js';
import type { ChainTx, Credential, DecodedEvent, EventRef, Hex, LedgerInput, NativeScript } from '../types.js';
import { classifyNewInput, mergeRecovery } from './classify.js';
import {
  type AttributedVerdict, type ChangeSet, type CredentialInput, type CursorUpdate, type Frontiers, type Keys,
  LeaseLostError, type QueuedEvent, type ReadyCredential, type Recovery, type RecoveryState, type Store,
  type StoredLabelTx, type TxContext, type View,
} from './types.js';

type ScriptRow = ChangeSet['scripts'][number];
type MemberScriptRow = ChangeSet['memberScripts'][number];
interface LabelTxRow { txHash: Hex; blockHeight: number; txIndex: number; marker: boolean; tx: ChainTx | null; bytes: number }
interface QueueRow { q: QueuedEvent; applied: boolean }
interface TxContextRow { txHash: Hex; blockHeight: number; txIndex: number; context: TxContext }
interface LeaseRow { owner: string; token: string; expiresAt: number; expired: boolean }

export interface EngineSnapshot {
  frontiers: Frontiers;
  recovery: RecoveryState;
  groups: GroupVersion[];                                 // current version per group, by creation
  versions: GroupVersion[];
  scripts: ScriptRow[];
  memberScripts: MemberScriptRow[];
  instances: StoredInstance[];
  verdicts: AttributedVerdict[];
  queue: Array<QueuedEvent & { applied: boolean }>;
  txContexts: Array<{ txHash: Hex; blockHeight: number; txIndex: number; context: TxContext }>;
  labelTxs: Array<{ txHash: Hex; blockHeight: number; txIndex: number; marker: boolean }>;
  ledger: LedgerInput[];
  appliedThrough: Array<{ credential: Credential; at: Pos }>;
  complete: Array<{ credential: Credential; complete: boolean }>; // explicit flags only
  stats: MemoryStore['stats'];
}

const posKey = (p: Pos): string => `${p.blockHeight},${p.txIndex},${p.phase},${p.index}`;
const versionKey = (v: GroupVersion): string => `${refKey(v.id)}@${posKey(v.at)}`;
const queueRef = (q: QueuedEvent): EventRef => ({ txHash: q.txHash, index: q.at.index });
const sameCred = (a: Credential, b: Credential): boolean => a.kind === b.kind && a.hash === b.hash;
const byPos = <T>(at: (x: T) => Pos, tie: (x: T) => string = () => '') => (a: T, b: T): number =>
  comparePos(at(a), at(b)) || (tie(a) < tie(b) ? -1 : tie(a) > tie(b) ? 1 : 0);
const byString = <T>(k: (x: T) => string) => (a: T, b: T): number => (k(a) < k(b) ? -1 : k(a) > k(b) ? 1 : 0);

// The marker rule: txs the library ignores, and txs without a readable event or
// script. A marker is kept by hash so a re-delivery is a duplicate, it never changes state.
function isMarker(tx: ChainTx): boolean {
  if (!tx.isValid || tx.payloadRepeated || tx.payload === undefined) return true;
  const d = decodePayload(tx.payload);
  return d === null || (d.scripts.length === 0 && !d.events.some((e) => e.ok));
}

// A bounded view: every answer was materialized at load time for the key it belongs to,
// a key that was not loaded is reported by `missing` and answered with nothing.
class MemoryView implements View {
  readonly loaded = new Set<string>();
  readonly scripts = new Map<string, NativeScript | null>();
  readonly groups = new Map<string, GroupVersion | null>();
  readonly dissolves = new Map<string, Pos | null>();
  readonly credentials = new Map<string, { registered: boolean; unregAfter: Pos | null; memberScript: NativeScript | null }>();
  readonly instances = new Map<string, StoredInstance | null>();
  readonly latest = new Map<string, StoredInstance | null>();

  scriptAt(hash: Hex, at: Pos): NativeScript | null {
    return this.scripts.get(`s:${hash}@${posKey(at)}`) ?? null;
  }
  groupAt(group: EventRef, at: Pos): GroupVersion | null {
    return this.groups.get(`g:${refKey(group)}@${posKey(at)}`) ?? null;
  }
  dissolvedAt(group: EventRef): Pos | null {
    return this.dissolves.get(refKey(group)) ?? null;
  }
  registeredAt(c: Credential, at: Pos): boolean {
    return this.credentials.get(`c:${credKey(c)}@${posKey(at)}`)?.registered ?? false;
  }
  memberScriptAt(c: Credential, at: Pos): NativeScript | null {
    return this.credentials.get(`c:${credKey(c)}@${posKey(at)}`)?.memberScript ?? null;
  }
  firstUnregAfter(c: Credential, at: Pos): Pos | null {
    return this.credentials.get(`c:${credKey(c)}@${posKey(at)}`)?.unregAfter ?? null;
  }
  instance(join: EventRef): StoredInstance | null {
    return this.instances.get(refKey(join)) ?? null;
  }
  latestInstance(group: EventRef, c: Credential): StoredInstance | null {
    return this.latest.get(`${refKey(group)}|${credKey(c)}`) ?? null;
  }
  missing(k: Keys): Keys {
    const out = (s: string): boolean => !this.loaded.has(s);
    return {
      instances: k.instances.filter((r) => out(`i:${refKey(r)}`)),
      latestInstances: k.latestInstances.filter(([g, c]) => out(`l:${refKey(g)}|${credKey(c)}`)),
      groupsAt: k.groupsAt.filter(([g, p]) => out(`g:${refKey(g)}@${posKey(p)}`)),
      scriptsAt: k.scriptsAt.filter(([h, p]) => out(`s:${h}@${posKey(p)}`)),
      credentialAt: k.credentialAt.filter(([c, p]) => out(`c:${credKey(c)}@${posKey(p)}`)),
    };
  }
}

export class MemoryStore implements Store {
  readonly stats: { calls: Record<string, number>; rowsReturned: Record<string, number> } = { calls: {}, rowsReturned: {} };

  private labelTxs = new Map<Hex, LabelTxRow>();
  private ledger = new Map<string, LedgerInput>();          // by txHash#certIndex
  private scripts = new Map<Hex, ScriptRow>();
  private memberScripts = new Map<string, MemberScriptRow>(); // by credential
  private versions = new Map<string, GroupVersion>();         // by (group, at)
  private instances = new Map<string, StoredInstance>();      // by join ref
  private verdicts = new Map<string, AttributedVerdict>();    // by event ref
  private queue = new Map<string, QueueRow>();                // by event ref
  private txContexts = new Map<Hex, TxContextRow>();
  private appliedThrough = new Map<string, { credential: Credential; at: Pos }>();
  private completeFlags = new Map<string, { credential: Credential; complete: boolean }>();
  private L = -1;
  private R: number | null = null;
  private G: Pos = endOf(-1);
  private recovery: RecoveryState = { first: null, then: null };
  private lease: LeaseRow | null = null;
  private leaseCounter = 0;

  private readonly isComplete: (c: Credential, s: MemoryStore) => boolean;
  private readonly now: () => number;
  private readonly leaseMs: number;

  constructor(opts: { isComplete?: (c: Credential, s: MemoryStore) => boolean; now?: () => number; leaseMs?: number } = {}) {
    this.isComplete = opts.isComplete ?? ((c) => this.completeFlags.get(credKey(c))?.complete ?? true);
    this.now = opts.now ?? (() => 0);
    this.leaseMs = opts.leaseMs ?? 60_000;
  }

  private count(method: string, rows: number): void {
    this.stats.calls[method] = (this.stats.calls[method] ?? 0) + 1;
    this.stats.rowsReturned[method] = (this.stats.rowsReturned[method] ?? 0) + rows;
  }

  // Lease. The same owner renews with a fresh token, another owner takes over only an
  // expired lease. Every write method checks the token before it writes anything.
  acquireLease(owner: string): string {
    const now = this.now();
    const cur = this.lease;
    if (cur && cur.owner !== owner && this.live(cur, now)) throw new Error(`lease held by ${cur.owner}`);
    const token = `${owner}#${++this.leaseCounter}`;
    this.lease = { owner, token, expiresAt: now + this.leaseMs, expired: false };
    return token;
  }

  expireLease(): void {
    if (this.lease) this.lease.expired = true;
  }

  private live(l: LeaseRow, now: number): boolean {
    return !l.expired && now < l.expiresAt;
  }

  private checkLease(token: string): void {
    const l = this.lease;
    if (!l || l.token !== token || !this.live(l, this.now())) throw new LeaseLostError('lease lost');
  }

  // Raw input ingest. A new row is classified against the applied progress and a late one
  // opens its recovery in the same write. A row already stored under its key is no input.
  ingestLabelTx(tx: ChainTx): 'stored' | 'duplicate' | 'marker' {
    if (this.labelTxs.has(tx.txHash)) return 'duplicate';
    const marker = isMarker(tx);
    this.labelTxs.set(tx.txHash, {
      txHash: tx.txHash, blockHeight: tx.blockHeight, txIndex: tx.txIndex, marker,
      tx: marker ? null : tx, bytes: marker ? 0 : (tx.payload?.length ?? 0),
    });
    if (marker) return 'marker'; // a marker cannot change state, so it opens no recovery
    this.classify(classifyNewInput({ kind: 'labelTx', at: afterTx(tx) }, { G: this.G, appliedThrough: null, L: this.L }));
    return 'stored';
  }

  ingestLedgerRow(input: LedgerInput): 'stored' | 'duplicate' {
    const key = `${input.txHash}#${input.certIndex}`;
    if (this.ledger.has(key)) return 'duplicate';
    this.ledger.set(key, { ...input });
    const applied = this.appliedThrough.get(credKey(input.credential))?.at ?? null;
    this.classify(classifyNewInput({ kind: 'ledger', at: posOfCert(input) }, { G: this.G, appliedThrough: applied, L: this.L }));
    return 'stored';
  }

  private classify(r: 'ordinary' | Recovery): void {
    if (r !== 'ordinary') this.recovery = mergeRecovery(this.recovery, r);
  }

  setFrontiers(f: { L?: number; R?: number | null }): void {
    if (f.L !== undefined) this.L = f.L;
    if (f.R !== undefined) this.R = f.R;
  }

  setComplete(c: Credential, complete: boolean): void {
    this.completeFlags.set(credKey(c), { credential: c, complete });
  }

  async load(keys: Keys, _overlay: ChangeSet[]): Promise<View> {
    // The overlay may only save loads, the view never merges it. This store loads every key.
    const v = new MemoryView();
    let rows = 0;
    const hit = <T>(x: T | null | undefined): T | null => {
      if (x !== null && x !== undefined) rows++;
      return x ?? null;
    };
    for (const r of keys.instances) {
      v.loaded.add(`i:${refKey(r)}`);
      v.instances.set(refKey(r), hit(this.instances.get(refKey(r))));
    }
    for (const [g, c] of keys.latestInstances) {
      v.loaded.add(`l:${refKey(g)}|${credKey(c)}`);
      let best: StoredInstance | null = null;
      for (const i of this.instances.values()) {
        if (refKey(i.group) !== refKey(g) || !sameCred(i.member, c)) continue;
        if (best === null || comparePos(i.joinedAt, best.joinedAt) > 0) best = i;
      }
      v.latest.set(`${refKey(g)}|${credKey(c)}`, hit(best));
    }
    for (const [g, p] of keys.groupsAt) {
      const k = `g:${refKey(g)}@${posKey(p)}`;
      v.loaded.add(k);
      let best: GroupVersion | null = null;
      let dissolve: Pos | null = null;
      for (const x of this.versions.values()) {
        if (refKey(x.id) !== refKey(g)) continue;
        if (x.status === 'dissolved') dissolve = x.at;
        if (comparePos(x.at, p) <= 0 && (best === null || comparePos(x.at, best.at) > 0)) best = x;
      }
      v.groups.set(k, hit(best));
      if (!v.dissolves.has(refKey(g))) v.dissolves.set(refKey(g), hit(dissolve));
    }
    for (const [h, p] of keys.scriptsAt) {
      const k = `s:${h}@${posKey(p)}`;
      v.loaded.add(k);
      const s = this.scripts.get(h);
      v.scripts.set(k, hit(s && comparePos(s.at, p) <= 0 ? s.script : null));
    }
    for (const [c, p] of keys.credentialAt) {
      const k = `c:${credKey(c)}@${posKey(p)}`;
      v.loaded.add(k);
      // Raw ledger rows, applied or not, so a unit sees the rows of its own batch.
      let last: LedgerInput | null = null;
      let unregAfter: Pos | null = null;
      for (const l of this.ledger.values()) {
        if (!sameCred(l.credential, c)) continue;
        const at = posOfCert(l);
        if (comparePos(at, p) <= 0) {
          if (last === null || comparePos(at, posOfCert(last)) > 0) last = l;
        } else if (l.kind === 'unreg' && (unregAfter === null || comparePos(at, unregAfter) < 0)) {
          unregAfter = at;
        }
      }
      const m = this.memberScripts.get(credKey(c));
      const memberScript = m && comparePos(m.at, p) <= 0 ? m.script : null;
      hit(last);
      hit(unregAfter);
      hit(memberScript);
      v.credentials.set(k, { registered: last?.kind === 'reg', unregAfter, memberScript });
    }
    this.count('load', rows);
    return v;
  }

  async commit(units: Array<{ change: ChangeSet; cursor: CursorUpdate }>, lease: string): Promise<void> {
    this.count('commit', 0);
    this.checkLease(lease);
    // Validate before any write, so a failing batch leaves nothing behind.
    for (const u of units) {
      for (const t of u.change.txContexts) {
        if (!this.labelTxs.has(t.txHash)) throw new Error(`tx context for a tx that is not stored: ${t.txHash}`);
      }
    }
    for (const { change, cursor } of units) {
      for (const s of change.scripts) if (!this.scripts.has(s.hash)) this.scripts.set(s.hash, s);
      for (const m of change.memberScripts) {
        if (!this.memberScripts.has(credKey(m.credential))) this.memberScripts.set(credKey(m.credential), m);
      }
      for (const v of change.versions) this.versions.set(versionKey(v), v);
      for (const i of change.instances) this.instances.set(refKey(i.joinId), i);
      for (const v of change.verdicts) this.verdicts.set(refKey(v.ref), v);
      for (const q of change.queued) {
        const k = refKey(queueRef(q));
        if (!this.queue.has(k)) this.queue.set(k, { q, applied: false });
      }
      for (const r of change.appliedQueue) {
        const row = this.queue.get(refKey(r));
        if (row) row.applied = true;
      }
      for (const t of change.txContexts) {
        const tx = this.labelTxs.get(t.txHash) as LabelTxRow;
        this.txContexts.set(t.txHash, { txHash: t.txHash, blockHeight: tx.blockHeight, txIndex: tx.txIndex, context: t.context });
      }
      if (cursor.kind === 'group') this.G = cursor.G;
      else this.appliedThrough.set(credKey(cursor.credential), { credential: cursor.credential, at: cursor.appliedThrough });
    }
  }

  async nextLabelTxs(after: Pos, L: number, maxTxs: number, maxBytes: number): Promise<{ txs: StoredLabelTx[]; done: boolean }> {
    const all = [...this.labelTxs.values()]
      .filter((t) => !t.marker && t.blockHeight <= L && comparePos(afterTx(t), after) > 0)
      .sort((a, b) => a.blockHeight - b.blockHeight || a.txIndex - b.txIndex);
    const txs: StoredLabelTx[] = [];
    let bytes = 0;
    for (const t of all) {
      if (txs.length >= maxTxs) break;
      if (txs.length > 0 && bytes + t.bytes > maxBytes) break;
      txs.push({ tx: t.tx as ChainTx, bytes: t.bytes });
      bytes += t.bytes;
    }
    this.count('nextLabelTxs', txs.length);
    return { txs, done: txs.length === all.length };
  }

  async queuedJoins(refs: EventRef[], overlay: ChangeSet[]): Promise<Map<string, DecodedEvent | 'ignored'>> {
    const out = new Map<string, DecodedEvent | 'ignored'>();
    for (const r of refs) {
      const k = refKey(r);
      const inOverlay = overlay.flatMap((o) => o.queued).find((q) => q.txHash === r.txHash && q.at.index === r.index);
      const stored = this.queue.get(k);
      if (inOverlay) out.set(k, inOverlay.event);
      else if (stored) out.set(k, stored.q.event);
      else if (this.labelTxs.get(r.txHash)?.marker) out.set(k, 'ignored');
    }
    this.count('queuedJoins', out.size);
    return out;
  }

  // Complete credentials with unapplied inputs at or below min(G, END(R)), oldest first.
  // Inputs are paged strictly after applied-through, within maxUnits and maxInputs in total.
  async readyCredentials(maxUnits: number, maxInputs: number, upTo: { G: Pos; R: number | null }): Promise<ReadyCredential[]> {
    const bound = upTo.R === null ? upTo.G : minPos(upTo.G, endOf(upTo.R));
    const byCred = new Map<string, { c: Credential; inputs: CredentialInput[] }>();
    const add = (c: Credential, x: CredentialInput): void => {
      const k = credKey(c);
      const at = x.kind === 'ledger' ? x.at : x.q.at;
      const applied = this.appliedThrough.get(k)?.at;
      if (comparePos(at, bound) > 0 || (applied && comparePos(at, applied) <= 0)) return;
      const entry = byCred.get(k) ?? { c, inputs: [] };
      entry.inputs.push(x);
      byCred.set(k, entry);
    };
    for (const { q, applied } of this.queue.values()) {
      if (applied) continue;
      const ctx = this.txContexts.get(q.txHash);
      if (!ctx) throw new Error(`queue entry without a tx context: ${q.txHash}`);
      add(q.subject, { kind: 'event', q, tx: ctx.context });
    }
    for (const l of this.ledger.values()) add(l.credential, { kind: 'ledger', at: posOfCert(l), input: l });

    const posOf = (x: CredentialInput): Pos => (x.kind === 'ledger' ? x.at : x.q.at);
    const ready = [...byCred.values()]
      .filter((e) => this.isComplete(e.c, this))
      .map((e) => ({ c: e.c, inputs: e.inputs.sort((a, b) => comparePos(posOf(a), posOf(b))) }))
      .sort(byPos((e) => posOf(e.inputs[0] as CredentialInput), (e) => credKey(e.c)));
    const out: ReadyCredential[] = [];
    let left = maxInputs;
    for (const e of ready) {
      if (out.length >= maxUnits || left <= 0) break;
      const inputs = e.inputs.slice(0, left);
      left -= inputs.length;
      out.push({ c: e.c, inputs, more: inputs.length < e.inputs.length });
    }
    this.count('readyCredentials', out.reduce((n, r) => n + r.inputs.length, 0));
    return out;
  }

  async frontiers(): Promise<Frontiers> {
    this.count('frontiers', 1);
    return { L: this.L, R: this.R, G: this.G };
  }

  async pendingRecovery(): Promise<Recovery | null> {
    this.count('pendingRecovery', this.recovery.first ? 1 : 0);
    return this.recovery.first;
  }

  async openRecovery(r: Recovery, lease: string): Promise<void> {
    this.checkLease(lease);
    this.recovery = mergeRecovery(this.recovery, r);
  }

  async finishRecovery(lease: string): Promise<void> {
    this.checkLease(lease);
    this.recovery = { first: this.recovery.then, then: null };
  }

  // Runs up to `budget` row operations (at least one) and lowers the frontiers in the step
  // that finishes. The work list is derived from what remains, so a step interrupted
  // anywhere is resumed by the next call with the same `above`.
  async truncateStep(above: number, budget: number, lease: string): Promise<'more' | 'done'> {
    this.checkLease(lease);
    const ops = this.truncateOps(above);
    if (!this.run(ops, budget)) return 'more';
    this.G = minPos(this.G, endOf(above));
    this.L = Math.min(this.L, above);
    if (this.R !== null) this.R = Math.min(this.R, above);
    return 'done';
  }

  // Rebuild resets the state tables and G, keeping raw inputs, L, R and completeness.
  // Fork deletes everything and resets every cursor.
  async resetStep(mode: 'rebuild' | 'fork', budget: number, lease: string): Promise<'more' | 'done'> {
    this.checkLease(lease);
    const tables: Array<Map<string, unknown>> = [
      this.scripts, this.memberScripts, this.versions, this.instances, this.verdicts, this.queue, this.txContexts, this.appliedThrough,
    ];
    if (mode === 'fork') tables.push(this.labelTxs, this.ledger, this.completeFlags);
    const ops = tables.flatMap((t) => [...t.keys()].map((k) => () => t.delete(k)));
    if (!this.run(ops, budget)) return 'more';
    this.G = endOf(-1);
    if (mode === 'fork') {
      this.L = -1;
      this.R = null;
    }
    return 'done';
  }

  // Runs the first `budget` operations, true when none is left.
  private run(ops: Array<() => void>, budget: number): boolean {
    const n = Math.max(1, budget);
    for (const op of ops.slice(0, n)) op();
    return ops.length <= n;
  }

  // Order: raw inputs, versions, scripts, member scripts, instances joined above,
  // approvals and explicit closes above, verdicts, queue entries, tx contexts, cursors.
  // A group's current version is derived from its remaining versions, so deleting the
  // versions above h resets it, or removes the group when its create is above h.
  private truncateOps(h: number): Array<() => void> {
    const ops: Array<() => void> = [];
    const del = <K, V>(m: Map<K, V>, cut: (v: V) => boolean): void => {
      for (const [k, v] of m) if (cut(v)) ops.push(() => m.delete(k));
    };
    const over = (p: Pos): boolean => p.blockHeight > h;
    del(this.labelTxs, (t) => t.blockHeight > h);
    del(this.ledger, (l) => l.blockHeight > h);
    del(this.versions, (v) => over(v.at));
    del(this.scripts, (s) => over(s.at));
    del(this.memberScripts, (m) => over(m.at));
    del(this.instances, (i) => over(i.joinedAt));
    for (const [k, i] of this.instances) {
      if (over(i.joinedAt)) continue;
      const update = (f: (x: StoredInstance) => StoredInstance): void => {
        ops.push(() => {
          const cur = this.instances.get(k);
          if (cur) this.instances.set(k, f(cur));
        });
      };
      if (i.approvedAt && over(i.approvedAt)) update((x) => ({ ...x, approvedAt: null }));
      if (i.closedAt && over(i.closedAt)) update((x) => ({ ...x, closedAt: null, closeReason: null }));
    }
    del(this.verdicts, (v) => over(v.at));
    del(this.queue, (q) => over(q.q.at));
    del(this.txContexts, (t) => t.blockHeight > h);
    for (const [k, a] of this.appliedThrough) {
      if (over(a.at)) ops.push(() => this.appliedThrough.set(k, { credential: a.credential, at: endOf(h) }));
    }
    return ops;
  }

  snapshot(): EngineSnapshot {
    const current = new Map<string, GroupVersion>();
    for (const v of this.versions.values()) {
      const cur = current.get(refKey(v.id));
      if (!cur || comparePos(v.at, cur.at) > 0) current.set(refKey(v.id), v);
    }
    const snap: EngineSnapshot = {
      frontiers: { L: this.L, R: this.R, G: this.G },
      recovery: this.recovery,
      groups: [...current.values()].sort(byPos((g) => g.createdAt, (g) => refKey(g.id))),
      versions: [...this.versions.values()].sort(byPos((v) => v.at, (v) => refKey(v.id))),
      scripts: [...this.scripts.values()].sort(byPos((s) => s.at, (s) => s.hash)),
      memberScripts: [...this.memberScripts.values()].sort(byPos((m) => m.at, (m) => credKey(m.credential))),
      instances: [...this.instances.values()].sort(byPos((i) => i.joinedAt, (i) => refKey(i.joinId))),
      verdicts: [...this.verdicts.values()].sort(byPos((v) => v.at, (v) => refKey(v.ref))),
      queue: [...this.queue.values()].map((r) => ({ ...r.q, applied: r.applied })).sort(byPos((q) => q.at, (q) => q.txHash)),
      txContexts: [...this.txContexts.values()].sort((a, b) => a.blockHeight - b.blockHeight || a.txIndex - b.txIndex),
      labelTxs: [...this.labelTxs.values()]
        .map(({ txHash, blockHeight, txIndex, marker }) => ({ txHash, blockHeight, txIndex, marker }))
        .sort((a, b) => a.blockHeight - b.blockHeight || a.txIndex - b.txIndex || (a.txHash < b.txHash ? -1 : 1)),
      ledger: [...this.ledger.values()].sort(byPos(posOfCert, (l) => l.txHash)),
      appliedThrough: [...this.appliedThrough.values()].sort(byString((a) => credKey(a.credential))),
      complete: [...this.completeFlags.values()].sort(byString((a) => credKey(a.credential))),
      stats: this.stats,
    };
    return structuredClone(snap);
  }
}
