// The schedule driver of the differential test: feeds a store through its ingest hooks,
// runs the engine as the schedule says and compares the result with replay. It is the
// contract test for any Store, mismatches throw ConformanceError with a readable diff.
import { effectiveClose } from '../effective.js';
import type { EngineSnapshot } from '../engine/memoryStore.js';
import { runEngine } from '../engine/run.js';
import { type Budget, LeaseLostError, type RunReport, type Store } from '../engine/types.js';
import { bytesToHex } from '../hex.js';
import { comparePos, endOf, minPos, type Pos, posOfCert } from '../position.js';
import type { StoredInstance } from '../rules.js';
import { credKey, refKey, replay } from '../state.js';
import type {
  ChainInput, ChainTx, Credential, EventVerdict, GroupState, Hex, Instance, LedgerInput, RegistryState,
} from '../types.js';
import { BIG_BUDGET, heightOf, inputKey, type ScheduleStep } from './generate.js';

export interface DriverStore extends Store {
  acquireLease(owner: string): string | Promise<string>;
  ingestLabelTx(tx: ChainTx): Promise<'stored' | 'duplicate' | 'marker'> | 'stored' | 'duplicate' | 'marker';
  ingestLedgerRow(input: LedgerInput): Promise<'stored' | 'duplicate'> | 'stored' | 'duplicate';
  setFrontiers(f: { L?: number; R?: number | null }): void | Promise<void>;
  setComplete(c: Credential, complete: boolean): void | Promise<void>;
  snapshot(): EngineSnapshot | Promise<EngineSnapshot>;
  expireLease(): void | Promise<void>; // makes the current lease stale, the next write must throw LeaseLostError
}

export class ConformanceError extends Error {
  override name = 'ConformanceError';
}

// What a page shows: groups, instances with their effective state, verdicts with a group
// and the published script hashes.
export interface DisplayProjection {
  groups: GroupState[];
  instances: Instance[];
  verdicts: EventVerdict[];
  scripts: Hex[];
}

export interface Coverage {
  reasons: Record<string, number>;   // rule results by reason, before the group filter
  closes: Record<string, number>;    // effective closes of the final state, ties included
  results: number;
  valid: number;
  validShare: number;
  schedules: number;
  schedulesWithGBehindL: number;
  completedAfterRollback: number;
  rebuildsMidway: number;
  truncations: number;
  rebuilds: number;
  forks: number;
  cutChecks: number;                 // equality with replay over a cut chain, checked
  leaseLosses: number;
  runs: number;
}

export interface ScheduleResult { final: EngineSnapshot; coverage: Coverage; checkpoints: Array<{ label: string; snapshot: EngineSnapshot }> }

export function emptyCoverage(): Coverage {
  return {
    reasons: {}, closes: {}, results: 0, valid: 0, validShare: 0, schedules: 0, schedulesWithGBehindL: 0, completedAfterRollback: 0,
    rebuildsMidway: 0, truncations: 0, rebuilds: 0, forks: 0, cutChecks: 0, leaseLosses: 0, runs: 0,
  };
}

// Adds `from` to `into` and returns `into`. The valid share is derived from the sums.
export function mergeCoverage(into: Coverage, from: Coverage): Coverage {
  for (const [k, n] of Object.entries(from.reasons)) into.reasons[k] = (into.reasons[k] ?? 0) + n;
  for (const [k, n] of Object.entries(from.closes)) into.closes[k] = (into.closes[k] ?? 0) + n;
  const sums = [
    'results', 'valid', 'schedules', 'schedulesWithGBehindL', 'completedAfterRollback', 'rebuildsMidway', 'truncations',
    'rebuilds', 'forks', 'cutChecks', 'leaseLosses', 'runs',
  ] as const;
  for (const k of sums) into[k] += from[k];
  into.validShare = into.results === 0 ? 0 : into.valid / into.results;
  return into;
}

// Canonical JSON: sorted object keys, bigints and bytes as strings, so equal values
// compare equal whatever their property order.
function canon(v: unknown): string {
  return JSON.stringify(v, (_k, x: unknown) => {
    if (typeof x === 'bigint') return `${x}n`;
    if (x instanceof Uint8Array) return bytesToHex(x);
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      const o = x as Record<string, unknown>;
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));
    }
    return x;
  });
}

const byPos = <T>(at: (x: T) => Pos, id: (x: T) => string) => (a: T, b: T): number =>
  comparePos(at(a), at(b)) || (id(a) < id(b) ? -1 : id(a) > id(b) ? 1 : 0);

const groupOf = (g: GroupState): GroupState => ({
  id: g.id, mode: g.mode, control: g.control, admission: g.admission, profile: g.profile,
  seq: g.seq, status: g.status, createdAt: g.createdAt, profileSetAt: g.profileSetAt,
});

export function replayProjection(s: RegistryState): DisplayProjection {
  return {
    groups: s.groups.map(groupOf).sort(byPos((g) => g.createdAt, (g) => refKey(g.id))),
    instances: [...s.instances].sort(byPos((i) => i.joinedAt, (i) => refKey(i.joinId))),
    verdicts: s.verdicts.filter((v) => v.group !== null).sort(byPos((v) => v.at, (v) => refKey(v.ref))),
    scripts: [...s.scripts.keys()].sort(),
  };
}

// The effective close of every stored instance: its explicit close, the stored dissolve
// of its group after the join and the first applied unreg of its member after the join.
function closesOf(s: EngineSnapshot): Map<string, ReturnType<typeof effectiveClose>> {
  const dissolves = new Map<string, Pos>();
  for (const v of s.versions) if (v.status === 'dissolved') dissolves.set(refKey(v.id), v.at);
  const applied = new Map(s.appliedThrough.map((a) => [credKey(a.credential), a.at] as const));
  const unregs = new Map<string, Pos[]>();
  for (const l of s.ledger) {
    if (l.kind !== 'unreg') continue;
    const k = credKey(l.credential);
    const through = applied.get(k);
    const at = posOfCert(l);
    if (!through || comparePos(at, through) > 0) continue;
    unregs.set(k, [...(unregs.get(k) ?? []), at]);
  }
  const out = new Map<string, ReturnType<typeof effectiveClose>>();
  for (const i of s.instances) {
    const firstUnreg = (unregs.get(credKey(i.member)) ?? []).filter((p) => comparePos(p, i.joinedAt) > 0).sort(comparePos)[0] ?? null;
    out.set(refKey(i.joinId), effectiveClose(i, dissolves.get(refKey(i.group)) ?? null, firstUnreg));
  }
  return out;
}

export function engineProjection(s: EngineSnapshot): DisplayProjection {
  const closes = closesOf(s);
  const instances: Instance[] = s.instances.map((i) => {
    const close = closes.get(refKey(i.joinId)) ?? null;
    return {
      joinId: i.joinId, group: i.group, member: i.member,
      state: close ? 'closed' : i.mode === 'open' || i.approvedAt !== null ? 'active' : 'pending',
      reason: close ? close.reason : null,
      joinedAt: i.joinedAt, approvedAt: i.approvedAt, closedAt: close ? close.at : null,
    };
  });
  return {
    groups: s.groups.map(groupOf).sort(byPos((g) => g.createdAt, (g) => refKey(g.id))),
    instances: instances.sort(byPos((i) => i.joinedAt, (i) => refKey(i.joinId))),
    verdicts: [...s.verdicts].sort(byPos((v) => v.at, (v) => refKey(v.ref))),
    scripts: s.scripts.map((x) => x.hash).sort(),
  };
}

// Differences of two keyed lists, at most `limit` lines.
function diffKeyed<T>(name: string, a: T[], b: T[], key: (x: T) => string, limit: number): string[] {
  const left = new Map(a.map((x) => [key(x), canon(x)] as const));
  const right = new Map(b.map((x) => [key(x), canon(x)] as const));
  const out: string[] = [];
  for (const [k, v] of left) {
    if (out.length >= limit) break;
    const w = right.get(k);
    if (w === undefined) out.push(`${name} ${k}: only in engine ${v}`);
    else if (w !== v) out.push(`${name} ${k}:\n    engine    ${v}\n    reference ${w}`);
  }
  for (const [k, w] of right) {
    if (out.length >= limit) break;
    if (!left.has(k)) out.push(`${name} ${k}: only in reference ${w}`);
  }
  return out;
}

export function assertEquivalent(engine: DisplayProjection, reference: DisplayProjection): void {
  const lines = [
    ...diffKeyed('group', engine.groups, reference.groups, (g) => refKey(g.id), 10),
    ...diffKeyed('instance', engine.instances, reference.instances, (i) => refKey(i.joinId), 10),
    ...diffKeyed('verdict', engine.verdicts, reference.verdicts, (v) => refKey(v.ref), 10),
    ...diffKeyed('script', engine.scripts, reference.scripts, (h) => h, 10),
  ];
  if (lines.length > 0) throw new ConformanceError(`engine differs from replay:\n  ${lines.join('\n  ')}`);
}

// The state tables of a snapshot, without raw inputs, frontiers and stats.
function stateTables(s: EngineSnapshot) {
  return {
    versions: s.versions, scripts: s.scripts, memberScripts: s.memberScripts, instances: s.instances,
    verdicts: s.verdicts, queue: s.queue, txContexts: s.txContexts, appliedThrough: s.appliedThrough,
  };
}

// The state before a truncation above h, cut back the way the truncation must leave it.
function cutBack(s: EngineSnapshot, h: number): ReturnType<typeof stateTables> {
  const ok = (p: Pos): boolean => p.blockHeight <= h;
  const t = stateTables(s);
  return {
    versions: t.versions.filter((v) => ok(v.at)),
    scripts: t.scripts.filter((x) => ok(x.at)),
    memberScripts: t.memberScripts.filter((x) => ok(x.at)),
    instances: t.instances.filter((i) => ok(i.joinedAt)).map((i): StoredInstance => ({
      ...i,
      approvedAt: i.approvedAt && ok(i.approvedAt) ? i.approvedAt : null,
      ...(i.closedAt && !ok(i.closedAt) ? { closedAt: null, closeReason: null } : {}),
    })),
    verdicts: t.verdicts.filter((v) => ok(v.at)),
    queue: t.queue.filter((q) => ok(q.at)),
    txContexts: t.txContexts.filter((x) => x.blockHeight <= h),
    appliedThrough: t.appliedThrough.map((a) => (ok(a.at) ? a : { ...a, at: endOf(h) })),
  };
}

// Queue entries are applied exactly up to the applied-through position of their subject,
// every entry has its tx context and its stored label tx, and no credential is applied
// beyond its bound.
function checkQueue(s: EngineSnapshot): void {
  const applied = new Map(s.appliedThrough.map((a) => [credKey(a.credential), a.at] as const));
  const contexts = new Set(s.txContexts.map((t) => t.txHash));
  const stored = new Set(s.labelTxs.filter((t) => !t.marker).map((t) => t.txHash));
  for (const q of s.queue) {
    const id = `${q.txHash}#${q.at.index}`;
    if (!contexts.has(q.txHash)) throw new ConformanceError(`queue entry ${id} has no tx context`);
    if (!stored.has(q.txHash)) throw new ConformanceError(`queue entry ${id} has no stored label tx`);
    const through = applied.get(credKey(q.subject));
    const below = through !== undefined && comparePos(q.at, through) <= 0;
    if (below !== q.applied) throw new ConformanceError(`queue entry ${id} applied ${q.applied} against applied-through ${canon(through)}`);
  }
  // Credential units never pass min(G, END(R)).
  const { G, R } = s.frontiers;
  const bound = R === null ? G : minPos(G, endOf(R));
  for (const a of s.appliedThrough) {
    if (comparePos(a.at, bound) > 0) throw new ConformanceError(`applied-through of ${credKey(a.credential)} above min(G, END(R))`);
  }
}

// Fields once set change only through a truncation or a reset: verdicts stay, an instance
// keeps its join fields and a set approval or close.
function checkMonotone(before: EngineSnapshot, after: EngineSnapshot): void {
  const verdicts = new Map(after.verdicts.map((v) => [refKey(v.ref), canon(v)] as const));
  for (const v of before.verdicts) {
    if (verdicts.get(refKey(v.ref)) !== canon(v)) throw new ConformanceError(`applied verdict ${refKey(v.ref)} changed without a truncation`);
  }
  const instances = new Map(after.instances.map((i) => [refKey(i.joinId), i] as const));
  for (const i of before.instances) {
    const j = instances.get(refKey(i.joinId));
    const same = j !== undefined && canon({ ...i, approvedAt: null, closedAt: null, closeReason: null })
      === canon({ ...j, approvedAt: null, closedAt: null, closeReason: null })
      && (i.approvedAt === null || canon(i.approvedAt) === canon(j.approvedAt))
      && (i.closedAt === null || (canon(i.closedAt) === canon(j.closedAt) && i.closeReason === j.closeReason));
    if (!same) throw new ConformanceError(`instance ${refKey(i.joinId)} changed without a truncation`);
  }
}

const sameState = (a: unknown, b: unknown): boolean => canon(a) === canon(b);

class Driver {
  private lease = '';
  private readonly owner = 'conformance';
  private readonly ref = new Map<string, ChainInput>();
  private target: { L: number; R: number | null } = { L: -1, R: null };
  private readonly flags = new Map<string, { c: Credential; complete: boolean }>();
  private budget: Budget = BIG_BUDGET;
  private baseline: EngineSnapshot | null = null;
  private episode: { before: EngineSnapshot; kinds: Set<string>; above: number | null } | null = null;
  private rolledBack = false;
  private gBehind = false;
  readonly cov = emptyCoverage();
  readonly checkpoints: ScheduleResult['checkpoints'] = [];

  constructor(private readonly store: DriverStore) {}

  async start(): Promise<void> {
    this.lease = await this.store.acquireLease(this.owner);
    this.baseline = await this.store.snapshot();
  }

  private async renew(): Promise<void> {
    this.cov.leaseLosses++;
    this.lease = await this.store.acquireLease(this.owner);
  }

  private async open(r: Parameters<Store['openRecovery']>[0]): Promise<void> {
    try {
      await this.store.openRecovery(r, this.lease);
    } catch (e) {
      if (!(e instanceof LeaseLostError)) throw e;
      await this.renew();
      await this.store.openRecovery(r, this.lease);
    }
  }

  async ingest(inputs: readonly ChainInput[], reference = true): Promise<void> {
    for (const x of inputs) {
      const before = canon(await this.store.pendingRecovery());
      const r = x.kind === 'tx' ? await this.store.ingestLabelTx(x.tx) : await this.store.ingestLedgerRow(x.input);
      // A row already stored under its key is no input and opens nothing.
      if (r === 'duplicate' && canon(await this.store.pendingRecovery()) !== before) {
        throw new ConformanceError(`a duplicate ${inputKey(x)} opened a recovery`);
      }
      if (reference) this.ref.set(inputKey(x), x);
    }
  }

  // The readers deliver everything again, the way they re-read after a cursor reset.
  private async redeliver(): Promise<void> {
    const all = [...this.ref.values()].sort((a, b) => heightOf(a) - heightOf(b));
    await this.ingest(all, false);
  }

  setFrontiers(f: { L?: number; R?: number | null }): Promise<void> | void {
    if (f.L !== undefined) this.target.L = f.L;
    if (f.R !== undefined) this.target.R = f.R;
    return this.store.setFrontiers(f);
  }

  async setComplete(c: Credential, complete: boolean): Promise<void> {
    this.flags.set(credKey(c), { c, complete });
    if (complete && this.rolledBack) this.cov.completedAfterRollback++;
    await this.store.setComplete(c, complete);
  }

  private observe = (r: { valid: boolean; reason: string | null }): void => {
    this.cov.results++;
    if (r.valid) this.cov.valid++;
    if (r.reason !== null) this.cov.reasons[r.reason] = (this.cov.reasons[r.reason] ?? 0) + 1;
  };

  // One run. A lost lease ends the run, the driver takes a new lease for the next one.
  async run(budget: Budget, maxCommits?: number): Promise<RunReport | null> {
    this.cov.runs++;
    if (this.episode === null && (await this.store.pendingRecovery()) !== null) {
      this.episode = { before: await this.store.snapshot(), kinds: new Set(), above: null };
    }
    let report: RunReport | null = null;
    try {
      report = await runEngine(this.store, budget, this.lease, { observe: this.observe, maxCommits });
    } catch (e) {
      if (!(e instanceof LeaseLostError)) throw e;
      await this.renew();
    }
    if (report?.recovery && this.episode) {
      this.episode.kinds.add(report.recovery.kind);
      if (report.recovery.kind === 'truncate') this.episode.above = report.recovery.above;
    }
    const snap = await this.store.snapshot();
    if (this.episode && (await this.store.pendingRecovery()) === null) {
      await this.endEpisode(snap);
      this.baseline = await this.store.snapshot();
      return report;
    }
    if (this.episode === null) {
      if (this.baseline) checkMonotone(this.baseline, snap);
      checkQueue(snap);
    }
    if (report?.phase === 'normal' && comparePos(snap.frontiers.G, endOf(snap.frontiers.L)) < 0) this.gBehind = true;
    this.baseline = snap;
    return report;
  }

  // A finished recovery: the cut state is checked, the readers deliver again and the
  // frontiers return to where the readers had them.
  private async endEpisode(snap: EngineSnapshot): Promise<void> {
    const ep = this.episode as NonNullable<Driver['episode']>;
    this.episode = null;
    const empty = { versions: [], scripts: [], memberScripts: [], instances: [], verdicts: [], queue: [], txContexts: [], appliedThrough: [] };
    if (ep.kinds.has('fork')) {
      this.cov.forks++;
      if (!sameState(stateTables(snap), empty) || snap.labelTxs.length + snap.ledger.length > 0) {
        throw new ConformanceError('state or raw inputs left after a fork recovery');
      }
      if (!sameState(snap.frontiers, { L: -1, R: null, G: endOf(-1) })) throw new ConformanceError(`frontiers after a fork: ${canon(snap.frontiers)}`);
      for (const { c, complete } of this.flags.values()) await this.store.setComplete(c, complete);
    } else if (ep.kinds.has('rebuild')) {
      this.cov.rebuilds++;
      if (!sameState(stateTables(snap), empty)) throw new ConformanceError('state left after a rebuild');
      if (!sameState(snap.frontiers.G, endOf(-1))) throw new ConformanceError(`G after a rebuild: ${canon(snap.frontiers.G)}`);
    } else if (ep.above !== null) {
      this.cov.truncations++;
      const h = ep.above;
      const want = cutBack(ep.before, h);
      const got = stateTables(snap);
      for (const k of Object.keys(want) as Array<keyof typeof want>) {
        if (!sameState(got[k], want[k])) {
          throw new ConformanceError(`truncation above ${h} left ${k}:\n    got  ${canon(got[k])}\n    want ${canon(want[k])}`);
        }
      }
      const raw = [...snap.labelTxs.map((t) => t.blockHeight), ...snap.ledger.map((l) => l.blockHeight)];
      if (raw.some((x) => x > h)) throw new ConformanceError(`raw inputs above ${h} left after the truncation`);
      const f = snap.frontiers;
      if (f.L > h || (f.R !== null && f.R > h) || comparePos(f.G, minPos(ep.before.frontiers.G, endOf(h))) !== 0) {
        throw new ConformanceError(`frontiers after a truncation above ${h}: ${canon(f)}`);
      }
    }
    checkQueue(snap);
    await this.redeliver();
    await this.store.setFrontiers(this.target);
  }

  // Runs until no recovery is open and a normal run reports no more work.
  async settle(budget: Budget): Promise<void> {
    for (let i = 0; i < 20_000; i++) {
      const pending = await this.store.pendingRecovery();
      const r = await this.run(budget);
      if (pending === null && r?.phase === 'normal' && !r.more && (await this.store.pendingRecovery()) === null) return;
    }
    throw new ConformanceError('the engine did not settle');
  }

  private async settleRecovery(): Promise<void> {
    for (let i = 0; i < 20_000; i++) {
      if ((await this.store.pendingRecovery()) === null && this.episode === null) return;
      await this.run(this.budget);
    }
    throw new ConformanceError('the recovery did not finish');
  }

  private allComplete(): boolean {
    return [...this.flags.values()].every((f) => f.complete);
  }

  private async compare(): Promise<EngineSnapshot> {
    const snap = await this.store.snapshot();
    checkQueue(snap);
    assertEquivalent(engineProjection(snap), replayProjection(replay([...this.ref.values()])));
    return snap;
  }

  async step(s: ScheduleStep): Promise<void> {
    switch (s.kind) {
      case 'deliver':
        return this.ingest(s.inputs);
      case 'frontiers':
        return this.setFrontiers(s);
      case 'complete':
        return this.setComplete(s.c, s.complete);
      case 'run':
        this.budget = s.budget;
        await this.run(s.budget);
        return;
      case 'interrupt':
        await this.run(this.budget, s.afterCommits);
        return;
      case 'expireLease': {
        await this.store.expireLease();
        // The contract: the next write with the stale token throws. An empty commit writes nothing.
        let lost = false;
        try {
          await this.store.commit([], this.lease);
        } catch (e) {
          if (!(e instanceof LeaseLostError)) throw e;
          lost = true;
        }
        if (!lost) throw new ConformanceError('a write after expireLease did not throw LeaseLostError');
        return;
      }
      case 'check': {
        const snapshot = await this.store.snapshot();
        // Between two recovery steps a snapshot may mix rows before and after the cut.
        if (this.episode === null && (await this.store.pendingRecovery()) === null) checkQueue(snapshot);
        this.checkpoints.push({ label: s.label, snapshot });
        return;
      }
      case 'rebuild': {
        const snap = await this.store.snapshot();
        const behind = comparePos(snap.frontiers.G, endOf(snap.frontiers.L)) < 0 || snap.queue.some((q) => !q.applied);
        if (comparePos(snap.frontiers.G, endOf(-1)) > 0 && behind) this.cov.rebuildsMidway++;
        return this.open({ kind: 'rebuild' });
      }
      case 'fork':
        await this.open({ kind: 'fork' });
        this.ref.clear();
        this.flags.clear();
        this.target = { L: -1, R: null };
        return;
      case 'rollback': {
        for (const [k, x] of this.ref) if (heightOf(x) > s.to) this.ref.delete(k);
        this.target = { L: Math.min(this.target.L, s.to), R: this.target.R === null ? null : Math.min(this.target.R, s.to) };
        await this.open({ kind: 'truncate', above: s.to });
        await this.settleRecovery();
        // Everything up to the cut applied without a new suffix equals replay over the cut chain.
        if (this.allComplete()) {
          await this.setFrontiers({ L: Math.max(this.target.L, s.to), R: Math.max(this.target.R ?? -1, s.to) });
          await this.settle(BIG_BUDGET);
          await this.compare();
          this.cov.cutChecks++;
        }
        this.rolledBack = true;
        return this.ingest(s.suffix);
      }
    }
  }

  // The end: every credential complete, the frontiers at the tip, settled, compared.
  async finish(chain: readonly ChainInput[]): Promise<EngineSnapshot> {
    const creds = new Map<string, Credential>();
    for (const x of [...chain, ...this.ref.values()]) {
      if (x.kind === 'ledger') creds.set(credKey(x.input.credential), x.input.credential);
    }
    for (const f of this.flags.values()) if (!f.complete) creds.set(credKey(f.c), f.c);
    // The final completion is the driver's own, it does not count as a late completion.
    for (const c of creds.values()) {
      if (this.flags.get(credKey(c))?.complete === false) {
        this.flags.set(credKey(c), { c, complete: true });
        await this.store.setComplete(c, true);
      }
    }
    await this.redeliver();
    const tip = [...this.ref.values()].reduce((h, x) => Math.max(h, heightOf(x)), Math.max(this.target.L, this.target.R ?? -1));
    await this.setFrontiers({ L: tip, R: tip });
    await this.settle(BIG_BUDGET);
    const snap = await this.compare();
    const proj = engineProjection(snap);
    const dissolves = new Map<string, Pos>();
    for (const v of snap.versions) if (v.status === 'dissolved') dissolves.set(refKey(v.id), v.at);
    for (const i of proj.instances) {
      if (i.reason === null || i.closedAt === null) continue;
      this.cov.closes[i.reason] = (this.cov.closes[i.reason] ?? 0) + 1;
      const d = dissolves.get(refKey(i.group));
      const sameTx = d !== undefined && d.blockHeight === i.closedAt.blockHeight && d.txIndex === i.closedAt.txIndex;
      if (sameTx && i.reason === 'retired') this.cov.closes['tie:unreg-before-dissolve'] = (this.cov.closes['tie:unreg-before-dissolve'] ?? 0) + 1;
      if (sameTx && i.reason === 'left') this.cov.closes['tie:leave-before-dissolve'] = (this.cov.closes['tie:leave-before-dissolve'] ?? 0) + 1;
    }
    this.cov.schedules = 1;
    this.cov.schedulesWithGBehindL = this.gBehind ? 1 : 0;
    this.cov.validShare = this.cov.results === 0 ? 0 : this.cov.valid / this.cov.results;
    return snap;
  }
}

// Runs `schedule` over a fresh store. Besides the final comparison with replay over the
// delivered chain, it checks the state after every finished truncation against the state
// before it, cut back, equality with replay over the cut chain after a rollback whenever
// every credential is complete, and on every run that no applied verdict and no set
// instance field changed without a truncation or a reset.
export async function runSchedule(
  makeStore: () => DriverStore | Promise<DriverStore>, chain: ChainInput[], schedule: ScheduleStep[],
): Promise<ScheduleResult> {
  const d = new Driver(await makeStore());
  await d.start();
  let i = 0;
  try {
    for (; i < schedule.length; i++) await d.step(schedule[i] as ScheduleStep);
    const final = await d.finish(chain);
    return { final, coverage: d.cov, checkpoints: d.checkpoints };
  } catch (e) {
    // Engine errors get the step too, so every failure names where it happened.
    if (e instanceof Error) {
      const at = i < schedule.length ? `step ${i} (${(schedule[i] as ScheduleStep).kind})` : 'the final comparison';
      e.message = `at ${at}: ${e.message}`;
    }
    throw e;
  }
}

