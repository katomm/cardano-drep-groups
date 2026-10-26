// A RuleWorld over a bounded view. Reads go to the unit's own change set first, then to
// the change sets of earlier units of the same uncommitted batch, then to the view. A
// read the view was not loaded for is recorded in `needed` and answered with null.
import { type CloseReason, effectiveClose } from '../effective.js';
import { comparePos, type Pos } from '../position.js';
import { type GroupVersion, resolve, type RuleWorld, type StoredInstance } from '../rules.js';
import { credKey, refKey } from '../state.js';
import type { ChainTx, Credential, EventRef, Hex, NativeScript } from '../types.js';
import type { ChangeSet, CredentialInput, Keys, Routed, View } from './types.js';

export type Step<T> = { done: T } | { need: Keys };

export const emptyKeys = (): Keys => ({ instances: [], latestInstances: [], groupsAt: [], scriptsAt: [], credentialAt: [] });
export const emptyChangeSet = (): ChangeSet => ({
  scripts: [], memberScripts: [], versions: [], instances: [], verdicts: [], queued: [], txContexts: [], appliedQueue: [], effects: [],
});
export const isEmptyKeys = (k: Keys): boolean =>
  k.instances.length + k.latestInstances.length + k.groupsAt.length + k.scriptsAt.length + k.credentialAt.length === 0;

const posKey = (p: Pos): string => `${p.blockHeight},${p.txIndex},${p.phase},${p.index}`;

// Collects keys without duplicates, in first seen order.
class KeySet {
  readonly keys = emptyKeys();
  private seen = new Set<string>();
  private add(id: string): boolean {
    if (this.seen.has(id)) return false;
    this.seen.add(id);
    return true;
  }
  instance(r: EventRef): void {
    if (this.add(`i:${refKey(r)}`)) this.keys.instances.push(r);
  }
  latest(g: EventRef, c: Credential): void {
    if (this.add(`l:${refKey(g)}|${credKey(c)}`)) this.keys.latestInstances.push([g, c]);
  }
  group(g: EventRef, at: Pos): void {
    if (this.add(`g:${refKey(g)}@${posKey(at)}`)) this.keys.groupsAt.push([g, at]);
  }
  script(h: Hex | null | undefined, at: Pos): void {
    if (h && this.add(`s:${h}@${posKey(at)}`)) this.keys.scriptsAt.push([h, at]);
  }
  credential(c: Credential, at: Pos): void {
    if (this.add(`c:${credKey(c)}@${posKey(at)}`)) this.keys.credentialAt.push([c, at]);
  }
  merge(k: Keys): void {
    for (const r of k.instances) this.instance(r);
    for (const [g, c] of k.latestInstances) this.latest(g, c);
    for (const [g, p] of k.groupsAt) this.group(g, p);
    for (const [h, p] of k.scriptsAt) this.script(h, p);
    for (const [c, p] of k.credentialAt) this.credential(c, p);
  }
}

const sameCred = (a: Credential, b: Credential): boolean => a.kind === b.kind && a.hash === b.hash;
const sameRef = (a: EventRef, b: EventRef): boolean => a.txHash === b.txHash && a.index === b.index;

export class LazyWorld implements RuleWorld {
  private need = new KeySet();
  // Own first, then the overlay from its latest unit back, so the first match is the most recent writer.
  private sets: ChangeSet[];

  constructor(private view: View, overlay: ChangeSet[], own: ChangeSet) {
    this.sets = [own, ...[...overlay].reverse()];
  }

  get needed(): Keys {
    return this.need.keys;
  }

  // True when the view was loaded for the key, otherwise the key is recorded.
  private loaded(k: Partial<Keys>): boolean {
    const full: Keys = { ...emptyKeys(), ...k };
    const m = this.view.missing(full);
    if (isEmptyKeys(m)) return true;
    this.need.merge(m);
    return false;
  }

  // A group whose ref names a tx of the own unit or of the overlay can only have been
  // created there, so a missing version there is a negative answer.
  private ownsTx(txHash: Hex): boolean {
    return this.sets.some((s) => s.txContexts.some((t) => t.txHash === txHash));
  }

  private versions(g: EventRef): GroupVersion[] {
    return this.sets.flatMap((s) => s.versions.filter((v) => sameRef(v.id, g)));
  }

  scriptAt(hash: Hex, at: Pos): NativeScript | null {
    for (const s of this.sets) {
      const hit = s.scripts.find((x) => x.hash === hash && comparePos(x.at, at) <= 0);
      if (hit) return hit.script;
    }
    return this.loaded({ scriptsAt: [[hash, at]] }) ? this.view.scriptAt(hash, at) : null;
  }

  groupAt(group: EventRef, at: Pos): GroupVersion | null {
    let best: GroupVersion | null = null;
    for (const v of this.versions(group)) {
      if (comparePos(v.at, at) <= 0 && (best === null || comparePos(v.at, best.at) > 0)) best = v;
    }
    if (best !== null || this.ownsTx(group.txHash)) return best;
    return this.loaded({ groupsAt: [[group, at]] }) ? this.view.groupAt(group, at) : null;
  }

  // The dissolve of a group, keyed by the position of the read (a group key loads the
  // dissolve version along with the version at that position).
  private dissolveOf(group: EventRef, at: Pos): Pos | null {
    const own = this.versions(group).find((v) => v.status === 'dissolved');
    if (own) return own.at;
    if (this.ownsTx(group.txHash)) return null;
    return this.loaded({ groupsAt: [[group, at]] }) ? this.view.dissolvedAt(group) : null;
  }

  registeredAt(c: Credential, at: Pos): boolean {
    return this.loaded({ credentialAt: [[c, at]] }) ? this.view.registeredAt(c, at) : false;
  }

  memberScriptAt(c: Credential, at: Pos): NativeScript | null {
    for (const s of this.sets) {
      const hit = s.memberScripts.find((x) => sameCred(x.credential, c) && comparePos(x.at, at) <= 0);
      if (hit) return hit.script;
    }
    return this.loaded({ credentialAt: [[c, at]] }) ? this.view.memberScriptAt(c, at) : null;
  }

  private firstUnregAfter(c: Credential, after: Pos): Pos | null {
    return this.loaded({ credentialAt: [[c, after]] }) ? this.view.firstUnregAfter(c, after) : null;
  }

  private closeOf(inst: StoredInstance, at: Pos): { at: Pos; reason: CloseReason } | null {
    return effectiveClose(inst, this.dissolveOf(inst.group, at), this.firstUnregAfter(inst.member, inst.joinedAt), at);
  }

  // The stored row of a join, independent of a position: the last write in the own unit,
  // then in the overlay, then the view.
  stored(join: EventRef): StoredInstance | null {
    for (const s of this.sets) {
      const rows = s.instances.filter((i) => sameRef(i.joinId, join));
      if (rows.length > 0) return rows[rows.length - 1] as StoredInstance;
    }
    return this.loaded({ instances: [join] }) ? this.view.instance(join) : null;
  }

  instanceAt(join: EventRef, at: Pos): { inst: StoredInstance; close: { at: Pos; reason: CloseReason } | null } | null {
    const inst = this.stored(join);
    if (!inst || comparePos(inst.joinedAt, at) >= 0) return null;
    return { inst, close: this.closeOf(inst, at) };
  }

  // The latest stored instance of (group, c), independent of a position. The most recent
  // writer of a join wins, own first, within a change set its last row.
  latestStored(group: EventRef, c: Credential): StoredInstance | null {
    const rows = new Map<string, StoredInstance>();
    for (const s of this.sets) {
      const mine = new Map<string, StoredInstance>();
      for (const i of s.instances) if (sameRef(i.group, group) && sameCred(i.member, c)) mine.set(refKey(i.joinId), i);
      for (const [k, i] of mine) if (!rows.has(k)) rows.set(k, i);
    }
    let latest: StoredInstance | null = null;
    for (const i of rows.values()) if (latest === null || comparePos(i.joinedAt, latest.joinedAt) > 0) latest = i;
    if (latest !== null) return latest;
    return this.loaded({ latestInstances: [[group, c]] }) ? this.view.latestInstance(group, c) : null;
  }

  openSlotAt(group: EventRef, c: Credential, at: Pos): StoredInstance | null {
    const latest = this.latestStored(group, c);
    if (latest === null || comparePos(latest.joinedAt, at) >= 0) return null;
    return this.closeOf(latest, at) === null ? latest : null;
  }
}

type ControlInputs = { tx: ChainTx; routed: Routed };
type CredentialInputs = { c: Credential; inputs: CredentialInput[] };

// Keys a unit needs, derived from its inputs instead of discovered by failed reads, so a
// unit loads in at most three rounds. Stage 1 is what the events name, stage 2 what the
// versions and instances loaded in stage 1 name, stage 3 the scripts those name. Each
// stage returns the keys of all stages up to it, so a store may load every stage alone.
// `partial` is the view of the previous stage as Store.load returned it, `overlay` the
// change sets of earlier units of the same batch. Both are read through a LazyWorld, so
// versions and instances of the overlay are seen without a view that merges them.
export function stageKeys(
  stage: 1 | 2 | 3, inputs: ControlInputs | CredentialInputs, partial: View | null, overlay: ChangeSet[] = [],
): Keys {
  const out = new KeySet();
  const read = partial ? new LazyWorld(partial, overlay, emptyChangeSet()) : null;
  if ('tx' in inputs) controlKeys(stage, inputs, read, out);
  else credentialKeys(stage, inputs, read, out);
  return out.keys;
}

function controlKeys(stage: 1 | 2 | 3, { routed }: ControlInputs, partial: LazyWorld | null, out: KeySet): void {
  // Hashes that earlier control events of this tx named for a group. A later event on the
  // same group may read them as its current policies at its own position.
  const named = new Map<string, Hex[]>();
  const name = (g: EventRef, ...hs: Array<Hex | null | undefined>): void => {
    const list = named.get(refKey(g)) ?? [];
    for (const h of hs) if (h && !list.includes(h)) list.push(h);
    named.set(refKey(g), list);
  };
  for (const r of routed.events) {
    if (r.plane !== 'control' || !r.decoded.ok) continue;
    const e = r.decoded.event;
    if (e.tag === 'create') {
      out.script(e.control, r.at);
      out.script(e.admission, r.at);
      name(r.ref, e.control, e.admission);
      continue;
    }
    if (e.tag !== 'update' && e.tag !== 'dissolve') continue;
    const g = resolve(e.group, r.ref);
    if (!g) continue;
    out.group(g, r.at);
    for (const h of named.get(refKey(g)) ?? []) out.script(h, r.at);
    if (e.tag === 'update') {
      out.script(e.changes.control, r.at);
      out.script(e.changes.admission, r.at);
      name(g, e.changes.control, e.changes.admission);
    }
    // The current policies of the group, for the control check and the consent rule.
    const v = stage >= 2 && partial ? partial.groupAt(g, r.at) : null;
    if (v) {
      out.script(v.control, r.at);
      out.script(v.admission, r.at);
    }
  }
}

function credentialKeys(stage: 1 | 2 | 3, { c, inputs }: CredentialInputs, partial: LazyWorld | null, out: KeySet): void {
  // Joins of this unit, so a later input on the same join finds its group before it is stored.
  const ownJoins = new Map<string, { group: EventRef; joinedAt: Pos }>();
  for (const x of inputs) {
    if (x.kind === 'ledger') {
      out.credential(c, x.at);
      continue;
    }
    const d = x.q.event;
    if (!d.ok) continue;
    const e = d.event;
    const at = x.q.at;
    const self: EventRef = { txHash: x.q.txHash, index: at.index };
    out.credential(c, at);
    if (c.kind === 'script') out.script(c.hash, at);
    if (e.tag === 'join') {
      const g = resolve(e.group, self);
      if (!g) continue;
      out.group(g, at);
      out.latest(g, c);
      ownJoins.set(refKey(self), { group: g, joinedAt: at });
      const li = stage >= 2 && partial ? partial.latestStored(g, c) : null;
      if (li) out.credential(li.member, li.joinedAt);
      continue;
    }
    if (e.tag !== 'approve' && e.tag !== 'leave' && e.tag !== 'remove') continue;
    const j = resolve(e.join, self);
    if (!j) continue;
    out.instance(j);
    if (stage < 2) continue;
    const stored = partial?.stored(j) ?? null;
    const inst = stored ? { group: stored.group, joinedAt: stored.joinedAt, member: stored.member } : (() => {
      const o = ownJoins.get(refKey(j));
      return o ? { ...o, member: c } : null;
    })();
    if (!inst) continue;
    out.group(inst.group, at);
    out.credential(inst.member, inst.joinedAt);
    const v = stage >= 3 && partial ? partial.groupAt(inst.group, at) : null;
    if (v) out.script(v.admission, at);
  }
}
