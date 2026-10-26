import { describe, expect, it } from 'vitest';
import { applyControl } from '../src/engine/control.js';
import { emptyChangeSet, LazyWorld, stageKeys, type Step } from '../src/engine/lazyWorld.js';
import { routeTx } from '../src/engine/route.js';
import type { ChangeSet, View } from '../src/engine/types.js';
import { nativeScriptHash } from '../src/hash.js';
import { parseNativeScript } from '../src/nativeScript.js';
import { decodePayload } from '../src/payload.js';
import { type Pos, posOfCert, posOfEvent, posOfScripts } from '../src/position.js';
import type { GroupVersion, StoredInstance } from '../src/rules.js';
import { refKey, replay } from '../src/state.js';
import type { ChainTx, EventRef, LedgerInput, NativeScript } from '../src/types.js';
import { chainTx, type Committed, committed, FixtureView, keyStrings } from './engineFixture.js';
import { buildPayload, ev, hashOf, K, kb, keyCred, local, ref, scriptBytes, type ScriptValue, sig, T } from './helpers.js';

// Routes a tx against the queue, then loads the three stages and runs the unit once,
// the order runEngine uses. Returns the step and the number of loads it took.
function runControl(c: Committed, tx: ChainTx, overlay: ChangeSet[] = [], stages: 0 | 1 | 2 | 3 = 3, observe?: Parameters<typeof applyControl>[4]) {
  const decoded = decodePayload(tx.payload!)!;
  const queue = [...c.queued, ...overlay.flatMap((o) => o.queued.map((q) => ({ ref: { txHash: q.txHash, index: q.at.index }, event: q.event })))];
  const routed = routeTx(tx, decoded, (r) => queue.find((q) => refKey(q.ref) === refKey(r))?.event ?? null);
  let view: View = new FixtureView(c, new Set());
  for (let s = 1; s <= stages; s++) {
    const keys = stageKeys(s as 1 | 2 | 3, { tx, routed }, s === 1 ? null : view, overlay);
    view = new FixtureView(c, new Set(keyStrings(keys)));
  }
  return { step: applyControl(view, tx, routed, overlay, observe), routed };
}
const done = (s: Step<ChangeSet>): ChangeSet => {
  if (!('done' in s)) throw new Error(`unit still needs ${JSON.stringify(s.need)}`);
  return s.done;
};
const parsed = (s: ScriptValue): NativeScript => parseNativeScript(scriptBytes(s))!;
const published = (s: ScriptValue, at: Pos) => ({ hash: nativeScriptHash(scriptBytes(s)), script: parsed(s), at });

const C0 = sig(K(1));
const A0 = sig(K(2));
const C1 = sig(K(3));
const A1 = sig(K(4));
const early = posOfScripts({ txHash: T(1), blockHeight: 1, txIndex: 0 });
const G1: EventRef = { txHash: T(2), index: 0 };
const createdAt = posOfEvent({ txHash: T(2), blockHeight: 2, txIndex: 0 }, 0);
const v0 = (o: Partial<GroupVersion> = {}): GroupVersion => ({
  id: G1, at: createdAt, mode: 'permissioned', control: hashOf(C0), admission: hashOf(A0), profile: null,
  seq: 0n, status: 'active', createdAt, profileSetAt: null, ...o,
});

describe('applyControl', () => {
  it('writes key 2 scripts of a tx with only membership events', () => {
    const tx = chainTx({ hash: T(10), h: 10, payload: buildPayload([ev.join(ref(T(2), 0), 'key', K(7))], [C0]), rs: [K(7)] });
    const cs = done(runControl(committed({ versions: [v0()] }), tx).step);
    expect(cs.scripts).toEqual([{ hash: hashOf(C0), script: parsed(C0), bytes: scriptBytes(C0), at: posOfScripts(tx) }]);
    expect(cs.verdicts).toEqual([]);
    expect(cs.versions).toEqual([]);
    expect(cs.queued).toHaveLength(1);
  });

  it('applies an update on a create of the same tx', () => {
    const tx = chainTx({
      hash: T(10), h: 10, rs: [K(1), K(2), K(3)],
      payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0)), ev.update(local(0), 0, new Map([[0, kb(hashOf(C1))]]))]),
    });
    const cs = done(runControl(committed({ scripts: [published(C0, early), published(A0, early), published(C1, early)] }), tx).step);
    const g = { txHash: T(10), index: 0 };
    expect(cs.verdicts.map((v) => [v.tag, v.valid, v.reason, v.group])).toEqual([['create', true, null, g], ['update', true, null, g]]);
    expect(cs.versions.map((v) => [v.seq, v.control, v.at])).toEqual([[0n, hashOf(C0), posOfEvent(tx, 0)], [1n, hashOf(C1), posOfEvent(tx, 1)]]);
  });

  it('a create whose control script is in the same payload is valid', () => {
    const tx = chainTx({ hash: T(10), h: 10, rs: [K(1)], payload: buildPayload([ev.create(0, hashOf(C0), null)], [C0]) });
    const cs = done(runControl(committed(), tx).step);
    expect(cs.verdicts).toMatchObject([{ tag: 'create', valid: true, group: { txHash: T(10), index: 0 } }]);
    expect(cs.versions).toHaveLength(1);
  });

  it('queues joins with their tx context once per tx', () => {
    const tx = chainTx({
      hash: T(10), h: 10, i: 2, rs: [K(7)], wk: [K(8), K(7)], ib: 5n, ih: 99n,
      payload: buildPayload([ev.join(ref(T(2), 0), 'key', K(7)), ev.join(ref(T(2), 0), 'key', K(8)), ev.leave(local(0))]),
    });
    const cs = done(runControl(committed({ versions: [v0()] }), tx).step);
    expect(cs.txContexts).toEqual([{ txHash: T(10), context: { signers: [K(7), K(8)], requiredSigners: [K(7)], invalidBefore: 5n, invalidHereafter: 99n } }]);
    expect(cs.queued.map((q) => [q.subject, q.at, q.group, q.txHash, (q.event as { ok: true; event: { tag: string } }).event.tag])).toEqual([
      [keyCred(K(7)), posOfEvent(tx, 0), G1, T(10), 'join'],
      [keyCred(K(8)), posOfEvent(tx, 1), G1, T(10), 'join'],
      [keyCred(K(7)), posOfEvent(tx, 2), null, T(10), 'leave'],
    ]);
    expect(cs.verdicts).toEqual([]);
  });

  it('drops orphan verdicts without a group', () => {
    const tx = chainTx({
      hash: T(10), h: 10, rs: [K(1)],
      payload: buildPayload([
        ev.approve(local(0)),                     // local ref to itself
        [9, 1],                                    // undecodable event
        ev.leave(ref(T(3), 0)),                    // no queued join
        ev.remove(ref(T(10), 5)),                  // own hash, later index
        ev.update(ref(T(4), 0), 0, new Map()),     // unknown group, control plane
        ev.dissolve(ref(T(2), 0), 0),              // valid, has a group
      ]),
    });
    const seen: Array<{ ref: EventRef; tag: string | null; valid: boolean; reason: string | null }> = [];
    const { step } = runControl(committed({ versions: [v0()], scripts: [published(C0, early)] }), tx, [], 3, (r) => seen.push(r));
    const cs = done(step);
    expect(seen.map((r) => [r.ref.index, r.tag, r.valid, r.reason])).toEqual([
      [0, 'approve', false, 'local reference must point to an earlier event'],
      [1, null, false, expect.any(String)],
      [2, 'leave', false, 'unknown join'],
      [3, 'remove', false, 'unknown join'],
      [4, 'update', false, 'unknown group'],
      [5, 'dissolve', true, null],
    ]);
    expect(cs.verdicts.map((v) => v.ref.index)).toEqual([5]);
    expect(cs.queued).toEqual([]);
  });

  it('an update of a permissioned group with a new control and admission policy, all scripts published earlier, is valid within three stages', () => {
    const c = committed({ versions: [v0()], scripts: [C0, A0, C1, A1].map((s) => published(s, early)) });
    const tx = chainTx({
      hash: T(10), h: 10, rs: [K(1), K(3), K(4)],
      payload: buildPayload([ev.update(ref(T(2), 0), 0, new Map([[0, kb(hashOf(C1))], [1, kb(hashOf(A1))]]))]),
    });
    // Stage 1 alone cannot know the current policies of the group, the rule stops at the first missing one.
    const one = runControl(c, tx, [], 1).step;
    expect('need' in one && one.need.scriptsAt.map(([h]) => h)).toEqual([hashOf(C0)]);
    // Stage 2 names them from the loaded version, stage 3 adds nothing for a control unit.
    expect(runControl(c, tx, [], 2).step).toEqual(runControl(c, tx, [], 3).step);
    const cs = done(runControl(c, tx, [], 3).step);
    expect(cs.verdicts).toMatchObject([{ tag: 'update', valid: true, reason: null, group: G1 }]);
    expect(cs.versions).toMatchObject([{ seq: 1n, control: hashOf(C1), admission: hashOf(A1) }]);
    // A key that newly appears must have signed, the old keys need not.
    const unsigned = chainTx({ hash: T(10), h: 10, rs: [K(1), K(3)], payload: tx.payload });
    expect(done(runControl(c, unsigned).step).verdicts).toMatchObject([{ valid: false, reason: 'newly listed key did not sign' }]);
  });

  it('a create in one tx and its update in the next tx of the same batch see each other through the overlay', () => {
    const c = committed({ scripts: [published(C0, early)] });
    const tx1 = chainTx({ hash: T(10), h: 10, rs: [K(1), K(3)], payload: buildPayload([ev.create(0, hashOf(C0), null)], [C1]) });
    const cs1 = done(runControl(c, tx1).step);
    const tx2 = chainTx({ hash: T(11), h: 10, i: 1, rs: [K(1), K(3)], payload: buildPayload([ev.update(ref(T(10), 0), 0, new Map([[0, kb(hashOf(C1))]]))]) });
    const cs2 = done(runControl(c, tx2, [cs1]).step);
    expect(cs2.verdicts).toMatchObject([{ tag: 'update', valid: true, group: { txHash: T(10), index: 0 } }]);
    expect(cs2.versions).toMatchObject([{ seq: 1n, control: hashOf(C1) }]);
    // The view does not merge the overlay, yet stage 2 names the control script published
    // before the batch through the overlay version, so the unit finishes within the stages.
    expect(runControl(c, tx2, [cs1], 1).step).toMatchObject({ need: { scriptsAt: [[hashOf(C0), posOfEvent(tx2, 0)]] } });
    expect(runControl(c, tx2, [cs1], 2).step).toEqual(runControl(c, tx2, [cs1], 3).step);
    // Without the overlay the second tx does not see the group.
    expect(done(runControl(c, tx2).step).verdicts).toEqual([]);
  });

  it('a dissolve writes the dissolved version and a groupDissolved effect, no instance', () => {
    const c = committed({ versions: [v0()], scripts: [published(C0, early), published(A0, early)] });
    const tx = chainTx({ hash: T(10), h: 10, rs: [K(1)], payload: buildPayload([ev.dissolve(ref(T(2), 0), 0)]) });
    const cs = done(runControl(c, tx).step);
    expect(cs.versions).toEqual([v0({ at: posOfEvent(tx, 0), status: 'dissolved' })]);
    expect(cs.effects).toEqual([{ kind: 'groupDissolved', group: G1, at: posOfEvent(tx, 0) }]);
    expect(cs.instances).toEqual([]);
  });

  it('returns need with every missing key instead of guessing', () => {
    const c = committed({ versions: [v0()], scripts: [published(C0, early)] });
    const tx = chainTx({ hash: T(10), h: 10, rs: [K(1)], payload: buildPayload([ev.dissolve(ref(T(2), 0), 0)]) });
    const step = runControl(c, tx, [], 0).step;
    expect(step).toEqual({ need: { instances: [], latestInstances: [], groupsAt: [[G1, posOfEvent(tx, 0)]], scriptsAt: [], credentialAt: [] } });
  });
});

describe('LazyWorld', () => {
  const at = (h: number, i = 0): Pos => posOfEvent({ txHash: T(h), blockHeight: h, txIndex: 0 }, i);
  const M = keyCred(K(7));
  const inst = (o: Partial<StoredInstance> = {}): StoredInstance => ({
    joinId: { txHash: T(5), index: 0 }, group: G1, member: M, mode: 'open',
    joinedAt: at(5), approvedAt: null, closedAt: null, closeReason: null, ...o,
  });
  const all = (c: Committed) => {
    const v = new FixtureView(c, new Set());
    // Loaded for everything: missing() answers nothing.
    v.missing = () => ({ instances: [], latestInstances: [], groupsAt: [], scriptsAt: [], credentialAt: [] });
    return v;
  };

  it('reads the own change set, then the overlay, then the view', () => {
    const own = emptyChangeSet();
    const overlay = [{ ...emptyChangeSet(), versions: [v0({ at: at(3), seq: 1n })] }];
    const w = new LazyWorld(all(committed({ versions: [v0()] })), overlay, own);
    expect(w.groupAt(G1, at(4))?.seq).toBe(1n);
    own.versions.push(v0({ at: at(4, 1), seq: 2n }));
    expect(w.groupAt(G1, at(4, 2))?.seq).toBe(2n);
    // Before the own version the overlay still answers.
    expect(w.groupAt(G1, at(4, 0))?.seq).toBe(1n);
    expect(w.needed).toEqual({ instances: [], latestInstances: [], groupsAt: [], scriptsAt: [], credentialAt: [] });
  });

  it('answers a group of a tx of the own or overlay unit without a key, positive or negative', () => {
    const own = { ...emptyChangeSet(), txContexts: [{ txHash: T(10), context: { signers: [], requiredSigners: [], invalidBefore: null, invalidHereafter: null } }] };
    const w = new LazyWorld(new FixtureView(committed(), new Set()), [], own);
    expect(w.groupAt({ txHash: T(10), index: 3 }, at(10, 5))).toBeNull();
    expect(w.needed.groupsAt).toEqual([]);
    expect(w.groupAt({ txHash: T(4), index: 0 }, at(10, 5))).toBeNull();
    expect(w.needed.groupsAt).toEqual([[{ txHash: T(4), index: 0 }, at(10, 5)]]);
  });

  it('records each missing key once and returns null for it', () => {
    const w = new LazyWorld(new FixtureView(committed({ scripts: [published(C0, early)] }), new Set()), [], emptyChangeSet());
    expect(w.scriptAt(hashOf(C0), at(9))).toBeNull();
    expect(w.scriptAt(hashOf(C0), at(9))).toBeNull();
    expect(w.registeredAt(M, at(9))).toBe(false);
    expect(w.needed.scriptsAt).toEqual([[hashOf(C0), at(9)]]);
    expect(w.needed.credentialAt).toEqual([[M, at(9)]]);
  });

  it('projects the dissolve and the first unreg after the join into instanceAt at q', () => {
    const unreg: LedgerInput = { kind: 'unreg', credential: M, txHash: T(25), blockHeight: 25, txIndex: 0, certIndex: 0 };
    const c = committed({ versions: [v0(), v0({ at: at(30), status: 'dissolved' })], instances: [inst()], ledger: [unreg] });
    const w = new LazyWorld(all(c), [], emptyChangeSet());
    expect(w.instanceAt(inst().joinId, at(5))).toBeNull(); // only joins before the position
    expect(w.instanceAt(inst().joinId, at(20))?.close).toBeNull();
    expect(w.instanceAt(inst().joinId, at(26))?.close).toEqual({ at: posOfCert(unreg), reason: 'retired' });
    const noUnreg = new LazyWorld(all({ ...c, ledger: [] }), [], emptyChangeSet());
    expect(noUnreg.instanceAt(inst().joinId, at(31))?.close).toEqual({ at: at(30), reason: 'dissolved' });
    // An own dissolve counts as well.
    const own = { ...emptyChangeSet(), versions: [v0({ at: at(28), status: 'dissolved' })] };
    const w2 = new LazyWorld(all({ ...c, versions: [v0()], ledger: [] }), [], own);
    expect(w2.instanceAt(inst().joinId, at(29))?.close).toEqual({ at: at(28), reason: 'dissolved' });
    expect(w2.openSlotAt(G1, M, at(29))).toBeNull();
    expect(w2.openSlotAt(G1, M, at(27))).toEqual(inst());
  });

  it('takes the last own row of an instance', () => {
    const own = { ...emptyChangeSet(), instances: [inst({ mode: 'permissioned' }), inst({ mode: 'permissioned', approvedAt: at(6) })] };
    const w = new LazyWorld(new FixtureView(committed(), new Set()), [], own);
    expect(w.instanceAt(inst().joinId, at(7))?.inst.approvedAt).toEqual(at(6));
    expect(w.needed.instances).toEqual([]);
  });
});

describe('control plane against replay', () => {
  it('gives the verdicts and versions of replay for a batch of control txs', () => {
    const txs = [
      chainTx({ hash: T(20), h: 20, rs: [K(1), K(2)], payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0))], [C0, A0]) }),
      chainTx({
        hash: T(21), h: 21, rs: [K(1), K(3), K(4)], payload: buildPayload([
          ev.update(ref(T(20), 0), 0, new Map([[0, kb(hashOf(C1))]])),
          ev.update(ref(T(20), 0), 1, new Map([[1, kb(hashOf(A1))]])),
          ev.update(ref(T(20), 0), 1, new Map()), // stale seq
          ev.create(0, hashOf(C1), null),
          ev.dissolve(local(3), 0),
          ev.update(local(3), 1, new Map()),      // group dissolved
        ], [C1, A1]),
      }),
      chainTx({ hash: T(22), h: 22, rs: [K(1)], payload: buildPayload([ev.dissolve(ref(T(20), 0), 2)]) }), // C1 did not sign
      chainTx({ hash: T(23), h: 23, rs: [K(3)], payload: buildPayload([ev.dissolve(ref(T(20), 0), 2)]) }),
    ];
    const overlay: ChangeSet[] = [];
    for (const tx of txs) overlay.push(done(runControl(committed(), tx, overlay).step));
    const reference = replay(txs.map((tx) => ({ kind: 'tx' as const, tx })));
    expect(overlay.flatMap((o) => o.verdicts)).toEqual(reference.verdicts.filter((v) => v.group !== null));
    const last = new Map<string, GroupVersion>();
    for (const v of overlay.flatMap((o) => o.versions)) last.set(refKey(v.id), v);
    expect([...last.values()].map(({ at: _at, ...g }) => g)).toEqual(reference.groups);
  });
});

describe('stageKeys for a credential unit', () => {
  it('finds the group of a join of the same unit for a later approve, then its admission script', () => {
    const M = keyCred(K(7));
    const tx: ChainTx = chainTx({ hash: T(30), h: 30, rs: [K(7)] });
    const joinAt = posOfEvent(tx, 0);
    const approveAt = posOfEvent(tx, 1);
    const ctx = { signers: [K(7)], requiredSigners: [K(7)], invalidBefore: null, invalidHereafter: null };
    const inputs = [
      { kind: 'event' as const, tx: ctx, q: { subject: M, at: joinAt, group: G1, txHash: T(30), event: { ok: true as const, event: { tag: 'join' as const, group: G1, member: M } } } },
      { kind: 'event' as const, tx: ctx, q: { subject: M, at: approveAt, group: null, txHash: T(30), event: { ok: true as const, event: { tag: 'approve' as const, join: { local: 0 } } } } },
    ];
    const c = committed({ versions: [v0()] });
    const s1 = stageKeys(1, { c: M, inputs }, null);
    expect(s1).toEqual({
      instances: [{ txHash: T(30), index: 0 }], latestInstances: [[G1, M]],
      groupsAt: [[G1, joinAt]], scriptsAt: [], credentialAt: [[M, joinAt], [M, approveAt]],
    });
    const view2 = new FixtureView(c, new Set(keyStrings(s1)));
    const s2 = stageKeys(2, { c: M, inputs }, view2);
    expect(s2.groupsAt).toEqual([[G1, joinAt], [G1, approveAt]]);
    const s3 = stageKeys(3, { c: M, inputs }, new FixtureView(c, new Set(keyStrings(s2))));
    expect(s3.scriptsAt).toEqual([[hashOf(A0), approveAt]]);
  });

  it('reads instances and versions of the overlay, not only the view', () => {
    const M = keyCred(K(7));
    const tx = chainTx({ hash: T(31), h: 31, rs: [K(7)] });
    const approveAt = posOfEvent(tx, 0);
    const J: EventRef = { txHash: T(25), index: 0 };
    const joinedAt = posOfEvent({ txHash: T(25), blockHeight: 25, txIndex: 0 }, 0);
    const ctx = { signers: [K(7)], requiredSigners: [K(7)], invalidBefore: null, invalidHereafter: null };
    const inputs = [{ kind: 'event' as const, tx: ctx, q: { subject: M, at: approveAt, group: null, txHash: T(31), event: { ok: true as const, event: { tag: 'approve' as const, join: J } } } }];
    const overlay = [{
      ...emptyChangeSet(),
      versions: [v0()],
      instances: [{ joinId: J, group: G1, member: M, mode: 'permissioned' as const, joinedAt, approvedAt: null, closedAt: null, closeReason: null }],
    }];
    const c = committed();
    const s1 = stageKeys(1, { c: M, inputs }, null, overlay);
    const s2 = stageKeys(2, { c: M, inputs }, new FixtureView(c, new Set(keyStrings(s1))), overlay);
    expect(s2.groupsAt).toEqual([[G1, approveAt]]);
    expect(s2.credentialAt).toEqual([[M, approveAt], [M, joinedAt]]);
    const s3 = stageKeys(3, { c: M, inputs }, new FixtureView(c, new Set(keyStrings(s2))), overlay);
    expect(s3.scriptsAt).toEqual([[hashOf(A0), approveAt]]);
  });
});
