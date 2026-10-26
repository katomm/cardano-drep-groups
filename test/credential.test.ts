import { describe, expect, it } from 'vitest';
import { applyControl } from '../src/engine/control.js';
import { applyCredential } from '../src/engine/credential.js';
import { stageKeys, type Step } from '../src/engine/lazyWorld.js';
import { routeTx } from '../src/engine/route.js';
import type { ChangeSet, CredentialInput, View } from '../src/engine/types.js';
import { effectiveClose } from '../src/effective.js';
import { parseNativeScript } from '../src/nativeScript.js';
import { decodePayload } from '../src/payload.js';
import { comparePos, type Pos, posKey, posOfCert, posOfEvent } from '../src/position.js';
import type { StoredInstance } from '../src/rules.js';
import { credKey, refKey, replay } from '../src/state.js';
import type { ChainTx, Credential, EventRef, Instance, LedgerInput } from '../src/types.js';
import { chainTx, type Committed, committed, FixtureView, keyStrings } from './engineFixture.js';
import { buildPayload, ev, hashOf, K, keyCred, local, ref, scriptBytes, scriptCred, sig, T } from './helpers.js';

type Observed = { ref: EventRef; tag: string | null; valid: boolean; reason: string | null };

const done = (s: Step<ChangeSet>): ChangeSet => {
  if (!('done' in s)) throw new Error(`unit still needs ${JSON.stringify(s.need)}`);
  return s.done;
};

// Loads the three stages through stageKeys over a view that never merges the overlay,
// then runs the credential unit once on the last view.
function runCredential(
  c: Committed, m: Credential, inputs: CredentialInput[], overlay: ChangeSet[] = [], stages: 0 | 1 | 2 | 3 = 3,
  observe?: (r: Observed) => void,
) {
  let view = new FixtureView(c, new Set());
  let keys: string[] = [];
  for (let s = 1; s <= stages; s++) {
    const k = stageKeys(s as 1 | 2 | 3, { c: m, inputs }, s === 1 ? null : (view as View), overlay);
    keys = keyStrings(k);
    view = new FixtureView(c, new Set(keys));
  }
  return { step: applyCredential(view, m, inputs, overlay, observe), view, keys };
}

// The group plane unit of one tx, as the control tests run it.
function runControl(c: Committed, tx: ChainTx, overlay: ChangeSet[]): ChangeSet {
  const decoded = decodePayload(tx.payload!)!;
  const queue = overlay.flatMap((o) => o.queued.map((q) => ({ ref: { txHash: q.txHash, index: q.at.index }, event: q.event })));
  const routed = routeTx(tx, decoded, (r) => queue.find((q) => refKey(q.ref) === refKey(r))?.event ?? null);
  let view: View = new FixtureView(c, new Set());
  for (let s = 1; s <= 3; s++) {
    view = new FixtureView(c, new Set(keyStrings(stageKeys(s as 1 | 2 | 3, { tx, routed }, s === 1 ? null : view, overlay))));
  }
  return done(applyControl(view, tx, routed, overlay));
}

// The inputs of one credential: its queued events with their tx context, then its
// ledger rows. Deliberately not in position order, the unit sorts them.
function inputsOf(sets: ChangeSet[], ledger: LedgerInput[], m: Credential): CredentialInput[] {
  const contexts = sets.flatMap((s) => s.txContexts);
  const events: CredentialInput[] = sets.flatMap((s) => s.queued)
    .filter((q) => credKey(q.subject) === credKey(m))
    .map((q) => ({ kind: 'event', q, tx: contexts.find((t) => t.txHash === q.txHash)!.context }));
  const rows: CredentialInput[] = ledger.filter((l) => credKey(l.credential) === credKey(m)).map((l) => ({ kind: 'ledger', at: posOfCert(l), input: l }));
  return [...events, ...rows];
}

// The group plane over every tx in chain order, then one credential unit per
// credential, each over the change sets before it. Ledger rows are raw inputs, so the
// committed state holds them before any unit runs.
function pipeline(txs: ChainTx[], ledger: LedgerInput[], observe?: (r: Observed) => void): ChangeSet[] {
  const c = committed({ ledger });
  const sets: ChangeSet[] = [];
  for (const tx of txs) sets.push(runControl(c, tx, sets));
  const creds = new Map<string, Credential>();
  for (const q of sets.flatMap((s) => s.queued)) creds.set(credKey(q.subject), q.subject);
  for (const l of ledger) creds.set(credKey(l.credential), l.credential);
  for (const m of creds.values()) {
    const run = runCredential(c, m, inputsOf(sets, ledger, m), [...sets], 3, observe);
    // Every key the unit read was staged by stageKeys.
    expect([...run.view.asked].filter((k) => !run.keys.includes(k))).toEqual([]);
    sets.push(done(run.step));
  }
  return sets;
}

// Verdicts with a group and the instances, projected through the effective close, equal replay.
function expectReplay(txs: ChainTx[], ledger: LedgerInput[], sets: ChangeSet[]): void {
  const reference = replay([...txs.map((tx) => ({ kind: 'tx' as const, tx })), ...ledger.map((input) => ({ kind: 'ledger' as const, input }))]);
  const verdicts = sets.flatMap((s) => s.verdicts).sort((a, b) => comparePos(a.at, b.at));
  expect(verdicts).toEqual(reference.verdicts.filter((v) => v.group !== null));
  const last = new Map<string, StoredInstance>();
  for (const s of sets) for (const i of s.instances) last.set(refKey(i.joinId), i);
  const versions = sets.flatMap((s) => s.versions);
  const project = (inst: StoredInstance): Instance => {
    const dissolve = versions.find((v) => refKey(v.id) === refKey(inst.group) && v.status === 'dissolved')?.at ?? null;
    const unreg = ledger.filter((l) => l.kind === 'unreg' && credKey(l.credential) === credKey(inst.member))
      .map(posOfCert).filter((p) => comparePos(p, inst.joinedAt) > 0).sort(comparePos)[0] ?? null;
    const close = effectiveClose(inst, dissolve, unreg);
    return {
      joinId: inst.joinId, group: inst.group, member: inst.member,
      state: close ? 'closed' : inst.mode === 'open' || inst.approvedAt !== null ? 'active' : 'pending',
      reason: close ? close.reason : null, joinedAt: inst.joinedAt, approvedAt: inst.approvedAt, closedAt: close ? close.at : null,
    };
  };
  const byJoin = (a: Instance, b: Instance): number => comparePos(a.joinedAt, b.joinedAt);
  expect([...last.values()].map(project).sort(byJoin)).toEqual([...reference.instances].sort(byJoin));
}

const C0 = sig(K(1));
const A0 = sig(K(2));
const M = keyCred(K(7));
const G: EventRef = { txHash: T(2), index: 0 };
const cert = (kind: 'reg' | 'unreg', credential: Credential, h: number, certIndex = 0, witnessScripts?: Uint8Array[]): LedgerInput =>
  ({ kind, credential, txHash: T(h), blockHeight: h, txIndex: 0, certIndex, ...(witnessScripts ? { witnessScripts } : {}) });
// A group created at height 2, permissioned (1) or open (0), with its scripts in the payload.
const createTx = (mode: 0 | 1): ChainTx =>
  chainTx({ hash: T(2), h: 2, rs: [K(1), K(2)], payload: buildPayload([ev.create(mode, hashOf(C0), mode ? hashOf(A0) : null)], [C0, A0]) });
const evTx = (h: number, events: unknown[], rs: string[]): ChainTx => chainTx({ hash: T(h), h, rs, payload: buildPayload(events) });
const dissolveTx = (h: number): ChainTx => evTx(h, [ev.dissolve(ref(T(2), 0), 0)], [K(1)]);
const tagsOf = (sets: ChangeSet[]) => sets.flatMap((s) => s.verdicts).map((v) => [v.tag, v.valid, v.reason]);

describe('applyCredential', () => {
  it('approve on a join of the same tx sees the instance', () => {
    const txs = [createTx(1), evTx(10, [ev.join(ref(T(2), 0), 'key', K(7)), ev.approve(local(0))], [K(7), K(2)])];
    const ledger = [cert('reg', M, 5)];
    const sets = pipeline(txs, ledger);
    expect(tagsOf(sets)).toEqual([['create', true, null], ['join', true, null], ['approve', true, null]]);
    const unit = sets[sets.length - 1] as ChangeSet;
    const joinRef = { txHash: T(10), index: 0 };
    expect(unit.instances.at(-1)).toMatchObject({ joinId: joinRef, approvedAt: posOfEvent(txs[1] as ChainTx, 1) });
    expect(unit.effects).toEqual([
      { kind: 'instanceCreated', instance: { joinId: joinRef, group: G, member: M, mode: 'permissioned', joinedAt: posOfEvent(txs[1] as ChainTx, 0), approvedAt: null, closedAt: null, closeReason: null } },
      { kind: 'instanceApproved', join: joinRef, at: posOfEvent(txs[1] as ChainTx, 1) },
    ]);
    expect(unit.appliedQueue).toEqual([joinRef, { txHash: T(10), index: 1 }]);
    expectReplay(txs, ledger, sets);
  });

  it('a leave at 20 stays valid with a stored dissolve at 30', () => {
    const txs = [createTx(0), evTx(10, [ev.join(ref(T(2), 0), 'key', K(7))], [K(7)]), evTx(20, [ev.leave(ref(T(10), 0))], [K(7)]), dissolveTx(30)];
    const ledger = [cert('reg', M, 5)];
    const sets = pipeline(txs, ledger);
    // The group plane stores the dissolve before the credential unit applies the leave.
    expect(sets.slice(0, 4).flatMap((s) => s.versions).some((v) => v.status === 'dissolved')).toBe(true);
    expect(tagsOf(sets)).toEqual([['create', true, null], ['dissolve', true, null], ['join', true, null], ['leave', true, null]]);
    const unit = sets[sets.length - 1] as ChangeSet;
    expect(unit.effects.at(-1)).toEqual({ kind: 'instanceClosed', join: { txHash: T(10), index: 0 }, at: posOfEvent(txs[2] as ChainTx, 0), reason: 'left' });
    expectReplay(txs, ledger, sets);
  });

  it('approve on a pending instance of a dissolved group gives join is not pending', () => {
    const txs = [createTx(1), evTx(10, [ev.join(ref(T(2), 0), 'key', K(7))], [K(7)]), dissolveTx(20), evTx(30, [ev.approve(ref(T(10), 0))], [K(2)])];
    const ledger = [cert('reg', M, 5)];
    const sets = pipeline(txs, ledger);
    const verdicts = sets.flatMap((s) => s.verdicts);
    expect(verdicts.at(-1)).toMatchObject({ tag: 'approve', valid: false, reason: 'join is not pending', group: G, subject: M });
    expect((sets[sets.length - 1] as ChangeSet).effects.map((e) => e.kind)).toEqual(['instanceCreated']);
    expectReplay(txs, ledger, sets);
  });

  it('a join of a script DRep authorizes through the member script of its own reg', () => {
    const MS = sig(K(9));
    const S = scriptCred(hashOf(MS));
    const other = scriptBytes(sig(K(8)));
    const txs = [createTx(0), evTx(10, [ev.join(ref(T(2), 0), 'script', hashOf(MS))], [K(9)])];
    // A witness with another hash is skipped, the matching one becomes the member script.
    const ledger = [cert('reg', S, 5, 0, [other, scriptBytes(MS)])];
    const sets = pipeline(txs, ledger);
    const unit = sets[sets.length - 1] as ChangeSet;
    expect(unit.memberScripts).toEqual([{ credential: S, script: parseNativeScript(scriptBytes(MS)), bytes: scriptBytes(MS), at: posOfCert(ledger[0] as LedgerInput) }]);
    expect(unit.verdicts).toMatchObject([{ tag: 'join', valid: true, group: G, subject: S }]);
    expectReplay(txs, ledger, sets);
    // Without the witness the script cannot be resolved.
    const bare = [cert('reg', S, 5)];
    const without = pipeline(txs, bare);
    expect((without[without.length - 1] as ChangeSet).verdicts).toMatchObject([{ tag: 'join', valid: false, reason: 'member script unresolved' }]);
    expectReplay(txs, bare, without);
  });

  it('a join naming an unknown group is marked applied without a verdict', () => {
    const txs = [evTx(10, [ev.join(ref(T(99), 0), 'key', K(7))], [K(7)])];
    const ledger = [cert('reg', M, 5)];
    const seen: Observed[] = [];
    const sets = pipeline(txs, ledger, (r) => seen.push(r));
    const unit = sets[sets.length - 1] as ChangeSet;
    expect(unit.verdicts).toEqual([]);
    expect(unit.instances).toEqual([]);
    expect(unit.appliedQueue).toEqual([{ txHash: T(10), index: 0 }]);
    expect(seen).toEqual([{ ref: { txHash: T(10), index: 0 }, tag: 'join', valid: false, reason: 'unknown group' }]);
    expectReplay(txs, ledger, sets);
  });

  it('registration and retirement in one tx close in phase order', () => {
    const txs = [
      createTx(0),
      evTx(10, [ev.join(ref(T(2), 0), 'key', K(7))], [K(7)]),  // reg at cert 0 of the same tx comes first
      evTx(20, [ev.leave(ref(T(10), 0))], [K(7)]),             // unreg at cert 0 of the same tx closed it
      evTx(40, [ev.join(ref(T(2), 0), 'key', K(7))], [K(7)]),  // reg at cert 0, unreg at cert 1, both before the join
    ];
    const ledger = [cert('reg', M, 10), cert('unreg', M, 20), cert('reg', M, 40, 0), cert('unreg', M, 40, 1)];
    const sets = pipeline(txs, ledger);
    expect(tagsOf(sets)).toEqual([
      ['create', true, null], ['join', true, null], ['leave', false, 'join is not open'], ['join', false, 'not a registered DRep'],
    ]);
    const unit = sets[sets.length - 1] as ChangeSet;
    expect(unit.effects).toEqual([
      { kind: 'instanceCreated', instance: expect.objectContaining({ joinId: { txHash: T(10), index: 0 } }) },
      { kind: 'credentialRetired', credential: M, at: posOfCert(ledger[1] as LedgerInput) },
      { kind: 'credentialRetired', credential: M, at: posOfCert(ledger[3] as LedgerInput) },
    ]);
    expect(unit.appliedQueue).toEqual([{ txHash: T(10), index: 0 }, { txHash: T(20), index: 0 }, { txHash: T(40), index: 0 }]);
    expectReplay(txs, ledger, sets);
  });

  it('asks for credentialAt keys of every position it reads', () => {
    // A stored join at 5, a leave on it at 20, a new join at 30, all of one credential.
    const joinedAt = posOfEvent({ txHash: T(5), blockHeight: 5, txIndex: 0 }, 0);
    const stored: StoredInstance = { joinId: { txHash: T(5), index: 0 }, group: G, member: M, mode: 'open', joinedAt, approvedAt: null, closedAt: null, closeReason: null };
    const created = createTx(0);
    const version = { id: G, at: posOfEvent(created, 0), mode: 'open' as const, control: hashOf(C0), admission: null, profile: null, seq: 0n, status: 'active' as const, createdAt: posOfEvent(created, 0), profileSetAt: null };
    const ledger = [cert('reg', M, 3), cert('unreg', M, 40)];
    const c = committed({ versions: [version], instances: [stored], ledger });
    const ctx = { signers: [K(7)], requiredSigners: [K(7)], invalidBefore: null, invalidHereafter: null };
    const leaveAt = posOfEvent({ txHash: T(20), blockHeight: 20, txIndex: 0 }, 0);
    const joinAt = posOfEvent({ txHash: T(30), blockHeight: 30, txIndex: 0 }, 0);
    const inputs: CredentialInput[] = [
      { kind: 'event', tx: ctx, q: { subject: M, at: leaveAt, group: null, txHash: T(20), event: { ok: true, event: { tag: 'leave', join: stored.joinId } } } },
      { kind: 'event', tx: ctx, q: { subject: M, at: joinAt, group: G, txHash: T(30), event: { ok: true, event: { tag: 'join', group: G, member: M } } } },
      { kind: 'ledger', at: posOfCert(ledger[1] as LedgerInput), input: ledger[1] as LedgerInput },
    ];
    const { step, view, keys } = runCredential(c, M, inputs);
    expect(done(step).verdicts.map((v) => [v.tag, v.valid, v.reason])).toEqual([['leave', true, null], ['join', true, null]]);
    // Every key the unit read was staged. The credential is read at the stored join (its
    // first unreg after the join, for the leave and for the open slot) and at the new join
    // (registered). The leave of a key member reads no registration.
    expect([...view.asked].filter((k) => !keys.includes(k))).toEqual([]);
    expect([...view.asked].filter((k) => k.startsWith('c:')).sort()).toEqual([joinedAt, joinAt].map((p) => `c:${credKey(M)}@${posKey(p)}`).sort());
    // Without the stages the unit names what it misses instead of a change set. The rules
    // stop at the first missing read, the instance of the leave and the group of the join.
    expect(runCredential(c, M, inputs, [], 0).step).toEqual({
      need: { instances: [stored.joinId], latestInstances: [], groupsAt: [[G, joinAt]], scriptsAt: [], credentialAt: [] },
    });
  });

  it('reports rule results only when the unit is done', () => {
    const txs = [createTx(0), evTx(10, [ev.join(ref(T(2), 0), 'key', K(7))], [K(7)])];
    const ledger = [cert('reg', M, 5)];
    const c = committed({ ledger });
    const sets: ChangeSet[] = [];
    for (const tx of txs) sets.push(runControl(c, tx, sets));
    const seen: Observed[] = [];
    const inputs = inputsOf(sets, ledger, M);
    expect('need' in runCredential(c, M, inputs, sets, 0, (r) => seen.push(r)).step).toBe(true);
    expect(seen).toEqual([]);
    done(runCredential(c, M, inputs, sets, 3, (r) => seen.push(r)).step);
    expect(seen).toEqual([{ ref: { txHash: T(10), index: 0 }, tag: 'join', valid: true, reason: null }]);
  });

  it('takes the subject of an approve, leave or remove on an invalid join from the rule, not from routing', () => {
    // The join of K(8) fails (not registered). Routing still sends the later events to K(8),
    // but the rule finds no instance, so there is no group and no stored verdict.
    const K8 = keyCred(K(8));
    const txs = [
      createTx(1),
      evTx(10, [ev.join(ref(T(2), 0), 'key', K(8)), ev.leave(local(0))], [K(8)]),
      evTx(20, [ev.approve(ref(T(10), 0)), ev.remove(ref(T(10), 0))], [K(2)]),
    ];
    const seen: Observed[] = [];
    const sets = pipeline(txs, [], (r) => seen.push(r));
    const queued = sets.flatMap((s) => s.queued).filter((q) => q.event.ok && q.event.event.tag !== 'join');
    expect(queued.map((q) => q.subject)).toEqual([K8, K8, K8]);
    const unit = sets[sets.length - 1] as ChangeSet;
    expect(unit.verdicts).toMatchObject([{ tag: 'join', valid: false, reason: 'not a registered DRep', group: G, subject: K8 }]);
    expect(seen.map((r) => [r.tag, r.reason])).toEqual([
      ['join', 'not a registered DRep'], ['leave', 'unknown join'], ['approve', 'unknown join'], ['remove', 'unknown join'],
    ]);
    expect(unit.appliedQueue).toHaveLength(4);
    expectReplay(txs, [], sets);
    const reference = replay(txs.map((tx) => ({ kind: 'tx' as const, tx })));
    expect(reference.verdicts.slice(2).map((v) => [v.group, v.subject])).toEqual([[null, null], [null, null], [null, null]]);
  });
});
