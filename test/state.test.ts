import { describe, expect, it } from 'vitest';
import { orderInputs, replay } from '../src/state.js';
import { allOf, buildPayload, ev, hashOf, K, kb, keyCred, local, nOfK, ref, regIn, scriptBytes, scriptCred, sig, T, txIn, unregIn } from './helpers.js';

const ctrl = nOfK(2, sig(K(1)), sig(K(2)), sig(K(3)));
const C = hashOf(ctrl);
const ALL = [K(1), K(2), K(3)];
const createTx = (o: { hash?: string; h?: number; rs?: string[]; wk?: string[]; scripts?: boolean } = {}) =>
  txIn({ hash: o.hash ?? T(1), h: o.h ?? 10, payload: buildPayload([ev.create(0, C, null)], o.scripts === false ? [] : [ctrl]), rs: o.rs ?? ALL, wk: o.wk });
const upd = (hash: string, h: number, seq: number, changes: Map<number, unknown>, rs: string[], scripts: unknown[][] = []) =>
  txIn({ hash, h, payload: buildPayload([ev.update(ref(T(1), 0), seq, changes)], scripts), rs });

describe('replay: groups', () => {
  it('creates a group when the policy is satisfied and every listed key signed', () => {
    const s = replay([createTx()]);
    expect(s.groups).toMatchObject([{ id: { txHash: T(1), index: 0 }, mode: 'open', control: C, seq: 0n, status: 'active' }]);
    expect(s.verdicts).toEqual([{ ref: { txHash: T(1), index: 0 }, tag: 'create', valid: true, reason: null }]);
  });

  it('rejects create below the threshold', () => {
    expect(replay([createTx({ rs: [K(1)] })]).verdicts[0]).toMatchObject({ valid: false, reason: 'control policy not satisfied' });
  });

  it('rejects create when a listed key did not sign', () => {
    expect(replay([createTx({ rs: [K(1), K(2)] })]).verdicts[0]).toMatchObject({ valid: false, reason: 'listed key did not sign' });
  });

  it('counts witness keys towards policy and consent', () => {
    expect(replay([createTx({ rs: [], wk: ALL })]).groups.length).toBe(1);
  });

  it('rejects a policy published after its first use', () => {
    const late = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.create(0, C, null)], [ctrl]), rs: ALL });
    const s = replay([createTx({ scripts: false }), late]);
    expect(s.verdicts.map((v) => v.valid)).toEqual([false, true]);
    expect(s.groups.map((g) => g.id.txHash)).toEqual([T(2)]);
  });

  it('ignores phase-2-invalid transactions and wrong versions and records why', () => {
    const invalid = txIn({ hash: T(1), h: 10, valid: false, payload: buildPayload([ev.create(0, C, null)], [ctrl]), rs: ALL });
    const v2 = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.create(0, C, null)], [ctrl], 2), rs: ALL });
    const repeated = txIn({ hash: T(3), h: 12, repeated: true, rs: ALL });
    const repeatedInvalid = txIn({ hash: T(4), h: 13, repeated: true, valid: false, rs: ALL });
    const none = txIn({ hash: T(5), h: 14, rs: ALL });
    const s = replay([invalid, v2, repeated, repeatedInvalid, none]);
    expect(s.groups).toEqual([]);
    expect(s.verdicts).toEqual([]);
    expect(s.scripts.size).toBe(0);
    expect(s.ignored).toEqual([
      { txHash: T(1), reason: 'phase-2 invalid' },
      { txHash: T(2), reason: 'payload rejected' },
      { txHash: T(3), reason: 'label repeated' },
      { txHash: T(4), reason: 'phase-2 invalid' },
    ]);
  });

  it('needs consent of newly listed keys on update, not of removed ones', () => {
    const newCtrl = nOfK(1, sig(K(4)));
    const noConsent = upd(T(2), 11, 0, new Map([[0, kb(hashOf(newCtrl))]]), [K(1), K(2)], [newCtrl]);
    const withConsent = upd(T(3), 12, 0, new Map([[0, kb(hashOf(newCtrl))]]), [K(1), K(2), K(4)]);
    const oldKeys = upd(T(4), 13, 1, new Map(), [K(1), K(2)]);
    const newKey = upd(T(5), 14, 1, new Map(), [K(4)]);
    const s = replay([createTx(), noConsent, withConsent, oldKeys, newKey]);
    expect(s.verdicts.map((v) => v.reason)).toEqual([null, 'newly listed key did not sign', null, 'control policy not satisfied', null]);
    expect(s.groups[0]).toMatchObject({ control: hashOf(newCtrl), seq: 2n });
  });

  it('rejects stale seq', () => {
    const s = replay([createTx(), upd(T(2), 11, 0, new Map(), [K(1), K(3)]), upd(T(3), 12, 0, new Map(), [K(1), K(3)])]);
    expect(s.verdicts.map((v) => v.reason)).toEqual([null, null, 'stale seq']);
    expect(s.groups[0]?.seq).toBe(1n);
  });

  it('rejects an admission policy on an open group and an unresolved new control', () => {
    const add = upd(T(2), 11, 0, new Map([[1, kb(C)]]), ALL);
    const unknown = upd(T(3), 12, 0, new Map([[0, kb(K(9))]]), ALL);
    const s = replay([createTx(), add, unknown]);
    expect(s.verdicts.map((v) => v.reason)).toEqual([null, 'open group has no admission policy', 'new control policy unresolved']);
  });

  it('dissolves without changing seq and rejects later control actions', () => {
    const d = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.dissolve(ref(T(1), 0), 0)]), rs: [K(1), K(2)] });
    const again = txIn({ hash: T(3), h: 12, payload: buildPayload([ev.dissolve(ref(T(1), 0), 0)]), rs: [K(1), K(2)] });
    const s = replay([createTx(), d, again]);
    expect(s.groups[0]).toMatchObject({ status: 'dissolved', seq: 0n });
    expect(s.verdicts[2]).toMatchObject({ valid: false, reason: 'group dissolved' });
  });

  it('expands local refs and rejects refs to the same or later index', () => {
    const p = buildPayload([ev.create(0, C, null), ev.update(local(0), 0, new Map()), ev.update(local(2), 1, new Map())], [ctrl]);
    const s = replay([txIn({ hash: T(1), h: 10, payload: p, rs: ALL })]);
    expect(s.verdicts.map((v) => v.reason)).toEqual([null, null, 'local reference must point to an earlier event']);
  });

  it('orders unsorted input and ignores duplicates', () => {
    const d = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.dissolve(ref(T(1), 0), 0)]), rs: [K(1), K(2)] });
    const once = replay([createTx(), d]);
    const shuffled = replay([d, createTx(), d, createTx()]);
    expect(shuffled.groups).toEqual(once.groups);
    expect(shuffled.verdicts).toEqual(once.verdicts);
    expect(orderInputs([d, createTx(), d]).length).toBe(2);
  });
});

const adm = nOfK(1, sig(K(1)), sig(K(2)));
const A = hashOf(adm);
const permCreate = txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(1, C, A)], [ctrl, adm]), rs: ALL });
const openCreate = createTx();
const M = K(0x50);
const reg = regIn(keyCred(M), T(0x40), 5);
const join = (o: { hash: string; h: number; i?: number; rs?: string[] }) =>
  txIn({ hash: o.hash, h: o.h, i: o.i, payload: buildPayload([ev.join(ref(T(1), 0), 'key', M)]), rs: o.rs ?? [M] });
const act = (kind: 'approve' | 'leave' | 'remove', joinHash: string, hash: string, h: number, rs: string[]) =>
  txIn({ hash, h, payload: buildPayload([ev[kind](ref(joinHash, 0))]), rs });

describe('replay: membership', () => {
  it('open group: join is active at once, leave closes it', () => {
    const s = replay([reg, openCreate, join({ hash: T(2), h: 11 }), act('leave', T(2), T(3), 12, [M])]);
    expect(s.instances).toMatchObject([{ joinId: { txHash: T(2), index: 0 }, state: 'closed', reason: 'left' }]);
  });

  it('permissioned group: pending, approve, remove', () => {
    const s = replay([reg, permCreate, join({ hash: T(2), h: 11 }), act('approve', T(2), T(3), 12, [K(2)]), act('remove', T(2), T(4), 13, [K(1)])]);
    expect(s.verdicts.map((v) => v.reason)).toEqual([null, null, null, null]);
    expect(s.instances[0]).toMatchObject({ state: 'closed', reason: 'removed' });
    expect(s.instances[0]?.approvedAt?.txHash).toBe(T(3));
  });

  it('leave works while pending and needs no group signature', () => {
    const s = replay([reg, permCreate, join({ hash: T(2), h: 11 }), act('leave', T(2), T(3), 12, [M])]);
    expect(s.instances[0]).toMatchObject({ state: 'closed', reason: 'left' });
  });

  it('rejects a key member that only appears as a witness', () => {
    const j = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.join(ref(T(1), 0), 'key', M)]), wk: [M] });
    expect(replay([reg, openCreate, j]).verdicts[1]?.reason).toBe('member key not in required_signers');
  });

  it('rejects join of an unregistered credential and a second open instance', () => {
    expect(replay([openCreate, join({ hash: T(2), h: 11 })]).verdicts[1]?.reason).toBe('not a registered DRep');
    const s = replay([reg, permCreate, join({ hash: T(2), h: 11 }), join({ hash: T(3), h: 12 })]);
    expect(s.verdicts[2]?.reason).toBe('already a member or applicant');
  });

  it('rejects approve after leave, remove in an open group and approve without admission signatures', () => {
    const left = replay([reg, permCreate, join({ hash: T(2), h: 11 }), act('leave', T(2), T(3), 12, [M]), act('approve', T(2), T(4), 13, [K(1)])]);
    expect(left.verdicts[3]?.reason).toBe('join is not pending');
    const open = replay([reg, openCreate, join({ hash: T(2), h: 11 }), act('remove', T(2), T(3), 12, ALL)]);
    expect(open.verdicts[2]?.reason).toBe('open group has no remove');
    const unsigned = replay([reg, permCreate, join({ hash: T(2), h: 11 }), act('approve', T(2), T(3), 12, [K(9)])]);
    expect(unsigned.verdicts[2]?.reason).toBe('admission policy not satisfied');
  });

  it('dissolve closes instances and leave afterwards is rejected', () => {
    const d = txIn({ hash: T(3), h: 12, payload: buildPayload([ev.dissolve(ref(T(1), 0), 0)]), rs: [K(1), K(2)] });
    const s = replay([reg, openCreate, join({ hash: T(2), h: 11 }), d, act('leave', T(2), T(4), 13, [M])]);
    expect(s.instances[0]).toMatchObject({ state: 'closed', reason: 'dissolved' });
    expect(s.verdicts[3]?.reason).toBe('join is not open');
  });

  it('applies certificates before events of the same transaction', () => {
    expect(replay([openCreate, regIn(keyCred(M), T(2), 11), join({ hash: T(2), h: 11 })]).verdicts[1]?.valid).toBe(true);
    expect(replay([reg, openCreate, unregIn(keyCred(M), T(2), 11), join({ hash: T(2), h: 11 })]).verdicts[1]?.reason).toBe('not a registered DRep');
  });

  it('retirement closes instances for good, a new join opens a new one', () => {
    const s = replay([
      reg, openCreate, join({ hash: T(2), h: 11 }),
      unregIn(keyCred(M), T(0x41), 12), regIn(keyCred(M), T(0x42), 13),
      join({ hash: T(3), h: 14 }),
    ]);
    expect(s.instances.map((i) => [i.joinId.txHash, i.state, i.reason])).toEqual([[T(2), 'closed', 'retired'], [T(3), 'active', null]]);
  });

  it('retire then re-register then join inside one block', () => {
    const s = replay([reg, openCreate, unregIn(keyCred(M), T(0x41), 20, 0), regIn(keyCred(M), T(0x42), 20, 1), join({ hash: T(2), h: 20, i: 2 })]);
    expect(s.instances[0]?.state).toBe('active');
  });

  it('founder joins in the create transaction through a local ref', () => {
    const p = buildPayload([ev.create(0, C, null), ev.join(local(0), 'key', M)], [ctrl]);
    const s = replay([reg, txIn({ hash: T(1), h: 10, payload: p, rs: [...ALL, M] })]);
    expect(s.instances[0]).toMatchObject({ group: { txHash: T(1), index: 0 }, state: 'active' });
  });

  it('script DRep member resolves from its registration witness set', () => {
    const ms = allOf(sig(K(0x60)), sig(K(0x61)));
    const SC = hashOf(ms);
    const j = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.join(ref(T(1), 0), 'script', SC)]), wk: [K(0x60), K(0x61)] });
    expect(replay([regIn(scriptCred(SC), T(0x40), 5, 0, [scriptBytes(ms)]), openCreate, j]).verdicts[1]?.valid).toBe(true);
    expect(replay([regIn(scriptCred(SC), T(0x40), 5), openCreate, j]).verdicts[1]?.reason).toBe('member script unresolved');
  });
});
