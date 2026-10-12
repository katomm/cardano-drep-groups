import { describe, expect, it } from 'vitest';
import { orderInputs, replay } from '../src/state.js';
import { buildPayload, ev, hashOf, K, kb, local, nOfK, ref, sig, T, txIn } from './helpers.js';

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
    const s = replay([invalid, v2]);
    expect(s.groups).toEqual([]);
    expect(s.verdicts).toEqual([]);
    expect(s.scripts.size).toBe(0);
    expect(s.ignored).toEqual([{ txHash: T(1), reason: 'phase-2 invalid' }, { txHash: T(2), reason: 'payload rejected' }]);
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
