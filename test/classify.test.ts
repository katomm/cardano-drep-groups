import { describe, expect, it } from 'vitest';
import { classifyNewInput, foreignJoinRefs, mergeRecovery, RETENTION_FLOOR } from '../src/engine/classify.js';
import { endOf, type Pos } from '../src/position.js';
import type { ChainTx, DecodedPayload } from '../src/types.js';

const pos = (blockHeight: number, txIndex = 0, phase: 0 | 1 | 2 = 2, index = 0): Pos =>
  ({ blockHeight, txIndex, txHash: `t${blockHeight}-${txIndex}`, phase, index });
const L = 10_000;

describe('classifyNewInput', () => {
  it('a label tx below G truncates above the block before it', () => {
    expect(classifyNewInput({ kind: 'labelTx', at: pos(9000) }, { G: endOf(9500), appliedThrough: null, L }))
      .toEqual({ kind: 'truncate', above: 8999 });
  });
  it('a label tx above G is ordinary', () => {
    expect(classifyNewInput({ kind: 'labelTx', at: pos(9600) }, { G: endOf(9500), appliedThrough: null, L })).toBe('ordinary');
  });
  it('a ledger row at applied-through truncates (inclusive)', () => {
    const at = pos(9000, 1, 0, 2);
    expect(classifyNewInput({ kind: 'ledger', at }, { G: endOf(9500), appliedThrough: at, L }))
      .toEqual({ kind: 'truncate', above: 8999 });
  });
  it('a ledger row of a credential without applied inputs is ordinary', () => {
    expect(classifyNewInput({ kind: 'ledger', at: pos(1) }, { G: endOf(9500), appliedThrough: null, L })).toBe('ordinary');
  });
  it('a late row in block L - 2160 opens fork recovery (cut L - 2161 is below the floor)', () => {
    expect(classifyNewInput({ kind: 'labelTx', at: pos(L - RETENTION_FLOOR) }, { G: endOf(L), appliedThrough: null, L }))
      .toEqual({ kind: 'fork' });
  });
  it('a late row in block L - 2159 truncates above L - 2160', () => {
    expect(classifyNewInput({ kind: 'labelTx', at: pos(L - RETENTION_FLOOR + 1) }, { G: endOf(L), appliedThrough: null, L }))
      .toEqual({ kind: 'truncate', above: L - RETENTION_FLOOR });
  });
  it('the first stored tx with G = endOf(-1) is ordinary', () => {
    expect(classifyNewInput({ kind: 'labelTx', at: pos(0) }, { G: endOf(-1), appliedThrough: null, L: 5 })).toBe('ordinary');
  });
});

describe('mergeRecovery', () => {
  const t = (above: number) => ({ kind: 'truncate' as const, above });
  it('keeps the lower truncation and lets fork replace both slots', () => {
    let s = mergeRecovery({ first: null, then: null }, t(50));
    s = mergeRecovery(s, t(70));
    expect(s).toEqual({ first: t(50), then: null });
    s = mergeRecovery(s, t(40));
    expect(s.first).toEqual(t(40));
    expect(mergeRecovery({ first: { kind: 'rebuild' }, then: t(5) }, { kind: 'fork' })).toEqual({ first: { kind: 'fork' }, then: null });
  });
  it('a truncation opened during a rebuild runs after it', () => {
    let s = mergeRecovery({ first: { kind: 'rebuild' }, then: null }, t(80));
    expect(s).toEqual({ first: { kind: 'rebuild' }, then: t(80) });
    s = mergeRecovery(s, t(60));
    expect(s.then).toEqual(t(60));
    s = mergeRecovery(s, t(90));
    expect(s.then).toEqual(t(60));
    expect(mergeRecovery(s, { kind: 'rebuild' })).toEqual(s);
  });
  it('a rebuild requested during a truncation keeps both, rebuild first', () => {
    expect(mergeRecovery({ first: t(30), then: null }, { kind: 'rebuild' })).toEqual({ first: { kind: 'rebuild' }, then: t(30) });
  });
  it('anything after a fork is absorbed', () => {
    const s = { first: { kind: 'fork' as const }, then: null };
    expect(mergeRecovery(s, t(1))).toEqual(s);
  });
});

describe('foreignJoinRefs', () => {
  it('returns unique refs to other txs only', () => {
    const tx = { txHash: 'aa' } as ChainTx;
    const ok = (event: object) => ({ ok: true as const, event: event as never });
    const decoded: DecodedPayload = {
      scripts: [],
      events: [
        ok({ tag: 'approve', join: { txHash: 'bb', index: 1 } }),
        ok({ tag: 'leave', join: { txHash: 'bb', index: 1 } }),
        ok({ tag: 'remove', join: { txHash: 'cc', index: 0 } }),
        ok({ tag: 'approve', join: { local: 0 } }),
        ok({ tag: 'approve', join: { txHash: 'aa', index: 2 } }),
        ok({ tag: 'join', group: { txHash: 'dd', index: 0 }, member: { kind: 'key', hash: 'ee' } }),
        { ok: false as const, reason: 'x' },
      ],
    };
    expect(foreignJoinRefs(tx, decoded)).toEqual([{ txHash: 'bb', index: 1 }, { txHash: 'cc', index: 0 }]);
  });
});
