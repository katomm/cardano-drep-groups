import { describe, expect, it } from 'vitest';
import { afterTx, comparePos, endOf, isEnd, maxPos, minPos, posOfCert, posOfEvent, posOfScripts } from '../src/position.js';
import { K, keyCred, T } from './helpers.js';

describe('positions', () => {
  it('orders certificates before scripts before events, then by index', () => {
    const tx = { txHash: T(1), blockHeight: 10, txIndex: 2 };
    const c = posOfCert({ kind: 'reg', credential: keyCred(K(1)), txHash: T(1), blockHeight: 10, txIndex: 2, certIndex: 3 });
    expect([posOfEvent(tx, 0), posOfScripts(tx), c].sort(comparePos)).toEqual([c, posOfScripts(tx), posOfEvent(tx, 0)]);
    expect(comparePos(posOfEvent(tx, 1), posOfEvent(tx, 2))).toBeLessThan(0);
    expect(comparePos(posOfEvent(tx, 63), posOfEvent({ ...tx, txIndex: 3 }, 0))).toBeLessThan(0);
  });

  it('puts END(h) after every position of h and before h + 1', () => {
    expect(comparePos(posOfEvent({ txHash: T(1), blockHeight: 7, txIndex: 9999 }, 63), endOf(7))).toBeLessThan(0);
    expect(comparePos(endOf(7), posOfCert({ kind: 'reg', credential: keyCred(K(1)), txHash: T(2), blockHeight: 8, txIndex: 0, certIndex: 0 }))).toBeLessThan(0);
    expect(comparePos(afterTx({ txHash: T(1), blockHeight: 7, txIndex: 9999 }), endOf(7))).toBeLessThan(0);
    expect(endOf(7)).toEqual({ blockHeight: 7, txIndex: Number.MAX_SAFE_INTEGER, txHash: '', phase: 2, index: Number.MAX_SAFE_INTEGER });
    expect(isEnd(endOf(7))).toBe(true);
    expect(isEnd(posOfEvent({ txHash: T(1), blockHeight: 7, txIndex: 0 }, 0))).toBe(false);
  });

  it('ignores the tx hash in the order', () => {
    expect(comparePos(posOfEvent({ txHash: T(1), blockHeight: 7, txIndex: 0 }, 0), posOfEvent({ txHash: T(2), blockHeight: 7, txIndex: 0 }, 0))).toBe(0);
  });

  it('places afterTx after every event of the tx and before the next tx', () => {
    const tx = { txHash: T(1), blockHeight: 5, txIndex: 1 };
    expect(afterTx(tx)).toEqual({ ...tx, phase: 2, index: Number.MAX_SAFE_INTEGER });
    expect(comparePos(posOfEvent(tx, 63), afterTx(tx))).toBeLessThan(0);
    expect(comparePos(afterTx(tx), posOfScripts({ txHash: T(2), blockHeight: 5, txIndex: 2 }))).toBeLessThan(0);
  });

  it('builds positions with all five fields and picks min and max', () => {
    const tx = { txHash: T(1), blockHeight: 5, txIndex: 1 };
    expect(posOfScripts(tx)).toEqual({ ...tx, phase: 1, index: -1 });
    expect(posOfEvent(tx, 4)).toEqual({ ...tx, phase: 2, index: 4 });
    expect(posOfCert({ kind: 'unreg', credential: keyCred(K(1)), ...tx, certIndex: 2 })).toEqual({ ...tx, phase: 0, index: 2 });
    const a = posOfEvent(tx, 0);
    const b = endOf(5);
    expect(minPos(a, b)).toBe(a);
    expect(minPos(b, a)).toBe(a);
    expect(maxPos(a, b)).toBe(b);
    expect(maxPos(b, a)).toBe(b);
  });
});
