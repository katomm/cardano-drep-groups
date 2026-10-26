import { describe, expect, it } from 'vitest';
import { effectiveClose } from '../src/effective.js';
import type { Pos } from '../src/position.js';

// p(h) is the first event of block h, ev(h, i) event i and cert(h, i) certificate i of the tx at block h.
const ev = (h: number, i: number): Pos => ({ blockHeight: h, txIndex: 0, txHash: 'aa', phase: 2, index: i });
const cert = (h: number, i: number): Pos => ({ blockHeight: h, txIndex: 0, txHash: 'aa', phase: 0, index: i });
const p = (h: number): Pos => ev(h, 0);
const inst = (o: { joined: number; closed?: [number, 'left' | 'removed'] }) => ({
  joinedAt: p(o.joined),
  closedAt: o.closed ? p(o.closed[0]) : null,
  closeReason: o.closed ? o.closed[1] : null,
});

describe('effectiveClose', () => {
  it('takes the earliest of leave, dissolve and unreg after the join', () => {
    expect(effectiveClose(inst({ joined: 10, closed: [20, 'left'] }), p(30), p(25))).toEqual({ at: p(20), reason: 'left' });
    expect(effectiveClose(inst({ joined: 10 }), p(30), p(25))).toEqual({ at: p(25), reason: 'retired' });
    expect(effectiveClose(inst({ joined: 10 }), p(30), null)).toEqual({ at: p(30), reason: 'dissolved' });
    expect(effectiveClose(inst({ joined: 10, closed: [40, 'removed'] }), null, null)).toEqual({ at: p(40), reason: 'removed' });
  });

  it('ignores a dissolve or unreg before the join', () => {
    expect(effectiveClose(inst({ joined: 10 }), p(5), null)).toBeNull();
    expect(effectiveClose(inst({ joined: 10 }), null, p(5))).toBeNull();
    expect(effectiveClose(inst({ joined: 10 }), p(5), p(20))).toEqual({ at: p(20), reason: 'retired' });
  });

  it('orders an unreg in phase 0 before a dissolve in phase 2 of the same tx', () => {
    expect(effectiveClose(inst({ joined: 10 }), ev(30, 0), cert(30, 0))?.reason).toBe('retired');
  });

  it('orders a leave at event 1 before a dissolve at event 2 of the same tx', () => {
    const i = { joinedAt: p(10), closedAt: ev(30, 1), closeReason: 'left' as const };
    expect(effectiveClose(i, ev(30, 2), null)).toEqual({ at: ev(30, 1), reason: 'left' });
  });

  it('bounds every cause by q', () => {
    expect(effectiveClose(inst({ joined: 10 }), p(30), null, p(20))).toBeNull();
    expect(effectiveClose(inst({ joined: 10 }), null, p(30), p(20))).toBeNull();
    expect(effectiveClose(inst({ joined: 10, closed: [30, 'left'] }), null, null, p(20))).toBeNull();
    expect(effectiveClose(inst({ joined: 10, closed: [30, 'left'] }), p(25), null, p(26))).toEqual({ at: p(25), reason: 'dissolved' });
    // q is inclusive
    expect(effectiveClose(inst({ joined: 10 }), p(30), null, p(30))).toEqual({ at: p(30), reason: 'dissolved' });
  });
});
