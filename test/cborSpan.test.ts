import { encode } from 'cborg';
import { describe, expect, it } from 'vitest';
import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead, readUint, skipTags } from '../src/cborSpan.js';
import { hexToBytes } from '../src/hex.js';

describe('cborSpan', () => {
  it('finds the end of definite items', () => {
    const b = encode([1, new Uint8Array([1, 2, 3]), 'abc', [true, null]]);
    expect(itemEnd(b, 0)).toBe(b.length);
  });

  it('returns the exact span of an indefinite-length item', () => {
    // all [sig 11..]: 0x82 0x01 0x9f <sig> 0xff, followed by a trailing 0x00
    const sig = `8200581c${'11'.repeat(28)}`;
    const b = hexToBytes(`82019f${sig}ff00`);
    expect(itemEnd(b, 0)).toBe(b.length - 1);
  });

  it('lists array items and map entries', () => {
    const b = encode([10, 20, 30]);
    expect(arrayItemOffsets(b, 0).map((o) => readUint(b, o))).toEqual([10, 20, 30]);
    const m = encode(new Map<number, number>([[1, 5], [2, 6]]));
    expect(mapEntryOffsets(m, 0).map(([k, v]) => [readUint(m, k), readUint(m, v)])).toEqual([[1, 5], [2, 6]]);
  });

  it('reads 64-bit arguments exactly', () => {
    const b = encode(2n ** 64n - 1n);
    expect(readHead(b, 0)).toMatchObject({ major: 0, big: 2n ** 64n - 1n });
    expect(readHead(hexToBytes('20'), 0)).toMatchObject({ major: 1, big: 0n }); // -1
  });

  it('skips tags', () => {
    const b = hexToBytes('d90102820102'); // tag 258 [1, 2]
    expect(skipTags(b, 0)).toBe(3);
    expect(arrayItemOffsets(b, skipTags(b, 0)).length).toBe(2);
  });

  it('throws on truncated input and stray breaks', () => {
    expect(() => itemEnd(hexToBytes('830102'), 0)).toThrow();
    expect(() => itemEnd(hexToBytes('58030102'), 0)).toThrow();
    expect(() => itemEnd(hexToBytes('ff'), 0)).toThrow();
  });

  it('rejects indefinite maps with odd number of items', () => {
    expect(() => mapEntryOffsets(hexToBytes('bf01ff'), 0)).toThrow();
  });

  it('accepts indefinite maps with even number of items', () => {
    const b = hexToBytes('bf0102ff');
    expect(mapEntryOffsets(b, 0)).toEqual([[1, 2]]);
  });
});
