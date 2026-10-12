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

  it('itemEnd spans tagged items', () => {
    // Tag 1, then int 1: should include both bytes
    expect(itemEnd(hexToBytes('c101'), 0)).toBe(2);
    // Tag 1, then array [1, 2]: should include tag + array
    expect(itemEnd(hexToBytes('d90102820102'), 0)).toBe(6);
    // Array [tag 1, int 1, int 2]: array contains tagged item
    expect(itemEnd(hexToBytes('82c10102'), 0)).toBe(4);
    // Array [tag 1, tag 1, int 1]: nested tags
    expect(itemEnd(hexToBytes('81c1c101'), 0)).toBe(4);
    // Array [tag 256, array [1, 2], int 3]: truncated to show tag is transparent
    const b = hexToBytes('83d9010282010203');
    expect(() => itemEnd(b, 0)).toThrow(); // truncated
  });

  it('handles 5000 levels of nested definite arrays', () => {
    // Each level: 81 (array of 1) + content
    const bytes = hexToBytes('81'.repeat(5000) + '00');
    expect(itemEnd(bytes, 0)).toBe(bytes.length);
  });

  it('handles 5000 levels of nested indefinite arrays', () => {
    // Each level: 9f (indefinite array) + content + ff (break)
    const bytes = hexToBytes('9f'.repeat(5000) + '00' + 'ff'.repeat(5000));
    expect(itemEnd(bytes, 0)).toBe(bytes.length);
  });

  it('requires complete key/value pairs in indefinite maps', () => {
    // Indefinite map with odd number of items (only key, no value) must throw
    expect(() => itemEnd(hexToBytes('bf01ff'), 0)).toThrow();
    // Same in a nested array
    expect(() => itemEnd(hexToBytes('81bf01ff'), 0)).toThrow();
    // Valid indefinite map with complete key/value pair
    expect(itemEnd(hexToBytes('bf0102ff'), 0)).toBe(4);
  });

  it('walks indefinite string chunks without recursion', () => {
    // Indefinite byte string with two definite chunks
    expect(itemEnd(hexToBytes('5f41014102ff'), 0)).toBe(6);
    // Indefinite byte string with nested indefinite chunk must throw
    expect(() => itemEnd(hexToBytes('5f5f4101ffff'), 0)).toThrow();
    // Indefinite byte string with non-byte chunk (int) must throw
    expect(() => itemEnd(hexToBytes('5f01ff'), 0)).toThrow();
    // Indefinite text string with byte chunk must throw (major type mismatch)
    expect(() => itemEnd(hexToBytes('7f4101ff'), 0)).toThrow();
  });

  it('handles 5000 levels of nested indefinite byte strings', () => {
    // Build: 5f (indefinite byte string) + 40 (empty byte string chunk) repeated 5000 times + ff (break)
    const bytes = hexToBytes('5f' + '40'.repeat(5000) + 'ff');
    expect(itemEnd(bytes, 0)).toBe(bytes.length);
  });
});
