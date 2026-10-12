import { encode } from 'cborg';
import { describe, expect, it } from 'vitest';
import { hexToBytes } from '../src/hex.js';
import { collectKeyHashes, evaluateNativeScript, parseNativeScript } from '../src/nativeScript.js';
import type { EvalContext, NativeScript } from '../src/types.js';
import { after, allOf, anyOf, before, K, nOfK, scriptBytes, sig } from './helpers.js';

const ctx = (signers: string[], ib: bigint | null = null, ih: bigint | null = null): EvalContext => ({
  signers: new Set(signers),
  invalidBefore: ib,
  invalidHereafter: ih,
});
const parse = (v: unknown[]): NativeScript => {
  const s = parseNativeScript(scriptBytes(v));
  if (!s) throw new Error('parse failed');
  return s;
};

describe('parseNativeScript', () => {
  it('parses every form', () => {
    expect(parse(allOf(sig(K(1)), anyOf(sig(K(2))), nOfK(1, sig(K(3))), after(10), before(20)))).toEqual({
      type: 'all',
      scripts: [
        { type: 'sig', keyHash: K(1) },
        { type: 'any', scripts: [{ type: 'sig', keyHash: K(2) }] },
        { type: 'nOfK', n: 1n, scripts: [{ type: 'sig', keyHash: K(3) }] },
        { type: 'after', slot: 10n },
        { type: 'before', slot: 20n },
      ],
    });
  });
  it('parses indefinite arrays', () => {
    const b = hexToBytes(`82019f8200581c${'11'.repeat(28)}ff`);
    expect(parseNativeScript(b)).toEqual({ type: 'all', scripts: [{ type: 'sig', keyHash: K(0x11) }] });
  });
  it('accepts a negative n_of_k threshold like the ledger', () => {
    expect(parseNativeScript(encode([3, -1, []]))).toEqual({ type: 'nOfK', n: -1n, scripts: [] });
  });
  it('rejects floats where the CDDL wants integers', () => {
    expect(parseNativeScript(hexToBytes(`82f90000581c${'11'.repeat(28)}`))).toBeNull(); // tag 0.0
    expect(parseNativeScript(hexToBytes('8204f93c00'))).toBeNull(); // after 1.0
    expect(parseNativeScript(hexToBytes('8303f93c0080'))).toBeNull(); // n_of_k 1.0
  });
  it('rejects malformed scripts, tags and trailing bytes', () => {
    expect(parseNativeScript(encode([0, new Uint8Array(27)]))).toBeNull();
    expect(parseNativeScript(encode([9, 1]))).toBeNull();
    expect(parseNativeScript(encode([1]))).toBeNull();
    expect(parseNativeScript(hexToBytes(`c18200581c${'11'.repeat(28)}`))).toBeNull();
    const ok = scriptBytes(sig(K(1)));
    const trailing = new Uint8Array(ok.length + 1);
    trailing.set(ok);
    expect(parseNativeScript(trailing)).toBeNull();
  });
  it('has no nesting limit', () => {
    let v: unknown[] = sig(K(1));
    for (let i = 0; i < 2000; i++) v = allOf(v);
    expect(parseNativeScript(scriptBytes(v))).not.toBeNull();
  });
});

describe('evaluateNativeScript', () => {
  it('evaluates sig, all, any and nOfK', () => {
    expect(evaluateNativeScript(parse(sig(K(1))), ctx([K(1)]))).toBe(true);
    expect(evaluateNativeScript(parse(sig(K(1))), ctx([K(2)]))).toBe(false);
    expect(evaluateNativeScript(parse(allOf()), ctx([]))).toBe(true);
    expect(evaluateNativeScript(parse(anyOf()), ctx([K(1)]))).toBe(false);
    const twoOfThree = parse(nOfK(2, sig(K(1)), sig(K(2)), sig(K(3))));
    expect(evaluateNativeScript(twoOfThree, ctx([K(1)]))).toBe(false);
    expect(evaluateNativeScript(twoOfThree, ctx([K(1), K(3)]))).toBe(true);
    expect(evaluateNativeScript(parse(nOfK(3, sig(K(1)), sig(K(2)))), ctx([K(1), K(2)]))).toBe(false);
    expect(evaluateNativeScript(parse(nOfK(0)), ctx([]))).toBe(true);
    expect(evaluateNativeScript(parse(nOfK(-1)), ctx([]))).toBe(true);
  });
  it('evaluates time locks against the validity interval', () => {
    expect(evaluateNativeScript(parse(after(100)), ctx([], 150n))).toBe(true);
    expect(evaluateNativeScript(parse(after(100)), ctx([], 99n))).toBe(false);
    expect(evaluateNativeScript(parse(after(100)), ctx([], null))).toBe(false);
    expect(evaluateNativeScript(parse(before(100)), ctx([], null, 100n))).toBe(true);
    expect(evaluateNativeScript(parse(before(100)), ctx([], null, 101n))).toBe(false);
    expect(evaluateNativeScript(parse(before(100)), ctx([], null, null))).toBe(false);
  });
  it('collects key hashes in order without duplicates', () => {
    expect(collectKeyHashes(parse(nOfK(1, sig(K(2)), anyOf(sig(K(1)), sig(K(2))))))).toEqual([K(2), K(1)]);
  });
});
