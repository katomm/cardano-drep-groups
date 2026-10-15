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
  it('parses a sig script written as an indefinite array', () => {
    const b = hexToBytes(`9f00581c${'11'.repeat(28)}ff`);
    expect(parseNativeScript(b)).toEqual({ type: 'sig', keyHash: K(0x11) });
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
    const sigHex = `8200581c${'11'.repeat(28)}`;
    const bytes = hexToBytes(`${'820181'.repeat(2000)}${sigHex}`);
    const script = parseNativeScript(bytes);
    expect(script).not.toBeNull();
    expect(evaluateNativeScript(script!, ctx([K(0x11)]))).toBe(true);
    expect(evaluateNativeScript(script!, ctx([]))).toBe(false);
    expect(collectKeyHashes(script!)).toEqual([K(0x11)]);
  });

  it('handles 5000 levels of nesting', () => {
    const sigHex = `8200581c${'11'.repeat(28)}`;
    const bytes = hexToBytes(`${'820181'.repeat(5000)}${sigHex}`);
    const script = parseNativeScript(bytes);
    expect(script).not.toBeNull();
    expect(evaluateNativeScript(script!, ctx([K(0x11)]))).toBe(true);
    expect(evaluateNativeScript(script!, ctx([]))).toBe(false);
    expect(collectKeyHashes(script!)).toEqual([K(0x11)]);
  });

  // A crafted script at the transaction size limit reaches about 5000 levels,
  // so parsing must stay linear in the input size.
  it.each([5000, 10000])('parses %i levels in linear time', (depth) => {
    const sigHex = `8200581c${'11'.repeat(28)}`;
    const deep = hexToBytes(`${'820181'.repeat(depth)}${sigHex}`);
    const deepIndefinite = hexToBytes(`${'9f019f'.repeat(depth)}${sigHex}${'ffff'.repeat(depth)}`);
    const start = performance.now();
    const a = parseNativeScript(deep);
    const b = parseNativeScript(deepIndefinite);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(500);
    // Walk both results by hand, a deep equality matcher would recurse.
    let x = a;
    let y = b;
    for (let i = 0; i < depth; i++) {
      expect(x?.type === 'all' && x.scripts.length === 1).toBe(true);
      expect(y?.type === 'all' && y.scripts.length === 1).toBe(true);
      x = x?.type === 'all' ? x.scripts[0]! : null;
      y = y?.type === 'all' ? y.scripts[0]! : null;
    }
    expect(x).toEqual({ type: 'sig', keyHash: K(0x11) });
    expect(y).toEqual({ type: 'sig', keyHash: K(0x11) });
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
