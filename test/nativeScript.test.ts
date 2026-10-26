import { encode } from 'cborg';
import { describe, expect, it } from 'vitest';
import { hexToBytes } from '../src/hex.js';
import { collectKeyHashes, evaluateNativeScript, memberScriptWitness, parseNativeScript } from '../src/nativeScript.js';
import type { EvalContext, NativeScript } from '../src/types.js';
import { after, allOf, anyOf, before, hashOf, K, keyCred, nOfK, scriptBytes, scriptCred, sig } from './helpers.js';

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
  it('accepts int64 thresholds and uint64 slots at their bounds', () => {
    expect(parseNativeScript(hexToBytes('83033b7fffffffffffffff80'))).toEqual({ type: 'nOfK', n: -(2n ** 63n), scripts: [] });
    expect(parseNativeScript(hexToBytes('83031b7fffffffffffffff80'))).toEqual({ type: 'nOfK', n: 2n ** 63n - 1n, scripts: [] });
    expect(parseNativeScript(hexToBytes('82041bffffffffffffffff'))).toEqual({ type: 'after', slot: 2n ** 64n - 1n });
    expect(parseNativeScript(hexToBytes('820180'))).toEqual({ type: 'all', scripts: [] });
    expect(parseNativeScript(hexToBytes('82019fff'))).toEqual({ type: 'all', scripts: [] });
    expect(parseNativeScript(hexToBytes('9f019fffff'))).toEqual({ type: 'all', scripts: [] });
    expect(parseNativeScript(hexToBytes('9f0180ff'))).toEqual({ type: 'all', scripts: [] });
  });

  it('rejects edge case encodings', () => {
    const k = '11'.repeat(28);
    const cases = [
      '', // empty input
      '80', // empty array
      '9fff', // empty indefinite array
      `8200581c${k}00`, // trailing byte
      `8200581b${k.slice(2)}`, // 27 byte key hash
      `8200581c${k.slice(2)}`, // truncated key hash
      `9f00581c${k}00ff`, // extra item in an indefinite sig
      `9f00581c${k}`, // missing break
      `82005f581c${k}ff`, // indefinite byte string as key hash
      '8303208000', // trailing byte after n_of_k
      '83033b800000000000000080', // threshold below int64
      '83031b800000000000000080', // threshold above int64
      '820520', // negative slot
      '820181', // truncated nested script
      '82019f', // unterminated indefinite list
      '9f018000ff', // extra item in an indefinite all
      '82069f', // unknown script tag
      '8201bf', // map where the list belongs
      'c1820180', // tagged script
      '82018180', // empty array as nested script
      '9b0000000000000002820180', // script array length in eight bytes
      '83039b00000000000000030180', // script list length in eight bytes
      '820199ffff', // list length past the input
      '82019bffffffffffffffff', // list length past the safe integer range
    ];
    for (const h of cases) expect(parseNativeScript(hexToBytes(h)), h).toBeNull();
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
  // so parsing must stay linear in the input size. A quadratic parser needs
  // seconds at these depths, the bound leaves room for a busy machine.
  it.each([5000, 10000])('parses %i levels in linear time', (depth) => {
    const sigHex = `8200581c${'11'.repeat(28)}`;
    const deep = hexToBytes(`${'820181'.repeat(depth)}${sigHex}`);
    const deepIndefinite = hexToBytes(`${'9f019f'.repeat(depth)}${sigHex}${'ffff'.repeat(depth)}`);
    const start = performance.now();
    const a = parseNativeScript(deep);
    const b = parseNativeScript(deepIndefinite);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1000);
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

describe('memberScriptWitness', () => {
  const member = allOf(sig(K(1)), sig(K(2)));
  const c = scriptCred(hashOf(member));

  it('takes the witness whose hash is the credential hash and that parses', () => {
    const other = scriptBytes(sig(K(3)));
    expect(memberScriptWitness(c, [other, scriptBytes(member)])).toEqual({ script: parse(member), bytes: scriptBytes(member) });
  });

  it('gives null without a matching witness, for a key credential and for unparsable bytes', () => {
    expect(memberScriptWitness(c, [scriptBytes(sig(K(3)))])).toBeNull();
    expect(memberScriptWitness(c, undefined)).toBeNull();
    expect(memberScriptWitness(keyCred(hashOf(member)), [scriptBytes(member)])).toBeNull();
    const bad = scriptBytes([9, 1] as never);
    expect(memberScriptWitness(scriptCred(hashOf([9, 1] as never)), [bad])).toBeNull();
  });
});
