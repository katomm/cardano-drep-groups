import { readFileSync } from 'node:fs';
import { decode, encode, Tagged } from 'cborg';
import { describe, expect, it } from 'vitest';
import { keyHashOfVkey } from '../src/hash.js';
import { bytesToHex, concatBytes, hexToBytes } from '../src/hex.js';
import { decodeTransaction } from '../src/tx.js';
import { allOf, buildPayload, ev, K, scriptBytes, sig, T } from './helpers.js';

const pos = { txHash: T(1), blockHeight: 100, txIndex: 2 };
const vkey = new Uint8Array(32).fill(0x33);
const payload = buildPayload([ev.create(0, K(1), null)]);
const payloadValue = decode(payload, { useMaps: true });

function tx(opts: { aux?: unknown; valid?: boolean; plutusData?: boolean; witnessScripts?: unknown[] } = {}): Uint8Array {
  const body = new Map<number, unknown>([
    [0, new Tagged(258, [[new Uint8Array(32), 0]])],
    [1, []],
    [2, 170000],
    [3, 5000],
    [8, 4000],
    [14, new Tagged(258, [hexToBytes(K(7))])],
  ]);
  const wits = new Map<number, unknown>([[0, new Tagged(258, [[vkey, new Uint8Array(64)]])]]);
  if (opts.witnessScripts) wits.set(1, opts.witnessScripts);
  if (opts.plutusData) wits.set(4, [new Tagged(121, [1, 2])]);
  return encode([body, wits, opts.valid ?? true, opts.aux === undefined ? null : opts.aux]);
}

describe('decodeTransaction', () => {
  it('decodes a Conway tx with set tags and a plutus data tag', () => {
    const aux = new Tagged(259, new Map([[0, new Map([[8416, payloadValue]])]]));
    const t = decodeTransaction(tx({ aux, plutusData: true }), pos);
    expect(t).toMatchObject({ ...pos, isValid: true, invalidBefore: 4000n, invalidHereafter: 5000n, requiredSigners: [K(7)] });
    expect(t.witnessKeyHashes).toEqual([keyHashOfVkey(vkey)]);
    expect(bytesToHex(t.payload as Uint8Array)).toBe(bytesToHex(payload));
  });
  it('reads Shelley and Shelley-MA auxiliary data', () => {
    expect(bytesToHex(decodeTransaction(tx({ aux: new Map([[8416, payloadValue]]) }), pos).payload as Uint8Array)).toBe(bytesToHex(payload));
    expect(bytesToHex(decodeTransaction(tx({ aux: [new Map([[8416, payloadValue]]), []] }), pos).payload as Uint8Array)).toBe(bytesToHex(payload));
  });
  it('returns undefined payload without auxiliary data, without the label or with the label twice', () => {
    expect(decodeTransaction(tx(), pos).payload).toBeUndefined();
    expect(decodeTransaction(tx({ aux: new Map([[674, 'hi']]) }), pos).payload).toBeUndefined();
    // Shelley metadata map {8416: x, 8416: x}, built by hand since encoders refuse duplicate keys
    const md = concatBytes([hexToBytes('a2'), encode(8416), payload, encode(8416), payload]);
    const raw = concatBytes([hexToBytes('84'), encode(new Map()), encode(new Map()), encode(true), md]);
    expect(decodeTransaction(raw, pos).payload).toBeUndefined();
  });
  it('flags a repeated label', () => {
    const md = concatBytes([hexToBytes('a2'), encode(8416), payload, encode(8416), payload]);
    const raw = concatBytes([hexToBytes('84'), encode(new Map()), encode(new Map()), encode(true), md]);
    expect(decodeTransaction(raw, pos).payloadRepeated).toBe(true);
    expect(decodeTransaction(tx({ aux: new Map([[8416, payloadValue]]) }), pos).payloadRepeated).toBe(false);
  });
  it('does not overflow on a deep value under another label', () => {
    // 3000 nested arrays under label 674, built by hand since encoders overflow at that depth
    const deep = new Uint8Array(3000).fill(0x81);
    deep[2999] = 0x80;
    const md = concatBytes([hexToBytes('a2'), encode(674), deep, encode(8416), payload]);
    const aux = concatBytes([hexToBytes('d90103'), hexToBytes('a1'), encode(0), md]);
    const body = encode(new Map<number, unknown>([[14, new Tagged(258, [hexToBytes(K(7))])]]));
    const raw = concatBytes([hexToBytes('84'), body, encode(new Map()), encode(true), aux]);
    const t = decodeTransaction(raw, pos);
    expect(bytesToHex(t.payload as Uint8Array)).toBe(bytesToHex(payload));
    expect(t.requiredSigners).toEqual([K(7)]);
  });
  it('reads an indefinite-length metadata map', () => {
    const md = concatBytes([hexToBytes('bf'), encode(674), encode('hi'), encode(8416), payload, hexToBytes('ff')]);
    const raw = concatBytes([hexToBytes('84'), encode(new Map()), encode(new Map()), encode(true), md]);
    expect(bytesToHex(decodeTransaction(raw, pos).payload as Uint8Array)).toBe(bytesToHex(payload));
  });
  it('reads required_signers with and without the set tag', () => {
    const withBody = (signers: unknown) => encode([new Map<number, unknown>([[14, signers]]), new Map(), true, null]);
    expect(decodeTransaction(withBody(new Tagged(258, [hexToBytes(K(7)), hexToBytes(K(8))])), pos).requiredSigners).toEqual([K(7), K(8)]);
    expect(decodeTransaction(withBody([hexToBytes(K(7)), hexToBytes(K(8))]), pos).requiredSigners).toEqual([K(7), K(8)]);
  });
  it('reads unwrapped vkey witnesses and keeps uint64 validity bounds', () => {
    const raw = encode([new Map<number, unknown>([[3, 2n ** 64n - 1n]]), new Map([[0, [[vkey, new Uint8Array(64)]]]]), true, null]);
    const t = decodeTransaction(raw, pos);
    expect(t.witnessKeyHashes).toEqual([keyHashOfVkey(vkey)]);
    expect(t.invalidHereafter).toBe(2n ** 64n - 1n);
    expect(t.invalidBefore).toBeNull();
  });
  it('keeps is_valid false', () => {
    expect(decodeTransaction(tx({ valid: false }), pos).isValid).toBe(false);
  });
  it('cuts witness scripts out by exact bytes', () => {
    const script = allOf(sig(K(1)), sig(K(2)));
    const t = decodeTransaction(tx({ witnessScripts: [script] }), pos);
    expect(t.witnessScripts.map(bytesToHex)).toEqual([bytesToHex(scriptBytes(script))]);
  });
  it('throws on bytes that are not a transaction', () => {
    expect(() => decodeTransaction(encode([1, 2]), pos)).toThrow();
    expect(() => decodeTransaction(encode([new Map(), new Map(), 1, null]), pos)).toThrow();
    expect(() => decodeTransaction(concatBytes([tx(), hexToBytes('00')]), pos)).toThrow();
    expect(() => decodeTransaction(tx().subarray(0, 20), pos)).toThrow();
  });
  it('decodes a real mainnet Conway transaction', () => {
    const hex = readFileSync(new URL('./fixtures-survey-tx.hex', import.meta.url), 'utf8').trim();
    const t = decodeTransaction(hexToBytes(hex), pos);
    expect(t.isValid).toBe(true);
    expect(t.requiredSigners.length).toBeGreaterThan(0);
    expect(t.witnessKeyHashes.length).toBeGreaterThan(0);
    expect(t.payload).toBeUndefined(); // label 17, not 8416
  });
});
