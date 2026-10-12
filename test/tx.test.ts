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
    const aux = new Tagged(259, new Map([[0, new Map([[1695, payloadValue]])]]));
    const t = decodeTransaction(tx({ aux, plutusData: true }), pos);
    expect(t).toMatchObject({ ...pos, isValid: true, invalidBefore: 4000n, invalidHereafter: 5000n, requiredSigners: [K(7)] });
    expect(t.witnessKeyHashes).toEqual([keyHashOfVkey(vkey)]);
    expect(bytesToHex(t.payload as Uint8Array)).toBe(bytesToHex(payload));
  });
  it('reads Shelley and Shelley-MA auxiliary data', () => {
    expect(bytesToHex(decodeTransaction(tx({ aux: new Map([[1695, payloadValue]]) }), pos).payload as Uint8Array)).toBe(bytesToHex(payload));
    expect(bytesToHex(decodeTransaction(tx({ aux: [new Map([[1695, payloadValue]]), []] }), pos).payload as Uint8Array)).toBe(bytesToHex(payload));
  });
  it('returns undefined payload without auxiliary data, without the label or with the label twice', () => {
    expect(decodeTransaction(tx(), pos).payload).toBeUndefined();
    expect(decodeTransaction(tx({ aux: new Map([[674, 'hi']]) }), pos).payload).toBeUndefined();
    // Shelley metadata map {1695: x, 1695: x}, built by hand since encoders refuse duplicate keys
    const md = concatBytes([hexToBytes('a2'), encode(1695), payload, encode(1695), payload]);
    const raw = concatBytes([hexToBytes('84'), encode(new Map()), encode(new Map()), encode(true), md]);
    expect(decodeTransaction(raw, pos).payload).toBeUndefined();
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
  });
  it('decodes a real mainnet Conway transaction', () => {
    const hex = readFileSync(new URL('./fixtures-survey-tx.hex', import.meta.url), 'utf8').trim();
    const t = decodeTransaction(hexToBytes(hex), pos);
    expect(t.isValid).toBe(true);
    expect(t.requiredSigners.length).toBeGreaterThan(0);
    expect(t.witnessKeyHashes.length).toBeGreaterThan(0);
    expect(t.payload).toBeUndefined(); // label 17, not 1695
  });
});
