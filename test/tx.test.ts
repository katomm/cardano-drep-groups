import { readFileSync } from 'node:fs';
import {
  Address, Assets, ScriptRef, Transaction, TransactionBody, TransactionHash, TransactionInput, TransactionWitnessSet, TxOut,
} from '@evolution-sdk/evolution';
import { decode, encode, Tagged } from 'cborg';
import { describe, expect, it } from 'vitest';
import { keyHashOfVkey } from '../src/hash.js';
import { bytesToHex, concatBytes, hexToBytes } from '../src/hex.js';
import { replay } from '../src/state.js';
import { decodeTransaction, decodeTxRefs, type TxIn } from '../src/tx.js';
import { allOf, buildPayload, ev, hashOf, K, ref, regIn, scriptBytes, scriptCred, scriptRefOf, sig, T, txIn } from './helpers.js';

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

// Transactions built with Evolution: inputs and reference inputs in the set tag 258,
// outputs as arrays without a script_ref and as maps with one.
const addr = Address.fromHex(`61${'11'.repeat(28)}`);
// The SDK takes the content of the tag 24 byte string, [language, script].
const evoOut = (scriptRef?: Uint8Array) =>
  new TxOut.TransactionOutput({
    address: addr, assets: Assets.fromLovelace(2_000_000n), ...(scriptRef ? { scriptRef: new ScriptRef.ScriptRef({ bytes: scriptRef }) } : {}),
  });
const evoIn = (i: TxIn) => new TransactionInput.TransactionInput({ transactionId: TransactionHash.fromHex(i.txHash), index: BigInt(i.index) });
function evoTx(o: { inputs: TxIn[]; refs?: TxIn[]; outputs: TxOut.TransactionOutput[] }): Uint8Array {
  const body = new TransactionBody.TransactionBody({
    inputs: o.inputs.map(evoIn), outputs: o.outputs, fee: 0n, ...(o.refs ? { referenceInputs: o.refs.map(evoIn) as [TransactionInput.TransactionInput] } : {}),
  });
  return Transaction.toCBORBytes(new Transaction.Transaction({ body, witnessSet: new TransactionWitnessSet.TransactionWitnessSet({}), isValid: true, auxiliaryData: null }));
}
const nativeContent = (s: unknown[]) => concatBytes([hexToBytes('8200'), scriptBytes(s)]);

describe('decodeTxRefs', () => {
  const ms = allOf(sig(K(0x60)), sig(K(0x61)));
  const plutus = new Uint8Array([0x4d, 1, 2, 3]);

  it('exposes inputs, reference inputs and output script refs of an Evolution transaction', () => {
    const raw = evoTx({
      inputs: [{ txHash: T(0xa1), index: 3 }, { txHash: T(0xa2), index: 0 }],
      refs: [{ txHash: T(0xa3), index: 7 }],
      outputs: [evoOut(nativeContent(ms)), evoOut(), evoOut(encode([2, plutus]))],
    });
    const r = decodeTxRefs(raw);
    expect(new Set(r.inputs.map((i) => `${i.txHash}#${i.index}`))).toEqual(new Set([`${T(0xa1)}#3`, `${T(0xa2)}#0`]));
    expect(r.referenceInputs).toEqual([{ txHash: T(0xa3), index: 7 }]);
    expect(r.outputScriptRefs.map((x) => (x ? bytesToHex(x) : null))).toEqual([
      bytesToHex(scriptRefOf(0, scriptBytes(ms))), null, bytesToHex(scriptRefOf(2, plutus)),
    ]);
  });

  it('reads plain input arrays, legacy array outputs and a pre-Alonzo envelope', () => {
    const legacyOut = [hexToBytes(`61${'11'.repeat(28)}`), 1_000_000];
    const mapOut = new Map<number, unknown>([[0, hexToBytes(`61${'11'.repeat(28)}`)], [1, 2_000_000], [3, new Tagged(24, nativeContent(ms))]]);
    const body = new Map<number, unknown>([[0, [[hexToBytes(T(0xb1)), 1]]], [1, [legacyOut, mapOut]], [2, 0], [18, [[hexToBytes(T(0xb2)), 2]]]]);
    for (const raw of [encode([body, new Map(), true, null]), encode([body, new Map(), null])]) {
      const r = decodeTxRefs(raw);
      expect(r.inputs).toEqual([{ txHash: T(0xb1), index: 1 }]);
      expect(r.referenceInputs).toEqual([{ txHash: T(0xb2), index: 2 }]);
      expect(r.outputScriptRefs.map((x) => (x ? bytesToHex(x) : null))).toEqual([null, bytesToHex(scriptRefOf(0, scriptBytes(ms)))]);
    }
    expect(decodeTxRefs(encode([new Map([[2, 0]]), new Map(), true, null]))).toEqual({ inputs: [], referenceInputs: [], outputScriptRefs: [] });
  });

  it('throws on bytes that are not a transaction', () => {
    expect(() => decodeTxRefs(encode([1, 2]))).toThrow();
    expect(() => decodeTxRefs(concatBytes([encode([new Map(), new Map(), true, null]), hexToBytes('00')]))).toThrow();
  });
});

// The indexer side of the division of labour: the reference scripts of a registration are
// the script_refs of the outputs its inputs and reference inputs point to, each looked up
// in its producing transaction by output index.
function referenceScriptsOf(registration: Uint8Array, producers: Map<string, Uint8Array>): Uint8Array[] {
  const r = decodeTxRefs(registration);
  return [...r.inputs, ...r.referenceInputs].flatMap((i) => {
    const producer = producers.get(i.txHash);
    const s = producer ? decodeTxRefs(producer).outputScriptRefs[i.index] : null;
    return s ? [s] : [];
  });
}

describe('replay with reference scripts found through decodeTxRefs', () => {
  const ms = allOf(sig(K(0x60)), sig(K(0x61)));
  const SC = hashOf(ms);
  const P = T(0x50);
  // The producing transaction carries the member script on output 0 only.
  const producers = new Map([[P, evoTx({ inputs: [{ txHash: T(0x51), index: 0 }], outputs: [evoOut(nativeContent(ms)), evoOut()] })]]);
  const create = txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(0, hashOf(sig(K(0x70))), null)], [sig(K(0x70))]), rs: [K(0x70)] });
  const join = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.join(ref(T(1), 0), 'script', SC)]), wk: [K(0x60), K(0x61)] });
  const run = (registration: Uint8Array) => {
    const refs = referenceScriptsOf(registration, producers);
    return { refs, verdict: replay([regIn(scriptCred(SC), T(0x40), 5, 0, undefined, refs), create, join]).verdicts[1] };
  };

  it('accepts the join when the registration spends the output with the script', () => {
    const { refs, verdict } = run(evoTx({ inputs: [{ txHash: P, index: 0 }], outputs: [evoOut()] }));
    expect(refs).toHaveLength(1);
    expect(verdict).toMatchObject({ valid: true, reason: null });
  });

  it('accepts the join when the registration uses the output as a reference input', () => {
    const { refs, verdict } = run(evoTx({ inputs: [{ txHash: T(0x52), index: 0 }], refs: [{ txHash: P, index: 0 }], outputs: [evoOut()] }));
    expect(refs).toHaveLength(1);
    expect(verdict).toMatchObject({ valid: true, reason: null });
  });

  it('rejects the join when the script sits on another output of the producing transaction', () => {
    const { refs, verdict } = run(evoTx({ inputs: [{ txHash: P, index: 1 }], outputs: [evoOut()] }));
    expect(refs).toEqual([]);
    expect(verdict).toMatchObject({ valid: false, reason: 'member script unresolved' });
  });
});
