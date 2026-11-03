import { AuxiliaryData, Transaction, TransactionBody, TransactionMetadatum, TransactionWitnessSet } from '@evolution-sdk/evolution';
import { blake2b } from '@noble/hashes/blake2.js';
import { decode, encode, Tagged } from 'cborg';
import { describe, expect, it } from 'vitest';
import { bytesToHex, concatBytes, hexToBytes } from '../src/hex.js';
import { inspectTransaction } from '../src/txFacts.js';
import { buildPayload, ev, K } from './helpers.js';

const payload = buildPayload([ev.create(0, K(1), null)]);
const payloadValue = decode(payload, { useMaps: true });
const h32 = (b: Uint8Array) => blake2b(b, { dkLen: 32 });

// Assembles [body, wits, true, aux] by hand. The aux item is passed as raw bytes
// so the hash covers its exact encoded span.
function tx(opts: { aux?: Uint8Array | null; hashOf?: Uint8Array; extra?: Array<[number, unknown]> } = {}): Uint8Array {
  const aux = opts.aux ?? null;
  const body = new Map<number, unknown>([[0, new Tagged(258, [[new Uint8Array(32), 0]])], [1, []], [2, 170000]]);
  const hashed = opts.hashOf ?? aux;
  if (hashed) body.set(7, h32(hashed));
  for (const [k, v] of opts.extra ?? []) body.set(k, v);
  return concatBytes([hexToBytes('84'), encode(body), encode(new Map()), encode(true), aux ?? encode(null)]);
}

const metadata = (label = 8416) => encode(new Map([[label, payloadValue]]));
const tagged = (label = 8416) => concatBytes([hexToBytes('d90103a100'), metadata(label)]);

describe('inspectTransaction on Evolution transactions', () => {
  const labelMap = new Map([[8416n, TransactionMetadatum.fromCBORBytes(payload)]]);
  const forms = {
    conway: AuxiliaryData.conway({ metadata: labelMap }),
    shelleyMA: AuxiliaryData.shelleyMA({ metadata: labelMap }),
    shelley: AuxiliaryData.shelley({ metadata: labelMap }),
  };
  const build = (aux: AuxiliaryData.AuxiliaryData, hashOf: AuxiliaryData.AuxiliaryData = aux) =>
    Transaction.toCBORBytes(
      new Transaction.Transaction({
        body: new TransactionBody.TransactionBody({ inputs: [], outputs: [], fee: 0n, auxiliaryDataHash: AuxiliaryData.toHash(hashOf) }),
        witnessSet: new TransactionWitnessSet.TransactionWitnessSet({}),
        isValid: true,
        auxiliaryData: aux,
      }),
    );
  for (const [name, aux] of Object.entries(forms)) {
    it(`binds and counts the ${name} auxiliary data form`, () => {
      expect(inspectTransaction(build(aux))).toMatchObject({ auxHashMatches: true, groupPayloads: 1 });
    });
  }
  it('detects an Evolution transaction whose auxiliary data was swapped', () => {
    const other = AuxiliaryData.conway({ metadata: new Map([[674n, TransactionMetadatum.fromCBORBytes(payload)]]) });
    expect(inspectTransaction(build(forms.conway, other))).toMatchObject({ auxHashMatches: false, groupPayloads: 1 });
  });
});

describe('inspectTransaction', () => {
  it('binds the auxiliary data to the body hash in every form', () => {
    for (const aux of [metadata(), encode([new Map([[8416, payloadValue]]), []]), tagged()]) {
      const f = inspectTransaction(tx({ aux }));
      expect(f.auxHashMatches).toBe(true);
      expect(f.auxDataHash).toBe(bytesToHex(h32(aux)));
    }
  });
  it('detects auxiliary data that does not match the body hash', () => {
    expect(inspectTransaction(tx({ aux: metadata(), hashOf: metadata(674) })).auxHashMatches).toBe(false);
  });
  it('is false when either side is missing', () => {
    const stripped = inspectTransaction(concatBytes([hexToBytes('84'), encode(new Map([[2, 1]])), encode(new Map()), encode(true), metadata()]));
    expect(stripped).toMatchObject({ auxDataHash: null, auxHashMatches: false });
    const noAux = inspectTransaction(tx({ hashOf: metadata() }));
    expect(noAux.auxHashMatches).toBe(false);
    expect(noAux.groupPayloads).toBe(0);
  });
  it('reports certificates, withdrawals, votes and proposals', () => {
    const plain = inspectTransaction(tx());
    expect(plain).toMatchObject({ hasCertificates: false, hasWithdrawals: false, hasVotes: false, hasProposals: false });
    const cert = [new Tagged(258, [[8, new Uint8Array(28), 0]])];
    expect(inspectTransaction(tx({ extra: [[4, cert[0]]] }))).toMatchObject({ hasCertificates: true, hasWithdrawals: false, hasVotes: false, hasProposals: false });
    expect(inspectTransaction(tx({ extra: [[5, new Map([[1, 2]])]] }))).toMatchObject({ hasCertificates: false, hasWithdrawals: true, hasVotes: false, hasProposals: false });
    expect(inspectTransaction(tx({ extra: [[19, new Map([[1, 2]])]] }))).toMatchObject({ hasWithdrawals: false, hasVotes: true, hasProposals: false });
    expect(inspectTransaction(tx({ extra: [[20, new Tagged(258, [[1]])]] }))).toMatchObject({ hasVotes: false, hasProposals: true });
  });
  it('treats empty certificate, withdrawal, vote and proposal fields as absent', () => {
    const f = inspectTransaction(tx({ extra: [[4, new Tagged(258, [])], [5, new Map()], [19, new Map()], [20, new Tagged(258, [])]] }));
    expect(f).toMatchObject({ hasCertificates: false, hasWithdrawals: false, hasVotes: false, hasProposals: false });
  });
  it('counts label 8416 entries', () => {
    expect(inspectTransaction(tx({ aux: metadata(674) })).groupPayloads).toBe(0);
    expect(inspectTransaction(tx({ aux: metadata() })).groupPayloads).toBe(1);
    // two 8416 keys, built by hand since encoders refuse duplicate keys
    const two = concatBytes([hexToBytes('a2'), encode(8416), payload, encode(8416), payload]);
    const f = inspectTransaction(tx({ aux: two }));
    expect(f.groupPayloads).toBe(2);
    expect(f.auxHashMatches).toBe(true);
  });
  it('handles the tag 259 auxiliary data form', () => {
    const aux = tagged();
    expect(aux.slice(0, 3)).toEqual(hexToBytes('d90103'));
    expect(inspectTransaction(tx({ aux }))).toMatchObject({ auxHashMatches: true, groupPayloads: 1 });
    // the label sitting beside key 0 instead of inside it is not counted
    const outside = concatBytes([hexToBytes('d90103a1'), encode(1), metadata()]);
    expect(inspectTransaction(tx({ aux: outside })).groupPayloads).toBe(0);
  });
  it('throws on malformed bytes', () => {
    expect(() => inspectTransaction(concatBytes([tx(), new Uint8Array([0])]))).toThrow('trailing');
    expect(() => inspectTransaction(encode([1, 2]))).toThrow();
    expect(() => inspectTransaction(new Uint8Array([0x84]))).toThrow();
  });
});
