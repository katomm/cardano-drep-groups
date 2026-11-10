import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead, readUint, skipTags } from './cborSpan.js';
import { keyHashOfVkey } from './hash.js';
import { bytesToHex } from './hex.js';
import { GROUPS_LABEL } from './payload.js';
import type { ChainTx, Hex, TxPosition } from './types.js';

// The transaction is read by span with an explicit stack, so deep values in
// fields this library does not interpret (other metadata labels, Plutus data)
// cannot exhaust the call stack.

const SET_TAG = 258n;

// Definite byte string at off, or null.
function bytesAt(b: Uint8Array, off: number): Uint8Array | null {
  const h = readHead(b, off);
  if (h.major !== 2 || h.indefinite) return null;
  return b.subarray(h.next, h.next + Number(h.big));
}

// Item offsets of an array that may be wrapped in the Conway set tag 258.
// Anything else yields no items.
function setItems(b: Uint8Array, off: number): number[] {
  let h = readHead(b, off);
  let p = off;
  if (h.major === 6 && h.big === SET_TAG) {
    p = h.next;
    h = readHead(b, p);
  }
  return h.major === 4 ? arrayItemOffsets(b, p) : [];
}

// Map entries keyed by uint. A repeated key keeps its last value, which the
// ledger never produces since it rejects such transactions.
function uintKeyed(b: Uint8Array, off: number): Map<number, number> {
  const out = new Map<number, number>();
  for (const [k, v] of mapEntryOffsets(b, off)) {
    const key = readUint(b, k);
    if (key !== null) out.set(key, v);
  }
  return out;
}

function uintAt(b: Uint8Array, off: number | undefined): bigint | null {
  if (off === undefined) return null;
  const h = readHead(b, off);
  return h.major === 0 ? h.big : null;
}

// Offset of the metadata map inside the auxiliary data item, for the three
// formats: Shelley map, Shelley-MA [metadata, scripts], Alonzo tag 259 {0: metadata}.
// Internal helper, shared with txFacts.
export function metadataOffset(cbor: Uint8Array, auxOff: number): number | null {
  const h = readHead(cbor, auxOff);
  if (h.major === 5) return auxOff;
  if (h.major === 4) return arrayItemOffsets(cbor, auxOff)[0] ?? null;
  if (h.major === 6 && h.big === 259n && readHead(cbor, h.next).major === 5) {
    for (const [k, v] of mapEntryOffsets(cbor, h.next)) if (readUint(cbor, k) === 0) return v;
  }
  return null;
}

// The envelope [body, witnesses, is_valid, aux] of a transaction. Proves the whole item is
// well-formed CBOR without trailing bytes, so every reader works on valid spans. Internal
// helper, shared with txFacts.
export function splitTransaction(cbor: Uint8Array): { bodyOff: number; witOff: number; validOff: number; auxOff: number; body: Map<number, number> } {
  if (itemEnd(cbor, 0) !== cbor.length) throw new Error('tx: trailing bytes');
  if (readHead(cbor, 0).major !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const top = arrayItemOffsets(cbor, 0);
  if (top.length !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const [rawBody, rawWit, validOff, auxOff] = top as [number, number, number, number];
  const bodyOff = skipTags(cbor, rawBody);
  if (readHead(cbor, bodyOff).major !== 5) throw new Error('tx: malformed');
  return { bodyOff, witOff: skipTags(cbor, rawWit), validOff, auxOff, body: uintKeyed(cbor, bodyOff) };
}

// The label 8416 entries of the auxiliary data, as [key, value] offsets. Internal helper, shared with txFacts.
export function labelHits(cbor: Uint8Array, auxOff: number): Array<[number, number]> {
  const md = metadataOffset(cbor, auxOff);
  if (md === null || readHead(cbor, md).major !== 5) return [];
  return mapEntryOffsets(cbor, md).filter(([k]) => readUint(cbor, k) === GROUPS_LABEL);
}

// Raw bytes of the label 8416 value, undefined when absent or present twice.
function labelPayload(cbor: Uint8Array, auxOff: number): { payload: Uint8Array | undefined; repeated: boolean } {
  const hits = labelHits(cbor, auxOff);
  const hit = hits.length === 1 ? hits[0] : undefined;
  return { payload: hit ? cbor.slice(hit[1], itemEnd(cbor, hit[1])) : undefined, repeated: hits.length > 1 };
}

export function decodeTransaction(cbor: Uint8Array, pos: TxPosition): ChainTx {
  const { witOff, validOff, auxOff, body } = splitTransaction(cbor);
  const validHead = readHead(cbor, validOff);
  if (readHead(cbor, witOff).major !== 5 || validHead.major !== 7 || (validHead.info !== 20 && validHead.info !== 21)) {
    throw new Error('tx: malformed');
  }
  const wits = uintKeyed(cbor, witOff);

  const signersOff = body.get(14);
  const requiredSigners = signersOff === undefined ? [] : setItems(cbor, signersOff).flatMap((o) => {
    const h = bytesAt(cbor, o);
    return h && h.length === 28 ? [bytesToHex(h)] : [];
  });
  const vkeysOff = wits.get(0);
  const witnessKeyHashes = vkeysOff === undefined ? [] : setItems(cbor, vkeysOff).flatMap((o) => {
    if (readHead(cbor, o).major !== 4) return [];
    const first = arrayItemOffsets(cbor, o)[0];
    const vkey = first === undefined ? null : bytesAt(cbor, first);
    return vkey && vkey.length === 32 ? [keyHashOfVkey(vkey)] : [];
  });
  // Witness field 1 native scripts, cut out of the original bytes.
  const scriptsOff = wits.get(1);
  const witnessScripts = scriptsOff === undefined ? [] : setItems(cbor, scriptsOff).map((o) => cbor.slice(o, itemEnd(cbor, o)));
  const { payload, repeated } = labelPayload(cbor, auxOff);

  return {
    ...pos,
    isValid: validHead.info === 21,
    invalidBefore: uintAt(cbor, body.get(8)),
    invalidHereafter: uintAt(cbor, body.get(3)),
    requiredSigners,
    witnessKeyHashes,
    payload,
    payloadRepeated: repeated,
    witnessScripts,
  };
}

// A transaction input: the hash of the producing transaction and the output index.
export interface TxIn { txHash: Hex; index: number }

// Inputs [tx_hash, index] of a set or a plain array. Malformed entries are skipped.
function txIns(b: Uint8Array, off: number | undefined): TxIn[] {
  if (off === undefined) return [];
  return setItems(b, off).flatMap((o) => {
    if (readHead(b, o).major !== 4) return [];
    const [h, i] = arrayItemOffsets(b, o);
    const hash = h === undefined ? null : bytesAt(b, h);
    const index = i === undefined ? null : readUint(b, i);
    return hash && hash.length === 32 && index !== null ? [{ txHash: bytesToHex(hash), index }] : [];
  });
}

// The raw script_ref of an output: the value of key 3 of a post-Alonzo map output, tag 24
// included and cut out of the original bytes. A legacy array output carries none.
function outputScriptRef(b: Uint8Array, off: number): Uint8Array | null {
  const p = skipTags(b, off);
  if (readHead(b, p).major !== 5) return null;
  const v = uintKeyed(b, p).get(3);
  return v === undefined ? null : b.slice(v, itemEnd(b, v));
}

// The inputs (body key 0), reference inputs (body key 18) and the script_ref of every
// output (body key 1, index aligned, null without one) of a transaction. A collateral
// return (body key 16) follows at index outputs.length, the index the ledger gives it
// when a phase-2 invalid transaction creates it. Accepts the pre-Alonzo envelope
// [body, witnesses, aux] too, since an indexer reads the producing transactions of old
// outputs. Throws on a Byron-era transaction, which an indexer treats as "no script"
// since Byron outputs cannot carry scripts. The script of an input is
// decodeTxRefs(producing tx).outputScriptRefs[input.index], never any other output.
export function decodeTxRefs(cbor: Uint8Array): { inputs: TxIn[]; referenceInputs: TxIn[]; outputScriptRefs: (Uint8Array | null)[] } {
  if (itemEnd(cbor, 0) !== cbor.length) throw new Error('tx: trailing bytes');
  const top = readHead(cbor, 0).major === 4 ? arrayItemOffsets(cbor, 0) : [];
  if (top.length !== 3 && top.length !== 4) throw new Error('tx: expected a transaction envelope');
  const bodyOff = skipTags(cbor, top[0] as number);
  if (readHead(cbor, bodyOff).major !== 5) throw new Error('tx: malformed');
  const body = uintKeyed(cbor, bodyOff);
  const outputsOff = body.get(1);
  const outputs = outputsOff !== undefined && readHead(cbor, outputsOff).major === 4 ? arrayItemOffsets(cbor, outputsOff) : [];
  const collateralOff = body.get(16);
  return {
    inputs: txIns(cbor, body.get(0)),
    referenceInputs: txIns(cbor, body.get(18)),
    outputScriptRefs: [...outputs, ...(collateralOff === undefined ? [] : [collateralOff])].map((o) => outputScriptRef(cbor, o)),
  };
}
