import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead, readUint, skipTags } from './cborSpan.js';
import { keyHashOfVkey } from './hash.js';
import { bytesToHex } from './hex.js';
import { GROUPS_LABEL } from './payload.js';
import type { ChainTx, TxPosition } from './types.js';

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
function metadataOffset(cbor: Uint8Array, auxOff: number): number | null {
  const h = readHead(cbor, auxOff);
  if (h.major === 5) return auxOff;
  if (h.major === 4) return arrayItemOffsets(cbor, auxOff)[0] ?? null;
  if (h.major === 6 && h.big === 259n && readHead(cbor, h.next).major === 5) {
    for (const [k, v] of mapEntryOffsets(cbor, h.next)) if (readUint(cbor, k) === 0) return v;
  }
  return null;
}

// Raw bytes of the label 8416 value, undefined when absent or present twice.
function labelPayload(cbor: Uint8Array, auxOff: number): { payload: Uint8Array | undefined; repeated: boolean } {
  const md = metadataOffset(cbor, auxOff);
  if (md === null || readHead(cbor, md).major !== 5) return { payload: undefined, repeated: false };
  const hits = mapEntryOffsets(cbor, md).filter(([k]) => readUint(cbor, k) === GROUPS_LABEL);
  const hit = hits.length === 1 ? hits[0] : undefined;
  return { payload: hit ? cbor.slice(hit[1], itemEnd(cbor, hit[1])) : undefined, repeated: hits.length > 1 };
}

export function decodeTransaction(cbor: Uint8Array, pos: TxPosition): ChainTx {
  // Proves the whole transaction is well-formed CBOR without trailing bytes,
  // so every reader below works on valid spans.
  if (itemEnd(cbor, 0) !== cbor.length) throw new Error('tx: trailing bytes');
  if (readHead(cbor, 0).major !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const top = arrayItemOffsets(cbor, 0);
  if (top.length !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const [rawBody, rawWit, validOff, auxOff] = top as [number, number, number, number];
  const bodyOff = skipTags(cbor, rawBody);
  const witOff = skipTags(cbor, rawWit);
  const validHead = readHead(cbor, validOff);
  if (readHead(cbor, bodyOff).major !== 5 || readHead(cbor, witOff).major !== 5 || validHead.major !== 7 || (validHead.info !== 20 && validHead.info !== 21)) {
    throw new Error('tx: malformed');
  }
  const body = uintKeyed(cbor, bodyOff);
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
