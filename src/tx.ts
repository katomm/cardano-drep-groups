import { decode } from 'cborg';
import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead, readUint, skipTags } from './cborSpan.js';
import { keyHashOfVkey } from './hash.js';
import { bytesToHex } from './hex.js';
import { asUint } from './nativeScript.js';
import { GROUPS_LABEL } from './payload.js';
import type { ChainTx, TxPosition } from './types.js';

// Every tag decodes to its content, so set tags (258), encoded CBOR (24) and
// Plutus data (121 and up) never stop the body and witness decode.
const ANY_TAG = new Proxy({}, { get: () => (d: () => unknown) => d() });

const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

// Offset of the metadata map inside the auxiliary data item, for the three
// formats: Shelley map, Shelley-MA [metadata, scripts], Alonzo tag 259 {0: metadata}.
function metadataOffset(cbor: Uint8Array, auxOff: number): number | null {
  const h = readHead(cbor, auxOff);
  if (h.major === 5) return auxOff;
  if (h.major === 4) return arrayItemOffsets(cbor, auxOff)[0] ?? null;
  if (h.major === 6 && h.big === 259n) {
    for (const [k, v] of mapEntryOffsets(cbor, h.next)) if (readUint(cbor, k) === 0) return v;
  }
  return null;
}

// Raw bytes of the label 1695 value, undefined when absent or present twice.
function payloadBytes(cbor: Uint8Array, auxOff: number | undefined): Uint8Array | undefined {
  if (auxOff === undefined) return undefined;
  const md = metadataOffset(cbor, auxOff);
  if (md === null || readHead(cbor, md).major !== 5) return undefined;
  const hits = mapEntryOffsets(cbor, md).filter(([k]) => readUint(cbor, k) === GROUPS_LABEL);
  const hit = hits.length === 1 ? hits[0] : undefined;
  return hit ? cbor.slice(hit[1], itemEnd(cbor, hit[1])) : undefined;
}

// Witness field 1 native scripts, cut out of the original bytes.
function rawWitnessScripts(cbor: Uint8Array, witOff: number | undefined): Uint8Array[] {
  if (witOff === undefined) return [];
  for (const [k, v] of mapEntryOffsets(cbor, skipTags(cbor, witOff))) {
    if (readUint(cbor, k) !== 1) continue;
    return arrayItemOffsets(cbor, skipTags(cbor, v)).map((o) => cbor.slice(o, itemEnd(cbor, o)));
  }
  return [];
}

export function decodeTransaction(cbor: Uint8Array, pos: TxPosition): ChainTx {
  const tx = decode(cbor, { useMaps: true, tags: ANY_TAG as never });
  if (!Array.isArray(tx) || tx.length !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const [body, wits, isValid] = tx;
  if (!(body instanceof Map) || !(wits instanceof Map) || typeof isValid !== 'boolean') throw new Error('tx: malformed');
  const top = arrayItemOffsets(cbor, 0);
  const requiredSigners = asList(body.get(14)).flatMap((h) => (h instanceof Uint8Array && h.length === 28 ? [bytesToHex(h)] : []));
  const witnessKeyHashes = asList(wits.get(0)).flatMap((w) =>
    Array.isArray(w) && w[0] instanceof Uint8Array && w[0].length === 32 ? [keyHashOfVkey(w[0])] : [],
  );
  return {
    ...pos,
    isValid,
    invalidBefore: asUint(body.get(8)),
    invalidHereafter: asUint(body.get(3)),
    requiredSigners,
    witnessKeyHashes,
    payload: payloadBytes(cbor, top[3]),
    witnessScripts: rawWitnessScripts(cbor, top[1]),
  };
}
