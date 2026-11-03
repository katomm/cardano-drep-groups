import { blake2b } from '@noble/hashes/blake2.js';
import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead, readUint, skipTags } from './cborSpan.js';
import { bytesToHex } from './hex.js';
import { GROUPS_LABEL } from './payload.js';
import { metadataOffset } from './tx.js';
import type { Hex } from './types.js';

export interface TxFacts {
  auxDataHash: Hex | null; // body field 7
  auxHashMatches: boolean; // blake2b-256 of the raw auxiliary data item equals field 7, false when either side is missing
  hasCertificates: boolean; // body field 4, non-empty
  hasWithdrawals: boolean; // body field 5, non-empty
  hasVotes: boolean; // body field 19, non-empty
  hasProposals: boolean; // body field 20, non-empty
  groupPayloads: number; // label 8416 entries in the metadata map that decodeTransaction reads
}

// True for a non-empty array or map, looking through tags such as the set tag 258.
function nonEmpty(b: Uint8Array, off: number | undefined): boolean {
  if (off === undefined) return false;
  const p = skipTags(b, off);
  const h = readHead(b, p);
  if (h.major === 4) return arrayItemOffsets(b, p).length > 0;
  if (h.major === 5) return mapEntryOffsets(b, p).length > 0;
  return false;
}

export function inspectTransaction(cbor: Uint8Array): TxFacts {
  if (itemEnd(cbor, 0) !== cbor.length) throw new Error('tx: trailing bytes');
  if (readHead(cbor, 0).major !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const top = arrayItemOffsets(cbor, 0);
  if (top.length !== 4) throw new Error('tx: expected [body, witnesses, is_valid, aux]');
  const [rawBody, , , auxOff] = top as [number, number, number, number];
  const bodyOff = skipTags(cbor, rawBody);
  if (readHead(cbor, bodyOff).major !== 5) throw new Error('tx: malformed');

  const fields = new Map<number, number>();
  for (const [k, v] of mapEntryOffsets(cbor, bodyOff)) {
    const key = readUint(cbor, k);
    if (key !== null) fields.set(key, v);
  }

  const hashOff = fields.get(7);
  let auxDataHash: Hex | null = null;
  if (hashOff !== undefined) {
    const h = readHead(cbor, hashOff);
    if (h.major === 2 && !h.indefinite && h.big === 32n) auxDataHash = bytesToHex(cbor.subarray(h.next, h.next + 32));
  }
  // A transaction without auxiliary data carries null, which has nothing to hash.
  const hasAux = readHead(cbor, auxOff).major !== 7;
  const auxHashMatches =
    auxDataHash !== null && hasAux && bytesToHex(blake2b(cbor.subarray(auxOff, itemEnd(cbor, auxOff)), { dkLen: 32 })) === auxDataHash;

  let groupPayloads = 0;
  if (hasAux) {
    const md = metadataOffset(cbor, auxOff);
    if (md !== null && readHead(cbor, md).major === 5) {
      groupPayloads = mapEntryOffsets(cbor, md).filter(([k]) => readUint(cbor, k) === GROUPS_LABEL).length;
    }
  }

  return {
    auxDataHash,
    auxHashMatches,
    hasCertificates: nonEmpty(cbor, fields.get(4)),
    hasWithdrawals: nonEmpty(cbor, fields.get(5)),
    hasVotes: nonEmpty(cbor, fields.get(19)),
    hasProposals: nonEmpty(cbor, fields.get(20)),
    groupPayloads,
  };
}
