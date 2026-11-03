import { blake2b } from '@noble/hashes/blake2.js';
import { itemEnd, readHead, skipTags } from './cborSpan.js';
import { bytesToHex } from './hex.js';
import { labelHits, splitTransaction } from './tx.js';
import type { Hex } from './types.js';

export interface TxFacts {
  auxDataHash: Hex | null; // body field 7
  auxHashMatches: boolean; // blake2b-256 of the raw auxiliary data item equals field 7, false when either side is missing
  hasCertificates: boolean; // body field 4, non-empty
  hasWithdrawals: boolean; // body field 5, non-empty
  hasVotes: boolean; // body field 19, non-empty
  hasProposals: boolean; // body field 20, non-empty
  groupPayloads: number; // label 8416 entries in the metadata map that metadataOffset resolves
}

// True for a non-empty array or map, looking through tags such as the set tag 258.
function nonEmpty(b: Uint8Array, off: number | undefined): boolean {
  if (off === undefined) return false;
  const p = skipTags(b, off);
  const h = readHead(b, p);
  if (h.major !== 4 && h.major !== 5) return false;
  return h.indefinite ? b[h.next] !== 0xff : h.big > 0n;
}

export function inspectTransaction(cbor: Uint8Array): TxFacts {
  const { auxOff, body: fields } = splitTransaction(cbor);

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

  const groupPayloads = hasAux ? labelHits(cbor, auxOff).length : 0;

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
