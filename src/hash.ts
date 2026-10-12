import { blake2b } from '@noble/hashes/blake2.js';
import { bytesToHex } from './hex.js';

// Ledger native script hash: blake2b-224 over the language tag 0x00 and the
// script bytes exactly as published.
export function nativeScriptHash(scriptCbor: Uint8Array): string {
  const tagged = new Uint8Array(scriptCbor.length + 1);
  tagged[0] = 0x00;
  tagged.set(scriptCbor, 1);
  return bytesToHex(blake2b(tagged, { dkLen: 28 }));
}

// Key hash of an Ed25519 verification key, as used in required_signers and sig scripts.
export function keyHashOfVkey(vkey: Uint8Array): string {
  return bytesToHex(blake2b(vkey, { dkLen: 28 }));
}
