import { EncodeError, encodeNativeScript } from './encode.js';
import { nativeScriptHash } from './hash.js';
import type { Hex, NativeScript } from './types.js';

export interface MajorityScript { script: NativeScript; bytes: Uint8Array; hash: Hex; keys: Hex[] }

const KEY_HASH = /^[0-9a-fA-F]{56}$/;

// An n of k script over sig leaves. Keys are lowercased, deduped and sorted ascending
// (the order of the lowercase hex equals byte order), so one key set always gives one hash.
export function majorityScript(keys: readonly Hex[], n: number): MajorityScript {
  for (const k of keys) {
    if (typeof k !== 'string' || !KEY_HASH.test(k)) throw new EncodeError('key hash must be 56 hex characters');
  }
  const sorted = [...new Set(keys.map((k) => k.toLowerCase()))].sort();
  if (sorted.length === 0) throw new EncodeError('at least one key is required');
  if (!Number.isSafeInteger(n) || n < 1 || n > sorted.length) throw new EncodeError('threshold must be between 1 and the number of keys');
  const script: NativeScript = {
    type: 'nOfK',
    n: BigInt(n),
    scripts: sorted.map((keyHash) => ({ type: 'sig' as const, keyHash })),
  };
  const bytes = encodeNativeScript(script);
  return { script, bytes, hash: nativeScriptHash(bytes), keys: sorted };
}
