import { encode } from 'cborg';
import { nativeScriptHash } from '../src/hash.js';
import { hexToBytes } from '../src/hex.js';

// Deterministic 28-byte key hashes and 32-byte tx hashes for readable tests.
export const K = (n: number): string => n.toString(16).padStart(2, '0').repeat(28);
export const T = (n: number): string => n.toString(16).padStart(2, '0').repeat(32);
export const kb = (hex: string): Uint8Array => hexToBytes(hex);

// Native script values in their CBOR array form.
export type ScriptValue = unknown[];
export const sig = (k: string): ScriptValue => [0, hexToBytes(k)];
export const allOf = (...s: ScriptValue[]): ScriptValue => [1, s];
export const anyOf = (...s: ScriptValue[]): ScriptValue => [2, s];
export const nOfK = (n: number, ...s: ScriptValue[]): ScriptValue => [3, n, s];
export const after = (slot: number): ScriptValue => [4, slot];
export const before = (slot: number): ScriptValue => [5, slot];
export const scriptBytes = (s: ScriptValue): Uint8Array => encode(s);
export const hashOf = (s: ScriptValue): string => nativeScriptHash(scriptBytes(s));

export function chunk64(bytes: Uint8Array, size = 64): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += size) out.push(bytes.subarray(i, i + size));
  return out.length > 0 ? out : [new Uint8Array(0)];
}

export const ref = (txHash: string, index: number): unknown[] => [hexToBytes(txHash), index];
export const local = (index: number): unknown[] => [index];
const cred = (kind: 'key' | 'script', hash: string): unknown[] => [kind === 'key' ? 0 : 1, hexToBytes(hash)];

export const ev = {
  create: (mode: 0 | 1, control: string, admission: string | null, profile?: { url: string; hash: string }): unknown[] => {
    const e: unknown[] = [0, mode, hexToBytes(control), admission ? hexToBytes(admission) : []];
    if (profile) e.push([[profile.url], hexToBytes(profile.hash)]);
    return e;
  },
  update: (group: unknown[], seq: number, changes: Map<number, unknown>): unknown[] => [1, group, seq, changes],
  dissolve: (group: unknown[], seq: number): unknown[] => [2, group, seq],
  join: (group: unknown[], kind: 'key' | 'script', hash: string): unknown[] => [3, group, cred(kind, hash)],
  approve: (join: unknown[]): unknown[] => [4, join],
  leave: (join: unknown[]): unknown[] => [5, join],
  remove: (join: unknown[]): unknown[] => [6, join],
};

// Builds payload bytes. Scripts go into key 2, each chunked to 64 bytes.
export function buildPayload(events: unknown[], scripts: ScriptValue[] = [], version = 1): Uint8Array {
  return buildPayloadRaw(events, scripts.map((s) => chunk64(scriptBytes(s))), version);
}

// Same, with key 2 entries given as is, for malformed entry tests.
export function buildPayloadRaw(events: unknown[], entries: unknown[] = [], version = 1): Uint8Array {
  const m = new Map<number, unknown>([[0, version], [1, events]]);
  if (entries.length > 0) m.set(2, entries);
  return encode(m);
}
