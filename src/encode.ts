// Payload encoder for label 8416. It grows out of the conformance CBOR writer, which
// stays a small definite length encoder owned by this package. It is promoted instead of
// taking cborg as a runtime dependency because cborg sorts map keys by their encoded bytes
// and has no notion of the 64 byte metadatum chunks. The exact byte output matters because
// native script hashes are taken over the encoded bytes.
import { bytesToHex, concatBytes, hexToBytes } from './hex.js';
import { scriptComplexity } from './nativeScript.js';
import { MAX_EVENTS_PER_PAYLOAD, MAX_SCRIPT_DEPTH, MAX_SCRIPT_ENTRIES, MAX_SCRIPT_NODES } from './payload.js';
import type { Anchor, Credential, GroupEvent, Hex, NativeScript, RefLike, UpdateChanges } from './types.js';

export class EncodeError extends Error {}

export type Cbor = number | bigint | Uint8Array | string | Cbor[] | Map<number, Cbor>;

const MAX_CHUNK = 64;
const UINT64_MAX = 2n ** 64n - 1n;
const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;
const utf8 = new TextEncoder();

function head(out: number[], major: number, n: bigint): void {
  const m = major << 5;
  if (n < 24n) out.push(m | Number(n));
  else if (n < 0x100n) out.push(m | 24, Number(n));
  else if (n < 0x1_0000n) out.push(m | 25, Number(n >> 8n), Number(n & 0xffn));
  else if (n < 0x1_0000_0000n) {
    out.push(m | 26);
    for (let i = 3; i >= 0; i--) out.push(Number((n >> BigInt(8 * i)) & 0xffn));
  } else {
    out.push(m | 27);
    for (let i = 7; i >= 0; i--) out.push(Number((n >> BigInt(8 * i)) & 0xffn));
  }
}

function put(out: number[], v: Cbor): void {
  if (typeof v === 'number' || typeof v === 'bigint') {
    if (typeof v === 'number' && !Number.isInteger(v)) throw new EncodeError('the encoder writes integers only');
    const n = BigInt(v);
    if (n >= 0n) {
      if (n > UINT64_MAX) throw new EncodeError('integer out of range');
      head(out, 0, n);
    } else {
      if (-1n - n > UINT64_MAX) throw new EncodeError('integer out of range');
      head(out, 1, -1n - n);
    }
  } else if (v instanceof Uint8Array) {
    head(out, 2, BigInt(v.length));
    for (const b of v) out.push(b);
  } else if (typeof v === 'string') {
    const b = utf8.encode(v);
    head(out, 3, BigInt(b.length));
    for (const x of b) out.push(x);
  } else if (Array.isArray(v)) {
    head(out, 4, BigInt(v.length));
    for (const x of v) put(out, x);
  } else {
    head(out, 5, BigInt(v.size));
    for (const k of [...v.keys()].sort((a, b) => a - b)) {
      put(out, k);
      put(out, v.get(k) as Cbor);
    }
  }
}

// Definite lengths, shortest heads, map keys ascending, negative integers as major type 1.
export function encodeCbor(v: Cbor): Uint8Array {
  const out: number[] = [];
  put(out, v);
  return Uint8Array.from(out);
}

// UTF-8 chunks of at most 64 bytes that never split a code point. The empty string is one empty chunk.
export function chunkText(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let len = 0;
  for (const ch of s) {
    const n = utf8.encode(ch).length;
    if (len + n > MAX_CHUNK) {
      out.push(cur);
      cur = '';
      len = 0;
    }
    cur += ch;
    len += n;
  }
  out.push(cur);
  return out;
}

// 64 byte chunks, one empty chunk for empty input.
export function chunkBytes(b: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += MAX_CHUNK) out.push(b.subarray(i, i + MAX_CHUNK));
  return out.length > 0 ? out : [new Uint8Array(0)];
}

function hexBytes(hex: Hex, len: number, what: string): Uint8Array {
  if (typeof hex !== 'string' || !/^[0-9a-f]*$/.test(hex) || hex.length !== len * 2) {
    throw new EncodeError(`${what} must be ${len} bytes of lowercase hex`);
  }
  return hexToBytes(hex);
}

function nativeScriptValue(s: NativeScript): Cbor {
  switch (s.type) {
    case 'sig':
      return [0, hexBytes(s.keyHash, 28, 'key hash')];
    case 'all':
      return [1, s.scripts.map(nativeScriptValue)];
    case 'any':
      return [2, s.scripts.map(nativeScriptValue)];
    case 'nOfK':
      if (s.n < INT64_MIN || s.n > INT64_MAX) throw new EncodeError('threshold out of int64 range');
      return [3, s.n, s.scripts.map(nativeScriptValue)];
    case 'after':
    case 'before':
      if (s.slot < 0n || s.slot > UINT64_MAX) throw new EncodeError('slot out of range');
      return [s.type === 'after' ? 4 : 5, s.slot];
  }
}

// Native script bytes in the Conway CDDL form.
export function encodeNativeScript(s: NativeScript): Uint8Array {
  return encodeCbor(nativeScriptValue(s));
}

export interface PayloadInput { events: GroupEvent[]; scripts?: NativeScript[] }

function safeIndex(n: number, what: string): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new EncodeError(`${what} must be a non-negative safe integer`);
  return n;
}

function seqValue(n: bigint): bigint {
  if (typeof n !== 'bigint' || n < 0n || n > UINT64_MAX) throw new EncodeError('seq must be an unsigned 64 bit integer');
  return n;
}

function refValue(r: RefLike, index: number): Cbor {
  if ('local' in r) {
    if (safeIndex(r.local, 'local reference') >= index) throw new EncodeError('local reference must point to an earlier event');
    return [r.local];
  }
  return [hexBytes(r.txHash, 32, 'transaction hash'), safeIndex(r.index, 'reference index')];
}

function credentialValue(c: Credential): Cbor {
  return [c.kind === 'key' ? 0 : 1, hexBytes(c.hash, 28, 'credential hash')];
}

function anchorValue(a: Anchor): Cbor {
  if (a.url.length === 0) throw new EncodeError('anchor url must not be empty');
  return [chunkText(a.url), hexBytes(a.dataHash, 32, 'anchor data hash')];
}

function changesValue(c: UpdateChanges): Cbor {
  const m = new Map<number, Cbor>();
  if (c.control !== undefined) m.set(0, hexBytes(c.control, 28, 'control hash'));
  if (c.admission !== undefined) m.set(1, hexBytes(c.admission, 28, 'admission hash'));
  if (c.profile !== undefined) m.set(2, anchorValue(c.profile));
  return m;
}

function eventValue(e: GroupEvent, index: number): Cbor {
  switch (e.tag) {
    case 'create': {
      if ((e.mode === 'permissioned') !== (e.admission !== null)) {
        throw new EncodeError('a permissioned group needs an admission policy and an open group must not have one');
      }
      const v: Cbor[] = [
        0,
        e.mode === 'open' ? 0 : 1,
        hexBytes(e.control, 28, 'control hash'),
        e.admission === null ? [] : hexBytes(e.admission, 28, 'admission hash'),
      ];
      if (e.profile !== null) v.push(anchorValue(e.profile));
      return v;
    }
    case 'update':
      return [1, refValue(e.group, index), seqValue(e.seq), changesValue(e.changes)];
    case 'dissolve':
      return [2, refValue(e.group, index), seqValue(e.seq)];
    case 'join':
      return [3, refValue(e.group, index), credentialValue(e.member)];
    case 'approve':
      return [4, refValue(e.join, index)];
    case 'leave':
      return [5, refValue(e.join, index)];
    case 'remove':
      return [6, refValue(e.join, index)];
  }
}

// Bytes of the label 8416 value: {0: 1, 1: events, 2: scripts} with key 2 only when scripts are given.
export function encodePayload(p: PayloadInput): Uint8Array {
  if (p.events.length === 0 || p.events.length > MAX_EVENTS_PER_PAYLOAD) {
    throw new EncodeError(`a payload carries 1 to ${MAX_EVENTS_PER_PAYLOAD} events`);
  }
  const scripts = p.scripts ?? [];
  if (scripts.length > MAX_SCRIPT_ENTRIES) throw new EncodeError(`a payload carries at most ${MAX_SCRIPT_ENTRIES} scripts`);
  const m = new Map<number, Cbor>([[0, 1], [1, p.events.map(eventValue)]]);
  if (scripts.length > 0) {
    m.set(2, scripts.map((s) => {
      const { nodes, depth } = scriptComplexity(s);
      if (nodes > MAX_SCRIPT_NODES || depth > MAX_SCRIPT_DEPTH) throw new EncodeError('script exceeds the node or depth limit');
      return chunkBytes(encodeNativeScript(s));
    }));
  }
  return encodeCbor(m);
}
