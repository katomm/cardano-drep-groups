import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead } from './cborSpan.js';
import { nativeScriptHash } from './hash.js';
import { bytesToHex, concatBytes } from './hex.js';
import { parseNativeScript } from './nativeScript.js';
import type { Anchor, Credential, DecodedEvent, DecodedPayload, GroupEvent, PublishedScript, RefLike, UpdateChanges } from './types.js';

export const GROUPS_LABEL = 8416;
const MAX_CHUNK = 64n;
const utf8 = new TextDecoder('utf-8', { fatal: true });

// All readers below work on offsets into the payload bytes. decodePayload
// checks once that the whole payload is well-formed CBOR, so these readers
// only judge shapes and return null for anything that does not fit. A tag or
// any other unexpected major type is a shape error of the layer it is in.

// Unsigned integer of major type 0, at full 64 bit precision.
function uintAt(b: Uint8Array, off: number | undefined): bigint | null {
  if (off === undefined) return null;
  const h = readHead(b, off);
  return h.major === 0 ? h.big : null;
}

function indexAt(b: Uint8Array, off: number | undefined): number | null {
  const n = uintAt(b, off);
  return n !== null && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : null;
}

// Definite byte string, optionally of an exact length.
function bytesAt(b: Uint8Array, off: number | undefined, len?: bigint): Uint8Array | null {
  if (off === undefined) return null;
  const h = readHead(b, off);
  if (h.major !== 2 || h.indefinite || (len !== undefined && h.big !== len)) return null;
  return b.subarray(h.next, h.next + Number(h.big));
}

function hexAt(b: Uint8Array, off: number | undefined, len: bigint): string | null {
  const v = bytesAt(b, off, len);
  return v ? bytesToHex(v) : null;
}

const hash28At = (b: Uint8Array, off: number | undefined): string | null => hexAt(b, off, 28n);

// Item offsets of an array, definite or indefinite, null for anything else.
function arrayAt(b: Uint8Array, off: number | undefined): number[] | null {
  if (off === undefined || readHead(b, off).major !== 4) return null;
  return arrayItemOffsets(b, off);
}

function refAt(b: Uint8Array, off: number | undefined): RefLike | null {
  const v = arrayAt(b, off);
  if (!v) return null;
  if (v.length === 1) {
    const local = indexAt(b, v[0]);
    return local === null ? null : { local };
  }
  if (v.length === 2) {
    const txHash = hexAt(b, v[0], 32n);
    const index = indexAt(b, v[1]);
    return txHash === null || index === null ? null : { txHash, index };
  }
  return null;
}

function credentialAt(b: Uint8Array, off: number | undefined): Credential | null {
  const v = arrayAt(b, off);
  if (!v || v.length !== 2) return null;
  const kind = uintAt(b, v[0]);
  const hash = hash28At(b, v[1]);
  if ((kind !== 0n && kind !== 1n) || hash === null) return null;
  return { kind: kind === 0n ? 'key' : 'script', hash };
}

// anchor = [url: [+ text .size (0..64)], data_hash: bytes .size 32]. Chunks
// are definite text strings, invalid UTF-8 makes the anchor invalid.
function anchorAt(b: Uint8Array, off: number | undefined): Anchor | null {
  const v = arrayAt(b, off);
  if (!v || v.length !== 2) return null;
  const chunks = arrayAt(b, v[0]);
  const dataHash = hexAt(b, v[1], 32n);
  if (!chunks || chunks.length === 0 || dataHash === null) return null;
  let url = '';
  for (const c of chunks) {
    const h = readHead(b, c);
    if (h.major !== 3 || h.indefinite || h.big > MAX_CHUNK) return null;
    try {
      url += utf8.decode(b.subarray(h.next, h.next + Number(h.big)));
    } catch {
      return null;
    }
  }
  return { url, dataHash };
}

// Spec A2 layer 3: an unknown or duplicate update key invalidates the event.
function changesAt(b: Uint8Array, off: number | undefined): UpdateChanges | null {
  if (off === undefined || readHead(b, off).major !== 5) return null;
  const out: UpdateChanges = {};
  const seen = new Set<bigint>();
  for (const [k, val] of mapEntryOffsets(b, off)) {
    const key = uintAt(b, k);
    if (key === null || seen.has(key)) return null;
    seen.add(key);
    if (key === 0n || key === 1n) {
      const h = hash28At(b, val);
      if (!h) return null;
      if (key === 0n) out.control = h;
      else out.admission = h;
    } else if (key === 2n) {
      const a = anchorAt(b, val);
      if (!a) return null;
      out.profile = a;
    } else return null;
  }
  return out;
}

function decodeEvent(b: Uint8Array, off: number): GroupEvent | string {
  const v = arrayAt(b, off);
  if (!v || v.length === 0) return 'event is not an array';
  const tag = uintAt(b, v[0]);
  switch (tag) {
    case 0n: {
      if (v.length !== 4 && v.length !== 5) return 'create: wrong arity';
      const mode = uintAt(b, v[1]);
      const control = hash28At(b, v[2]);
      if (!control || (mode !== 0n && mode !== 1n)) return 'create: bad mode or control';
      let admission: string | null = null;
      if (mode === 1n) {
        admission = hash28At(b, v[3]);
        if (!admission) return 'create: permissioned group needs an admission policy';
      } else if (arrayAt(b, v[3])?.length !== 0) return 'create: open group must not have an admission policy';
      let profile: Anchor | null = null;
      if (v.length === 5) {
        profile = anchorAt(b, v[4]);
        if (!profile) return 'create: bad profile anchor';
      }
      return { tag: 'create', mode: mode === 1n ? 'permissioned' : 'open', control, admission, profile };
    }
    case 1n: {
      const group = v.length === 4 ? refAt(b, v[1]) : null;
      const seq = uintAt(b, v[2]);
      const changes = group ? changesAt(b, v[3]) : null;
      if (!group || seq === null || !changes) return 'update: bad shape';
      return { tag: 'update', group, seq, changes };
    }
    case 2n: {
      const group = v.length === 3 ? refAt(b, v[1]) : null;
      const seq = uintAt(b, v[2]);
      if (!group || seq === null) return 'dissolve: bad shape';
      return { tag: 'dissolve', group, seq };
    }
    case 3n: {
      const group = v.length === 3 ? refAt(b, v[1]) : null;
      const member = credentialAt(b, v[2]);
      if (!group || !member) return 'join: bad shape';
      return { tag: 'join', group, member };
    }
    case 4n:
    case 5n:
    case 6n: {
      const join = v.length === 2 ? refAt(b, v[1]) : null;
      if (!join) return 'bad join reference';
      return { tag: tag === 4n ? 'approve' : tag === 5n ? 'leave' : 'remove', join };
    }
    default:
      return 'unknown event tag';
  }
}

// Spec A2 layer 2: each entry is an array of definite byte strings of at most
// 64 bytes, concatenated. Entries that do not fit or do not parse are skipped.
function decodeScripts(b: Uint8Array, off: number): PublishedScript[] {
  const entries = arrayAt(b, off);
  if (!entries) return [];
  const out: PublishedScript[] = [];
  for (const e of entries) {
    const chunks = arrayAt(b, e);
    if (!chunks || chunks.length === 0) continue;
    const parts = chunks.map((c) => bytesAt(b, c));
    if (!parts.every((p): p is Uint8Array => p !== null && BigInt(p.length) <= MAX_CHUNK)) continue;
    const bytes = concatBytes(parts);
    const script = parseNativeScript(bytes);
    if (script) out.push({ hash: nativeScriptHash(bytes), bytes, script });
  }
  return out;
}

// Identity of a payload map key for the duplicate rule. A uint key counts by
// value, so 0x00 and 0x1800 are the same key. Any other key is an unknown key
// and counts by its exact bytes.
function keyId(b: Uint8Array, off: number): string {
  const n = uintAt(b, off);
  return n !== null ? `u${n}` : `x${bytesToHex(b.subarray(off, itemEnd(b, off)))}`;
}

// Spec A2 decoding layers over the raw label 8416 metadatum bytes, read by
// span with an explicit stack, so no nesting depth can exhaust the call stack.
// A duplicate key in the payload map ignores the whole payload. Values of
// unknown payload keys are skipped by span and never inspected.
export function decodePayload(bytes: Uint8Array): DecodedPayload | null {
  try {
    if (itemEnd(bytes, 0) !== bytes.length) return null;
    if (readHead(bytes, 0).major !== 5) return null;
    const fields = new Map<string, number>();
    for (const [k, v] of mapEntryOffsets(bytes, 0)) {
      const id = keyId(bytes, k);
      if (fields.has(id)) return null;
      fields.set(id, v);
    }
    if (uintAt(bytes, fields.get('u0')) !== 1n) return null;
    const events = arrayAt(bytes, fields.get('u1'));
    if (!events || events.length === 0) return null;
    const scriptsOff = fields.get('u2');
    const scripts = scriptsOff === undefined ? [] : decodeScripts(bytes, scriptsOff);
    const decoded: DecodedEvent[] = events.map((e) => {
      const r = decodeEvent(bytes, e);
      return typeof r === 'string' ? { ok: false, reason: r } : { ok: true, event: r };
    });
    return { events: decoded, scripts };
  } catch {
    return null;
  }
}
