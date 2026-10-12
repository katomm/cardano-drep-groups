import { decode } from 'cborg';
import { nativeScriptHash } from './hash.js';
import { bytesToHex, concatBytes } from './hex.js';
import { asUint, parseNativeScript } from './nativeScript.js';
import type { Anchor, Credential, DecodedEvent, DecodedPayload, GroupEvent, PublishedScript, RefLike, UpdateChanges } from './types.js';

export const GROUPS_LABEL = 1695;
const MAX_CHUNK = 64;
const utf8 = new TextEncoder();

const isBytes = (v: unknown, len?: number): v is Uint8Array => v instanceof Uint8Array && (len === undefined || v.length === len);

function asIndex(v: unknown): number | null {
  const n = asUint(v);
  return n !== null && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : null;
}

function asRef(v: unknown): RefLike | null {
  if (!Array.isArray(v)) return null;
  if (v.length === 1) {
    const local = asIndex(v[0]);
    return local === null ? null : { local };
  }
  if (v.length === 2 && isBytes(v[0], 32)) {
    const index = asIndex(v[1]);
    return index === null ? null : { txHash: bytesToHex(v[0]), index };
  }
  return null;
}

function asCredential(v: unknown): Credential | null {
  if (!Array.isArray(v) || v.length !== 2 || !isBytes(v[1], 28)) return null;
  const kind = asUint(v[0]);
  if (kind !== 0n && kind !== 1n) return null;
  return { kind: kind === 0n ? 'key' : 'script', hash: bytesToHex(v[1]) };
}

function asAnchor(v: unknown): Anchor | null {
  if (!Array.isArray(v) || v.length !== 2 || !Array.isArray(v[0]) || v[0].length === 0 || !isBytes(v[1], 32)) return null;
  let url = '';
  for (const c of v[0]) {
    if (typeof c !== 'string' || utf8.encode(c).length > MAX_CHUNK) return null;
    url += c;
  }
  return { url, dataHash: bytesToHex(v[1]) };
}

const asHash28 = (v: unknown): string | null => (isBytes(v, 28) ? bytesToHex(v) : null);

function asChanges(v: unknown): UpdateChanges | null {
  if (!(v instanceof Map)) return null;
  const out: UpdateChanges = {};
  for (const [k, val] of v) {
    const key = asUint(k);
    if (key === 0n || key === 1n) {
      const h = asHash28(val);
      if (!h) return null;
      if (key === 0n) out.control = h;
      else out.admission = h;
    } else if (key === 2n) {
      const a = asAnchor(val);
      if (!a) return null;
      out.profile = a;
    } else return null; // spec A2 layer 3: unknown update keys invalidate the event
  }
  return out;
}

function decodeEvent(v: unknown): GroupEvent | string {
  if (!Array.isArray(v) || v.length === 0) return 'event is not an array';
  const tag = asUint(v[0]);
  switch (tag) {
    case 0n: {
      if (v.length !== 4 && v.length !== 5) return 'create: wrong arity';
      const mode = asUint(v[1]);
      const control = asHash28(v[2]);
      if (!control || (mode !== 0n && mode !== 1n)) return 'create: bad mode or control';
      let admission: string | null = null;
      if (mode === 1n) {
        admission = asHash28(v[3]);
        if (!admission) return 'create: permissioned group needs an admission policy';
      } else if (!Array.isArray(v[3]) || v[3].length !== 0) return 'create: open group must not have an admission policy';
      let profile: Anchor | null = null;
      if (v.length === 5) {
        profile = asAnchor(v[4]);
        if (!profile) return 'create: bad profile anchor';
      }
      return { tag: 'create', mode: mode === 1n ? 'permissioned' : 'open', control, admission, profile };
    }
    case 1n: {
      const group = v.length === 4 ? asRef(v[1]) : null;
      const seq = asUint(v[2]);
      const changes = asChanges(v[3]);
      if (!group || seq === null || !changes) return 'update: bad shape';
      return { tag: 'update', group, seq, changes };
    }
    case 2n: {
      const group = v.length === 3 ? asRef(v[1]) : null;
      const seq = asUint(v[2]);
      if (!group || seq === null) return 'dissolve: bad shape';
      return { tag: 'dissolve', group, seq };
    }
    case 3n: {
      const group = v.length === 3 ? asRef(v[1]) : null;
      const member = asCredential(v[2]);
      if (!group || !member) return 'join: bad shape';
      return { tag: 'join', group, member };
    }
    case 4n:
    case 5n:
    case 6n: {
      const join = v.length === 2 ? asRef(v[1]) : null;
      if (!join) return 'bad join reference';
      return { tag: tag === 4n ? 'approve' : tag === 5n ? 'leave' : 'remove', join };
    }
    default:
      return 'unknown event tag';
  }
}

function decodeScripts(v: unknown): PublishedScript[] {
  if (!Array.isArray(v)) return [];
  const out: PublishedScript[] = [];
  for (const entry of v) {
    if (!Array.isArray(entry) || entry.length === 0) continue;
    if (!entry.every((c) => isBytes(c) && c.length <= MAX_CHUNK)) continue;
    const bytes = concatBytes(entry as Uint8Array[]);
    const script = parseNativeScript(bytes);
    if (script) out.push({ hash: nativeScriptHash(bytes), bytes, script });
  }
  return out;
}

// Spec A2 decoding layers over the raw label 1695 metadatum bytes. Tags are
// not part of transaction metadata and duplicate map keys make the payload
// ambiguous, both reject the payload as a whole.
export function decodePayload(bytes: Uint8Array): DecodedPayload | null {
  let value: unknown;
  try {
    value = decode(bytes, { useMaps: true, rejectDuplicateMapKeys: true });
  } catch {
    return null;
  }
  if (!(value instanceof Map)) return null;
  if (asUint(value.get(0)) !== 1n) return null;
  const events = value.get(1);
  if (!Array.isArray(events) || events.length === 0) return null;
  const scripts = value.has(2) ? decodeScripts(value.get(2)) : [];
  const decoded: DecodedEvent[] = events.map((e) => {
    const r = decodeEvent(e);
    return typeof r === 'string' ? { ok: false, reason: r } : { ok: true, event: r };
  });
  return { events: decoded, scripts };
}
