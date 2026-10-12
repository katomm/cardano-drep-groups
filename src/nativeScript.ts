import { arrayItemOffsets, itemEnd, readHead } from './cborSpan.js';
import { bytesToHex } from './hex.js';
import type { EvalContext, Hex, NativeScript } from './types.js';

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;

// Accepts a JS number or bigint that is a non-negative integer. Used for
// payload fields, where on-chain metadata cannot carry floats.
export function asUint(v: unknown): bigint | null {
  if (typeof v === 'bigint') return v >= 0n ? v : null;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  return null;
}

// Reads a CBOR integer at off by its major type: 0 is unsigned, 1 is negative.
function intAt(b: Uint8Array, off: number): bigint | null {
  const h = readHead(b, off);
  if (h.major === 0) return h.big;
  if (h.major === 1) return -1n - h.big;
  return null;
}

function scriptsAt(b: Uint8Array, off: number): NativeScript[] | null {
  if (readHead(b, off).major !== 4) return null;
  const out: NativeScript[] = [];
  for (const o of arrayItemOffsets(b, off)) {
    const s = scriptAt(b, o);
    if (!s) return null;
    out.push(s);
  }
  return out;
}

// Spec A2: native script grammar of the Conway CDDL with exact major types.
function scriptAt(b: Uint8Array, off: number): NativeScript | null {
  if (readHead(b, off).major !== 4) return null;
  const items = arrayItemOffsets(b, off);
  const [t, a1, a2] = items;
  if (t === undefined || readHead(b, t).major !== 0) return null;
  const tag = readHead(b, t).big;
  if ((tag <= 2n || tag >= 4n) && items.length !== 2) return null;
  if (tag === 3n && items.length !== 3) return null;
  switch (tag) {
    case 0n: {
      const h = readHead(b, a1 as number);
      if (h.major !== 2 || h.indefinite || h.big !== 28n) return null;
      return { type: 'sig', keyHash: bytesToHex(b.subarray(h.next, h.next + 28)) };
    }
    case 1n:
    case 2n: {
      const scripts = scriptsAt(b, a1 as number);
      return scripts ? { type: tag === 1n ? 'all' : 'any', scripts } : null;
    }
    case 3n: {
      const n = intAt(b, a1 as number);
      if (n === null || n < INT64_MIN || n > INT64_MAX) return null;
      const scripts = scriptsAt(b, a2 as number);
      return scripts ? { type: 'nOfK', n, scripts } : null;
    }
    case 4n:
    case 5n: {
      const h = readHead(b, a1 as number);
      if (h.major !== 0) return null;
      return { type: tag === 4n ? 'after' : 'before', slot: h.big };
    }
    default:
      return null;
  }
}

// Parses native script bytes. Returns null on anything that is not exactly one
// well-formed native script using all bytes.
export function parseNativeScript(bytes: Uint8Array): NativeScript | null {
  try {
    if (itemEnd(bytes, 0) !== bytes.length) return null;
    return scriptAt(bytes, 0);
  } catch {
    return null;
  }
}

// Spec A3: evaluated against the signer set and the validity interval. The
// ledger does not run these scripts for a metadata-only transaction.
export function evaluateNativeScript(s: NativeScript, ctx: EvalContext): boolean {
  switch (s.type) {
    case 'sig':
      return ctx.signers.has(s.keyHash);
    case 'all':
      return s.scripts.every((c) => evaluateNativeScript(c, ctx));
    case 'any':
      return s.scripts.some((c) => evaluateNativeScript(c, ctx));
    case 'nOfK': {
      let ok = 0n;
      for (const c of s.scripts) if (evaluateNativeScript(c, ctx)) ok += 1n;
      return ok >= s.n;
    }
    case 'after':
      return ctx.invalidBefore !== null && ctx.invalidBefore >= s.slot;
    case 'before':
      return ctx.invalidHereafter !== null && ctx.invalidHereafter <= s.slot;
  }
}

export function collectKeyHashes(s: NativeScript): Hex[] {
  const out: Hex[] = [];
  const walk = (x: NativeScript): void => {
    if (x.type === 'sig') {
      if (!out.includes(x.keyHash)) out.push(x.keyHash);
    } else if (x.type === 'all' || x.type === 'any' || x.type === 'nOfK') x.scripts.forEach(walk);
  };
  walk(s);
  return out;
}
