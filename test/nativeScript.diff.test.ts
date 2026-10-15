import { isDeepStrictEqual } from 'node:util';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/hex.js';
import { parseNativeScript } from '../src/nativeScript.js';
import type { NativeScript } from '../src/types.js';

// Differential test: the single pass parser must give exactly the same result
// as the previous parser for every input. The previous parser and the CBOR
// walker it used are copied below verbatim as the reference. It is quadratic
// in nesting depth, so the generated inputs stay shallow enough for it.

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;

// ---- Reference: src/cborSpan.ts at the previous commit ----

interface Head {
  major: number;
  info: number;
  big: bigint; // argument: integer value, length or tag number
  indefinite: boolean;
  next: number;
}

function readHead(b: Uint8Array, off: number): Head {
  if (off >= b.length) throw new Error('cbor: unexpected end');
  const ib = b[off] as number;
  const major = ib >> 5;
  const info = ib & 0x1f;
  let next = off + 1;
  let big = 0n;
  if (info < 24) big = BigInt(info);
  else if (info >= 24 && info <= 27) {
    const n = 1 << (info - 24); // 1, 2, 4 or 8 bytes
    if (next + n > b.length) throw new Error('cbor: unexpected end');
    for (let i = 0; i < n; i++) big = (big << 8n) | BigInt(b[next + i] as number);
    next += n;
  } else if (info === 31 && major >= 2 && major <= 5) {
    return { major, info, big: 0n, indefinite: true, next };
  } else throw new Error('cbor: unsupported additional info');
  return { major, info, big, indefinite: false, next };
}

function length(h: Head): number {
  if (h.big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: length too large');
  return Number(h.big);
}

// One open container while walking. A definite container counts down the
// items it still needs (2n for a map of n pairs). An indefinite one counts the
// items it has completed, so a map can reject a break after a dangling key.
type Frame = { indefinite: false; remaining: number } | { indefinite: true; map: boolean; count: number };

// Returns the offset just past the CBOR item at off. Walks with one explicit
// stack, so nesting depth is limited only by memory. Every loop step either
// consumes bytes or closes a container, so the walk always terminates.
function itemEnd(b: Uint8Array, off: number): number {
  const stack: Frame[] = [];
  let p = off;
  for (;;) {
    const top = stack[stack.length - 1];
    let done: boolean;
    if (top?.indefinite && p >= b.length) throw new Error('cbor: missing break');
    if (top?.indefinite && b[p] === 0xff) {
      if (top.map && top.count % 2 !== 0) throw new Error('cbor: odd map length');
      stack.pop();
      p += 1;
      done = true;
    } else {
      // Tags are transparent: skip them here, so that no break check falls
      // between a tag and its content.
      let h = readHead(b, p);
      while (h.major === 6) h = readHead(b, h.next);
      switch (h.major) {
        case 0:
        case 1:
        case 7:
          p = h.next;
          done = true;
          break;
        case 2:
        case 3:
          p = h.indefinite ? stringChunksEnd(b, h.next, h.major) : definiteEnd(b, h);
          done = true;
          break;
        case 4:
        case 5:
          p = h.next;
          if (h.indefinite) {
            stack.push({ indefinite: true, map: h.major === 5, count: 0 });
            done = false;
          } else {
            const remaining = length(h) * (h.major === 4 ? 1 : 2);
            if (remaining > 0) stack.push({ indefinite: false, remaining });
            done = remaining === 0;
          }
          break;
        default:
          throw new Error('cbor: unknown major type');
      }
    }
    if (!done) continue;
    // One item completed. Count it on its parent and close every definite
    // container that this completes, each of them one item of its own parent.
    for (;;) {
      const parent = stack[stack.length - 1];
      if (parent === undefined) return p;
      if (parent.indefinite) {
        parent.count += 1;
        break;
      }
      parent.remaining -= 1;
      if (parent.remaining > 0) break;
      stack.pop();
    }
  }
}

function definiteEnd(b: Uint8Array, h: Head): number {
  const end = h.next + length(h);
  if (end > b.length) throw new Error('cbor: unexpected end');
  return end;
}

// An indefinite byte or text string holds only definite chunks of its own
// major type (RFC 8949), so its chunks are walked in a flat loop.
function stringChunksEnd(b: Uint8Array, off: number, major: number): number {
  let p = off;
  for (;;) {
    if (p >= b.length) throw new Error('cbor: missing break');
    if (b[p] === 0xff) return p + 1;
    const h = readHead(b, p);
    if (h.major !== major || h.indefinite) throw new Error('cbor: bad indefinite string chunk');
    p = definiteEnd(b, h);
  }
}

function collect(b: Uint8Array, off: number, major: number): number[] {
  const h = readHead(b, off);
  if (h.major !== major) throw new Error('cbor: unexpected type');
  const perItem = major === 4 ? 1 : 2;
  const out: number[] = [];
  let p = h.next;
  if (h.indefinite) {
    for (;;) {
      if (p >= b.length) throw new Error('cbor: missing break');
      if (b[p] === 0xff) {
        if (major === 5 && out.length % 2 !== 0) throw new Error('cbor: odd map length');
        return out;
      }
      out.push(p);
      p = itemEnd(b, p);
    }
  }
  const n = length(h) * perItem;
  for (let i = 0; i < n; i++) {
    out.push(p);
    p = itemEnd(b, p);
  }
  return out;
}

function arrayItemOffsets(b: Uint8Array, off: number): number[] {
  return collect(b, off, 4);
}


// ---- Reference: parseNativeScript at the previous commit ----

// Reads a CBOR integer at off by its major type: 0 is unsigned, 1 is negative.
function intAt(b: Uint8Array, off: number): bigint | null {
  const h = readHead(b, off);
  if (h.major === 0) return h.big;
  if (h.major === 1) return -1n - h.big;
  return null;
}

// Spec A2: native script grammar of the Conway CDDL with exact major types.
// Uses explicit stack to avoid recursion depth limits with deeply nested scripts.
function scriptAt(b: Uint8Array, startOff: number): NativeScript | null {
  type Work = {
    phase: 'parse' | 'gather_subs';
    off: number;
    tag?: bigint;
    items?: number[];
    itemOffsets?: number[];
    itemIndex?: number;
    subScripts?: NativeScript[];
    n?: bigint;
  };
  const stack: Work[] = [{ phase: 'parse', off: startOff }];
  let result: NativeScript | null = null;

  while (stack.length > 0) {
    const work = stack[stack.length - 1]!;

    if (work.phase === 'parse') {
      if (readHead(b, work.off).major !== 4) return null;
      const items = arrayItemOffsets(b, work.off);
      const [t] = items;
      if (t === undefined || readHead(b, t).major !== 0) return null;
      work.tag = readHead(b, t).big;
      if ((work.tag <= 2n || work.tag >= 4n) && items.length !== 2) return null;
      if (work.tag === 3n && items.length !== 3) return null;
      work.items = items;

      const tag = work.tag;
      const [, a1, a2] = items;

      switch (tag) {
        case 0n: {
          const h = readHead(b, a1 as number);
          if (h.major !== 2 || h.indefinite || h.big !== 28n) return null;
          result = { type: 'sig', keyHash: bytesToHex(b.subarray(h.next, h.next + 28)) };
          stack.pop();
          if (stack.length > 0 && result) {
            const parent = stack[stack.length - 1]!;
            if (parent.phase === 'gather_subs') {
              parent.subScripts!.push(result);
            }
          }
          break;
        }
        case 1n:
        case 2n: {
          if (readHead(b, a1 as number).major !== 4) return null;
          const offsets = arrayItemOffsets(b, a1 as number);
          work.phase = 'gather_subs';
          work.itemOffsets = offsets;
          work.itemIndex = 0;
          work.subScripts = [];
          if (offsets.length === 0) {
            result = { type: tag === 1n ? 'all' : 'any', scripts: [] };
            stack.pop();
            if (stack.length > 0) {
              const parent = stack[stack.length - 1]!;
              if (parent.phase === 'gather_subs') {
                parent.subScripts!.push(result!);
              }
            }
          } else {
            stack.push({ phase: 'parse', off: offsets[0]! });
          }
          break;
        }
        case 3n: {
          const n = intAt(b, a1 as number);
          if (n === null || n < INT64_MIN || n > INT64_MAX) return null;
          if (readHead(b, a2 as number).major !== 4) return null;
          const offsets = arrayItemOffsets(b, a2 as number);
          work.phase = 'gather_subs';
          work.itemOffsets = offsets;
          work.itemIndex = 0;
          work.subScripts = [];
          work.n = n;
          if (offsets.length === 0) {
            result = { type: 'nOfK', n, scripts: [] };
            stack.pop();
            if (stack.length > 0) {
              const parent = stack[stack.length - 1]!;
              if (parent.phase === 'gather_subs') {
                parent.subScripts!.push(result);
              }
            }
          } else {
            stack.push({ phase: 'parse', off: offsets[0]! });
          }
          break;
        }
        case 4n:
        case 5n: {
          const h = readHead(b, a1 as number);
          if (h.major !== 0) return null;
          result = { type: tag === 4n ? 'after' : 'before', slot: h.big };
          stack.pop();
          if (stack.length > 0 && result) {
            const parent = stack[stack.length - 1]!;
            if (parent.phase === 'gather_subs') {
              parent.subScripts!.push(result);
            }
          }
          break;
        }
        default:
          return null;
      }
    } else {
      // gather_subs phase
      const offsets = work.itemOffsets!;
      const index = work.itemIndex!;
      if (index + 1 >= offsets.length) {
        // All subs gathered
        const tag = work.tag!;
        if (tag === 1n || tag === 2n) {
          result = { type: tag === 1n ? 'all' : 'any', scripts: work.subScripts! };
        } else if (tag === 3n) {
          result = { type: 'nOfK', n: work.n!, scripts: work.subScripts! };
        }
        stack.pop();
        if (stack.length > 0) {
          const parent = stack[stack.length - 1]!;
          if (parent.phase === 'gather_subs') {
            parent.subScripts!.push(result!);
          }
        }
      } else {
        work.itemIndex = index + 1;
        stack.push({ phase: 'parse', off: offsets[index + 1]! });
      }
    }
  }

  return result;
}

// Parses native script bytes. Returns null on anything that is not exactly one
// well-formed native script using all bytes.
function refParseNativeScript(bytes: Uint8Array): NativeScript | null {
  try {
    if (itemEnd(bytes, 0) !== bytes.length) return null;
    return scriptAt(bytes, 0);
  } catch {
    return null;
  }
}


// Seeded generator. mulberry32 keeps every run identical, so a mismatch is
// reproducible from the reported case index.
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MAX_U64 = 2n ** 64n - 1n;

class Gen {
  readonly out: number[] = [];
  stats = { forms: new Set<number>(), indefinite: 0, defects: 0, maxDepth: 0, nonCanonical: 0 };
  constructor(readonly r: () => number) {}
  int(n: number): number {
    return Math.floor(this.r() * n);
  }
  chance(p: number): boolean {
    return this.r() < p;
  }
  pick<T>(xs: readonly T[]): T {
    return xs[this.int(xs.length)] as T;
  }
  // Writes a head with argument v, sometimes in a wider encoding than needed.
  head(major: number, v: bigint): void {
    const min = v < 24n ? -1 : v < 0x100n ? 0 : v < 0x10000n ? 1 : v < 0x100000000n ? 2 : 3;
    let w = min;
    if (this.chance(0.1)) {
      w = min + 1 + this.int(3 - min);
      if (w > 3) w = 3;
      if (w !== min) this.stats.nonCanonical++;
    }
    if (w === -1) {
      this.out.push((major << 5) | Number(v));
      return;
    }
    this.out.push((major << 5) | (24 + w));
    const n = 1 << w;
    for (let i = n - 1; i >= 0; i--) this.out.push(Number((v >> BigInt(8 * i)) & 0xffn));
  }
  // An array of items, definite or indefinite. Each item is a writer.
  array(items: Array<() => void>, forceDefinite = false): void {
    const indefinite = !forceDefinite && this.chance(0.2);
    if (indefinite) {
      this.stats.indefinite++;
      this.out.push(0x9f);
    } else this.head(4, BigInt(items.length));
    for (const it of items) it();
    if (indefinite) this.out.push(0xff);
  }
  uint(v: bigint): () => void {
    return () => this.head(0, v);
  }
  sint(v: bigint): () => void {
    return () => (v >= 0n ? this.head(0, v) : this.head(1, -1n - v));
  }
  bytes(n: number): () => void {
    return () => {
      this.head(2, BigInt(n));
      for (let i = 0; i < n; i++) this.out.push(this.int(256));
    };
  }
  // Any well-formed CBOR item that is never a valid script part.
  junk(): () => void {
    return () => {
      switch (this.int(8)) {
        case 0:
          this.out.push(0xf9, 0x3c, 0x00); // float16 1.0
          break;
        case 1:
          this.out.push(0xfb, 0, 0, 0, 0, 0, 0, 0, 0); // float64 0.0
          break;
        case 2:
          this.out.push(0xc1, 0x00); // tag 1 around 0
          break;
        case 3:
          this.out.push(0xa1, 0x00, 0x00); // map {0: 0}
          break;
        case 4:
          this.out.push(0x63, 0x61, 0x62, 0x63); // text "abc"
          break;
        case 5:
          this.out.push(0xf6); // null
          break;
        case 6:
          this.out.push(0x5f, 0x41, 0x00, 0xff); // indefinite byte string
          break;
        default:
          this.out.push(0xf5); // true
      }
    };
  }
  // A native script. A spine forces composite forms along the first child down
  // to maxDepth, so deep trees are actually produced. With defectRate > 0 a node is sometimes broken in a way
  // that keeps the CBOR well formed, so the grammar checks are exercised deep
  // inside the tree and not only the CBOR walker.
  script(depth: number, maxDepth: number, defectRate: number, spine = false): void {
    if (depth > this.stats.maxDepth) this.stats.maxDepth = depth;
    const leafOnly = depth >= maxDepth;
    const form = leafOnly ? this.pick([0, 4, 5]) : spine ? this.pick([1, 2, 3]) : this.int(6);
    this.stats.forms.add(form);
    const defect = this.chance(defectRate) ? 1 + this.int(9) : 0;
    if (defect) this.stats.defects++;
    let tag: () => void = this.uint(BigInt(form));
    if (defect === 1) tag = this.uint(this.pick([6n, 7n, 24n, 255n, MAX_U64]));
    if (defect === 2) tag = this.sint(-1n - BigInt(this.int(3)));
    if (defect === 3) tag = this.junk();
    const items: Array<() => void> = [tag];
    switch (form) {
      case 0:
        items.push(defect === 4 ? this.bytes(this.pick([0, 27, 29, 32])) : defect === 5 ? this.junk() : this.bytes(28));
        break;
      case 1:
      case 2:
      case 3: {
        if (form === 3) {
          const n = this.pick([
            0n,
            1n,
            2n,
            -1n,
            -5n,
            BigInt(this.int(1000)),
            2n ** 63n - 1n,
            2n ** 63n,
            -(2n ** 63n),
            -(2n ** 63n) - 1n,
            MAX_U64,
            -(2n ** 64n),
            2n ** 32n,
          ]);
          items.push(defect === 5 ? this.junk() : this.sint(n));
        }
        const k = spine ? 1 + this.int(2) : this.chance(0.15) ? 0 : 1 + this.int(depth < 2 ? 4 : 2);
        const kids: Array<() => void> = [];
        for (let i = 0; i < k; i++) kids.push(() => this.script(depth + 1, maxDepth, defectRate, spine && i === 0));
        if (defect === 6) items.push(this.junk());
        else items.push(() => this.array(kids));
        break;
      }
      default: {
        const slot = this.pick([0n, 1n, 23n, 24n, 255n, 256n, 65535n, 2n ** 32n, 2n ** 63n, MAX_U64]);
        items.push(defect === 5 ? this.pick([this.junk(), this.sint(-1n)]) : this.uint(slot));
      }
    }
    if (defect === 7) items.push(this.uint(0n)); // one item too many
    if (defect === 8) items.pop(); // one item too few
    if (defect === 9) {
      this.out.push(0xc1); // tag around the script itself
    }
    this.array(items);
  }
}

// One random input: a valid script, a script with grammar defects, or a
// byte level mutation of either.
function sample(seed: number): { bytes: Uint8Array; kind: string; stats: Gen['stats'] } {
  const g = new Gen(rng(seed));
  const deep = g.chance(0.1);
  const maxDepth = deep ? 10 + g.int(30) : g.int(6);
  const mode = g.int(10);
  g.script(0, maxDepth, mode < 3 ? 0 : mode < 5 ? 0.08 : 0, deep);
  let b = g.out;
  let kind = mode < 3 ? 'valid' : mode < 5 ? 'defect' : 'mutated';
  if (mode >= 5) {
    const m = g.int(9);
    const at = g.int(b.length + 1);
    switch (m) {
      case 0:
        b = b.slice(0, g.int(b.length)); // truncate
        break;
      case 1:
        b = [...b.slice(0, at), g.int(256), ...b.slice(at)]; // insert a byte
        break;
      case 2:
        b = [...b.slice(0, at), ...b.slice(at + 1)]; // delete a byte
        break;
      case 3: {
        b = b.slice();
        if (b.length) b[g.int(b.length)] = g.int(256); // replace a byte
        break;
      }
      case 4: {
        b = b.slice();
        if (b.length) {
          const j = g.int(b.length);
          b[j] = (b[j] as number) ^ (1 << g.int(5)); // flip a length bit
        }
        break;
      }
      case 5:
        b = [...b, ...Array.from({ length: 1 + g.int(3) }, () => g.int(256))]; // trailing bytes
        break;
      case 6:
        b = [...b.slice(0, at), g.pick([0xc1, 0xd8, 0xf9, 0xfa, 0xfb, 0xff, 0x1c, 0xbf]), ...b.slice(at)];
        break;
      case 7:
        b = [...b.slice(0, at), 0xf9, 0x00, 0x00, ...b.slice(at)]; // a float16 item
        break;
      default:
        b = [...b.slice(0, at), 0xff, ...b.slice(at)]; // a stray break
    }
    kind = `mutated${m}`;
  }
  return { bytes: Uint8Array.from(b), kind, stats: g.stats };
}

const CASES = 25000;

describe('parseNativeScript matches the previous implementation', () => {
  it(`agrees on ${CASES} seeded random inputs`, () => {
    let accepted = 0;
    let rejected = 0;
    let indefinite = 0;
    let defects = 0;
    let nonCanonical = 0;
    let maxDepth = 0;
    const forms = new Set<number>();
    const kinds = new Map<string, number>();
    const acceptedKinds = new Set<string>();
    const distinct = new Set<string>();
    const mismatches: string[] = [];
    for (let i = 0; i < CASES; i++) {
      const { bytes, kind, stats } = sample(0x5eed + i);
      const want = refParseNativeScript(bytes);
      let got: NativeScript | null;
      try {
        got = parseNativeScript(bytes);
      } catch (e) {
        mismatches.push(`case ${i} threw ${String(e)}: ${bytesToHex(bytes)}`);
        continue;
      }
      if (!isDeepStrictEqual(got, want)) mismatches.push(`case ${i} (${kind}): ${bytesToHex(bytes)}`);
      if (want === null) rejected++;
      else {
        accepted++;
        acceptedKinds.add(kind);
      }
      kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
      distinct.add(bytesToHex(bytes));
      indefinite += stats.indefinite;
      defects += stats.defects;
      nonCanonical += stats.nonCanonical;
      maxDepth = Math.max(maxDepth, stats.maxDepth);
      for (const f of stats.forms) forms.add(f);
    }
    expect(mismatches.slice(0, 5)).toEqual([]);

    // The generator must cover both outcomes and every shape it claims to.
    expect(accepted).toBeGreaterThan(CASES * 0.25);
    expect(rejected).toBeGreaterThan(CASES * 0.25);
    expect(distinct.size).toBeGreaterThan(CASES * 0.6);
    expect([...forms].sort()).toEqual([0, 1, 2, 3, 4, 5]);
    expect(indefinite).toBeGreaterThan(1000);
    expect(nonCanonical).toBeGreaterThan(1000);
    expect(defects).toBeGreaterThan(1000);
    expect(maxDepth).toBeGreaterThanOrEqual(30);
    expect(kinds.size).toBe(11); // valid, defect and nine mutations
    expect(acceptedKinds.has('valid')).toBe(true);
  });

  it('agrees on hand picked edge cases', () => {
    const k = '11'.repeat(28);
    const cases = [
      '',
      '80',
      '9fff',
      `8200581c${k}`,
      `8200581c${k}00`,
      `8200581b${k.slice(2)}`,
      `8200581c${k.slice(2)}`,
      `9f00581c${k}ff`,
      `9f00581c${k}00ff`,
      `9f00581c${k}`,
      `82005f581c${k}ff`,
      '8303208000',
      '83033b7fffffffffffffff80',
      '83033b800000000000000080',
      '83031b7fffffffffffffff80',
      '83031b800000000000000080',
      '82041bffffffffffffffff',
      '820520',
      '820181',
      '820180',
      '82019f',
      '82019fff',
      '9f019fffff',
      '9f0180ff',
      '9f018000ff',
      '82069f',
      '8201bf',
      'c18201 80',
      '82018180',
      '9b00000000000000028201 80',
      '83039b0000000000000003 0180',
      '820199ffff',
      '82019bffffffffffffffff',
    ].map((h) => h.replace(/ /g, ''));
    for (const h of cases) {
      const bytes = hexToBytes(h);
      expect(parseNativeScript(bytes), h).toEqual(refParseNativeScript(bytes));
    }
  });
});
