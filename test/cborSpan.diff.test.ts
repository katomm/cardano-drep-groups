import { describe, expect, it } from 'vitest';
import { itemEnd } from '../src/cborSpan.js';
import { bytesToHex } from '../src/hex.js';

// Recursive reference walker: a straightforward recursive itemEnd with the
// RFC 8949 string rule applied. An indefinite byte or text string accepts only definite chunks of
// the same major type (RFC 8949). It recurses on data depth, so it is only
// run on the bounded inputs generated below.
interface Head {
  major: number;
  big: bigint;
  indefinite: boolean;
  next: number;
}

function refReadHead(b: Uint8Array, off: number): Head {
  if (off >= b.length) throw new Error('cbor: unexpected end');
  const ib = b[off] as number;
  const major = ib >> 5;
  const info = ib & 0x1f;
  let next = off + 1;
  let big = 0n;
  if (info < 24) big = BigInt(info);
  else if (info >= 24 && info <= 27) {
    const n = 1 << (info - 24);
    if (next + n > b.length) throw new Error('cbor: unexpected end');
    for (let i = 0; i < n; i++) big = (big << 8n) | BigInt(b[next + i] as number);
    next += n;
  } else if (info === 31 && major >= 2 && major <= 5) {
    return { major, big: 0n, indefinite: true, next };
  } else throw new Error('cbor: unsupported additional info');
  return { major, big, indefinite: false, next };
}

function refLength(h: Head): number {
  if (h.big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: length too large');
  return Number(h.big);
}

function untilBreak(b: Uint8Array, off: number, perItem: number): number {
  let p = off;
  for (;;) {
    if (p >= b.length) throw new Error('cbor: missing break');
    if (b[p] === 0xff) return p + 1;
    for (let i = 0; i < perItem; i++) p = refItemEnd(b, p);
  }
}

// RFC 8949: chunks must be definite strings of the same major type.
function stringChunks(b: Uint8Array, off: number, major: number): number {
  let p = off;
  for (;;) {
    if (p >= b.length) throw new Error('cbor: missing break');
    if (b[p] === 0xff) return p + 1;
    const h = refReadHead(b, p);
    if (h.major !== major || h.indefinite) throw new Error('cbor: bad chunk');
    p = h.next + refLength(h);
    if (p > b.length) throw new Error('cbor: unexpected end');
  }
}

function refItemEnd(b: Uint8Array, off: number): number {
  const h = refReadHead(b, off);
  switch (h.major) {
    case 0:
    case 1:
    case 7:
      return h.next;
    case 2:
    case 3: {
      if (h.indefinite) return stringChunks(b, h.next, h.major);
      const end = h.next + refLength(h);
      if (end > b.length) throw new Error('cbor: unexpected end');
      return end;
    }
    case 4:
    case 5: {
      const perItem = h.major === 4 ? 1 : 2;
      if (h.indefinite) return untilBreak(b, h.next, perItem);
      let p = h.next;
      const n = refLength(h) * perItem;
      for (let i = 0; i < n; i++) p = refItemEnd(b, p);
      return p;
    }
    case 6:
      return refItemEnd(b, h.next);
    default:
      throw new Error('cbor: unknown major type');
  }
}

// Deterministic PRNG (mulberry32), so a failure reproduces from the seed.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Gen {
  private readonly rnd: () => number;
  constructor(seed: number) {
    this.rnd = mulberry32(seed);
  }
  int(n: number): number {
    return Math.floor(this.rnd() * n);
  }
  chance(p: number): boolean {
    return this.rnd() < p;
  }
  bytes(n: number): number[] {
    return Array.from({ length: n }, () => this.int(256));
  }

  // A head with the argument v, encoded in a random valid width.
  head(major: number, v: number): number[] {
    const m = major << 5;
    const widths: number[] = [];
    if (v < 24) widths.push(0);
    if (v < 0x100) widths.push(1);
    if (v < 0x10000) widths.push(2);
    widths.push(4, 8);
    const w = widths[this.int(widths.length)] as number;
    if (w === 0) return [m | v];
    const out = [m | (24 + Math.log2(w))];
    for (let i = w - 1; i >= 0; i--) out.push(Math.floor(v / 2 ** (8 * i)) % 256);
    return out;
  }

  // A head whose argument does not fit a safe integer.
  hugeHead(major: number): number[] {
    return [(major << 5) | 27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, this.int(256)];
  }

  string(major: number): number[] {
    if (this.chance(0.03)) return this.hugeHead(major);
    if (!this.chance(0.3)) {
      const n = this.int(6);
      return [...this.head(major, n), ...this.bytes(n)];
    }
    const out = [(major << 5) | 31];
    const chunks = this.int(4);
    for (let i = 0; i < chunks; i++) {
      const r = this.int(20);
      if (r === 0) out.push((major << 5) | 31, 0xff); // nested indefinite chunk
      else if (r === 1) out.push(this.int(24)); // integer chunk
      else if (r === 2) out.push(((major === 2 ? 3 : 2) << 5) | 0); // other string major
      else {
        const n = this.int(4);
        out.push(...this.head(major, n), ...this.bytes(n));
      }
    }
    out.push(0xff);
    return out;
  }

  simple(): number[] {
    switch (this.int(6)) {
      case 0:
        return [0xe0 | (20 + this.int(4))]; // false, true, null, undefined
      case 1:
        return [0xf8, this.int(256)];
      case 2:
        return [0xf9, ...this.bytes(2)];
      case 3:
        return [0xfa, ...this.bytes(4)];
      case 4:
        return [0xfb, ...this.bytes(8)];
      default:
        return [0xe0 | (28 + this.int(3))]; // reserved additional info
    }
  }

  item(depth: number): number[] {
    const leaf = depth >= 5 || this.chance(0.35);
    const r = leaf ? this.int(5) : 5 + this.int(5);
    switch (r) {
      case 0:
      case 1: {
        const major = r;
        if (this.chance(0.05)) return [(major << 5) | (28 + this.int(4))]; // reserved or indefinite info
        const v = this.chance(0.1) ? this.int(2 ** 32) : this.int(300);
        return this.head(major, v);
      }
      case 2:
        return this.string(2);
      case 3:
        return this.string(3);
      case 4:
        return this.simple();
      case 5:
      case 6: {
        // Array, definite or indefinite.
        if (this.chance(0.03)) return [...this.hugeHead(4), ...this.item(depth + 1)];
        const n = this.int(4);
        const items: number[] = [];
        for (let i = 0; i < n; i++) items.push(...this.item(depth + 1));
        return this.chance(0.5) ? [...this.head(4, n), ...items] : [0x9f, ...items, 0xff];
      }
      case 7:
      case 8: {
        // Map, definite or indefinite, with keys and values of any kind.
        if (this.chance(0.03)) return [...this.hugeHead(5), ...this.item(depth + 1)];
        const n = this.int(4);
        const items: number[] = [];
        for (let i = 0; i < n; i++) items.push(...this.item(depth + 1), ...this.item(depth + 1));
        if (this.chance(0.5)) return [...this.head(5, n), ...items];
        if (this.chance(0.1)) items.push(...this.item(depth + 1)); // dangling key
        return [0xbf, ...items, 0xff];
      }
      default: {
        // One or more tags around an item.
        const out: number[] = [];
        const tags = 1 + this.int(3);
        for (let i = 0; i < tags; i++) out.push(...this.head(6, this.int(70000)));
        return [...out, ...this.item(depth + 1)];
      }
    }
  }

  // A generated item with optional damage: truncation, a stray break, a
  // flipped byte, trailing bytes.
  input(): Uint8Array {
    const b = this.item(0);
    if (this.chance(0.2)) b.splice(this.int(b.length + 1), 0, 0xff);
    if (this.chance(0.1)) b[this.int(b.length)] = this.int(256);
    if (this.chance(0.2)) b.length = this.int(b.length + 1);
    if (this.chance(0.1)) b.push(...this.bytes(1 + this.int(3)));
    return new Uint8Array(b);
  }
}

class HangGuard extends Error {}

// Wraps the input so that the walker under test fails cleanly instead of
// hanging: it may read each byte only a bounded number of times.
function guarded(b: Uint8Array): Uint8Array {
  let reads = 0;
  const limit = 32 * (b.length + 1) + 64;
  return new Proxy(b, {
    get(target, prop) {
      if (++reads > limit) throw new HangGuard(`more than ${limit} reads`);
      // Read from the target itself, the typed array getters reject a proxy receiver.
      const v = (target as unknown as Record<PropertyKey, unknown>)[prop];
      return typeof v === 'function' ? v.bind(target) : v;
    },
  });
}

type Outcome = { end: number } | { threw: true };

function run(f: (b: Uint8Array, off: number) => number, b: Uint8Array, off: number): Outcome {
  try {
    return { end: f(b, off) };
  } catch (e) {
    if (e instanceof HangGuard) throw e;
    return { threw: true };
  }
}

describe('itemEnd differential against the recursive reference', () => {
  it('agrees on 20000 seeded random items', () => {
    const gen = new Gen(0x1695);
    const hexes = new Set<string>();
    let returned = 0;
    let threw = 0;
    for (let i = 0; i < 20000; i++) {
      const b = gen.input();
      const hex = bytesToHex(b);
      hexes.add(hex);
      const offsets = [0];
      if (b.length > 1) offsets.push(1 + gen.int(b.length - 1));
      for (const off of offsets) {
        const want = run(refItemEnd, b, off);
        const got = run(itemEnd, guarded(b), off);
        expect(got, `itemEnd(${hex}, ${off})`).toEqual(want);
        if ('end' in want) returned++;
        else threw++;
      }
    }
    // The generator must vary its output and reach both outcomes.
    expect(hexes.size).toBeGreaterThan(15000);
    expect(returned).toBeGreaterThan(5000);
    expect(threw).toBeGreaterThan(5000);
  });
});
