// Minimal CBOR walker that reads heads and returns byte offsets without
// decoding values. Script hashes must be computed over the bytes as they
// appear on chain, and native scripts must be checked against exact CBOR
// major types, which a value decoder hides (it turns 0.0 and 0 into the
// same number).

export interface Head {
  major: number;
  info: number;
  big: bigint; // argument: integer value, length or tag number
  indefinite: boolean;
  next: number;
}

export function readHead(b: Uint8Array, off: number): Head {
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
export function itemEnd(b: Uint8Array, off: number): number {
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

export function skipTags(b: Uint8Array, off: number): number {
  let p = off;
  while (p < b.length && (b[p] as number) >> 5 === 6) p = readHead(b, p).next;
  return p;
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

export function arrayItemOffsets(b: Uint8Array, off: number): number[] {
  return collect(b, off, 4);
}

export function mapEntryOffsets(b: Uint8Array, off: number): Array<[number, number]> {
  const flat = collect(b, off, 5);
  const out: Array<[number, number]> = [];
  for (let i = 0; i + 1 < flat.length; i += 2) out.push([flat[i] as number, flat[i + 1] as number]);
  return out;
}

export function readUint(b: Uint8Array, off: number): number | null {
  const h = readHead(b, off);
  return h.major === 0 && h.big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(h.big) : null;
}
