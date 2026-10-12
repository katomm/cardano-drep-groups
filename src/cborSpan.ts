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

function untilBreak(b: Uint8Array, off: number, perItem: number): number {
  let p = off;
  for (;;) {
    if (p >= b.length) throw new Error('cbor: missing break');
    if (b[p] === 0xff) return p + 1;
    for (let i = 0; i < perItem; i++) p = itemEnd(b, p);
  }
}

export function itemEnd(b: Uint8Array, off: number): number {
  // Use an explicit stack to avoid recursion depth limits with deeply nested arrays/maps
  type StackEntry = { count: number; index: number };
  const countStack: StackEntry[] = [];
  let current = off;

  for (;;) {
    const h = readHead(b, current);
    switch (h.major) {
      case 0:
      case 1:
      case 7:
        current = h.next;
        break;
      case 2:
      case 3: {
        if (h.indefinite) current = untilBreak(b, h.next, 1);
        else {
          const end = h.next + length(h);
          if (end > b.length) throw new Error('cbor: unexpected end');
          current = end;
        }
        break;
      }
      case 4:
      case 5: {
        const perItem = h.major === 4 ? 1 : 2;
        if (h.indefinite) current = untilBreak(b, h.next, perItem);
        else {
          const n = length(h) * perItem;
          if (n > 0) {
            countStack.push({ count: n, index: 0 });
            current = h.next;
            continue;
          }
          current = h.next;
        }
        break;
      }
      case 6:
        current = h.next;
        break;
      default:
        throw new Error('cbor: unknown major type');
    }

    // Handle the stack
    while (countStack.length > 0) {
      const top = countStack[countStack.length - 1]!;
      top.index += 1;
      if (top.index < top.count) {
        break;
      }
      countStack.pop();
    }

    if (countStack.length === 0) return current;
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
