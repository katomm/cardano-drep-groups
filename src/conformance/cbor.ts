// A minimal definite length CBOR encoder for payloads and native scripts. Numbers are
// unsigned integers, a Map has unsigned integer keys.
export type Cbor = number | bigint | Uint8Array | string | Cbor[] | Map<number, Cbor>;

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
    const n = BigInt(v);
    if (n < 0n) throw new Error('the encoder writes unsigned integers only');
    head(out, 0, n);
  } else if (v instanceof Uint8Array) {
    head(out, 2, BigInt(v.length));
    for (const b of v) out.push(b);
  } else if (typeof v === 'string') {
    const b = new TextEncoder().encode(v);
    head(out, 3, BigInt(b.length));
    for (const x of b) out.push(x);
  } else if (Array.isArray(v)) {
    head(out, 4, BigInt(v.length));
    for (const x of v) put(out, x);
  } else {
    head(out, 5, BigInt(v.size));
    for (const [k, x] of v) {
      put(out, k);
      put(out, x);
    }
  }
}

export function encodeCbor(v: Cbor): Uint8Array {
  const out: number[] = [];
  put(out, v);
  return Uint8Array.from(out);
}
