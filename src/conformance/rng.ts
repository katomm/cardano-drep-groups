// The seeded generator of the conformance module, the only source of randomness.
// xorshift32, seeded through a multiplicative hash so that neighbouring seeds diverge at once.
export class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = (Math.imul(seed ^ 0x5bd1e995, 0x9e3779b1) ^ 0x85ebca6b) >>> 0 || 1;
    for (let i = 0; i < 4; i++) this.next();
  }
  next(): number {
    let x = this.s;
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    this.s = x >>> 0;
    return this.s;
  }
  float(): number {
    return this.next() / 0x1_0000_0000;
  }
  int(n: number): number {
    return Math.floor(this.float() * n);
  }
  range(lo: number, hi: number): number {
    return lo + this.int(hi - lo + 1);
  }
  chance(p: number): boolean {
    return this.float() < p;
  }
  pick<T>(xs: readonly T[]): T {
    if (xs.length === 0) throw new Error('pick from an empty list');
    return xs[this.int(xs.length)] as T;
  }
  // One entry of `table`, weighted by its first element.
  weighted<T>(table: ReadonlyArray<readonly [number, T]>): T {
    const total = table.reduce((n, [w]) => n + w, 0);
    let r = this.float() * total;
    for (const [w, v] of table) {
      r -= w;
      if (r < 0) return v;
    }
    return (table[table.length - 1] as readonly [number, T])[1];
  }
  shuffle<T>(xs: T[]): T[] {
    for (let i = xs.length - 1; i > 0; i--) {
      const j = this.int(i + 1);
      [xs[i], xs[j]] = [xs[j] as T, xs[i] as T];
    }
    return xs;
  }
}
