import { readHead } from './cborSpan.js';
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

// One composite script (all, any or n_of_k) whose child list is still open.
type ListFrame = {
  tag: 1n | 2n | 3n;
  n: bigint;
  scriptIndefinite: boolean; // the script array itself, closed by a break
  listIndefinite: boolean; // the child list, closed by a break
  expected: number; // child count of a definite list
  scripts: NativeScript[];
};

// Spec A2: native script grammar of the Conway CDDL with exact major types.
// One forward pass over the bytes reads every head exactly once, so the work
// is linear in the input size. Open child lists live on an explicit stack, so
// nesting depth is limited only by memory. Returns null on anything that is
// not exactly one well-formed script using all bytes, and may throw on
// truncated input (the caller turns that into null).
function parseScript(b: Uint8Array): NativeScript | null {
  const stack: ListFrame[] = [];
  let p = 0;
  for (;;) {
    // A script starts at p.
    const h = readHead(b, p);
    if (h.major !== 4) return null;
    const scriptIndefinite = h.indefinite;
    p = h.next;
    if (scriptIndefinite && b[p] === 0xff) return null; // empty script array
    const th = readHead(b, p);
    if (th.major !== 0) return null;
    const tag = th.big;
    p = th.next;
    if (tag > 5n) return null;
    if (!scriptIndefinite && h.big !== (tag === 3n ? 3n : 2n)) return null;

    let done: NativeScript | null = null;
    let doneIndefinite = scriptIndefinite;
    if (tag === 0n) {
      const kh = readHead(b, p);
      if (kh.major !== 2 || kh.indefinite || kh.big !== 28n) return null;
      if (kh.next + 28 > b.length) return null;
      done = { type: 'sig', keyHash: bytesToHex(b.subarray(kh.next, kh.next + 28)) };
      p = kh.next + 28;
    } else if (tag === 4n || tag === 5n) {
      const sh = readHead(b, p);
      if (sh.major !== 0) return null;
      done = { type: tag === 4n ? 'after' : 'before', slot: sh.big };
      p = sh.next;
    } else {
      let n = 0n;
      if (tag === 3n) {
        const nh = readHead(b, p);
        if (nh.major === 0) n = nh.big;
        else if (nh.major === 1) n = -1n - nh.big;
        else return null;
        if (n < INT64_MIN || n > INT64_MAX) return null;
        p = nh.next;
      }
      const lh = readHead(b, p);
      if (lh.major !== 4) return null;
      p = lh.next;
      // Every child takes at least one byte, so a longer list cannot fit.
      if (!lh.indefinite && lh.big > BigInt(b.length - p)) return null;
      stack.push({
        tag: tag as 1n | 2n | 3n,
        n,
        scriptIndefinite,
        listIndefinite: lh.indefinite,
        expected: Number(lh.big),
        scripts: [],
      });
    }

    // Close every script and child list that is complete at p, innermost
    // first, then either return the root or go on with the next child.
    for (;;) {
      if (done !== null) {
        if (doneIndefinite) {
          if (b[p] !== 0xff) return null; // more items than the arity allows
          p += 1;
        }
        const parent = stack[stack.length - 1];
        if (parent === undefined) return p === b.length ? done : null;
        parent.scripts.push(done);
        done = null;
      }
      const top = stack[stack.length - 1];
      if (top === undefined) return null;
      if (top.listIndefinite) {
        if (p >= b.length) return null;
        if (b[p] !== 0xff) break; // next child
        p += 1;
      } else if (top.scripts.length < top.expected) break; // next child
      stack.pop();
      done =
        top.tag === 3n
          ? { type: 'nOfK', n: top.n, scripts: top.scripts }
          : { type: top.tag === 1n ? 'all' : 'any', scripts: top.scripts };
      doneIndefinite = top.scriptIndefinite;
    }
  }
}

// Parses native script bytes. Returns null on anything that is not exactly one
// well-formed native script using all bytes.
export function parseNativeScript(bytes: Uint8Array): NativeScript | null {
  try {
    return parseScript(bytes);
  } catch {
    return null;
  }
}

// Spec A3: evaluated against the signer set and the validity interval. The
// ledger does not run these scripts for a metadata-only transaction.
// Uses explicit stack to avoid recursion depth limits with deeply nested scripts.
export function evaluateNativeScript(s: NativeScript, ctx: EvalContext): boolean {
  type Work = {
    phase: 'eval' | 'collect';
    script: NativeScript;
    childIndex?: number;
    childResults?: boolean[];
    children?: NativeScript[];
  };
  const stack: Work[] = [{ phase: 'eval', script: s }];
  let result = false;

  while (stack.length > 0) {
    const work = stack[stack.length - 1]!;

    if (work.phase === 'eval') {
      switch (work.script.type) {
        case 'sig':
          result = ctx.signers.has(work.script.keyHash);
          stack.pop();
          if (stack.length > 0) {
            const parent = stack[stack.length - 1]!;
            if (parent.phase === 'collect') {
              parent.childResults![parent.childIndex!] = result;
            }
          }
          break;
        case 'all': {
          if (work.script.scripts.length === 0) {
            result = true;
            stack.pop();
            if (stack.length > 0) {
              const parent = stack[stack.length - 1]!;
              if (parent.phase === 'collect') {
                parent.childResults![parent.childIndex!] = result;
              }
            }
          } else {
            work.phase = 'collect';
            work.childIndex = 0;
            work.childResults = [];
            work.children = work.script.scripts;
            stack.push({ phase: 'eval', script: work.children[0]! });
          }
          break;
        }
        case 'any': {
          if (work.script.scripts.length === 0) {
            result = false;
            stack.pop();
            if (stack.length > 0) {
              const parent = stack[stack.length - 1]!;
              if (parent.phase === 'collect') {
                parent.childResults![parent.childIndex!] = result;
              }
            }
          } else {
            work.phase = 'collect';
            work.childIndex = 0;
            work.childResults = [];
            work.children = work.script.scripts;
            stack.push({ phase: 'eval', script: work.children[0]! });
          }
          break;
        }
        case 'nOfK': {
          if (work.script.scripts.length === 0) {
            result = 0n >= work.script.n;
            stack.pop();
            if (stack.length > 0) {
              const parent = stack[stack.length - 1]!;
              if (parent.phase === 'collect') {
                parent.childResults![parent.childIndex!] = result;
              }
            }
          } else {
            work.phase = 'collect';
            work.childIndex = 0;
            work.childResults = [];
            work.children = work.script.scripts;
            stack.push({ phase: 'eval', script: work.children[0]! });
          }
          break;
        }
        case 'after':
          result = ctx.invalidBefore !== null && ctx.invalidBefore >= work.script.slot;
          stack.pop();
          if (stack.length > 0) {
            const parent = stack[stack.length - 1]!;
            if (parent.phase === 'collect') {
              parent.childResults![parent.childIndex!] = result;
            }
          }
          break;
        case 'before':
          result = ctx.invalidHereafter !== null && ctx.invalidHereafter <= work.script.slot;
          stack.pop();
          if (stack.length > 0) {
            const parent = stack[stack.length - 1]!;
            if (parent.phase === 'collect') {
              parent.childResults![parent.childIndex!] = result;
            }
          }
          break;
      }
    } else {
      // collect phase - only 'all', 'any', 'nOfK' have scripts
      const children = work.children!;
      const nextIndex = work.childIndex! + 1;

      if (nextIndex >= children.length) {
        // All children evaluated
        if (work.script.type === 'all') {
          result = work.childResults!.every((r) => r);
        } else if (work.script.type === 'any') {
          result = work.childResults!.some((r) => r);
        } else if (work.script.type === 'nOfK') {
          let ok = 0n;
          for (const r of work.childResults!) if (r) ok += 1n;
          result = ok >= work.script.n;
        }
        stack.pop();
        if (stack.length > 0) {
          const parent = stack[stack.length - 1]!;
          if (parent.phase === 'collect') {
            parent.childResults![parent.childIndex!] = result;
          }
        }
      } else {
        work.childIndex = nextIndex;
        stack.push({ phase: 'eval', script: children[nextIndex]! });
      }
    }
  }

  return result;
}

export function collectKeyHashes(s: NativeScript): Hex[] {
  const out: Hex[] = [];
  const stack: NativeScript[] = [s];

  while (stack.length > 0) {
    const script = stack.pop()!;

    if (script.type === 'sig') {
      if (!out.includes(script.keyHash)) out.push(script.keyHash);
    } else if (script.type === 'all' || script.type === 'any' || script.type === 'nOfK') {
      // Push in reverse order so they process in forward order
      for (let i = script.scripts.length - 1; i >= 0; i--) {
        stack.push(script.scripts[i]!);
      }
    }
  }

  return out;
}
