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
