// Pure classification of newly stored inputs: ordinary, or late and therefore a recovery.
import { comparePos, type Pos } from '../position.js';
import type { ChainTx, DecodedPayload, EventRef } from '../types.js';
import type { Recovery, RecoveryState } from './types.js';

// Blocks below L that are still treated as reorg-able (the security parameter k).
export const RETENTION_FLOOR = 2160;

// A label tx at or below G, or a ledger row at or below the credential's applied-through
// position, is late. Completeness of the credential never enters the decision.
export function classifyNewInput(
  input: { kind: 'labelTx' | 'ledger'; at: Pos },
  state: { G: Pos; appliedThrough: Pos | null; L: number },
): 'ordinary' | Recovery {
  const late = input.kind === 'labelTx'
    ? comparePos(input.at, state.G) <= 0
    : state.appliedThrough !== null && comparePos(input.at, state.appliedThrough) <= 0;
  if (!late) return 'ordinary';
  const above = input.at.blockHeight - 1;
  return above < state.L - RETENTION_FLOOR ? { kind: 'fork' } : { kind: 'truncate', above };
}

// State transition for a newly opened recovery. A fork replaces everything, a truncation
// keeps the lower cut, and a truncation during a rebuild runs after it.
export function mergeRecovery(current: RecoveryState, next: Recovery): RecoveryState {
  if (next.kind === 'fork') return { first: next, then: null };
  const first = current.first;
  if (first === null) return { first: next, then: current.then };
  if (first.kind === 'fork') return current;
  if (first.kind === 'truncate') {
    if (next.kind === 'truncate') return { first: { kind: 'truncate', above: Math.min(first.above, next.above) }, then: current.then };
    // A rebuild is not representable behind a truncation, so it runs first and the
    // truncation (still needed, it deletes raw inputs) follows. Nothing is lost.
    const above = current.then === null ? first.above : Math.min(current.then.above, first.above);
    return { first: next, then: { kind: 'truncate', above } };
  }
  // first is a rebuild
  if (next.kind === 'rebuild') return current;
  const then = current.then === null ? next : { kind: 'truncate' as const, above: Math.min(current.then.above, next.above) };
  return { first, then };
}

// Refs of approve, leave and remove events that name a join in another tx, unique.
// Read before routing so the queue entries of those joins can be loaded.
export function foreignJoinRefs(tx: ChainTx, decoded: DecodedPayload): EventRef[] {
  const seen = new Set<string>();
  const out: EventRef[] = [];
  for (const d of decoded.events) {
    if (!d.ok) continue;
    const e = d.event;
    if (e.tag !== 'approve' && e.tag !== 'leave' && e.tag !== 'remove') continue;
    if (!('txHash' in e.join) || e.join.txHash === tx.txHash) continue;
    const key = `${e.join.txHash}#${e.join.index}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ txHash: e.join.txHash, index: e.join.index });
  }
  return out;
}
