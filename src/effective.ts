import { comparePos, type Pos } from './position.js';

export type CloseReason = 'left' | 'removed' | 'retired' | 'dissolved';

// The effective close of an instance: the earliest of its explicit close, the dissolve
// of its group after the join and the first unreg of its member after the join. Each
// cause counts only at or before q, no q means no bound. Ties follow the position order,
// so an unreg in phase 0 precedes a dissolve in phase 2 of the same tx.
export function effectiveClose(
  inst: { joinedAt: Pos; closedAt: Pos | null; closeReason: 'left' | 'removed' | null },
  dissolveAt: Pos | null,
  firstUnregAfterJoin: Pos | null,
  q?: Pos,
): { at: Pos; reason: CloseReason } | null {
  let best: { at: Pos; reason: CloseReason } | null = null;
  const consider = (at: Pos | null, reason: CloseReason, afterJoin: boolean): void => {
    if (at === null) return;
    if (afterJoin && comparePos(at, inst.joinedAt) <= 0) return;
    if (q !== undefined && comparePos(at, q) > 0) return;
    if (best === null || comparePos(at, best.at) < 0) best = { at, reason };
  };
  if (inst.closedAt !== null && inst.closeReason !== null) consider(inst.closedAt, inst.closeReason, false);
  consider(dissolveAt, 'dissolved', true);
  consider(firstUnregAfterJoin, 'retired', true);
  return best;
}
