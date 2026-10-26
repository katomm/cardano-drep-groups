import type { Hex, LedgerInput, TxPosition } from './types.js';

// Full position of a certificate, a payload's scripts or an event. Ordered by
// (blockHeight, txIndex, phase, index), the tx hash never takes part in the order.
// Phase 0 is a certificate (index = cert index), phase 1 the payload scripts
// (index = -1), phase 2 an event (index = event index).
export interface Pos { blockHeight: number; txIndex: number; txHash: Hex; phase: 0 | 1 | 2; index: number }

export function comparePos(a: Pos, b: Pos): number {
  return a.blockHeight - b.blockHeight || a.txIndex - b.txIndex || a.phase - b.phase || a.index - b.index;
}

// The end of block h: after every position of h and before (h + 1, 0, 0, 0). Never a real tx position.
export const endOf = (h: number): Pos =>
  ({ blockHeight: h, txIndex: Number.MAX_SAFE_INTEGER, txHash: '', phase: 2, index: Number.MAX_SAFE_INTEGER });

export const isEnd = (p: Pos): boolean => p.txIndex === Number.MAX_SAFE_INTEGER && p.txHash === '';

// The position just past every event of a tx.
export const afterTx = (tx: TxPosition): Pos =>
  ({ blockHeight: tx.blockHeight, txIndex: tx.txIndex, txHash: tx.txHash, phase: 2, index: Number.MAX_SAFE_INTEGER });

export const posOfCert = (l: LedgerInput): Pos =>
  ({ blockHeight: l.blockHeight, txIndex: l.txIndex, txHash: l.txHash, phase: 0, index: l.certIndex });

export const posOfScripts = (tx: TxPosition): Pos =>
  ({ blockHeight: tx.blockHeight, txIndex: tx.txIndex, txHash: tx.txHash, phase: 1, index: -1 });

export const posOfEvent = (tx: TxPosition, index: number): Pos =>
  ({ blockHeight: tx.blockHeight, txIndex: tx.txIndex, txHash: tx.txHash, phase: 2, index });

// A string key of the order fields, for maps keyed by position. The tx hash is left out
// as in the order.
export const posKey = (p: Pos): string => `${p.blockHeight},${p.txIndex},${p.phase},${p.index}`;

export const minPos = (a: Pos, b: Pos): Pos => (comparePos(a, b) <= 0 ? a : b);
export const maxPos = (a: Pos, b: Pos): Pos => (comparePos(a, b) >= 0 ? a : b);
