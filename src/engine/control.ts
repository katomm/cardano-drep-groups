// The group plane unit: applies one stored label tx over a bounded view.
import { posOfScripts } from '../position.js';
import { controlRule, resolve } from '../rules.js';
import type { ChainTx, EvalContext, EventRef, Hex } from '../types.js';
import { emptyChangeSet, isEmptyKeys, LazyWorld, type Step } from './lazyWorld.js';
import type { ChangeSet, Routed, RoutedEvent, TxContext, View } from './types.js';

export type RuleObserver = (r: { ref: EventRef; tag: string | null; valid: boolean; reason: string | null }) => void;

const unique = (xs: Hex[]): Hex[] => [...new Set(xs)];

// Signers are required signers and vkey witnesses together, as replay builds them.
export const txContextOf = (tx: ChainTx): TxContext => ({
  signers: unique([...tx.requiredSigners, ...tx.witnessKeyHashes]),
  requiredSigners: [...tx.requiredSigners],
  invalidBefore: tx.invalidBefore,
  invalidHereafter: tx.invalidHereafter,
});

// The reason replay gives an orphan. Orphans have no group, so it only reaches the observer.
function orphanReason(r: RoutedEvent): string {
  if (!r.decoded.ok) return r.decoded.reason;
  const e = r.decoded.event;
  if ('join' in e && 'local' in e.join && e.join.local >= r.ref.index) return 'local reference must point to an earlier event';
  return 'unknown join';
}

// Writes the key 2 scripts, the tx context, the control events through the A4 rules and
// their verdicts when they have a group, and a queue entry for every membership event.
// Pure over the view: when a read hits a key the view was not loaded for, the unit
// returns every such key instead of a change set.
export function applyControl(view: View, tx: ChainTx, routed: Routed, observe?: RuleObserver): Step<ChangeSet> {
  const own = emptyChangeSet();
  const world = new LazyWorld(view, [], own);
  const scriptsAt = posOfScripts(tx);
  for (const s of routed.scripts) {
    if (!own.scripts.some((x) => x.hash === s.hash)) own.scripts.push({ hash: s.hash, script: s.script, bytes: s.bytes, at: scriptsAt });
  }
  const context = txContextOf(tx);
  own.txContexts.push({ txHash: tx.txHash, context });
  const ctx: EvalContext = { signers: new Set(context.signers), invalidBefore: tx.invalidBefore, invalidHereafter: tx.invalidHereafter };

  for (const r of routed.events) {
    if (r.plane === 'orphan') {
      observe?.({ ref: r.ref, tag: r.decoded.ok ? r.decoded.event.tag : null, valid: false, reason: orphanReason(r) });
      continue;
    }
    if (!r.decoded.ok) continue; // routing makes every undecodable event an orphan
    const e = r.decoded.event;
    if (r.plane === 'membership') {
      // A join names its group, approve, leave and remove are grouped by their credential unit.
      const group = e.tag === 'join' ? resolve(e.group, r.ref) : null;
      own.queued.push({ subject: r.subject as NonNullable<typeof r.subject>, at: r.at, group, txHash: tx.txHash, event: r.decoded });
      continue;
    }
    const res = controlRule(world, e, r.ref, ctx, r.at);
    for (const w of res.writes) if (w.kind === 'version') own.versions.push(w.version);
    const valid = res.reason === null;
    observe?.({ ref: r.ref, tag: e.tag, valid, reason: res.reason });
    if (res.group !== null) {
      own.verdicts.push({ ref: r.ref, tag: e.tag, valid, reason: res.reason, at: r.at, group: res.group, subject: res.subject });
    }
    if (valid && e.tag === 'dissolve' && res.group !== null) own.effects.push({ kind: 'groupDissolved', group: res.group, at: r.at });
  }
  return isEmptyKeys(world.needed) ? { done: own } : { need: world.needed };
}
