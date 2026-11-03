// Preview of an unsubmitted transaction: every event judged with the engine's own rules
// over the caller's committed state, without writing anything.
import { foreignJoinRefs } from './engine/classify.js';
import { applyControl, type RuleObserver } from './engine/control.js';
import { applyCredential } from './engine/credential.js';
import { type CredentialUnit, loadAndApply, orderCredentialUnits } from './engine/run.js';
import { routeTx } from './engine/route.js';
import type { ChangeSet, Keys, View } from './engine/types.js';
import { decodePayload } from './payload.js';
import { credKey, refKey } from './state.js';
import type { ChainTx, DecodedEvent, EventRef, GroupEvent, IgnoredTx } from './types.js';

export interface PreviewDeps {
  // A bounded view of the committed state for `keys`. Every registration, member script
  // and other answer of the preview comes from the views this returns.
  load(keys: Keys): Promise<View>;
  // The stored queue entries of the joins named by refs, keyed by refKey, 'ignored' for a marker tx.
  queuedJoins(refs: EventRef[]): Promise<Map<string, DecodedEvent | 'ignored'>>;
}
export interface PreviewEvent { index: number; tag: GroupEvent['tag'] | null; valid: boolean; reason: string | null }
export type Preview = { ignored: IgnoredTx['reason'] } | { events: PreviewEvent[] };

type Observed = Parameters<RuleObserver>[0];

// Judges `tx` as the engine would apply it next. The caller sets its position after
// everything it has ingested and passes required signers and vkey witnesses apart. The
// control step runs first, then one credential step per subject in the order the engine
// would batch them, each reading the earlier steps as overlay. Nothing is written.
//
// Precondition: the engine applies credential inputs only up to min(G, END(R)). While the
// ledger frontier R lags the label frontier L, membership events between END(R) and L are
// still pending, so the preview can report an unknown join or a wrong registration answer.
// The preview is exact once runEngine reports more: false with R at or above L, otherwise
// its verdicts are inconclusive.
export async function previewTransaction(deps: PreviewDeps, tx: ChainTx): Promise<Preview> {
  if (!tx.isValid) return { ignored: 'phase-2 invalid' };
  if (tx.payloadRepeated) return { ignored: 'label repeated' };
  if (tx.payload === undefined) throw new Error('tx carries no label 8416 payload');
  const decoded = decodePayload(tx.payload);
  if (decoded === null) return { ignored: 'payload rejected' };

  const results: Observed[] = [];
  const joins = await deps.queuedJoins(foreignJoinRefs(tx, decoded));
  const routed = routeTx(tx, decoded, (r) => joins.get(refKey(r)) ?? null);
  const control = await loadAndApply((k) => deps.load(k), { tx, routed }, [], results,
    (v, o) => applyControl(v, tx, routed, [], o));

  // The control step queued every membership event with the tx context, as the engine stores them.
  const bySubject = new Map<string, CredentialUnit>();
  if (control.queued.length > 0) {
    const context = control.txContexts[0]?.context;
    if (!context) throw new Error('control step wrote no tx context');
    for (const q of control.queued) {
      const k = credKey(q.subject);
      const unit = bySubject.get(k) ?? { c: q.subject, inputs: [] };
      unit.inputs.push({ kind: 'event', q, tx: context });
      bySubject.set(k, unit);
    }
  }
  const overlay: ChangeSet[] = [control];
  for (const u of orderCredentialUnits(bySubject.values())) {
    overlay.push(await loadAndApply((k) => deps.load(k), { c: u.c, inputs: u.inputs }, overlay, results,
      (v, o) => applyCredential(v, u.c, u.inputs, overlay, o)));
  }

  const events: PreviewEvent[] = new Array(decoded.events.length);
  for (const r of results) {
    if (r.ref.txHash !== tx.txHash || events[r.ref.index] !== undefined) throw new Error(`unexpected rule result for ${refKey(r.ref)}`);
    events[r.ref.index] = { index: r.ref.index, tag: r.tag as GroupEvent['tag'] | null, valid: r.valid, reason: r.reason };
  }
  for (let i = 0; i < events.length; i++) if (events[i] === undefined) throw new Error(`no rule result for event ${i}`);
  return { events };
}
