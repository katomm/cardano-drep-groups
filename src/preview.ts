// Preview of an unsubmitted transaction: every event judged with the engine's own rules
// over the caller's committed state, without writing anything.
import { foreignJoinRefs } from './engine/classify.js';
import { applyControl, type RuleObserver } from './engine/control.js';
import { applyCredential } from './engine/credential.js';
import { loadAndApply } from './engine/run.js';
import { routeTx } from './engine/route.js';
import type { ChangeSet, CredentialInput, Keys, View } from './engine/types.js';
import { decodePayload } from './payload.js';
import { comparePos } from './position.js';
import { credKey, refKey } from './state.js';
import type { ChainTx, Credential, DecodedEvent, EventRef, GroupEvent, IgnoredTx } from './types.js';

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
export async function previewTransaction(deps: PreviewDeps, tx: ChainTx): Promise<Preview> {
  if (!tx.isValid) return { ignored: 'phase-2 invalid' };
  if (tx.payloadRepeated || tx.payload === undefined) return { ignored: 'label repeated' };
  const decoded = decodePayload(tx.payload);
  if (decoded === null) return { ignored: 'payload rejected' };

  const results: Observed[] = [];
  const joins = await deps.queuedJoins(foreignJoinRefs(tx, decoded));
  const routed = routeTx(tx, decoded, (r) => joins.get(refKey(r)) ?? null);
  const control = await loadAndApply((k) => deps.load(k), { tx, routed }, [], results,
    (v, o) => applyControl(v, tx, routed, [], o));

  // The control step queued every membership event with the tx context, as the engine stores them.
  const context = control.txContexts[0]?.context;
  const bySubject = new Map<string, { c: Credential; inputs: CredentialInput[] }>();
  for (const q of control.queued) {
    if (!context) throw new Error('control step wrote no tx context');
    const entry = bySubject.get(credKey(q.subject)) ?? { c: q.subject, inputs: [] };
    entry.inputs.push({ kind: 'event', q, tx: context });
    bySubject.set(credKey(q.subject), entry);
  }
  // Oldest first input, then credential key, as readyCredentials orders a batch.
  const units = [...bySubject.values()].sort((a, b) => {
    const pa = a.inputs[0] as Extract<CredentialInput, { kind: 'event' }>;
    const pb = b.inputs[0] as Extract<CredentialInput, { kind: 'event' }>;
    const ka = credKey(a.c);
    const kb = credKey(b.c);
    return comparePos(pa.q.at, pb.q.at) || (ka < kb ? -1 : ka > kb ? 1 : 0);
  });
  const overlay: ChangeSet[] = [control];
  for (const u of units) {
    const before = [...overlay];
    overlay.push(await loadAndApply((k) => deps.load(k), { c: u.c, inputs: u.inputs }, before, results,
      (v, o) => applyCredential(v, u.c, u.inputs, before, o)));
  }

  const byIndex = new Map<number, PreviewEvent>();
  for (const r of results) {
    if (r.ref.txHash !== tx.txHash || byIndex.has(r.ref.index)) throw new Error(`unexpected rule result for ${refKey(r.ref)}`);
    byIndex.set(r.ref.index, { index: r.ref.index, tag: r.tag as GroupEvent['tag'] | null, valid: r.valid, reason: r.reason });
  }
  const events = decoded.events.map((_, index) => {
    const e = byIndex.get(index);
    if (!e) throw new Error(`no rule result for event ${index}`);
    return e;
  });
  return { events };
}
