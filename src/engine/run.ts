// The scheduler of the incremental engine: one bounded run over a Store.
import { decodePayload } from '../payload.js';
import { afterTx, comparePos, endOf, type Pos } from '../position.js';
import { refKey } from '../state.js';
import { foreignJoinRefs } from './classify.js';
import { applyControl, type RuleObserver } from './control.js';
import { applyCredential } from './credential.js';
import { emptyChangeSet, stageKeys, type Step } from './lazyWorld.js';
import { routeTx } from './route.js';
import type { Budget, ChangeSet, CredentialInput, CursorUpdate, RunReport, Store, View } from './types.js';

export interface RunOptions {
  maxCommits?: number;           // stop after this many commits, for interruption tests
  observe?: RuleObserver;        // every rule result of an applied unit, exactly once
}

type Unit = { change: ChangeSet; cursor: CursorUpdate };
type Inputs = Parameters<typeof stageKeys>[1];

const posOf = (x: CredentialInput): Pos => (x.kind === 'ledger' ? x.at : x.q.at);

type Observed = Parameters<RuleObserver>[0];

// Loads the three key stages, each stage from the view of the one before, then runs the
// unit once on the complete view. Both units report rule results only when done, they go
// to `sink`, and the caller forwards them only once the commit that carries the unit has
// succeeded.
async function runUnit(
  store: Store, inputs: Inputs, overlay: ChangeSet[], sink: Observed[],
  apply: (view: View, observe: RuleObserver) => Step<ChangeSet>,
): Promise<ChangeSet> {
  let view: View | null = null;
  for (const stage of [1, 2, 3] as const) view = await store.load(stageKeys(stage, inputs, view, overlay), overlay);
  const step = apply(view as View, (r) => sink.push(r));
  if (!('done' in step)) throw new Error(`unit still needs keys after stage 3: ${JSON.stringify(step.need)}`);
  return step.done;
}

// One run, in order: an open recovery alone, otherwise one page of the group plane up to
// L, then one batch of credential units up to min(G, END(R)). Every write checks `lease`.
export async function runEngine(store: Store, budget: Budget, lease: string, opts: RunOptions = {}): Promise<RunReport> {
  const recovery = await store.pendingRecovery();
  if (recovery !== null) {
    const step = recovery.kind === 'truncate'
      ? await store.truncateStep(recovery.above, budget.truncateRows, lease)
      : await store.resetStep(recovery.kind, budget.resetRows, lease);
    if (step === 'done') await store.finishRecovery(recovery, lease);
    // The normal phase has not run yet and a second recovery slot may follow.
    return { phase: 'recovery', recovery, controlTxs: 0, units: 0, inputs: 0, G: null, more: true };
  }

  const maxCommits = opts.maxCommits ?? Number.POSITIVE_INFINITY;
  let commits = 0;
  const { L, R, G: G0 } = await store.frontiers();
  const report = (o: Partial<RunReport> & { G: Pos; more: boolean }): RunReport =>
    ({ phase: 'normal', recovery: null, controlTxs: 0, units: 0, inputs: 0, ...o });
  // One commit, then its rule results, so a failed or skipped commit reports nothing.
  const commit = async (units: Unit[], results: Observed[]): Promise<void> => {
    await store.commit(units, lease);
    commits++;
    if (opts.observe) for (const r of results) opts.observe(r);
  };
  // A stopped run computes no work it would then discard.
  if (commits >= maxCommits) return report({ G: G0, more: true });

  // Group plane. Each tx reads the change sets of the earlier txs of the page as overlay.
  const page = await store.nextLabelTxs(G0, L, budget.controlTxs, budget.controlBytes);
  if (page.txs.length === 0 && !page.done) throw new Error('nextLabelTxs returned an empty page that is not done');
  const overlay: ChangeSet[] = [];
  const groupUnits: Unit[] = [];
  const groupResults: Observed[] = [];
  let G = G0;
  for (const { tx } of page.txs) {
    const decoded = decodePayload(tx.payload ?? new Uint8Array(0));
    if (decoded === null) throw new Error(`stored label tx without a readable payload: ${tx.txHash}`);
    const joins = await store.queuedJoins(foreignJoinRefs(tx, decoded), overlay);
    const routed = routeTx(tx, decoded, (r) => joins.get(refKey(r)) ?? null);
    const change = await runUnit(store, { tx, routed }, overlay, groupResults, (v, o) => applyControl(v, tx, routed, overlay, o));
    overlay.push(change);
    G = afterTx(tx);
    groupUnits.push({ change, cursor: { kind: 'group', G } });
  }
  // A done page moves G to END(L) in the same commit, also when it holds no tx.
  const end = endOf(L);
  if (page.done && comparePos(G0, end) < 0) {
    G = end;
    const last = groupUnits[groupUnits.length - 1];
    if (last) last.cursor = { kind: 'group', G };
    else groupUnits.push({ change: emptyChangeSet(), cursor: { kind: 'group', G } });
  }
  if (groupUnits.length > 0) await commit(groupUnits, groupResults);
  const controlTxs = page.txs.length;
  if (commits >= maxCommits) return report({ controlTxs, G, more: true });

  // Credential units of one batch, each reading the earlier units of the batch as overlay.
  const ready = await store.readyCredentials(budget.credentialUnits, budget.credentialInputs, { G, R });
  const batch: ChangeSet[] = [];
  const credentialUnits: Unit[] = [];
  const credentialResults: Observed[] = [];
  let inputs = 0;
  for (const r of ready) {
    if (r.inputs.length === 0) continue;
    const change = await runUnit(store, { c: r.c, inputs: r.inputs }, batch, credentialResults, (v, o) => applyCredential(v, r.c, r.inputs, batch, o));
    batch.push(change);
    const appliedThrough = r.inputs.map(posOf).reduce((a, b) => (comparePos(a, b) >= 0 ? a : b));
    credentialUnits.push({ change, cursor: { kind: 'credential', credential: r.c, appliedThrough } });
    inputs += r.inputs.length;
  }
  if (credentialUnits.length > 0) await commit(credentialUnits, credentialResults);

  const more = !page.done || ready.some((r) => r.more)
    || ready.length >= budget.credentialUnits || inputs >= budget.credentialInputs;
  return report({ controlTxs, units: credentialUnits.length, inputs, G, more });
}
