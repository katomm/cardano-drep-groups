import { describe, expect, it } from 'vitest';
import { generateChain } from '../src/conformance/index.js';
import { BIG_BUDGET } from '../src/conformance/generate.js';
import { MemoryStore } from '../src/engine/memoryStore.js';
import { runEngine } from '../src/engine/run.js';
import type { View } from '../src/engine/types.js';
import { type Preview, type PreviewDeps, type PreviewEvent, previewTransaction } from '../src/preview.js';
import type { ChainInput, ChainTx } from '../src/types.js';
import { chainTx } from './engineFixture.js';
import { allOf, buildPayload, ev, hashOf, K, kb, keyCred, ref, regIn, sig, T, txIn } from './helpers.js';

type Observed = { txHash: string; index: number; tag: string | null; valid: boolean; reason: string | null };

// Runs the engine until it has nothing more to do and returns the rule results it observed.
async function runToDone(store: MemoryStore, lease: string): Promise<Observed[]> {
  const out: Observed[] = [];
  for (let i = 0; i < 100; i++) {
    const r = await runEngine(store, BIG_BUDGET, lease, { observe: (x) => out.push({ txHash: x.ref.txHash, index: x.ref.index, tag: x.tag, valid: x.valid, reason: x.reason }) });
    if (r.phase === 'normal' && !r.more) return out;
  }
  throw new Error('engine did not finish');
}

const depsOf = (store: MemoryStore): PreviewDeps => ({
  load: (keys) => store.load(keys, []),
  queuedJoins: (refs) => store.queuedJoins(refs, []),
});

// A store that has ingested and applied `inputs` up to their highest block.
async function storeOf(inputs: ChainInput[]): Promise<{ store: MemoryStore; lease: string; height: number }> {
  const store = new MemoryStore();
  const lease = store.acquireLease('test');
  let height = 0;
  for (const x of inputs) {
    if (x.kind === 'tx') store.ingestLabelTx(x.tx);
    else store.ingestLedgerRow(x.input);
    height = Math.max(height, x.kind === 'tx' ? x.tx.blockHeight : x.input.blockHeight);
  }
  store.setFrontiers({ L: height, R: height });
  await runToDone(store, lease);
  return { store, lease, height };
}

const eventsOf = (p: Preview): PreviewEvent[] => {
  if (!('events' in p)) throw new Error(`ignored: ${p.ignored}`);
  return p.events;
};

// Keys and scripts. A signs the control policy, M is a key DRep.
const A = K(1);
const CTL = sig(A);
const ctl = hashOf(CTL);
const M = K(0x21);
const m = keyCred(M);
const create = (tx: number, h: number, mode: 0 | 1): ChainInput =>
  txIn({ hash: T(tx), h, rs: [A], payload: buildPayload([ev.create(mode, ctl, mode === 1 ? ctl : null)], [CTL]) });
const regM = (h: number): ChainInput => regIn(m, T(0xe0), h);

describe('previewTransaction', () => {
  it('matches the engine for the next tx of every generated chain', async () => {
    const started = Date.now();
    let compared = 0;
    for (let seed = 1; seed <= 200; seed++) {
      const chain = generateChain(seed);
      const last = chain.map((x) => x.kind === 'tx').lastIndexOf(true);
      if (last < 0) continue;
      const { store, lease, height } = await storeOf(chain.slice(0, last));
      const orig = (chain[last] as { kind: 'tx'; tx: ChainTx }).tx;
      // The next tx sits after everything the store has ingested.
      const tx: ChainTx = { ...orig, blockHeight: Math.max(orig.blockHeight, height + 1) };
      const preview = await previewTransaction(depsOf(store), tx);

      const stored = store.ingestLabelTx(tx);
      store.setFrontiers({ L: tx.blockHeight, R: tx.blockHeight });
      const engine = (await runToDone(store, lease))
        .filter((x) => x.txHash === tx.txHash)
        .map(({ index, tag, valid, reason }) => ({ index, tag, valid, reason }))
        .sort((a, b) => a.index - b.index);
      try {
        if ('ignored' in preview) {
          expect(stored).toBe('marker');
          expect(engine).toEqual([]);
        } else if (stored === 'marker') {
          // A payload without a readable event: the engine skips it, preview reports every event invalid.
          expect(engine).toEqual([]);
          expect(preview.events.every((e) => !e.valid)).toBe(true);
        } else {
          expect(preview.events).toEqual(engine);
          compared++;
        }
      } catch (e) {
        if (e instanceof Error) e.message = `seed ${seed}: ${e.message}`;
        throw e;
      }
    }
    expect(compared).toBeGreaterThan(150);
    if (process.env.PREVIEW_TIMING) console.log(`200 seeds in ${Date.now() - started} ms`);
  }, 120_000);

  it('sees scripts published in the same payload', async () => {
    const { store } = await storeOf([]);
    const tx = (create(1, 1, 0) as { kind: 'tx'; tx: ChainTx }).tx;
    expect(eventsOf(await previewTransaction(depsOf(store), tx))).toEqual([{ index: 0, tag: 'create', valid: true, reason: null }]);
  });

  it('keeps required signers apart from witnesses', async () => {
    const { store } = await storeOf([create(1, 1, 0), regM(2)]);
    const payload = buildPayload([ev.join(ref(T(1), 0), 'key', M)]);
    const witnessOnly = chainTx({ hash: T(2), h: 3, wk: [M], payload });
    expect(eventsOf(await previewTransaction(depsOf(store), witnessOnly)))
      .toEqual([{ index: 0, tag: 'join', valid: false, reason: 'member key not in required_signers' }]);
    const required = chainTx({ hash: T(2), h: 3, rs: [M], payload });
    expect(eventsOf(await previewTransaction(depsOf(store), required)))
      .toEqual([{ index: 0, tag: 'join', valid: true, reason: null }]);
  });

  it('judges a combined approve and update in event order', async () => {
    const join = txIn({ hash: T(2), h: 3, rs: [M], payload: buildPayload([ev.join(ref(T(1), 0), 'key', M)]) });
    const { store } = await storeOf([create(1, 1, 1), regM(2), join]);
    const NEW = allOf(sig(A), sig(M));
    const payload = buildPayload([ev.approve(ref(T(2), 0)), ev.update(ref(T(1), 0), 0, new Map([[0, kb(hashOf(NEW))]]))], [NEW]);
    const signed = chainTx({ hash: T(3), h: 4, rs: [M], wk: [A], payload });
    expect(eventsOf(await previewTransaction(depsOf(store), signed))).toEqual([
      { index: 0, tag: 'approve', valid: true, reason: null },
      { index: 1, tag: 'update', valid: true, reason: null },
    ]);
    const unsigned = chainTx({ hash: T(3), h: 4, wk: [A], payload });
    expect(eventsOf(await previewTransaction(depsOf(store), unsigned))).toEqual([
      { index: 0, tag: 'approve', valid: true, reason: null },
      { index: 1, tag: 'update', valid: false, reason: 'key new to its role did not sign explicitly' },
    ]);
  });

  it('reports decode failures and orphans at their index', async () => {
    const { store } = await storeOf([]);
    const payload = buildPayload([ev.create(0, ctl, null), [99], ev.approve(ref(T(0x77), 0))], [CTL]);
    const events = eventsOf(await previewTransaction(depsOf(store), chainTx({ hash: T(1), h: 1, rs: [A], payload })));
    expect(events.map((e) => e.index)).toEqual([0, 1, 2]);
    expect(events[0]).toEqual({ index: 0, tag: 'create', valid: true, reason: null });
    expect(events[1]).toMatchObject({ index: 1, tag: null, valid: false });
    expect(typeof events[1]?.reason).toBe('string');
    expect(events[2]).toEqual({ index: 2, tag: 'approve', valid: false, reason: 'unknown join' });
  });

  it('reports phase-2 invalid and repeated labels as ignored', async () => {
    const { store } = await storeOf([]);
    const payload = buildPayload([ev.create(0, ctl, null)], [CTL]);
    expect(await previewTransaction(depsOf(store), chainTx({ hash: T(1), h: 1, wk: [A], payload, valid: false })))
      .toEqual({ ignored: 'phase-2 invalid' });
    expect(await previewTransaction(depsOf(store), chainTx({ hash: T(1), h: 1, wk: [A], repeated: true })))
      .toEqual({ ignored: 'label repeated' });
    expect(await previewTransaction(depsOf(store), chainTx({ hash: T(1), h: 1, wk: [A], payload: new Uint8Array([0xff]) })))
      .toEqual({ ignored: 'payload rejected' });
  });

  it('takes registration answers from the loaded view', async () => {
    const { store } = await storeOf([create(1, 1, 0)]);
    const tx = chainTx({ hash: T(2), h: 3, rs: [M], payload: buildPayload([ev.join(ref(T(1), 0), 'key', M)]) });
    expect(eventsOf(await previewTransaction(depsOf(store), tx))[0]?.reason).toBe('not a registered DRep');
    // A caller that knows of a registration in the same unsubmitted tx answers it through its view.
    const registered = (v: View): View => Object.assign(Object.create(v) as View, { registeredAt: () => true });
    const deps: PreviewDeps = { ...depsOf(store), load: async (keys) => registered(await store.load(keys, [])) };
    expect(eventsOf(await previewTransaction(deps, tx))[0]).toEqual({ index: 0, tag: 'join', valid: true, reason: null });
  });

  it('throws for a tx without a label payload and ignores a repeated label', async () => {
    const { store } = await storeOf([create(1, 1, 0)]);
    const bare = chainTx({ hash: T(2), h: 3 });
    await expect(previewTransaction(depsOf(store), bare)).rejects.toThrow('tx carries no label 8416 payload');
    const repeated = chainTx({ hash: T(2), h: 3, payload: buildPayload([ev.approve(ref(T(1), 0))]) });
    expect(await previewTransaction(depsOf(store), { ...repeated, payloadRepeated: true })).toEqual({ ignored: 'label repeated' });
  });

  it('is inconclusive while the ledger frontier lags the label frontier', async () => {
    const store = new MemoryStore();
    const lease = store.acquireLease('test');
    const join = txIn({ hash: T(2), h: 5, rs: [M], payload: buildPayload([ev.join(ref(T(1), 0), 'key', M)]) });
    for (const x of [create(1, 1, 1), regM(2), join]) {
      if (x.kind === 'tx') store.ingestLabelTx(x.tx);
      else store.ingestLedgerRow(x.input);
    }
    store.setFrontiers({ L: 5, R: 3 });
    await runToDone(store, lease);
    const approve = chainTx({ hash: T(3), h: 6, wk: [A], payload: buildPayload([ev.approve(ref(T(2), 0))]) });
    expect(eventsOf(await previewTransaction(depsOf(store), approve))[0]?.reason).toBe('unknown join');
    // Once the frontiers meet, the engine itself judges the join and the approval valid.
    store.ingestLabelTx(approve);
    store.setFrontiers({ L: 6, R: 6 });
    const seen = await runToDone(store, lease);
    expect(seen.map((o) => [o.tag, o.valid])).toEqual([['join', true], ['approve', true]]);
  });
});
