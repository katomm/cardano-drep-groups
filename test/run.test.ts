import { describe, expect, it } from 'vitest';
import { MemoryStore, type MemoryStoreSnapshot } from '../src/engine/memoryStore.js';
import { runEngine } from '../src/engine/run.js';
import { type Budget, type ChangeSet, type CursorUpdate, type Keys, LeaseLostError, type RunReport, type View } from '../src/engine/types.js';
import { afterTx, endOf, posOfCert, posOfEvent } from '../src/position.js';
import { refKey } from '../src/state.js';
import type { ChainTx, Credential, LedgerInput } from '../src/types.js';
import { chainTx } from './engineFixture.js';
import { buildPayload, ev, hashOf, K, kb, keyCred, ref, sig, T } from './helpers.js';

const BIG: Budget = { controlTxs: 100, controlBytes: 1_000_000, credentialUnits: 100, credentialInputs: 1000, truncateRows: 1000, resetRows: 1000 };
const budget = (o: Partial<Budget> = {}): Budget => ({ ...BIG, ...o });

const fresh = (s = new MemoryStore({})) => ({ s, lease: s.acquireLease('test') });
const commits = (s: MemoryStore): number => s.stats.calls.commit ?? 0;
const withoutStats = ({ stats: _stats, ...rest }: MemoryStoreSnapshot) => rest;

type Observed = { ref: { txHash: string; index: number }; tag: string | null; valid: boolean; reason: string | null };

// Runs until a run reports no more work, with a cap so a wrong `more` fails instead of hanging.
async function runUntilDone(
  s: MemoryStore, lease: string, b: Budget = BIG, observe?: (r: Observed) => void,
): Promise<RunReport[]> {
  const reports: RunReport[] = [];
  for (let i = 0; i < 100; i++) {
    const r = await runEngine(s, b, lease, { observe });
    reports.push(r);
    if (!r.more) return reports;
  }
  throw new Error('runEngine did not settle');
}

const reg = (c: Credential, hash: string, h: number, i = 0): LedgerInput =>
  ({ kind: 'reg', credential: c, txHash: hash, blockHeight: h, txIndex: i, certIndex: 0 });

const C0 = sig(K(1));
const A0 = sig(K(2));
const C1 = sig(K(3));
const X = sig(K(4));
const M7 = keyCred(K(7));
const M9 = keyCred(K(9));
const G1 = ref(T(0x10), 0);

const create = chainTx({ hash: T(0x10), h: 10, rs: [K(1), K(2)], payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0))], [C0, A0]) });
const join7 = (h: number, hash = T(0x20), i = 0): ChainTx =>
  chainTx({ hash, h, i, rs: [K(7)], payload: buildPayload([ev.join(G1, 'key', K(7))]) });
const queueOf = (s: MemoryStore, txHash: string) => s.snapshot().queue.filter((q) => q.txHash === txHash);
const verdictOf = (s: MemoryStore, txHash: string) => s.snapshot().verdicts.filter((v) => v.ref.txHash === txHash);

describe('runEngine recovery', () => {
  it('runs an open truncation and nothing else', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(create);
    s.ingestLabelTx(join7(20));
    s.setFrontiers({ L: 30, R: 30 });
    await runUntilDone(s, lease);
    expect(s.snapshot().instances).toHaveLength(1);

    await s.openRecovery({ kind: 'truncate', above: 15 }, lease);
    const label = s.stats.calls.nextLabelTxs;
    const ready = s.stats.calls.readyCredentials;
    const first = await runEngine(s, budget({ truncateRows: 1 }), lease);
    expect(first).toMatchObject({ phase: 'recovery', recovery: { kind: 'truncate', above: 15 }, more: true });
    expect(await s.pendingRecovery()).toEqual({ kind: 'truncate', above: 15 });
    let runs = 1;
    while ((await s.pendingRecovery()) !== null) {
      const r = await runEngine(s, budget({ truncateRows: 1 }), lease);
      expect(r.phase).toBe('recovery');
      runs++;
      expect(runs).toBeLessThan(50);
    }
    expect(runs).toBeGreaterThan(1);
    // No group plane and no credential unit ran while the truncation was open.
    expect(s.stats.calls.nextLabelTxs).toBe(label);
    expect(s.stats.calls.readyCredentials).toBe(ready);
    const snap = s.snapshot();
    expect(snap.instances).toEqual([]);
    expect(snap.frontiers).toEqual({ L: 15, R: 15, G: endOf(15) });
    expect(snap.recovery).toEqual({ first: null, then: null });
  });

  it('finishes a step that reports done in the same run', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(create);
    s.setFrontiers({ L: 30 });
    await runUntilDone(s, lease);
    await s.openRecovery({ kind: 'truncate', above: 5 }, lease);
    const r = await runEngine(s, BIG, lease);
    expect(r).toMatchObject({ phase: 'recovery', recovery: { kind: 'truncate', above: 5 } });
    expect(await s.pendingRecovery()).toBeNull();
  });

  it('runs a rebuild within the reset budget, then the second slot, then reapplies', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(create);
    s.ingestLabelTx(join7(20));
    s.setFrontiers({ L: 30, R: 30 });
    await runUntilDone(s, lease);
    const { frontiers: _f, ...before } = withoutStats(s.snapshot());

    await s.openRecovery({ kind: 'rebuild' }, lease);
    await s.openRecovery({ kind: 'truncate', above: 25 }, lease);
    const kinds: string[] = [];
    while ((await s.pendingRecovery()) !== null) {
      const r = await runEngine(s, budget({ resetRows: 2, truncateRows: 1 }), lease);
      expect(r.phase).toBe('recovery');
      kinds.push(r.recovery?.kind ?? 'none');
      expect(kinds.length).toBeLessThan(50);
    }
    expect(kinds[0]).toBe('rebuild');
    expect(kinds.filter((k) => k === 'rebuild').length).toBeGreaterThan(1); // the budget of 2 rows needs several steps
    expect(kinds[kinds.length - 1]).toBe('truncate');
    expect(s.snapshot().frontiers.G).toEqual(endOf(-1));

    await runUntilDone(s, lease);
    const { frontiers: _g, ...after } = withoutStats(s.snapshot());
    expect(after).toEqual(before); // nothing of the chain lies above the cut
    expect(s.snapshot().frontiers).toEqual({ L: 25, R: 25, G: endOf(25) });
  });
});

describe('runEngine recovery merged during a step', () => {
  // The Store contract forbids ingest while a run is in flight. This store breaks it on
  // purpose: a late tx arrives after the truncation step reported done and before the run
  // finishes the recovery, so the first slot is merged to a lower cut in between.
  class LateIngestStore extends MemoryStore {
    late: ChainTx | null = null;
    override async truncateStep(above: number, budget: number, lease: string): Promise<'more' | 'done'> {
      const step = await super.truncateStep(above, budget, lease);
      if (step === 'done' && this.late) {
        this.ingestLabelTx(this.late);
        this.late = null;
      }
      return step;
    }
  }

  it('keeps a truncation merged after the step and applies the late tx', async () => {
    const s = new LateIngestStore({});
    const lease = s.acquireLease('test');
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLedgerRow(reg(M9, T(0xa2), 5));
    s.ingestLabelTx(create);
    s.ingestLabelTx(join7(30));
    s.setFrontiers({ L: 40, R: 40 });
    await runUntilDone(s, lease);

    const join9 = chainTx({ hash: T(0x21), h: 20, rs: [K(9)], payload: buildPayload([ev.join(G1, 'key', K(9))]) });
    s.late = join9;
    await s.openRecovery({ kind: 'truncate', above: 25 }, lease);
    const r = await runEngine(s, BIG, lease);
    expect(r).toMatchObject({ phase: 'recovery', recovery: { kind: 'truncate', above: 25 } });
    // The late tx at 20 merged the slot to a cut above 19, finishing the old step keeps it.
    expect(await s.pendingRecovery()).toEqual({ kind: 'truncate', above: 19 });
    while ((await s.pendingRecovery()) !== null) await runEngine(s, BIG, lease);

    // The readers deliver again after the cut, as they do after every truncation.
    s.ingestLabelTx(join7(30));
    s.ingestLabelTx(join9);
    s.setFrontiers({ L: 40, R: 40 });
    await runUntilDone(s, lease);
    expect(s.snapshot().instances.map((i) => i.joinId.txHash).sort()).toEqual([T(0x20), T(0x21)].sort());
    expect(verdictOf(s, T(0x21))).toMatchObject([{ tag: 'join', valid: true }]);
  });
});

describe('runEngine group plane', () => {
  it('advances G to END(L) when no stored label tx is left', async () => {
    const { s, lease } = fresh();
    s.setFrontiers({ L: 50 });
    const r = await runEngine(s, BIG, lease);
    expect(r).toMatchObject({ phase: 'normal', controlTxs: 0, G: endOf(50), more: false });
    expect(s.snapshot().frontiers.G).toEqual(endOf(50));
    expect(commits(s)).toBe(1);
    // Nothing left: no further commit.
    await runEngine(s, BIG, lease);
    expect(commits(s)).toBe(1);

    s.ingestLabelTx(chainTx({ hash: T(0x60), h: 60, rs: [K(1), K(2)], payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0))], [C0, A0]) }));
    s.setFrontiers({ L: 80 });
    await runEngine(s, BIG, lease);
    expect(s.snapshot().frontiers.G).toEqual(endOf(80));
    expect(s.snapshot().groups).toHaveLength(1);
  });

  it('does not move G past an unprocessed stored tx when the byte budget cuts the page', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(create);
    const second = chainTx({ hash: T(0x11), h: 11, rs: [K(1), K(2)], payload: buildPayload([ev.create(0, hashOf(C0), null)]) });
    s.ingestLabelTx(second);
    s.setFrontiers({ L: 30 });
    const first = await runEngine(s, budget({ controlBytes: (create.payload as Uint8Array).length }), lease);
    expect(first).toMatchObject({ controlTxs: 1, G: afterTx(create), more: true });
    expect(s.snapshot().frontiers.G).toEqual(afterTx(create));
    expect(s.snapshot().groups.map((g) => g.id.txHash)).toEqual([T(0x10)]);
    const next = await runEngine(s, budget({ controlBytes: (create.payload as Uint8Array).length }), lease);
    expect(next).toMatchObject({ controlTxs: 1, G: endOf(30) });
    expect(s.snapshot().groups.map((g) => g.id.txHash)).toEqual([T(0x10), T(0x11)]);
  });

  it('returns an oversized tx alone and applies it', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(create);
    s.ingestLabelTx(chainTx({ hash: T(0x11), h: 11, rs: [K(1), K(2)], payload: buildPayload([ev.create(0, hashOf(C0), null)]) }));
    s.setFrontiers({ L: 30 });
    const r = await runEngine(s, budget({ controlBytes: 1 }), lease);
    expect(r).toMatchObject({ controlTxs: 1, G: afterTx(create), more: true });
    expect(s.snapshot().groups.map((g) => g.id.txHash)).toEqual([T(0x10)]);
    const reports = await runUntilDone(s, lease, budget({ controlBytes: 1 }));
    expect(reports[0]?.controlTxs).toBe(1);
    expect(s.snapshot().frontiers.G).toEqual(endOf(30));
    expect(s.snapshot().groups).toHaveLength(2);
  });

  it('applies a label tx in block L and then sets G to endOf(L)', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(chainTx({ hash: T(0x30), h: 30, rs: [K(1), K(2)], payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0))], [C0, A0]) }));
    s.setFrontiers({ L: 30 });
    const r = await runEngine(s, BIG, lease);
    expect(r).toMatchObject({ controlTxs: 1, G: endOf(30) });
    expect(s.snapshot().groups.map((g) => g.id.txHash)).toEqual([T(0x30)]);
    expect(commits(s)).toBe(1); // one commit carries the tx and the move to endOf(L)
  });

  it('leaves a tx in block L + 1', async () => {
    const { s, lease } = fresh();
    s.setFrontiers({ L: 30 });
    s.ingestLabelTx(chainTx({ hash: T(0x31), h: 31, rs: [K(1), K(2)], payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0))], [C0, A0]) }));
    const r = await runEngine(s, BIG, lease);
    expect(r).toMatchObject({ controlTxs: 0, G: endOf(30), more: false });
    expect(s.snapshot().groups).toEqual([]);
    s.setFrontiers({ L: 31 });
    await runEngine(s, BIG, lease);
    expect(s.snapshot().groups.map((g) => g.id.txHash)).toEqual([T(0x31)]);
    expect(s.snapshot().frontiers.G).toEqual(endOf(31));
  });

  it('routes approve on a join of an earlier committed tx to its member', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(create);
    s.ingestLabelTx(join7(20));
    s.setFrontiers({ L: 20, R: 20 });
    await runUntilDone(s, lease);
    expect(s.snapshot().instances).toHaveLength(1);

    s.ingestLabelTx(chainTx({ hash: T(0x21), h: 21, rs: [K(2)], payload: buildPayload([ev.approve(ref(T(0x20), 0))]) }));
    s.setFrontiers({ L: 21, R: 21 });
    await runUntilDone(s, lease);
    expect(queueOf(s, T(0x21)).map((q) => [q.subject, q.applied])).toEqual([[M7, true]]);
    expect(verdictOf(s, T(0x21)).map((v) => [v.tag, v.valid, v.subject])).toEqual([['approve', true, M7]]);
    expect(s.snapshot().instances[0]?.approvedAt).toEqual(posOfEvent({ txHash: T(0x21), blockHeight: 21, txIndex: 0 }, 0));
  });
});

describe('runEngine credential units', () => {
  it('applies inputs in block R', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(create);
    s.ingestLedgerRow(reg(M7, T(0xa1), 20));
    const j = join7(20, T(0x20), 1);
    s.ingestLabelTx(j);
    s.setFrontiers({ L: 30, R: 20 });
    await runUntilDone(s, lease);
    expect(s.snapshot().appliedThrough).toEqual([{ credential: M7, at: posOfEvent(j, 0) }]);
    expect(verdictOf(s, T(0x20)).map((v) => [v.tag, v.valid])).toEqual([['join', true]]);
  });

  it('stops at min(G, END(R))', async () => {
    // R below G: inputs above END(R) wait.
    const { s, lease } = fresh();
    s.ingestLabelTx(create);
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    const early = join7(20);
    s.ingestLabelTx(early);
    s.ingestLabelTx(join7(25, T(0x25)));
    s.setFrontiers({ L: 30, R: 20 });
    await runUntilDone(s, lease);
    expect(s.snapshot().frontiers.G).toEqual(endOf(30));
    expect(s.snapshot().appliedThrough).toEqual([{ credential: M7, at: posOfEvent(early, 0) }]);
    expect(queueOf(s, T(0x25)).map((q) => q.applied)).toEqual([false]);

    // G below END(R): a ledger row above G waits.
    const t = fresh();
    t.s.ingestLedgerRow(reg(M9, T(0xa2), 10));
    t.s.ingestLedgerRow(reg(M9, T(0xa3), 25));
    t.s.setFrontiers({ L: 20, R: 30 });
    await runUntilDone(t.s, t.lease);
    expect(t.s.snapshot().appliedThrough).toEqual([{ credential: M9, at: posOfCert(reg(M9, T(0xa2), 10)) }]);
  });

  it('commits a batch of credentials once', async () => {
    const { s, lease } = fresh();
    for (const n of [7, 8, 9]) s.ingestLedgerRow(reg(keyCred(K(n)), T(0xa0 + n), 5));
    s.setFrontiers({ L: 10, R: 10 });
    const r = await runEngine(s, BIG, lease);
    expect(r).toMatchObject({ units: 3, inputs: 3, more: false });
    expect(commits(s)).toBe(2); // the group plane move to END(L), then one batch
    expect(s.snapshot().appliedThrough).toHaveLength(3);
  });

  it('stops a credential batch at the unit and input budget and reports more', async () => {
    const { s, lease } = fresh();
    for (const n of [7, 8, 9]) s.ingestLedgerRow(reg(keyCred(K(n)), T(0xa0 + n), 5));
    s.ingestLedgerRow(reg(M7, T(0xb7), 6));
    s.setFrontiers({ L: 10, R: 10 });
    const r = await runEngine(s, budget({ credentialUnits: 1, credentialInputs: 1 }), lease);
    expect(r).toMatchObject({ units: 1, inputs: 1, more: true });
    const reports = await runUntilDone(s, lease, budget({ credentialUnits: 1, credentialInputs: 1 }));
    expect(reports.length).toBeGreaterThan(2);
    expect(s.snapshot().appliedThrough.map((a) => a.at.txHash).sort()).toEqual([T(0xa8), T(0xa9), T(0xb7)].sort());
  });

  it('throws when a unit still needs keys after stage 3', async () => {
    class Forgetful extends MemoryStore {
      override async load(keys: Keys, overlay: ChangeSet[]): Promise<View> {
        return super.load({ ...keys, credentialAt: [] }, overlay);
      }
    }
    const { s, lease } = fresh(new Forgetful({}));
    s.ingestLabelTx(create);
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(join7(20));
    s.setFrontiers({ L: 30, R: 30 });
    await expect(runEngine(s, BIG, lease)).rejects.toThrow(/still needs keys/);
    // The group plane commit went through, the credential batch did not.
    expect(s.snapshot().frontiers.G).toEqual(endOf(30));
    expect(s.snapshot().appliedThrough).toEqual([]);
  });
});

describe('runEngine batching and interruption', () => {
  // Create then update by ref, join then approve, a key 2 script then a create that uses
  // it, every pair in txs of one page of five.
  const chain: ChainTx[] = [
    create,
    join7(11, T(0x11)),
    chainTx({ hash: T(0x12), h: 12, rs: [K(2)], payload: buildPayload([ev.approve(ref(T(0x11), 0)), ev.leave(ref(T(0x99), 0))]) }),
    chainTx({ hash: T(0x13), h: 13, rs: [K(1), K(2), K(3)], payload: buildPayload([ev.update(G1, 0, new Map([[0, kb(hashOf(C1))]]))], [C1, X]) }),
    chainTx({ hash: T(0x14), h: 14, rs: [K(4)], payload: buildPayload([ev.create(0, hashOf(X), null)]) }),
  ];

  async function runWith(controlTxs: number, credentialUnits: number) {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    for (const tx of chain) s.ingestLabelTx(tx);
    s.setFrontiers({ L: 20, R: 20 });
    const seen = new Map<string, Observed[]>();
    await runUntilDone(s, lease, budget({ controlTxs, credentialUnits }), (r) => {
      seen.set(refKey(r.ref), [...(seen.get(refKey(r.ref)) ?? []), r]);
    });
    return { snap: withoutStats(s.snapshot()), seen };
  }

  it('batch sizes 1 and 5 give the same state', async () => {
    const one = await runWith(1, 1);
    const five = await runWith(5, 5);
    expect(five.snap.queue.map((q) => [q.txHash, q.subject])).toEqual([[T(0x11), M7], [T(0x12), M7]]);
    expect(five.snap).toEqual(one.snap);
    const verdicts = five.snap.verdicts.map((v) => [v.ref.txHash, v.tag, v.valid, v.reason]);
    expect(verdicts).toEqual([
      [T(0x10), 'create', true, null],
      [T(0x11), 'join', true, null],
      [T(0x12), 'approve', true, null],
      [T(0x13), 'update', true, null],
      [T(0x14), 'create', true, null],
    ]);
    expect(five.snap.groups.find((g) => g.id.txHash === T(0x10))?.control).toBe(hashOf(C1));
    expect(five.snap.instances[0]?.approvedAt).not.toBeNull();
    // Every rule result reaches observe exactly once, the orphan leave included.
    for (const o of [one, five]) {
      const refs = [T(0x10), T(0x11), T(0x12), T(0x13), T(0x14)].map((h) => `${h}#0`);
      expect([...o.seen.keys()].sort()).toEqual([...refs, `${T(0x12)}#1`].sort());
      for (const rs of o.seen.values()) expect(rs).toHaveLength(1);
      expect(o.seen.get(`${T(0x12)}#1`)?.[0]).toMatchObject({ tag: 'leave', valid: false, reason: 'unknown join' });
    }
  });

  it('maxCommits 1 stops after the group plane commit', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(create);
    s.setFrontiers({ L: 30, R: 30 });
    const r = await runEngine(s, BIG, lease, { maxCommits: 1 });
    expect(r).toMatchObject({ phase: 'normal', controlTxs: 1, units: 0, G: endOf(30), more: true });
    expect(commits(s)).toBe(1);
    expect(s.snapshot().groups).toHaveLength(1);
    expect(s.snapshot().appliedThrough).toEqual([]);
    await runEngine(s, BIG, lease);
    expect(s.snapshot().appliedThrough).toEqual([{ credential: M7, at: posOfCert(reg(M7, T(0xa1), 5)) }]);
  });

  it('maxCommits 0 emits nothing and makes no load calls', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(create);
    s.ingestLabelTx(join7(20));
    s.setFrontiers({ L: 30, R: 30 });
    const seen: Observed[] = [];
    const r = await runEngine(s, BIG, lease, { maxCommits: 0, observe: (o) => seen.push(o) });
    expect(r).toMatchObject({ phase: 'normal', controlTxs: 0, units: 0, G: endOf(-1), more: true });
    expect(seen).toEqual([]);
    expect(s.stats.calls.load).toBeUndefined();
    expect(s.stats.calls.nextLabelTxs).toBeUndefined();
    expect(s.stats.calls.readyCredentials).toBeUndefined();
    expect(commits(s)).toBe(0);
  });
});

describe('runEngine with a lost lease', () => {
  // Throws LeaseLostError on the nth commit, before anything is written.
  class Losing extends MemoryStore {
    calls = 0;
    constructor(private failOn: number) {
      super({});
    }
    override async commit(units: Array<{ change: ChangeSet; cursor: CursorUpdate }>, lease: string): Promise<void> {
      if (++this.calls === this.failOn) throw new LeaseLostError('lease lost');
      return super.commit(units, lease);
    }
  }

  const setup = (s: MemoryStore): void => {
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLabelTx(create);
    s.ingestLabelTx(join7(20));
    s.setFrontiers({ L: 30, R: 30 });
  };
  const counter = () => {
    const counts = new Map<string, number>();
    return { counts, observe: (r: Observed) => counts.set(refKey(r.ref), (counts.get(refKey(r.ref)) ?? 0) + 1) };
  };

  async function reference() {
    const { s, lease } = fresh();
    setup(s);
    const c = counter();
    await runUntilDone(s, lease, BIG, c.observe);
    return { snap: withoutStats(s.snapshot()), counts: c.counts };
  }

  it('a failed group commit writes nothing and emits no observe results', async () => {
    const s = new Losing(1);
    const lease = s.acquireLease('test');
    setup(s);
    const before = withoutStats(s.snapshot());
    const c = counter();
    await expect(runEngine(s, BIG, lease, { observe: c.observe })).rejects.toThrow(LeaseLostError);
    expect(withoutStats(s.snapshot())).toEqual(before);
    expect(c.counts.size).toBe(0);
  });

  it('a failed credential commit keeps the group commit and emits only the group results', async () => {
    const s = new Losing(2);
    const lease = s.acquireLease('test');
    setup(s);
    const c = counter();
    await expect(runEngine(s, BIG, lease, { observe: c.observe })).rejects.toThrow(LeaseLostError);
    expect(s.snapshot().frontiers.G).toEqual(endOf(30));
    expect(s.snapshot().groups).toHaveLength(1);
    expect(s.snapshot().appliedThrough).toEqual([]);
    expect([...c.counts]).toEqual([[`${T(0x10)}#0`, 1]]);
  });

  it('a later run with a fresh lease reaches the same state and each result exactly once', async () => {
    const ref = await reference();
    expect(ref.counts.size).toBe(2);
    for (const failOn of [1, 2]) {
      const s = new Losing(failOn);
      setup(s);
      const c = counter();
      await expect(runEngine(s, BIG, s.acquireLease('test'), { observe: c.observe })).rejects.toThrow(LeaseLostError);
      await runUntilDone(s, s.acquireLease('test'), BIG, c.observe);
      expect(withoutStats(s.snapshot())).toEqual(ref.snap);
      expect(c.counts).toEqual(ref.counts);
    }
  });
});
