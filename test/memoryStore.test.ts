import { describe, expect, it } from 'vitest';
import { foreignJoinRefs } from '../src/engine/classify.js';
import { applyControl } from '../src/engine/control.js';
import { applyCredential } from '../src/engine/credential.js';
import { emptyChangeSet, emptyKeys, stageKeys, type Step } from '../src/engine/lazyWorld.js';
import { type EngineSnapshot, MemoryStore } from '../src/engine/memoryStore.js';
import { routeTx } from '../src/engine/route.js';
import { type ChangeSet, type CursorUpdate, type CredentialInput, LeaseLostError, type View } from '../src/engine/types.js';
import { decodePayload } from '../src/payload.js';
import { afterTx, comparePos, endOf, type Pos, posOfCert, posOfEvent, posOfScripts } from '../src/position.js';
import { refKey } from '../src/state.js';
import type { ChainTx, Credential, LedgerInput } from '../src/types.js';
import { chainTx } from './engineFixture.js';
import { buildPayload, ev, hashOf, K, kb, keyCred, ref, scriptBytes, scriptCred, sig, T } from './helpers.js';

const done = (s: Step<ChangeSet>): ChangeSet => {
  if (!('done' in s)) throw new Error(`unit still needs ${JSON.stringify(s.need)}`);
  return s.done;
};
const posOfInput = (x: CredentialInput): Pos => (x.kind === 'ledger' ? x.at : x.q.at);
const lastPos = (xs: CredentialInput[]): Pos => xs.map(posOfInput).sort(comparePos)[xs.length - 1] as Pos;

const fresh = () => {
  const s = new MemoryStore({});
  return { s, lease: s.acquireLease('test') };
};

// The group plane units of one page, in the order runEngine uses, without committing.
async function groupUnits(s: MemoryStore, maxTxs = 100): Promise<Array<{ change: ChangeSet; cursor: CursorUpdate }>> {
  const f = await s.frontiers();
  const page = await s.nextLabelTxs(f.G, f.L, maxTxs, 1_000_000);
  const overlay: ChangeSet[] = [];
  const units: Array<{ change: ChangeSet; cursor: CursorUpdate }> = [];
  for (const { tx } of page.txs) {
    const decoded = decodePayload(tx.payload as Uint8Array);
    if (!decoded) throw new Error('markers are never returned');
    const joins = await s.queuedJoins(foreignJoinRefs(tx, decoded), overlay);
    const routed = routeTx(tx, decoded, (r) => joins.get(refKey(r)) ?? null);
    let view: View | null = null;
    for (const st of [1, 2, 3] as const) view = await s.load(stageKeys(st, { tx, routed }, view, overlay), overlay);
    const change = done(applyControl(view as View, tx, routed, overlay));
    overlay.push(change);
    units.push({ change, cursor: { kind: 'group', G: afterTx(tx) } });
  }
  if (page.done) units.push({ change: emptyChangeSet(), cursor: { kind: 'group', G: endOf(f.L) } });
  return units;
}

// The credential units of one batch, without committing.
async function credentialUnits(s: MemoryStore, maxUnits = 100, maxInputs = 1000): Promise<Array<{ change: ChangeSet; cursor: CursorUpdate }>> {
  const f = await s.frontiers();
  const ready = await s.readyCredentials(maxUnits, maxInputs, { G: f.G, R: f.R });
  const overlay: ChangeSet[] = [];
  const units: Array<{ change: ChangeSet; cursor: CursorUpdate }> = [];
  for (const r of ready) {
    let view: View | null = null;
    for (const st of [1, 2, 3] as const) view = await s.load(stageKeys(st, { c: r.c, inputs: r.inputs }, view, overlay), overlay);
    const change = done(applyCredential(view as View, r.c, r.inputs, overlay));
    overlay.push(change);
    units.push({ change, cursor: { kind: 'credential', credential: r.c, appliedThrough: lastPos(r.inputs) } });
  }
  return units;
}

async function runAll(s: MemoryStore, lease: string): Promise<void> {
  await s.commit(await groupUnits(s), lease);
  await s.commit(await credentialUnits(s), lease);
}

const withoutStats = ({ stats: _stats, ...rest }: EngineSnapshot) => rest;
const reg = (c: Credential, hash: string, h: number, scripts?: Uint8Array[]): LedgerInput =>
  ({ kind: 'reg', credential: c, txHash: hash, blockHeight: h, txIndex: 0, certIndex: 0, witnessScripts: scripts });
const unreg = (c: Credential, hash: string, h: number): LedgerInput =>
  ({ kind: 'unreg', credential: c, txHash: hash, blockHeight: h, txIndex: 0, certIndex: 0 });

// A chain that touches every truncation item at h = 35: an approval, a join and an
// explicit close above the cut, an update and a create above it, a script and a member
// script published above it.
const C0 = sig(K(1));
const A0 = sig(K(2));
const C1 = sig(K(3));
const S = sig(K(8));
const M7 = keyCred(K(7));
const M9 = keyCred(K(9));
const MS = scriptCred(hashOf(S));
const G1 = ref(T(0x10), 0);
const txs: ChainTx[] = [
  chainTx({ hash: T(0x10), h: 10, rs: [K(1), K(2)], payload: buildPayload([ev.create(1, hashOf(C0), hashOf(A0))], [C0, A0]) }),
  chainTx({ hash: T(0x20), h: 20, rs: [K(7)], payload: buildPayload([ev.join(G1, 'key', K(7))]) }),
  chainTx({ hash: T(0x40), h: 40, rs: [K(2), K(9)], payload: buildPayload([ev.approve(ref(T(0x20), 0)), ev.join(G1, 'key', K(9))]) }),
  chainTx({
    hash: T(0x47), h: 47, rs: [K(1), K(2), K(3)],
    payload: buildPayload([ev.update(G1, 0, new Map([[0, kb(hashOf(C1))]])), ev.create(1, hashOf(C0), hashOf(A0))], [C1]),
  }),
  chainTx({ hash: T(0x50), h: 50, rs: [K(7)], payload: buildPayload([ev.leave(ref(T(0x20), 0))]) }),
];
const ledger: LedgerInput[] = [reg(M7, T(0xa5), 5), reg(M9, T(0xa6), 5), reg(MS, T(0xa7), 45, [scriptBytes(S)])];

async function applied(): Promise<{ s: MemoryStore; lease: string; before: EngineSnapshot }> {
  const { s, lease } = fresh();
  for (const l of ledger) s.ingestLedgerRow(l);
  for (const tx of txs) s.ingestLabelTx(tx);
  s.setFrontiers({ L: 60, R: 55 });
  await runAll(s, lease);
  return { s, lease, before: s.snapshot() };
}

async function truncated(h = 35): Promise<{ s: MemoryStore; lease: string; before: EngineSnapshot; after: EngineSnapshot }> {
  const { s, lease, before } = await applied();
  let steps = 0;
  while ((await s.truncateStep(h, 2, lease)) === 'more') steps++;
  expect(steps).toBeGreaterThan(0); // the budget of 2 rows needs several steps
  return { s, lease, before, after: s.snapshot() };
}

describe('MemoryStore ingest', () => {
  it('returns no marker from nextLabelTxs', async () => {
    const { s } = fresh();
    expect(s.ingestLabelTx(chainTx({ hash: T(1), h: 1, valid: false, payload: buildPayload([ev.leave(ref(T(9), 0))]) }))).toBe('marker');
    expect(s.ingestLabelTx(chainTx({ hash: T(2), h: 1, i: 1, repeated: true }))).toBe('marker');
    expect(s.ingestLabelTx(chainTx({ hash: T(3), h: 1, i: 2, payload: new Uint8Array([0xff]) }))).toBe('marker');
    // Only undecodable events and no script: nothing readable.
    expect(s.ingestLabelTx(chainTx({ hash: T(4), h: 1, i: 3, payload: buildPayload([[99, 1]]) }))).toBe('marker');
    expect(s.ingestLabelTx(chainTx({ hash: T(5), h: 1, i: 4, payload: buildPayload([ev.leave(ref(T(9), 0))]) }))).toBe('stored');
    expect(s.ingestLabelTx(chainTx({ hash: T(3), h: 1, i: 2, payload: new Uint8Array([0xff]) }))).toBe('duplicate');
    s.setFrontiers({ L: 1 });
    const page = await s.nextLabelTxs(endOf(-1), 1, 10, 1_000_000);
    expect(page.txs.map((t) => t.tx.txHash)).toEqual([T(5)]);
    expect(page.done).toBe(true);
  });

  it('recognises a re-delivered ledger row as duplicate and opens no recovery', async () => {
    const { s, lease } = fresh();
    const row = reg(M7, T(0xa5), 5);
    expect(s.ingestLedgerRow(row)).toBe('stored');
    s.setFrontiers({ L: 10 });
    await runAll(s, lease);
    expect(s.snapshot().appliedThrough).toEqual([{ credential: M7, at: posOfCert(row) }]);
    expect(s.ingestLedgerRow({ ...row })).toBe('duplicate');
    expect(await s.pendingRecovery()).toBeNull();
  });

  it("opens a truncation for a new ledger row at a credential's applied-through even while the credential is incomplete", async () => {
    const { s, lease } = fresh();
    const row = reg(M7, T(0xa5), 50);
    s.ingestLedgerRow(row);
    s.setFrontiers({ L: 60 });
    await runAll(s, lease);
    s.setComplete(M7, false);
    // Same position, another tx hash: a new row at applied-through.
    expect(s.ingestLedgerRow(unreg(M7, T(0xa6), 50))).toBe('stored');
    expect(await s.pendingRecovery()).toEqual({ kind: 'truncate', above: 49 });
  });

  it('opens a truncation for a label tx at or below G and fork recovery below the floor', async () => {
    const { s, lease } = fresh();
    s.setFrontiers({ L: 3000 });
    await runAll(s, lease);
    s.ingestLabelTx(chainTx({ hash: T(1), h: 2990, payload: buildPayload([ev.leave(ref(T(9), 0))]) }));
    expect(await s.pendingRecovery()).toEqual({ kind: 'truncate', above: 2989 });
    s.ingestLabelTx(chainTx({ hash: T(2), h: 10, payload: buildPayload([ev.leave(ref(T(9), 0))]) }));
    expect(await s.pendingRecovery()).toEqual({ kind: 'fork' });
  });

  it('answers registration from stored rows not yet applied', async () => {
    // A join after a reg of the same batch must see the reg.
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa5), 20));
    s.ingestLabelTx(txs[0] as ChainTx);
    s.ingestLabelTx(chainTx({ hash: T(0x21), h: 20, i: 1, rs: [K(7)], payload: buildPayload([ev.join(G1, 'key', K(7))]) }));
    s.setFrontiers({ L: 30 });
    await s.commit(await groupUnits(s), lease);
    expect(s.snapshot().appliedThrough).toEqual([]);
    const joinAt = posOfEvent({ txHash: T(0x21), blockHeight: 20, txIndex: 1 }, 0);
    const keys = { ...emptyKeys(), credentialAt: [[M7, joinAt]] as Array<[Credential, Pos]> };
    const view = await s.load(keys, []);
    expect(view.missing(keys).credentialAt).toEqual([]);
    expect(view.registeredAt(M7, joinAt)).toBe(true);
    const units = await credentialUnits(s);
    expect(units[0]?.change.verdicts.map((v) => [v.tag, v.valid, v.reason])).toEqual([['join', true, null]]);
  });
});

describe('MemoryStore commit and lease', () => {
  it('commit is all or nothing', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(txs[0] as ChainTx);
    s.setFrontiers({ L: 10 });
    const before = withoutStats(s.snapshot());
    const good = await groupUnits(s);
    const bad = emptyChangeSet();
    bad.txContexts.push({ txHash: T(0xee), context: { signers: [], requiredSigners: [], invalidBefore: null, invalidHereafter: null } });
    await expect(s.commit([...good, { change: bad, cursor: { kind: 'group', G: endOf(10) } }], lease)).rejects.toThrow();
    expect(withoutStats(s.snapshot())).toEqual(before);
    await s.commit(good, lease);
    expect(s.snapshot().versions).toHaveLength(1);
  });

  it('a unit retried after a failed commit writes the same change set', async () => {
    const { s, lease } = fresh();
    for (const tx of txs.slice(0, 2)) s.ingestLabelTx(tx);
    s.setFrontiers({ L: 30 });
    const first = await groupUnits(s);
    s.expireLease();
    await expect(s.commit(first, lease)).rejects.toBeInstanceOf(LeaseLostError);
    const lease2 = s.acquireLease('test');
    const retry = await groupUnits(s);
    expect(retry).toEqual(first);
    await s.commit(retry, lease2);
    expect(s.snapshot().versions).toHaveLength(1);
    expect(s.snapshot().queue).toHaveLength(1);
  });

  it('an expired lease cannot commit', async () => {
    const { s, lease } = fresh();
    s.ingestLabelTx(txs[0] as ChainTx);
    s.setFrontiers({ L: 10 });
    const units = await groupUnits(s);
    const before = withoutStats(s.snapshot());
    s.expireLease();
    await expect(s.commit(units, lease)).rejects.toBeInstanceOf(LeaseLostError);
    await expect(s.openRecovery({ kind: 'rebuild' }, lease)).rejects.toBeInstanceOf(LeaseLostError);
    expect(withoutStats(s.snapshot())).toEqual(before);
  });

  it('expires a lease through the injected clock and lets another owner take it over', async () => {
    let t = 0;
    const s = new MemoryStore({ now: () => t, leaseMs: 100 });
    const a = s.acquireLease('a');
    expect(() => s.acquireLease('b')).toThrow();
    t = 100;
    await expect(s.commit([], a)).rejects.toBeInstanceOf(LeaseLostError);
    const b = s.acquireLease('b');
    await s.commit([], b);
    await expect(s.commit([], a)).rejects.toBeInstanceOf(LeaseLostError);
  });

  it('an expired lease cannot run a truncation step', async () => {
    const { s, lease, before } = await applied();
    s.expireLease();
    await expect(s.truncateStep(35, 100, lease)).rejects.toBeInstanceOf(LeaseLostError);
    await expect(s.resetStep('fork', 100, lease)).rejects.toBeInstanceOf(LeaseLostError);
    expect(withoutStats(s.snapshot())).toEqual(withoutStats(before));
  });

  it('committing the same change set twice leaves the snapshot unchanged', async () => {
    const { s, lease } = fresh();
    for (const l of ledger) s.ingestLedgerRow(l);
    for (const tx of txs) s.ingestLabelTx(tx);
    s.setFrontiers({ L: 60 });
    const g = await groupUnits(s);
    await s.commit(g, lease);
    const c = await credentialUnits(s);
    await s.commit(c, lease);
    const once = withoutStats(s.snapshot());
    await s.commit(g, lease);
    await s.commit(c, lease);
    expect(withoutStats(s.snapshot())).toEqual(once);
  });

  it('a committed label tx is not returned again', async () => {
    const { s, lease } = fresh();
    for (const tx of txs.slice(0, 2)) s.ingestLabelTx(tx);
    s.setFrontiers({ L: 30 });
    await s.commit(await groupUnits(s, 1), lease);
    const f = await s.frontiers();
    expect(f.G).toEqual(afterTx(txs[0] as ChainTx));
    const page = await s.nextLabelTxs(f.G, f.L, 10, 1_000_000);
    expect(page.txs.map((t) => t.tx.txHash)).toEqual([T(0x20)]);
    await s.commit(await groupUnits(s), lease);
    expect((await s.frontiers()).G).toEqual(endOf(30));
    expect((await s.nextLabelTxs(endOf(30), 30, 10, 1_000_000)).txs).toEqual([]);
  });

  it('a ledger row at applied-through is not returned again', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa5), 5));
    s.setFrontiers({ L: 10 });
    await runAll(s, lease);
    const f = await s.frontiers();
    expect(await s.readyCredentials(10, 10, { G: f.G, R: f.R })).toEqual([]);
  });
});

describe('MemoryStore truncation', () => {
  it('deletes raw inputs above h', async () => {
    const { before, after } = await truncated();
    expect(before.labelTxs.map((t) => t.txHash)).toEqual([T(0x10), T(0x20), T(0x40), T(0x47), T(0x50)]);
    expect(after.labelTxs.map((t) => t.txHash)).toEqual([T(0x10), T(0x20)]);
    expect(after.ledger).toEqual([reg(M7, T(0xa5), 5), reg(M9, T(0xa6), 5)]);
  });

  it('deletes group versions above h', async () => {
    const { before, after } = await truncated();
    expect(before.versions.map((v) => v.at.blockHeight)).toEqual([10, 47, 47]);
    expect(after.versions.map((v) => v.at.blockHeight)).toEqual([10]);
  });

  it('deletes script publications above h', async () => {
    const { before, after } = await truncated();
    expect(before.scripts.map((x) => x.hash)).toContain(hashOf(C1));
    expect(after.scripts.map((x) => x.hash).sort()).toEqual([hashOf(C0), hashOf(A0)].sort());
  });

  it('deletes member script publications above h', async () => {
    const { before, after } = await truncated();
    expect(before.memberScripts.map((m) => m.credential)).toEqual([MS]);
    expect(after.memberScripts).toEqual([]);
  });

  it('deletes instances joined above h', async () => {
    const { before, after } = await truncated();
    expect(before.instances.map((i) => i.member)).toEqual([M7, M9]);
    expect(after.instances.map((i) => i.member)).toEqual([M7]);
  });

  it('undoes approvals above h', async () => {
    const { before, after } = await truncated();
    expect(before.instances[0]?.approvedAt?.blockHeight).toBe(40);
    expect(after.instances[0]?.approvedAt).toBeNull();
  });

  it('undoes explicit closes above h', async () => {
    const { before, after } = await truncated();
    expect(before.instances[0]?.closedAt?.blockHeight).toBe(50);
    expect(before.instances[0]?.closeReason).toBe('left');
    expect(after.instances[0]?.closedAt).toBeNull();
    expect(after.instances[0]?.closeReason).toBeNull();
  });

  it('deletes verdicts above h', async () => {
    const { before, after } = await truncated();
    expect(before.verdicts.map((v) => v.at.blockHeight)).toEqual([10, 20, 40, 40, 47, 47, 50]);
    expect(after.verdicts.map((v) => [v.tag, v.at.blockHeight])).toEqual([['create', 10], ['join', 20]]);
  });

  it('deletes queue entries above h', async () => {
    const { before, after } = await truncated();
    expect(before.queue.map((q) => q.at.blockHeight)).toEqual([20, 40, 40, 50]);
    expect(after.queue.map((q) => [q.at.blockHeight, q.applied])).toEqual([[20, true]]);
  });

  it('deletes tx contexts above h', async () => {
    const { before, after } = await truncated();
    expect(before.txContexts.map((t) => t.txHash)).toEqual([T(0x10), T(0x20), T(0x40), T(0x47), T(0x50)]);
    expect(after.txContexts.map((t) => t.txHash)).toEqual([T(0x10), T(0x20)]);
  });

  it('resets each group to its latest remaining version or deletes it', async () => {
    const { before, after } = await truncated();
    expect(before.groups.map((g) => [refKey(g.id), g.seq, g.at.blockHeight])).toEqual([
      [`${T(0x10)}#0`, 1n, 47], [`${T(0x47)}#1`, 0n, 47],
    ]);
    expect(after.groups.map((g) => [refKey(g.id), g.seq, g.at.blockHeight])).toEqual([[`${T(0x10)}#0`, 0n, 10]]);
  });

  it('lowers G and applied-through to endOf(h)', async () => {
    const { before, after } = await truncated();
    expect(before.frontiers.G).toEqual(endOf(60));
    expect(after.frontiers.G).toEqual(endOf(35));
    expect(after.appliedThrough).toEqual([
      { credential: M7, at: endOf(35) }, { credential: M9, at: endOf(35) }, { credential: MS, at: endOf(35) },
    ]);
  });

  it('lowers L and R to h', async () => {
    const { after } = await truncated();
    expect(after.frontiers.L).toBe(35);
    expect(after.frontiers.R).toBe(35);
  });

  it('keeps every input of block h applied', async () => {
    const { s, lease } = await applied();
    while ((await s.truncateStep(20, 3, lease)) === 'more');
    const after = s.snapshot();
    expect(after.verdicts.map((v) => v.at.blockHeight)).toEqual([10, 20]);
    expect(after.queue.map((q) => [q.at.blockHeight, q.applied])).toEqual([[20, true]]);
    const f = await s.frontiers();
    expect(f.G).toEqual(endOf(20));
    // Nothing of block 20 is offered again, to either plane.
    expect((await s.nextLabelTxs(f.G, f.L, 10, 1_000_000)).txs).toEqual([]);
    expect(await s.readyCredentials(10, 100, { G: f.G, R: f.R })).toEqual([]);
  });

  it('truncation keeps every input of block h applied', async () => {
    // Re-applying after the cut gives the state of the cut chain, with no input of
    // block h run twice (a second join would give 'already a member or applicant').
    const { s, lease } = await applied();
    while ((await s.truncateStep(20, 100, lease)) === 'more');
    s.setFrontiers({ L: 60, R: 60 });
    s.ingestLabelTx(chainTx({ hash: T(0x30), h: 30, rs: [K(2)], payload: buildPayload([ev.approve(ref(T(0x20), 0))]) }));
    await runAll(s, lease);
    const after = s.snapshot();
    expect(after.verdicts.map((v) => [v.tag, v.valid, v.at.blockHeight])).toEqual([['create', true, 10], ['join', true, 20], ['approve', true, 30]]);
    expect(after.instances.map((i) => i.approvedAt?.blockHeight)).toEqual([30]);
  });
});

describe('MemoryStore recovery', () => {
  it('a truncation opened during a rebuild runs after it', async () => {
    const { s, lease } = await applied();
    await s.openRecovery({ kind: 'rebuild' }, lease);
    s.ingestLedgerRow(unreg(M7, T(0xb0), 30)); // late, below M7's applied-through
    expect(await s.pendingRecovery()).toEqual({ kind: 'rebuild' });
    while ((await s.resetStep('rebuild', 4, lease)) === 'more');
    await s.finishRecovery(lease);
    expect(await s.pendingRecovery()).toEqual({ kind: 'truncate', above: 29 });
    await s.finishRecovery(lease);
    expect(await s.pendingRecovery()).toBeNull();
  });

  it('fork replaces a pending rebuild and truncation', async () => {
    const { s, lease } = await applied();
    await s.openRecovery({ kind: 'rebuild' }, lease);
    await s.openRecovery({ kind: 'truncate', above: 30 }, lease);
    await s.openRecovery({ kind: 'fork' }, lease);
    expect(s.snapshot().recovery).toEqual({ first: { kind: 'fork' }, then: null });
    while ((await s.resetStep('fork', 5, lease)) === 'more');
    await s.finishRecovery(lease);
    expect(await s.pendingRecovery()).toBeNull();
    const after = s.snapshot();
    expect(after.labelTxs).toEqual([]);
    expect(after.ledger).toEqual([]);
    expect(after.versions).toEqual([]);
    expect(after.frontiers).toEqual({ L: -1, R: null, G: endOf(-1) });
    expect(after.appliedThrough).toEqual([]);
  });

  it('rebuild keeps raw inputs and frontiers', async () => {
    const { s, lease, before } = await applied();
    s.setComplete(M9, false);
    let steps = 0;
    while ((await s.resetStep('rebuild', 3, lease)) === 'more') steps++;
    expect(steps).toBeGreaterThan(0);
    const after = s.snapshot();
    expect(after.labelTxs).toEqual(before.labelTxs);
    expect(after.ledger).toEqual(before.ledger);
    expect(after.complete).toEqual([{ credential: M9, complete: false }]);
    expect(after.frontiers).toEqual({ L: 60, R: 55, G: endOf(-1) });
    for (const k of ['groups', 'versions', 'scripts', 'memberScripts', 'instances', 'verdicts', 'queue', 'txContexts', 'appliedThrough'] as const) {
      expect(after[k]).toEqual([]);
    }
    // Re-applying gives the same state (M9 completed again).
    s.setComplete(M9, true);
    await runAll(s, lease);
    const again = s.snapshot();
    expect({ ...withoutStats(again), complete: [] }).toEqual({ ...withoutStats(before), complete: [] });
  });
});

describe('MemoryStore readyCredentials', () => {
  it('readyCredentials bounds by min(G, END(R)) and pages inputs', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLedgerRow(unreg(M7, T(0xa2), 6));
    s.ingestLedgerRow(reg(M7, T(0xa3), 7));
    s.ingestLedgerRow(unreg(M7, T(0xa4), 8));
    s.setFrontiers({ L: 20, R: 7 });
    await s.commit(await groupUnits(s), lease);
    const f = await s.frontiers();
    expect(f.G).toEqual(endOf(20));
    // Bound END(7): the row in block 7 counts, block 8 waits for R.
    const page = await s.readyCredentials(10, 2, { G: f.G, R: f.R });
    expect(page).toHaveLength(1);
    expect(page[0]?.inputs.map(posOfInput).map((p) => p.blockHeight)).toEqual([5, 6]);
    expect(page[0]?.more).toBe(true);
    // G below END(R) bounds instead.
    expect((await s.readyCredentials(10, 10, { G: endOf(5), R: 7 }))[0]?.inputs).toHaveLength(1);
    await s.commit([{ change: emptyChangeSet(), cursor: { kind: 'credential', credential: M7, appliedThrough: lastPos(page[0]?.inputs ?? []) } }], lease);
    const next = await s.readyCredentials(10, 2, { G: f.G, R: f.R });
    expect(next[0]?.inputs.map(posOfInput).map((p) => p.blockHeight)).toEqual([7]);
    expect(next[0]?.more).toBe(false);
  });

  it('readyCredentials skips an incomplete old credential for a complete young one', async () => {
    const { s } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa1), 5));
    s.ingestLedgerRow(reg(M9, T(0xa2), 9));
    s.ingestLedgerRow(reg(MS, T(0xa3), 7));
    s.setComplete(M7, false);
    const all = await s.readyCredentials(10, 10, { G: endOf(10), R: null });
    expect(all.map((r) => r.c)).toEqual([MS, M9]);
    const one = await s.readyCredentials(1, 10, { G: endOf(10), R: null });
    expect(one.map((r) => r.c)).toEqual([MS]);
    const custom = new MemoryStore({ isComplete: (c) => c.hash !== K(9) });
    custom.ingestLedgerRow(reg(M9, T(0xa2), 9));
    custom.ingestLedgerRow(reg(M7, T(0xa1), 10));
    expect((await custom.readyCredentials(10, 10, { G: endOf(10), R: null })).map((r) => r.c)).toEqual([M7]);
  });

  it('counts calls and returned rows', async () => {
    const { s, lease } = fresh();
    s.ingestLedgerRow(reg(M7, T(0xa5), 5));
    s.ingestLabelTx(txs[0] as ChainTx);
    s.setFrontiers({ L: 10 });
    await runAll(s, lease);
    expect(s.stats.calls.nextLabelTxs).toBe(1);
    expect(s.stats.rowsReturned.nextLabelTxs).toBe(1);
    expect(s.stats.rowsReturned.readyCredentials).toBe(1);
    expect(s.stats.calls.load).toBeGreaterThan(0);
    expect(s.stats.calls.commit).toBe(2);
    expect(s.snapshot().scripts.map((x) => x.at)).toEqual([posOfScripts(txs[0] as ChainTx), posOfScripts(txs[0] as ChainTx)]);
  });
});
