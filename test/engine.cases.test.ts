// Named cases of the incremental engine: hand built chains with explicit schedules, run
// through the schedule driver over MemoryStore. The driver compares every final state
// with replay, each case asserts its own expectation on top.
import { describe, expect, it } from 'vitest';
import { assertEquivalent, engineProjection, replayProjection, runSchedule, type ScheduleResult, type ScheduleStep } from '../src/conformance/index.js';
import { BIG_BUDGET } from '../src/conformance/generate.js';
import { type EngineSnapshot, MemoryStore } from '../src/engine/memoryStore.js';
import type { Budget, ReadyCredential } from '../src/engine/types.js';
import { endOf, type Pos, posOfCert, posOfEvent, posOfScripts } from '../src/position.js';
import { credKey, refKey, replay } from '../src/state.js';
import type { ChainInput, Credential, EventVerdict, Instance, LedgerInput } from '../src/types.js';
import {
  buildPayload, ev, hashOf, K, kb, keyCred, local, ref, regIn, type ScriptValue, scriptBytes, scriptCred, sig, T, txIn, unregIn,
} from './helpers.js';

// Keys and scripts. A signs every policy, M and N are key DReps, S and S2 member scripts.
const A = K(1);
const CTL = sig(A);
const ctl = hashOf(CTL);
const A2 = K(2);
const CTL2 = sig(A2);
const M = K(0x21);
const m = keyCred(M);
const N = K(0x22);
const n = keyCred(N);
const SK = K(0x31);
const S = sig(SK);
const s = scriptCred(hashOf(S));
const SK2 = K(0x32);
const S2 = sig(SK2);
const s2 = scriptCred(hashOf(S2));

// Label txs use T(0x01) to T(0xdf), ledger rows T(0xe0) and above.
const LH = (i: number): string => T(0xe0 + i);
const G = (n: number): unknown[] => ref(T(n), 0);
const J = (n: number): unknown[] => ref(T(n), 0);

const create = (tx: number, h: number, mode: 0 | 1): ChainInput =>
  txIn({ hash: T(tx), h, wk: [A], payload: buildPayload([ev.create(mode, ctl, mode === 1 ? ctl : null)], [CTL]) });
// A key join, signed through required_signers unless `signed` is false.
const join = (tx: number, h: number, group: unknown[], member = M, signed = true): ChainInput =>
  txIn({ hash: T(tx), h, rs: signed ? [member] : [], wk: [member], payload: buildPayload([ev.join(group, 'key', member)]) });
// A script join, the member script is satisfied by its key as a vkey witness.
const scriptJoin = (tx: number, h: number, group: unknown[], script: ScriptValue, key: string): ChainInput =>
  txIn({ hash: T(tx), h, wk: [key], payload: buildPayload([ev.join(group, 'script', hashOf(script))]) });
// Control and admission events signed by A, a leave signed by the key member.
const byA = (tx: number, h: number, event: unknown[]): ChainInput => txIn({ hash: T(tx), h, wk: [A], payload: buildPayload([event]) });
const leave = (tx: number, h: number, j: unknown[], member = M): ChainInput =>
  txIn({ hash: T(tx), h, rs: [member], payload: buildPayload([ev.leave(j)]) });
const reg = (c: Credential, i: number, h: number, script?: ScriptValue): ChainInput =>
  regIn(c, LH(i), h, 0, script ? [scriptBytes(script)] : undefined);
const unreg = (c: Credential, i: number, h: number): ChainInput => unregIn(c, LH(i), h);

const BIG: Budget = BIG_BUDGET;
const deliver = (...inputs: ChainInput[]): ScheduleStep => ({ kind: 'deliver', inputs });
const frontiers = (L: number, R: number | null = L): ScheduleStep => ({ kind: 'frontiers', L, R });
const run = (o: Partial<Budget> = {}): ScheduleStep => ({ kind: 'run', budget: { ...BIG, ...o } });
const check = (label: string): ScheduleStep => ({ kind: 'check', label });
const complete = (c: Credential, done: boolean): ScheduleStep => ({ kind: 'complete', c, complete: done });

const inputsOf = (steps: ScheduleStep[]): ChainInput[] =>
  steps.flatMap((x) => (x.kind === 'deliver' ? x.inputs : x.kind === 'rollback' ? x.suffix : []));
const go = (steps: ScheduleStep[], store: () => MemoryStore = () => new MemoryStore()): Promise<ScheduleResult> =>
  runSchedule(store, inputsOf(steps), steps);

const at = (r: ScheduleResult, label: string): EngineSnapshot => {
  const c = r.checkpoints.find((x) => x.label === label);
  if (!c) throw new Error(`no checkpoint ${label}`);
  return c.snapshot;
};
const verdict = (snap: EngineSnapshot, tx: number, index = 0): EventVerdict | undefined =>
  engineProjection(snap).verdicts.find((v) => v.ref.txHash === T(tx) && v.ref.index === index);
const instance = (snap: EngineSnapshot, tx: number, index = 0): Instance | undefined =>
  engineProjection(snap).instances.find((i) => i.joinId.txHash === T(tx) && i.joinId.index === index);
const reasonOf = (snap: EngineSnapshot, tx: number, index = 0): string | null | undefined => {
  const v = verdict(snap, tx, index);
  return v === undefined ? undefined : v.valid ? null : v.reason;
};
// The reason replay gives an event, for verdicts the engine never stores (no group).
const replayReason = (steps: ScheduleStep[], tx: number, index = 0): string | null | undefined =>
  replay(inputsOf(steps)).verdicts.find((v) => v.ref.txHash === T(tx) && v.ref.index === index)?.reason;
const applied = (snap: EngineSnapshot, c: Credential): Pos | undefined =>
  snap.appliedThrough.find((a) => credKey(a.credential) === credKey(c))?.at;
const certAt = (x: ChainInput): Pos => posOfCert((x as { kind: 'ledger'; input: LedgerInput }).input);
const evAt = (tx: number, h: number, index = 0, i = 0): Pos => posOfEvent({ txHash: T(tx), blockHeight: h, txIndex: i }, index);

// Counts how often readyCredentials hands out each queued event.
class CountingStore extends MemoryStore {
  readonly delivered = new Map<string, number>();
  override async readyCredentials(maxUnits: number, maxInputs: number, upTo: { G: Pos; R: number | null }): Promise<ReadyCredential[]> {
    const out = await super.readyCredentials(maxUnits, maxInputs, upTo);
    for (const r of out) {
      for (const x of r.inputs) {
        if (x.kind !== 'event') continue;
        const k = refKey({ txHash: x.q.txHash, index: x.q.at.index });
        this.delivered.set(k, (this.delivered.get(k) ?? 0) + 1);
      }
    }
    return out;
  }
}

describe('named engine cases', () => {
  it('join, leave, dissolve and join', async () => {
    const steps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10)), leave(0x30, 30, J(0x20)), byA(0x40, 40, ev.dissolve(G(0x10), 0)), join(0x50, 50, G(0x10))),
      frontiers(50), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x20)).toBeNull();
    expect(reasonOf(r.final, 0x30)).toBeNull();
    expect(reasonOf(r.final, 0x40)).toBeNull();
    expect(reasonOf(r.final, 0x50)).toBe('group dissolved');
    expect(instance(r.final, 0x20)).toMatchObject({ state: 'closed', reason: 'left', closedAt: evAt(0x30, 30) });
    expect(instance(r.final, 0x50)).toBeUndefined();
  });

  it('approve and retirement with the group and ledger rows stored far ahead of a late credential', async () => {
    const steps = [
      complete(m, false),
      deliver(reg(m, 0, 5), create(0x10, 10, 1), join(0x20, 20, G(0x10)), byA(0x30, 30, ev.approve(J(0x20))), unreg(m, 1, 40)),
      frontiers(500), run(), run(), check('ahead'),
      complete(m, true), run(), check('applied'),
    ];
    const r = await go(steps);
    const ahead = at(r, 'ahead');
    expect(ahead.frontiers.G).toEqual(endOf(500));
    expect(applied(ahead, m)).toBeUndefined();
    expect(ahead.queue.filter((q) => !q.applied)).toHaveLength(2);
    for (const snap of [at(r, 'applied'), r.final]) {
      expect(reasonOf(snap, 0x30)).toBeNull();
      expect(instance(snap, 0x20)).toMatchObject({ state: 'closed', reason: 'retired', approvedAt: evAt(0x30, 30), closedAt: certAt(unreg(m, 1, 40)) });
    }
  });

  it('an unsigned join and later a signed join of the same registered DRep', async () => {
    const steps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10), M, false)),
      frontiers(20), run(), check('unsigned'),
      deliver(join(0x30, 30, G(0x10))), check('delivered'),
      frontiers(30), run(), check('signed'),
    ];
    const r = await go(steps);
    expect(reasonOf(at(r, 'unsigned'), 0x20)).toBe('member key not in required_signers');
    expect(at(r, 'delivered').recovery.first).toBeNull();
    expect(reasonOf(at(r, 'signed'), 0x30)).toBeNull();
    expect(reasonOf(r.final, 0x20)).toBe('member key not in required_signers');
    expect(reasonOf(r.final, 0x30)).toBeNull();
    expect(r.coverage.truncations + r.coverage.rebuilds + r.coverage.forks).toBe(0);
  });

  it('refs to a stored later tx and to a not stored tx', async () => {
    const steps = [
      deliver(
        reg(m, 0, 5), create(0x10, 10, 1),
        byA(0x15, 15, ev.approve(J(0x20))), // the join is stored, but later in the chain
        join(0x20, 20, G(0x10)),
        byA(0x25, 25, ev.approve(J(0x99))), // never stored
      ),
      frontiers(25), run(),
    ];
    const r = await go(steps);
    expect(replayReason(steps, 0x15)).toBe('unknown join');
    expect(replayReason(steps, 0x25)).toBe('unknown join');
    expect(verdict(r.final, 0x15)).toBeUndefined();
    expect(verdict(r.final, 0x25)).toBeUndefined();
    expect(r.coverage.reasons['unknown join']).toBe(2);
    expect(instance(r.final, 0x20)).toMatchObject({ state: 'pending', approvedAt: null });
  });

  it('dissolve before a late credential\'s join and leave', async () => {
    const steps = [
      complete(m, false),
      deliver(reg(m, 0, 5), create(0x10, 10, 0), byA(0x15, 15, ev.dissolve(G(0x10), 0)), join(0x20, 20, G(0x10)), leave(0x25, 25, J(0x20))),
      frontiers(30), run(), complete(m, true), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x20)).toBe('group dissolved');
    expect(replayReason(steps, 0x25)).toBe('unknown join');
    expect(verdict(r.final, 0x25)).toBeUndefined();
    expect(r.final.instances).toEqual([]);
  });

  it('retirement between join and approve', async () => {
    const steps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 1), join(0x20, 20, G(0x10)), unreg(m, 1, 25), byA(0x30, 30, ev.approve(J(0x20)))),
      frontiers(30), run({ credentialInputs: 1 }), run({ credentialInputs: 1 }),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x30)).toBe('join is not pending');
    expect(instance(r.final, 0x20)).toMatchObject({ state: 'closed', reason: 'retired', approvedAt: null });
  });

  it('reg, unreg, reg with joins between and a leave after the retirement', async () => {
    const steps = [
      deliver(create(0x03, 3, 0), reg(m, 0, 5), join(0x10, 10, G(0x03)), unreg(m, 1, 15), join(0x18, 18, G(0x03))),
      frontiers(18), run(),
      deliver(reg(m, 2, 20), join(0x25, 25, G(0x03)), leave(0x30, 30, J(0x10))),
      frontiers(30), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x10)).toBeNull();
    expect(reasonOf(r.final, 0x18)).toBe('not a registered DRep');
    expect(reasonOf(r.final, 0x25)).toBeNull();
    expect(reasonOf(r.final, 0x30)).toBe('join is not open');
    expect(instance(r.final, 0x10)).toMatchObject({ reason: 'retired', closedAt: certAt(unreg(m, 1, 15)) });
    expect(instance(r.final, 0x25)).toMatchObject({ state: 'active', reason: null });
  });

  it('approve on a pending instance of a dissolved group', async () => {
    const steps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 1), join(0x20, 20, G(0x10)), byA(0x25, 25, ev.dissolve(G(0x10), 0)), byA(0x30, 30, ev.approve(J(0x20)))),
      frontiers(30), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x30)).toBe('join is not pending');
    expect(instance(r.final, 0x20)).toMatchObject({ state: 'closed', reason: 'dissolved', approvedAt: null });
  });

  it('a script DRep whose script comes from its registration and stays known after its retirement', async () => {
    const steps = [
      deliver(reg(s, 0, 5, S), create(0x10, 10, 0), scriptJoin(0x20, 20, G(0x10), S, SK), unreg(s, 1, 25)),
      frontiers(25), run(),
      deliver(reg(s, 2, 30), scriptJoin(0x35, 35, G(0x10), S, SK)),
      frontiers(35), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x20)).toBeNull();
    expect(reasonOf(r.final, 0x35)).toBeNull();
    expect(instance(r.final, 0x20)).toMatchObject({ reason: 'retired' });
    expect(instance(r.final, 0x35)).toMatchObject({ state: 'active' });
    expect(r.final.memberScripts.map((x) => [credKey(x.credential), x.at])).toEqual([[credKey(s), certAt(reg(s, 0, 5, S))]]);
  });

  it('a rollback through a create, an update, a dissolve and an approval', async () => {
    const branch = [create(0x13, 12, 1), join(0x21, 20, G(0x13)), byA(0x26, 25, ev.approve(J(0x21)))];
    const steps: ScheduleStep[] = [
      deliver(
        reg(m, 0, 5), create(0x12, 12, 1), join(0x20, 20, G(0x12)), byA(0x30, 30, ev.update(G(0x12), 0, new Map())),
        byA(0x40, 40, ev.approve(J(0x20))), byA(0x50, 50, ev.dissolve(G(0x12), 1)),
      ),
      frontiers(50), run(), check('old'),
      { kind: 'rollback', to: 8, suffix: branch },
      frontiers(30), run(), check('new'),
    ];
    const r = await go(steps);
    const old = at(r, 'old');
    expect(old.versions.filter((v) => v.id.txHash === T(0x12)).map((v) => v.status)).toEqual(['active', 'active', 'dissolved']);
    expect(reasonOf(old, 0x40)).toBeNull();
    const reference = replayProjection(replay([reg(m, 0, 5), ...branch]));
    for (const snap of [at(r, 'new'), r.final]) {
      assertEquivalent(engineProjection(snap), reference);
      expect(snap.versions.map((v) => v.id.txHash)).toEqual([T(0x13)]);
      expect(instance(snap, 0x21)).toMatchObject({ state: 'active', approvedAt: evAt(0x26, 25) });
    }
    expect(r.coverage.truncations).toBe(1);
  });

  it('the dissolve unit runs before a late credential\'s join is committed', async () => {
    const steps = [
      complete(m, false),
      deliver(reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10)), byA(0x30, 30, ev.dissolve(G(0x10), 0))),
      frontiers(30), run(), check('dissolved'),
      complete(m, true), run(), check('joined'),
    ];
    const r = await go(steps);
    const dissolved = at(r, 'dissolved');
    expect(dissolved.versions.some((v) => v.status === 'dissolved')).toBe(true);
    expect(dissolved.instances).toEqual([]);
    expect(instance(at(r, 'joined'), 0x20)).toMatchObject({ state: 'closed', reason: 'dissolved', closedAt: evAt(0x30, 30) });
  });

  it('a leave below the dissolve still queued when the dissolve is applied', async () => {
    const steps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10))),
      frontiers(20), run(),
      deliver(leave(0x25, 25, J(0x20)), byA(0x30, 30, ev.dissolve(G(0x10), 0))),
      frontiers(40), run({ credentialUnits: 0 }), check('before'),
      run(), check('after'),
    ];
    const r = await go(steps);
    const before = at(r, 'before');
    expect(before.queue.find((q) => q.txHash === T(0x25))?.applied).toBe(false);
    expect(instance(before, 0x20)).toMatchObject({ state: 'closed', reason: 'dissolved', closedAt: evAt(0x30, 30) });
    for (const snap of [at(r, 'after'), r.final]) {
      expect(instance(snap, 0x20)).toMatchObject({ state: 'closed', reason: 'left', closedAt: evAt(0x25, 25) });
    }
  });

  it('a credential whose last input is its join, after a later dissolve', async () => {
    const steps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10))),
      frontiers(20), run(), check('joined'),
      deliver(byA(0x30, 30, ev.dissolve(G(0x10), 0))),
      frontiers(30), run(), check('dissolved'),
    ];
    const r = await go(steps);
    const through = applied(at(r, 'joined'), m);
    expect(through).toEqual(evAt(0x20, 20));
    for (const snap of [at(r, 'dissolved'), r.final]) {
      expect(applied(snap, m)).toEqual(through);
      expect(instance(snap, 0x20)).toMatchObject({ state: 'closed', reason: 'dissolved', closedAt: evAt(0x30, 30) });
    }
  });

  it('a signed join applied, then a new reg or unreg row below it from the reader\'s overlap', async () => {
    // A retirement below the applied join.
    const unregSteps = [
      deliver(reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10))),
      frontiers(20), run(), check('applied'),
      deliver(unreg(m, 1, 15)), check('late'),
      run(), run(), run(),
    ];
    const u = await go(unregSteps);
    expect(reasonOf(at(u, 'applied'), 0x20)).toBeNull();
    expect(at(u, 'late').recovery.first).toEqual({ kind: 'truncate', above: 14 });
    expect(reasonOf(u.final, 0x20)).toBe('not a registered DRep');
    expect(u.final.instances).toEqual([]);
    expect(u.coverage.truncations).toBe(1);

    // A registration below the applied join.
    const regSteps = [
      deliver(create(0x10, 10, 0), join(0x20, 20, G(0x10))),
      frontiers(20), run(), check('applied'),
      deliver(reg(m, 0, 15)), check('late'),
      run(), run(), run(),
    ];
    const g = await go(regSteps);
    expect(reasonOf(at(g, 'applied'), 0x20)).toBe('not a registered DRep');
    expect(at(g, 'late').recovery.first).toEqual({ kind: 'truncate', above: 14 });
    expect(reasonOf(g.final, 0x20)).toBeNull();
    expect(instance(g.final, 0x20)).toMatchObject({ state: 'active' });
    expect(g.coverage.truncations).toBe(1);
  });

  it('applied up to 100, rollback to 80, a new branch and a retirement at 90 delivered late', async () => {
    const steps: ScheduleStep[] = [
      deliver(reg(m, 0, 5), create(0x10, 10, 1), join(0x90, 90, G(0x10)), byA(0xa0, 100, ev.approve(J(0x90)))),
      frontiers(100), run(), check('old'),
      { kind: 'rollback', to: 80, suffix: [join(0x85, 85, G(0x10)), byA(0x95, 95, ev.approve(J(0x85)))] },
      frontiers(95), run(), check('new'),
      deliver(unreg(m, 1, 90)), check('late'),
      run(), run(), run(),
    ];
    const r = await go(steps);
    expect(applied(at(r, 'old'), m)).toEqual(evAt(0xa0, 100));
    expect(reasonOf(at(r, 'new'), 0x95)).toBeNull();
    expect(at(r, 'late').recovery.first).toEqual({ kind: 'truncate', above: 89 });
    expect(reasonOf(r.final, 0x85)).toBeNull();
    expect(reasonOf(r.final, 0x95)).toBe('join is not pending');
    expect(instance(r.final, 0x85)).toMatchObject({ state: 'closed', reason: 'retired', approvedAt: null });
    expect(r.coverage.truncations).toBe(2);
    expect(r.coverage.forks).toBe(0);
  });

  it('a credential older than the floor with a re-delivered history', async () => {
    const history = [reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10))];
    const steps = [
      deliver(...history, reg(n, 1, 6), join(0xc0, 2990, G(0x10), N)),
      frontiers(3000), run(), check('settled'),
      // A late retirement of N restarts the readers through a truncation.
      deliver(unreg(n, 2, 2980)), check('late'),
      run(), run(), run(),
      // The restarted history of m delivers its rows again.
      deliver(...history), check('redelivered'),
      run(),
    ];
    const r = await go(steps);
    const settled = at(r, 'settled');
    expect(settled.frontiers.L - 2160).toBeGreaterThan(20);
    expect(at(r, 'late').recovery.first).toEqual({ kind: 'truncate', above: 2979 });
    const redelivered = at(r, 'redelivered');
    expect(redelivered.recovery.first).toBeNull();
    expect(redelivered.ledger).toHaveLength(3);
    expect(redelivered.labelTxs).toHaveLength(3);
    expect(applied(redelivered, m)).toEqual(applied(settled, m));
    expect(r.coverage.truncations).toBe(1);
    expect(r.coverage.forks).toBe(0);
    expect(reasonOf(r.final, 0x20)).toBeNull();
    expect(reasonOf(r.final, 0xc0)).toBe('not a registered DRep');
  });

  it('a script DRep with join at 80 and approval at 100 applied, made incomplete, then a retirement at 90', async () => {
    const steps = [
      deliver(reg(s, 0, 5, S), create(0x10, 10, 1), scriptJoin(0x80, 80, G(0x10), S, SK), byA(0xa0, 100, ev.approve(J(0x80)))),
      frontiers(100), run(), check('applied'),
      complete(s, false),
      deliver(unreg(s, 1, 90)), check('late'),
      run(), run(), run(), check('incomplete'),
      complete(s, true), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(at(r, 'applied'), 0xa0)).toBeNull();
    expect(at(r, 'late').recovery.first).toEqual({ kind: 'truncate', above: 89 });
    // The truncation lowers applied-through to END(89), the incomplete credential stays there.
    expect(applied(at(r, 'incomplete'), s)).toEqual(endOf(89));
    expect(reasonOf(r.final, 0xa0)).toBe('join is not pending');
    expect(instance(r.final, 0x80)).toMatchObject({ state: 'closed', reason: 'retired', approvedAt: null });
    expect(r.coverage.truncations).toBe(1);
  });

  it('a reorg 30 blocks deep', async () => {
    const steps: ScheduleStep[] = [
      deliver(reg(m, 0, 5), create(0x10, 2950, 0), join(0x20, 2960, G(0x10)), leave(0x30, 2990, J(0x20))),
      frontiers(3000), run(), check('tip'),
      { kind: 'rollback', to: 2970, suffix: [leave(0x31, 2985, J(0x20))] },
      check('cut'),
      frontiers(3000), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(at(r, 'tip'), 0x30)).toBeNull();
    const cut = at(r, 'cut');
    expect(cut.recovery.first).toBeNull();
    expect(cut.verdicts.some((v) => v.ref.txHash === T(0x30))).toBe(false);
    expect(cut.ledger).toHaveLength(1);
    expect(r.coverage.truncations).toBe(1);
    expect(r.coverage.forks).toBe(0);
    expect(instance(r.final, 0x20)).toMatchObject({ reason: 'left', closedAt: evAt(0x31, 2985) });
  });

  it('inputs in block R', async () => {
    const steps = [
      deliver(reg(m, 0, 5), reg(n, 1, 5), create(0x10, 10, 0), join(0x50, 50, G(0x10)), join(0x51, 51, G(0x10), N)),
      frontiers(60, 50), run(), run(), check('R'),
    ];
    const r = await go(steps);
    const snap = at(r, 'R');
    expect(snap.frontiers.G).toEqual(endOf(60));
    expect(applied(snap, m)).toEqual(evAt(0x50, 50));
    expect(reasonOf(snap, 0x50)).toBeNull();
    // N is applied through its registration, its join in block 51 waits for R.
    expect(applied(snap, n)).toEqual(certAt(reg(n, 1, 5)));
    expect(snap.queue.find((q) => q.txHash === T(0x51))?.applied).toBe(false);
  });

  it('scripts published only in a tx with membership events, used by an update in a later tx', async () => {
    const NEW = sig(K(5));
    const steps = [
      deliver(
        reg(m, 0, 5), create(0x10, 10, 0),
        txIn({ hash: T(0x20), h: 20, rs: [M], payload: buildPayload([ev.join(G(0x10), 'key', M)], [NEW]) }),
        txIn({ hash: T(0x30), h: 30, wk: [A, K(5)], payload: buildPayload([ev.update(G(0x10), 0, new Map([[0, kb(hashOf(NEW))]]))]) }),
      ),
      frontiers(30), run({ controlTxs: 1 }), run({ controlTxs: 1 }), run({ controlTxs: 1 }), run({ controlTxs: 1 }),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x20)).toBeNull();
    expect(reasonOf(r.final, 0x30)).toBeNull();
    expect(r.final.scripts.find((x) => x.hash === hashOf(NEW))?.at).toEqual(posOfScripts({ txHash: T(0x20), blockHeight: 20, txIndex: 0 }));
    expect(r.final.groups[0]).toMatchObject({ control: hashOf(NEW), seq: 1n });
  });

  it('open group approve and remove on a closed instance', async () => {
    const steps = [
      deliver(
        reg(m, 0, 5), create(0x10, 10, 0), join(0x20, 20, G(0x10)), leave(0x25, 25, J(0x20)),
        byA(0x30, 30, ev.approve(J(0x20))), byA(0x35, 35, ev.remove(J(0x20))),
      ),
      frontiers(35), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x30)).toBe('open group has no approval');
    expect(reasonOf(r.final, 0x35)).toBe('open group has no remove');
    expect(instance(r.final, 0x20)).toMatchObject({ reason: 'left' });
  });

  it('same tx folds', async () => {
    const membership = txIn({
      hash: T(0x10), h: 10, rs: [M], wk: [A],
      payload: buildPayload([
        ev.create(1, ctl, ctl),            // 0, its control script is in this payload
        ev.update(local(0), 0, new Map()), // 1
        ev.join(local(0), 'key', M),       // 2
        ev.approve(local(2)),              // 3
        ev.leave(local(2)),                // 4
        ev.join(local(0), 'key', M),       // 5
        ev.remove(local(5)),               // 6
      ], [CTL]),
    });
    const control = txIn({
      hash: T(0x11), h: 11, wk: [A2],
      payload: buildPayload([ev.create(0, hashOf(CTL2), null), ev.dissolve(local(0), 0)], [CTL2]),
    });
    const steps = [deliver(reg(m, 0, 5), membership, control), frontiers(11), run({ controlTxs: 1, credentialInputs: 1 })];
    const r = await go(steps);
    for (let i = 0; i <= 6; i++) expect(reasonOf(r.final, 0x10, i), `event ${i}`).toBeNull();
    for (let i = 0; i <= 1; i++) expect(reasonOf(r.final, 0x11, i), `event ${i}`).toBeNull();
    expect(instance(r.final, 0x10, 2)).toMatchObject({ reason: 'left', approvedAt: evAt(0x10, 10, 3), closedAt: evAt(0x10, 10, 4) });
    expect(instance(r.final, 0x10, 5)).toMatchObject({ reason: 'removed', closedAt: evAt(0x10, 10, 6) });
    const groups = new Map(r.final.groups.map((g) => [g.id.txHash, g]));
    expect(groups.get(T(0x10))).toMatchObject({ seq: 1n, status: 'active' });
    expect(groups.get(T(0x11))).toMatchObject({ status: 'dissolved' });
  });

  it('a join naming an unknown group', async () => {
    let store: CountingStore | null = null;
    const steps = [
      deliver(reg(m, 0, 5), join(0x20, 20, G(0x99))),
      frontiers(20), run(), run(), run(), check('applied'),
    ];
    const r = await go(steps, () => (store = new CountingStore()));
    expect(replayReason(steps, 0x20)).toBe('unknown group');
    const snap = at(r, 'applied');
    expect(verdict(snap, 0x20)).toBeUndefined();
    expect(snap.queue.find((q) => q.txHash === T(0x20))?.applied).toBe(true);
    expect((store as CountingStore | null)?.delivered.get(refKey({ txHash: T(0x20), index: 0 }))).toBe(1);
    expect(r.final.verdicts).toEqual([]);
  });

  it('a script credential whose first reg has no matching witness and whose later reg has one', async () => {
    const later = reg(s2, 2, 30, S2);
    const steps = [
      deliver(reg(s2, 0, 5), create(0x10, 10, 0), scriptJoin(0x20, 20, G(0x10), S2, SK2), unreg(s2, 1, 25)),
      frontiers(25), run(),
      deliver(later, scriptJoin(0x40, 40, G(0x10), S2, SK2)),
      frontiers(40), run(),
    ];
    const r = await go(steps);
    expect(reasonOf(r.final, 0x20)).toBe('member script unresolved');
    expect(reasonOf(r.final, 0x40)).toBeNull();
    expect(r.final.memberScripts.map((x) => [credKey(x.credential), x.at])).toEqual([[credKey(s2), certAt(later)]]);
  });
});
