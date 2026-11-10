import { describe, expect, it } from 'vitest';
import { effectiveClose } from '../src/effective.js';
import { comparePos, type Pos } from '../src/position.js';
import { ALL_REASONS, controlRule, eventRule, type GroupVersion, membershipRule, type RuleWorld, type StoredInstance } from '../src/rules.js';
import { refKey, replay } from '../src/state.js';
import type { Credential, EvalContext, EventRef, GroupEvent, Hex, NativeScript } from '../src/types.js';
import { VECTORS } from '../vectors/definitions.js';
import { allOf, buildPayload, ev, hashOf, K, kb, keyCred, nOfK, ref, regIn, sig, T, txIn } from './helpers.js';

const p = (h: number, i = 0): Pos => ({ blockHeight: h, txIndex: 0, txHash: T(h), phase: 2, index: i });
const cert = (h: number): Pos => ({ blockHeight: h, txIndex: 0, txHash: T(h), phase: 0, index: 0 });
const selfAt = (h: number, i = 0): EventRef => ({ txHash: T(h), index: i });
const credKeyOf = (c: Credential): string => `${c.kind}:${c.hash}`;

const CONTROL = 'cc'.repeat(28);
const controlScript: NativeScript = { type: 'sig', keyHash: K(9) };
const G: EventRef = { txHash: T(5), index: 0 };
const M: Credential = { kind: 'key', hash: K(1) };
const ctx: EvalContext = { signers: new Set([K(1), K(9)]), invalidBefore: null, invalidHereafter: null };
const required = new Set([K(1)]);

const version = (o: Partial<GroupVersion> & { at: Pos }): GroupVersion => ({
  id: G, mode: 'open', control: CONTROL, admission: null, profile: null, seq: 0n,
  status: 'active', createdAt: p(5), profileSetAt: null, resignedControl: [], resignedAdmission: [], ...o,
});
const instance = (o: Partial<StoredInstance> & { joinId: EventRef; joinedAt: Pos }): StoredInstance => ({
  group: G, member: M, mode: 'open', approvedAt: null, closedAt: null, closeReason: null, ...o,
});

// A lazy world: dissolves and unregs are never applied to the stored instances,
// every read projects them through effectiveClose with q = the read position.
function lazyWorld(o: {
  versions: GroupVersion[];
  instances?: StoredInstance[];
  ledger?: Array<{ c: Credential; at: Pos; kind: 'reg' | 'unreg' }>;
}): RuleWorld {
  const instances = o.instances ?? [];
  const ledger = o.ledger ?? [{ c: M, at: cert(1), kind: 'reg' }];
  const scripts = new Map<Hex, { at: Pos; script: NativeScript }>([[CONTROL, { at: p(1), script: controlScript }]]);
  const versionsOf = (g: EventRef) => o.versions.filter((v) => refKey(v.id) === refKey(g));
  const dissolveOf = (g: EventRef) => versionsOf(g).find((v) => v.status === 'dissolved')?.at ?? null;
  const firstUnregAfter = (c: Credential, after: Pos) =>
    ledger.filter((l) => l.kind === 'unreg' && credKeyOf(l.c) === credKeyOf(c) && comparePos(l.at, after) > 0)
      .sort((a, b) => comparePos(a.at, b.at))[0]?.at ?? null;
  const closeAt = (inst: StoredInstance, q: Pos) =>
    effectiveClose(inst, dissolveOf(inst.group), firstUnregAfter(inst.member, inst.joinedAt), q);
  return {
    scriptAt: (hash, at) => {
      const s = scripts.get(hash);
      return s && comparePos(s.at, at) <= 0 ? s.script : null;
    },
    groupAt: (g, at) => versionsOf(g).filter((v) => comparePos(v.at, at) <= 0).sort((a, b) => comparePos(b.at, a.at))[0] ?? null,
    registeredAt: (c, at) => {
      const last = ledger.filter((l) => credKeyOf(l.c) === credKeyOf(c) && comparePos(l.at, at) <= 0)
        .sort((a, b) => comparePos(b.at, a.at))[0];
      return last?.kind === 'reg';
    },
    memberScriptAt: () => null,
    instanceAt: (join, at) => {
      const inst = instances.find((i) => refKey(i.joinId) === refKey(join) && comparePos(i.joinedAt, at) < 0);
      return inst ? { inst, close: closeAt(inst, at) } : null;
    },
    openSlotAt: (g, c, at) => {
      const latest = instances
        .filter((i) => refKey(i.group) === refKey(g) && credKeyOf(i.member) === credKeyOf(c) && comparePos(i.joinedAt, at) < 0)
        .sort((a, b) => comparePos(b.joinedAt, a.joinedAt))[0];
      return latest && closeAt(latest, at) === null ? latest : null;
    },
  };
}

const J = selfAt(10);
const join: GroupEvent = { tag: 'join', group: G, member: M };

describe('rules over a lazy world', () => {
  it('a join after a lazy dissolve gives group dissolved', () => {
    const w = lazyWorld({ versions: [version({ at: p(5) }), version({ at: p(30), status: 'dissolved' })] });
    expect(eventRule(w, join, selfAt(40), ctx, required, p(40))).toEqual({ reason: 'group dissolved', group: G, subject: M, writes: [] });
    // Before the dissolve the same join is valid.
    expect(eventRule(w, join, selfAt(20), ctx, required, p(20)).reason).toBeNull();
  });

  it('a join after unreg and a new registration is valid (open slot follows the effective close)', () => {
    const ledger = [
      { c: M, at: cert(1), kind: 'reg' as const },
      { c: M, at: cert(20), kind: 'unreg' as const },
      { c: M, at: cert(25), kind: 'reg' as const },
    ];
    const w = lazyWorld({ versions: [version({ at: p(5) })], instances: [instance({ joinId: J, joinedAt: p(10) })], ledger });
    expect(membershipRule(w, join, selfAt(30), ctx, required, p(30))).toEqual({
      reason: null, group: G, subject: M,
      writes: [{ kind: 'instance', instance: instance({ joinId: selfAt(30), joinedAt: p(30) }) }],
    });
    // Between the unreg and the new registration the credential is not registered.
    expect(membershipRule(w, join, selfAt(22), ctx, required, p(22)).reason).toBe('not a registered DRep');
    // Without the unreg the slot is still taken.
    const taken = lazyWorld({ versions: [version({ at: p(5) })], instances: [instance({ joinId: J, joinedAt: p(10) })] });
    expect(membershipRule(taken, join, selfAt(30), ctx, required, p(30)).reason).toBe('already a member or applicant');
  });

  it('approve on an open group with a closed instance gives open group has no approval', () => {
    const w = lazyWorld({
      versions: [version({ at: p(5) })],
      instances: [instance({ joinId: J, joinedAt: p(10), closedAt: p(20), closeReason: 'left' })],
    });
    expect(membershipRule(w, { tag: 'approve', join: J }, selfAt(30), ctx, required, p(30)))
      .toEqual({ reason: 'open group has no approval', group: G, subject: M, writes: [] });
    expect(membershipRule(w, { tag: 'remove', join: J }, selfAt(30), ctx, required, p(30)).reason).toBe('open group has no remove');
  });

  it('a stored dissolve at 30 does not turn a leave at 20 into join is not open', () => {
    const w = lazyWorld({
      versions: [version({ at: p(5) }), version({ at: p(30), status: 'dissolved' })],
      instances: [instance({ joinId: J, joinedAt: p(10) })],
    });
    expect(membershipRule(w, { tag: 'leave', join: J }, selfAt(20), ctx, required, p(20))).toEqual({
      reason: null, group: G, subject: M,
      writes: [{ kind: 'instance', instance: instance({ joinId: J, joinedAt: p(10), closedAt: p(20), closeReason: 'left' }) }],
    });
    expect(membershipRule(w, { tag: 'leave', join: J }, selfAt(35), ctx, required, p(35)).reason).toBe('join is not open');
  });

  it('a join ref to a join not yet at the position gives unknown join with no attribution', () => {
    const w = lazyWorld({ versions: [version({ at: p(5) })], instances: [instance({ joinId: J, joinedAt: p(10) })] });
    expect(membershipRule(w, { tag: 'leave', join: J }, selfAt(8), ctx, required, p(8)))
      .toEqual({ reason: 'unknown join', group: null, subject: null, writes: [] });
  });

  it('a dissolve writes the dissolved version only, never instances', () => {
    const w = lazyWorld({ versions: [version({ at: p(5) })], instances: [instance({ joinId: J, joinedAt: p(10) })] });
    expect(controlRule(w, { tag: 'dissolve', group: G, seq: 0n }, selfAt(30), ctx, required, p(30))).toEqual({
      reason: null, group: G, subject: null,
      writes: [{ kind: 'version', version: version({ at: p(30), status: 'dissolved' }) }],
    });
  });

  it('an update writes a new version at its position with the next seq', () => {
    const w = lazyWorld({ versions: [version({ at: p(5) })] });
    const profile = { url: 'https://x', dataHash: 'dd'.repeat(32) };
    const r = controlRule(w, { tag: 'update', group: G, seq: 0n, changes: { profile } }, selfAt(30), ctx, required, p(30));
    expect(r.writes).toEqual([{ kind: 'version', version: version({ at: p(30), seq: 1n, profile, profileSetAt: p(30) }) }]);
  });

  it('membershipRule returns unknown event for a control event', () => {
    const w = lazyWorld({ versions: [] });
    const create: GroupEvent = { tag: 'create', mode: 'open', control: CONTROL, admission: null, profile: null };
    expect(membershipRule(w, create, selfAt(30), ctx, required, p(30)))
      .toEqual({ reason: 'unknown event', group: null, subject: null, writes: [] });
  });
});

describe('consent by explicit signature, per role', () => {
  const k1 = sig(K(1));
  const k2 = sig(K(2));
  const create = (mode: 0 | 1, control: unknown[], admission: unknown[] | null, rs: string[], wk: string[] = []) =>
    txIn({
      hash: T(1), h: 10, rs, wk,
      payload: buildPayload([ev.create(mode, hashOf(control), admission ? hashOf(admission) : null)], admission ? [control, admission] : [control]),
    });
  const update = (changes: Map<number, unknown>, scripts: unknown[][], rs: string[], wk: string[] = []) =>
    txIn({ hash: T(2), h: 11, rs, wk, payload: buildPayload([ev.update(ref(T(1), 0), 0, changes)], scripts) });
  const reasons = (inputs: Parameters<typeof replay>[0]) => replay(inputs).verdicts.map((v) => v.reason);

  it('a create needs every listed key in required_signers, a vkey witness is not enough', () => {
    expect(reasons([create(0, k1, null, [], [K(1)])])).toEqual(['listed key did not sign explicitly']);
    expect(reasons([create(0, k1, null, [K(1)])])).toEqual([null]);
  });

  it('a key moving from admission into control signs explicitly again', () => {
    const both = allOf(k1, k2);
    const set = new Map([[0, kb(hashOf(both))]]);
    const base = create(1, k1, k2, [K(1), K(2)]);
    expect(reasons([base, update(set, [both], [K(1)], [K(2)])])).toEqual([null, 'key new to its role did not sign explicitly']);
    expect(reasons([base, update(set, [both], [K(1), K(2)])])).toEqual([null, null]);
  });

  it('policy satisfaction still counts vkey witnesses', () => {
    const two = nOfK(2, k1, k2);
    expect(reasons([create(0, two, null, [K(1), K(2)]), update(new Map(), [], [K(1)], [K(2)])])).toEqual([null, null]);
  });

  it('a control key that joins the admission role signs explicitly for it', () => {
    const both = allOf(k1, k2);
    const set = new Map([[1, kb(hashOf(both))]]);
    expect(reasons([create(1, k1, k2, [K(1), K(2)]), update(set, [both], [K(2)], [K(1)])]))
      .toEqual([null, 'key new to its role did not sign explicitly']);
  });

  it('a key the role already lists may sign only as a witness on an update that keeps it', () => {
    const next = allOf(k1, sig(K(3)));
    const set = new Map([[0, kb(hashOf(next))]]);
    expect(reasons([create(0, nOfK(1, k1, k2), null, [K(1), K(2)]), update(set, [next], [K(2), K(3)], [K(1)])])).toEqual([null, null]);
  });
});

describe('resignation per role', () => {
  const k1 = sig(K(1));
  const k3 = sig(K(3));
  const shared = nOfK(1, k1, sig(K(2)));
  const one3 = nOfK(1, k1, k3);
  const M = K(0x50);
  const G1 = ref(T(1), 0);
  const tx = (h: number, events: unknown[][], rs: string[], wk: string[] = [], scripts: unknown[][] = []) =>
    txIn({ hash: T(h), h, rs, wk, payload: buildPayload(events, scripts) });
  // Control and admission are the same 1 of [K1, K2] script, K1 resigns from both roles.
  const base = [
    tx(1, [ev.create(1, hashOf(shared), hashOf(shared))], [K(1), K(2)], [], [shared]),
    tx(2, [ev.resign(G1, K(1))], [K(1)]),
  ];
  const reasons = (inputs: Parameters<typeof replay>[0]) => replay(inputs).verdicts.map((v) => v.reason);
  const group = (inputs: Parameters<typeof replay>[0]) => replay(inputs).groups[0]!;

  it('a resign from a shared policy records the key in both roles and drops its signature there', () => {
    expect(reasons(base)).toEqual([null, null]);
    expect(group(base)).toMatchObject({ seq: 1n, resignedControl: [K(1)], resignedAdmission: [K(1)] });
    expect(reasons([...base, tx(3, [ev.update(G1, 1, new Map())], [K(1)])])[2]).toBe('control policy not satisfied');
    expect(reasons([...base, tx(3, [ev.update(G1, 1, new Map())], [K(2)])])[2]).toBeNull();
  });

  it('an update that sets one role clears the resignations of that role only', () => {
    const relist = tx(3, [ev.update(G1, 1, new Map([[1, kb(hashOf(one3))]]))], [K(2), K(1), K(3)], [], [one3]);
    expect(reasons([...base, relist])[2]).toBeNull();
    expect(group([...base, relist])).toMatchObject({ seq: 2n, resignedControl: [K(1)], resignedAdmission: [] });
    // The resigned key counts as not listed, so a witness alone does not re-list it.
    const witnessed = tx(3, [ev.update(G1, 1, new Map([[1, kb(hashOf(one3))]]))], [K(2), K(3)], [K(1)], [one3]);
    expect(reasons([...base, witnessed])[2]).toBe('key new to its role did not sign explicitly');
    const join = tx(4, [ev.join(G1, 'key', M)], [M]);
    const after = [...base, relist, regIn(keyCred(M), T(0x40), 3, 1), join];
    expect(reasons([...after, tx(5, [ev.approve(ref(T(4), 0))], [K(1)])])[4]).toBeNull();
    expect(reasons([...after, tx(5, [ev.update(G1, 2, new Map())], [K(1)])])[4]).toBe('control policy not satisfied');
  });

  it('a key not listed in any role, or resigned from every role that lists it, cannot resign', () => {
    expect(reasons([base[0]!, tx(2, [ev.resign(G1, K(9))], [K(9)])])).toEqual([null, 'key not listed in any role']);
    expect(reasons([...base, tx(3, [ev.resign(G1, K(1))], [K(1)])])[2]).toBe('key not listed in any role');
  });

  it('a key listed again in one role can resign from it again', () => {
    const relist = tx(3, [ev.update(G1, 1, new Map([[1, kb(hashOf(one3))]]))], [K(2), K(1), K(3)], [], [one3]);
    const again = [...base, relist, tx(4, [ev.resign(G1, K(1))], [K(1)])];
    expect(reasons(again)).toEqual([null, null, null, null]);
    expect(group(again)).toMatchObject({ seq: 3n, resignedControl: [K(1)], resignedAdmission: [K(1)] });
  });

  it('a resign needs the explicit signature of the key', () => {
    expect(reasons([base[0]!, tx(2, [ev.resign(G1, K(1))], [], [K(1)])])).toEqual([null, 'resigning key did not sign explicitly']);
  });

  it('events of one transaction apply in order', () => {
    const solo = tx(1, [ev.create(0, hashOf(k1), null)], [K(1)], [], [k1]);
    const frozen = [solo, tx(2, [ev.resign(G1, K(1)), ev.dissolve(G1, 1)], [K(1)])];
    expect(reasons(frozen)).toEqual([null, null, 'control policy not satisfied']);
    expect(group(frozen)).toMatchObject({ status: 'active', seq: 1n, resignedControl: [K(1)] });
    const gone = [solo, tx(2, [ev.dissolve(G1, 0), ev.resign(G1, K(1))], [K(1)])];
    expect(reasons(gone)).toEqual([null, null, 'group dissolved']);
    expect(group(gone)).toMatchObject({ status: 'dissolved', resignedControl: [] });
    const three = nOfK(2, k1, sig(K(2)), k3);
    const multi = tx(1, [ev.create(0, hashOf(three), null)], [K(1), K(2), K(3)], [], [three]);
    expect(reasons([multi, tx(2, [ev.resign(G1, K(1)), ev.update(G1, 0, new Map())], [K(1), K(2), K(3)])]))
      .toEqual([null, null, 'stale seq']);
  });

  it('a resign makes a control transaction signed before it stale', () => {
    const three = nOfK(2, k1, sig(K(2)), k3);
    const multi = tx(1, [ev.create(0, hashOf(three), null)], [K(1), K(2), K(3)], [], [three]);
    expect(reasons([multi, tx(2, [ev.resign(G1, K(1))], [K(1)]), tx(3, [ev.update(G1, 0, new Map())], [K(2), K(3)])]))
      .toEqual([null, null, 'stale seq']);
  });
});

describe('policies that need no signature', () => {
  const reasons = (inputs: Parameters<typeof replay>[0]) => replay(inputs).verdicts.map((v) => v.reason);
  const k1 = sig(K(1));
  it('a create with a signature-free control policy is invalid', () => {
    const free = allOf();
    const tx = txIn({ hash: T(1), h: 10, rs: [], payload: buildPayload([ev.create(0, hashOf(free), null)], [free]) });
    expect(reasons([tx])).toEqual(['control policy needs no signature']);
  });
  it('an update to a signature-free admission policy is invalid', () => {
    const free = [2, [[4, 0]]];
    const create = txIn({ hash: T(1), h: 10, rs: [K(1)], payload: buildPayload([ev.create(1, hashOf(k1), hashOf(k1))], [k1]) });
    const update = txIn({
      hash: T(2), h: 11, rs: [K(1)],
      payload: buildPayload([ev.update(ref(T(1), 0), 0, new Map([[1, kb(hashOf(free))]]))], [free]),
    });
    expect(reasons([create, update])).toEqual([null, 'admission policy needs no signature']);
  });
});

describe('ALL_REASONS', () => {
  it('lists each reason once and leaves out the defensive unknown event', () => {
    expect(new Set(ALL_REASONS).size).toBe(ALL_REASONS.length);
    expect(ALL_REASONS).not.toContain('unknown event');
  });

  it('covers every reason that replay gives for a decodable event in the vectors', () => {
    for (const v of VECTORS) {
      for (const verdict of replay(v.inputs).verdicts) {
        if (verdict.tag !== null && verdict.reason !== null) expect(ALL_REASONS).toContain(verdict.reason);
      }
    }
  });
});
