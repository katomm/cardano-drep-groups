import { describe, expect, it } from 'vitest';
import { routeTx } from '../src/engine/route.js';
import type { ChainTx, Credential, DecodedEvent, DecodedPayload, EventRef, GroupEvent } from '../src/types.js';
import { K, T } from './helpers.js';

const tx: ChainTx = {
  txHash: T(1), blockHeight: 100, txIndex: 3, isValid: true, invalidBefore: null, invalidHereafter: null,
  requiredSigners: [], witnessKeyHashes: [], payload: undefined, payloadRepeated: false, witnessScripts: [],
};
const key = (n: number): Credential => ({ kind: 'key', hash: K(n) });
const script = (n: number): Credential => ({ kind: 'script', hash: K(n) });
const ok = (event: GroupEvent): DecodedEvent => ({ ok: true, event });
const group = { txHash: T(9), index: 0 };
const join = (member: Credential): DecodedEvent => ok({ tag: 'join', group, member });
const payload = (...events: DecodedEvent[]): DecodedPayload => ({ events, scripts: [] });
const none = (): null => null;

describe('routeTx', () => {
  it("routes approve on a join of the same tx to that join's member", () => {
    const r = routeTx(tx, payload(join(key(1)), ok({ tag: 'approve', join: { local: 0 } })), none);
    expect(r.events.map((e) => [e.plane, e.subject])).toEqual([['membership', key(1)], ['membership', key(1)]]);
    expect(r.events[1]!.at).toMatchObject({ blockHeight: 100, txIndex: 3, txHash: T(1), phase: 2, index: 1 });
    expect(r.events[1]!.ref).toEqual({ txHash: T(1), index: 1 });
    expect(r.events.map((e) => e.group)).toEqual([group, group]);
  });

  it('carries the resolved group of the join on approve, leave and remove', () => {
    // A join naming a group created earlier in the same tx resolves against the join's own tx.
    const local = ok({ tag: 'join', group: { local: 0 }, member: key(1) });
    const create = ok({ tag: 'create', mode: 'permissioned', control: K(1), admission: K(2), profile: null });
    const own = { txHash: T(1), index: 0 };
    const r = routeTx(tx, payload(
      create, local,
      ok({ tag: 'approve', join: { local: 1 } }),
      ok({ tag: 'leave', join: { txHash: T(1), index: 1 } }),
      ok({ tag: 'remove', join: { txHash: T(2), index: 4 } }),
    ), () => ok({ tag: 'join', group: { local: 1 }, member: key(3) }));
    expect(r.events.map((e) => [e.plane, e.group])).toEqual([
      ['control', null], ['membership', own], ['membership', own], ['membership', own],
      // The queued join's local group ref resolves against the queued join's tx.
      ['membership', { txHash: T(2), index: 1 }],
    ]);
  });

  it('gives a join with an unresolvable group and its approve a null group', () => {
    const bad = ok({ tag: 'join', group: { local: 0 }, member: key(1) }); // refers to itself
    const r = routeTx(tx, payload(bad, ok({ tag: 'approve', join: { local: 0 } })), none);
    expect(r.events.map((e) => [e.plane, e.subject, e.group])).toEqual([['membership', key(1), null], ['membership', key(1), null]]);
  });

  it("routes a ref to a queued join of another tx to its member", () => {
    const asked: EventRef[] = [];
    const r = routeTx(tx, payload(ok({ tag: 'leave', join: { txHash: T(2), index: 4 } })), (ref) => {
      asked.push(ref);
      return join(script(5));
    });
    expect(asked).toEqual([{ txHash: T(2), index: 4 }]);
    expect(r.events[0]).toMatchObject({ plane: 'membership', subject: script(5), group });
  });

  it('treats ignored and null alike as orphan', () => {
    const p = payload(ok({ tag: 'remove', join: { txHash: T(2), index: 0 } }));
    for (const answer of ['ignored', null] as const) {
      expect(routeTx(tx, p, () => answer).events[0]).toMatchObject({ plane: 'orphan', subject: null, group: null });
    }
    // A queued entry that is not a join is an orphan as well.
    const create = ok({ tag: 'create', mode: 'open', control: K(1), admission: null, profile: null });
    expect(routeTx(tx, p, () => create).events[0]).toMatchObject({ plane: 'orphan', subject: null });
  });

  it('rejects a local ref to the same or a later index', () => {
    const r = routeTx(tx, payload(
      ok({ tag: 'approve', join: { local: 0 } }), // same index
      ok({ tag: 'leave', join: { local: 5 } }),   // later index
      join(key(1)),
      ok({ tag: 'approve', join: { local: 0 } }), // refers to a non join
    ), none);
    expect(r.events.map((e) => [e.plane, e.subject])).toEqual([
      ['orphan', null], ['orphan', null], ['membership', key(1)], ['orphan', null],
    ]);
  });

  it('routes an explicit ref to its own hash like a same tx ref', () => {
    const own = (index: number): GroupEvent => ({ tag: 'approve', join: { txHash: T(1), index } });
    const r = routeTx(tx, payload(
      join(key(1)),
      ok(own(0)), // earlier join
      ok(own(1)), // itself
      ok(own(3)), // later index, a join
      join(key(2)),
      ok(own(1)), // earlier non join
    ), () => { throw new Error('own hash must not ask the queue'); });
    expect(r.events.map((e) => [e.plane, e.subject])).toEqual([
      ['membership', key(1)], ['membership', key(1)], ['orphan', null],
      ['orphan', null], ['membership', key(2)], ['orphan', null],
    ]);
    expect(r.foreignJoins).toEqual([]);
  });

  it('routes control events and unreadable events', () => {
    const r = routeTx(tx, payload(
      ok({ tag: 'create', mode: 'open', control: K(1), admission: null, profile: null }),
      ok({ tag: 'update', group: { local: 0 }, seq: 0n, changes: {} }),
      ok({ tag: 'dissolve', group: { local: 0 }, seq: 1n }),
      { ok: false, reason: 'bad event' },
    ), none);
    expect(r.events.map((e) => [e.plane, e.subject])).toEqual([
      ['control', null], ['control', null], ['control', null], ['orphan', null],
    ]);
  });

  it('lists every join member, signed or unsigned, key or script', () => {
    const r = routeTx(tx, payload(join(key(1)), join(script(2)), join(key(1)), join(script(1))), none);
    expect(r.joinMembers).toEqual([key(1), script(2), script(1)]);
  });

  it('lists foreign join refs once', () => {
    const a = { txHash: T(2), index: 0 };
    const r = routeTx(tx, payload(
      ok({ tag: 'approve', join: a }), ok({ tag: 'leave', join: { ...a } }),
      ok({ tag: 'remove', join: { txHash: T(3), index: 1 } }), ok({ tag: 'approve', join: { local: 0 } }),
    ), () => null);
    expect(r.foreignJoins).toEqual([a, { txHash: T(3), index: 1 }]);
  });

  it('passes the published scripts through', () => {
    const s = { hash: K(1), bytes: new Uint8Array([1]), script: { type: 'sig' as const, keyHash: K(1) } };
    expect(routeTx(tx, { events: [], scripts: [s] }, none).scripts).toEqual([s]);
  });
});
