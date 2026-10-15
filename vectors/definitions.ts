import { encode } from 'cborg';
import { concatBytes, hexToBytes } from '../src/hex.js';
import type { ChainInput } from '../src/types.js';
import {
  after, allOf, anyOf, before, buildPayload, buildPayloadRaw, chunk64, ev, hashOf, K, kb, keyCred, local,
  nOfK, ref, regIn, scriptBytes, scriptCred, sig, T, txIn, unregIn,
} from '../test/helpers.js';

export interface GroupExpect { id: string; status: string; seq: string; mode: string; control: string; admission: string | null; profileUrl: string | null }
export interface InstanceExpect { joinId: string; group: string; member: string; state: string; reason: string | null }
export interface VerdictExpect { ref: string; valid: boolean; reason: string | null }
export interface VectorDef {
  name: string;
  inputs: ChainInput[];
  expect: { groups: GroupExpect[]; instances: InstanceExpect[]; verdicts: VerdictExpect[] };
}

const ctrl = nOfK(2, sig(K(1)), sig(K(2)), sig(K(3)));
const adm = nOfK(1, sig(K(1)), sig(K(2)));
const C = hashOf(ctrl);
const A = hashOf(adm);
const ALL = [K(1), K(2), K(3)];
const M = K(0x50);
const reg = regIn(keyCred(M), T(0x40), 5);

const G = (tx: string, o: Partial<GroupExpect> = {}): GroupExpect => ({
  id: `${tx}#0`, status: 'active', seq: '0', mode: 'open', control: C, admission: null, profileUrl: null, ...o,
});
const I = (tx: string, state: string, reason: string | null = null, o: { index?: number; group?: string; member?: string } = {}): InstanceExpect => ({
  joinId: `${tx}#${o.index ?? 0}`, group: o.group ?? `${T(1)}#0`, member: o.member ?? `key:${M}`, state, reason,
});
const V = (tx: string, valid: boolean, reason: string | null = null, index = 0): VerdictExpect => ({ ref: `${tx}#${index}`, valid, reason });

const openCreate = (rs = ALL, hash = T(1), h = 10) => txIn({ hash, h, payload: buildPayload([ev.create(0, C, null)], [ctrl]), rs });
const permCreate = txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(1, C, A)], [ctrl, adm]), rs: ALL });
const join = (hash: string, h: number, member = M, i = 0) => txIn({ hash, h, i, payload: buildPayload([ev.join(ref(T(1), 0), 'key', member)]), rs: [member] });
const act = (kind: 'approve' | 'leave' | 'remove', joinTx: string, hash: string, h: number, rs: string[]) =>
  txIn({ hash, h, payload: buildPayload([ev[kind](ref(joinTx, 0))]), rs });
const update = (hash: string, h: number, seq: number, changes: Map<number, unknown>, rs: string[], scripts: unknown[][] = []) =>
  txIn({ hash, h, payload: buildPayload([ev.update(ref(T(1), 0), seq, changes)], scripts), rs });
const dissolve = (hash: string, h: number, seq: number, rs: string[]) => txIn({ hash, h, payload: buildPayload([ev.dissolve(ref(T(1), 0), seq)]), rs });

const newCtrl = nOfK(1, sig(K(4)));
const ms = allOf(sig(K(0x60)), sig(K(0x61)));
const ms2 = allOf(sig(K(0x62)));
const lockA = allOf(sig(K(1)), after(100));
const lockB = allOf(sig(K(1)), before(100));
const negN = [3, -1, []];
const createWith = (hash: string, h: number, script: unknown[], rs: string[], extra: Partial<{ ib: bigint; ih: bigint }> = {}) =>
  txIn({ hash, h, payload: buildPayload([ev.create(0, hashOf(script), null)], [script]), rs, ...extra });
const dupKeyPayload = concatBytes([
  hexToBytes('a4'), encode(0), encode(1), encode(1), encode([ev.create(0, C, null)]),
  encode(2), encode([chunk64(scriptBytes(ctrl))]), encode(1), encode([ev.create(0, C, null)]),
]);
const retireChain = [reg, openCreate(), join(T(2), 11)];

// Payload map {0: 1, 1: events, ...extra} built by hand, for bytes that
// encoders refuse (duplicate keys) or cannot produce (very deep nesting).
const rawPayload = (events: Uint8Array, extra: Uint8Array[] = [], pairs = 2 + extra.length / 2): Uint8Array =>
  concatBytes([new Uint8Array([0xa0 + pairs]), encode(0), encode(1), encode(1), events, ...extra]);
const rawArray = (items: Uint8Array[]): Uint8Array => concatBytes([new Uint8Array([0x80 + items.length]), ...items]);
const deepValue = (() => {
  const d = new Uint8Array(3000).fill(0x81); // 3000 nested arrays
  d[2999] = 0x80;
  return d;
})();
const scriptsEntry = [encode(2), encode([chunk64(scriptBytes(ctrl))])];
const dupUpdateMap = concatBytes([hexToBytes('a2'), encode(0), encode(kb(C)), encode(0), encode(kb(C))]);

export const VECTORS: VectorDef[] = [
  {
    name: 'open group: create, join, leave',
    inputs: [reg, openCreate(), join(T(2), 11), act('leave', T(2), T(3), 12, [M])],
    expect: { groups: [G(T(1))], instances: [I(T(2), 'closed', 'left')], verdicts: [V(T(1), true), V(T(2), true), V(T(3), true)] },
  },
  {
    name: 'permissioned group: pending, approve, remove',
    inputs: [reg, permCreate, join(T(2), 11), act('approve', T(2), T(3), 12, [K(2)]), act('remove', T(2), T(4), 13, [K(1)])],
    expect: {
      groups: [G(T(1), { mode: 'permissioned', admission: A })],
      instances: [I(T(2), 'closed', 'removed')],
      verdicts: [V(T(1), true), V(T(2), true), V(T(3), true), V(T(4), true)],
    },
  },
  {
    name: 'create needs every listed key, a group that was never created cannot be joined',
    inputs: [reg, openCreate([K(1), K(2)]), join(T(2), 11)],
    expect: { groups: [], instances: [], verdicts: [V(T(1), false, 'listed key did not sign'), V(T(2), false, 'unknown group')] },
  },
  {
    name: 'create below the threshold',
    inputs: [openCreate([K(1)])],
    expect: { groups: [], instances: [], verdicts: [V(T(1), false, 'control policy not satisfied')] },
  },
  {
    name: 'policy published after first use stays invalid',
    inputs: [
      txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(0, C, null)]), rs: ALL }),
      update(T(2), 11, 0, new Map(), ALL, [ctrl]),
    ],
    expect: { groups: [], instances: [], verdicts: [V(T(1), false, 'control policy unresolved'), V(T(2), false, 'unknown group')] },
  },
  {
    name: 'founder joins through a local ref, local refs to the same or a later index fail',
    inputs: [reg, txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(0, C, null), ev.join(local(0), 'key', M), ev.leave(local(2)), ev.leave(local(5))], [ctrl]), rs: [...ALL, M] })],
    expect: {
      groups: [G(T(1))],
      instances: [I(T(1), 'active', null, { index: 1 })],
      verdicts: [
        V(T(1), true, null, 0), V(T(1), true, null, 1),
        V(T(1), false, 'local reference must point to an earlier event', 2),
        V(T(1), false, 'local reference must point to an earlier event', 3),
      ],
    },
  },
  {
    name: 'empty update bumps seq, a stale seq is rejected',
    inputs: [openCreate(), update(T(2), 11, 0, new Map(), [K(1), K(3)]), dissolve(T(3), 12, 0, [K(1), K(2)])],
    expect: { groups: [G(T(1), { seq: '1' })], instances: [], verdicts: [V(T(1), true), V(T(2), true), V(T(3), false, 'stale seq')] },
  },
  {
    name: 'policy rotation needs consent of the new key, then the old keys lose control',
    inputs: [
      openCreate(),
      update(T(2), 11, 0, new Map([[0, kb(hashOf(newCtrl))]]), [K(1), K(2)], [newCtrl]),
      update(T(3), 12, 0, new Map([[0, kb(hashOf(newCtrl))]]), [K(1), K(2), K(4)]),
      update(T(4), 13, 1, new Map(), [K(1), K(2)]),
      update(T(5), 14, 1, new Map(), [K(4)]),
    ],
    expect: {
      groups: [G(T(1), { seq: '2', control: hashOf(newCtrl) })],
      instances: [],
      verdicts: [V(T(1), true), V(T(2), false, 'newly listed key did not sign'), V(T(3), true), V(T(4), false, 'control policy not satisfied'), V(T(5), true)],
    },
  },
  {
    name: 'certificates apply before events of the same transaction',
    inputs: [regIn(keyCred(K(0x51)), T(0x45), 6), openCreate(), regIn(keyCred(M), T(2), 11), join(T(2), 11), unregIn(keyCred(K(0x51)), T(3), 12), join(T(3), 12, K(0x51))],
    expect: { groups: [G(T(1))], instances: [I(T(2), 'active')], verdicts: [V(T(1), true), V(T(2), true), V(T(3), false, 'not a registered DRep')] },
  },
  {
    name: 'retirement closes for good, rejoin opens a new instance',
    inputs: [...retireChain, unregIn(keyCred(M), T(0x41), 12), regIn(keyCred(M), T(0x42), 13), join(T(3), 14)],
    expect: {
      groups: [G(T(1))],
      instances: [I(T(2), 'closed', 'retired'), I(T(3), 'active')],
      verdicts: [V(T(1), true), V(T(2), true), V(T(3), true)],
    },
  },
  {
    name: 'rollback: the same chain with the retirement rolled back',
    inputs: [...retireChain],
    expect: { groups: [G(T(1))], instances: [I(T(2), 'active')], verdicts: [V(T(1), true), V(T(2), true)] },
  },
  {
    name: 'retire, re-register and join inside one block',
    inputs: [reg, openCreate(), unregIn(keyCred(M), T(0x41), 20, 0), regIn(keyCred(M), T(0x42), 20, 1), join(T(2), 20, M, 2)],
    expect: { groups: [G(T(1))], instances: [I(T(2), 'active')], verdicts: [V(T(1), true), V(T(2), true)] },
  },
  {
    name: 'members: key only as witness rejected, script resolved from registration, script unresolved',
    inputs: [
      reg,
      regIn(scriptCred(hashOf(ms)), T(0x43), 6, 0, [scriptBytes(ms)]),
      regIn(scriptCred(hashOf(ms2)), T(0x44), 7),
      openCreate(),
      txIn({ hash: T(2), h: 11, payload: buildPayload([ev.join(ref(T(1), 0), 'key', M)]), wk: [M] }),
      txIn({ hash: T(3), h: 12, payload: buildPayload([ev.join(ref(T(1), 0), 'script', hashOf(ms))]), wk: [K(0x60), K(0x61)] }),
      txIn({ hash: T(4), h: 13, payload: buildPayload([ev.join(ref(T(1), 0), 'script', hashOf(ms2))]), wk: [K(0x62)] }),
    ],
    expect: {
      groups: [G(T(1))],
      instances: [I(T(3), 'active', null, { member: `script:${hashOf(ms)}` })],
      verdicts: [V(T(1), true), V(T(2), false, 'member key not in required_signers'), V(T(3), true), V(T(4), false, 'member script unresolved')],
    },
  },
  {
    name: 'leave, approve after leave, rejoin, dissolve closes, leave after dissolve',
    inputs: [
      reg, permCreate, join(T(2), 11), act('leave', T(2), T(3), 12, [M]), act('approve', T(2), T(4), 13, [K(1)]),
      join(T(5), 14), dissolve(T(6), 15, 0, [K(1), K(2)]), act('leave', T(5), T(7), 16, [M]),
    ],
    expect: {
      groups: [G(T(1), { mode: 'permissioned', admission: A, status: 'dissolved' })],
      instances: [I(T(2), 'closed', 'left'), I(T(5), 'closed', 'dissolved')],
      verdicts: [
        V(T(1), true), V(T(2), true), V(T(3), true), V(T(4), false, 'join is not pending'),
        V(T(5), true), V(T(6), true), V(T(7), false, 'join is not open'),
      ],
    },
  },
  {
    name: 'remove is not possible in an open group',
    inputs: [reg, openCreate(), join(T(2), 11), act('remove', T(2), T(3), 12, ALL)],
    expect: { groups: [G(T(1))], instances: [I(T(2), 'active')], verdicts: [V(T(1), true), V(T(2), true), V(T(3), false, 'open group has no remove')] },
  },
  {
    name: 'policy and consent satisfied by witnesses only',
    inputs: [txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(0, C, null)], [ctrl]), wk: ALL })],
    expect: { groups: [G(T(1))], instances: [], verdicts: [V(T(1), true)] },
  },
  {
    name: 'script forms: all [], any [], n_of_k 0, n above k, negative n',
    inputs: [
      createWith(T(1), 10, allOf(), []),
      createWith(T(2), 11, anyOf(), [K(1)]),
      createWith(T(3), 12, nOfK(0), []),
      createWith(T(4), 13, nOfK(3, sig(K(1)), sig(K(2))), [K(1), K(2)]),
      createWith(T(5), 14, negN, []),
    ],
    expect: {
      groups: [
        G(T(1), { control: hashOf(allOf()) }),
        G(T(3), { control: hashOf(nOfK(0)) }),
        G(T(5), { control: hashOf(negN) }),
      ],
      instances: [],
      verdicts: [V(T(1), true), V(T(2), false, 'control policy not satisfied'), V(T(3), true), V(T(4), false, 'control policy not satisfied'), V(T(5), true)],
    },
  },
  {
    name: 'time locks with and without interval bounds',
    inputs: [
      createWith(T(1), 10, lockA, [K(1)], { ib: 150n }),
      createWith(T(2), 11, lockA, [K(1)]),
      createWith(T(3), 12, lockB, [K(1)], { ih: 100n }),
      createWith(T(4), 13, lockB, [K(1)]),
    ],
    expect: {
      groups: [G(T(1), { control: hashOf(lockA) }), G(T(3), { control: hashOf(lockB) })],
      instances: [],
      verdicts: [V(T(1), true), V(T(2), false, 'control policy not satisfied'), V(T(3), true), V(T(4), false, 'control policy not satisfied')],
    },
  },
  {
    name: 'phase-2-invalid transaction, wrong version and duplicate map key are ignored',
    inputs: [
      txIn({ hash: T(1), h: 10, valid: false, payload: buildPayload([ev.create(0, C, null)], [ctrl]), rs: ALL }),
      txIn({ hash: T(2), h: 11, payload: buildPayload([ev.create(0, C, null)], [ctrl], 2), rs: ALL }),
      txIn({ hash: T(3), h: 12, payload: dupKeyPayload, rs: ALL }),
    ],
    expect: { groups: [], instances: [], verdicts: [] },
  },
  {
    name: 'decoding: malformed events keep their index',
    inputs: [
      txIn({
        hash: T(1), h: 10, rs: ALL,
        payload: buildPayload([
          ev.create(0, C, null),
          [3, 'junk'],
          [9, 1],
          [0, 0, kb(C), kb(C)],
          ev.update(local(0), 0, new Map<number, unknown>([[7, 1]])),
          ev.update(local(0), 0, new Map()),
          [3, [new Uint8Array(31), 0], [0, kb(M)]],
        ], [ctrl]),
      }),
    ],
    expect: {
      groups: [G(T(1), { seq: '1' })],
      instances: [],
      verdicts: [
        V(T(1), true, null, 0),
        V(T(1), false, 'join: bad shape', 1),
        V(T(1), false, 'unknown event tag', 2),
        V(T(1), false, 'create: open group must not have an admission policy', 3),
        V(T(1), false, 'update: bad shape', 4),
        V(T(1), true, null, 5),
        V(T(1), false, 'join: bad shape', 6),
      ],
    },
  },
  {
    name: 'policy and consent satisfied by required_signers and witnesses together',
    inputs: [txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(0, C, null)], [ctrl]), rs: [K(1)], wk: [K(2), K(3)] })],
    expect: { groups: [G(T(1))], instances: [], verdicts: [V(T(1), true)] },
  },
  {
    name: 'an unknown payload key with a deep value is ignored and the events count',
    inputs: [
      reg,
      txIn({ hash: T(1), h: 10, rs: ALL, payload: rawPayload(encode([ev.create(0, C, null)]), [...scriptsEntry, encode(9), deepValue]) }),
      join(T(2), 11),
    ],
    expect: { groups: [G(T(1))], instances: [I(T(2), 'active')], verdicts: [V(T(1), true), V(T(2), true)] },
  },
  {
    name: 'an admission change on an open group is invalid',
    inputs: [openCreate(), update(T(2), 11, 0, new Map([[1, kb(A)]]), ALL, [adm])],
    expect: { groups: [G(T(1))], instances: [], verdicts: [V(T(1), true), V(T(2), false, 'open group has no admission policy')] },
  },
  {
    name: 'a duplicate unknown key in the payload map ignores the whole payload',
    inputs: [
      reg,
      txIn({ hash: T(1), h: 10, rs: ALL, payload: rawPayload(encode([ev.create(0, C, null)]), [...scriptsEntry, encode(9), encode(1), encode(9), encode(2)]) }),
      join(T(2), 11),
    ],
    expect: { groups: [], instances: [], verdicts: [V(T(2), false, 'unknown group')] },
  },
  {
    name: 'a duplicate key in an update map invalidates only that event',
    inputs: [
      txIn({
        hash: T(1), h: 10, rs: ALL,
        payload: rawPayload(
          rawArray([
            encode(ev.create(0, C, null)),
            concatBytes([hexToBytes('84'), encode(1), encode(local(0)), encode(0), dupUpdateMap]),
            encode(ev.update(local(0), 0, new Map())),
          ]),
          scriptsEntry,
        ),
      }),
    ],
    expect: {
      groups: [G(T(1), { seq: '1' })],
      instances: [],
      verdicts: [V(T(1), true, null, 0), V(T(1), false, 'update: bad shape', 1), V(T(1), true, null, 2)],
    },
  },
  {
    name: 'script list: junk entries between valid scripts are skipped',
    inputs: [
      txIn({
        hash: T(1), h: 10, rs: ALL,
        payload: buildPayloadRaw([ev.create(1, C, A)], [chunk64(scriptBytes(adm)), ['text'], [new Uint8Array([0xff])], chunk64(scriptBytes(ctrl))]),
      }),
    ],
    expect: { groups: [G(T(1), { mode: 'permissioned', admission: A })], instances: [], verdicts: [V(T(1), true)] },
  },
];
