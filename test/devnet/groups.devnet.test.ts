// Devnet proof of the library's ledger assumptions (spec Part A). Every
// scenario builds real transactions, submits them to a local Conway devnet,
// reads their original bytes and positions back from the chain, and runs
// decodeTransaction and replay over everything the chain holds so far.
//
// Runs only through `npm run test:devnet` and needs Docker. There is no skip
// condition on purpose: without Docker the cluster start fails loudly instead
// of the suite passing with zero tests.
//
// The scenarios share one cluster and run in order, later ones build on the
// groups and DReps of earlier ones. Account 0 pays for every transaction,
// other keys of the test mnemonic only add witnesses.
import { blake2b } from '@noble/hashes/blake2.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  Bytes,
  KeyHash,
  NativeScripts,
  PrivateKey,
  ScriptHash,
  Time,
  Transaction,
  TransactionBody,
  TransactionHash,
  TransactionMetadatum,
  TransactionWitnessSet,
  VKey,
  Ed25519Signature,
  type UTxO,
} from '@evolution-sdk/evolution';
import { runSchedule, type ScheduleStep } from '../../src/conformance/index.js';
import { BIG_BUDGET } from '../../src/conformance/generate.js';
import { MemoryStore, type Budget } from '../../src/engine/index.js';
import { credKey } from '../../src/state.js';
import { arrayItemOffsets, itemEnd, mapEntryOffsets, readHead, readUint, skipTags } from '../../src/cborSpan.js';
import { nativeScriptHash } from '../../src/hash.js';
import {
  decodeTransaction, GROUPS_LABEL, replay,
  type ChainInput, type ChainTx, type Credential, type EventRef, type RegistryState,
} from '../../src/index.js';
import {
  after, allOf, before, buildPayload, buildPayloadRaw, ev, hashOf, local, nOfK, ref, scriptBytes, sig,
  type ScriptValue,
} from '../helpers.js';
import { errorText, startDevnet, testKey, type DevnetClient, type DevnetHandle, type TestKey } from './cluster.js';

const PAYER = 0;
/** Fee headroom for witnesses the builder cannot know about (unlisted keys). */
const FEE_PAD = 50_000;

// Payment keys of accounts 0 to 5 act as policy keys, role 3 keys as DRep keys.
const P = [0, 1, 2, 3, 4, 5].map((i) => testKey(i, 0));
const D0 = testKey(0, 3);
const D3 = testKey(3, 3);
const [P0, P1, P2, P3, P4, P5] = P as [TestKey, TestKey, TestKey, TestKey, TestKey, TestKey];

type Certs = 'regDrep' | 'unregDrep';
interface CertSpec { kind: Certs; credential: Credential; script?: ScriptValue }

interface SendOptions {
  payload?: Uint8Array;
  /** Listed in required_signers, and they sign. */
  listed?: TestKey[];
  /** Sign without being listed in required_signers. */
  unlisted?: TestKey[];
  /** invalid_before and invalid_hereafter as slots. */
  from?: bigint;
  to?: bigint;
  cert?: CertSpec;
}

interface Included {
  ok: true;
  hash: string;
  chain: ChainTx;
  cbor: Uint8Array;
}
type Outcome = Included | { ok: false; error: string };

/** Ledger findings collected for the report, printed at the end. */
const findings: string[] = [];
const note = (line: string) => {
  findings.push(line);
  console.log(`[devnet] ${line}`);
};

function vkeyWitness(k: TestKey, bodyHash: Uint8Array): TransactionWitnessSet.VKeyWitness {
  return new TransactionWitnessSet.VKeyWitness({ vkey: VKey.fromPrivateKey(k.key), signature: PrivateKey.sign(k.key, bodyHash) });
}

function uniqueKeys(keys: TestKey[]): TestKey[] {
  const seen = new Set<string>();
  return keys.filter((k) => (seen.has(k.hash) ? false : (seen.add(k.hash), true)));
}

// DRep certificates of a transaction, read from the chain bytes: body field 4,
// reg_drep_cert = [16, credential, coin, anchor / null], unreg_drep_cert = [17, credential, coin].
function drepCerts(cbor: Uint8Array): { kind: 'reg' | 'unreg'; credential: Credential; certIndex: number }[] {
  const [bodyOff] = arrayItemOffsets(cbor, 0);
  const body = skipTags(cbor, bodyOff!);
  let certsOff: number | undefined;
  for (const [k, v] of mapEntryOffsets(cbor, body)) if (readUint(cbor, k) === 4) certsOff = v;
  if (certsOff === undefined) return [];
  const list = skipTags(cbor, certsOff);
  const out: { kind: 'reg' | 'unreg'; credential: Credential; certIndex: number }[] = [];
  arrayItemOffsets(cbor, list).forEach((certOff, certIndex) => {
    const [tagOff, credOff] = arrayItemOffsets(cbor, certOff);
    const tag = readUint(cbor, tagOff!);
    if (tag !== 16 && tag !== 17) return;
    const [kindOff, hashOff] = arrayItemOffsets(cbor, credOff!);
    const h = readHead(cbor, hashOff!);
    out.push({
      kind: tag === 16 ? 'reg' : 'unreg',
      credential: { kind: readUint(cbor, kindOff!) === 0 ? 'key' : 'script', hash: Bytes.toHex(cbor.slice(h.next, h.next + Number(h.big))) },
      certIndex,
    });
  });
  return out;
}

function indexOf(hay: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

describe('DRep groups on a devnet', () => {
  let devnet: DevnetHandle | undefined;
  let payer: DevnetClient;
  let payerAddress: Awaited<ReturnType<DevnetClient['address']>>;
  let genesisSpent = false;
  /** Every ledger input and transaction the chain holds, in the order seen. */
  const inputs: ChainInput[] = [];

  const dev = () => {
    if (!devnet) throw new Error('Devnet not started.');
    return devnet;
  };
  const state = (): RegistryState => replay(inputs);
  const verdict = (txHash: string, index: number) =>
    state().verdicts.find((v) => v.ref.txHash === txHash && v.ref.index === index);
  const group = (id: EventRef) => state().groups.find((g) => g.id.txHash === id.txHash && g.id.index === id.index);
  const instance = (id: EventRef) =>
    state().instances.find((i) => i.joinId.txHash === id.txHash && i.joinId.index === id.index);
  const heightOf = (x: ChainInput): number => (x.kind === 'tx' ? x.tx.blockHeight : x.input.blockHeight);

  /**
   * Runs the chain inputs collected so far through the incremental engine over a
   * MemoryStore and compares the result with replay. runSchedule ends with the
   * comparison and the quiescence checks, a mismatch throws with a diff. Twice:
   * everything at once with a big budget, then one input at a time with a run of
   * budget 1 after each and the frontiers at the delivered height.
   */
  async function checkEngine(): Promise<void> {
    const started = Date.now();
    const chain = [...inputs];
    const tip = chain.reduce((h, x) => Math.max(h, heightOf(x)), -1);
    const credentials = new Map<string, Credential>();
    for (const x of chain) if (x.kind === 'ledger') credentials.set(credKey(x.input.credential), x.input.credential);
    for (const i of replay(chain).instances) credentials.set(credKey(i.member), i.member);
    const complete: ScheduleStep[] = [...credentials.values()].map((c) => ({ kind: 'complete', c, complete: true }));

    await runSchedule(() => new MemoryStore(), chain, [
      { kind: 'deliver', inputs: chain }, { kind: 'frontiers', L: tip, R: tip }, ...complete, { kind: 'run', budget: BIG_BUDGET },
    ]);

    const one: Budget = { controlTxs: 1, controlBytes: 1, credentialUnits: 1, credentialInputs: 1, truncateRows: 1, resetRows: 1 };
    const steps: ScheduleStep[] = [...complete];
    chain.forEach((x, i) => {
      steps.push({ kind: 'deliver', inputs: [x] });
      // The ledger rows of a transaction come right before the transaction at the
      // same height, the frontiers pass a height only once all of it is delivered.
      const next = chain[i + 1];
      if (next === undefined || heightOf(next) > heightOf(x)) steps.push({ kind: 'frontiers', L: heightOf(x), R: heightOf(x) });
      steps.push({ kind: 'run', budget: one });
    });
    await runSchedule(() => new MemoryStore(), chain, steps);
    console.log(`[devnet] engine equals replay over ${chain.length} inputs, at once and one input at a time (${Date.now() - started} ms)`);
  }

  const slotUnix = (slot: bigint) => Time.slotToUnixTime(slot, dev().slotConfig);

  async function currentSlot(): Promise<bigint> {
    const tip = await dev().ogmios<{ slot: number }>('queryNetwork/tip');
    return BigInt(tip.slot);
  }

  async function paddedParams() {
    const pp = await payer.getProtocolParameters();
    return { ...pp, minFeeB: pp.minFeeB + FEE_PAD };
  }

  /** Submits raw transaction bytes through Ogmios, the error comes back unshortened. */
  async function submitRaw(cbor: Uint8Array): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
    try {
      const r = await dev().ogmios<{ transaction: { id: string } }>('submitTransaction', { transaction: { cbor: Bytes.toHex(cbor) } });
      return { ok: true, id: r.transaction.id };
    } catch (err) {
      return { ok: false, error: errorText(err) };
    }
  }

  /**
   * Waits for the transaction on chain, checks the chain holds exactly the
   * submitted bytes, waits for Kupo to show the change, and records the
   * transaction and its DRep certificates as replay inputs.
   */
  async function include(label: string, id: string, submitted: Uint8Array, cert?: CertSpec, payload?: Uint8Array): Promise<Included> {
    const entry = await dev().onChain(id);
    expect(Bytes.toHex(entry.cbor), `${label}: chain bytes equal the submitted bytes`).toBe(Bytes.toHex(submitted));
    genesisSpent = true;
    await dev().waitFor(`${label} (${id}) change in Kupo`, async () => {
      const utxos = await payer.getUtxos(payerAddress);
      return utxos.some((u: UTxO.UTxO) => TransactionHash.toHex(u.transactionId) === id) ? true : null;
    });
    const chain = decodeTransaction(entry.cbor, { txHash: id, blockHeight: entry.blockHeight, txIndex: entry.txIndex });
    expect(chain.isValid).toBe(true);
    if (payload) expect(Bytes.toHex(chain.payload ?? new Uint8Array()), `${label}: payload read back`).toBe(Bytes.toHex(payload));
    if (cert) {
      for (const c of drepCerts(entry.cbor)) {
        inputs.push({
          kind: 'ledger',
          input: {
            kind: c.kind, credential: c.credential, txHash: id, blockHeight: entry.blockHeight, txIndex: entry.txIndex,
            certIndex: c.certIndex, ...(c.kind === 'reg' && c.credential.kind === 'script' ? { witnessScripts: chain.witnessScripts } : {}),
          },
        });
      }
    }
    inputs.push({ kind: 'tx', tx: chain });
    console.log(`[devnet] ${label}: ${id} at block ${entry.blockHeight} index ${entry.txIndex}`);
    return { ok: true, hash: id, chain, cbor: entry.cbor };
  }

  /** Builds with the SDK, signs with the listed and unlisted keys plus the payer, submits and reads back. */
  async function send(label: string, o: SendOptions): Promise<Outcome> {
    const listed = o.listed ?? [];
    const unlisted = o.unlisted ?? [];
    let txb = payer.newTx();
    if (o.payload) {
      txb = txb.attachMetadata({ label: BigInt(GROUPS_LABEL), metadata: TransactionMetadatum.fromCBORBytes(o.payload) });
    }
    for (const k of listed) txb = txb.addSigner({ keyHash: KeyHash.fromHex(k.hash) });
    if (o.from !== undefined || o.to !== undefined) {
      txb = txb.setValidity({
        ...(o.from !== undefined ? { from: slotUnix(o.from) } : {}),
        ...(o.to !== undefined ? { to: slotUnix(o.to) } : {}),
      });
    }
    if (o.cert?.kind === 'regDrep' || o.cert?.kind === 'unregDrep') {
      const c = o.cert.credential;
      const credential = c.kind === 'key' ? KeyHash.fromHex(c.hash) : ScriptHash.fromHex(c.hash);
      txb = o.cert.kind === 'regDrep' ? txb.registerDRep({ drepCredential: credential }) : txb.deregisterDRep({ drepCredential: credential });
      if (o.cert.script) txb = txb.attachScript({ script: NativeScripts.fromCBORBytes(scriptBytes(o.cert.script)) });
    }
    const built = await txb
      .build({
        ...(genesisSpent ? {} : { availableUtxos: [dev().genesisUtxo(PAYER)] }),
        ...(unlisted.length > 0 || o.cert ? { fullProtocolParameters: await paddedParams() } : {}),
      })
      .catch((err: unknown) => {
        throw new Error(`${label}: build failed: ${errorText(err)}`);
      });
    const unsigned = await built.toTransaction();
    const bodyHash = TransactionBody.toHash(unsigned.body).hash;
    const signers = uniqueKeys([P[PAYER]!, ...listed, ...unlisted]);
    const assembled = await built.assemble([TransactionWitnessSet.fromVKeyWitnesses(signers.map((k) => vkeyWitness(k, bodyHash)))]);
    const signed = new Transaction.Transaction({
      body: unsigned.body,
      witnessSet: assembled.witnessSet,
      isValid: true,
      auxiliaryData: unsigned.auxiliaryData,
    });
    const cbor = Transaction.toCBORBytes(signed);
    const submitted = await submitRaw(cbor);
    if (!submitted.ok) return submitted;
    expect(submitted.id).toBe(Bytes.toHex(bodyHash));
    return include(label, submitted.id, cbor, o.cert, o.payload);
  }

  async function mustInclude(label: string, o: SendOptions): Promise<Included> {
    const r = await send(label, o);
    if (!r.ok) throw new Error(`${label}: ledger rejected: ${r.error}`);
    return r;
  }

  beforeAll(async () => {
    const started = Date.now();
    devnet = await startDevnet('drep-groups-devnet');
    console.log(`[devnet] cluster up in ${Date.now() - started} ms`);
    payer = devnet.client(PAYER);
    payerAddress = await payer.address();
    // The derived payment keys are the ones behind the funded addresses.
    for (const i of [0, 1, 2, 3, 4, 5]) {
      const address = await devnet.client(i).address();
      expect(KeyHash.toHex(address.paymentCredential as KeyHash.KeyHash)).toBe(P[i]!.hash);
    }
  });

  afterAll(async () => {
    console.log(`[devnet] findings:\n${findings.map((f) => `  - ${f}`).join('\n')}`);
    await devnet?.stop();
  }, 120_000);

  // Shared across scenarios.
  const control1 = nOfK(2, sig(P0.hash), sig(P1.hash), sig(P2.hash));
  let group1: EventRef;
  let founderJoin: EventRef;

  it('1: a 2 of 3 group whose founder DRep joins in the same transaction', async () => {
    await mustInclude('reg_drep D0', { cert: { kind: 'regDrep', credential: { kind: 'key', hash: D0.hash } }, listed: [D0] });
    const payload = buildPayload([ev.create(0, hashOf(control1), null), ev.join(local(0), 'key', D0.hash)], [control1]);
    expect(scriptBytes(control1).length).toBeGreaterThan(64); // key 2 travels in more than one chunk
    const tx = await mustInclude('create + join', { payload, listed: [P0, P1, P2, D0] });
    expect(Bytes.toHex(tx.chain.payload!)).toBe(Bytes.toHex(payload));
    expect(new Set(tx.chain.requiredSigners)).toEqual(new Set([P0.hash, P1.hash, P2.hash, D0.hash]));

    group1 = { txHash: tx.hash, index: 0 };
    founderJoin = { txHash: tx.hash, index: 1 };
    expect(verdict(tx.hash, 0)).toMatchObject({ tag: 'create', valid: true, reason: null });
    expect(verdict(tx.hash, 1)).toMatchObject({ tag: 'join', valid: true, reason: null });
    expect(group(group1)).toMatchObject({ mode: 'open', control: hashOf(control1), admission: null, seq: 0n, status: 'active' });
    expect(instance(founderJoin)).toMatchObject({ member: { kind: 'key', hash: D0.hash }, state: 'active', group: group1 });
    expect(state().scripts.has(hashOf(control1))).toBe(true);
    note(`S1 accepted: nested event arrays, a local ref [0] and a ${scriptBytes(control1).length} byte script in 64 byte chunks under label ${GROUPS_LABEL}, bytes read back unchanged`);
    await checkEngine();
  });

  it('2: a create signed by only 2 of the 3 listed keys is valid for the ledger, invalid for the library', async () => {
    const payload = buildPayload([ev.create(0, hashOf(control1), null)]);
    const tx = await mustInclude('create 2 of 3 signed', { payload, listed: [P0, P1] });
    expect(new Set(tx.chain.witnessKeyHashes)).toEqual(new Set([P0.hash, P1.hash]));
    expect(verdict(tx.hash, 0)).toMatchObject({ tag: 'create', valid: false, reason: 'listed key did not sign' });
    expect(group({ txHash: tx.hash, index: 0 })).toBeUndefined();
    note('S2 accepted by the ledger, library verdict "listed key did not sign"');
    await checkEngine();
  });

  it('3: a DRep key in required_signers of a metadata-only transaction, join then leave', async () => {
    await mustInclude('reg_drep D3', { cert: { kind: 'regDrep', credential: { kind: 'key', hash: D3.hash } }, listed: [D3] });

    // The DRep key only witnesses without being listed: a key member must be listed.
    const unlistedJoin = await send('join D3 unlisted', { payload: buildPayload([ev.join(ref(group1.txHash, 0), 'key', D3.hash)]), unlisted: [D3] });
    if (unlistedJoin.ok) {
      expect(unlistedJoin.chain.witnessKeyHashes).toContain(D3.hash);
      expect(unlistedJoin.chain.requiredSigners).not.toContain(D3.hash);
      expect(verdict(unlistedJoin.hash, 0)).toMatchObject({ valid: false, reason: 'member key not in required_signers' });
      note('S3 a join witnessed by the DRep key but not listed: ledger accepted, library verdict "member key not in required_signers"');
    } else note(`S3 a join witnessed by the DRep key but not listed: ledger rejected: ${unlistedJoin.error}`);

    const join = await mustInclude('join D3', { payload: buildPayload([ev.join(ref(group1.txHash, 0), 'key', D3.hash)]), listed: [D3] });
    expect(join.chain.requiredSigners).toEqual([D3.hash]);
    expect(join.chain.witnessKeyHashes).toContain(D3.hash);
    const joinId = { txHash: join.hash, index: 0 };
    expect(verdict(join.hash, 0)).toMatchObject({ tag: 'join', valid: true });
    expect(instance(joinId)).toMatchObject({ state: 'active', member: { kind: 'key', hash: D3.hash } });

    const leave = await mustInclude('leave D3', { payload: buildPayload([ev.leave(ref(join.hash, 0))]), listed: [D3] });
    expect(verdict(leave.hash, 0)).toMatchObject({ tag: 'leave', valid: true });
    expect(instance(joinId)).toMatchObject({ state: 'closed', reason: 'left', closedAt: { txHash: leave.hash } });
    note('S3 accepted: a CIP-105 DRep key (role 3, owns no input) as the only required signer of a metadata-only transaction, join and leave valid');
    await checkEngine();
  });

  it('4: a policy key that witnesses without being in required_signers', async () => {
    const control = allOf(sig(P1.hash), sig(P2.hash));
    const payload = buildPayload([ev.create(0, hashOf(control), null)], [control]);
    const r = await send('create with unlisted witness', { payload, listed: [P1], unlisted: [P2] });
    if (!r.ok) {
      note(`S4 REJECTED by the ledger, this contradicts spec A3: ${r.error}`);
      throw new Error(`ledger rejected an extra vkey witness: ${r.error}`);
    }
    expect(r.chain.requiredSigners).toEqual([P1.hash]);
    expect(r.chain.witnessKeyHashes).toContain(P2.hash);
    expect(verdict(r.hash, 0)).toMatchObject({ tag: 'create', valid: true, reason: null });
    expect(group({ txHash: r.hash, index: 0 })).toMatchObject({ control: hashOf(control), status: 'active' });
    note('S4 accepted: the ledger takes a vkey witness of a key that is in neither required_signers nor any input, the library counts it (union signer set)');
    await checkEngine();
  });

  it('5: a permissioned group, join pending, approve with 1 of 2, remove', async () => {
    const control = sig(P0.hash);
    const admission = nOfK(1, sig(P1.hash), sig(P2.hash));
    const create = await mustInclude('permissioned create', {
      payload: buildPayload([ev.create(1, hashOf(control), hashOf(admission))], [control, admission]),
      listed: [P0, P1, P2],
    });
    const g = { txHash: create.hash, index: 0 };
    expect(group(g)).toMatchObject({ mode: 'permissioned', admission: hashOf(admission), status: 'active' });

    const join = await mustInclude('permissioned join', { payload: buildPayload([ev.join(ref(g.txHash, 0), 'key', D3.hash)]), listed: [D3] });
    const joinId = { txHash: join.hash, index: 0 };
    expect(instance(joinId)).toMatchObject({ state: 'pending' });

    const approve = await mustInclude('approve', { payload: buildPayload([ev.approve(ref(join.hash, 0))]), listed: [P1] });
    expect(verdict(approve.hash, 0)).toMatchObject({ tag: 'approve', valid: true });
    expect(instance(joinId)).toMatchObject({ state: 'active', approvedAt: { txHash: approve.hash } });

    const remove = await mustInclude('remove', { payload: buildPayload([ev.remove(ref(join.hash, 0))]), listed: [P2] });
    expect(verdict(remove.hash, 0)).toMatchObject({ tag: 'remove', valid: true });
    expect(instance(joinId)).toMatchObject({ state: 'closed', reason: 'removed', closedAt: { txHash: remove.hash } });
    note('S5 accepted: permissioned create, join pending, approve by 1 of 2, remove, all valid');
    await checkEngine();
  });

  it('6: a script DRep joins, its script resolved from the reg_drep witness set', async () => {
    const script = allOf(sig(P4.hash), sig(P5.hash));
    const bytes = scriptBytes(script);
    // The SDK must carry the script bytes unchanged, or the credential hash would not match the witness.
    expect(Bytes.toHex(NativeScripts.toCBORBytes(NativeScripts.fromCBORBytes(bytes)))).toBe(Bytes.toHex(bytes));
    const h = hashOf(script);
    const reg = await mustInclude('reg_drep script', { cert: { kind: 'regDrep', credential: { kind: 'script', hash: h }, script }, unlisted: [P4, P5] });
    expect(reg.chain.witnessScripts.map((s) => nativeScriptHash(s))).toContain(h);
    const regInput = inputs.find((x) => x.kind === 'ledger' && x.input.txHash === reg.hash);
    expect(regInput).toMatchObject({ kind: 'ledger', input: { kind: 'reg', credential: { kind: 'script', hash: h } } });

    const join = await mustInclude('script join', { payload: buildPayload([ev.join(ref(group1.txHash, 0), 'script', h)]), listed: [P4, P5] });
    expect(join.chain.witnessScripts).toEqual([]);
    expect(verdict(join.hash, 0)).toMatchObject({ tag: 'join', valid: true, reason: null });
    expect(instance({ txHash: join.hash, index: 0 })).toMatchObject({ state: 'active', member: { kind: 'script', hash: h } });
    expect(state().scripts.has(h)).toBe(false); // resolved through the reg_drep witness set, not key 2
    note('S6 accepted: reg_drep of a native script credential carries the script in witness field 1, decodeTransaction reads it, the join without key 2 is valid');
    await checkEngine();
  });

  it('7: a control policy rotation that adds a key, then the old keys alone cannot update', async () => {
    const control2 = allOf(sig(P3.hash), control1);
    const rotate = await mustInclude('rotate', {
      payload: buildPayload([ev.update(ref(group1.txHash, 0), 0, new Map([[0, Bytes.fromHex(hashOf(control2))]]))], [control2]),
      listed: [P0, P1, P3],
    });
    expect(verdict(rotate.hash, 0)).toMatchObject({ tag: 'update', valid: true, reason: null });
    expect(group(group1)).toMatchObject({ control: hashOf(control2), seq: 1n });

    const stale = await mustInclude('stale seq update', { payload: buildPayload([ev.update(ref(group1.txHash, 0), 0, new Map())]), listed: [P0, P1, P3] });
    expect(verdict(stale.hash, 0)).toMatchObject({ valid: false, reason: 'stale seq' });
    const oldKeys = await mustInclude('old keys update', { payload: buildPayload([ev.update(ref(group1.txHash, 0), 1, new Map())]), listed: [P0, P1, P2] });
    expect(verdict(oldKeys.hash, 0)).toMatchObject({ valid: false, reason: 'control policy not satisfied' });
    expect(group(group1)).toMatchObject({ seq: 1n });
    note('S7 accepted: rotation valid with seq 1, a stale seq and an update by the old keys alone are invalid for the library');
    await checkEngine();
  });

  it('8: unreg_drep closes the membership as retired, a new join after re-registration opens a new instance', async () => {
    const unreg = await mustInclude('unreg_drep D0', { cert: { kind: 'unregDrep', credential: { kind: 'key', hash: D0.hash } }, listed: [D0] });
    expect(instance(founderJoin)).toMatchObject({ state: 'closed', reason: 'retired', closedAt: { txHash: unreg.hash } });

    const early = await mustInclude('join while retired', { payload: buildPayload([ev.join(ref(group1.txHash, 0), 'key', D0.hash)]), listed: [D0] });
    expect(verdict(early.hash, 0)).toMatchObject({ valid: false, reason: 'not a registered DRep' });

    await mustInclude('reg_drep D0 again', { cert: { kind: 'regDrep', credential: { kind: 'key', hash: D0.hash } }, listed: [D0] });
    expect(instance(founderJoin)).toMatchObject({ state: 'closed', reason: 'retired' });
    const rejoin = await mustInclude('rejoin D0', { payload: buildPayload([ev.join(ref(group1.txHash, 0), 'key', D0.hash)]), listed: [D0] });
    expect(instance({ txHash: rejoin.hash, index: 0 })).toMatchObject({ state: 'active', member: { kind: 'key', hash: D0.hash } });
    expect(instance(founderJoin)).toMatchObject({ state: 'closed', reason: 'retired' });
    note('S8 accepted: unreg_drep closes with reason retired, a join while unregistered is invalid, re-registration plus a new join opens a new active instance');
    await checkEngine();
  });

  it('9: time locks against real validity intervals', async () => {
    const s = (await currentSlot()) - 5n;
    const lockAfter = allOf(sig(P0.hash), after(Number(s)));
    const createAfter = buildPayload([ev.create(0, hashOf(lockAfter), null)], [lockAfter]);

    const atS = await mustInclude('after: invalid_before = S', { payload: createAfter, from: s });
    expect(atS.chain.invalidBefore).toBe(s);
    expect(verdict(atS.hash, 0)).toMatchObject({ valid: true });
    const noStart = await mustInclude('after: no validity start', { payload: createAfter });
    expect(noStart.chain.invalidBefore).toBeNull();
    expect(verdict(noStart.hash, 0)).toMatchObject({ valid: false, reason: 'control policy not satisfied' });
    const early = await mustInclude('after: invalid_before = S - 1', { payload: createAfter, from: s - 1n });
    expect(early.chain.invalidBefore).toBe(s - 1n);
    expect(verdict(early.hash, 0)).toMatchObject({ valid: false, reason: 'control policy not satisfied' });

    const t = (await currentSlot()) + 3000n; // one minute ahead at 20 ms slots
    const lockBefore = allOf(sig(P0.hash), before(Number(t)));
    const createBefore = buildPayload([ev.create(0, hashOf(lockBefore), null)], [lockBefore]);
    const atT = await mustInclude('before: invalid_hereafter = T', { payload: createBefore, to: t });
    expect(atT.chain.invalidHereafter).toBe(t);
    expect(verdict(atT.hash, 0)).toMatchObject({ valid: true });
    const late = await mustInclude('before: invalid_hereafter = T + 1', { payload: createBefore, to: t + 1n });
    expect(late.chain.invalidHereafter).toBe(t + 1n);
    expect(verdict(late.hash, 0)).toMatchObject({ valid: false, reason: 'control policy not satisfied' });
    const noEnd = await mustInclude('before: no ttl', { payload: createBefore });
    expect(noEnd.chain.invalidHereafter).toBeNull();
    expect(verdict(noEnd.hash, 0)).toMatchObject({ valid: false, reason: 'control policy not satisfied' });
    note(`S9 accepted all six: after ${s} valid only with invalid_before >= ${s}, before ${t} valid only with invalid_hereafter <= ${t}`);
    await checkEngine();
  });

  it('10: ledger limits on metadata', async () => {
    const control = sig(P0.hash);
    const inputCount = inputs.length;

    const bytes65 = buildPayloadRaw([ev.create(0, hashOf(control), null)], [[new Uint8Array(65)]]);
    const r1 = await send('65 byte chunk', { payload: bytes65 });
    if (r1.ok) note(`S10 a 65 byte byte string was ACCEPTED by the ledger (${r1.hash})`);
    else note(`S10 a 65 byte byte string in the payload: ledger rejected: ${r1.error}`);
    expect(r1.ok).toBe(false);

    const text65 = buildPayload([ev.create(0, hashOf(control), null, { url: `https://${'a'.repeat(57)}`, hash: '00'.repeat(32) })], [control]);
    const r2 = await send('65 byte text', { payload: text65 });
    if (r2.ok) note(`S10 a 65 byte text string was ACCEPTED by the ledger (${r2.hash})`);
    else note(`S10 a 65 byte text string in the payload: ledger rejected: ${r2.error}`);
    expect(r2.ok).toBe(false);
    expect(inputs.length).toBe(inputCount);

    // 3000 nested arrays under the unknown payload key 9, next to a valid create.
    // The SDK's recursive CBOR codec stops near 1000 levels, so the SDK builds
    // the transaction around a placeholder of the same length, and the deep
    // value replaces it in the auxiliary data. The auxiliary data hash in the
    // body is patched, the payer signs the patched body.
    const head = buildPayload([ev.create(0, hashOf(control), null)], [control]);
    const tail = (value: Uint8Array) => concat(new Uint8Array([head[0]! + 1]), head.subarray(1), new Uint8Array([0x09]), value);
    const deepValue = concat(new Uint8Array(3000).fill(0x81), new Uint8Array([0x00]));
    const placeholderValue = concat(new Uint8Array([0x59, 0x0b, 0xb6]), new Uint8Array(2998).fill(0xee));
    expect(placeholderValue.length).toBe(deepValue.length);
    const deep = tail(deepValue);
    const placeholder = tail(placeholderValue);

    const built = await payer
      .newTx()
      .attachMetadata({ label: BigInt(GROUPS_LABEL), metadata: TransactionMetadatum.fromCBORBytes(placeholder) })
      .build({ fullProtocolParameters: await paddedParams() });
    const unsignedBytes = Transaction.toCBORBytes(await built.toTransaction());
    const [bodyOff, , , auxOff] = arrayItemOffsets(unsignedBytes, 0) as [number, number, number, number];
    const body = unsignedBytes.slice(bodyOff, itemEnd(unsignedBytes, bodyOff));
    const aux = unsignedBytes.slice(auxOff, itemEnd(unsignedBytes, auxOff));
    const at = indexOf(aux, placeholder);
    expect(at).toBeGreaterThan(0);
    const newAux = concat(aux.subarray(0, at), deep, aux.subarray(at + placeholder.length));
    const oldHash = concat(new Uint8Array([0x58, 0x20]), blake2b(aux, { dkLen: 32 }));
    const hashAt = indexOf(body, oldHash);
    expect(hashAt).toBeGreaterThan(0);
    const newBody = concat(body.subarray(0, hashAt + 2), blake2b(newAux, { dkLen: 32 }), body.subarray(hashAt + oldHash.length));
    const txId = blake2b(newBody, { dkLen: 32 });
    const w = vkeyWitness(P0, txId);
    const witnesses = concat(
      new Uint8Array([0xa1, 0x00, 0xd9, 0x01, 0x02, 0x81, 0x82, 0x58, 0x20]), VKey.toBytes(w.vkey),
      new Uint8Array([0x58, 0x40]), Ed25519Signature.toBytes(w.signature),
    );
    const tx = concat(new Uint8Array([0x84]), newBody, witnesses, new Uint8Array([0xf5]), newAux);
    const r3 = await submitRaw(tx);
    if (!r3.ok) {
      note(`S10 3000 nested arrays under an unknown payload key: ledger rejected: ${r3.error}`);
      throw new Error(r3.error);
    }
    expect(r3.id).toBe(Bytes.toHex(txId));
    const deepTx = await include('3000 nested arrays', r3.id, tx, undefined, deep);
    expect(Bytes.toHex(deepTx.chain.payload!)).toBe(Bytes.toHex(deep));
    expect(verdict(deepTx.hash, 0)).toMatchObject({ tag: 'create', valid: true, reason: null });
    expect(group({ txHash: deepTx.hash, index: 0 })).toMatchObject({ status: 'active' });
    note(`S10 3000 nested arrays under unknown payload key 9 (tx ${tx.length} bytes): ledger accepted, the library decodes the payload and the create next to it is valid`);
    await checkEngine();
  });
});
