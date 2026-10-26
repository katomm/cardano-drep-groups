// Seeded generators for the differential test of the incremental engine: random chains
// with the hostile shapes of the protocol, and random delivery and run schedules over them.
// The only randomness is the xorshift generator of rng.ts, so a seed reproduces its chain and
// its schedule exactly.
import type { Budget } from '../engine/types.js';
import { nativeScriptHash } from '../hash.js';
import { hexToBytes } from '../hex.js';
import { credKey } from '../state.js';
import { type Cbor, encodeCbor } from './cbor.js';
import { Rng } from './rng.js';
import type { ChainInput, ChainTx, Credential, EventRef, Hex, LedgerInput } from '../types.js';

// Native script values in their CBOR array form.
const sigS = (k: Hex): Cbor => [0, hexToBytes(k)];
const allS = (...s: Cbor[]): Cbor => [1, s];
const anyS = (...s: Cbor[]): Cbor => [2, s];
const nOfKS = (n: number, ...s: Cbor[]): Cbor => [3, n, s];
const afterS = (slot: number): Cbor => [4, slot];
const beforeS = (slot: number): Cbor => [5, slot];

const chunk64 = (b: Uint8Array): Cbor[] => {
  const out: Cbor[] = [];
  for (let i = 0; i < b.length; i += 64) out.push(b.subarray(i, i + 64));
  return out;
};

// A policy or member script: its bytes, its hash, the keys it lists and the keys that
// satisfy it under the default validity interval of a tx.
interface Script { bytes: Uint8Array; hash: Hex; listed: Hex[]; satisfy: Hex[] }
const script = (value: Cbor, listed: Hex[], satisfy: Hex[]): Script => {
  const bytes = encodeCbor(value);
  return { bytes, hash: nativeScriptHash(bytes), listed, satisfy };
};

// Validity interval that satisfies every time lock the generator writes.
const SLOT_AFTER = 100;
const SLOT_BEFORE = 5000;
const IB = 200n;
const IH = 4000n;

const keyHash = (n: number): Hex => n.toString(16).padStart(2, '0').repeat(28);

interface MGroup { ref: EventRef; mode: 'open' | 'permissioned'; control: Script; admission: Script | null; seq: bigint; dissolved: boolean }
interface MMember { cred: Credential; script: Script | null; registered: boolean; witnessKnown: boolean }
interface MJoin { ref: EventRef; group: MGroup; member: MMember; state: 'pending' | 'active' | 'closed' }

// One label tx under construction. Events are added in index order and the model is
// updated at once, so later events of the same tx see earlier ones as replay does.
interface Draft {
  pos: { txHash: Hex; blockHeight: number; txIndex: number };
  events: Cbor[];
  scripts: Script[];
  rawEntries: Cbor[] | null; // key 2 as is, for the limit shapes
  rs: Set<Hex>;
  wk: Set<Hex>;
  validity: boolean;
  ignored: boolean;          // phase 2 invalid or label repeated, the model is not updated
  invalid: boolean;
  repeated: boolean;
}

export interface ChainOptions { txs?: number; credentials?: number; groups?: number }

class ChainBuilder {
  readonly rng: Rng;
  readonly out: ChainInput[] = [];
  private counter = 0;
  private height = 0;
  private txIndex = 0;
  private readonly policies: Script[] = [];
  private readonly published = new Set<Hex>();
  private readonly members: MMember[] = [];
  private readonly groups: MGroup[] = [];
  private readonly joins: MJoin[] = [];
  private readonly maxGroups: number;
  private readonly hashBase: string;

  constructor(seed: number, private readonly opts: Required<ChainOptions>) {
    this.rng = new Rng(seed);
    this.maxGroups = opts.groups;
    this.hashBase = (seed >>> 0).toString(16).padStart(8, '0');
    const keys = Array.from({ length: 12 }, (_, i) => keyHash(i + 1));
    const k = (): Hex => this.rng.pick(keys);
    const two = (): [Hex, Hex] => {
      const a = k();
      let b = k();
      while (b === a) b = k();
      return [a, b];
    };
    // Policies: single keys, thresholds, alternatives and time locks.
    for (let i = 0; i < 10; i++) {
      const [a, b] = two();
      let c = k();
      while (c === a || c === b) c = k();
      const p = this.rng.weighted<() => Script>([
        [3, () => script(sigS(a), [a], [a])],
        [2, () => script(anyS(sigS(a), sigS(b)), [a, b], [a])],
        [2, () => script(nOfKS(2, sigS(a), sigS(b), sigS(c)), [a, b, c], [a, b])],
        [1, () => script(allS(sigS(a), afterS(SLOT_AFTER)), [a], [a])],
        [1, () => script(allS(sigS(a), beforeS(SLOT_BEFORE)), [a], [a])],
      ])();
      if (!this.policies.some((x) => x.hash === p.hash)) this.policies.push(p);
    }
    // Members: key credentials and script credentials.
    for (let i = 0; i < opts.credentials; i++) {
      const own = keyHash(0x21 + i);
      if (this.rng.chance(0.65)) {
        this.members.push({ cred: { kind: 'key', hash: own }, script: null, registered: false, witnessKnown: false });
        continue;
      }
      const other = keyHash(this.rng.range(1, 12));
      const s = this.rng.weighted<() => Script>([
        [3, () => script(sigS(own), [own], [own])],
        [1, () => script(anyS(sigS(own), sigS(other)), [own, other], [own])],
        [1, () => script(allS(sigS(own), afterS(SLOT_AFTER)), [own], [own])],
      ])();
      this.members.push({ cred: { kind: 'script', hash: s.hash }, script: s, registered: false, witnessKnown: false });
    }
  }

  private txHash(n: number): Hex {
    return `${this.hashBase}${n.toString(16).padStart(8, '0')}`.repeat(4);
  }

  // A tx hash some later tx of the chain will carry, or one never used.
  private laterHash(): Hex {
    return this.txHash(this.counter + this.rng.range(0, 6));
  }

  private unusedHash(): Hex {
    return `ff${this.hashBase}${this.rng.int(1 << 30).toString(16).padStart(8, '0')}`.padEnd(64, 'e');
  }

  private nextPos(): { txHash: Hex; blockHeight: number; txIndex: number } {
    if (this.height === 0 || this.rng.chance(0.55)) {
      this.height += this.rng.range(1, 3);
      this.txIndex = 0;
    } else {
      this.txIndex += 1;
    }
    return { txHash: this.txHash(this.counter++), blockHeight: this.height, txIndex: this.txIndex };
  }

  // Ledger rows, in cert index order, of the tx at `pos`.
  private certs(pos: Draft['pos'], rows: Array<{ kind: 'reg' | 'unreg'; m: MMember; witness?: boolean }>): void {
    rows.forEach((r, certIndex) => {
      const input: LedgerInput = { kind: r.kind, credential: r.m.cred, txHash: pos.txHash, blockHeight: pos.blockHeight, txIndex: pos.txIndex, certIndex };
      if (r.kind === 'reg' && r.m.script) {
        const ws: Uint8Array[] = [];
        if (r.witness) ws.push(r.m.script.bytes);
        if (this.rng.chance(0.3)) ws.push(this.rng.pick(this.policies).bytes); // an unrelated witness
        if (ws.length > 0) input.witnessScripts = ws;
      }
      this.out.push({ kind: 'ledger', input });
      this.applyLedger(r.kind, r.m, r.kind === 'reg' && r.witness === true);
    });
  }

  private applyLedger(kind: 'reg' | 'unreg', m: MMember, witness: boolean): void {
    if (kind === 'reg') {
      m.registered = true;
      if (witness) m.witnessKnown = true;
      return;
    }
    m.registered = false;
    for (const j of this.joins) if (j.member === m && j.state !== 'closed') j.state = 'closed';
  }

  private draft(): Draft {
    const invalid = this.rng.chance(0.03);
    const repeated = !invalid && this.rng.chance(0.02);
    return {
      pos: this.nextPos(), events: [], scripts: [], rawEntries: null, rs: new Set(), wk: new Set(),
      validity: !this.rng.chance(0.08), ignored: invalid || repeated, invalid, repeated,
    };
  }

  private finish(d: Draft): void {
    const m = new Map<number, Cbor>([[0, 1], [1, d.events]]);
    if (d.rawEntries) m.set(2, d.rawEntries);
    else if (d.scripts.length > 0) m.set(2, d.scripts.map((s) => chunk64(s.bytes)));
    const tx: ChainTx = {
      txHash: d.pos.txHash, blockHeight: d.pos.blockHeight, txIndex: d.pos.txIndex, isValid: !d.invalid,
      invalidBefore: d.validity ? IB : null, invalidHereafter: d.validity ? IH : null,
      requiredSigners: [...d.rs], witnessKeyHashes: [...d.wk],
      payload: d.repeated ? undefined : encodeCbor(m), payloadRepeated: d.repeated, witnessScripts: [],
    };
    this.out.push({ kind: 'tx', tx });
  }

  // Signs with `keys`, mostly as required signers, sometimes as vkey witnesses only.
  private sign(d: Draft, keys: Hex[]): void {
    for (const k of keys) (this.rng.chance(0.8) ? d.rs : d.wk).add(k);
  }

  private publish(d: Draft, s: Script): void {
    if (!d.scripts.some((x) => x.hash === s.hash) && d.scripts.length < 8) d.scripts.push(s);
    if (!d.ignored) this.published.add(s.hash);
  }

  private isPublished(s: Script): boolean {
    return this.published.has(s.hash);
  }

  private ref(r: EventRef, d: Draft): Cbor {
    // A ref into the own tx is written as a local ref most of the time.
    if (r.txHash === d.pos.txHash && this.rng.chance(0.8)) return [r.index];
    return [hexToBytes(r.txHash), r.index];
  }

  private self(d: Draft): EventRef {
    return { txHash: d.pos.txHash, index: d.events.length };
  }

  private activeGroups(): MGroup[] {
    return this.groups.filter((g) => !g.dissolved);
  }

  private openJoins(): MJoin[] {
    return this.joins.filter((j) => j.state !== 'closed' && !j.group.dissolved);
  }

  // Events. Each returns false when its preconditions are missing, the caller picks another.

  private create(d: Draft, flaw: 'none' | 'control' | 'admission' | 'unsigned' | 'listed' | 'witness'): boolean {
    if (flaw === 'none' && this.groups.length >= this.maxGroups) return false;
    const mode = this.rng.chance(0.55) ? 'permissioned' : 'open';
    const unpublished = this.policies.filter((p) => !this.isPublished(p));
    let control = this.rng.pick(this.policies);
    let admission: Script | null = mode === 'permissioned' ? this.rng.pick(this.policies) : null;
    if (flaw === 'control') {
      if (unpublished.length === 0) return false;
      control = this.rng.pick(unpublished);
    } else if (flaw === 'witness') {
      // A control hash known only from a DRep registration witness stays unresolved.
      const s = this.members.find((m) => m.script && m.witnessKnown && !this.published.has(m.cred.hash))?.script;
      if (!s) return false;
      control = s;
    } else if (flaw === 'admission') {
      if (unpublished.length === 0 || mode === 'open') return false;
      admission = this.rng.pick(unpublished);
      if (!this.isPublished(control)) this.publish(d, control);
    } else {
      if (!this.isPublished(control)) this.publish(d, control);
      if (admission && !this.isPublished(admission)) this.publish(d, admission);
    }
    if (flaw === 'listed') {
      if (control.satisfy.length === control.listed.length) return false;
      this.sign(d, control.satisfy);
    } else if (flaw !== 'unsigned') {
      this.sign(d, [...control.listed, ...(admission?.listed ?? [])]);
    }
    const ref = this.self(d);
    const ev: Cbor[] = [0, mode === 'open' ? 0 : 1, hexToBytes(control.hash), admission ? hexToBytes(admission.hash) : []];
    if (this.rng.chance(0.2)) ev.push([[`ipfs://g${ref.index}`], hexToBytes(keyHash(0x77).padEnd(64, '0'))]);
    d.events.push(ev);
    if (flaw === 'none' && !d.ignored && d.validity) {
      this.groups.push({ ref, mode, control, admission, seq: 0n, dissolved: false });
    }
    return true;
  }

  private groupRef(d: Draft, kind: 'known' | 'unknown' | 'later' | 'forward'): { ref: Cbor; g: MGroup | null } | null {
    if (kind === 'unknown') {
      // A join ref or a ref to a tx that is never stored names no group.
      const j = this.joins.length > 0 && this.rng.chance(0.5) ? this.rng.pick(this.joins).ref : { txHash: this.unusedHash(), index: 0 };
      return { ref: [hexToBytes(j.txHash), j.index], g: null };
    }
    if (kind === 'later') return { ref: [hexToBytes(this.laterHash()), 0], g: null };
    if (kind === 'forward') return { ref: [d.events.length + this.rng.range(0, 1)], g: null };
    const gs = this.activeGroups();
    if (gs.length === 0) return null;
    const g = this.rng.pick(gs);
    return { ref: this.ref(g.ref, d), g };
  }

  private update(d: Draft, flaw: 'none' | 'stale' | 'unknown' | 'dissolved' | 'unsigned' | 'newControl' | 'openAdmission' | 'newAdmission' | 'newKeys' | 'forward' | 'flood'): boolean {
    let target: { ref: Cbor; g: MGroup | null } | null;
    if (flaw === 'unknown') target = this.groupRef(d, this.rng.chance(0.7) ? 'unknown' : 'later');
    else if (flaw === 'forward') target = this.groupRef(d, 'forward');
    else if (flaw === 'dissolved') {
      const gs = this.groups.filter((g) => g.dissolved);
      if (gs.length === 0) return false;
      const g = this.rng.pick(gs);
      target = { ref: this.ref(g.ref, d), g };
    } else target = this.groupRef(d, 'known');
    if (!target) return false;
    const g = target.g;
    const changes = new Map<number, Cbor>();
    let next: { control?: Script; admission?: Script } = {};
    if (flaw === 'newControl' || flaw === 'newAdmission') {
      const unpublished = this.policies.filter((p) => !this.isPublished(p));
      if (unpublished.length === 0) return false;
      if (flaw === 'newAdmission' && g?.mode !== 'permissioned') return false;
      changes.set(flaw === 'newControl' ? 0 : 1, hexToBytes(this.rng.pick(unpublished).hash));
    } else if (flaw === 'openAdmission') {
      if (g?.mode !== 'open') return false;
      changes.set(1, hexToBytes(this.rng.pick(this.policies).hash));
    } else {
      const choice = this.rng.int(3);
      if (choice === 0 || flaw === 'newKeys') {
        const p = this.rng.pick(this.policies);
        if (!this.isPublished(p)) this.publish(d, p);
        changes.set(0, hexToBytes(p.hash));
        next = { control: p };
      } else if (choice === 1 && g?.mode === 'permissioned') {
        const p = this.rng.pick(this.policies);
        if (!this.isPublished(p)) this.publish(d, p);
        changes.set(1, hexToBytes(p.hash));
        next = { admission: p };
      } else {
        changes.set(2, [[`ipfs://p${this.counter}`], hexToBytes(keyHash(0x78).padEnd(64, '0'))]);
      }
    }
    const seq = g ? (flaw === 'stale' ? (g.seq === 0n || this.rng.chance(0.5) ? g.seq + 1n : g.seq - 1n) : g.seq) : BigInt(this.rng.int(3));
    if (g && flaw !== 'unsigned') this.sign(d, g.control.satisfy);
    const added = [...(next.control?.listed ?? []), ...(next.admission?.listed ?? [])];
    if (flaw === 'newKeys') {
      const current = new Set([...(g?.control.listed ?? []), ...(g?.admission?.listed ?? [])]);
      if (!added.some((k) => !current.has(k) && !d.rs.has(k) && !d.wk.has(k))) return false;
    } else if (flaw !== 'unsigned') this.sign(d, added);
    d.events.push([1, target.ref, seq, changes]);
    if ((flaw === 'none' || flaw === 'flood') && g && !d.ignored) {
      g.seq += 1n;
      if (next.control) g.control = next.control;
      if (next.admission) g.admission = next.admission;
    }
    return true;
  }

  private dissolve(d: Draft, flaw: 'none' | 'stale' | 'unsigned', g0?: MGroup): boolean {
    const target = g0 ? { ref: this.ref(g0.ref, d), g: g0 } : this.groupRef(d, 'known');
    if (!target?.g) return false;
    const g = target.g;
    if (flaw !== 'unsigned') this.sign(d, g.control.satisfy);
    d.events.push([2, target.ref, flaw === 'stale' ? g.seq + 1n : g.seq]);
    if (flaw === 'none' && !d.ignored) {
      g.dissolved = true;
      for (const j of this.joins) if (j.group === g) j.state = 'closed';
    }
    return true;
  }

  private memberAuth(d: Draft, m: MMember): void {
    if (m.cred.kind === 'key') d.rs.add(m.cred.hash);
    else if (m.script) this.sign(d, m.script.satisfy);
  }

  private memberKnown(m: MMember): boolean {
    return m.cred.kind === 'key' || m.witnessKnown || this.published.has(m.cred.hash);
  }

  private join(
    d: Draft, flaw: 'none' | 'unsigned' | 'unresolved' | 'unregistered' | 'already' | 'unknown' | 'dissolved', g0?: MGroup, m0?: MMember,
  ): MJoin | boolean {
    let g: MGroup | null = g0 ?? null;
    let gref: Cbor;
    if (flaw === 'unknown') {
      const t = this.groupRef(d, this.rng.weighted([[2, 'unknown'], [2, 'later'], [1, 'forward']] as const));
      if (!t) return false;
      gref = t.ref;
    } else if (flaw === 'dissolved') {
      const gs = this.groups.filter((x) => x.dissolved);
      if (!g && gs.length === 0) return false;
      g = g ?? this.rng.pick(gs);
      gref = this.ref(g.ref, d);
    } else {
      if (!g) {
        const gs = this.activeGroups();
        if (gs.length === 0) return false;
        g = this.rng.pick(gs);
      }
      gref = this.ref(g.ref, d);
    }
    const inGroup = (m: MMember): boolean => g !== null && this.joins.some((j) => j.group === g && j.member === m && j.state !== 'closed');
    const candidates = this.members.filter((m) => {
      if (flaw === 'already') return inGroup(m);
      if (flaw === 'unresolved') return m.cred.kind === 'script' && !this.memberKnown(m);
      if (flaw === 'unregistered') return !m.registered && this.memberKnown(m) && !inGroup(m);
      if (flaw === 'unsigned') return this.memberKnown(m);
      if (flaw === 'unknown' || flaw === 'dissolved') return true;
      return m.registered && this.memberKnown(m) && !inGroup(m);
    });
    if (!m0 && candidates.length === 0) return false;
    const m = m0 ?? this.rng.pick(candidates);
    if (flaw === 'unsigned') {
      // A key member that only witnesses, or a script member whose keys do not sign.
      if (m.cred.kind === 'key') d.wk.add(m.cred.hash);
    } else this.memberAuth(d, m);
    const ref = this.self(d);
    d.events.push([3, gref, [m.cred.kind === 'key' ? 0 : 1, hexToBytes(m.cred.hash)]]);
    if (flaw === 'none' && g && !d.ignored) {
      const j: MJoin = { ref, group: g, member: m, state: g.mode === 'open' ? 'active' : 'pending' };
      this.joins.push(j);
      return j;
    }
    return true;
  }

  private transition(
    d: Draft, tag: 'approve' | 'leave' | 'remove',
    flaw: 'none' | 'unsigned' | 'open' | 'closed' | 'notPending' | 'unknown' | 'forward' | 'dissolvedPending',
    j0?: MJoin,
  ): boolean {
    const code = tag === 'approve' ? 4 : tag === 'leave' ? 5 : 6;
    if (flaw === 'unknown') {
      // A ref to a later stored tx, to a tx never stored, or to an event that is no join.
      const r = this.rng.weighted<() => EventRef>([
        [2, () => ({ txHash: this.laterHash(), index: 0 })],
        [2, () => ({ txHash: this.unusedHash(), index: 0 })],
        [1, () => (this.groups.length > 0 ? this.rng.pick(this.groups).ref : { txHash: this.unusedHash(), index: 1 })],
      ])();
      d.events.push([code, [hexToBytes(r.txHash), r.index]]);
      return true;
    }
    if (flaw === 'forward') {
      d.events.push([code, [d.events.length + this.rng.range(0, 1)]]);
      return true;
    }
    const pool = j0 ? [j0] : this.joins.filter((j) => {
      const closed = j.state === 'closed' || j.group.dissolved;
      if (flaw === 'open') return j.group.mode === 'open';
      if (flaw === 'closed') return closed && (tag !== 'remove' || j.group.mode === 'permissioned');
      if (flaw === 'notPending') return j.group.mode === 'permissioned' && j.state === 'active' && !j.group.dissolved;
      if (flaw === 'dissolvedPending') return j.group.mode === 'permissioned' && j.state !== 'active' && j.group.dissolved;
      if (closed) return false;
      if (tag === 'leave') return true;
      if (j.group.mode !== 'permissioned') return false;
      return tag === 'approve' ? j.state === 'pending' : true;
    });
    if (pool.length === 0) return false;
    const j = this.rng.pick(pool);
    if (flaw !== 'unsigned') {
      if (tag === 'leave') this.memberAuth(d, j.member);
      else if (j.group.admission) this.sign(d, j.group.admission.satisfy);
    }
    d.events.push([code, this.ref(j.ref, d)]);
    if (flaw === 'none' && !d.ignored && d.validity) {
      if (tag === 'approve') j.state = 'active';
      else j.state = 'closed';
    }
    return true;
  }

  private malformed(d: Draft): boolean {
    d.events.push(this.rng.weighted<Cbor>([
      [3, [9]], [3, 'x'], [2, 7], [1, [0, 5, hexToBytes(keyHash(1)), []]], [1, [3, [0]]], [1, [4]],
    ]));
    return true;
  }

  // One random event from the shape menu, retried until one fits.
  private randomEvent(d: Draft): void {
    const menu: Array<[number, () => boolean | MJoin]> = [
      [10, () => this.create(d, 'none')],
      [1.2, () => this.create(d, 'control')],
      [0.6, () => this.create(d, 'witness')],
      [1, () => this.create(d, 'admission')],
      [0.8, () => this.create(d, 'unsigned')],
      [1, () => this.create(d, 'listed')],
      [7, () => this.update(d, 'none')],
      [0.8, () => this.update(d, 'stale')],
      [0.8, () => this.update(d, 'unknown')],
      [0.6, () => this.update(d, 'dissolved')],
      [0.6, () => this.update(d, 'unsigned')],
      [0.8, () => this.update(d, 'newControl')],
      [0.8, () => this.update(d, 'openAdmission')],
      [0.8, () => this.update(d, 'newAdmission')],
      [0.8, () => this.update(d, 'newKeys')],
      [0.4, () => this.update(d, 'forward')],
      [2.5, () => this.dissolve(d, 'none')],
      [0.4, () => this.dissolve(d, 'stale')],
      [0.4, () => this.dissolve(d, 'unsigned')],
      [14, () => this.join(d, 'none')],
      [1.2, () => this.join(d, 'unsigned')],
      [1, () => this.join(d, 'unresolved')],
      [1.2, () => this.join(d, 'unregistered')],
      [1.2, () => this.join(d, 'already')],
      [1, () => this.join(d, 'unknown')],
      [0.8, () => this.join(d, 'dissolved')],
      [8, () => this.transition(d, 'approve', 'none')],
      [1, () => this.transition(d, 'approve', 'unsigned')],
      [1, () => this.transition(d, 'approve', 'open')],
      [1, () => this.transition(d, 'approve', 'notPending')],
      [0.6, () => this.transition(d, 'approve', 'dissolvedPending')],
      [5, () => this.transition(d, 'leave', 'none')],
      [1, () => this.transition(d, 'leave', 'closed')],
      [0.8, () => this.transition(d, 'leave', 'unsigned')],
      [3, () => this.transition(d, 'remove', 'none')],
      [1, () => this.transition(d, 'remove', 'open')],
      [0.8, () => this.transition(d, 'remove', 'closed')],
      [0.8, () => this.transition(d, 'remove', 'unsigned')],
      [1.2, () => this.transition(d, this.rng.pick(['approve', 'leave', 'remove'] as const), 'unknown')],
      [0.4, () => this.transition(d, this.rng.pick(['approve', 'leave', 'remove'] as const), 'forward')],
      [0.4, () => this.malformed(d)],
    ];
    for (let i = 0; i < 50; i++) if (this.rng.weighted(menu)()) return;
    this.malformed(d);
  }

  // Same tx folds: a create with membership and control events by local ref, a join with
  // its transitions, dissolves next to joins and leaves in both orders.
  private combo(d: Draft): void {
    const kind = this.rng.int(8);
    if (kind === 0 || kind === 1) {
      const before = this.groups.length;
      if (!this.create(d, 'none') || this.groups.length === before) return this.randomEvent(d);
      const g = this.groups[this.groups.length - 1] as MGroup;
      if (kind === 0) this.join(d, 'none', g);
      else this.update(d, 'none');
      if (this.rng.chance(0.3)) this.dissolve(d, 'none', g);
      return;
    }
    if (kind === 2 || kind === 3) {
      const j = this.join(d, 'none');
      if (typeof j !== 'object') return this.randomEvent(d);
      const steps = kind === 2 ? ['approve', 'leave'] as const : this.rng.pick([['approve'], ['leave'], ['remove'], ['approve', 'remove']] as const);
      for (const t of steps) this.transition(d, t, 'none', j);
      return;
    }
    if (kind === 4) {
      // A join and a dissolve of the same group, in either order.
      const gs = this.activeGroups();
      if (gs.length === 0) return this.randomEvent(d);
      const g = this.rng.pick(gs);
      if (this.rng.chance(0.5)) {
        this.join(d, 'none', g);
        this.dissolve(d, 'none', g);
      } else {
        this.dissolve(d, 'none', g);
        this.join(d, 'dissolved', g);
      }
      return;
    }
    if (kind === 5) {
      // A leave before a dissolve of the same group, a tie the leave wins.
      const js = this.openJoins();
      if (js.length === 0) return this.randomEvent(d);
      const j = this.rng.pick(js);
      this.transition(d, 'leave', 'none', j);
      this.dissolve(d, 'none', j.group);
      return;
    }
    if (kind === 6) {
      // A flood of updates on one group.
      const gs = this.activeGroups();
      if (gs.length === 0) return this.randomEvent(d);
      const n = this.rng.range(6, 20);
      const g = this.rng.pick(gs);
      for (let i = 0; i < n; i++) {
        const before = g.seq;
        if (!this.update(d, 'flood') || g.seq === before) break;
      }
      return;
    }
    // Events whose policies are published in the same payload, after a membership event.
    this.join(d, 'none');
    this.create(d, 'none');
  }

  private labelTx(): void {
    const d = this.draft();
    const shape = this.rng.weighted([[70, 'plain'], [18, 'combo'], [1.5, 'tooMany'], [1.5, 'scripts'], [1, 'complex'], [8, 'publish']] as const);
    if (shape === 'tooMany') {
      // More than 64 events: the payload is rejected, scripts included.
      const ignored = d.ignored;
      d.ignored = true;
      for (let i = 0; i < 65; i++) this.randomEvent(d);
      d.ignored = ignored;
      d.scripts = [];
      this.finish(d);
      return;
    }
    if (shape === 'scripts') {
      // More than 8 key 2 entries: key 2 is ignored, the events stay.
      const extra = this.policies.slice(0, 9).map((p) => chunk64(p.bytes));
      while (extra.length < 9) extra.push(chunk64(this.rng.pick(this.policies).bytes));
      const ignored = d.ignored;
      d.ignored = true; // nothing it publishes counts
      this.randomEvent(d);
      d.ignored = ignored;
      d.rawEntries = extra;
      this.finish(d);
      return;
    }
    if (shape === 'complex') {
      // Scripts over the node or the depth limit are skipped, the other entries stay usable.
      const big = encodeCbor(nOfKS(1, ...Array.from({ length: 70 }, (_, i) => sigS(keyHash((i % 12) + 1)))));
      let deep: Cbor = sigS(keyHash(this.rng.range(1, 12)));
      for (let i = 0; i < 8; i++) deep = allS(deep);
      const p = this.rng.pick(this.policies);
      d.rawEntries = [chunk64(this.rng.chance(0.5) ? big : encodeCbor(deep)), chunk64(p.bytes)];
      if (!d.ignored) this.published.add(p.hash);
      this.randomEvent(d);
      d.rawEntries.push(...d.scripts.slice(0, 6).map((s) => chunk64(s.bytes)));
      this.finish(d);
      return;
    }
    if (shape === 'publish') {
      // Policies published ahead of use, next to a membership event.
      const unpublished = this.policies.filter((p) => !this.isPublished(p));
      for (const p of unpublished.slice(0, this.rng.range(1, 2))) this.publish(d, p);
      // A member script published in key 2, which then resolves before the member's own.
      const scripted = this.members.filter((m) => m.script && !this.published.has(m.cred.hash));
      if (scripted.length > 0 && this.rng.chance(0.35)) this.publish(d, this.rng.pick(scripted).script as Script);
      if (!this.join(d, 'none')) this.randomEvent(d);
      this.finish(d);
      return;
    }
    if (shape === 'combo') this.combo(d);
    else {
      const n = this.rng.weighted([[5, 1], [3, 2], [1, 3], [1, 4]] as const);
      for (let i = 0; i < n; i++) this.randomEvent(d);
      // An undecodable event next to readable ones, so the tx is no marker and it is seen.
      if (this.rng.chance(0.12)) this.malformed(d);
    }
    if (d.events.length === 0) this.malformed(d);
    this.finish(d);
  }

  private ledgerTx(): void {
    const pos = this.nextPos();
    const unregistered = this.members.filter((m) => !m.registered);
    const registered = this.members.filter((m) => m.registered);
    const kind = this.rng.weighted([[5, 'reg'], [3, 'unreg'], [1, 'both'], [1, 'pair']] as const);
    if ((kind === 'reg' || kind === 'pair') && unregistered.length > 0) {
      const m = this.rng.pick(unregistered);
      const rows: Array<{ kind: 'reg' | 'unreg'; m: MMember; witness?: boolean }> = [{ kind: 'reg', m, witness: this.rng.chance(0.75) }];
      if (kind === 'pair') rows.push({ kind: 'unreg', m });
      this.certs(pos, rows);
    } else if (kind === 'both' && registered.length > 0 && unregistered.length > 0) {
      const a = this.rng.pick(registered);
      const b = this.rng.pick(unregistered);
      this.certs(pos, [{ kind: 'unreg', m: a }, { kind: 'reg', m: b, witness: this.rng.chance(0.75) }]);
    } else if (registered.length > 0) {
      this.certs(pos, [{ kind: 'unreg', m: this.rng.pick(registered) }]);
    } else if (unregistered.length > 0) {
      this.certs(pos, [{ kind: 'reg', m: this.rng.pick(unregistered), witness: this.rng.chance(0.75) }]);
    }
  }

  // A dissolve whose tx also retires a member of the group: the unreg in phase 0 wins.
  private retireAndDissolve(): boolean {
    const js = this.openJoins();
    if (js.length === 0) return false;
    const j = this.rng.pick(js);
    const d = this.draft();
    if (d.ignored) return false;
    this.certs(d.pos, [{ kind: 'unreg', m: j.member }]);
    this.dissolve(d, 'none', j.group);
    this.finish(d);
    return true;
  }

  // A reg in the same tx as the member's join.
  private regAndJoin(): boolean {
    const gs = this.activeGroups();
    const ms = this.members.filter((m) => !m.registered && m.cred.kind === 'key');
    if (gs.length === 0 || ms.length === 0) return false;
    const d = this.draft();
    const m = this.rng.pick(ms);
    this.certs(d.pos, [{ kind: 'reg', m }]);
    this.join(d, 'none', this.rng.pick(gs), m);
    this.finish(d);
    return true;
  }

  build(): ChainInput[] {
    // Early registrations, so joins have registered members to work with.
    for (const m of this.members) {
      if (this.rng.chance(0.8)) this.certs(this.nextPos(), [{ kind: 'reg', m, witness: this.rng.chance(0.75) }]);
    }
    for (let i = 0; i < this.opts.txs; i++) {
      const what = this.rng.weighted([[76, 'label'], [16, 'ledger'], [4, 'tie'], [4, 'regJoin']] as const);
      if (what === 'tie' && this.retireAndDissolve()) continue;
      if (what === 'regJoin' && this.regAndJoin()) continue;
      if (what === 'ledger') this.ledgerTx();
      else this.labelTx();
    }
    // The chain ends with ledger rows and no later label tx.
    for (let i = this.rng.range(1, 3); i > 0; i--) this.ledgerTx();
    return this.out;
  }
}

export function generateChain(seed: number, opts: ChainOptions = {}): ChainInput[] {
  return new ChainBuilder(seed, { txs: opts.txs ?? 60, credentials: opts.credentials ?? 10, groups: opts.groups ?? 8 }).build();
}

// Schedules.

export type ScheduleStep =
  | { kind: 'deliver'; inputs: ChainInput[] }
  | { kind: 'frontiers'; L?: number; R?: number | null }
  | { kind: 'complete'; c: Credential; complete: boolean }
  | { kind: 'run'; budget: Budget }
  | { kind: 'rollback'; to: number; suffix: ChainInput[] }
  | { kind: 'rebuild' }
  | { kind: 'fork' }
  | { kind: 'interrupt'; afterCommits: number }
  | { kind: 'expireLease' }
  | { kind: 'check'; label: string };

export interface ScheduleOptions {
  chunks?: number;      // delivery chunks of the chain, before late inputs and duplicates
  rollback?: number;    // probability of a rollback
  rebuild?: number;     // probability of a rebuild midway
  fork?: number;        // probability of a fork recovery
}

export const BIG_BUDGET: Budget = {
  controlTxs: 1000, controlBytes: 10_000_000, credentialUnits: 1000, credentialInputs: 10_000, truncateRows: 100_000, resetRows: 100_000,
};

export const heightOf = (x: ChainInput): number => (x.kind === 'tx' ? x.tx.blockHeight : x.input.blockHeight);
export const inputKey = (x: ChainInput): string => (x.kind === 'tx' ? `tx:${x.tx.txHash}` : `cert:${x.input.txHash}#${x.input.certIndex}`);

function credentialsOf(chain: readonly ChainInput[]): Credential[] {
  const out = new Map<string, Credential>();
  for (const x of chain) if (x.kind === 'ledger') out.set(credKey(x.input.credential), x.input.credential);
  return [...out.values()].sort((a, b) => (credKey(a) < credKey(b) ? -1 : 1));
}

function randomBudget(rng: Rng): Budget {
  const small = (lo: number, hi: number, big: number): number => (rng.chance(0.6) ? rng.range(lo, hi) : big);
  return {
    controlTxs: small(1, 4, 1000),
    controlBytes: rng.chance(0.15) ? rng.range(1, 400) : 10_000_000,
    credentialUnits: small(1, 3, 1000),
    credentialInputs: small(1, 5, 10_000),
    truncateRows: small(1, 12, 100_000),
    resetRows: small(1, 12, 100_000),
  };
}

// A schedule delivers the chain in chunks in chain order, holds some inputs back and
// delivers them after their frontier passed, delivers some twice, completes credentials
// late and non monotonically, and runs the engine with small budgets, interruptions and
// lost leases between the deliveries. It may roll back to a random height and deliver a
// different suffix, rebuild midway and recover from a fork. It ends with every credential
// complete, the frontiers at the tip and runs with a large budget.
export function generateSchedule(seed: number, chain: ChainInput[], opts: ScheduleOptions = {}): ScheduleStep[] {
  const rng = new Rng(seed ^ 0x2545f491);
  const steps: ScheduleStep[] = [];
  const creds = credentialsOf(chain);
  const scriptCreds = creds.filter((c) => c.kind === 'script');
  const maxH = chain.reduce((h, x) => Math.max(h, heightOf(x)), 0);
  const chunks = opts.chunks ?? rng.range(3, 8);
  const rollbackAt = rng.chance(opts.rollback ?? 0.45) ? rng.range(1, chunks - 1) : -1;
  const rebuildAt = rng.chance(opts.rebuild ?? 0.35) ? rng.range(1, chunks - 1) : -1;
  const forkAt = rng.chance(opts.fork ?? 0.12) ? rng.range(1, chunks - 1) : -1;

  // What the driver's reference chain holds, simulated, so a rollback suffix and a fork
  // re-delivery are built from it.
  let delivered = new Map<string, ChainInput>();
  let held: ChainInput[] = [];
  let L = -1;
  let R: number | null = rng.chance(0.3) ? null : -1;
  const incomplete = new Set<string>();
  const certTxs = new Set(chain.flatMap((x) => (x.kind === 'ledger' ? [x.input.txHash] : [])));
  const moved = new Set<string>(); // label txs a rollback suffix carries to another height
  let fresh = 0;
  const newHash = (): Hex => `cc${(seed >>> 0).toString(16).padStart(8, '0')}${(fresh++).toString(16).padStart(8, '0')}`.padEnd(64, 'c');
  const byKey = new Map(creds.map((c) => [credKey(c), c] as const));

  const deliver = (inputs: ChainInput[]): void => {
    if (inputs.length === 0) return;
    steps.push({ kind: 'deliver', inputs });
    for (const x of inputs) delivered.set(inputKey(x), x);
  };
  const runs = (): void => {
    for (let i = rng.range(1, 4); i > 0; i--) {
      const r = rng.float();
      if (r < 0.1) steps.push({ kind: 'interrupt', afterCommits: rng.range(0, 2) });
      else if (r < 0.15) steps.push({ kind: 'expireLease' });
      else steps.push({ kind: 'run', budget: randomBudget(rng) });
    }
  };
  const completeness = (): void => {
    for (const c of creds) {
      const k = credKey(c);
      if (incomplete.has(k) && rng.chance(0.35)) {
        incomplete.delete(k);
        steps.push({ kind: 'complete', c, complete: true });
      } else if (!incomplete.has(k) && c.kind === 'script' && rng.chance(0.06)) {
        // A reopened member script search makes a script credential incomplete again.
        incomplete.add(k);
        steps.push({ kind: 'complete', c, complete: false });
      }
    }
  };

  // Credentials that start incomplete, in random order.
  for (const c of rng.shuffle([...creds])) {
    if (rng.chance(0.3)) {
      incomplete.add(credKey(c));
      steps.push({ kind: 'complete', c, complete: false });
    }
  }
  // A script credential complete, then incomplete at a later chunk, then complete again.
  const reopen = scriptCreds.length > 0 && rng.chance(0.6) ? { c: rng.pick(scriptCreds), at: rng.range(1, chunks - 1) } : null;
  if (reopen) {
    steps.push({ kind: 'complete', c: reopen.c, complete: true });
    incomplete.delete(credKey(reopen.c));
  }

  const size = Math.ceil(chain.length / chunks);
  for (let n = 0; n < chunks; n++) {
    const part = chain.slice(n * size, (n + 1) * size);
    const now: ChainInput[] = [];
    for (const x of part) {
      if (rng.chance(0.06)) held.push(x);
      else now.push(x);
      if (rng.chance(0.04)) now.push(x); // the same input twice in one delivery
    }
    // A few held inputs arrive now, after their frontier passed.
    const late = held.filter(() => rng.chance(0.4));
    held = held.filter((x) => !late.includes(x));
    deliver([...now, ...late]);
    // Re-delivery of stored rows: the reader's overlap and a restarted history.
    if (delivered.size > 0 && rng.chance(0.3)) {
      const all = [...delivered.values()];
      deliver(all.filter(() => rng.chance(0.2)));
    }
    const top = part.reduce((h, x) => Math.max(h, heightOf(x)), L);
    L = Math.max(L, top - (rng.chance(0.3) ? rng.range(0, 3) : 0));
    // R starts at the safe height of the run that tracks the first credential, so it never
    // starts below what credentials bound by G alone have applied, then it may lag behind L.
    if (R === null && rng.chance(0.5)) R = L;
    else if (R !== null) R = Math.max(R, L - (rng.chance(0.4) ? rng.range(0, 6) : 0));
    steps.push({ kind: 'frontiers', L, R });
    completeness();
    if (reopen && n === reopen.at) {
      incomplete.add(credKey(reopen.c));
      steps.push({ kind: 'complete', c: reopen.c, complete: false });
    }
    runs();
    if (rng.chance(0.3)) steps.push({ kind: 'check', label: `chunk ${n}` });

    if (n === rebuildAt) {
      steps.push({ kind: 'rebuild' });
      runs();
    }
    if (n === rollbackAt && delivered.size > 0) {
      // Often every credential is complete at the rollback, so the cut chain check can run.
      if (rng.chance(0.7)) {
        for (const k of incomplete) steps.push({ kind: 'complete', c: byKey.get(k) as Credential, complete: true });
        incomplete.clear();
      }
      const heights = [...new Set([...delivered.values()].map(heightOf))].sort((a, b) => a - b);
      const to = rng.pick(heights) - 1;
      // A different suffix: part of the rolled back inputs again, some label txs of the old
      // branch at another height after the cut, and new txs, the rest never.
      const above = [...delivered.values()].filter((x) => heightOf(x) > to);
      const kept: ChainInput[] = [];
      let slot = 0;
      const elsewhere = (tx: ChainTx, txHash: Hex): ChainInput =>
        ({ kind: 'tx', tx: { ...tx, txHash, blockHeight: to + 1 + rng.int(6), txIndex: 100 + slot++ } });
      for (const x of above) {
        const r = rng.float();
        if (x.kind === 'tx' && !certTxs.has(x.tx.txHash) && r < 0.15) {
          kept.push(elsewhere(x.tx, x.tx.txHash));
          moved.add(inputKey(x));
        } else if (r < 0.65) kept.push(x);
        if (x.kind === 'tx' && rng.chance(0.15)) kept.push(elsewhere(x.tx, newHash()));
      }
      delivered = new Map([...delivered].filter(([, x]) => heightOf(x) <= to));
      L = Math.min(L, to);
      if (R !== null) R = Math.min(R, to);
      steps.push({ kind: 'rollback', to, suffix: kept });
      for (const x of kept) delivered.set(inputKey(x), x);
      // Inputs of the old branch that were still held back are dropped with it.
      held = held.filter((x) => (heightOf(x) <= to || rng.chance(0.5)) && !moved.has(inputKey(x)));
      completeness();
      runs();
    }
    if (n === forkAt) {
      steps.push({ kind: 'fork' });
      const again = [...delivered.values()];
      delivered = new Map();
      incomplete.clear();
      L = -1;
      R = null;
      runs();
      deliver(again);
      L = again.reduce((h, x) => Math.max(h, heightOf(x)), -1);
      R = L;
      steps.push({ kind: 'frontiers', L, R });
      runs();
    }
  }
  deliver(held);

  // The end: every credential complete, the frontiers at the tip, large runs.
  for (const k of incomplete) steps.push({ kind: 'complete', c: byKey.get(k) as Credential, complete: true });
  steps.push({ kind: 'frontiers', L: maxH, R: maxH });
  // Mostly the driver's own settle finishes the work, so a wrong `more` is seen there.
  if (rng.chance(0.3)) for (let i = 0; i < 3; i++) steps.push({ kind: 'run', budget: BIG_BUDGET });
  steps.push({ kind: 'check', label: 'end' });
  return steps;
}
