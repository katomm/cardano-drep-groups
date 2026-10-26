import { nativeScriptHash } from './hash.js';
import type { CloseReason } from './effective.js';
import { parseNativeScript } from './nativeScript.js';
import { decodePayload } from './payload.js';
import { comparePos, type Pos, posOfCert, posOfEvent, posOfScripts } from './position.js';
import { eventRule, type GroupVersion, type RuleWorld, type RuleWrite, type StoredInstance } from './rules.js';
import type {
  ChainInput, ChainTx, Credential, EvalContext, EventRef, EventVerdict, GroupState,
  Hex, IgnoredTx, Instance, LedgerInput, NativeScript, RegistryState,
} from './types.js';

export const refKey = (r: EventRef): string => `${r.txHash}#${r.index}`;
export const credKey = (c: Credential): string => `${c.kind}:${c.hash}`;

// Spec A4 chain order: block height, tx index, ledger inputs before events,
// then certificate index. Duplicates (the same tx or cert seen twice) are dropped.
export function orderInputs(inputs: readonly ChainInput[]): ChainInput[] {
  const seen = new Set<string>();
  const out: ChainInput[] = [];
  for (const x of inputs) {
    const key = x.kind === 'tx' ? `tx:${x.tx.txHash}` : `cert:${x.input.txHash}#${x.input.certIndex}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(x);
  }
  const k = (x: ChainInput): [number, number, number, number] =>
    x.kind === 'tx' ? [x.tx.blockHeight, x.tx.txIndex, 1, 0] : [x.input.blockHeight, x.input.txIndex, 0, x.input.certIndex];
  return out.sort((a, b) => {
    const ka = k(a);
    const kb = k(b);
    for (let i = 0; i < 4; i++) if (ka[i] !== kb[i]) return (ka[i] as number) - (kb[i] as number);
    return 0;
  });
}

// The world of replay: every input is applied in chain order, a dissolve or an unreg
// closes the affected instances at once, so instanceAt returns that eager close.
class EagerWorld implements RuleWorld {
  groups = new Map<string, GroupVersion>();
  instances = new Map<string, { inst: StoredInstance; close: { at: Pos; reason: CloseReason } | null }>();
  latestBySlot = new Map<string, string>(); // group key + credential key to the latest join key
  registered = new Set<string>();
  scripts = new Map<Hex, { at: Pos; script: NativeScript }>();
  memberScripts = new Map<Hex, NativeScript>();
  verdicts: EventVerdict[] = [];
  ignored: IgnoredTx[] = [];

  scriptAt(hash: Hex, at: Pos): NativeScript | null {
    const s = this.scripts.get(hash);
    return s && comparePos(s.at, at) <= 0 ? s.script : null;
  }

  groupAt(group: EventRef, at: Pos): GroupVersion | null {
    const g = this.groups.get(refKey(group));
    return g && comparePos(g.at, at) <= 0 ? g : null;
  }

  registeredAt(c: Credential): boolean {
    return this.registered.has(credKey(c));
  }

  memberScriptAt(c: Credential): NativeScript | null {
    return c.kind === 'script' ? (this.memberScripts.get(c.hash) ?? null) : null;
  }

  instanceAt(join: EventRef, at: Pos): { inst: StoredInstance; close: { at: Pos; reason: CloseReason } | null } | null {
    const x = this.instances.get(refKey(join));
    return x && comparePos(x.inst.joinedAt, at) < 0 ? x : null;
  }

  openSlotAt(group: EventRef, c: Credential, at: Pos): StoredInstance | null {
    const key = this.latestBySlot.get(`${refKey(group)}|${credKey(c)}`);
    const x = key === undefined ? undefined : this.instances.get(key);
    return x && x.close === null && comparePos(x.inst.joinedAt, at) < 0 ? x.inst : null;
  }

  apply(w: RuleWrite): void {
    if (w.kind === 'version') {
      const v = w.version;
      const before = this.groups.get(refKey(v.id));
      this.groups.set(refKey(v.id), v);
      if (v.status === 'dissolved' && before?.status !== 'dissolved') {
        for (const x of this.instances.values()) {
          if (x.close === null && refKey(x.inst.group) === refKey(v.id)) x.close = { at: v.at, reason: 'dissolved' };
        }
      }
      return;
    }
    const inst = w.instance;
    const key = refKey(inst.joinId);
    const prev = this.instances.get(key);
    const close = inst.closedAt !== null && inst.closeReason !== null ? { at: inst.closedAt, reason: inst.closeReason } : null;
    this.instances.set(key, { inst, close: prev?.close ?? close });
    if (!prev) this.latestBySlot.set(`${refKey(inst.group)}|${credKey(inst.member)}`, key);
  }

  ledger(l: LedgerInput): void {
    const ck = credKey(l.credential);
    const at = posOfCert(l);
    if (l.kind === 'reg') {
      this.registered.add(ck);
      if (l.credential.kind === 'script') {
        for (const raw of l.witnessScripts ?? []) {
          if (nativeScriptHash(raw) !== l.credential.hash) continue;
          const s = parseNativeScript(raw);
          if (s) this.memberScripts.set(l.credential.hash, s);
        }
      }
      return;
    }
    this.registered.delete(ck);
    for (const x of this.instances.values()) {
      if (x.close === null && credKey(x.inst.member) === ck) x.close = { at, reason: 'retired' };
    }
  }

  tx(t: ChainTx): void {
    if (t.payload === undefined && !t.payloadRepeated) return;
    if (!t.isValid) {
      this.ignored.push({ txHash: t.txHash, reason: 'phase-2 invalid' });
      return;
    }
    if (t.payloadRepeated || t.payload === undefined) {
      this.ignored.push({ txHash: t.txHash, reason: 'label repeated' });
      return;
    }
    const p = decodePayload(t.payload);
    if (!p) {
      this.ignored.push({ txHash: t.txHash, reason: 'payload rejected' });
      return;
    }
    const scriptsAt = posOfScripts(t);
    for (const s of p.scripts) if (!this.scripts.has(s.hash)) this.scripts.set(s.hash, { at: scriptsAt, script: s.script });
    const ctx: EvalContext = {
      signers: new Set([...t.requiredSigners, ...t.witnessKeyHashes]),
      invalidBefore: t.invalidBefore,
      invalidHereafter: t.invalidHereafter,
    };
    const required = new Set(t.requiredSigners);
    p.events.forEach((d, index) => {
      const ref: EventRef = { txHash: t.txHash, index };
      const at = posOfEvent(t, index);
      if (!d.ok) {
        this.verdicts.push({ ref, tag: null, valid: false, reason: d.reason, at, group: null, subject: null });
        return;
      }
      const r = eventRule(this, d.event, ref, ctx, required, at);
      for (const w of r.writes) this.apply(w);
      this.verdicts.push({ ref, tag: d.event.tag, valid: r.reason === null, reason: r.reason, at, group: r.group, subject: r.subject });
    });
  }

  result(): RegistryState {
    const groups: GroupState[] = [...this.groups.values()].map(({ at: _at, ...g }) => g);
    const instances: Instance[] = [...this.instances.values()].map(({ inst, close }) => ({
      joinId: inst.joinId, group: inst.group, member: inst.member,
      state: close ? 'closed' : inst.mode === 'open' || inst.approvedAt !== null ? 'active' : 'pending',
      reason: close ? close.reason : null,
      joinedAt: inst.joinedAt, approvedAt: inst.approvedAt, closedAt: close ? close.at : null,
    }));
    const scripts = new Map<Hex, NativeScript>();
    for (const [hash, s] of this.scripts) scripts.set(hash, s.script);
    return { groups, instances, verdicts: this.verdicts, ignored: this.ignored, scripts };
  }
}

export function replay(inputs: readonly ChainInput[]): RegistryState {
  const engine = new EagerWorld();
  for (const x of orderInputs(inputs)) {
    if (x.kind === 'tx') engine.tx(x.tx);
    else engine.ledger(x.input);
  }
  return engine.result();
}
