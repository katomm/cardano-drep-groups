import { nativeScriptHash } from './hash.js';
import { collectKeyHashes, evaluateNativeScript, parseNativeScript } from './nativeScript.js';
import { decodePayload } from './payload.js';
import type {
  ChainInput, ChainTx, Credential, EvalContext, EventRef, EventVerdict, GroupEvent, GroupState,
  Hex, IgnoredTx, Instance, InstanceReason, LedgerInput, NativeScript, Position, RefLike, RegistryState,
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

class Engine {
  groups = new Map<string, GroupState>();
  instances = new Map<string, Instance>();
  openByMember = new Map<string, string>(); // group key + credential key to join key
  registered = new Set<string>();
  scripts = new Map<Hex, NativeScript>();
  memberScripts = new Map<Hex, NativeScript>();
  verdicts: EventVerdict[] = [];
  ignored: IgnoredTx[] = [];

  ledger(l: LedgerInput): void {
    const ck = credKey(l.credential);
    const at: Position = { txHash: l.txHash, blockHeight: l.blockHeight, txIndex: l.txIndex };
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
    for (const inst of this.instances.values()) {
      if (inst.state !== 'closed' && credKey(inst.member) === ck) this.close(inst, 'retired', at);
    }
  }

  tx(t: ChainTx): void {
    if (t.payload === undefined) return;
    if (!t.isValid) {
      this.ignored.push({ txHash: t.txHash, reason: 'phase-2 invalid' });
      return;
    }
    const p = decodePayload(t.payload);
    if (!p) {
      this.ignored.push({ txHash: t.txHash, reason: 'payload rejected' });
      return;
    }
    for (const s of p.scripts) if (!this.scripts.has(s.hash)) this.scripts.set(s.hash, s.script);
    const ctx: EvalContext = {
      signers: new Set([...t.requiredSigners, ...t.witnessKeyHashes]),
      invalidBefore: t.invalidBefore,
      invalidHereafter: t.invalidHereafter,
    };
    const required = new Set(t.requiredSigners);
    const at: Position = { txHash: t.txHash, blockHeight: t.blockHeight, txIndex: t.txIndex };
    p.events.forEach((d, index) => {
      const ref: EventRef = { txHash: t.txHash, index };
      if (!d.ok) {
        this.verdicts.push({ ref, tag: null, valid: false, reason: d.reason });
        return;
      }
      const reason = this.event(d.event, ref, ctx, required, at);
      this.verdicts.push({ ref, tag: d.event.tag, valid: reason === null, reason });
    });
  }

  resolve(r: RefLike, self: EventRef): EventRef | null {
    if ('local' in r) return r.local < self.index ? { txHash: self.txHash, index: r.local } : null;
    return r;
  }

  policy(hash: Hex | null, ctx: EvalContext): boolean {
    const s = hash ? this.scripts.get(hash) : undefined;
    return s !== undefined && evaluateNativeScript(s, ctx);
  }

  keysOf(...hashes: Array<Hex | null | undefined>): Hex[] {
    const out: Hex[] = [];
    for (const h of hashes) {
      const s = h ? this.scripts.get(h) : undefined;
      if (s) for (const k of collectKeyHashes(s)) if (!out.includes(k)) out.push(k);
    }
    return out;
  }

  memberAuthorized(c: Credential, ctx: EvalContext, required: ReadonlySet<Hex>): string | null {
    if (c.kind === 'key') return required.has(c.hash) ? null : 'member key not in required_signers';
    const s = this.scripts.get(c.hash) ?? this.memberScripts.get(c.hash);
    if (!s) return 'member script unresolved';
    return evaluateNativeScript(s, ctx) ? null : 'member script not satisfied';
  }

  close(inst: Instance, reason: InstanceReason, at: Position): void {
    inst.state = 'closed';
    inst.reason = reason;
    inst.closedAt = at;
    this.openByMember.delete(`${refKey(inst.group)}|${credKey(inst.member)}`);
  }

  event(e: GroupEvent, self: EventRef, ctx: EvalContext, required: ReadonlySet<Hex>, at: Position): string | null {
    if (e.tag === 'create') {
      if (!this.scripts.has(e.control)) return 'control policy unresolved';
      if (e.admission !== null && !this.scripts.has(e.admission)) return 'admission policy unresolved';
      if (!this.policy(e.control, ctx)) return 'control policy not satisfied';
      // Spec A4 consent rule: every listed key signed the create.
      if (this.keysOf(e.control, e.admission).some((k) => !ctx.signers.has(k))) return 'listed key did not sign';
      this.groups.set(refKey(self), {
        id: self, mode: e.mode, control: e.control, admission: e.admission, profile: e.profile,
        seq: 0n, status: 'active', createdAt: at, profileSetAt: e.profile ? at : null,
      });
      return null;
    }
    if (e.tag === 'update' || e.tag === 'dissolve') {
      const gref = this.resolve(e.group, self);
      if (!gref) return 'local reference must point to an earlier event';
      const g = this.groups.get(refKey(gref));
      if (!g) return 'unknown group';
      if (g.status === 'dissolved') return 'group dissolved';
      if (e.seq !== g.seq) return 'stale seq';
      if (!this.policy(g.control, ctx)) return 'control policy not satisfied';
      if (e.tag === 'dissolve') {
        g.status = 'dissolved';
        for (const inst of this.instances.values()) {
          if (inst.state !== 'closed' && refKey(inst.group) === refKey(g.id)) this.close(inst, 'dissolved', at);
        }
        return null;
      }
      const c = e.changes;
      if (c.control !== undefined && !this.scripts.has(c.control)) return 'new control policy unresolved';
      if (c.admission !== undefined) {
        if (g.mode === 'open') return 'open group has no admission policy';
        if (!this.scripts.has(c.admission)) return 'new admission policy unresolved';
      }
      // Spec A4 consent rule: keys that the current policies do not list must sign.
      const current = new Set(this.keysOf(g.control, g.admission));
      const added = this.keysOf(c.control, c.admission).filter((k) => !current.has(k));
      if (added.some((k) => !ctx.signers.has(k))) return 'newly listed key did not sign';
      if (c.control !== undefined) g.control = c.control;
      if (c.admission !== undefined) g.admission = c.admission;
      if (c.profile !== undefined) {
        g.profile = c.profile;
        g.profileSetAt = at;
      }
      g.seq += 1n;
      return null;
    }
    return this.membership(e, self, ctx, required, at);
  }

  membership(_e: GroupEvent, _self: EventRef, _ctx: EvalContext, _required: ReadonlySet<Hex>, _at: Position): string | null {
    return 'not implemented';
  }

  result(): RegistryState {
    return {
      groups: [...this.groups.values()],
      instances: [...this.instances.values()],
      verdicts: this.verdicts,
      ignored: this.ignored,
      scripts: this.scripts,
    };
  }
}

export function replay(inputs: readonly ChainInput[]): RegistryState {
  const engine = new Engine();
  for (const x of orderInputs(inputs)) {
    if (x.kind === 'tx') engine.tx(x.tx);
    else engine.ledger(x.input);
  }
  return engine.result();
}
