// The A4 rules of spec Part A over an abstract world. A rule reads state only through
// RuleWorld and returns its writes, so the same rules run over the eager world of
// replay and over a lazy world that projects dissolves and unregs at read time.
import type { CloseReason } from './effective.js';
import { collectKeyHashes, evaluateNativeScript } from './nativeScript.js';
import type { Pos } from './position.js';
import type { Anchor, Credential, EvalContext, EventRef, GroupEvent, GroupMode, Hex, NativeScript, RefLike } from './types.js';

export interface StoredInstance {
  joinId: EventRef; group: EventRef; member: Credential; mode: GroupMode;
  joinedAt: Pos; approvedAt: Pos | null; closedAt: Pos | null; closeReason: 'left' | 'removed' | null;
}
export interface GroupVersion {
  id: EventRef; at: Pos; mode: GroupMode; control: Hex; admission: Hex | null; profile: Anchor | null;
  seq: bigint; status: 'active' | 'dissolved'; createdAt: Pos; profileSetAt: Pos | null;
}
export interface RuleWorld {
  // First publication at or before at.
  scriptAt(hash: Hex, at: Pos): NativeScript | null;
  // Latest version at or before at.
  groupAt(group: EventRef, at: Pos): GroupVersion | null;
  registeredAt(c: Credential, at: Pos): boolean;
  memberScriptAt(c: Credential, at: Pos): NativeScript | null;
  // Only instances with joinedAt < at, close is the effective close at q = at.
  instanceAt(join: EventRef, at: Pos): { inst: StoredInstance; close: { at: Pos; reason: CloseReason } | null } | null;
  // The latest instance of (group, c) with joinedAt < at, when it has no effective close at q = at.
  openSlotAt(group: EventRef, c: Credential, at: Pos): StoredInstance | null;
}
export type RuleWrite = { kind: 'version'; version: GroupVersion } | { kind: 'instance'; instance: StoredInstance };
export interface RuleResult { reason: string | null; group: EventRef | null; subject: Credential | null; writes: RuleWrite[] }

// Every reason a rule returns for a decodable event. The defensive 'unknown event' is
// left out, decoding already rejects unknown tags.
const REASONS = [
  'control policy unresolved',
  'admission policy unresolved',
  'control policy not satisfied',
  'listed key did not sign',
  'local reference must point to an earlier event',
  'unknown group',
  'group dissolved',
  'stale seq',
  'new control policy unresolved',
  'open group has no admission policy',
  'new admission policy unresolved',
  'newly listed key did not sign',
  'member key not in required_signers',
  'member script unresolved',
  'member script not satisfied',
  'not a registered DRep',
  'already a member or applicant',
  'unknown join',
  'join is not open',
  'open group has no remove',
  'open group has no approval',
  'join is not pending',
  'admission policy not satisfied',
] as const;
type Reason = (typeof REASONS)[number] | 'unknown event';
export const ALL_REASONS: readonly string[] = REASONS;

const fail = (reason: Reason, group: EventRef | null = null, subject: Credential | null = null): RuleResult =>
  ({ reason, group, subject, writes: [] });
const ok = (group: EventRef | null, subject: Credential | null, write: RuleWrite): RuleResult =>
  ({ reason: null, group, subject, writes: [write] });

function resolve(r: RefLike, self: EventRef): EventRef | null {
  if ('local' in r) return r.local < self.index ? { txHash: self.txHash, index: r.local } : null;
  return r;
}

function policy(w: RuleWorld, hash: Hex | null, ctx: EvalContext, at: Pos): boolean {
  const s = hash ? w.scriptAt(hash, at) : null;
  return s !== null && evaluateNativeScript(s, ctx);
}

function keysOf(w: RuleWorld, at: Pos, ...hashes: Array<Hex | null | undefined>): Hex[] {
  const out: Hex[] = [];
  for (const h of hashes) {
    const s = h ? w.scriptAt(h, at) : null;
    if (s) for (const k of collectKeyHashes(s)) if (!out.includes(k)) out.push(k);
  }
  return out;
}

function memberAuthorized(w: RuleWorld, c: Credential, ctx: EvalContext, required: ReadonlySet<Hex>, at: Pos): Reason | null {
  if (c.kind === 'key') return required.has(c.hash) ? null : 'member key not in required_signers';
  const s = w.scriptAt(c.hash, at) ?? w.memberScriptAt(c, at);
  if (!s) return 'member script unresolved';
  return evaluateNativeScript(s, ctx) ? null : 'member script not satisfied';
}

export function controlRule(w: RuleWorld, e: GroupEvent, self: EventRef, ctx: EvalContext, at: Pos): RuleResult {
  if (e.tag === 'create') {
    if (!w.scriptAt(e.control, at)) return fail('control policy unresolved');
    if (e.admission !== null && !w.scriptAt(e.admission, at)) return fail('admission policy unresolved');
    if (!policy(w, e.control, ctx, at)) return fail('control policy not satisfied');
    // Spec A4 consent rule: every listed key signed the create.
    if (keysOf(w, at, e.control, e.admission).some((k) => !ctx.signers.has(k))) return fail('listed key did not sign');
    return ok(self, null, {
      kind: 'version',
      version: {
        id: self, at, mode: e.mode, control: e.control, admission: e.admission, profile: e.profile,
        seq: 0n, status: 'active', createdAt: at, profileSetAt: e.profile ? at : null,
      },
    });
  }
  if (e.tag !== 'update' && e.tag !== 'dissolve') return fail('unknown event');
  const gref = resolve(e.group, self);
  if (!gref) return fail('local reference must point to an earlier event');
  const g = w.groupAt(gref, at);
  if (!g) return fail('unknown group');
  if (g.status === 'dissolved') return fail('group dissolved', g.id);
  if (e.seq !== g.seq) return fail('stale seq', g.id);
  if (!policy(w, g.control, ctx, at)) return fail('control policy not satisfied', g.id);
  // A dissolve writes the dissolved version only, the world decides how instances close.
  if (e.tag === 'dissolve') return ok(g.id, null, { kind: 'version', version: { ...g, at, status: 'dissolved' } });
  const c = e.changes;
  if (c.control !== undefined && !w.scriptAt(c.control, at)) return fail('new control policy unresolved', g.id);
  if (c.admission !== undefined) {
    if (g.mode === 'open') return fail('open group has no admission policy', g.id);
    if (!w.scriptAt(c.admission, at)) return fail('new admission policy unresolved', g.id);
  }
  // Spec A4 consent rule: keys that the current policies do not list must sign.
  const current = new Set(keysOf(w, at, g.control, g.admission));
  const added = keysOf(w, at, c.control, c.admission).filter((k) => !current.has(k));
  if (added.some((k) => !ctx.signers.has(k))) return fail('newly listed key did not sign', g.id);
  const next: GroupVersion = { ...g, at, seq: g.seq + 1n };
  if (c.control !== undefined) next.control = c.control;
  if (c.admission !== undefined) next.admission = c.admission;
  if (c.profile !== undefined) {
    next.profile = c.profile;
    next.profileSetAt = at;
  }
  return ok(g.id, null, { kind: 'version', version: next });
}

export function membershipRule(
  w: RuleWorld, e: GroupEvent, self: EventRef, ctx: EvalContext, required: ReadonlySet<Hex>, at: Pos,
): RuleResult {
  if (e.tag === 'join') {
    const subject = e.member;
    const gref = resolve(e.group, self);
    if (!gref) return fail('local reference must point to an earlier event', null, subject);
    const g = w.groupAt(gref, at);
    if (!g) return fail('unknown group', null, subject);
    if (g.status === 'dissolved') return fail('group dissolved', g.id, subject);
    const auth = memberAuthorized(w, e.member, ctx, required, at);
    if (auth) return fail(auth, g.id, subject);
    if (!w.registeredAt(e.member, at)) return fail('not a registered DRep', g.id, subject);
    if (w.openSlotAt(g.id, e.member, at)) return fail('already a member or applicant', g.id, subject);
    return ok(g.id, subject, {
      kind: 'instance',
      instance: {
        joinId: self, group: g.id, member: e.member, mode: g.mode,
        joinedAt: at, approvedAt: null, closedAt: null, closeReason: null,
      },
    });
  }
  if (e.tag !== 'approve' && e.tag !== 'leave' && e.tag !== 'remove') return fail('unknown event');
  const jref = resolve(e.join, self);
  if (!jref) return fail('local reference must point to an earlier event');
  const found = w.instanceAt(jref, at);
  if (!found) return fail('unknown join');
  const { inst, close } = found;
  const group = inst.group;
  const subject = inst.member;
  const g = w.groupAt(inst.group, at);
  if (!g) return fail('unknown group', group, subject);
  if (e.tag === 'leave') {
    if (close) return fail('join is not open', group, subject);
    const auth = memberAuthorized(w, inst.member, ctx, required, at);
    if (auth) return fail(auth, group, subject);
    return ok(group, subject, { kind: 'instance', instance: { ...inst, closedAt: at, closeReason: 'left' } });
  }
  if (g.mode === 'open') return fail(e.tag === 'remove' ? 'open group has no remove' : 'open group has no approval', group, subject);
  if (e.tag === 'approve') {
    if (close || inst.approvedAt !== null) return fail('join is not pending', group, subject);
    if (g.status === 'dissolved') return fail('group dissolved', group, subject);
    if (!policy(w, g.admission, ctx, at)) return fail('admission policy not satisfied', group, subject);
    return ok(group, subject, { kind: 'instance', instance: { ...inst, approvedAt: at } });
  }
  if (close) return fail('join is not open', group, subject);
  if (!policy(w, g.admission, ctx, at)) return fail('admission policy not satisfied', group, subject);
  return ok(group, subject, { kind: 'instance', instance: { ...inst, closedAt: at, closeReason: 'removed' } });
}

// Dispatches like the spec's event order: control events, then membership events.
export function eventRule(
  w: RuleWorld, e: GroupEvent, self: EventRef, ctx: EvalContext, required: ReadonlySet<Hex>, at: Pos,
): RuleResult {
  if (e.tag === 'create' || e.tag === 'update' || e.tag === 'dissolve') return controlRule(w, e, self, ctx, at);
  return membershipRule(w, e, self, ctx, required, at);
}
