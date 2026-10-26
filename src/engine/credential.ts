// The membership plane unit: applies the inputs of one credential over a bounded view.
import { memberScriptWitness } from '../nativeScript.js';
import { comparePos, type Pos } from '../position.js';
import { membershipRule } from '../rules.js';
import type { Credential, EvalContext, EventRef } from '../types.js';
import type { RuleObserver } from './control.js';
import { emptyChangeSet, isEmptyKeys, LazyWorld, type Step } from './lazyWorld.js';
import type { ChangeSet, CredentialInput, View } from './types.js';

const posOf = (x: CredentialInput): Pos => (x.kind === 'ledger' ? x.at : x.q.at);

// Folds the inputs of `c` in position order. A reg of a script credential writes the
// witness script whose hash is the credential hash as its member script, an unreg adds a
// retirement effect. Registration itself is read from the stored ledger rows through the
// view. Every event runs the membership rule with its tx context, its verdict is kept when
// it has a group, and its ref is marked applied either way. `overlay` holds the change sets
// of earlier units of the same uncommitted batch. Rule results reach `observe` only when
// the unit is done, so a unit that needs more keys reports nothing.
export function applyCredential(
  view: View, c: Credential, inputs: CredentialInput[], overlay: ChangeSet[] = [], observe?: RuleObserver,
): Step<ChangeSet> {
  const own = emptyChangeSet();
  const world = new LazyWorld(view, overlay, own);
  const results: Parameters<RuleObserver>[0][] = [];
  const ordered = [...inputs].sort((a, b) => comparePos(posOf(a), posOf(b)));

  for (const x of ordered) {
    if (x.kind === 'ledger') {
      const l = x.input;
      if (l.kind === 'unreg') {
        own.effects.push({ kind: 'credentialRetired', credential: c, at: x.at });
        continue;
      }
      if (own.memberScripts.length > 0) continue;
      const m = memberScriptWitness(c, l.witnessScripts);
      if (m) own.memberScripts.push({ credential: c, script: m.script, bytes: m.bytes, at: x.at });
      continue;
    }

    const { q, tx } = x;
    const self: EventRef = { txHash: q.txHash, index: q.at.index };
    own.appliedQueue.push(self);
    if (!q.event.ok) {
      // Routing makes every undecodable event an orphan, kept for completeness.
      results.push({ ref: self, tag: null, valid: false, reason: q.event.reason });
      continue;
    }
    const e = q.event.event;
    const ctx: EvalContext = { signers: new Set(tx.signers), invalidBefore: tx.invalidBefore, invalidHereafter: tx.invalidHereafter };
    const res = membershipRule(world, e, self, ctx, new Set(tx.requiredSigners), q.at);
    const valid = res.reason === null;
    results.push({ ref: self, tag: e.tag, valid, reason: res.reason });
    for (const w of res.writes) {
      if (w.kind !== 'instance') continue;
      const inst = w.instance;
      own.instances.push(inst);
      if (e.tag === 'join') own.effects.push({ kind: 'instanceCreated', instance: inst });
      else if (e.tag === 'approve') own.effects.push({ kind: 'instanceApproved', join: inst.joinId, at: q.at });
      else if (inst.closeReason !== null) own.effects.push({ kind: 'instanceClosed', join: inst.joinId, at: q.at, reason: inst.closeReason });
    }
    // Group and subject come from the rule, the instance at this position, never from routing.
    if (res.group !== null) own.verdicts.push({ ref: self, tag: e.tag, valid, reason: res.reason, at: q.at, group: res.group, subject: res.subject });
  }

  if (!isEmptyKeys(world.needed)) return { need: world.needed };
  if (observe) for (const r of results) observe(r);
  return { done: own };
}
