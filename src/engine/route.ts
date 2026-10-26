// Splits one label tx into control plane, membership plane and orphans.
import { posOfEvent } from '../position.js';
import type { ChainTx, Credential, DecodedEvent, DecodedPayload, EventRef } from '../types.js';
import { foreignJoinRefs } from './classify.js';
import type { Routed, RoutedEvent } from './types.js';

type JoinLookup = (ref: EventRef) => DecodedEvent | 'ignored' | null;

const memberOf = (d: DecodedEvent | 'ignored' | null | undefined): Credential | null =>
  d && d !== 'ignored' && d.ok && d.event.tag === 'join' ? d.event.member : null;

// Events are folded in index order. A join is always a membership event. An approve, leave
// or remove is routed to the member of the join it names, or becomes an orphan when the
// join cannot be found in this tx or in the queue. Orphans carry no subject.
export function routeTx(tx: ChainTx, decoded: DecodedPayload, joinEventAt: JoinLookup): Routed {
  const events: RoutedEvent[] = [];
  const joinMembers: Credential[] = [];
  const seenMembers = new Set<string>();

  decoded.events.forEach((d, index) => {
    const base = { ref: { txHash: tx.txHash, index }, at: posOfEvent(tx, index), decoded: d };
    if (!d.ok) {
      events.push({ ...base, plane: 'orphan', subject: null });
      return;
    }
    const e = d.event;
    if (e.tag === 'create' || e.tag === 'update' || e.tag === 'dissolve') {
      events.push({ ...base, plane: 'control', subject: null });
      return;
    }
    if (e.tag === 'join') {
      events.push({ ...base, plane: 'membership', subject: e.member });
      const key = `${e.member.kind}:${e.member.hash}`;
      if (!seenMembers.has(key)) {
        seenMembers.add(key);
        joinMembers.push(e.member);
      }
      return;
    }
    // approve, leave, remove. A local ref only works towards an earlier event, as in replay.
    // An explicit ref to this tx's own hash is read like a same tx ref.
    const r = e.join;
    let target: number | null = null;
    let remote: EventRef | null = null;
    if ('local' in r) {
      if (r.local >= index) {
        events.push({ ...base, plane: 'orphan', subject: null });
        return;
      }
      target = r.local;
    } else if (r.txHash === tx.txHash) {
      target = r.index;
    } else {
      remote = r;
    }
    const subject = remote ? memberOf(joinEventAt(remote))
      : target !== null && target >= 0 && target < index ? memberOf(decoded.events[target]) : null;
    events.push(subject
      ? { ...base, plane: 'membership', subject }
      : { ...base, plane: 'orphan', subject: null });
  });

  return { scripts: decoded.scripts, events, joinMembers, foreignJoins: foreignJoinRefs(tx, decoded) };
}
