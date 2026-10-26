// A bounded fixture view for the engine unit tests.
import type { Keys, View } from '../src/engine/types.js';
import { comparePos, type Pos, posKey, posOfCert } from '../src/position.js';
import type { GroupVersion, StoredInstance } from '../src/rules.js';
import { credKey, refKey } from '../src/state.js';
import type { ChainTx, Credential, DecodedEvent, EventRef, Hex, LedgerInput, NativeScript } from '../src/types.js';
import { txIn } from './helpers.js';

// Committed state a fixture view answers from, before any key is loaded.
export interface Committed {
  scripts: Array<{ hash: Hex; script: NativeScript; at: Pos }>;
  memberScripts: Array<{ credential: Credential; script: NativeScript; at: Pos }>;
  versions: GroupVersion[];
  instances: StoredInstance[];
  ledger: LedgerInput[];
  queued: Array<{ ref: EventRef; event: DecodedEvent }>;
}
export const committed = (o: Partial<Committed> = {}): Committed =>
  ({ scripts: [], memberScripts: [], versions: [], instances: [], ledger: [], queued: [], ...o });

export function keyStrings(k: Keys): string[] {
  return [
    ...k.instances.map((r) => `i:${refKey(r)}`),
    ...k.latestInstances.map(([g, c]) => `l:${refKey(g)}|${credKey(c)}`),
    ...k.groupsAt.map(([g, p]) => `g:${refKey(g)}@${posKey(p)}`),
    ...k.scriptsAt.map(([h, p]) => `s:${h}@${posKey(p)}`),
    ...k.credentialAt.map(([c, p]) => `c:${credKey(c)}@${posKey(p)}`),
  ];
}

// A bounded view: answers only for the keys it was loaded for, from the committed state
// alone. It never merges the overlay, the units read it through LazyWorld. Every key a
// unit asks for is recorded in `asked`.
export class FixtureView implements View {
  readonly asked = new Set<string>();
  constructor(private c: Committed, private loaded: Set<string>) {}
  private versions(g: EventRef): GroupVersion[] {
    return this.c.versions.filter((v) => refKey(v.id) === refKey(g));
  }
  scriptAt(hash: Hex, at: Pos): NativeScript | null {
    const all = this.c.scripts;
    return all.find((s) => s.hash === hash && comparePos(s.at, at) <= 0)?.script ?? null;
  }
  groupAt(g: EventRef, at: Pos): GroupVersion | null {
    return this.versions(g).filter((v) => comparePos(v.at, at) <= 0).sort((a, b) => comparePos(b.at, a.at))[0] ?? null;
  }
  dissolvedAt(g: EventRef): Pos | null {
    return this.versions(g).find((v) => v.status === 'dissolved')?.at ?? null;
  }
  registeredAt(c: Credential, at: Pos): boolean {
    const rows = this.c.ledger.filter((l) => credKey(l.credential) === credKey(c) && comparePos(posOfCert(l), at) <= 0);
    return rows.sort((a, b) => comparePos(posOfCert(b), posOfCert(a)))[0]?.kind === 'reg';
  }
  memberScriptAt(c: Credential, at: Pos): NativeScript | null {
    return this.c.memberScripts.find((m) => credKey(m.credential) === credKey(c) && comparePos(m.at, at) <= 0)?.script ?? null;
  }
  firstUnregAfter(c: Credential, at: Pos): Pos | null {
    const rows = this.c.ledger.filter((l) => l.kind === 'unreg' && credKey(l.credential) === credKey(c) && comparePos(posOfCert(l), at) > 0);
    return rows.map(posOfCert).sort(comparePos)[0] ?? null;
  }
  instance(join: EventRef): StoredInstance | null {
    return this.c.instances.find((i) => refKey(i.joinId) === refKey(join)) ?? null;
  }
  latestInstance(g: EventRef, c: Credential): StoredInstance | null {
    return this.c.instances.filter((i) => refKey(i.group) === refKey(g) && credKey(i.member) === credKey(c))
      .sort((a, b) => comparePos(b.joinedAt, a.joinedAt))[0] ?? null;
  }
  missing(k: Keys): Keys {
    for (const s of keyStrings(k)) this.asked.add(s);
    const out = (s: string): boolean => !this.loaded.has(s);
    return {
      instances: k.instances.filter((r) => out(`i:${refKey(r)}`)),
      latestInstances: k.latestInstances.filter(([g, c]) => out(`l:${refKey(g)}|${credKey(c)}`)),
      groupsAt: k.groupsAt.filter(([g, p]) => out(`g:${refKey(g)}@${posKey(p)}`)),
      scriptsAt: k.scriptsAt.filter(([h, p]) => out(`s:${h}@${posKey(p)}`)),
      credentialAt: k.credentialAt.filter(([c, p]) => out(`c:${credKey(c)}@${posKey(p)}`)),
    };
  }
}

export const chainTx = (o: Parameters<typeof txIn>[0]): ChainTx => (txIn(o) as { kind: 'tx'; tx: ChainTx }).tx;
