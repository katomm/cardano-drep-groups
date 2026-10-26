// Type layer of the incremental engine: store contract, units of work and budgets.
import type { Pos } from '../position.js';
import type { CloseReason } from '../effective.js';
import type { GroupVersion, StoredInstance } from '../rules.js';
import type {
  ChainTx, Credential, DecodedEvent, EventRef, EventVerdict, Hex, LedgerInput, NativeScript, PublishedScript,
} from '../types.js';

export type { Pos, StoredInstance, GroupVersion, CloseReason };

export interface Keys {
  instances: EventRef[];                          // join refs named by approve, leave, remove
  latestInstances: Array<[EventRef, Credential]>; // the latest instance of (group, credential)
  groupsAt: Array<[EventRef, Pos]>;               // one version per (group, position), plus the dissolve version
  scriptsAt: Array<[Hex, Pos]>;
  credentialAt: Array<[Credential, Pos]>;         // registered?, member script, first unreg after
}
export interface View {
  scriptAt(hash: Hex, at: Pos): NativeScript | null;
  groupAt(group: EventRef, at: Pos): GroupVersion | null;
  dissolvedAt(group: EventRef): Pos | null;        // the machine counts it only when <= q
  registeredAt(c: Credential, at: Pos): boolean;
  memberScriptAt(c: Credential, at: Pos): NativeScript | null;
  firstUnregAfter(c: Credential, at: Pos): Pos | null;
  instance(join: EventRef): StoredInstance | null; // stored row, independent of p
  latestInstance(group: EventRef, c: Credential): StoredInstance | null;
  missing(keys: Keys): Keys;                       // keys the view was not loaded for
}
export type AttributedVerdict = EventVerdict; // carries at, group and subject since Task 2
export interface QueuedEvent { subject: Credential; at: Pos; group: EventRef | null; txHash: Hex; event: DecodedEvent }
export interface TxContext { signers: Hex[]; requiredSigners: Hex[]; invalidBefore: bigint | null; invalidHereafter: bigint | null }
export type CredentialInput = { kind: 'event'; q: QueuedEvent; tx: TxContext } | { kind: 'ledger'; at: Pos; input: LedgerInput };
export type AggregateEffect =
  | { kind: 'instanceCreated'; instance: StoredInstance }
  | { kind: 'instanceApproved'; join: EventRef; at: Pos }
  | { kind: 'instanceClosed'; join: EventRef; at: Pos; reason: 'left' | 'removed' }
  | { kind: 'groupDissolved'; group: EventRef; at: Pos }
  | { kind: 'credentialRetired'; credential: Credential; at: Pos };
export interface ChangeSet {
  scripts: Array<{ hash: Hex; script: NativeScript; bytes: Uint8Array; at: Pos }>;   // insert when absent
  memberScripts: Array<{ credential: Credential; script: NativeScript; bytes: Uint8Array; at: Pos }>; // insert when absent
  versions: GroupVersion[];
  instances: StoredInstance[];
  verdicts: AttributedVerdict[];            // only verdicts with a group
  queued: QueuedEvent[];
  txContexts: Array<{ txHash: Hex; context: TxContext }>;
  appliedQueue: EventRef[];
  effects: AggregateEffect[];
}
export interface StoredLabelTx { tx: ChainTx; bytes: number } // position from tx, markers are never returned
export interface RoutedEvent { ref: EventRef; at: Pos; decoded: DecodedEvent; plane: 'control' | 'membership' | 'orphan'; subject: Credential | null }
export interface Routed { scripts: PublishedScript[]; events: RoutedEvent[]; joinMembers: Credential[]; foreignJoins: EventRef[] }
export type CursorUpdate = { kind: 'group'; G: Pos } | { kind: 'credential'; credential: Credential; appliedThrough: Pos };
export interface Budget { controlTxs: number; controlBytes: number; credentialUnits: number; credentialInputs: number; truncateRows: number; resetRows: number }
export interface RunReport { phase: 'recovery' | 'normal'; recovery: Recovery | null; controlTxs: number; units: number; inputs: number; G: Pos | null; more: boolean }
export type Recovery = { kind: 'truncate'; above: number } | { kind: 'rebuild' } | { kind: 'fork' };
export interface Frontiers { L: number; R: number | null; G: Pos }
export interface RecoveryState { first: Recovery | null; then: { kind: 'truncate'; above: number } | null }
export interface ReadyCredential { c: Credential; inputs: CredentialInput[]; more: boolean }
export interface Store {
  load(keys: Keys, overlay: ChangeSet[]): Promise<View>;
  commit(units: Array<{ change: ChangeSet; cursor: CursorUpdate }>, lease: string): Promise<void>; // atomic
  // Txs strictly after `after` and before endOf(L), at most maxTxs, stopping before the first tx that would exceed
  // maxBytes unless the page is still empty (a single oversized tx is returned alone). `done` is true when no stored
  // label tx is left before endOf(L) after this page.
  nextLabelTxs(after: Pos, L: number, maxTxs: number, maxBytes: number): Promise<{ txs: StoredLabelTx[]; done: boolean }>;
  queuedJoins(refs: EventRef[], overlay: ChangeSet[]): Promise<Map<string, DecodedEvent | 'ignored'>>; // keyed by refKey, store plus the queued entries of the overlay
  readyCredentials(maxUnits: number, maxInputs: number, upTo: { G: Pos; R: number | null }): Promise<ReadyCredential[]>; // bound min(G, END(R))
  frontiers(): Promise<Frontiers>;
  pendingRecovery(): Promise<Recovery | null>;     // the first slot of RecoveryState
  openRecovery(r: Recovery, lease: string): Promise<void>; // stores mergeRecovery(current, r)
  finishRecovery(lease: string): Promise<void>;     // pops the first slot when its step reported done
  truncateStep(above: number, budget: number, lease: string): Promise<'more' | 'done'>;
  resetStep(mode: 'rebuild' | 'fork', budget: number, lease: string): Promise<'more' | 'done'>;
}
export class LeaseLostError extends Error {}
