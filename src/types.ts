// Domain types of the DRep Groups protocol (spec Part A). Hex strings are lowercase.
import type { Pos } from './position.js';

export type { Pos } from './position.js';
export type Hex = string;
export interface EventRef { txHash: Hex; index: number }
export type RefLike = EventRef | { local: number };
export interface Credential { kind: 'key' | 'script'; hash: Hex }
export interface Anchor { url: string; dataHash: Hex }
export type GroupMode = 'open' | 'permissioned';
export interface UpdateChanges { control?: Hex; admission?: Hex; profile?: Anchor }
export type GroupEvent =
  | { tag: 'create'; mode: GroupMode; control: Hex; admission: Hex | null; profile: Anchor | null }
  | { tag: 'update'; group: RefLike; seq: bigint; changes: UpdateChanges }
  | { tag: 'dissolve'; group: RefLike; seq: bigint }
  | { tag: 'join'; group: RefLike; member: Credential }
  | { tag: 'approve' | 'leave' | 'remove'; join: RefLike };
export type DecodedEvent = { ok: true; event: GroupEvent } | { ok: false; reason: string };
export type NativeScript =
  | { type: 'sig'; keyHash: Hex }
  | { type: 'all'; scripts: NativeScript[] }
  | { type: 'any'; scripts: NativeScript[] }
  | { type: 'nOfK'; n: bigint; scripts: NativeScript[] } // n is int64, may be negative
  | { type: 'after'; slot: bigint }
  | { type: 'before'; slot: bigint };
export interface PublishedScript { hash: Hex; bytes: Uint8Array; script: NativeScript }
export interface DecodedPayload { events: DecodedEvent[]; scripts: PublishedScript[] }
export interface EvalContext { signers: ReadonlySet<Hex>; invalidBefore: bigint | null; invalidHereafter: bigint | null }

export interface TxPosition { txHash: Hex; blockHeight: number; txIndex: number }
export type Position = Pos;
export interface ChainTx extends TxPosition {
  isValid: boolean;
  invalidBefore: bigint | null;    // body field 8
  invalidHereafter: bigint | null; // body field 3
  requiredSigners: Hex[];          // body field 14
  witnessKeyHashes: Hex[];         // blake2b-224 of each vkey in witness field 0
  payload: Uint8Array | undefined; // raw label 8416 metadatum bytes
  payloadRepeated: boolean;        // label 8416 appears more than once, payload is then undefined
  witnessScripts: Uint8Array[];    // raw bytes of witness field 1 native scripts
}
// Only certificates of transactions with is_valid = true may be passed in.
export interface LedgerInput {
  kind: 'reg' | 'unreg';
  credential: Credential;
  txHash: Hex;
  blockHeight: number;
  txIndex: number;
  certIndex: number;
  witnessScripts?: Uint8Array[]; // raw witness scripts of the reg_drep tx, for script DReps
}
export type ChainInput = { kind: 'tx'; tx: ChainTx } | { kind: 'ledger'; input: LedgerInput };
export interface GroupState {
  id: EventRef; mode: GroupMode; control: Hex; admission: Hex | null; profile: Anchor | null;
  seq: bigint; status: 'active' | 'dissolved'; createdAt: Position; profileSetAt: Position | null;
}
export type InstanceReason = 'left' | 'removed' | 'retired' | 'dissolved';
export interface Instance {
  joinId: EventRef; group: EventRef; member: Credential;
  state: 'pending' | 'active' | 'closed'; reason: InstanceReason | null;
  joinedAt: Position; approvedAt: Position | null; closedAt: Position | null;
}
// group and subject are informative attribution, null when the event resolves to no
// group or instance that exists at its position.
export interface EventVerdict {
  ref: EventRef; tag: GroupEvent['tag'] | null; valid: boolean; reason: string | null;
  at: Pos; group: EventRef | null; subject: Credential | null;
}
export interface IgnoredTx { txHash: Hex; reason: 'phase-2 invalid' | 'payload rejected' | 'label repeated' }
export interface RegistryState {
  groups: GroupState[];
  instances: Instance[];
  verdicts: EventVerdict[];
  ignored: IgnoredTx[];
  scripts: Map<Hex, NativeScript>; // every policy script published so far
}
