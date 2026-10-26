# drep-groups

Reference implementation of **DRep Groups**, a draft Cardano standard for recording which DReps belong to which group, party or council, directly on chain.

A group publishes its rules in transaction metadata under label `8416`. DReps join and leave with their own signatures. Any indexer that follows the standard computes the same membership list from the chain alone, without trusting a website or a database.

This package holds the rules in code: it decodes the metadata, checks every signature against the group's policies and replays the chain into groups and memberships. Pure TypeScript, no network access, no platform dependency.

> **Status: draft.** The CIP is not submitted yet, metadata label `8416` will be registered in CIP-10 together with it, and the API can still change.

## What a group can do

- **Open groups**: any registered DRep can join, anyone can leave at any time.
- **Permissioned groups**: joining needs approval by the group's admission policy, leaving is always possible without anyone's consent.
- **Multisig from day one**: a group is controlled by a native script (for example 3 of 5 admins). A separate admission policy can approve and remove members with its own threshold.
- **Consent of listed admins**: every key a group names in a policy must sign once when it is added, so nobody can be shown as an admin without agreeing.
- **Profile**: name, description, website, logo, a link to the charter and optional payment addresses, stored as a CIP-100 document and referenced by hash.
- **Website verification**: a group can prove a domain through a well-known file.

Affiliation only. Groups do not vote together and membership never changes a delegation.

## How it works

Every action is an ordinary transaction with a small metadata payload. There is no smart contract, no token and no deposit.

| Event | Signed by | Effect |
|---|---|---|
| `create` | every key of the new policies | new open or permissioned group |
| `update` | control policy, plus every newly listed key | new policies or profile |
| `dissolve` | control policy | group closed for good, all memberships end |
| `join` | the DRep | member (open group) or pending request (permissioned) |
| `approve` | admission policy | pending request becomes a membership |
| `leave` | the DRep | membership or request ends, always allowed |
| `remove` | admission policy | membership or request ends (permissioned groups only) |

The rules this library enforces, in short:

- **Signatures come from the transaction**, the union of `required_signers` and the vkey witnesses. A key-based DRep must appear in `required_signers`, so its wallet signed knowingly.
- **Scripts must be on chain** at or before the event that uses them, published in the payload or, for script DReps, in their registration transaction. A cache can never change a verdict.
- **Chain order decides**: block height, position in the block, certificates before metadata events. DRep registrations and retirements are part of the replay, a retirement ends every membership of that DRep.
- **Control actions carry a sequence number**, so a stale multisig transaction cannot apply on top of a newer change.
- **Malformed data never stops an indexer**: invalid events are ignored one by one, decoding works without recursion, and deeply nested values cannot crash it.

## Install

```sh
npm install drep-groups
```

ESM only.

## Quick start

```ts
import { decodeTransaction, replay, type ChainInput } from 'drep-groups';

// 1. Every transaction with metadata label 8416, as full CBOR plus its position in the chain
const tx = decodeTransaction(cborBytes, { txHash, blockHeight, txIndex });

// 2. DRep registrations and retirements of every credential that appears in a join
const registration: ChainInput = {
  kind: 'ledger',
  input: { kind: 'reg', credential: { kind: 'key', hash: drepKeyHash }, txHash, blockHeight, txIndex, certIndex: 0 },
};

// 3. Replay in any order, the library sorts by chain order and drops duplicates
const state = replay([{ kind: 'tx', tx }, registration]);

state.groups;    // groups with mode, policies, profile anchor, seq and status
state.instances; // memberships and requests: pending, active or closed with a reason
state.verdicts;  // valid or invalid for every event, with a reason text
state.ignored;   // transactions whose payload did not count, and why
```

`replay` is pure. After a rollback, replay again without the rolled back inputs.

### Feeding it from Koios

Any chain source works. With the public Koios API the inputs come from three calls:

- `GET /tx_by_metalabel?_label=8416&_after_block_height=<cursor>` lists new transactions with the label.
- `POST /tx_cbor` with `{"_tx_hashes": [...]}` returns their full CBOR.
- `POST /tx_info` with the same hashes returns `tx_block_index`, the position inside the block.

DRep registrations and retirements come from `GET /drep_updates`, the position of each certificate again from `tx_info`.

## Incremental indexing

`replay` recomputes everything from all inputs. An indexer with a database can instead call `runEngine` after every sync: it applies only the new label transactions and credential inputs to your `Store`, in steps bounded by a budget, and recovers after rollbacks. `MemoryStore` is a complete in-memory implementation. A store of your own can run the contract checks of `drep-groups/conformance` (`runSchedule` with seeded chains), which compare the engine against `replay`.

```ts
import { MemoryStore, runEngine } from 'drep-groups';

const store = new MemoryStore();
store.ingestLabelTx(tx);                // chain inputs go in through the store
const lease = store.acquireLease('indexer');
const budget = { controlTxs: 50, controlBytes: 200_000, credentialUnits: 50, credentialInputs: 500, truncateRows: 1000, resetRows: 1000 };

let report;
do report = await runEngine(store, budget, lease);
while (report.more);
```

## API

| Function | Purpose |
|---|---|
| `decodeTransaction(cbor, position)` | full Conway transaction to a `ChainTx` (signers, validity interval, raw label 8416 payload, witness scripts) |
| `replay(inputs)` | chain inputs to a `RegistryState` |
| `decodePayload(bytes)` | one payload to its events and published scripts, `null` when the payload is ignored |
| `parseNativeScript(bytes)`, `evaluateNativeScript(script, ctx)`, `collectKeyHashes(script)` | native scripts with exact CBOR types and ledger semantics |
| `checkPaymentAddress(entry, network, scripts)` | checks a profile payment address: `invalid`, `declared` or `script-controlled` |
| `groupIdToBech32(ref)`, `groupIdFromBech32(s)` | display form of a group id, bech32 with prefix `group` |
| `nativeScriptHash(bytes)`, `keyHashOfVkey(vkey)` | Cardano hashes |
| `refKey(ref)`, `credKey(credential)`, `orderInputs(inputs)` | helpers for keys and ordering |

All types are exported, among them `ChainTx`, `LedgerInput`, `ChainInput`, `GroupState`, `Instance`, `EventVerdict` and `RegistryState`.

**Hex strings**: every hash passed in and returned is lowercase hex without a prefix. Hashes are compared as strings, so lowercase hex from other sources before passing it in.

**Ledger inputs** must come from transactions with `is_valid = true`. The caller guarantees this.

### Payment addresses

`checkPaymentAddress({ address, treasuryScript }, network, state.scripts)` returns a `status`:

- `invalid`: not a bech32 address, wrong network, a pointer address or not a payment address. Do not show it.
- `declared`: a valid base or enterprise address without a proven controller. `reason` says why a treasury claim did not hold.
- `script-controlled`: the payment credential is a script, it equals `treasuryScript` and the script is published on chain. `script` holds it for display, for example "3 of 5: Alice, Bob, ...".

`hasStake` is `false` for enterprise addresses, which cannot delegate their votes.

## Test vectors

`vectors/vectors.json` (also importable as `drep-groups/vectors/vectors.json`) holds 26 scenarios with inputs and expected results: open and permissioned lifecycles, the consent rule, policy rotation, retirement and re-registration, certificate ordering, script DReps, time locks, malformed payloads, duplicate keys and deeply nested data.

Payloads are CBOR hex, so the file works for any language. An implementation passes when it produces the same `groups` and `instances` and the same `valid` flag for every verdict. Reason texts are informative.

## Development

```sh
npm install
npm test           # unit tests, differential tests and test vectors
npm run typecheck
npm run build      # emits dist/
npm run vectors    # regenerates vectors/vectors.json from vectors/definitions.ts
```

Expected results in `vectors/definitions.ts` are written by hand from the specification. When a vector fails, check the case against the rules before changing either side.

## License

[Apache-2.0](LICENSE)

## Releasing

Releases are tag driven and staged:

1. Bump the version in a pull request with `npm version <patch|minor> --no-git-tag-version` and add a changelog entry.
2. After the squash merge, tag the merge commit `v<version>` and push the tag.
3. The release workflow checks the tag against `package.json` and `main`, runs the tests and stages the package on npm with provenance.
4. A maintainer approves the staged version on npmjs.com with 2FA. The workflow also creates the GitHub release.
