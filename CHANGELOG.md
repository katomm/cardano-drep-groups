# Changelog

All notable changes to this package. Versions follow [semantic versioning](https://semver.org). While the CIP is a draft, minor versions may contain breaking changes.

## 0.5.0 (2026-11-10)

- **Group id display form** uses a one byte index as in CIP-0129 (breaking for stored ids): 33 bytes `tx_hash || uint8(event_index)`. `groupIdToBech32` throws for an index above 255 and `groupIdFromBech32` rejects the 34 byte form. The on-chain data is unchanged.
- **Consent only from `required_signers`** (breaking): a key that consents (listed in a new policy, resigning, or a key-based DRep joining) must be in `required_signers`, a vkey witness alone no longer counts. The rule applies per role, so a key that moves from admission into control signs again, and a key that resigned from a role counts as new when it is listed again. New reasons: `listed key did not sign explicitly`, `key new to its role did not sign explicitly`.
- **Signature-free policies are rejected** (breaking): a `create` or `update` that sets a control or admission policy satisfiable without a signature, for example by a time lock alone, is invalid (`control policy needs no signature`, `admission policy needs no signature`). New export `satisfiableWithoutSignature`.
- **`resign` event** (tag 7, `[7, event_ref, hash28]`): a key leaves every role whose policy lists it, signed by that key in `required_signers`. Tags 0 to 6 decode as before and the wire format version stays 1. `GroupState` and `GroupVersion` gained two required fields, `resignedControl` and `resignedAdmission` (lowercase hex, deduplicated, ascending), which breaks code that builds these objects. New reasons: `key not listed in any role`, `resigning key did not sign explicitly`, decoder reason `resign: bad shape`. A resign bumps `seq`.
- **Reference scripts for script DReps**: the member script can come from a native script in a reference script of an output that the registration transaction spends or uses as a reference input. New `LedgerInput.referenceScripts`, `memberScriptWitness(credential, witnessScripts, referenceScripts?)`, `decodeTxRefs` (a collateral return output sits at index `outputs.length`) and `nativeScriptFromScriptRef`. Plutus reference scripts resolve nothing.
- **Payment script field** (breaking): the profile term and the `checkPaymentAddress` entry field `treasuryScript` are now `paymentScript`, with no alias. The reason texts say "payment script".
- **Test vectors**: 48 scenarios, 13 new ones for consent, signature-free policies, resign and reference scripts. Two cases were renamed (`consent by witness only`, `a witness signature next to a required_signers key gives no consent`) because their inputs are invalid now. A `referenceScriptsHex` field on ledger inputs carries reference scripts. The devnet suite has 24 scenarios.
- **README**: consent, resign, reference scripts, the 33 byte id and the vector count.

## 0.4.0 (2026-11-10)

- **Group id prefix** (breaking): the bech32 display form of a group id uses the prefix `drep_group` instead of `group`, following the CIP-0005 naming of `drep_script` and `cc_hot`. `groupIdFromBech32` rejects the old prefix. The bytes and the on-chain data are unchanged.

## 0.3.1 (2026-11-09)

- **Anchor URL chunks** are concatenated unchanged: a leading U+FEFF at the start of a chunk is kept instead of being dropped by the text decoder, as the CIP text requires.
- **Test vectors** now compare the full profile anchor (`profileHash` next to `profileUrl`), and 10 new cases pin the anchor URL across chunks, the limits at and above their bounds (64 and 65 events, 8 and 9 script entries, 64 and 65 script nodes, depth 8 and 9), duplicate payload key equality (`0x09` against `0x1809`, `0x20` against `0x3800`) and indefinite length payload maps and event arrays.
- **README**: group members may agree to vote together, each DRep still casts its own vote.

## 0.3.0 (2026-11-03)

- **`encodePayload`**: builds the label 8416 payload bytes from events and scripts, with local references, 64 byte chunking of long anchor URLs and scripts, and the decoder's limits enforced. Throws `EncodeError`. `encodeNativeScript`, `encodeCbor`, `chunkText` and `chunkBytes` are exported with it.
- **`majorityScript`**: n of k native script over lowercased, deduplicated and ascending sorted key hashes, so one key set gives one script hash.
- **`inspectTransaction`**: reads the facts a signer needs from transaction CBOR, such as whether the auxiliary data hash matches the attached metadata, how many label 8416 payloads it holds and whether it also carries certificates, withdrawals, votes or proposals.
- **`previewTransaction`**: judges every event of an unsubmitted transaction with the engine's own rules over committed state and writes nothing. Exported with `PreviewDeps`, `PreviewEvent` and `Preview`.
- **JSON-LD context** `context/drep-groups-v1.jsonld` for the group profile document, shipped in the package.
- **README**: new section "Building transactions".

## 0.2.0 (2026-10-26)

- **Limits** (breaking for oversized payloads): at most 64 events and 8 script entries per payload, at most 64 nodes and nesting depth 8 per payload script. More than 64 events ignores the whole payload, more than 8 script entries ignores only the scripts, an oversized script is skipped on its own. Exported as `MAX_EVENTS_PER_PAYLOAD`, `MAX_SCRIPT_ENTRIES`, `MAX_SCRIPT_NODES`, `MAX_SCRIPT_DEPTH` and `scriptComplexity`. Registration witness scripts have no complexity limit.
- **Full positions** (breaking type change, allowed while the CIP is a draft): `Position` gains `phase` and `index`, so certificates, payload scripts and events of one transaction have a total order. New helpers `Pos`, `comparePos`, `endOf`, `posOfCert`, `posOfScripts` and `posOfEvent`.
- **Attributed verdicts** (breaking type change, `EventVerdict` gains required fields): every verdict carries its position (`at`), its group and its subject credential. `ALL_REASONS` lists every rejection reason, and `effectiveClose` is the single place that decides when a membership ends.
- **Incremental engine**: `runEngine` applies new chain inputs to a `Store` in bounded steps instead of replaying everything, with recovery after rollbacks and forks. `replay` stays the reference semantics.
- **`MemoryStore`**: in-memory `Store` implementation. Its `snapshot()` returns a `MemoryStoreSnapshot`, the `EngineSnapshot` the conformance driver reads plus the store's recovery slots, completeness flags and call counters.
- **`memberScriptWitness`**: the member script a script DRep's registration proves, the same check `replay` and the engine use.
- **`drep-groups/conformance`** subpath: seeded chain and schedule generators and `runSchedule`, which checks any `Store` against `replay` across interruptions, lease expiry and rollbacks.

## 0.1.1 (2026-10-16)

- `parseNativeScript` reads the bytes in one linear pass. Deeply nested scripts parsed in time quadratic in their depth before, so a crafted script of 5000 levels cost seconds of CPU.

## 0.1.0 (2026-10-15)

First version of the reference library for the DRep Groups CIP draft.

- Group events under transaction metadata label `8416`: `create`, `update`, `dissolve`, `join`, `approve`, `leave`, `remove`, with local references to earlier events of the same transaction.
- `decodeTransaction` turns full Conway transaction CBOR into a `ChainTx`, `decodePayload` decodes one payload in three layers. Both read by span with an explicit stack, so deeply nested data cannot crash them.
- Native scripts parsed byte exact against the Conway CDDL and evaluated against the signer set (`required_signers` plus vkey witnesses) and the validity interval.
- `replay` computes groups, memberships and per-event verdicts in chain order, including the consent rule for listed admins, sequence numbers for control actions, DRep registrations and retirements, and scripts known only from on-chain publication.
- `checkPaymentAddress` and `groupIdToBech32` / `groupIdFromBech32` for profiles and display.
- Test vectors in `vectors/vectors.json` for other implementations.
- Devnet suite (`npm run test:devnet`, needs Docker) that checks the ledger assumptions on a real Conway ledger.
