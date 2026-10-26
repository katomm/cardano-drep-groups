# Changelog

All notable changes to this package. Versions follow [semantic versioning](https://semver.org). While the CIP is a draft, minor versions may contain breaking changes.

## 0.2.0

- **Limits** (breaking for oversized payloads): at most 64 events and 8 script entries per payload, at most 64 nodes and nesting depth 8 per payload script. More than 64 events ignores the whole payload, more than 8 script entries ignores only the scripts, an oversized script is skipped on its own. Exported as `MAX_EVENTS_PER_PAYLOAD`, `MAX_SCRIPT_ENTRIES`, `MAX_SCRIPT_NODES`, `MAX_SCRIPT_DEPTH` and `scriptComplexity`. Registration witness scripts have no complexity limit.
- **Full positions** (breaking type change, allowed while the CIP is a draft): `Position` gains `phase` and `index`, so certificates, payload scripts and events of one transaction have a total order. New helpers `Pos`, `comparePos`, `endOf`, `posOfCert`, `posOfScripts` and `posOfEvent`.
- **Attributed verdicts**: every verdict names the rule that decided it, `ALL_REASONS` lists the reasons and `effectiveClose` is the single place that decides when a membership ends.
- **Incremental engine**: `runEngine` applies new chain inputs to a `Store` in bounded steps instead of replaying everything, with recovery after rollbacks and forks. `replay` stays the reference semantics.
- **`MemoryStore`**: in-memory `Store` implementation with `EngineSnapshot` for inspection.
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
