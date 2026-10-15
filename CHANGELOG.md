# Changelog

All notable changes to this package. Versions follow [semantic versioning](https://semver.org). While the CIP is a draft, minor versions may contain breaking changes.

## Unreleased

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
