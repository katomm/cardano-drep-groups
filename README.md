# drep-groups

Reference library for the DRep Groups CIP draft (metadata label 1695): payload and transaction decoding, native script evaluation and the registry state machine. Pure functions, no network.

Test vectors for other implementations: `vectors/vectors.json`, also importable as `drep-groups/vectors/vectors.json`.

## Usage

```ts
import { decodeTransaction, replay } from 'drep-groups';

const tx = decodeTransaction(cborBytes, { txHash, blockHeight, txIndex });
const state = replay([{ kind: 'tx', tx }, { kind: 'ledger', input: registration }]);
```

`replay` is pure. Give it every label 1695 transaction and every DRep registration and retirement of the credentials that appear in `join` events, in any order. Ledger inputs must come from transactions with `is_valid = true`. It sorts by chain order and drops duplicates. After a rollback, replay without the rolled back inputs.

`state.ignored` lists transactions whose payload did not count (phase-2 failure, payload rejected by the decoder, label 1695 present more than once), so tools can tell users why.

Decoding reads the CBOR by span with an explicit stack and never recurses on data depth, so a deeply nested value under another metadata label or an unknown payload key cannot stop an ingest.

### Hex strings

All hashes passed in and returned are lowercase hex without a prefix: `txHash` in positions and ledger inputs, `requiredSigners` and `witnessKeyHashes` of a `ChainTx`, credential hashes, policy and script hashes. Hashes are compared as strings, so normalize hex from other sources with `.toLowerCase()` before passing it in.

### Group ids

`groupIdToBech32({ txHash, index })` gives the display form of a group id (spec A6): bech32 with prefix `group` over the 32 byte tx hash and the event index as uint16 big endian. It throws when the index is outside 0 to 65535 or the hash is not 32 bytes. `groupIdFromBech32(s)` reverses it and throws on another prefix or length.

### Payment addresses

`checkPaymentAddress({ address, treasuryScript }, network, state.scripts)` checks one `paymentAddresses` entry of a group profile (spec A6). `network` is `'mainnet'` or `'testnet'`. The result has a `status`:

- `invalid`: not a bech32 address, wrong network, a pointer address or not a payment address. Tools must not show it.
- `declared`: a valid base or enterprise address without a proven controller. `reason` says why the treasury claim did not hold, if one was made.
- `script-controlled`: the payment credential is a script, it equals `treasuryScript` and that script is resolved in `scripts`. `script` holds the parsed native script for display.

`hasStake` is false for enterprise addresses, which have no vote delegation.

## Test vectors

`vectors/vectors.json` lists inputs and the expected groups, instances and per-event verdicts. Payloads are CBOR hex. Another implementation passes when it produces the same `groups` and `instances` and the same `valid` flag for every verdict. Reason texts are informative only.
