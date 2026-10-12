# drep-groups

Reference library for the DRep Groups CIP draft (metadata label 1695): payload and transaction decoding, native script evaluation and the registry state machine. Pure functions, no network.

Test vectors for other implementations: `vectors/vectors.json`.

## Usage

```ts
import { decodeTransaction, replay } from 'drep-groups';

const tx = decodeTransaction(cborBytes, { txHash, blockHeight, txIndex });
const state = replay([{ kind: 'tx', tx }, { kind: 'ledger', input: registration }]);
```

`replay` is pure. Give it every label 1695 transaction and every DRep registration and retirement of the credentials that appear in `join` events, in any order. Ledger inputs must come from transactions with `is_valid = true`. It sorts by chain order and drops duplicates. After a rollback, replay without the rolled back inputs.

`state.ignored` lists transactions whose payload did not count (phase-2 failure, payload rejected by the decoder), so tools can tell users why.

## Test vectors

`vectors/vectors.json` lists inputs and the expected groups, instances and per-event verdicts. Payloads are CBOR hex. Another implementation passes when it produces the same `groups` and `instances` and the same `valid` flag for every verdict. Reason texts are informative only.
