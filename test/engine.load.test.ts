// Load test: the work of one run depends on the new inputs and the budget, never on how
// much history is stored. Every shape is built at 1x, 10x and 100x, then the same new
// inputs are run in and the per run counters of the store are compared for exact equality.
import { describe, expect, it } from 'vitest';
import { MemoryStore } from '../src/engine/memoryStore.js';
import { runEngine } from '../src/engine/run.js';
import type { Budget, ChangeSet, CursorUpdate } from '../src/engine/types.js';
import type { ChainInput, ChainTx, Credential, LedgerInput } from '../src/types.js';
import { buildPayload, ev, hashOf, K, keyCred, ref, sig } from './helpers.js';

const MULTIPLIERS = [1, 10, 100] as const;
const TIMEOUT_MS = 60_000;

// The history is built with its own large budget, the measured runs use the two below.
const HISTORY: Budget = { controlTxs: 500, controlBytes: 1 << 24, credentialUnits: 500, credentialInputs: 5000, truncateRows: 1000, resetRows: 1000 };
const SINGLE: Budget = { controlTxs: 50, controlBytes: 1 << 20, credentialUnits: 50, credentialInputs: 1, truncateRows: 1000, resetRows: 1000 };
const DEFAULT: Budget = { controlTxs: 50, controlBytes: 1 << 20, credentialUnits: 50, credentialInputs: 500, truncateRows: 1000, resetRows: 1000 };

// Unique hashes from a counter: 32 byte tx hashes and 28 byte key hashes.
const hex = (n: number, bytes: number): string => n.toString(16).padStart(8, '0').repeat(Math.ceil((bytes * 2) / 8)).slice(0, bytes * 2);
const txHash = (n: number): string => hex(n + 1, 32);
const keyHash = (salt: number, n: number): string => hex(salt * 0x1000000 + n + 1, 28);

const CTL = sig(K(1));
const GROUP = ref(txHash(0), 0);
const FIRST_HEIGHT = 100;

// One block per input, so every tx and ledger row has its own position. A source hands out
// the next free block height and unique tx hashes.
class Source {
  private height = FIRST_HEIGHT;
  private counter = 1; // txHash(0) is the group
  readonly inputs: ChainInput[] = [];
  take(): { h: number; hash: string } {
    return { h: this.height++, hash: txHash(this.counter++) };
  }
  get top(): number {
    return this.height - 1;
  }
}

const createGroup = (): ChainInput => ({
  kind: 'tx',
  tx: {
    txHash: txHash(0), blockHeight: 10, txIndex: 0, isValid: true, invalidBefore: null, invalidHereafter: null,
    requiredSigners: [], witnessKeyHashes: [K(1)], payload: buildPayload([ev.create(0, hashOf(CTL), null)], [CTL]),
    payloadRepeated: false, witnessScripts: [],
  },
});

const txInput = (s: Source, o: { rs?: string[]; wk?: string[]; payload: Uint8Array }): ChainInput => {
  const { h, hash } = s.take();
  return {
    kind: 'tx',
    tx: {
      txHash: hash, blockHeight: h, txIndex: 0, isValid: true, invalidBefore: null, invalidHereafter: null,
      requiredSigners: o.rs ?? [], witnessKeyHashes: o.wk ?? [], payload: o.payload, payloadRepeated: false, witnessScripts: [],
    },
  };
};
const joinTx = (s: Source, member: string, signed = true): ChainInput =>
  txInput(s, { rs: signed ? [member] : [], payload: buildPayload([ev.join(GROUP, 'key', member)]) });
const updateTx = (s: Source, seq: number): ChainInput =>
  txInput(s, { wk: [K(1)], payload: buildPayload([ev.update(GROUP, seq, new Map())]) });
const ledgerRow = (s: Source, c: Credential, kind: 'reg' | 'unreg'): ChainInput => {
  const { h, hash } = s.take();
  const input: LedgerInput = { kind, credential: c, txHash: hash, blockHeight: h, txIndex: 0, certIndex: 0 };
  return { kind: 'ledger', input };
};

// What the fresh inputs of a batch must cause in the store, so a pass cannot be empty work.
interface Fresh { inputs: ChainInput[]; credentialInputs: number; verdicts: number }

interface History {
  inputs: ChainInput[];
  incomplete: Credential[];                // credentials whose input stays unready for good
  freshBatch: (s: Source, batch: number) => Fresh;
  top: number;
}

// 10 new members, each registered and then joining: 20 inputs, 20 credential inputs, 10 verdicts.
const freshJoins = (s: Source, batch: number): Fresh => {
  const inputs: ChainInput[] = [];
  for (let i = 0; i < 10; i++) {
    const m = keyHash(9, batch * 10 + i);
    inputs.push(ledgerRow(s, keyCred(m), 'reg'), joinTx(s, m));
  }
  return { inputs, credentialInputs: 20, verdicts: 10 };
};

interface Shape {
  name: string;
  // `n` is the multiplier. At 100x the counts are the ones of the load test brief.
  build: (n: number) => History;
}

const shapes: Shape[] = [
  {
    // One group with a long chain of versions, new updates and joins extend it.
    name: 'long version chain of one group',
    build: (n) => {
      const s = new Source();
      const inputs: ChainInput[] = [createGroup()];
      const length = 10 * n;
      for (let seq = 0; seq < length; seq++) inputs.push(updateTx(s, seq));
      return {
        inputs, incomplete: [], top: s.top,
        freshBatch: (src, batch) => {
          const base = length + batch * 10;
          const updates = Array.from({ length: 10 }, (_, i) => updateTx(src, base + i));
          return { inputs: updates, credentialInputs: 0, verdicts: 10 };
        },
      };
    },
  },
  {
    // A group with many members, new members join it.
    name: 'group with 5,000 members',
    build: (n) => {
      const s = new Source();
      const inputs: ChainInput[] = [createGroup()];
      for (let i = 0; i < 50 * n; i++) {
        const m = keyHash(1, i);
        inputs.push(ledgerRow(s, keyCred(m), 'reg'), joinTx(s, m));
      }
      return { inputs, incomplete: [], top: s.top, freshBatch: freshJoins };
    },
  },
  {
    // One credential with many registrations, new registrations alternate with unregistrations.
    name: 'credential with 500 registrations',
    build: (n) => {
      const s = new Source();
      const c = keyCred(keyHash(2, 0));
      const inputs: ChainInput[] = [createGroup()];
      const rows = 2 * Math.ceil(2.5 * n); // always even, so the history ends with an unregistration at every size
      for (let i = 0; i < rows; i++) inputs.push(ledgerRow(s, c, i % 2 === 0 ? 'reg' : 'unreg'));
      return {
        inputs, incomplete: [], top: s.top,
        freshBatch: (src, batch) => {
          const first = rows + batch * 10;
          const fresh = Array.from({ length: 10 }, (_, i) => ledgerRow(src, c, (first + i) % 2 === 0 ? 'reg' : 'unreg'));
          return { inputs: fresh, credentialInputs: 10, verdicts: 0 };
        },
      };
    },
  },
  {
    // A queue of events that stay stored and unapplied because their credentials are not complete.
    name: 'queue of 10,000 entries',
    build: (n) => {
      const s = new Source();
      const inputs: ChainInput[] = [createGroup()];
      const incomplete: Credential[] = [];
      for (let i = 0; i < 100 * n; i++) {
        const m = keyHash(3, i);
        incomplete.push(keyCred(m));
        inputs.push(joinTx(s, m));
      }
      return { inputs, incomplete, top: s.top, freshBatch: freshJoins };
    },
  },
  {
    // Joins without any signature naming fake keys, each one is applied and rejected.
    name: 'flood of 2,000 unsigned joins naming fake keys',
    build: (n) => {
      const s = new Source();
      const inputs: ChainInput[] = [createGroup()];
      for (let i = 0; i < 20 * n; i++) inputs.push(joinTx(s, keyHash(4, i), false));
      return { inputs, incomplete: [], top: s.top, freshBatch: freshJoins };
    },
  },
];

const rowCount = (c: ChangeSet): number =>
  c.scripts.length + c.memberScripts.length + c.versions.length + c.instances.length + c.verdicts.length
  + c.queued.length + c.txContexts.length + c.appliedQueue.length + c.effects.length;

// Records for every commit the number of units and the rows across all change set fields.
class RecordingStore extends MemoryStore {
  readonly commits: Array<{ units: number; rows: number }> = [];
  override async commit(units: Array<{ change: ChangeSet; cursor: CursorUpdate }>, lease: string): Promise<void> {
    await super.commit(units, lease);
    this.commits.push({ units: units.length, rows: units.reduce((n, u) => n + rowCount(u.change), 0) });
  }
}

const METHODS = ['nextLabelTxs', 'readyCredentials', 'load'] as const;
interface RunWork { rows: Record<(typeof METHODS)[number], number>; calls: Record<(typeof METHODS)[number], number>; commits: Array<{ units: number; rows: number }> }

async function ingest(s: MemoryStore, inputs: ChainInput[]): Promise<void> {
  for (const x of inputs) {
    if (x.kind === 'tx') s.ingestLabelTx(x.tx as ChainTx);
    else s.ingestLedgerRow(x.input);
  }
}

async function runUntilDone(s: RecordingStore, lease: string, budget: Budget): Promise<RunWork[]> {
  const runs: RunWork[] = [];
  for (let i = 0; i < 1000; i++) {
    const rows0 = { ...s.stats.rowsReturned };
    const calls0 = { ...s.stats.calls };
    const commits0 = s.commits.length;
    const report = await runEngine(s, budget, lease);
    const pick = (from: Record<string, number>, before: Record<string, number>) =>
      Object.fromEntries(METHODS.map((m) => [m, (from[m] ?? 0) - (before[m] ?? 0)])) as RunWork['rows'];
    runs.push({ rows: pick(s.stats.rowsReturned, rows0), calls: pick(s.stats.calls, calls0), commits: s.commits.slice(commits0) });
    if (!report.more) return runs;
  }
  throw new Error('runEngine did not settle');
}

interface Measured { single: RunWork[]; normal: RunWork[] }

async function measure(shape: Shape, n: number): Promise<Measured> {
  const history = shape.build(n);
  const s = new RecordingStore();
  const lease = s.acquireLease('load');
  for (const c of history.incomplete) s.setComplete(c, false);
  await ingest(s, history.inputs);
  s.setFrontiers({ L: history.top, R: history.top });
  await runUntilDone(s, lease, HISTORY);
  expect(s.snapshot().frontiers.G.blockHeight).toBe(history.top); // the history is fully applied

  // From here on only the new inputs count.
  s.stats.calls = {};
  s.stats.rowsReturned = {};
  const source = new Source();
  // Continue the block numbering above the history so the new inputs sort after it.
  while (source.top < history.top) source.take();
  const before = s.snapshot();
  const out: Partial<Measured> = {};
  let credentialInputs = 0;
  let verdicts = 0;
  for (const [batch, key, budget] of [[0, 'single', SINGLE], [1, 'normal', DEFAULT]] as const) {
    const fresh = history.freshBatch(source, batch);
    credentialInputs += fresh.credentialInputs;
    verdicts += fresh.verdicts;
    await ingest(s, fresh.inputs);
    s.setFrontiers({ L: source.top, R: source.top });
    out[key] = await runUntilDone(s, lease, budget);
  }
  const after = s.snapshot();
  // The measured runs did real work: every fresh input was applied.
  expect(after.verdicts.length - before.verdicts.length).toBe(verdicts);
  expect(s.stats.rowsReturned.readyCredentials).toBe(credentialInputs);
  expect(after.frontiers.G.blockHeight).toBe(source.top);
  if (credentialInputs > 0) expect(out.single?.length).toBeGreaterThan(1); // one credential input per run needs several runs
  return out as Measured;
}

describe('per run work does not depend on the stored history', () => {
  for (const shape of shapes) {
    it(`${shape.name}: counters equal at 1x, 10x and 100x`, async () => {
      const results = new Map<number, Measured>();
      for (const n of MULTIPLIERS) results.set(n, await measure(shape, n));
      const base = results.get(1) as Measured;
      for (const n of MULTIPLIERS) {
        // Rows returned per method per run and the commit sizes, run by run.
        expect(results.get(n), `${n}x against 1x`).toEqual(base);
      }
    }, TIMEOUT_MS);
  }
});
