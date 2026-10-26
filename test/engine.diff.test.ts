import { describe, expect, it } from 'vitest';
import {
  emptyCoverage, generateChain, generateSchedule, mergeCoverage, runSchedule,
} from '../src/conformance/index.js';
import { MemoryStore } from '../src/engine/memoryStore.js';
import { ALL_REASONS } from '../src/rules.js';

describe('incremental engine against replay', () => {
  it('equals replay over seeded chains and schedules', async () => {
    const cov = emptyCoverage();
    const seeds = Number(process.env.ENGINE_SEEDS ?? 200);
    const first = Number(process.env.ENGINE_SEED_FROM ?? 1);
    for (let seed = first; seed < first + seeds; seed++) {
      const chain = generateChain(seed);
      try {
        const r = await runSchedule(() => new MemoryStore(), chain, generateSchedule(seed, chain));
        mergeCoverage(cov, r.coverage);
      } catch (e) {
        if (e instanceof Error) e.message = `seed ${seed}: ${e.message}`;
        throw e;
      }
    }
    if (process.env.ENGINE_COVERAGE) console.log(JSON.stringify(cov, null, 1));
    for (const reason of ALL_REASONS) expect(cov.reasons[reason] ?? 0, reason).toBeGreaterThanOrEqual(20);
    for (const c of ['left', 'removed', 'retired', 'dissolved', 'tie:unreg-before-dissolve', 'tie:leave-before-dissolve']) {
      expect(cov.closes[c] ?? 0, c).toBeGreaterThan(0);
    }
    expect(cov.schedulesWithGBehindL).toBeGreaterThan(50);
    expect(cov.completedAfterRollback).toBeGreaterThan(0);
    expect(cov.rebuildsMidway).toBeGreaterThan(0);
    expect(cov.validShare).toBeGreaterThan(0.3);
  }, 300_000);
});
