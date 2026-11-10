import { describe, expect, it } from 'vitest';
import {
  emptyCoverage, generateChain, generateSchedule, mergeCoverage, runSchedule,
} from '../src/conformance/index.js';
import { MemoryStore } from '../src/engine/memoryStore.js';
import { nativeScriptHash } from '../src/hash.js';
import { bytesToHex } from '../src/hex.js';
import { nativeScriptFromScriptRef } from '../src/nativeScript.js';
import { ALL_REASONS } from '../src/rules.js';
import { scriptRefOf } from './helpers.js';

describe('generated chains', () => {
  it('carry member scripts as native and Plutus reference scripts in the script_ref form', () => {
    let native = 0;
    let plutus = 0;
    for (let seed = 1; seed <= 20; seed++) {
      for (const x of generateChain(seed)) {
        if (x.kind !== 'ledger') continue;
        for (const r of x.input.referenceScripts ?? []) {
          const inner = nativeScriptFromScriptRef(r);
          if (inner === null) {
            plutus += 1;
            continue;
          }
          native += 1;
          // The test helper form, which equals the script_ref the Evolution SDK writes.
          expect(bytesToHex(r)).toBe(bytesToHex(scriptRefOf(0, inner)));
          expect(nativeScriptHash(inner)).toBe(x.input.credential.hash);
        }
      }
    }
    expect(native).toBeGreaterThan(0);
    expect(plutus).toBeGreaterThan(0);
  });
});

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
    // Thresholds are shares of the schedule count, so a smaller or larger ENGINE_SEEDS
    // keeps them meaningful. At 200 seeds they are 20 distinct results per reason,
    // 150 schedules with G behind L and 40 cut checks.
    const n = cov.schedules;
    for (const reason of ALL_REASONS) expect(cov.reasons[reason] ?? 0, reason).toBeGreaterThanOrEqual(0.1 * n);
    for (const c of ['left', 'removed', 'retired', 'dissolved', 'tie:unreg-before-dissolve', 'tie:leave-before-dissolve']) {
      expect(cov.closes[c] ?? 0, c).toBeGreaterThan(0);
    }
    expect(cov.schedulesWithGBehindL).toBeGreaterThan(0.75 * n);
    expect(cov.completedAfterRollback).toBeGreaterThan(0);
    expect(cov.cutChecks).toBeGreaterThanOrEqual(0.2 * n);
    expect(cov.rebuildsMidway).toBeGreaterThan(0);
    expect(cov.validShare).toBeGreaterThan(0.3);
  }, 300_000);
});
