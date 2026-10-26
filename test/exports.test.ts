import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { DriverStore } from '../src/conformance/index.js';
import * as root from '../src/index.js';
import type { EngineSnapshot, Store } from '../src/index.js';

// Type-level proof: the snapshot type reachable from the root types the conformance driver store.
type SnapshotOfDriver = Awaited<ReturnType<DriverStore['snapshot']>>;
const sameType: (a: SnapshotOfDriver) => EngineSnapshot = (a) => a;
const storeIsDriverStore: (s: DriverStore) => Store = (s) => s;

describe('package surface', () => {
  it('LIBRARY_VERSION equals the package.json version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(root.LIBRARY_VERSION).toBe(pkg.version);
  });

  it('exports the limits, positions, engine and helpers from the root', () => {
    expect(root.MAX_EVENTS_PER_PAYLOAD).toBe(64);
    expect(root.MAX_SCRIPT_ENTRIES).toBe(8);
    expect(root.MAX_SCRIPT_NODES).toBe(64);
    expect(root.MAX_SCRIPT_DEPTH).toBe(8);
    for (const fn of [
      root.scriptComplexity, root.comparePos, root.endOf, root.posOfCert, root.posOfScripts,
      root.posOfEvent, root.effectiveClose, root.runEngine, root.MemoryStore, root.classifyNewInput,
      root.routeTx, root.LazyWorld, root.applyControl, root.applyCredential, root.replay,
    ]) expect(typeof fn).toBe('function');
    expect(root.ALL_REASONS.length).toBeGreaterThan(0);
  });

  it('keeps the type-level checks referenced', () => {
    expect(typeof sameType).toBe('function');
    expect(typeof storeIsDriverStore).toBe('function');
  });
});
