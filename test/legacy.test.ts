import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type ChainInput, replay } from '../src/index.js';

// Replays exported chain history with the current library and compares it with the output
// of drep-groups 0.4.0. The fixtures live outside the repository: set DREP_GROUPS_LEGACY_DIR
// to a folder with <name>.json (ChainInput[] as JSON) and <name>.expected.json.
const dir = process.env.DREP_GROUPS_LEGACY_DIR;

const fromHex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
const toHex = (u: Uint8Array): string => Buffer.from(u).toString('hex');

/* biome-ignore lint/suspicious/noExplicitAny: raw fixture JSON */
type Raw = any;

function rebuild(raw: Raw[]): ChainInput[] {
  return raw.map((x): ChainInput => {
    if (x.kind === 'tx') {
      const t = x.tx;
      return {
        kind: 'tx',
        tx: {
          ...t,
          invalidBefore: t.invalidBefore == null ? null : BigInt(t.invalidBefore),
          invalidHereafter: t.invalidHereafter == null ? null : BigInt(t.invalidHereafter),
          payload: t.payload == null ? undefined : fromHex(t.payload),
          witnessScripts: t.witnessScripts.map(fromHex),
        },
      };
    }
    return { kind: 'ledger', input: { ...x.input, witnessScripts: x.input.witnessScripts.map(fromHex) } };
  });
}

// Same serialization as the script that produced the expected files.
function serialize(s: ReturnType<typeof replay>): Raw {
  return JSON.parse(
    JSON.stringify(
      { ...s, scripts: [...s.scripts.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([h, sc]) => [h, sc]) },
      (_k, v) =>
        typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? toHex(v) : v instanceof Set ? [...v].sort() : v,
    ),
  );
}

const names =
  dir && existsSync(dir)
    ? readdirSync(dir)
        .filter((f) => f.endsWith('.json') && !f.endsWith('.expected.json'))
        .map((f) => f.slice(0, -'.json'.length))
    : [];

describe.skipIf(!dir)('legacy replay', () => {
  it('finds fixtures', () => {
    expect(names.length).toBeGreaterThan(0);
  });

  for (const name of names) {
    it(`${name}: 0.5.0 judges the history as 0.4.0 did`, () => {
      const inputs = rebuild(JSON.parse(readFileSync(join(dir as string, `${name}.json`), 'utf8')));
      const expected = JSON.parse(readFileSync(join(dir as string, `${name}.expected.json`), 'utf8'));
      const actual = serialize(replay(inputs));

      for (const g of actual.groups) {
        expect(g.resignedControl, 'resignedControl').toEqual([]);
        expect(g.resignedAdmission, 'resignedAdmission').toEqual([]);
        // biome-ignore lint/performance/noDelete: drop the two new fields before comparing
        delete g.resignedControl;
        // biome-ignore lint/performance/noDelete: drop the two new fields before comparing
        delete g.resignedAdmission;
      }

      expect(actual.groups.length).toBe(expected.groups.length);
      expect(actual.instances.length).toBe(expected.instances.length);
      expect(actual.verdicts.length).toBe(expected.verdicts.length);
      expect(actual.verdicts).toEqual(expected.verdicts);
      expect(actual.instances).toEqual(expected.instances);
      expect(actual.groups).toEqual(expected.groups);
      expect(actual).toEqual(expected);
    });
  }
});
