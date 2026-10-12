import { readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '../src/hex.js';
import { credKey, refKey, replay } from '../src/state.js';
import type { ChainInput, RegistryState } from '../src/types.js';
import { VECTORS, type VectorDef } from '../vectors/definitions.js';

const FILE = new URL('../vectors/vectors.json', import.meta.url);

function serialize(defs: VectorDef[]): unknown {
  return {
    version: 1,
    compare: 'groups and instances exactly, verdicts by ref and valid. reason texts are informative.',
    vectors: defs.map((d) => ({
      name: d.name,
      inputs: d.inputs.map((x) =>
        x.kind === 'tx'
          ? {
              kind: 'tx', txHash: x.tx.txHash, blockHeight: x.tx.blockHeight, txIndex: x.tx.txIndex, isValid: x.tx.isValid,
              invalidBefore: x.tx.invalidBefore === null ? null : x.tx.invalidBefore.toString(),
              invalidHereafter: x.tx.invalidHereafter === null ? null : x.tx.invalidHereafter.toString(),
              requiredSigners: x.tx.requiredSigners, witnessKeyHashes: x.tx.witnessKeyHashes,
              payloadHex: x.tx.payload ? bytesToHex(x.tx.payload) : null, witnessScriptsHex: x.tx.witnessScripts.map(bytesToHex),
            }
          : {
              kind: 'ledger', type: x.input.kind, credential: x.input.credential, txHash: x.input.txHash,
              blockHeight: x.input.blockHeight, txIndex: x.input.txIndex, certIndex: x.input.certIndex,
              witnessScriptsHex: (x.input.witnessScripts ?? []).map(bytesToHex),
            },
      ),
      expect: d.expect,
    })),
  };
}

// Rebuilds chain inputs from the JSON form, the way another implementation would.
// biome-ignore lint/suspicious/noExplicitAny: JSON input
function fromJson(inputs: any[]): ChainInput[] {
  return inputs.map((x) =>
    x.kind === 'tx'
      ? {
          kind: 'tx',
          tx: {
            txHash: x.txHash, blockHeight: x.blockHeight, txIndex: x.txIndex, isValid: x.isValid,
            invalidBefore: x.invalidBefore === null ? null : BigInt(x.invalidBefore),
            invalidHereafter: x.invalidHereafter === null ? null : BigInt(x.invalidHereafter),
            requiredSigners: x.requiredSigners, witnessKeyHashes: x.witnessKeyHashes,
            payload: x.payloadHex === null ? undefined : hexToBytes(x.payloadHex),
            witnessScripts: x.witnessScriptsHex.map(hexToBytes),
          },
        }
      : {
          kind: 'ledger',
          input: {
            kind: x.type, credential: x.credential, txHash: x.txHash, blockHeight: x.blockHeight, txIndex: x.txIndex,
            certIndex: x.certIndex, witnessScripts: x.witnessScriptsHex.map(hexToBytes),
          },
        },
  );
}

function summarize(s: RegistryState) {
  return {
    groups: s.groups.map((g) => ({
      id: refKey(g.id), status: g.status, seq: g.seq.toString(), mode: g.mode,
      control: g.control, admission: g.admission, profileUrl: g.profile ? g.profile.url : null,
    })),
    instances: s.instances.map((i) => ({ joinId: refKey(i.joinId), group: refKey(i.group), member: credKey(i.member), state: i.state, reason: i.reason })),
    verdicts: s.verdicts.map((v) => ({ ref: refKey(v.ref), valid: v.valid, reason: v.reason })),
  };
}

describe('test vectors', () => {
  const json = serialize(VECTORS) as { vectors: Array<{ name: string; inputs: unknown[]; expect: ReturnType<typeof summarize> }> };

  it('vectors.json is up to date', () => {
    const text = `${JSON.stringify(json, null, 2)}\n`;
    if (process.env.UPDATE_VECTORS === '1') writeFileSync(FILE, text);
    expect(readFileSync(FILE, 'utf8')).toBe(text);
  });

  for (const v of json.vectors) {
    it(v.name, () => {
      const got = summarize(replay(fromJson(v.inputs as unknown[])));
      // What another implementation must match.
      expect(got.groups).toEqual(v.expect.groups);
      expect(got.instances).toEqual(v.expect.instances);
      expect(got.verdicts.map(({ ref, valid }) => ({ ref, valid }))).toEqual(v.expect.verdicts.map(({ ref, valid }) => ({ ref, valid })));
      // This implementation also keeps its reason texts stable.
      expect(got.verdicts).toEqual(v.expect.verdicts);
    });
  }
});
