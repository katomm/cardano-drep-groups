import { describe, expect, it } from 'vitest';
import { parseNativeScript, scriptComplexity } from '../src/nativeScript.js';
import { decodePayload } from '../src/payload.js';
import { replay } from '../src/state.js';
import { allOf, anyOf, buildPayload, ev, hashOf, K, nOfK, ref, regIn, scriptBytes, scriptCred, sig, T, txIn } from './helpers.js';

describe('protocol limits', () => {
  it('accepts a payload of exactly 64 events', () => {
    const d = decodePayload(buildPayload(Array.from({ length: 64 }, () => ev.leave(ref(T(9), 0)))));
    expect(d?.events.length).toBe(64);
  });
  it('rejects a payload of 65 events as a whole', () => {
    expect(decodePayload(buildPayload(Array.from({ length: 65 }, () => ev.leave(ref(T(9), 0)))))).toBeNull();
  });
  it('keeps 8 script entries and ignores only key 2 with 9', () => {
    const s = Array.from({ length: 9 }, (_, i) => sig(K(i + 1)));
    expect(decodePayload(buildPayload([ev.create(0, hashOf(s[0]!), null)], s.slice(0, 8)))?.scripts.length).toBe(8);
    const d = decodePayload(buildPayload([ev.create(0, hashOf(s[0]!), null)], s));
    expect(d?.scripts).toEqual([]);
    expect(d?.events.length).toBe(1);
  });
  it('skips a key 2 entry over 64 nodes or depth 8 and keeps the others', () => {
    const wide = anyOf(...Array.from({ length: 64 }, (_, i) => sig(K(i + 1)))); // 65 nodes
    const deep = [1, 2, 3, 4, 5, 6, 7, 8].reduce((s) => allOf(s), sig(K(1))); // depth 9
    const ok = nOfK(1, sig(K(2)));
    const d = decodePayload(buildPayload([ev.create(0, hashOf(ok), null)], [wide, deep, ok]));
    expect(d?.scripts.map((x) => x.hash)).toEqual([hashOf(ok)]);
  });
  it('accepts a key 2 script of exactly 64 nodes and one of exactly depth 8', () => {
    const n64 = anyOf(...Array.from({ length: 63 }, (_, i) => sig(K(i + 1))));
    const d8 = [1, 2, 3, 4, 5, 6, 7].reduce((s) => allOf(s), sig(K(1)));
    const d = decodePayload(buildPayload([ev.create(0, hashOf(n64), null)], [n64, d8]));
    expect(d?.scripts.map((x) => x.hash)).toEqual([hashOf(n64), hashOf(d8)]);
  });
  it('counts nodes and depth inclusively', () => {
    expect(scriptComplexity(parseNativeScript(scriptBytes(anyOf(...Array.from({ length: 63 }, (_, i) => sig(K(i + 1))))))!)).toEqual({ nodes: 64, depth: 2 });
  });
  it('does not limit registration witness scripts', () => {
    const big = anyOf(...Array.from({ length: 200 }, (_, i) => sig(K(i + 1))));
    const SC = hashOf(big);
    const control = sig(K(0x70));
    const create = txIn({ hash: T(1), h: 10, payload: buildPayload([ev.create(0, hashOf(control), null)], [control]), rs: [K(0x70)] });
    const j = txIn({ hash: T(2), h: 11, payload: buildPayload([ev.join(ref(T(1), 0), 'script', SC)]), wk: [K(1)] });
    const s = replay([regIn(scriptCred(SC), T(0x40), 5, 0, [scriptBytes(big)]), create, j]);
    expect(s.verdicts[1]?.valid).toBe(true);
    expect(s.instances[0]).toMatchObject({ state: 'active' });
  });
});
