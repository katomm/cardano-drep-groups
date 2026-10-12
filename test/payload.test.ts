import { encode } from 'cborg';
import { describe, expect, it } from 'vitest';
import { nativeScriptHash } from '../src/hash.js';
import { concatBytes, hexToBytes } from '../src/hex.js';
import { decodePayload } from '../src/payload.js';
import { buildPayload, buildPayloadRaw, chunk64, ev, hashOf, K, local, nOfK, ref, scriptBytes, sig, T } from './helpers.js';

const ctrl = nOfK(1, sig(K(1)), sig(K(2)));
const other = nOfK(1, sig(K(3)));
const create = ev.create(0, hashOf(ctrl), null);

describe('decodePayload layer 1', () => {
  it('rejects wrong version, missing or empty events and non maps', () => {
    expect(decodePayload(buildPayload([create], [], 2))).toBeNull();
    expect(decodePayload(encode(new Map([[0, 1]])))).toBeNull();
    expect(decodePayload(encode(new Map<number, unknown>([[0, 1], [1, []]])))).toBeNull();
    expect(decodePayload(encode([1, 2]))).toBeNull();
  });
  it('ignores unknown payload keys', () => {
    const m = new Map<number, unknown>([[0, 1], [1, [create]], [9, 'x']]);
    expect(decodePayload(encode(m))?.events[0]?.ok).toBe(true);
  });
  it('rejects a payload with a duplicate map key or a tag', () => {
    const dup = concatBytes([hexToBytes('a3'), encode(0), encode(1), encode(1), encode([create]), encode(1), encode([create])]);
    expect(decodePayload(dup)).toBeNull();
    const tagged = concatBytes([hexToBytes('a2'), encode(0), encode(1), encode(1), hexToBytes('c1'), encode([create])]);
    expect(decodePayload(tagged)).toBeNull();
  });
});

describe('decodePayload layer 2', () => {
  it('hashes scripts across arbitrary chunk boundaries', () => {
    const bytes = scriptBytes(ctrl);
    const chunks = [bytes.subarray(0, 3), bytes.subarray(3, 40), bytes.subarray(40)];
    const p = decodePayload(buildPayloadRaw([create], [chunks]));
    expect(p?.scripts.map((s) => s.hash)).toEqual([nativeScriptHash(concatBytes(chunks))]);
    expect(p?.scripts[0]?.hash).toBe(hashOf(ctrl));
  });
  it('skips junk entries between valid ones', () => {
    const entries = [chunk64(scriptBytes(ctrl)), ['text'], [new Uint8Array([0xff])], [new Uint8Array(65)], chunk64(scriptBytes(other))];
    expect(decodePayload(buildPayloadRaw([create], entries))?.scripts.map((s) => s.hash)).toEqual([hashOf(ctrl), hashOf(other)]);
  });
  it('ignores key 2 when it is not an array', () => {
    const m = new Map<number, unknown>([[0, 1], [1, [create]], [2, 5]]);
    const p = decodePayload(encode(m));
    expect(p?.scripts).toEqual([]);
    expect(p?.events[0]?.ok).toBe(true);
  });
});

describe('decodePayload layer 3', () => {
  it('decodes every event form', () => {
    const p = decodePayload(
      buildPayload([
        ev.create(1, K(1), K(2), { url: 'https://x.test/g.json', hash: T(9) }),
        ev.update(ref(T(1), 0), 3, new Map<number, unknown>([[0, new Uint8Array(28).fill(7)]])),
        ev.dissolve(ref(T(1), 0), 4),
        ev.join(local(0), 'key', K(5)),
        ev.approve(ref(T(2), 1)),
        ev.leave(local(3)),
        ev.remove(ref(T(2), 1)),
      ]),
    );
    expect(p?.events.map((e) => (e.ok ? e.event.tag : e.reason))).toEqual(['create', 'update', 'dissolve', 'join', 'approve', 'leave', 'remove']);
    expect(p?.events[0]).toEqual({
      ok: true,
      event: { tag: 'create', mode: 'permissioned', control: K(1), admission: K(2), profile: { url: 'https://x.test/g.json', dataHash: T(9) } },
    });
    expect(p?.events[3]).toEqual({ ok: true, event: { tag: 'join', group: { local: 0 }, member: { kind: 'key', hash: K(5) } } });
  });
  it('keeps the index of a malformed event between valid ones', () => {
    const p = decodePayload(buildPayload([create, [3, 'junk'], ev.leave(ref(T(1), 0))]));
    expect(p?.events.map((e) => e.ok)).toEqual([true, false, true]);
  });
  it('rejects mode and admission mismatches, wrong lengths and unknown tags', () => {
    const p = decodePayload(
      buildPayload([
        [0, 0, new Uint8Array(28), new Uint8Array(28)],
        [0, 1, new Uint8Array(28), []],
        [0, 2, new Uint8Array(28), []],
        [3, [new Uint8Array(31), 0], [0, new Uint8Array(28)]],
        [9, 1],
        'not an array',
      ]),
    );
    expect(p?.events.every((e) => !e.ok)).toBe(true);
  });
  it('rejects an update map with an unknown key', () => {
    const p = decodePayload(buildPayload([ev.update(ref(T(1), 0), 0, new Map<number, unknown>([[7, 1]]))]));
    expect(p?.events[0]?.ok).toBe(false);
  });
  it('accepts bigint seq and rejects negative values', () => {
    const big = new Map<number, unknown>([[0, 1], [1, [[2, ref(T(1), 0), 2n ** 64n - 1n], [2, ref(T(1), 0), -1]]]]);
    const p = decodePayload(encode(big));
    expect(p?.events[0]).toEqual({ ok: true, event: { tag: 'dissolve', group: { txHash: T(1), index: 0 }, seq: 2n ** 64n - 1n } });
    expect(p?.events[1]?.ok).toBe(false);
  });
  it('joins url chunks and rejects chunks over 64 bytes', () => {
    const ok = decodePayload(buildPayload([[0, 0, new Uint8Array(28), [], [['https://x.test/', 'g.json'], new Uint8Array(32)]]]));
    const first = ok?.events[0];
    expect(first?.ok && first.event.tag === 'create' ? first.event.profile?.url : null).toBe('https://x.test/g.json');
    const bad = decodePayload(buildPayload([[0, 0, new Uint8Array(28), [], [['a'.repeat(65)], new Uint8Array(32)]]]));
    expect(bad?.events[0]?.ok).toBe(false);
  });
});
