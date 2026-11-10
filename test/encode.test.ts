import { describe, expect, it } from 'vitest';
import * as Metadatum from '@evolution-sdk/evolution/TransactionMetadatum';
import {
  chunkBytes, chunkText, EncodeError, encodeCbor, encodeNativeScript, encodePayload,
} from '../src/encode.js';
import { nativeScriptHash } from '../src/hash.js';
import { bytesToHex } from '../src/hex.js';
import { parseNativeScript } from '../src/nativeScript.js';
import { decodePayload } from '../src/payload.js';
import type { GroupEvent, NativeScript } from '../src/types.js';
import { VECTORS } from '../vectors/definitions.js';
import { buildPayload, ev, hashOf, K, nOfK as nOfKv, sig as sigv, T } from './helpers.js';

const sig = (n: number): NativeScript => ({ type: 'sig', keyHash: K(n) });
const nOfK = (n: bigint, scripts: NativeScript[]): NativeScript => ({ type: 'nOfK', n, scripts });
const A = sig(1);
const B = sig(2);
const C = sig(3);
const anchor = { url: 'https://example.org/profile.json', dataHash: T(9) };

const create: GroupEvent = { tag: 'create', mode: 'open', control: K(1), admission: null, profile: null };
const createWithProfile = (url: string): GroupEvent => ({ ...create, profile: { url, dataHash: T(9) } });
const joinEv = (group: { local: number }): GroupEvent => ({ tag: 'join', group, member: { kind: 'key', hash: K(7) } });
const ref = { txHash: T(1), index: 0 };

const ALL_EVENTS: GroupEvent[] = [
  create,
  createWithProfile(anchor.url),
  { tag: 'create', mode: 'permissioned', control: K(1), admission: K(2), profile: null },
  { tag: 'create', mode: 'permissioned', control: K(1), admission: K(2), profile: anchor },
  { tag: 'update', group: ref, seq: 0n, changes: {} },
  { tag: 'update', group: ref, seq: 3n, changes: { control: K(4) } },
  { tag: 'update', group: ref, seq: 3n, changes: { admission: K(5) } },
  { tag: 'update', group: { local: 0 }, seq: 2n ** 40n, changes: { profile: anchor, control: K(4), admission: K(5) } },
  { tag: 'dissolve', group: ref, seq: 7n },
  { tag: 'join', group: ref, member: { kind: 'key', hash: K(7) } },
  { tag: 'join', group: ref, member: { kind: 'script', hash: K(8) } },
  { tag: 'approve', join: ref },
  { tag: 'leave', join: { local: 0 } },
  { tag: 'remove', join: ref },
  { tag: 'resign', group: ref, key: K(6) },
  { tag: 'resign', group: { local: 0 }, key: K(6) },
];

describe('encodePayload', () => {
  it('round trips every event type through decodePayload', () => {
    for (const e of ALL_EVENTS) {
      const input: GroupEvent[] = 'local' in ('group' in e ? e.group : 'join' in e ? e.join : {}) ? [create, e] : [e];
      const d = decodePayload(encodePayload({ events: input }))!;
      expect(d.events[input.length - 1]).toEqual({ ok: true, event: e });
    }
  });

  it('round trips local refs and published scripts', () => {
    const join1 = joinEv({ local: 0 });
    const approve: GroupEvent = { tag: 'approve', join: { local: 1 } };
    const p = encodePayload({ events: [create, join1, approve], scripts: [nOfK(2n, [A, B, C])] });
    const d = decodePayload(p)!;
    expect(d.events.map((e) => e.ok)).toEqual([true, true, true]);
    expect(d.scripts[0]?.hash).toBe(nativeScriptHash(encodeNativeScript(nOfK(2n, [A, B, C]))));
  });

  it('matches the bytes the cborg based test builder produces', () => {
    const ctrl = nOfKv(2, sigv(K(1)), sigv(K(2)), sigv(K(3)));
    const ctrlScript = nOfK(2n, [sig(1), sig(2), sig(3)]);
    const cases: [Uint8Array, Uint8Array][] = [
      [buildPayload([ev.create(0, hashOf(ctrl), null)], [ctrl]), encodePayload({
        events: [{ ...create, control: hashOf(ctrl) }], scripts: [ctrlScript],
      })],
      [buildPayload([ev.create(1, K(1), K(2), { url: anchor.url, hash: T(9) }), ev.join([0], 'script', K(7))]), encodePayload({
        events: [
          { tag: 'create', mode: 'permissioned', control: K(1), admission: K(2), profile: anchor },
          { tag: 'join', group: { local: 0 }, member: { kind: 'script', hash: K(7) } },
        ],
      })],
      [buildPayload([ev.update([Buffer.from(T(1), 'hex'), 0], 2, new Map<number, unknown>([[0, Buffer.from(K(4), 'hex')]]))]), encodePayload({
        events: [{ tag: 'update', group: ref, seq: 2n, changes: { control: K(4) } }],
      })],
    ];
    for (const [expected, actual] of cases) expect(bytesToHex(actual)).toBe(bytesToHex(expected));
  });

  it('re-encodes every vector payload to the same bytes', () => {
    let compared = 0;
    const skipped: string[] = [];
    for (const v of VECTORS) {
      for (const i of v.inputs) {
        if (i.kind !== 'tx' || !i.tx.payload) continue;
        const d = decodePayload(i.tx.payload);
        // Deliberately malformed payloads (duplicate keys, rejected events, skipped scripts) have no PayloadInput form.
        if (!d || d.events.some((e) => !e.ok)) { skipped.push(v.name); continue; }
        const events = d.events.map((e) => (e.ok ? e.event : create));
        const scripts = d.scripts.map((x) => x.script);
        let again: Uint8Array;
        try {
          again = encodePayload({ events, scripts });
        } catch (err) {
          // The encoder refuses what the decoder only flags per event, such as a local reference to itself.
          if (!(err instanceof EncodeError)) throw err;
          skipped.push(v.name);
          continue;
        }
        if (bytesToHex(again) !== bytesToHex(i.tx.payload)) { skipped.push(v.name); continue; }
        compared++;
      }
    }
    expect(compared).toBe(107);
    expect([...new Set(skipped)]).toEqual([
      'founder joins through a local ref, local refs to the same or a later index fail',
      'phase-2-invalid transaction, wrong version and duplicate map key are ignored',
      'decoding: malformed events keep their index',
      'an unknown payload key with a deep value is ignored and the events count',
      'a duplicate unknown key in the payload map ignores the whole payload',
      'a duplicate key in an update map invalidates only that event',
      'script list: junk entries between valid scripts are skipped',
      'a profile anchor URL is concatenated unchanged, a U+FEFF at a chunk start stays',
      'events limit: 65 events ignore the whole payload',
      'script entries: 9 entries ignore key 2, an event that needs those scripts is invalid',
      'script complexity: 65 nodes or depth 9 are skipped, the dependent events are invalid',
      'duplicate payload keys: 0x09 and 0x1809 are the same unsigned key, the payload is ignored',
      'payload keys: negative 0x20 and 0x3800 are different unknown keys, the payload is processed',
      'indefinite length payload map and event array are accepted',
    ]);
  });

  it('chunks a URL without splitting a code point', () => {
    for (const url of ['https://example.org/x' + 'ü'.repeat(40), 'https://example.org/' + '€'.repeat(30), 'https://example.org/' + '😀'.repeat(20)]) {
      const chunks = chunkText(url);
      const strict = new TextDecoder('utf-8', { fatal: true });
      for (const c of chunks) {
        const b = new TextEncoder().encode(c);
        expect(b.length).toBeLessThanOrEqual(64);
        expect(strict.decode(b)).toBe(c);
      }
      expect(chunks.join('')).toBe(url);
    }
    const url = 'https://example.org/x' + 'ü'.repeat(40);
    expect(decodePayload(encodePayload({ events: [createWithProfile(url)] }))!.events[0]).toEqual({ ok: true, event: createWithProfile(url) });
    expect(chunkText('')).toEqual(['']);
    expect(chunkBytes(new Uint8Array(0))).toEqual([new Uint8Array(0)]);
    expect(chunkBytes(new Uint8Array(130)).map((c) => c.length)).toEqual([64, 64, 2]);
  });

  it('accepts anchors over 64 bytes and scripts at the limits', () => {
    const longUrl = `https://example.org/${'a'.repeat(180)}`;
    const d = decodePayload(encodePayload({ events: [createWithProfile(longUrl)] }))!;
    expect(d.events[0]).toEqual({ ok: true, event: createWithProfile(longUrl) });
    const scripts = Array.from({ length: 8 }, (_, i) => nOfK(1n, [sig(i + 1)]));
    expect(decodePayload(encodePayload({ events: [create], scripts }))!.scripts).toHaveLength(8);
    // 64 nodes: root plus 63 sigs, depth 2. Depth 8: seven nested all scripts around one sig.
    const wide: NativeScript = { type: 'all', scripts: Array.from({ length: 63 }, (_, i) => sig(i + 1)) };
    let deep: NativeScript = sig(1);
    for (let i = 0; i < 7; i++) deep = { type: 'all', scripts: [deep] };
    const d2 = decodePayload(encodePayload({ events: [create], scripts: [wide, deep] }))!;
    expect(d2.scripts).toHaveLength(2);
  });

  it('accepts exactly 64 events', () => {
    const d = decodePayload(encodePayload({ events: Array.from({ length: 64 }, () => create) }))!;
    expect(d.events).toHaveLength(64);
  });

  it('throws EncodeError beyond the limits', () => {
    const bad = (p: Parameters<typeof encodePayload>[0]) => expect(() => encodePayload(p)).toThrow(EncodeError);
    bad({ events: [] });
    bad({ events: Array.from({ length: 65 }, () => create) });
    bad({ events: [create], scripts: Array.from({ length: 9 }, (_, i) => sig(i + 1)) });
    bad({ events: [create], scripts: [{ type: 'all', scripts: Array.from({ length: 64 }, (_, i) => sig(i + 1)) }] });
    let deep: NativeScript = sig(1);
    for (let i = 0; i < 8; i++) deep = { type: 'all', scripts: [deep] };
    bad({ events: [create], scripts: [deep] });
    bad({ events: [joinEv({ local: 0 })] });
    bad({ events: [create, joinEv({ local: 1 })] });
    bad({ events: [{ ...create, control: 'abcd' }] });
    bad({ events: [{ ...create, control: K(0xab).toUpperCase() }] });
    bad({ events: [{ tag: 'approve', join: { txHash: 'ab', index: 0 } }] });
    bad({ events: [{ ...create, mode: 'permissioned', admission: null }] });
    bad({ events: [{ ...create, mode: 'open', admission: K(2) }] });
    bad({ events: [createWithProfile('')] });
    bad({ events: [create], scripts: [{ type: 'sig', keyHash: 'abcd' }] });
    expect(() => encodeCbor(1.5)).toThrow(EncodeError);
    bad({ events: [{ tag: 'dissolve', group: ref, seq: -1n }] });
    bad({ events: [{ tag: 'update', group: ref, seq: -1n, changes: {} }] });
    bad({ events: [{ tag: 'dissolve', group: ref, seq: 2n ** 64n }] });
    bad({ events: [{ tag: 'approve', join: { txHash: T(1), index: -1 } }] });
    bad({ events: [{ tag: 'approve', join: { txHash: T(1), index: 1.5 } }] });
    bad({ events: [{ tag: 'approve', join: { txHash: T(1), index: 2 ** 53 } }] });
    bad({ events: [create, { tag: 'approve', join: { local: -1 } }] });
  });

  it('emits map keys ascending whatever the insertion order', () => {
    expect(bytesToHex(encodeCbor(new Map<number, number>([[2, 1], [0, 1]])))).toBe('a200010201');
    const changes = { profile: anchor, control: K(4) };
    const bytes = encodePayload({ events: [{ tag: 'update', group: ref, seq: 0n, changes }] });
    expect(decodePayload(bytes)!.events[0]).toEqual({ ok: true, event: { tag: 'update', group: ref, seq: 0n, changes } });
    expect(bytesToHex(bytes)).toContain('a2' + '00' + '581c' + K(4) + '02');
  });

  it('is accepted by the ledger metadatum grammar', () => {
    const events: GroupEvent[] = [...ALL_EVENTS.filter((e) => !('local' in ('group' in e ? e.group : 'join' in e ? e.join : {}))), createWithProfile(`https://example.org/${'a'.repeat(180)}`)];
    const bytes = encodePayload({ events, scripts: [nOfK(2n, [A, B, C])] });
    expect(() => Metadatum.fromCBORBytes(bytes)).not.toThrow();
  });

  it('encodes negative nOfK thresholds as major type 1', () => {
    expect(parseNativeScript(encodeNativeScript(nOfK(-1n, [A])))).toEqual(nOfK(-1n, [A]));
    expect(bytesToHex(encodeCbor(-1))).toBe('20');
    expect(bytesToHex(encodeCbor(-25n))).toBe('3818');
  });

  it('encodes the time lock and signature scripts to the Conway grammar', () => {
    expect(bytesToHex(encodeNativeScript({ type: 'after', slot: 100n }))).toBe('82041864');
    expect(bytesToHex(encodeNativeScript({ type: 'before', slot: 5n }))).toBe('820505');
    expect(bytesToHex(encodeNativeScript(A))).toBe(`8200581c${K(1)}`);
  });
});
