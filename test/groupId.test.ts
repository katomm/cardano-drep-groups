import { describe, expect, it } from 'vitest';
import { groupIdFromBech32, groupIdToBech32 } from '../src/groupId.js';
import { decodePayload } from '../src/payload.js';
import { buildPayload, ev, ref, T } from './helpers.js';

describe('group id', () => {
  it('round trips and starts with the drep_group prefix', () => {
    const s = groupIdToBech32({ txHash: T(1), index: 3 });
    expect(s.startsWith('drep_group1')).toBe(true);
    expect(groupIdFromBech32(s)).toEqual({ txHash: T(1), index: 3 });
  });
  it('rejects indexes above 255 and foreign prefixes', () => {
    expect(() => groupIdToBech32({ txHash: T(1), index: 256 })).toThrow('event index out of range');
    expect(() => groupIdFromBech32('drep1qqqqqq')).toThrow();
    // The pre-0.4.0 prefix is no longer accepted.
    const legacy = 'group1x9q04su93gdqvuklks4802dhf82j7j08nsh7qsnr0ve0xmg8qk9sqqqdtx542';
    expect(() => groupIdFromBech32(legacy)).toThrow();
  });
  it('encodes the CIP example', () => {
    expect(groupIdToBech32({ txHash: '3140fac3858a1a0672dfb42a77a9b749d52f49e79c2fe042637b32f36d07058b', index: 0 })).toBe(
      'drep_group1x9q04su93gdqvuklks4802dhf82j7j08nsh7qsnr0ve0xmg8qk9sqpwk7pe',
    );
  });
  it('round trips the largest one byte indexes', () => {
    for (const index of [63, 255]) expect(groupIdFromBech32(groupIdToBech32({ txHash: T(1), index }))).toEqual({ txHash: T(1), index });
  });
  it('rejects the 0.4.0 two byte form', () => {
    const v040 = 'drep_group1x9q04su93gdqvuklks4802dhf82j7j08nsh7qsnr0ve0xmg8qk9sqqqmcftfd';
    expect(() => groupIdFromBech32(v040)).toThrow('bad group id length');
  });
  it('still decodes event indexes above 255 on the wire', () => {
    const d = decodePayload(buildPayload([ev.approve(ref(T(1), 300))]));
    expect(d?.events[0]).toMatchObject({ ok: true, event: { tag: 'approve', join: { txHash: T(1), index: 300 } } });
  });
});
