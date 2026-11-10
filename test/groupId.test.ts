import { describe, expect, it } from 'vitest';
import { groupIdFromBech32, groupIdToBech32 } from '../src/groupId.js';
import { T } from './helpers.js';

describe('group id', () => {
  it('round trips and starts with the drep_group prefix', () => {
    const s = groupIdToBech32({ txHash: T(1), index: 3 });
    expect(s.startsWith('drep_group1')).toBe(true);
    expect(groupIdFromBech32(s)).toEqual({ txHash: T(1), index: 3 });
  });
  it('rejects indexes above 65535 and foreign prefixes', () => {
    expect(() => groupIdToBech32({ txHash: T(1), index: 70000 })).toThrow();
    expect(() => groupIdFromBech32('drep1qqqqqq')).toThrow();
    // The pre-0.4.0 prefix is no longer accepted.
    const legacy = 'group1x9q04su93gdqvuklks4802dhf82j7j08nsh7qsnr0ve0xmg8qk9sqqqdtx542';
    expect(() => groupIdFromBech32(legacy)).toThrow();
  });
  it('encodes the CIP example', () => {
    expect(groupIdToBech32({ txHash: '3140fac3858a1a0672dfb42a77a9b749d52f49e79c2fe042637b32f36d07058b', index: 0 })).toBe(
      'drep_group1x9q04su93gdqvuklks4802dhf82j7j08nsh7qsnr0ve0xmg8qk9sqqqmcftfd',
    );
  });
});
