import { describe, expect, it } from 'vitest';
import { groupIdFromBech32, groupIdToBech32 } from '../src/groupId.js';
import { T } from './helpers.js';

describe('group id', () => {
  it('round trips and starts with the group prefix', () => {
    const s = groupIdToBech32({ txHash: T(1), index: 3 });
    expect(s.startsWith('group1')).toBe(true);
    expect(groupIdFromBech32(s)).toEqual({ txHash: T(1), index: 3 });
  });
  it('rejects indexes above 65535 and foreign prefixes', () => {
    expect(() => groupIdToBech32({ txHash: T(1), index: 70000 })).toThrow();
    expect(() => groupIdFromBech32('drep1qqqqqq')).toThrow();
  });
});
