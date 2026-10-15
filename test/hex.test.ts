import { describe, expect, it } from 'vitest';
import { keyHashOfVkey, nativeScriptHash } from '../src/hash.js';
import { bytesToHex, concatBytes, hexToBytes } from '../src/hex.js';

describe('hex', () => {
  it('round trips', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
  });
  it('rejects odd length and non hex', () => {
    expect(() => hexToBytes('abc')).toThrow();
    expect(() => hexToBytes('zz')).toThrow();
  });
  it('concatenates', () => {
    expect(bytesToHex(concatBytes([hexToBytes('01'), hexToBytes('0203')]))).toBe('010203');
  });
});

describe('hash', () => {
  // Reference values computed with @evolution-sdk/evolution ScriptHash.fromScript
  // and with blakejs.
  it('hashes a sig native script like the ledger', () => {
    const sig = hexToBytes(`8200581c${'11'.repeat(28)}`);
    expect(nativeScriptHash(sig)).toBe('5334c8c55ec6518f2e262da617d3170bf0722f43813d64dbaf0ff0b9');
  });
  it('hashes an all native script like the ledger', () => {
    const all = hexToBytes(`820182${'8200581c'}${'11'.repeat(28)}${'8200581c'}${'22'.repeat(28)}`);
    expect(nativeScriptHash(all)).toBe('6c81737a61d80ff7e74862f5fc6c4f984b5d6e5020038afb4dcdac82');
  });
  it('hashes a vkey to its key hash', () => {
    expect(keyHashOfVkey(new Uint8Array(32).fill(0x33))).toBe('e47bb1c6309ebd06695ae459e69fcf3d585e5f41e3d3d8ce7152b524');
  });
});
