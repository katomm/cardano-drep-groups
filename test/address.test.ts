import { bech32 } from 'bech32';
import { describe, expect, it } from 'vitest';
import { checkPaymentAddress } from '../src/address.js';
import { hexToBytes } from '../src/hex.js';
import { parseNativeScript } from '../src/nativeScript.js';
import type { NativeScript } from '../src/types.js';
import { hashOf, K, nOfK, scriptBytes, sig } from './helpers.js';

const treasury = nOfK(2, sig(K(1)), sig(K(2)), sig(K(3)));
const TH = hashOf(treasury);
const scripts = new Map<string, NativeScript>([[TH, parseNativeScript(scriptBytes(treasury)) as NativeScript]]);

function addr(type: number, netId: number, payment: string, tail?: string): string {
  const extra = tail ? hexToBytes(tail) : new Uint8Array(0);
  const bytes = new Uint8Array(1 + 28 + extra.length);
  bytes[0] = (type << 4) | netId;
  bytes.set(hexToBytes(payment), 1);
  bytes.set(extra, 29);
  return bech32.encode(netId === 1 ? 'addr' : 'addr_test', bech32.toWords(bytes), 1023);
}

describe('checkPaymentAddress', () => {
  it('marks a base script address with matching treasury script as script-controlled', () => {
    const r = checkPaymentAddress({ address: addr(3, 1, TH, K(9)), treasuryScript: TH }, 'mainnet', scripts);
    expect(r).toMatchObject({ status: 'script-controlled', hasStake: true, reason: null });
    expect(r.script?.type).toBe('nOfK');
  });
  it('enterprise script address has no stake part', () => {
    expect(checkPaymentAddress({ address: addr(7, 1, TH), treasuryScript: TH }, 'mainnet', scripts)).toMatchObject({ status: 'script-controlled', hasStake: false });
  });
  it('a key payment credential with the same hash is only declared', () => {
    expect(checkPaymentAddress({ address: addr(0, 1, TH, K(9)), treasuryScript: TH }, 'mainnet', scripts)).toMatchObject({ status: 'declared', reason: 'payment credential is not a script' });
  });
  it('non matching and unresolved treasury scripts are only declared', () => {
    expect(checkPaymentAddress({ address: addr(3, 1, K(5), K(9)), treasuryScript: TH }, 'mainnet', scripts).reason).toBe('treasury script does not match the address');
    expect(checkPaymentAddress({ address: addr(3, 1, K(5), K(9)), treasuryScript: K(5) }, 'mainnet', scripts).reason).toBe('treasury script unresolved');
  });
  it('an address without treasury script is declared', () => {
    expect(checkPaymentAddress({ address: addr(0, 1, K(5), K(9)) }, 'mainnet', scripts)).toMatchObject({ status: 'declared', reason: null });
  });
  it('rejects pointer addresses, the wrong network and garbage', () => {
    expect(checkPaymentAddress({ address: addr(4, 1, K(5), '010203') }, 'mainnet', scripts)).toMatchObject({ status: 'invalid', reason: 'pointer addresses are not supported' });
    expect(checkPaymentAddress({ address: addr(0, 0, K(5), K(9)) }, 'mainnet', scripts).status).toBe('invalid');
    expect(checkPaymentAddress({ address: addr(0, 1, K(5), K(9)) }, 'testnet', scripts).status).toBe('invalid');
    expect(checkPaymentAddress({ address: 'addr1nope' }, 'mainnet', scripts).status).toBe('invalid');
  });
});
