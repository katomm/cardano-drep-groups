import { bech32 } from 'bech32';
import { bytesToHex } from './hex.js';
import type { Hex, NativeScript } from './types.js';

export type Network = 'mainnet' | 'testnet';
export interface AddressCheck {
  status: 'invalid' | 'declared' | 'script-controlled';
  reason: string | null;
  hasStake: boolean;
  script: NativeScript | null;
}

const invalid = (reason: string): AddressCheck => ({ status: 'invalid', reason, hasStake: false, script: null });

// Spec A6: a listed address is script-controlled only when its payment
// credential is a script whose hash equals the declared and resolved treasury
// script. Anything else is shown as a declared address. Pointer addresses are
// rejected, base and enterprise addresses are supported.
export function checkPaymentAddress(
  entry: { address: string; treasuryScript?: string },
  network: Network,
  scripts: ReadonlyMap<Hex, NativeScript>,
): AddressCheck {
  let bytes: Uint8Array;
  let prefix: string;
  try {
    const d = bech32.decode(entry.address, 1023);
    prefix = d.prefix;
    bytes = new Uint8Array(bech32.fromWords(d.words));
  } catch {
    return invalid('not a bech32 address');
  }
  const header = bytes[0];
  if (header === undefined) return invalid('empty address');
  const type = header >> 4;
  const netId = header & 0x0f;
  if (netId !== (network === 'mainnet' ? 1 : 0) || prefix !== (network === 'mainnet' ? 'addr' : 'addr_test')) return invalid('wrong network');
  if (type === 4 || type === 5) return invalid('pointer addresses are not supported');
  if (type > 7) return invalid('not a payment address');
  if (type <= 3 && bytes.length !== 57) return invalid('bad base address length');
  if ((type === 6 || type === 7) && bytes.length !== 29) return invalid('bad enterprise address length');
  const hasStake = type <= 3;
  const paymentIsScript = type % 2 === 1;
  const payment = bytesToHex(bytes.subarray(1, 29));
  const declared = (reason: string | null): AddressCheck => ({ status: 'declared', reason, hasStake, script: null });
  if (entry.treasuryScript === undefined) return declared(null);
  const th = entry.treasuryScript.toLowerCase();
  if (!/^[0-9a-f]{56}$/.test(th)) return declared('treasury script is not a 28 byte hash');
  if (!paymentIsScript) return declared('payment credential is not a script');
  if (payment !== th) return declared('treasury script does not match the address');
  const script = scripts.get(th);
  if (!script) return declared('treasury script unresolved');
  return { status: 'script-controlled', reason: null, hasStake, script };
}
