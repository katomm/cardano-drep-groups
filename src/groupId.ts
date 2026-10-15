import { bech32 } from 'bech32';
import { bytesToHex, hexToBytes } from './hex.js';
import type { EventRef } from './types.js';

const PREFIX = 'group';

// Spec A6 display form: bech32 of tx_hash || uint16be(event_index).
export function groupIdToBech32(ref: EventRef): string {
  if (!Number.isInteger(ref.index) || ref.index < 0 || ref.index > 0xffff) throw new Error('event index out of range');
  const tx = hexToBytes(ref.txHash);
  if (tx.length !== 32) throw new Error('tx hash must be 32 bytes');
  const bytes = new Uint8Array(34);
  bytes.set(tx, 0);
  bytes[32] = ref.index >> 8;
  bytes[33] = ref.index & 0xff;
  return bech32.encode(PREFIX, bech32.toWords(bytes), 1023);
}

export function groupIdFromBech32(s: string): EventRef {
  const d = bech32.decode(s, 1023);
  if (d.prefix !== PREFIX) throw new Error('not a group id');
  const bytes = new Uint8Array(bech32.fromWords(d.words));
  if (bytes.length !== 34) throw new Error('bad group id length');
  return { txHash: bytesToHex(bytes.subarray(0, 32)), index: ((bytes[32] as number) << 8) | (bytes[33] as number) };
}
