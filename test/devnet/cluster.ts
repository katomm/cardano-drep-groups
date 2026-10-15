// A local Conway devnet for the ledger assumption tests: cardano-node, Kupo
// and Ogmios in Docker through @evolution-sdk/devnet. Only the devnet suite
// imports this file (npm run test:devnet), so the default suite never needs
// Docker.
//
// Next to the devnet's own Ogmios, a second Ogmios container runs on the same
// node socket with --include-transaction-cbor. Its chain sync hands out the
// original bytes of every transaction in every block, together with the block
// height and the transaction's index in the block, so the tests read what the
// chain holds instead of what the local builder produced.
//
// The genesis has no guardrail script and no committee, one second epochs
// (50 slots of 20 ms) and the default Conway deposits.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as Cluster from '@evolution-sdk/devnet/Cluster';
import * as Config from '@evolution-sdk/devnet/Config';
import * as Container from '@evolution-sdk/devnet/Container';
import * as Genesis from '@evolution-sdk/devnet/Genesis';
import { Address, Bytes, Client, KeyHash, PrivateKey, preprod, type UTxO } from '@evolution-sdk/evolution';

const run = promisify(execFile);

export const TEST_MNEMONIC =
  'test test test test test test test test test test test test test test test test test test test test test test test sauce';

/** Accounts 0 to 5 of the test mnemonic are funded. */
export const FUNDED_ACCOUNTS = [0, 1, 2, 3, 4, 5] as const;
const FUNDS_PER_ACCOUNT = 300_000_000_000;
/** The node socket inside the devnet's cardano-node container. */
const NODE_SOCKET = '/opt/cardano/ipc/node.socket';
/** Host port of the second Ogmios that includes transaction CBOR. */
const CBOR_OGMIOS_PORT = 1347;

function makeSeedClient(cluster: Cluster.Cluster, accountIndex: number) {
  return Client.make(Cluster.getChain(cluster))
    .withKupmios({
      kupoUrl: `http://localhost:${cluster.ports.kupo}`,
      ogmiosUrl: `http://localhost:${cluster.ports.ogmios}`,
    })
    .withSeed({ mnemonic: TEST_MNEMONIC, accountIndex, addressType: 'Base' });
}

export type DevnetClient = ReturnType<typeof makeSeedClient>;

/** A key of the test mnemonic: CIP-1852 role 0 payment, 2 stake, 3 DRep (CIP-105). */
export interface TestKey {
  account: number;
  role: 0 | 2 | 3;
  key: PrivateKey.PrivateKey;
  hash: string;
}

export function testKey(account: number, role: 0 | 2 | 3): TestKey {
  // The SDK types role as 0 or 2, the derivation itself takes any role index.
  const key = PrivateKey.fromMnemonicCardano(TEST_MNEMONIC, { account, role: role as 0 | 2, index: 0 });
  return { account, role, key, hash: KeyHash.toHex(KeyHash.fromPrivateKey(key)) };
}

/** A transaction as the chain holds it. */
export interface ChainEntry {
  txHash: string;
  cbor: Uint8Array;
  blockHeight: number;
  txIndex: number;
  slot: number;
}

/**
 * Follows the chain from origin through the CBOR Ogmios and keeps every
 * transaction it sees. One devnet has one block producer, so a rollback only
 * happens at the start, it still drops what it rolls back.
 */
class ChainReader {
  private ws: WebSocket | undefined;
  private readonly txs = new Map<string, ChainEntry>();
  tipSlot = 0;
  error: string | null = null;

  constructor(private readonly url: string) {}

  async open(): Promise<void> {
    const ws = new WebSocket(this.url);
    this.ws = ws;
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener('open', () => resolve(), { once: true });
      ws.addEventListener('error', () => reject(new Error(`chain reader cannot connect to ${this.url}`)), { once: true });
    });
    ws.addEventListener('message', (msg) => this.onMessage(String(msg.data)));
    ws.addEventListener('close', () => {
      if (this.ws === ws) this.error ??= 'chain reader connection closed';
    });
    this.send('findIntersection', { points: ['origin'] });
  }

  private send(method: string, params?: unknown): void {
    this.ws?.send(JSON.stringify({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }), id: method }));
  }

  private onMessage(raw: string): void {
    const msg = JSON.parse(raw) as { id?: string; result?: Record<string, unknown>; error?: unknown };
    if (msg.error !== undefined) {
      this.error = `chain reader ${msg.id}: ${show(msg.error)}`;
      return;
    }
    const result = msg.result ?? {};
    if (msg.id === 'nextBlock' && result.direction === 'forward') {
      const block = result.block as { height?: number; slot?: number; transactions?: { id: string; cbor?: string }[] };
      const slot = block.slot ?? 0;
      this.tipSlot = Math.max(this.tipSlot, slot);
      (block.transactions ?? []).forEach((t, txIndex) => {
        if (t.cbor === undefined) {
          this.error = `transaction ${t.id} came without cbor`;
          return;
        }
        this.txs.set(t.id, { txHash: t.id, cbor: Bytes.fromHex(t.cbor), blockHeight: block.height ?? 0, txIndex, slot });
      });
    } else if (msg.id === 'nextBlock' && result.direction === 'backward') {
      const point = result.point as { slot?: number } | 'origin';
      const slot = point === 'origin' ? -1 : (point.slot ?? -1);
      for (const [id, e] of this.txs) if (e.slot > slot) this.txs.delete(id);
    }
    // Pipelined one at a time: the next request goes out once the previous answer is in.
    this.send('nextBlock');
  }

  get(txHash: string): ChainEntry | undefined {
    return this.txs.get(txHash);
  }

  close(): void {
    const ws = this.ws;
    this.ws = undefined;
    ws?.close();
  }
}

export interface DevnetHandle {
  cluster: Cluster.Cluster;
  slotConfig: Cluster.SlotConfig;
  /** The SDK's own seed client against the devnet (Kupo and Ogmios). */
  client(accountIndex: number): DevnetClient;
  /** The genesis UTxO of a funded account, for its first transaction before Kupo has indexed anything. */
  genesisUtxo(accountIndex: number): UTxO.UTxO;
  /** One Ogmios JSON-RPC call over HTTP. Throws with the Ogmios error when the call fails. */
  ogmios<T>(method: string, params?: unknown): Promise<T>;
  /** A cardano-cli query inside the node container, parsed as JSON. */
  cli<T>(args: string[]): Promise<T>;
  /** Waits until the chain holds the transaction and returns its original bytes and position. */
  onChain(txHash: string, timeoutMs?: number): Promise<ChainEntry>;
  /** The newest slot the chain reader has seen. */
  tipSlot(): number;
  /** Polls the probe every 500 ms until it returns a value, throws with the last value seen at the deadline. */
  waitFor<T>(label: string, probe: () => Promise<T | null>, timeoutMs?: number): Promise<T>;
  stop(): Promise<void>;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** JSON with bigints written as strings and byte arrays as hex, for messages. */
export function show(value: unknown): string {
  return JSON.stringify(value, (_key, v) =>
    typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? Bytes.toHex(v) : v,
  );
}

/** The message of an error and every cause below it, so a wrapped failure stays readable. */
export function errorText(err: unknown): string {
  const parts: string[] = [];
  let current: unknown = err;
  for (let depth = 0; depth < 8 && current !== null && current !== undefined; depth++) {
    if (typeof current !== 'object') {
      parts.push(String(current));
      break;
    }
    const message = (current as { message?: unknown }).message;
    parts.push(typeof message === 'string' ? message : show(current));
    current = (current as { cause?: unknown }).cause;
  }
  return parts.join(' | ');
}

async function ogmiosCall<T>(port: number, method: string, params?: unknown): Promise<T> {
  const res = await fetch(`http://localhost:${port}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }), id: null }),
  });
  const body = (await res.json()) as { result?: T; error?: unknown };
  if (body.error !== undefined) throw new Error(`Ogmios ${method} failed: ${show(body.error)}`);
  return body.result as T;
}

async function waitFor<T>(label: string, probe: () => Promise<T | null>, timeoutMs = 60_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: unknown = null;
  for (;;) {
    try {
      const value = await probe();
      if (value !== null) return value;
      last = value;
    } catch (err) {
      last = err instanceof Error ? err.message : err;
    }
    if (Date.now() > deadline) throw new Error(`Timed out after ${timeoutMs} ms waiting for ${label}. Last seen: ${show(last)}`);
    await sleep(500);
  }
}

async function docker(args: string[]): Promise<string> {
  const { stdout } = await run('docker', args);
  return stdout.trim();
}

/** Removes a container by name, quietly when it does not exist. */
async function removeContainer(name: string): Promise<void> {
  await docker(['rm', '-f', name]).catch(() => undefined);
}

/**
 * Starts a fresh devnet named `name`. The caller must call stop() in its
 * afterAll, which also removes the containers and the network. A failure
 * after the containers exist removes them before rethrowing.
 */
export async function startDevnet(name: string): Promise<DevnetHandle> {
  const addresses = await Promise.all(
    FUNDED_ACCOUNTS.map((accountIndex) =>
      Client.make(preprod).withSeed({ mnemonic: TEST_MNEMONIC, accountIndex, addressType: 'Base' }).address(),
    ),
  );

  const shelleyGenesis: Config.ShelleyGenesis = {
    ...Config.DEFAULT_SHELLEY_GENESIS,
    slotLength: 0.02,
    epochLength: 50,
    activeSlotsCoeff: 1.0,
    initialFunds: Object.fromEntries(addresses.map((a) => [Address.toHex(a), FUNDS_PER_ACCOUNT])),
  };
  const conwayGenesis: Config.ConwayGenesis = { ...Config.DEFAULT_CONWAY_GENESIS, dRepActivity: 1000 };

  const genesisUtxos = await Genesis.calculateUtxosFromConfig(shelleyGenesis);
  const genesisByAccount = new Map<number, UTxO.UTxO>();
  addresses.forEach((address, i) => {
    const utxo = genesisUtxos.find((u) => Address.toBech32(u.address) === Address.toBech32(address));
    if (utxo) genesisByAccount.set(i, utxo);
  });

  const cborOgmios = `${name}-ogmios-cbor`;
  await removeContainer(cborOgmios);
  const cluster = await Cluster.make({
    clusterName: name,
    shelleyGenesis,
    conwayGenesis,
    kupo: { enabled: true, logLevel: 'Info' },
    ogmios: { enabled: true, logLevel: 'info' },
  });
  const ogmiosPort = cluster.ports.ogmios;
  if (ogmiosPort === undefined) throw new Error('The devnet has no Ogmios port.');
  const reader = new ChainReader(`ws://localhost:${CBOR_OGMIOS_PORT}`);

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    reader.close();
    await removeContainer(cborOgmios);
    try {
      await Cluster.stop(cluster);
    } finally {
      await Cluster.remove(cluster);
    }
  };

  try {
    await Cluster.start(cluster);
    await waitFor('Ogmios to answer queryNetwork/tip', () =>
      ogmiosCall<unknown>(ogmiosPort, 'queryNetwork/tip').then((tip) => (tip ? tip : null)),
    );
    // Same image, same node socket volume and config mount as the devnet's Ogmios.
    const image = await docker(['inspect', '--format', '{{.Config.Image}}', `${name}-ogmios`]);
    await docker([
      'run', '-d', '--name', cborOgmios, '--volumes-from', `${name}-ogmios`,
      '-e', 'NETWORK=custom', '-p', `${CBOR_OGMIOS_PORT}:1337`, image,
      '--log-level', 'warning', '--host', '0.0.0.0', '--port', '1337',
      '--node-socket', '/ipc/node.socket', '--node-config', '/config/config.json',
      '--include-transaction-cbor',
    ]);
    await waitFor('the CBOR Ogmios to answer', () =>
      ogmiosCall<unknown>(CBOR_OGMIOS_PORT, 'queryNetwork/tip').then((tip) => (tip ? tip : null)),
    );
    await reader.open();
  } catch (err) {
    await stop();
    throw err;
  }

  return {
    cluster,
    slotConfig: Cluster.getSlotConfig(cluster),
    client: (accountIndex) => makeSeedClient(cluster, accountIndex),
    genesisUtxo: (accountIndex) => {
      const utxo = genesisByAccount.get(accountIndex);
      if (!utxo) throw new Error(`No genesis UTxO for account ${accountIndex}.`);
      return utxo;
    },
    ogmios: (method, params) => ogmiosCall(ogmiosPort, method, params),
    cli: async <T>(args: string[]) => {
      const command = ['cardano-cli', 'conway', ...args, '--socket-path', NODE_SOCKET, '--testnet-magic'];
      const output = await Container.execCommand(cluster.cardanoNode, [...command, String(shelleyGenesis.networkMagic)]);
      try {
        return JSON.parse(output) as T;
      } catch {
        throw new Error(`cardano-cli ${args.join(' ')} did not answer JSON: ${output}`);
      }
    },
    onChain: (txHash, timeoutMs = 60_000) =>
      waitFor(`transaction ${txHash} on chain`, async () => {
        if (reader.error) throw new Error(reader.error);
        return reader.get(txHash) ?? null;
      }, timeoutMs),
    tipSlot: () => reader.tipSlot,
    waitFor,
    stop,
  };
}
