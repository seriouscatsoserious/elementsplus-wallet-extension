import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  resolveEcxAlphaAddress,
  type FetchImplementation,
} from "../../src/network/ecx-alpha.js";
import {
  ExplorerHdScanError,
  ExplorerHdScanner,
  type ExplorerHdAddressDeriver,
  type ExplorerHdChain,
  type ExplorerHdDerivedAddress,
  type ExplorerHdRawTransactionVerifier,
  type ExplorerHdVerifiedTransaction,
} from "../../src/network/explorer-hd-scan.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BLOCK_HASH = "f".repeat(64);

function bech32Polymod(values: readonly number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const high = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < generators.length; index += 1) {
      if (((high >>> index) & 1) !== 0) checksum ^= generators[index] ?? 0;
    }
    checksum >>>= 0;
  }
  return checksum;
}

function convertToFiveBits(bytes: Uint8Array): number[] {
  let accumulator = 0;
  let bits = 0;
  const result: number[] = [];
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result.push((accumulator >>> bits) & 31);
    }
  }
  if (bits > 0) result.push((accumulator << (5 - bits)) & 31);
  return result;
}

function bech32Address(program: Uint8Array): string {
  const hrp = "elements";
  const words = [0, ...convertToFiveBits(program)];
  const expanded = [
    ...Array.from(hrp, (character) => character.charCodeAt(0) >>> 5),
    0,
    ...Array.from(hrp, (character) => character.charCodeAt(0) & 31),
  ];
  const checksumInput = [...expanded, ...words, 0, 0, 0, 0, 0, 0];
  const checksum = (bech32Polymod(checksumInput) ^ 1) >>> 0;
  const checksumWords = Array.from(
    { length: 6 },
    (_, index) => (checksum >>> (5 * (5 - index))) & 31,
  );
  return `${hrp}1${[...words, ...checksumWords]
    .map((word) => BECH32_CHARSET[word])
    .join("")}`;
}

function derivedAddress(chain: ExplorerHdChain, index: number): ExplorerHdDerivedAddress {
  const program = new Uint8Array(20);
  program[0] = chain === "external" ? 1 : 2;
  new DataView(program.buffer).setUint32(16, index);
  const programHex = Buffer.from(program).toString("hex");
  return Object.freeze({
    chain,
    index,
    address: bech32Address(program),
    scriptPubKeyHex: `0014${programHex}`,
  });
}

function txidFor(chain: ExplorerHdChain, index: number): string {
  const value = BigInt(index + 1 + (chain === "change" ? 1_000_000 : 0));
  return value.toString(16).padStart(64, "0");
}

function emptyStats(): Record<string, number> {
  return {
    funded_txo_count: 0,
    funded_txo_sum: 0,
    spent_txo_count: 0,
    spent_txo_sum: 0,
    tx_count: 0,
  };
}

interface AddressRecord extends ExplorerHdDerivedAddress {
  readonly key: string;
}

interface FixtureOptions {
  readonly used?: ReadonlySet<string>;
  readonly spent?: ReadonlySet<string>;
  readonly alterDerived?: (
    value: ExplorerHdDerivedAddress,
  ) => ExplorerHdDerivedAddress;
  readonly alterSummary?: (
    record: AddressRecord,
    value: Record<string, unknown>,
  ) => unknown;
  readonly alterUtxos?: (
    record: AddressRecord,
    value: readonly Record<string, unknown>[],
  ) => unknown;
  readonly verifier?: ExplorerHdRawTransactionVerifier;
  readonly responseDelayMs?: number;
}

function fixture(options: FixtureOptions = {}): {
  readonly deriveAddress: ExplorerHdAddressDeriver;
  readonly verifyRawTransaction: ExplorerHdRawTransactionVerifier;
  readonly fetchImpl: FetchImplementation;
  readonly metrics: { active: number; maximumActive: number; calls: string[] };
} {
  const records = new Map<string, AddressRecord>();
  const metrics = { active: 0, maximumActive: 0, calls: [] as string[] };
  const used = options.used ?? new Set<string>();
  const spent = options.spent ?? new Set<string>();

  const deriveAddress: ExplorerHdAddressDeriver = async ({ chain, index }) => {
    const base = derivedAddress(chain, index);
    const altered = options.alterDerived?.(base) ?? base;
    const record = { ...altered, key: `${chain}:${index}` };
    records.set(altered.address, record);
    records.set(resolveEcxAlphaAddress(altered.address).canonical, record);
    return altered;
  };

  const fetchImpl: FetchImplementation = async (input, init) => {
    assert.equal(init?.method, "GET");
    assert.equal(init?.credentials, "omit");
    const path = new URL(input.toString()).pathname;
    metrics.calls.push(path);
    metrics.active += 1;
    metrics.maximumActive = Math.max(metrics.maximumActive, metrics.active);
    try {
      if ((options.responseDelayMs ?? 0) > 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, options.responseDelayMs));
      }
      if (path === "/api/block-height/0") {
        return new Response(ECX_ALPHA_IDENTITY.genesisHash);
      }
      if (path === `/api/asset/${ECX_ALPHA_IDENTITY.nativeAssetId}`) {
        return Response.json({ asset_id: ECX_ALPHA_IDENTITY.nativeAssetId });
      }
      if (path === "/api/blocks/tip/hash") return new Response(BLOCK_HASH);
      if (path === `/api/block/${BLOCK_HASH}`) {
        return Response.json({ id: BLOCK_HASH, height: 321 });
      }
      const rawMatch = /^\/api\/tx\/([0-9a-f]{64})\/hex$/u.exec(path);
      if (rawMatch !== null) return new Response("02000000\n");

      const addressMatch = /^\/api\/address\/([^/]+)(\/utxo)?$/u.exec(path);
      if (addressMatch === null) return new Response("not found", { status: 404 });
      const address = decodeURIComponent(addressMatch[1] ?? "");
      const record = records.get(address);
      if (record === undefined) return new Response("unknown address", { status: 404 });
      const isUsed = used.has(record.key);
      const isSpent = spent.has(record.key);
      const value = 1_000;
      if (addressMatch[2] === "/utxo") {
        const base = isUsed && !isSpent
          ? [
            {
              txid: txidFor(record.chain, record.index),
              vout: 0,
              value,
              asset: ECX_ALPHA_IDENTITY.nativeAssetId,
              status: {
                confirmed: true,
                block_height: 300,
                block_hash: "e".repeat(64),
                block_time: 1_789_000_000,
              },
            },
          ]
          : [];
        return Response.json(options.alterUtxos?.(record, base) ?? base);
      }

      const chainStats = isUsed
        ? {
          funded_txo_count: 1,
          funded_txo_sum: value,
          spent_txo_count: 0,
          spent_txo_sum: 0,
          tx_count: 1,
        }
        : emptyStats();
      const mempoolStats = isSpent
        ? {
          funded_txo_count: 0,
          funded_txo_sum: 0,
          spent_txo_count: 1,
          spent_txo_sum: value,
          tx_count: 1,
        }
        : emptyStats();
      const base = {
        address: record.address,
        chain_stats: chainStats,
        mempool_stats: mempoolStats,
      };
      return Response.json(options.alterSummary?.(record, base) ?? base);
    } finally {
      metrics.active -= 1;
    }
  };

  const verifyRawTransaction: ExplorerHdRawTransactionVerifier = options.verifier
    ?? (async (request): Promise<ExplorerHdVerifiedTransaction> => Object.freeze({
      txid: request.expectedTxid,
      outputs: Object.freeze(request.expectedWalletOutputs.map((output) => Object.freeze({
        vout: output.vout,
        scriptPubKeyHex: output.scriptPubKeyHex,
        assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        valueAtomic: "1000",
      }))),
    }));

  return { deriveAddress, verifyRawTransaction, fetchImpl, metrics };
}

function scanner(
  harness: ReturnType<typeof fixture>,
  overrides: ConstructorParameters<typeof ExplorerHdScanner>[2] = {},
): ExplorerHdScanner {
  return new ExplorerHdScanner(harness.deriveAddress, harness.verifyRawTransaction, {
    explorerUrl: "https://explorer.example",
    fetchImpl: harness.fetchImpl,
    gapLimit: 2,
    maximumIndex: 20,
    pageSize: 2,
    concurrency: 2,
    ...overrides,
  });
}

describe("explorer-backed HD discovery", () => {
  it("scans both chains in pages, verifies funding bytes, and returns deterministic ordering", async () => {
    const harness = fixture({
      used: new Set(["external:0", "external:2", "change:1"]),
      responseDelayMs: 1,
    });
    const snapshot = await scanner(harness).scan();

    assert.equal(snapshot.source.identityPinsMatched, true);
    assert.equal(snapshot.source.headerChainVerified, false);
    assert.deepEqual(snapshot.tip, { height: 321, hash: BLOCK_HASH });
    assert.deepEqual(snapshot.scan.chains, [
      {
        chain: "external",
        lastScannedIndex: 4,
        highestUsedIndex: 2,
        nextUnusedIndex: 3,
        trailingUnused: 2,
        pagesScanned: 3,
      },
      {
        chain: "change",
        lastScannedIndex: 3,
        highestUsedIndex: 1,
        nextUnusedIndex: 2,
        trailingUnused: 2,
        pagesScanned: 2,
      },
    ]);
    assert.deepEqual(
      snapshot.addresses.map(({ chain, index }) => `${chain}:${index}`),
      [
        "external:0",
        "external:1",
        "external:2",
        "external:3",
        "external:4",
        "change:0",
        "change:1",
        "change:2",
        "change:3",
      ],
    );
    assert.deepEqual(
      snapshot.utxos.map(({ txid }) => txid),
      [txidFor("external", 0), txidFor("external", 2), txidFor("change", 1)].sort(),
    );
    assert.deepEqual(
      snapshot.fundingTransactions.map(({ txid }) => txid),
      [txidFor("external", 0), txidFor("external", 2), txidFor("change", 1)].sort(),
    );
    assert(harness.metrics.maximumActive <= 2);
    assert(Object.isFrozen(snapshot));
    assert(Object.isFrozen(snapshot.addresses));
    assert(Object.isFrozen(snapshot.utxos));
  });

  it("handles a mempool spend of a confirmed output without misreading mempool stats", async () => {
    const harness = fixture({
      used: new Set(["external:0"]),
      spent: new Set(["external:0"]),
    });
    const snapshot = await scanner(harness).scan();

    const address = snapshot.addresses.find(
      (candidate) => candidate.chain === "external" && candidate.index === 0,
    );
    assert.equal(address?.used, true);
    assert.equal(address?.mempoolStats.spentOutputCount, 1);
    assert.equal(snapshot.utxos.length, 0);
    assert.equal(snapshot.fundingTransactions.length, 0);
  });

  it("normalizes supported address aliases before querying", async () => {
    const canonical = "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh";
    const alias = "ert1qw508d6qejxtdg4y5r3zarvary0c5xw7kuu73e0";
    const harness = fixture({
      alterDerived: (value) => value.index === 0 && value.chain === "external"
        ? { ...value, address: alias }
        : value,
    });
    const snapshot = await scanner(harness, { gapLimit: 1 }).scan();

    assert(snapshot.addresses.every((address) => address.address.startsWith("elements1")));
    assert(harness.metrics.calls.includes(`/api/address/${canonical}`));
  });
});

describe("HD scan fail-closed validation", () => {
  it("rejects an address deriver that returns the wrong requested index", async () => {
    const harness = fixture({
      alterDerived: (value) => ({ ...value, index: value.index + 1 }),
    });
    await assert.rejects(scanner(harness, { gapLimit: 1 }).scan(), /different chain or index/u);
  });

  it("rejects duplicate derived addresses across the external and change chains", async () => {
    const duplicate = derivedAddress("external", 0);
    const harness = fixture({
      alterDerived: (value) => value.index === 0
        ? { ...value, address: duplicate.address, scriptPubKeyHex: duplicate.scriptPubKeyHex }
        : value,
    });
    await assert.rejects(scanner(harness, { gapLimit: 1 }).scan(), /duplicate address/u);
  });

  it("rejects statistics that disagree with the UTXO set", async () => {
    const harness = fixture({
      alterSummary: (record, value) => record.key === "external:0"
        ? {
          ...value,
          chain_stats: {
            funded_txo_count: 1,
            funded_txo_sum: 1000,
            spent_txo_count: 0,
            spent_txo_sum: 0,
            tx_count: 1,
          },
        }
        : value,
    });
    await assert.rejects(scanner(harness).scan(), /inconsistent statistics and UTXOs/u);
  });

  it("rejects duplicate outpoints returned for different wallet addresses", async () => {
    const duplicateTxid = "a".repeat(64);
    const harness = fixture({
      used: new Set(["external:0", "change:0"]),
      alterUtxos: (record, value) => record.index === 0
        ? value.map((utxo) => ({ ...utxo, txid: duplicateTxid }))
        : value,
    });
    await assert.rejects(scanner(harness).scan(), /one outpoint for multiple wallet addresses/u);
  });

  it("rejects a locally verified output that disagrees with the derived script", async () => {
    const harness = fixture({
      used: new Set(["external:0"]),
      verifier: async (request) => ({
        txid: request.expectedTxid,
        outputs: [{
          vout: 0,
          scriptPubKeyHex: "0014" + "99".repeat(20),
          assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
          valueAtomic: "1000",
        }],
      }),
    });
    await assert.rejects(scanner(harness).scan(), /script does not match derivation/u);
  });

  it("rejects explorer UTXO indexes outside uint32", async () => {
    const harness = fixture({
      used: new Set(["external:0"]),
      alterUtxos: (record, value) => record.key === "external:0"
        ? value.map((utxo) => ({ ...utxo, vout: 0x1_0000_0000 }))
        : value,
    });
    await assert.rejects(scanner(harness).scan(), /vout is not an in-range/u);
  });

  it("fails rather than returning a truncated wallet when maximumIndex exhausts the gap", async () => {
    const harness = fixture();
    await assert.rejects(
      scanner(harness, { gapLimit: 2, maximumIndex: 0, pageSize: 1 }).scan(),
      /maximum index before satisfying the gap limit/u,
    );
  });

  it("rejects a wrong immutable identity pin and never starts derivation", async () => {
    let derived = 0;
    const harness = fixture();
    const fetchImpl: FetchImplementation = async (input, init) => {
      const path = new URL(input.toString()).pathname;
      if (path === "/api/block-height/0") return new Response("0".repeat(64));
      return await harness.fetchImpl(input, init);
    };
    const derive: ExplorerHdAddressDeriver = async (request) => {
      derived += 1;
      return await harness.deriveAddress(request);
    };
    const candidate = new ExplorerHdScanner(derive, harness.verifyRawTransaction, {
      explorerUrl: "https://explorer.example",
      fetchImpl,
      gapLimit: 1,
      maximumIndex: 1,
    });

    await assert.rejects(candidate.scan(), ExplorerHdScanError);
    assert.equal(derived, 0);
  });
});
