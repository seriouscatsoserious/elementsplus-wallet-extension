import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  EcxAlphaAddressError,
  EcxAlphaApiError,
  EcxAlphaEsploraClient,
  EcxAlphaIdentityError,
  resolveEcxAlphaAddress,
  type FetchImplementation,
} from "../../src/network/ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";

type MockBody = string | Readonly<Record<string, unknown>>;

interface MockRoute {
  readonly body: MockBody;
  readonly status?: number;
}

function mockExplorer(routes: Readonly<Record<string, MockRoute>>): {
  readonly fetchImpl: FetchImplementation;
  readonly calls: string[];
} {
  const calls: string[] = [];
  return {
    calls,
    fetchImpl: async (input, init) => {
      assert.equal(init?.method, "GET");
      assert.equal(init?.credentials, "omit");
      const url = new URL(input.toString());
      calls.push(url.pathname);
      const route = routes[url.pathname];
      if (route === undefined) return new Response("not mocked", { status: 404 });
      const body = typeof route.body === "string" ? route.body : JSON.stringify(route.body);
      return new Response(body, {
        status: route.status ?? 200,
        headers: {
          "Content-Type": typeof route.body === "string" ? "text/plain" : "application/json",
        },
      });
    },
  };
}

function identityRoutes(): Record<string, MockRoute> {
  return {
    "/api/block-height/0": { body: `${ECX_ALPHA_IDENTITY.genesisHash}\n` },
    [`/api/asset/${ECX_ALPHA_IDENTITY.nativeAssetId}`]: {
      body: { asset_id: ECX_ALPHA_IDENTITY.nativeAssetId },
    },
  };
}

describe("ECX Alpha explorer identity", () => {
  it("verifies the immutable genesis and policy asset pins", async () => {
    const mock = mockExplorer(identityRoutes());
    const client = new EcxAlphaEsploraClient({
      explorerUrl: "https://explorer.example",
      fetchImpl: mock.fetchImpl,
    });

    const identity = await client.verifyIdentity();

    assert.equal(identity.genesisHash, ECX_ALPHA_IDENTITY.genesisHash);
    assert.equal(identity.policyAssetId, ECX_ALPHA_IDENTITY.nativeAssetId);
    assert.equal(identity.explorerApiUrl, "https://explorer.example/api");
    assert(Object.isFrozen(identity));
    assert.deepEqual(
      new Set(mock.calls),
      new Set([
        "/api/block-height/0",
        `/api/asset/${ECX_ALPHA_IDENTITY.nativeAssetId}`,
      ]),
    );
  });

  it("fails closed on a different genesis", async () => {
    const routes = identityRoutes();
    routes["/api/block-height/0"] = { body: "a".repeat(64) };
    const mock = mockExplorer(routes);
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    await assert.rejects(client.verifyIdentity(), EcxAlphaIdentityError);
  });

  it("fails closed when policy-asset lookup does not identify the pinned asset", async () => {
    const routes = identityRoutes();
    routes[`/api/asset/${ECX_ALPHA_IDENTITY.nativeAssetId}`] = {
      body: { asset_id: "b".repeat(64) },
    };
    const mock = mockExplorer(routes);
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    await assert.rejects(client.verifyIdentity(), EcxAlphaIdentityError);
  });

  it("does not accept credentials, queries, or non-HTTP explorer URLs", () => {
    assert.throws(
      () => new EcxAlphaEsploraClient({ explorerUrl: "ftp://explorer.example" }),
      TypeError,
    );
    assert.throws(
      () => new EcxAlphaEsploraClient({ explorerUrl: "https://user@example.test" }),
      TypeError,
    );
    assert.throws(
      () => new EcxAlphaEsploraClient({ explorerUrl: "https://example.test/?network=alpha" }),
      TypeError,
    );
  });
});

describe("ECX Alpha live status parsing", () => {
  it("returns a coherent tip plus mempool and sorted fee status", async () => {
    const tipHash = "c".repeat(64);
    const previousHash = "d".repeat(64);
    const routes: Record<string, MockRoute> = {
      ...identityRoutes(),
      "/api/blocks/tip/hash": { body: tipHash },
      [`/api/block/${tipHash}`]: {
        body: {
          id: tipHash,
          height: 223,
          timestamp: 1_789_780_337,
          tx_count: 3,
          size: 514,
          weight: 1_927,
          previousblockhash: previousHash,
        },
      },
      "/api/mempool": {
        body: {
          count: 2,
          vsize: 401,
          total_fee: 900,
          fee_histogram: [
            [2.5, 101],
            [1, 300],
          ],
        },
      },
      "/api/fee-estimates": { body: { "6": 0.4, "1": 1.2 } },
    };
    const mock = mockExplorer(routes);
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    const status = await client.getNetworkStatus();

    assert.equal(status.tip.hash, tipHash);
    assert.equal(status.tip.height, 223);
    assert.equal(status.tip.previousBlockHash, previousHash);
    assert.equal(status.mempool.count, 2);
    assert.deepEqual(status.mempool.feeHistogram, [
      [2.5, 101],
      [1, 300],
    ]);
    assert.deepEqual(status.fees.estimates, [
      { confirmationTargetBlocks: 1, satsPerVbyte: 1.2 },
      { confirmationTargetBlocks: 6, satsPerVbyte: 0.4 },
    ]);
    assert.equal(status.fees.available, true);
    assert(Object.isFrozen(status));
  });

  it("treats an empty fee-estimate response as unavailable rather than fabricating a rate", async () => {
    const mock = mockExplorer({ "/api/fee-estimates": { body: {} } });
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    assert.deepEqual(await client.getFeeStatus(), { available: false, estimates: [] });
  });

  it("rejects malformed untrusted explorer fields", async () => {
    const mock = mockExplorer({
      "/api/mempool": {
        body: { count: -1, vsize: 0, total_fee: 0, fee_histogram: [] },
      },
    });
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    await assert.rejects(client.getMempool(), EcxAlphaApiError);
  });

  it("surfaces HTTP status without incorporating an untrusted response body", async () => {
    const mock = mockExplorer({
      "/api/fee-estimates": { body: "server secret", status: 503 },
    });
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    await assert.rejects(client.getFeeStatus(), (error: unknown) => {
      assert(error instanceof EcxAlphaApiError);
      assert.equal(error.status, 503);
      assert(!error.message.includes("server secret"));
      return true;
    });
  });

  it("rejects explorer bodies larger than 1 MiB even without Content-Length", async () => {
    const oversized = new Uint8Array(1024 * 1024 + 1);
    const fetchImpl: FetchImplementation = async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(oversized.subarray(0, 600_000));
          controller.enqueue(oversized.subarray(600_000));
          controller.close();
        },
      });
      return new Response(stream, { status: 200 });
    };
    const client = new EcxAlphaEsploraClient({ fetchImpl });

    await assert.rejects(client.getFeeStatus(), /exceeds the 1 MiB limit/u);
  });

  it("rejects an oversized declared Content-Length before consuming the body", async () => {
    const fetchImpl: FetchImplementation = async () =>
      new Response("{}", {
        status: 200,
        headers: { "Content-Length": String(1024 * 1024 + 1) },
      });
    const client = new EcxAlphaEsploraClient({ fetchImpl });

    await assert.rejects(client.getFeeStatus(), /exceeds the 1 MiB limit/u);
  });

  it("aborts a hung request at the configured timeout", async () => {
    const fetchImpl: FetchImplementation = async (_input, init) =>
      await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), {
          once: true,
        });
      });
    const client = new EcxAlphaEsploraClient({ fetchImpl, requestTimeoutMs: 10 });

    await assert.rejects(client.getFeeStatus(), /timed out/u);
  });
});

describe("canonical and LWK-alias address support", () => {
  const alias = "ert1qw508d6qejxtdg4y5r3zarvary0c5xw7kuu73e0";
  const canonical = "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh";
  const confidentialAlias =
    "el1pqwp9ze75659cn5ad0hw25nt2kv7j882gudn636hnh4qvjcmjh6jq5ca0d4cgl009m5rn5w0n3k2cqa3ths2qf7s8q6x2xplwgvlfhg0atxwjah9089tf";
  const confidentialCanonical =
    "elementsl1pqwp9ze75659cn5ad0hw25nt2kv7j882gudn636hnh4qvjcmjh6jq5ca0d4cgl009m5rn5w0n3k2cqa3ths2qf7s8q6x2xplwgvlfhg0ag5kxszmzfcmc";

  it("re-encodes unconfidential aliases with a new checksum", () => {
    const resolvedAlias = resolveEcxAlphaAddress(alias);
    const resolvedCanonical = resolveEcxAlphaAddress(canonical);

    assert.equal(resolvedAlias.canonical, canonical);
    assert.equal(resolvedAlias.alias, alias);
    assert.equal(resolvedAlias.notation, "lwk-alias");
    assert.equal(resolvedAlias.confidential, false);
    assert.equal(resolvedAlias.witnessProgramLength, 20);
    assert.equal(resolvedCanonical.alias, alias);
    assert.equal(resolvedCanonical.notation, "canonical");
  });

  it("re-encodes Blech32m confidential aliases with the 12-symbol checksum", () => {
    const resolvedAlias = resolveEcxAlphaAddress(confidentialAlias);
    const resolvedCanonical = resolveEcxAlphaAddress(confidentialCanonical);

    assert.equal(resolvedAlias.canonical, confidentialCanonical);
    assert.equal(resolvedCanonical.alias, confidentialAlias);
    assert.equal(resolvedAlias.confidential, true);
    assert.equal(resolvedAlias.witnessProgramLength, 32);
    assert.equal(resolvedAlias.witnessVersion, 1);
  });

  it("rejects wrong checksums and unrelated networks", () => {
    assert.throws(() => resolveEcxAlphaAddress(`${alias.slice(0, -1)}q`), EcxAlphaAddressError);
    assert.throws(
      () => resolveEcxAlphaAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
      EcxAlphaAddressError,
    );
  });

  it("canonicalizes an alias before querying address statistics", async () => {
    const path = `/api/address/${canonical}`;
    const mock = mockExplorer({
      [path]: {
        body: {
          address: canonical,
          chain_stats: { funded_txo_count: 2, spent_txo_count: 1, tx_count: 2 },
          mempool_stats: { funded_txo_count: 1, spent_txo_count: 0, tx_count: 1 },
        },
      },
    });
    const client = new EcxAlphaEsploraClient({ fetchImpl: mock.fetchImpl });

    const summary = await client.getAddressSummary(alias);

    assert.deepEqual(mock.calls, [path]);
    assert.equal(summary.address.canonical, canonical);
    assert.deepEqual(summary.chain, {
      fundedOutputCount: 2,
      spentOutputCount: 1,
      transactionCount: 2,
    });
  });
});
