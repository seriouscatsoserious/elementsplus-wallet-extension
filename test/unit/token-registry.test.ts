import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { TokenRegistry } from "../../src/background/token-registry.js";
import { ECX, MemoryStorage, TOKEN_A, TOKEN_B, txid } from "./helpers.js";

function registry(entries: Record<string, unknown>, verifiedAs: { assetId: string; tokenId: string | null }) {
  const calls: string[] = [];
  const storage = new MemoryStorage();
  const fetchImpl = async (input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    if (url.startsWith("https://dex.example/api/assets/")) {
      const entry = entries[url.slice("https://dex.example/api/assets/".length)];
      return entry === undefined ? new Response("not found", { status: 404 }) : new Response(JSON.stringify(entry));
    }
    if (url === `https://explorer.example/api/tx/${txid(1)}/hex`) return new Response("0200aa\n");
    return new Response("", { status: 404 });
  };
  const verifications: unknown[] = [];
  const tokens = new TokenRegistry({
    storage,
    fetchImpl,
    endpoints: async () => ({ registryUrl: "https://dex.example/api/assets", explorerUrl: "https://explorer.example" }),
    nativeAsset: { assetId: ECX, name: "ECX Alpha", ticker: "ECX" },
    verifyIssuance: async (request) => {
      verifications.push(request);
      return { ...verifiedAs, contractHash: "f".repeat(64) };
    },
  });
  return { tokens, calls, verifications, storage };
}

const contract = { name: "Alpha", ticker: "ALPHA", precision: 2, version: 0 };

describe("token registry", () => {
  it("trusts metadata only after core verification of the issuance", async () => {
    const { tokens, verifications, calls } = registry({ [TOKEN_A]: { asset_id: TOKEN_A, contract, issuance_txid: txid(1), issuance_vin: 0 } }, { assetId: TOKEN_A, tokenId: null });
    const result = await tokens.lookup([ECX, TOKEN_A, TOKEN_B]);
    assert.deepEqual(result[TOKEN_A], { assetId: TOKEN_A, name: "Alpha", ticker: "ALPHA", precision: 2, verified: true, native: false, tokenFor: null });
    assert.equal(result[ECX]!.native, true);
    assert.equal(result[TOKEN_B]!.verified, false);
    assert.equal(result[TOKEN_B]!.name, "Unknown asset");
    assert.equal(result[TOKEN_B]!.precision, 0);
    assert.deepEqual(verifications, [{ rawTxHex: "0200aa", expectedTxid: txid(1), vin: 0, contract }]);
    // Cached: no further network access.
    const before = calls.length;
    assert.equal((await tokens.lookup([TOKEN_A]))[TOKEN_A]!.verified, true);
    assert.equal(calls.length, before);
  });

  it("refuses entries whose issuance proves a different asset", async () => {
    const { tokens } = registry({ [TOKEN_A]: { asset_id: TOKEN_A, contract, issuance_txid: txid(1), issuance_vin: 0 } }, { assetId: TOKEN_B, tokenId: null });
    assert.equal((await tokens.lookup([TOKEN_A]))[TOKEN_A]!.verified, false);
  });

  it("never lets a token impersonate the native ticker", async () => {
    const { tokens, verifications } = registry({ [TOKEN_A]: { contract: { ...contract, ticker: "ecx" }, issuance_txid: txid(1), issuance_vin: 0 } }, { assetId: TOKEN_A, tokenId: null });
    assert.equal((await tokens.lookup([TOKEN_A]))[TOKEN_A]!.verified, false);
    assert.equal(verifications.length, 0);
  });

  it("labels reissuance tokens of verified assets", async () => {
    const { tokens } = registry({ [TOKEN_B]: { contract, issuance_txid: txid(1), issuance_vin: 0 } }, { assetId: TOKEN_A, tokenId: TOKEN_B });
    const info = (await tokens.lookup([TOKEN_B]))[TOKEN_B]!;
    assert.equal(info.verified, true);
    assert.equal(info.tokenFor, TOKEN_A);
    assert.equal(info.precision, 0);
  });
});
