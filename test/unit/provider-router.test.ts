import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parseTxReview } from "../../src/adapters/wallet-core.js";
import type { WalletSnapshot } from "../../src/adapters/elementsplus-wasm.js";
import type { ApprovalResult, ApprovalView } from "../../src/background/controller.js";
import type { WalletOperation } from "../../src/background/operations.js";
import { ProviderErrorCode, ProviderRouter, type ProviderResponse, type RouterController } from "../../src/background/provider-router.js";
import { SitePermissions } from "../../src/background/settings.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";
import { ADDRESS_1, ADDRESS_2, ECX, MemoryStorage, rawReview, txid } from "./helpers.js";

const DEX = "https://dex.example";
const EVIL = "https://evil.example";

class FakeController implements RouterController {
  unlocked = true;
  prepared: { operation: WalletOperation; origin: string }[] = [];
  approvals: string[] = [];
  rejected: string[] = [];
  isUnlocked(): boolean { return this.unlocked; }
  async primaryAddress(): Promise<string | null> { return this.unlocked ? ADDRESS_1 : null; }
  async snapshot(): Promise<WalletSnapshot> {
    return { tipHeight: 1, receiveAddress: ADDRESS_1, primaryAddress: ADDRESS_1, balances: [{ assetId: ECX, amount: "10", confirmed: "7", utxoCount: 2 }], syncedAt: "x" };
  }
  async prepare(operation: WalletOperation, origin: string): Promise<ApprovalView> {
    this.prepared.push({ operation, origin });
    const n = this.prepared.length;
    return {
      approvalId: `approval${n}`.padEnd(22, "x"),
      approvalToken: "t".repeat(43),
      reviewHash: "c".repeat(64),
      expiresAt: "2026-10-02T00:05:00.000Z",
      origin,
      operation: { kind: "transfer", feeRate: 2 },
      review: parseTxReview(rawReview()),
      tokens: {},
    };
  }
  async approve(approvalId: string, token: string, hash: string): Promise<ApprovalResult> {
    assert.equal(token, "t".repeat(43));
    assert.equal(hash, "c".repeat(64));
    this.approvals.push(approvalId);
    return { txid: txid(42) };
  }
  reject(approvalId: string): void { this.rejected.push(approvalId); }
}

function setup() {
  const controller = new FakeController();
  const permissions = new SitePermissions(new MemoryStorage());
  const opened: string[] = [];
  const events: { origin: string; event: string; data: unknown }[] = [];
  let counter = 0;
  const router = new ProviderRouter({
    controller,
    permissions,
    identity: ECX_ALPHA_IDENTITY,
    randomId: () => `request-${(counter += 1)}`,
    openApproval: async (id) => { opened.push(id); return 100 + opened.length; },
    emit: (origin, event, data) => events.push({ origin, event, data }),
  });
  return { controller, permissions, router, opened, events };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

function errorCode(response: ProviderResponse): number | undefined {
  return "error" in response ? response.error.code : undefined;
}

describe("dApp provider router", () => {
  it("rejects unknown methods, malformed requests and unauthorized origins", async () => {
    const { router } = setup();
    assert.equal(errorCode(await router.request(DEX, { method: "eth_accounts" })), ProviderErrorCode.UNSUPPORTED_METHOD);
    assert.equal(errorCode(await router.request(DEX, { method: "ep_getAddress", extra: 1 })), ProviderErrorCode.INVALID_PARAMS);
    assert.equal(errorCode(await router.request(DEX, "ep_getAddress")), ProviderErrorCode.INVALID_PARAMS);
    for (const method of ["ep_getAddress", "ep_getBalances", "ep_sendTransfer", "ep_issueAsset"]) {
      assert.equal(errorCode(await router.request(DEX, { method, params: {} })), ProviderErrorCode.UNAUTHORIZED, method);
    }
  });

  it("connects via an approval window and binds the permission to that origin only", async () => {
    const { router, opened, permissions } = setup();
    const pending = router.request(DEX, { method: "ep_connect" });
    await tick();
    assert.deepEqual(opened, ["request-1"]);
    const described = await router.describe("request-1") as { kind: string; origin: string };
    assert.equal(described.kind, "connect");
    assert.equal(described.origin, DEX);
    await router.resolve({ requestId: "request-1", approved: true });
    const response = await pending;
    assert.ok("result" in response);
    assert.deepEqual(response.result, {
      address: ADDRESS_1,
      network: { name: ECX_ALPHA_IDENTITY.displayName, genesisHash: ECX_ALPHA_IDENTITY.genesisHash, policyAsset: ECX_ALPHA_IDENTITY.nativeAssetId },
    });
    assert.equal(await permissions.has(DEX), true);
    // A second connect from the same origin is remembered; no new window.
    assert.ok("result" in await router.request(DEX, { method: "ep_connect" }));
    assert.equal(opened.length, 1);
    // Another origin is still unauthorized.
    assert.equal(errorCode(await router.request(EVIL, { method: "ep_getAddress" })), ProviderErrorCode.UNAUTHORIZED);
    assert.deepEqual(await router.request(DEX, { method: "ep_getAddress" }), { result: { address: ADDRESS_1 } });
    assert.deepEqual(await router.request(DEX, { method: "ep_getBalances" }), { result: [{ assetId: ECX, amount: "10", confirmed: "7" }] });
  });

  it("returns 4001 when the user rejects or closes the window", async () => {
    const { router } = setup();
    const rejected = router.request(DEX, { method: "ep_connect" });
    await tick();
    await router.resolve({ requestId: "request-1", approved: false });
    assert.equal(errorCode(await rejected), ProviderErrorCode.USER_REJECTED);
    const closed = router.request(DEX, { method: "ep_connect" });
    await tick();
    router.windowClosed(102);
    assert.equal(errorCode(await closed), ProviderErrorCode.USER_REJECTED);
  });

  it("validates transaction params before opening any window", async () => {
    const { router, permissions, opened } = setup();
    await permissions.grant(DEX, new Date());
    const cases = [
      { assetId: ECX, amount: 5, recipient: ADDRESS_2 },
      { assetId: ECX, amount: "5" },
      { assetId: ECX, amount: "5", recipient: ADDRESS_2, memo: "hi" },
      { assetId: "zz", amount: "5", recipient: ADDRESS_2 },
    ];
    for (const params of cases) {
      assert.equal(errorCode(await router.request(DEX, { method: "ep_sendTransfer", params })), ProviderErrorCode.INVALID_PARAMS, JSON.stringify(params));
    }
    assert.equal(opened.length, 0);
  });

  it("prepares for the requesting origin and returns the txid after approval", async () => {
    const { router, permissions, controller } = setup();
    await permissions.grant(DEX, new Date());
    const pending = router.request(DEX, { method: "ep_sendTransfer", params: { assetId: ECX, amount: "100000", recipient: ADDRESS_2 } });
    await tick();
    const described = await router.describe("request-1") as { approval: ApprovalView };
    assert.equal(controller.prepared[0]!.origin, DEX);
    assert.equal(controller.prepared[0]!.operation.kind, "transfer");
    await assert.rejects(router.resolve({ requestId: "request-1", approved: true }), /token/u);
    // The failed resolve did not consume the request; a proper approval succeeds.
    const done = await router.resolve({ requestId: "request-1", approved: true, approvalToken: described.approval.approvalToken, reviewHash: described.approval.reviewHash }) as { result: ApprovalResult };
    assert.equal(done.result.txid, txid(42));
    assert.deepEqual(await pending, { result: { txid: txid(42) } });
  });

  it("rejects the prepared approval when the user declines a transaction", async () => {
    const { router, permissions, controller } = setup();
    await permissions.grant(DEX, new Date());
    const pending = router.request(DEX, { method: "ep_cancelSwapOffer", params: { txid: txid(3), vout: 1 } });
    await tick();
    const described = await router.describe("request-1") as { approval: ApprovalView };
    await router.resolve({ requestId: "request-1", approved: false });
    assert.equal(errorCode(await pending), ProviderErrorCode.USER_REJECTED);
    assert.deepEqual(controller.rejected, [described.approval.approvalId]);
  });

  it("asks a locked wallet to unlock before reading balances", async () => {
    const { router, permissions, controller, opened } = setup();
    await permissions.grant(DEX, new Date());
    controller.unlocked = false;
    const pending = router.request(DEX, { method: "ep_getBalances" });
    await tick();
    assert.equal((await router.describe(opened[0]!) as { kind: string; locked: boolean }).locked, true);
    await assert.rejects(router.resolve({ requestId: opened[0]!, approved: true }), /unlock/u);
    controller.unlocked = true;
    await router.resolve({ requestId: opened[0]!, approved: true });
    assert.ok("result" in await pending);
  });

  it("disconnect revokes the origin and notifies its pages", async () => {
    const { router, permissions, events } = setup();
    await permissions.grant(DEX, new Date());
    await permissions.grant(EVIL, new Date());
    assert.deepEqual(await router.request(DEX, { method: "ep_disconnect" }), { result: null });
    assert.equal(await permissions.has(DEX), false);
    assert.equal(await permissions.has(EVIL), true);
    assert.deepEqual(events.map((entry) => [entry.origin, entry.event]), [[DEX, "accountsChanged"], [DEX, "disconnect"]]);
    await router.revokeSite(EVIL);
    assert.equal(errorCode(await router.request(EVIL, { method: "ep_getAddress" })), ProviderErrorCode.UNAUTHORIZED);
  });
});
