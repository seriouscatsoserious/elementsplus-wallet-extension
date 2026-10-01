import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parsePreparedTx, type PreparedTx, type SignResult } from "../../src/adapters/wallet-core.js";
import type { WalletAddress, WalletSession, WalletSnapshot } from "../../src/adapters/elementsplus-wasm.js";
import { WalletController, type ApprovalView, type WalletOpener, type WalletResponse } from "../../src/background/controller.js";
import type { PreparedPlan, WalletOperation } from "../../src/background/operations.js";
import { SettingsStore } from "../../src/background/settings.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";
import { VaultStore } from "../../src/vault.js";
import {
  ADDRESS_1, ADDRESS_2, ECX, GENESIS, MemoryStorage, MNEMONIC, PASSWORD, preparedJson, rawReview, TOKEN_A, txid, type RawReview,
} from "./helpers.js";

class FakeSession implements WalletSession {
  destroyed = 0;
  signed: string[] = [];
  broadcasts: string[] = [];
  review: RawReview = rawReview();
  planExtra: Partial<PreparedPlan> = {};
  plans: WalletOperation[] = [];
  async sync(): Promise<WalletSnapshot> {
    return { tipHeight: 7, receiveAddress: ADDRESS_1, primaryAddress: ADDRESS_1, balances: [{ assetId: ECX, amount: "500000", confirmed: "500000", utxoCount: 1 }], syncedAt: "2026-10-02T00:00:00.000Z" };
  }
  primaryAddress(): string { return ADDRESS_1; }
  async walletAddresses(): Promise<readonly WalletAddress[]> { return [{ address: ADDRESS_1, scriptPubKeyHex: "0014" }]; }
  async plan(operation: WalletOperation): Promise<PreparedPlan> {
    this.plans.push(operation);
    return { prepared: parsePreparedTx(preparedJson(this.review, "c".repeat(64))), ...this.planExtra };
  }
  async planOfferAfterSplit(): Promise<{ prepared: PreparedTx; offeredOutpoint: string }> {
    const review = rawReview({
      kind: "swap_offer", sighash: "SINGLE|ANYONECANPAY", fee: 0, external_outputs: [],
      balance_changes: [{ asset_id: TOKEN_A, amount: "-50" }, { asset_id: ECX, amount: "900" }],
      inputs_signed: [`${txid(77)}:1`],
    });
    return { prepared: parsePreparedTx(preparedJson(review, "d".repeat(64))), offeredOutpoint: `${txid(77)}:1` };
  }
  sign(prepared: PreparedTx, hash: string): SignResult {
    assert.equal(prepared.reviewHash, hash);
    this.signed.push(hash);
    if (prepared.review.kind === "swap_offer") {
      return { txid: txid(78), reviewHash: hash, rawTxHex: null, offer: { version: 1, network: "ecx-alpha", genesis_hash: GENESIS, tx: "00", give: { asset_id: TOKEN_A, amount: "50" }, want: { asset_id: ECX, amount: "900" } } };
    }
    return { txid: txid(77), reviewHash: hash, rawTxHex: "0200", offer: null };
  }
  async broadcast(raw: string, id: string): Promise<string> { this.broadcasts.push(raw); return id; }
  destroy(): void { this.destroyed += 1; }
}

class FakeOpener implements WalletOpener {
  sessions: FakeSession[] = [];
  async generateMnemonic(): Promise<string> { return MNEMONIC; }
  async validateMnemonic(mnemonic: string): Promise<boolean> { return mnemonic === MNEMONIC; }
  async open(): Promise<WalletSession> {
    const session = new FakeSession();
    this.sessions.push(session);
    return session;
  }
}

function ok<T>(response: WalletResponse): T {
  if (!response.ok) assert.fail(`${response.error.code}: ${response.error.message}`);
  return response.result as T;
}

async function setup(now = { value: Date.parse("2026-10-02T00:00:00Z") }) {
  const storage = new MemoryStorage();
  const opener = new FakeOpener();
  const controller = new WalletController({
    vaultStore: new VaultStore(storage),
    storage,
    wallets: opener,
    settings: new SettingsStore(storage),
    identity: ECX_ALPHA_IDENTITY,
    now: () => new Date(now.value),
    approvalTimeoutMilliseconds: 60_000,
  });
  ok(await controller.handle({ type: "vault.create", password: PASSWORD, mnemonic: MNEMONIC }));
  return { storage, opener, controller, now, session: opener.sessions[0]! };
}

const transfer = { kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "100000", feeRate: 2 };

describe("wallet controller", () => {
  it("creates an encrypted vault, unlocks, and exposes only public status", async () => {
    const { storage, controller } = await setup();
    assert.ok(!JSON.stringify(storage.values).includes("abandon"));
    const status = ok<{ initialized: boolean; unlocked: boolean; primaryAddress: string }>(await controller.handle({ type: "wallet.status" }));
    assert.equal(status.initialized, true);
    assert.equal(status.unlocked, true);
    assert.equal(status.primaryAddress, ADDRESS_1);
    ok(await controller.handle({ type: "wallet.lock" }));
    const locked = await controller.handle({ type: "wallet.snapshot" });
    assert.equal(locked.ok, false);
    assert.equal(!locked.ok && locked.error.code, "LOCKED");
    const wrong = await controller.handle({ type: "wallet.unlock", password: "not the password" });
    assert.equal(!wrong.ok && wrong.error.code, "WRONG_PASSWORD");
    ok(await controller.handle({ type: "wallet.unlock", password: PASSWORD }));
    assert.equal(await controller.primaryAddress(), ADDRESS_1);
  });

  it("refuses to overwrite an existing vault unless asked, and validates the phrase", async () => {
    const { controller } = await setup();
    assert.equal((await controller.handle({ type: "vault.create", password: PASSWORD, mnemonic: MNEMONIC })).ok, false);
    const bad = await controller.handle({ type: "vault.create", password: PASSWORD, mnemonic: "zoo ".repeat(11) + "wrong", replace: true });
    assert.equal(bad.ok, false);
    ok(await controller.handle({ type: "vault.create", password: PASSWORD, mnemonic: MNEMONIC, replace: true }));
  });

  it("reveals the phrase only with the password", async () => {
    const { controller } = await setup();
    assert.equal((await controller.handle({ type: "vault.reveal", password: "wrong password!" })).ok, false);
    assert.equal(ok<{ mnemonic: string }>(await controller.handle({ type: "vault.reveal", password: PASSWORD })).mnemonic, MNEMONIC);
  });

  it("signs and broadcasts only with the one-time token bound to the review hash", async () => {
    const { controller, session } = await setup();
    const view = ok<ApprovalView>(await controller.handle({ type: "tx.prepare", operation: transfer }));
    assert.equal(view.reviewHash, "c".repeat(64));
    assert.equal(view.review.externalOutputs[0]!.address, ADDRESS_2);
    const wrongHash = await controller.handle({ type: "tx.approve", approvalId: view.approvalId, approvalToken: view.approvalToken, reviewHash: "d".repeat(64) });
    assert.equal(wrongHash.ok, false);
    // The failed attempt consumed the approval.
    const replay = await controller.handle({ type: "tx.approve", approvalId: view.approvalId, approvalToken: view.approvalToken, reviewHash: view.reviewHash });
    assert.equal(replay.ok, false);
    assert.equal(session.signed.length, 0);

    const second = ok<ApprovalView>(await controller.handle({ type: "tx.prepare", operation: transfer }));
    const result = ok<{ txid: string }>(await controller.handle({ type: "tx.approve", approvalId: second.approvalId, approvalToken: second.approvalToken, reviewHash: second.reviewHash }));
    assert.equal(result.txid, txid(77));
    assert.deepEqual(session.broadcasts, ["0200"]);
    assert.equal((await controller.handle({ type: "tx.approve", approvalId: second.approvalId, approvalToken: second.approvalToken, reviewHash: second.reviewHash })).ok, false);
  });

  it("expires approvals and drops them when the wallet locks", async () => {
    const { controller, now } = await setup();
    const view = ok<ApprovalView>(await controller.handle({ type: "tx.prepare", operation: transfer }));
    now.value += 61_000;
    assert.equal((await controller.handle({ type: "tx.approve", approvalId: view.approvalId, approvalToken: view.approvalToken, reviewHash: view.reviewHash })).ok, false);
    const again = ok<ApprovalView>(await controller.handle({ type: "tx.prepare", operation: transfer }));
    ok(await controller.handle({ type: "wallet.lock" }));
    ok(await controller.handle({ type: "wallet.unlock", password: PASSWORD }));
    assert.equal((await controller.handle({ type: "tx.approve", approvalId: again.approvalId, approvalToken: again.approvalToken, reviewHash: again.reviewHash })).ok, false);
  });

  it("rejects a core review that does not match the request before showing it", async () => {
    const { controller, session } = await setup();
    session.review = rawReview({ external_outputs: [{ address: ADDRESS_1, asset_id: ECX, amount: "100000" }] });
    const response = await controller.handle({ type: "tx.prepare", operation: transfer });
    assert.equal(!response.ok && response.error.code, "INVALID_REQUEST");
  });

  it("lets the wallet UI prepare only transfers, with exact fields", async () => {
    const { controller } = await setup();
    const issuance = await controller.handle({ type: "tx.prepare", operation: { kind: "issuance", name: "A", ticker: "AAA", precision: 0, amount: "1", tokenAmount: "0" } });
    assert.equal(issuance.ok, false);
    assert.equal((await controller.handle({ type: "tx.prepare", operation: transfer, extra: true })).ok, false);
    assert.equal((await controller.handle({ type: "wallet.status", sneaky: 1 })).ok, false);
  });

  it("auto-locks after the configured idle time and destroys the session", async () => {
    const { controller, now, session } = await setup();
    ok(await controller.handle({ type: "settings.update", patch: { autoLockMinutes: 1 } }));
    now.value += 59_000;
    assert.equal(ok<{ unlocked: boolean }>(await controller.handle({ type: "wallet.touch" })).unlocked, true);
    now.value += 61_000;
    assert.equal(ok<{ unlocked: boolean }>(await controller.handle({ type: "wallet.status" })).unlocked, false);
    assert.equal(session.destroyed, 1);
    assert.equal((await controller.handle({ type: "settings.update", patch: { autoLockMinutes: 7 } })).ok, false);
  });

  it("locks when the explorer endpoint changes", async () => {
    const { controller } = await setup();
    const result = ok<{ unlocked: boolean }>(await controller.handle({ type: "settings.update", patch: { explorerUrl: "https://explorer.example.org" } }));
    assert.equal(result.unlocked, false);
    assert.equal((await controller.handle({ type: "settings.update", patch: { explorerUrl: "http://evil.example.org" } })).ok, false);
  });

  it("runs split + offer behind one approval for dApp swap offers", async () => {
    const { controller, session } = await setup();
    session.review = rawReview({ kind: "offer_split", external_outputs: [], balance_changes: [] });
    session.planExtra = { offeredOutpoint: null, splitReceiveIndex: 4 };
    const op: WalletOperation = { kind: "swap_offer", giveAsset: TOKEN_A, giveAmount: "50", wantAsset: ECX, wantAmount: "900", feeRate: 2 };
    const view = await controller.prepare(op, "https://dex.example");
    assert.equal(view.operation.kind, "swap_offer");
    assert.equal(view.origin, "https://dex.example");
    const result = await controller.approve(view.approvalId, view.approvalToken, view.reviewHash);
    assert.equal(result.splitTxid, txid(77));
    assert.equal(result.offer?.give.asset_id, TOKEN_A);
    assert.deepEqual(session.signed, ["c".repeat(64), "d".repeat(64)]);
  });
});
