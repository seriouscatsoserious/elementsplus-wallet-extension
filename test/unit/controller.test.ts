import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type {
  BurnDraft,
  IssueDraft,
  LwkWalletAdapter,
  LwkWalletSession,
  PreparedTransaction,
  ReissueDraft,
  TransferDraft,
} from "../../src/adapters/lwk.js";
import { validateWalletSnapshot, WalletController } from "../../src/background/controller.js";
import { ECX_ALPHA_IDENTITY, type EcxAlphaIdentity } from "../../src/network/identity.js";
import type { ExtensionStorageArea } from "../../src/platform/browser.js";
import { encryptVault, VaultStore, type WalletVaultPayload } from "../../src/vault.js";

class MemoryStorage implements ExtensionStorageArea {
  readonly values: Record<string, unknown> = {};
  async get(keys: string | readonly string[]): Promise<Record<string, unknown>> {
    const requested = typeof keys === "string" ? [keys] : keys;
    return Object.fromEntries(requested.filter((key) => this.values[key] !== undefined).map((key) => [key, this.values[key]]));
  }
  async set(items: Record<string, unknown>): Promise<void> { Object.assign(this.values, items); }
  async remove(keys: string | readonly string[]): Promise<void> {
    for (const key of typeof keys === "string" ? [keys] : keys) delete this.values[key];
  }
}

class FakeSession implements LwkWalletSession {
  destroyed = 0;
  prepareCalls = 0;
  signCalls = 0;
  lastSigned: PreparedTransaction | undefined;
  async sync(_signal: AbortSignal) {
    return {
      chain: {
        genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
        nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        backend: "explorer" as const,
        headerChainVerified: false as const,
        transactionPolicy: "explicit-only" as const,
      },
      tipHeight: 1,
      tipHash: "0".repeat(64),
      receiveAddress: "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh",
      assets: [{
        assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        ticker: "ECX",
        name: "Alpha ECX",
        amountAtomic: "0",
        confirmedAtomic: "0",
        isNative: true,
      }],
      syncedAt: "2026-09-19T12:00:00.000Z",
    };
  }
  async prepareTransfer(draft: TransferDraft): Promise<PreparedTransaction> {
    this.prepareCalls += 1;
    return {
      pset: "cHNldP8=",
      coreReviewHash: "2".repeat(64),
      summary: {
        kind: "transfer",
        networkKey: ECX_ALPHA_IDENTITY.key,
        genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
        assetId: draft.assetId,
        destination: draft.destination,
        amountAtomic: draft.amountAtomic,
        networkFeeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        networkFeeAtomic: "100",
        feeRate: draft.feeRate,
        transactionPolicy: "explicit-only",
      },
    };
  }
  async prepareIssue(_draft: IssueDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async prepareReissue(_draft: ReissueDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async prepareBurn(_draft: BurnDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async signAndBroadcast(transaction: PreparedTransaction): Promise<string> {
    this.signCalls += 1;
    this.lastSigned = transaction;
    return "1".repeat(64);
  }
  destroy(): void { this.destroyed += 1; }
}

class FakeAdapter implements LwkWalletAdapter {
  readonly implementation = "test-only";
  readonly available = true;
  readonly capabilities = {
    mnemonic: true,
    walletSync: true,
    explicitTransactions: true,
    issuance: true,
    reissuance: true,
    burning: true,
    confidentialTransactions: false,
    dex: false,
  } as const;
  readonly session = new FakeSession();
  async generateMnemonic(): Promise<string> { return "abandon ".repeat(11) + "about"; }
  async validateMnemonic(_mnemonic: string): Promise<boolean> { return true; }
  async openWallet(_mnemonic: string, identity: EcxAlphaIdentity): Promise<LwkWalletSession> {
    assert.equal(identity.genesisHash, ECX_ALPHA_IDENTITY.genesisHash);
    return this.session;
  }
}

class HangingSession extends FakeSession {
  aborted = false;
  override async sync(signal: AbortSignal): Promise<never> {
    return await new Promise<never>((_resolve, reject) => {
      signal.addEventListener("abort", () => {
        this.aborted = true;
        reject(new Error("aborted"));
      }, { once: true });
    });
  }
}

class HangingAdapter extends FakeAdapter {
  override readonly session = new HangingSession();
}

class MismatchedSummarySession extends FakeSession {
  override async prepareTransfer(draft: TransferDraft): Promise<PreparedTransaction> {
    const prepared = await super.prepareTransfer(draft);
    return {
      ...prepared,
      summary: { ...prepared.summary, amountAtomic: (BigInt(draft.amountAtomic) + 1n).toString() },
    };
  }
}

class MismatchedSummaryAdapter extends FakeAdapter {
  override readonly session = new MismatchedSummarySession();
}

class ZeroFeeSummarySession extends FakeSession {
  override async prepareTransfer(draft: TransferDraft): Promise<PreparedTransaction> {
    const prepared = await super.prepareTransfer(draft);
    return {
      ...prepared,
      summary: { ...prepared.summary, networkFeeAtomic: "0" },
    };
  }
}

class ZeroFeeSummaryAdapter extends FakeAdapter {
  override readonly session = new ZeroFeeSummarySession();
}

class BindingVariantSession extends FakeSession {
  constructor(
    private readonly pset: string,
    private readonly coreReviewHash: string,
  ) { super(); }

  override async prepareTransfer(draft: TransferDraft): Promise<PreparedTransaction> {
    const prepared = await super.prepareTransfer(draft);
    return { ...prepared, pset: this.pset, coreReviewHash: this.coreReviewHash };
  }
}

class BindingVariantAdapter extends FakeAdapter {
  override readonly session: BindingVariantSession;
  constructor(pset: string, coreReviewHash: string) {
    super();
    this.session = new BindingVariantSession(pset, coreReviewHash);
  }
}

const payload: WalletVaultPayload = {
  schemaVersion: 1,
  walletId: "abcdefghijklmnopqrstuv",
  mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  createdAt: "2026-09-19T12:00:00.000Z",
  networkKey: ECX_ALPHA_IDENTITY.key,
  genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
  explicitOutputsOnly: true,
};

const TEST_RECEIVE_ADDRESS = "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh";

async function unlockedController(
  adapter: FakeAdapter = new FakeAdapter(),
  options: { readonly now?: () => Date; readonly approvalTimeoutMilliseconds?: number } = {},
): Promise<{ readonly controller: WalletController; readonly adapter: FakeAdapter }> {
  const store = new VaultStore(new MemoryStorage());
  await store.write(await encryptVault(payload, "a sufficiently long password"));
  const controller = new WalletController({
    vaultStore: store,
    adapter,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.approvalTimeoutMilliseconds === undefined
      ? {}
      : { approvalTimeoutMilliseconds: options.approvalTimeoutMilliseconds }),
  });
  assert.equal((await controller.handle({
    type: "wallet.unlock",
    password: "a sufficiently long password",
  })).ok, true);
  return { controller, adapter };
}

describe("wallet controller", () => {
  it("rejects surplus message fields", async () => {
    const controller = new WalletController({ vaultStore: new VaultStore(new MemoryStorage()), adapter: new FakeAdapter() });
    const response = await controller.handle({ type: "wallet.status", surprise: true });
    assert.equal(response.ok, false);
    if (!response.ok) assert.equal(response.error.code, "INVALID_REQUEST");
  });

  it("serializes competing vault-creation requests", async () => {
    const controller = new WalletController({
      vaultStore: new VaultStore(new MemoryStorage()),
      adapter: new FakeAdapter(),
    });
    const request = {
      type: "vault.create",
      password: "a sufficiently long password",
      mnemonic: payload.mnemonic,
      identityAcknowledged: true,
    };
    const responses = await Promise.all([controller.handle(request), controller.handle(request)]);
    assert.equal(responses.filter((response) => response.ok).length, 1);
    assert.equal(responses.filter((response) => !response.ok).length, 1);
  });

  it("locks and destroys its LWK session after inactivity", async () => {
    const storage = new MemoryStorage();
    const store = new VaultStore(storage);
    await store.write(await encryptVault(payload, "a sufficiently long password"));
    const adapter = new FakeAdapter();
    let now = Date.parse("2026-09-19T12:00:00.000Z");
    const controller = new WalletController({
      vaultStore: store,
      adapter,
      now: () => new Date(now),
      autoLockMilliseconds: 1_000,
    });
    const unlocked = await controller.handle({ type: "wallet.unlock", password: "a sufficiently long password" });
    assert.equal(unlocked.ok, true);
    now += 1_001;
    const status = await controller.handle({ type: "wallet.status" });
    assert.equal(status.ok, true);
    if (status.ok) assert.equal((status.result as { unlocked: boolean }).unlocked, false);
    assert.equal(adapter.session.destroyed, 1);
  });

  it("validates the adapter snapshot before returning it to the UI", async () => {
    const snapshot = await new FakeSession().sync(new AbortController().signal);
    assert.deepEqual(validateWalletSnapshot(snapshot), snapshot);
    assert.equal(
      validateWalletSnapshot({ ...snapshot, receiveAddress: ` ${snapshot.receiveAddress} ` }).receiveAddress,
      snapshot.receiveAddress,
    );
    await assert.rejects(
      async () => validateWalletSnapshot({
        ...snapshot,
        assets: [{ ...snapshot.assets[0], assetId: "f".repeat(64) }],
      }),
      /native-asset marker/u,
    );
    await assert.rejects(
      async () => validateWalletSnapshot({
        ...snapshot,
        chain: { ...snapshot.chain, headerChainVerified: true },
      }),
      /trust metadata/u,
    );
  });

  it("keeps a prepared PSET in the controller and broadcasts it only after bound approval", async () => {
    const { controller, adapter } = await unlockedController();
    const prepared = await controller.handle({
      type: "transaction.prepare-send",
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: TEST_RECEIVE_ADDRESS,
      amountAtomic: "500",
      feeRate: "1.25",
    });
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    assert.equal(Object.hasOwn(prepared.result, "pset"), false);
    assert.equal(prepared.result.summary.amountAtomic, "500");
    assert.match(prepared.result.approvalToken, /^[A-Za-z0-9_-]{43}$/u);
    assert.match(prepared.result.summaryHash, /^[0-9a-f]{64}$/u);

    const broadcast = await controller.handle({
      type: "transaction.approve-and-broadcast",
      approvalToken: prepared.result.approvalToken,
      summaryHash: prepared.result.summaryHash,
    });
    assert.deepEqual(broadcast, { ok: true, result: { txid: "1".repeat(64) } });
    assert.equal(adapter.session.signCalls, 1);
    assert.equal(adapter.session.lastSigned?.pset, "cHNldP8=");
    assert.equal(adapter.session.lastSigned?.coreReviewHash, "2".repeat(64));

    const replay = await controller.handle({
      type: "transaction.approve-and-broadcast",
      approvalToken: prepared.result.approvalToken,
      summaryHash: prepared.result.summaryHash,
    });
    assert.equal(replay.ok, false);
    assert.equal(adapter.session.signCalls, 1);
    assert.equal((await controller.handle({ type: "wallet.lock" })).ok, true);
  });

  it("binds both the exact PSET bytes and Rust core review commitment into approval", async () => {
    const request = {
      type: "transaction.prepare-send",
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: TEST_RECEIVE_ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
    } as const;
    const first = await unlockedController(new BindingVariantAdapter("cHNldP8=", "2".repeat(64)));
    const changedPset = await unlockedController(new BindingVariantAdapter("cHNldP8A", "2".repeat(64)));
    const changedCoreReview = await unlockedController(new BindingVariantAdapter("cHNldP8=", "3".repeat(64)));
    const approvals = await Promise.all([
      first.controller.handle(request),
      changedPset.controller.handle(request),
      changedCoreReview.controller.handle(request),
    ]);
    for (const approval of approvals) assert.equal(approval.ok, true);
    const [baseApproval, psetApproval, coreReviewApproval] = approvals;
    if (!baseApproval?.ok || !psetApproval?.ok || !coreReviewApproval?.ok) return;
    assert.notEqual(baseApproval.result.summaryHash, psetApproval.result.summaryHash);
    assert.notEqual(baseApproval.result.summaryHash, coreReviewApproval.result.summaryHash);
    await Promise.all([
      first.controller.handle({ type: "wallet.lock" }),
      changedPset.controller.handle({ type: "wallet.lock" }),
      changedCoreReview.controller.handle({ type: "wallet.lock" }),
    ]);
  });

  it("consumes a pending approval when its bound summary hash does not match", async () => {
    const { controller, adapter } = await unlockedController();
    const prepared = await controller.handle({
      type: "transaction.prepare-send",
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: TEST_RECEIVE_ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
    });
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    const mismatch = await controller.handle({
      type: "transaction.approve-and-broadcast",
      approvalToken: prepared.result.approvalToken,
      summaryHash: "f".repeat(64),
    });
    assert.equal(mismatch.ok, false);
    const retry = await controller.handle({
      type: "transaction.approve-and-broadcast",
      approvalToken: prepared.result.approvalToken,
      summaryHash: prepared.result.summaryHash,
    });
    assert.equal(retry.ok, false);
    assert.equal(adapter.session.signCalls, 0);
    assert.equal((await controller.handle({ type: "wallet.lock" })).ok, true);
  });

  it("expires prepared approvals without signing", async () => {
    let now = Date.parse("2026-09-19T12:00:00.000Z");
    const { controller, adapter } = await unlockedController(new FakeAdapter(), {
      now: () => new Date(now),
      approvalTimeoutMilliseconds: 1_000,
    });
    const prepared = await controller.handle({
      type: "transaction.prepare-send",
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: TEST_RECEIVE_ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
    });
    assert.equal(prepared.ok, true);
    if (!prepared.ok) return;
    now += 1_001;
    const response = await controller.handle({
      type: "transaction.approve-and-broadcast",
      approvalToken: prepared.result.approvalToken,
      summaryHash: prepared.result.summaryHash,
    });
    assert.equal(response.ok, false);
    assert.equal(adapter.session.signCalls, 0);
    assert.equal((await controller.handle({ type: "wallet.lock" })).ok, true);
  });

  it("rejects an adapter PSET summary that does not match the requested transfer", async () => {
    const adapter = new MismatchedSummaryAdapter();
    const { controller } = await unlockedController(adapter);
    const response = await controller.handle({
      type: "transaction.prepare-send",
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: TEST_RECEIVE_ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
    });
    assert.equal(response.ok, false);
    if (!response.ok) assert.match(response.error.message, /does not match/u);
    assert.equal(adapter.session.signCalls, 0);
    assert.equal((await controller.handle({ type: "wallet.lock" })).ok, true);
  });

  it("rejects an adapter PSET summary with a zero network fee", async () => {
    const { controller, adapter } = await unlockedController(new ZeroFeeSummaryAdapter());
    const response = await controller.handle({
      type: "transaction.prepare-send",
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: TEST_RECEIVE_ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
    });
    assert.equal(response.ok, false);
    if (!response.ok) assert.equal(response.error.code, "INVALID_REQUEST");
    assert.equal(adapter.session.signCalls, 0);
    assert.equal((await controller.handle({ type: "wallet.lock" })).ok, true);
  });

  it("aborts a hung adapter sync so lock requests cannot be blocked forever", async () => {
    const storage = new MemoryStorage();
    const store = new VaultStore(storage);
    await store.write(await encryptVault(payload, "a sufficiently long password"));
    const adapter = new HangingAdapter();
    const controller = new WalletController({
      vaultStore: store,
      adapter,
      syncTimeoutMilliseconds: 10,
    });
    assert.equal((await controller.handle({
      type: "wallet.unlock",
      password: "a sufficiently long password",
    })).ok, true);
    assert.equal((await controller.handle({ type: "wallet.snapshot" })).ok, false);
    assert.equal(adapter.session.aborted, true);
    assert.equal((await controller.handle({ type: "wallet.lock" })).ok, true);
  });
});
