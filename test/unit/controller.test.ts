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
  async sync(_signal: AbortSignal) {
    return {
      chain: {
        genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
        nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        headerChainVerified: true as const,
        explicitOutputsOnly: true as const,
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
  async prepareTransfer(_draft: TransferDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async prepareIssue(_draft: IssueDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async prepareReissue(_draft: ReissueDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async prepareBurn(_draft: BurnDraft): Promise<PreparedTransaction> { throw new Error("not used"); }
  async signAndBroadcast(_transaction: PreparedTransaction): Promise<string> { throw new Error("not used"); }
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

const payload: WalletVaultPayload = {
  schemaVersion: 1,
  walletId: "abcdefghijklmnopqrstuv",
  mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  createdAt: "2026-09-19T12:00:00.000Z",
  networkKey: ECX_ALPHA_IDENTITY.key,
  genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
  explicitOutputsOnly: true,
};

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
