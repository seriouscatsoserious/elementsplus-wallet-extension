import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { ExtensionStorageArea } from "../../src/platform/browser.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";
import {
  decryptVault,
  encryptVault,
  VaultAuthenticationError,
  VaultStore,
  type WalletVaultPayload,
} from "../../src/vault.js";

const payload: WalletVaultPayload = {
  schemaVersion: 1,
  walletId: "abcdefghijklmnopqrstuv",
  mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  createdAt: "2026-09-19T12:00:00.000Z",
  networkKey: ECX_ALPHA_IDENTITY.key,
  genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
  explicitOutputsOnly: true,
};

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

describe("encrypted ECX Alpha vault", () => {
  it("round-trips an identity-bound payload and rejects the wrong password", async () => {
    const encrypted = await encryptVault(payload, "a sufficiently long password");
    assert(!JSON.stringify(encrypted).includes("abandon"));
    assert.deepEqual(await decryptVault(encrypted, "a sufficiently long password"), payload);
    await assert.rejects(decryptVault(encrypted, "a different long password"), VaultAuthenticationError);
  });

  it("refuses to overwrite an existing encrypted vault", async () => {
    const storage = new MemoryStorage();
    const store = new VaultStore(storage);
    const encrypted = await encryptVault(payload, "a sufficiently long password");
    await store.write(encrypted);
    assert.equal(await store.exists(), true);
    await assert.rejects(store.write(encrypted), /refusing to overwrite/u);
  });
});
