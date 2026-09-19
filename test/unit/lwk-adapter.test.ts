import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { LwkUnavailableError, UnavailableLwkAdapter } from "../../src/adapters/lwk.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";

describe("unavailable LWK adapter", () => {
  it("advertises no capabilities and never generates fallback wallet material", async () => {
    const adapter = new UnavailableLwkAdapter();
    assert.equal(adapter.available, false);
    assert.deepEqual(adapter.capabilities, {
      mnemonic: false,
      walletSync: false,
      explicitTransactions: false,
      issuance: false,
      reissuance: false,
      burning: false,
      confidentialTransactions: false,
      dex: false,
    });
    await assert.rejects(adapter.generateMnemonic(), LwkUnavailableError);
    await assert.rejects(adapter.validateMnemonic("abandon ".repeat(11) + "about"), LwkUnavailableError);
    await assert.rejects(adapter.openWallet("abandon ".repeat(11) + "about", ECX_ALPHA_IDENTITY), LwkUnavailableError);
  });
});
