import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { abbreviatedHash, ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";

describe("pinned ECX Alpha identity", () => {
  it("pins the chain, parent, native asset, and explicit-only policy", () => {
    assert.equal(ECX_ALPHA_IDENTITY.sidechainSlot, 24);
    assert.equal(ECX_ALPHA_IDENTITY.genesisHash.length, 64);
    assert.equal(ECX_ALPHA_IDENTITY.nativeAssetId.length, 64);
    assert.equal(ECX_ALPHA_IDENTITY.parentGenesisHash.length, 64);
    assert.equal(ECX_ALPHA_IDENTITY.transactionPolicy, "explicit-only");
    assert.equal(abbreviatedHash(ECX_ALPHA_IDENTITY.genesisHash), "672af009…96fa5bcd");
  });

  it("rejects malformed identity hashes", () => {
    assert.throws(() => abbreviatedHash("672af009"), TypeError);
    assert.throws(() => abbreviatedHash("A".repeat(64)), TypeError);
  });
});
