import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { abbreviatedHash, NETWORK_IDENTITY } from "../../src/network/identity.js";

describe("compiled network identity (source fixture: archived ECX Alpha)", () => {
  it("pins the chain, parent, native asset, and explicit-only policy", () => {
    assert.equal(NETWORK_IDENTITY.id, "ecx-alpha");
    assert.equal(NETWORK_IDENTITY.key, "ecx-alpha-elements-v11");
    assert.equal(NETWORK_IDENTITY.sidechainSlot, 24);
    assert.equal(NETWORK_IDENTITY.genesisHash.length, 64);
    assert.equal(NETWORK_IDENTITY.nativeAssetId.length, 64);
    assert.equal(NETWORK_IDENTITY.parentGenesisHash.length, 64);
    assert.equal(NETWORK_IDENTITY.transactionPolicy, "explicit-only");
    assert.equal(NETWORK_IDENTITY.explorerUrl, "https://explorer.bitnames.info");
    assert.equal(abbreviatedHash(NETWORK_IDENTITY.genesisHash), "672af009…96fa5bcd");
  });

  it("rejects malformed identity hashes", () => {
    assert.throws(() => abbreviatedHash("672af009"), TypeError);
    assert.throws(() => abbreviatedHash("A".repeat(64)), TypeError);
  });
});
