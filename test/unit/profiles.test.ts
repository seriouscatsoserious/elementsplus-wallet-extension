import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ECX_ALPHA_ARCHIVED_PROFILE,
  ECX_BETA_PROFILE,
  ECX_MAINNET_PROFILE,
  ELEMENTSPLUS_REGTEST_PROFILE,
  findNetworkProfile,
  missingPins,
  NETWORK_PROFILES,
  NetworkProfileError,
  SELECTABLE_PROFILE_IDS,
  selectableProfile,
  toWalletBuildProfile,
} from "../../src/network/profiles.js";

const LOCAL = Object.freeze({
  genesisHash: "a".repeat(64),
  nativeAssetId: "b".repeat(64),
  explorerUrl: "http://127.0.0.1:43199",
  dexUrl: "http://127.0.0.1:5173",
});

describe("network profile registry", () => {
  it("lists every profile once, with alpha archived and not selectable", () => {
    const ids = NETWORK_PROFILES.map((profile) => profile.id);
    assert.deepEqual(ids, ["ecx-beta", "ecx-mainnet", "elementsplus-regtest", "ecx-alpha"]);
    assert.deepEqual([...SELECTABLE_PROFILE_IDS], ["ecx-beta", "ecx-mainnet", "elementsplus-regtest"]);
    assert.equal(findNetworkProfile("ecx-alpha")?.status, "archived");
    assert.throws(() => selectableProfile("ecx-alpha"), /archived/u);
    assert.throws(() => selectableProfile("liquidv1"), /unknown network profile/u);
  });

  it("keeps status consistent with missing pins (pending <=> something unpublished)", () => {
    for (const profile of NETWORK_PROFILES) {
      assert.equal(profile.status === "pending", missingPins(profile).length > 0, profile.id);
    }
  });

  it("keeps beta and mainnet pending and refuses them", () => {
    for (const profile of [ECX_BETA_PROFILE, ECX_MAINNET_PROFILE]) {
      assert.equal(profile.status, "pending");
      assert.equal(profile.esploraUrl, null);
      assert.equal(profile.sidechainSlot, 24);
      assert.throws(() => selectableProfile(profile.id), (error: unknown) =>
        error instanceof NetworkProfileError && /pending/u.test(error.message) && /esploraUrl/u.test(error.message));
      assert.throws(() => toWalletBuildProfile(profile), /pending/u);
    }
    // Betanet slot 24 commits to the v11 identity; only the sidechain Esplora is missing.
    assert.deepEqual(missingPins(ECX_BETA_PROFILE), ["esploraUrl"]);
    assert.equal(ECX_BETA_PROFILE.genesisHash, ECX_ALPHA_ARCHIVED_PROFILE.genesisHash);
    assert.equal(ECX_BETA_PROFILE.policyAssetId, ECX_ALPHA_ARCHIVED_PROFILE.policyAssetId);
    assert.deepEqual(ECX_BETA_PROFILE.address, ECX_ALPHA_ARCHIVED_PROFILE.address);
    // Once JK publishes a sidechain Esplora, filling it and flipping the status is the whole change.
    const published = toWalletBuildProfile({ ...ECX_BETA_PROFILE, status: "live", esploraUrl: "https://esplora.example/api" });
    assert.equal(published.id, "ecx-beta");
    assert.equal(published.key, "ecx-beta-672af009bd90");
    assert.equal(published.explorerUrl, "https://esplora.example");
    assert.equal(published.bech32Hrp, "elements");
    assert.equal(published.parentGenesisHash, ECX_BETA_PROFILE.l1.genesisHash);
    assert.throws(() => toWalletBuildProfile({ ...ECX_BETA_PROFILE, status: "live" }), /missing esploraUrl/u);
    assert.deepEqual(missingPins(ECX_MAINNET_PROFILE), ["genesisHash", "policyAssetId", "esploraUrl", "l1.genesisHash", "address"]);
    assert.equal(ECX_BETA_PROFILE.displayName, "eCash Beta · Elements");
    assert.equal(ECX_MAINNET_PROFILE.displayName, "eCash · Elements");
    assert.equal(ECX_BETA_PROFILE.l1.esploraUrl, "https://esplora.beta.ecash.ninja");
    assert.equal(ECX_BETA_PROFILE.l1.explorerUrl, "https://explorer.beta.ecash.ninja");
  });

  it("builds the regtest identity only from local chain parameters", () => {
    assert.throws(() => toWalletBuildProfile(ELEMENTSPLUS_REGTEST_PROFILE), /local chain parameters/u);
    const profile = toWalletBuildProfile(ELEMENTSPLUS_REGTEST_PROFILE, { local: LOCAL });
    assert.equal(profile.id, "elementsplus-regtest");
    assert.equal(profile.displayName, "Elements+ local regtest");
    assert.equal(profile.key, `elementsplus-regtest-${"a".repeat(12)}`);
    assert.equal(profile.bech32Hrp, "ert");
    assert.equal(profile.explorerUrl, "http://127.0.0.1:43199");
    assert.throws(
      () => toWalletBuildProfile(ELEMENTSPLUS_REGTEST_PROFILE, { local: { ...LOCAL, genesisHash: "zz" } }),
      /malformed/u,
    );
  });

  it("flattens the archived alpha fixture only on explicit request", () => {
    assert.throws(() => toWalletBuildProfile(ECX_ALPHA_ARCHIVED_PROFILE), /archived/u);
    const alpha = toWalletBuildProfile(ECX_ALPHA_ARCHIVED_PROFILE, { allowArchived: true });
    assert.equal(alpha.key, "ecx-alpha-elements-v11");
    assert.equal(alpha.bech32Hrp, "elements");
    assert.equal(alpha.aliasBech32Hrp, "ert");
    assert.ok(Object.isFrozen(alpha));
  });
});
