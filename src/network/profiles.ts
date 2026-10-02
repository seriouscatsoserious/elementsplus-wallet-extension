/**
 * Typed network profile registry (mirrors `rust/wallet-core/src/network.rs`;
 * keep both in step, see docs/NETWORKS.md).
 *
 * Every extension artifact is built for exactly one profile; its pins are
 * compiled in and never user-editable. Profiles whose sidechain parameters
 * have not been published are `pending`: their pins are `null` and the build
 * refuses them rather than guessing. The retired ECX Alpha chain is kept as an
 * `archived`, non-selectable entry so historical tests and vectors still pass.
 *
 * This module is plain erasable TypeScript with no imports so the Node build
 * scripts can load it directly.
 */

export type NetworkProfileId = "ecx-beta" | "ecx-mainnet" | "elementsplus-regtest";
export type ArchivedNetworkProfileId = "ecx-alpha";
export type AnyNetworkProfileId = NetworkProfileId | ArchivedNetworkProfileId;
export type NetworkProfileStatus = "live" | "pending" | "archived";
/** `public`: pins compiled from this registry. `local-regtest`: pins read from the local node at build time. */
export type NetworkProfileKind = "public" | "local-regtest";

export interface AddressParams {
  readonly bech32Hrp: string;
  readonly blech32Hrp: string;
  readonly p2pkhPrefix: number;
  readonly p2shPrefix: number;
  readonly blindedPrefix: number;
}

export interface ProfileAddressParams {
  /** The chain's own address spelling (shown to users). */
  readonly native: AddressParams;
  /** Generic-Elements alias rendered by LWK and accepted by the node. */
  readonly alias: { readonly bech32Hrp: string; readonly blech32Hrp: string };
}

export interface L1Profile {
  readonly networkId: string;
  /** Parent-chain genesis hash used in the Elements network parameters. */
  readonly genesisHash: string | null;
  readonly esploraUrl: string | null;
  readonly explorerUrl: string | null;
}

export interface NetworkProfile {
  /** Stable id; also the `network` field of every swap offer (V2-SPEC §2). */
  readonly id: AnyNetworkProfileId;
  readonly displayName: string;
  readonly status: NetworkProfileStatus;
  readonly kind: NetworkProfileKind;
  readonly implementation: string;
  readonly sidechainSlot: number;
  readonly genesisHash: string | null;
  /** Pegged (policy / fee) asset id. */
  readonly policyAssetId: string | null;
  readonly address: ProfileAddressParams | null;
  /** Sidechain Esplora API base URL. */
  readonly esploraUrl: string | null;
  readonly l1: L1Profile;
  /** DEX / asset registry origin. */
  readonly dexUrl: string | null;
}

/** Native v11 address encoding (Elements+ chainparams) plus the LWK alias. */
const ALPHA_ADDRESS: ProfileAddressParams = Object.freeze({
  native: Object.freeze({ bech32Hrp: "elements", blech32Hrp: "elementsl", p2pkhPrefix: 68, p2shPrefix: 13, blindedPrefix: 6 }),
  alias: Object.freeze({ bech32Hrp: "ert", blech32Hrp: "el" }),
});

const ELEMENTS_REGTEST_ADDRESS: ProfileAddressParams = Object.freeze({
  native: Object.freeze({ bech32Hrp: "ert", blech32Hrp: "el", p2pkhPrefix: 235, p2shPrefix: 75, blindedPrefix: 4 }),
  alias: Object.freeze({ bech32Hrp: "elements", blech32Hrp: "elementsl" }),
});

/**
 * Elements v11 identity: the retired ECX Alpha chain and the eCash betanet
 * slot-24 proposal (bytes equal `PROPOSAL_DESCRIPTION_HEX` in Elements+
 * `src/elements_drivechain_identity.h`, master 006d2a30) commit to it alike.
 */
const ELEMENTS_V11_GENESIS = "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd";
const ELEMENTS_V11_PEGGED_ASSET = "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4";
/** L1 genesis; for betanet observed from its Esplora `/block-height/0` (2026-10-02). */
const ECASH_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/**
 * Elements sidechain in slot 24 on eCash betanet (activated at parent height
 * 970715). Pending only because no public sidechain node / Esplora runs on
 * betanet yet: `esploraUrl` is the single missing pin.
 */
export const ECX_BETA_PROFILE: NetworkProfile = Object.freeze({
  id: "ecx-beta",
  displayName: "eCash Beta · Elements",
  status: "pending",
  kind: "public",
  implementation: "Elements+ (Elements Drivechain v11)",
  sidechainSlot: 24,
  genesisHash: ELEMENTS_V11_GENESIS,
  policyAssetId: ELEMENTS_V11_PEGGED_ASSET,
  address: ALPHA_ADDRESS,
  esploraUrl: null,
  l1: Object.freeze({
    networkId: "ecash-beta",
    genesisHash: ECASH_GENESIS,
    esploraUrl: "https://esplora.beta.ecash.ninja",
    explorerUrl: "https://explorer.beta.ecash.ninja",
  }),
  dexUrl: null,
});

/** eCash mainnet Elements sidechain (planned ~2026-10-31). */
export const ECX_MAINNET_PROFILE: NetworkProfile = Object.freeze({
  id: "ecx-mainnet",
  displayName: "eCash · Elements",
  status: "pending",
  kind: "public",
  implementation: "Elements+ (Elements Drivechain v11)",
  sidechainSlot: 24,
  genesisHash: null,
  policyAssetId: null,
  address: null,
  esploraUrl: null,
  l1: Object.freeze({ networkId: "ecash-mainnet", genesisHash: null, esploraUrl: null, explorerUrl: null }),
  dexUrl: null,
});

/** Disposable local functional-test chain; genesis and asset come from `.regtest/network.json`. */
export const ELEMENTSPLUS_REGTEST_PROFILE: NetworkProfile = Object.freeze({
  id: "elementsplus-regtest",
  displayName: "Elements+ local regtest",
  status: "live",
  kind: "local-regtest",
  implementation: "Elements+ functional-test node",
  sidechainSlot: 24,
  genesisHash: null,
  policyAssetId: null,
  address: ELEMENTS_REGTEST_ADDRESS,
  esploraUrl: "http://127.0.0.1:43199/api",
  l1: Object.freeze({
    networkId: "regtest",
    genesisHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    esploraUrl: null,
    explorerUrl: null,
  }),
  dexUrl: "http://127.0.0.1:5173",
});

/** Retired ECX Alpha chain. Archived: kept for historical tests only, never selectable. */
export const ECX_ALPHA_ARCHIVED_PROFILE: NetworkProfile = Object.freeze({
  id: "ecx-alpha",
  displayName: "ECX Alpha (archived)",
  status: "archived",
  kind: "public",
  implementation: "Elements+",
  sidechainSlot: 24,
  genesisHash: ELEMENTS_V11_GENESIS,
  policyAssetId: ELEMENTS_V11_PEGGED_ASSET,
  address: ALPHA_ADDRESS,
  esploraUrl: "https://explorer.bitnames.info/api",
  l1: Object.freeze({
    networkId: "ecash-alpha",
    genesisHash: ECASH_GENESIS,
    esploraUrl: null,
    explorerUrl: null,
  }),
  dexUrl: null,
});

export const NETWORK_PROFILES: readonly NetworkProfile[] = Object.freeze([
  ECX_BETA_PROFILE,
  ECX_MAINNET_PROFILE,
  ELEMENTSPLUS_REGTEST_PROFILE,
  ECX_ALPHA_ARCHIVED_PROFILE,
]);

export const SELECTABLE_PROFILE_IDS: readonly NetworkProfileId[] = Object.freeze([
  "ecx-beta",
  "ecx-mainnet",
  "elementsplus-regtest",
]);

export class NetworkProfileError extends Error {
  override readonly name = "NetworkProfileError";
}

export function findNetworkProfile(id: string): NetworkProfile | undefined {
  return NETWORK_PROFILES.find((profile) => profile.id === id);
}

/**
 * Pins a public profile still lacks. A profile is buildable only when this is
 * empty and its status is `live` (the unit tests enforce pending <=> missing).
 */
export function missingPins(profile: NetworkProfile): string[] {
  const missing: string[] = [];
  if (profile.kind === "public") {
    if (profile.genesisHash === null) missing.push("genesisHash");
    if (profile.policyAssetId === null) missing.push("policyAssetId");
    if (profile.esploraUrl === null) missing.push("esploraUrl");
    if (profile.l1.genesisHash === null) missing.push("l1.genesisHash");
  }
  if (profile.address === null) missing.push("address");
  return missing;
}

/**
 * Resolve a profile a build may target. Unknown, archived and pending profiles
 * throw with an explanation; a live profile must have every pin.
 */
export function selectableProfile(id: string): NetworkProfile {
  const profile = findNetworkProfile(id);
  if (profile === undefined) {
    throw new NetworkProfileError(
      `unknown network profile "${id}"; known profiles: ${SELECTABLE_PROFILE_IDS.join(", ")}`,
    );
  }
  return assertSelectable(profile);
}

/** Throw unless this exact profile value is live with every pin set. */
export function assertSelectable(profile: NetworkProfile): NetworkProfile {
  const id = profile.id;
  if (profile.status === "archived") {
    throw new NetworkProfileError(`network profile "${id}" is archived (retired chain) and cannot be selected`);
  }
  if (profile.status === "pending") {
    throw new NetworkProfileError(
      `network profile "${id}" (${profile.displayName}) is pending: ${missingPins(profile).join(", ") || "status"} `
      + "not yet published, so this wallet refuses to build or run for it (see docs/NETWORKS.md)",
    );
  }
  const missing = missingPins(profile);
  if (missing.length > 0) {
    throw new NetworkProfileError(`live network profile "${id}" is missing ${missing.join(", ")}`);
  }
  return profile;
}

/** The flat, frozen identity compiled into one extension artifact. */
export interface WalletBuildProfile {
  readonly id: AnyNetworkProfileId;
  /** Vault binding key; changes whenever the chain identity changes. */
  readonly key: string;
  readonly displayName: string;
  readonly implementation: string;
  readonly sidechainSlot: number;
  readonly genesisHash: string;
  readonly nativeAssetId: string;
  readonly parentGenesisHash: string;
  readonly bech32Hrp: string;
  readonly blech32Hrp: string;
  readonly aliasBech32Hrp: string;
  readonly aliasBlech32Hrp: string;
  readonly explorerUrl: string;
  /** DEX web app / server origin. Empty means "not configured" (user sets it in Settings). */
  readonly dexUrl: string;
  readonly l1NetworkId: string;
  readonly transactionPolicy: "explicit-only";
}

export interface LocalChainParameters {
  readonly genesisHash: string;
  readonly nativeAssetId: string;
  readonly explorerUrl: string;
  readonly dexUrl?: string;
}

const HEX_32 = /^[0-9a-f]{64}$/u;

/**
 * Flatten a profile into the compiled build identity. Public profiles must be
 * live (archived only with `allowArchived`, for historical test fixtures);
 * the local regtest profile takes its genesis/asset/explorer from `local`.
 */
export function toWalletBuildProfile(
  profile: NetworkProfile,
  options: { readonly local?: LocalChainParameters; readonly allowArchived?: boolean } = {},
): WalletBuildProfile {
  if (!(options.allowArchived === true && profile.status === "archived")) assertSelectable(profile);
  const local = profile.kind === "local-regtest" ? options.local : undefined;
  if (profile.kind === "local-regtest" && local === undefined) {
    throw new NetworkProfileError(`${profile.id} needs local chain parameters (.regtest/network.json)`);
  }
  const genesisHash = local?.genesisHash ?? profile.genesisHash;
  const nativeAssetId = local?.nativeAssetId ?? profile.policyAssetId;
  const explorerUrl = local?.explorerUrl ?? profile.esploraUrl;
  if (genesisHash === null || nativeAssetId === null || explorerUrl === null
    || profile.address === null || profile.l1.genesisHash === null) {
    throw new NetworkProfileError(`network profile "${profile.id}" has unpublished pins`);
  }
  if (!HEX_32.test(genesisHash) || !HEX_32.test(nativeAssetId)) {
    throw new NetworkProfileError(`network profile "${profile.id}" has malformed pins`);
  }
  const key = profile.id === "ecx-alpha"
    ? "ecx-alpha-elements-v11"
    : `${profile.id}-${genesisHash.slice(0, 12)}`;
  return Object.freeze({
    id: profile.id,
    key,
    displayName: profile.displayName,
    implementation: profile.implementation,
    sidechainSlot: profile.sidechainSlot,
    genesisHash,
    nativeAssetId,
    parentGenesisHash: profile.l1.genesisHash,
    bech32Hrp: profile.address.native.bech32Hrp,
    blech32Hrp: profile.address.native.blech32Hrp,
    aliasBech32Hrp: profile.address.alias.bech32Hrp,
    aliasBlech32Hrp: profile.address.alias.blech32Hrp,
    explorerUrl: explorerUrl.replace(/\/api\/?$/u, ""),
    dexUrl: local?.dexUrl ?? profile.dexUrl ?? "",
    l1NetworkId: profile.l1.networkId,
    transactionPolicy: "explicit-only",
  });
}
