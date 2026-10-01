/**
 * Compile-time wallet profile. The reviewed build always uses this ECX value.
 * `scripts/build-regtest.mjs` replaces only the compiled copy in the clearly
 * labelled disposable regtest artifact; it never edits this source file.
 */
export interface WalletBuildProfile {
  readonly mode: "ecx-alpha" | "elementsplus-regtest";
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
  readonly transactionPolicy: "explicit-only";
}

export const BUILD_NETWORK_PROFILE: WalletBuildProfile = Object.freeze({
  mode: "ecx-alpha",
  key: "ecx-alpha-elements-v11",
  displayName: "ECX Alpha",
  implementation: "Elements+",
  sidechainSlot: 24,
  genesisHash: "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd",
  nativeAssetId: "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4",
  parentGenesisHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  bech32Hrp: "elements",
  blech32Hrp: "elementsl",
  aliasBech32Hrp: "ert",
  aliasBlech32Hrp: "el",
  explorerUrl: "https://explorer.bitnames.info",
  dexUrl: "",
  transactionPolicy: "explicit-only",
});
