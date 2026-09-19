export const ECX_ALPHA_IDENTITY = Object.freeze({
  key: "ecx-alpha-elements-v11",
  displayName: "ECX Alpha",
  implementation: "Elements+",
  sidechainSlot: 24,
  genesisHash: "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd",
  nativeAssetId: "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4",
  parentGenesisHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  bech32Hrp: "elements",
  blech32Hrp: "elementsl",
  explorerUrl: "https://explorer.bitnames.info",
  transactionPolicy: "explicit-only",
} as const);

export type EcxAlphaIdentity = typeof ECX_ALPHA_IDENTITY;

export function abbreviatedHash(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("identity hash must be 32-byte lowercase hex");
  }
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}
