import type { ExtensionStorageArea } from "../../src/platform/browser.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";

export class MemoryStorage implements ExtensionStorageArea {
  readonly values: Record<string, unknown> = {};
  async get(keys: string | readonly string[]): Promise<Record<string, unknown>> {
    const requested = typeof keys === "string" ? [keys] : keys;
    return Object.fromEntries(requested.filter((key) => this.values[key] !== undefined).map((key) => [key, structuredClone(this.values[key])]));
  }
  async set(items: Record<string, unknown>): Promise<void> {
    for (const [key, value] of Object.entries(items)) this.values[key] = structuredClone(value);
  }
  async remove(keys: string | readonly string[]): Promise<void> {
    for (const key of typeof keys === "string" ? [keys] : keys) delete this.values[key];
  }
}

export const ECX = ECX_ALPHA_IDENTITY.nativeAssetId;
export const GENESIS = ECX_ALPHA_IDENTITY.genesisHash;
export const TOKEN_A = "a".repeat(64);
export const TOKEN_B = "b".repeat(64);
export const ADDRESS_1 = "elements1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3jmpdlq";
export const SCRIPT_1 = `0014${"11".repeat(20)}`;
export const ADDRESS_2 = "elements1qyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zaxythh";
export const SCRIPT_2 = `0014${"22".repeat(20)}`;
export const ADDRESS_3 = "elements1qxvenxvenxvenxvenxvenxvenxvenxven0cnkz9";
export const SCRIPT_3 = `0014${"33".repeat(20)}`;
export const ADDRESS_4 = "elements1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyshmfyt";
export const SCRIPT_4 = `0014${"44".repeat(20)}`;
export const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
export const PASSWORD = "correct horse battery";
export const PSET = "cHNldP8BAA==";

export function txid(n: number): string {
  return n.toString(16).padStart(64, "0");
}

export interface RawReview {
  kind: string;
  network: string;
  genesis_hash: string;
  balance_changes: { asset_id: string; amount: string }[];
  fee: number;
  external_outputs: { address: string; asset_id: string; amount: string }[];
  inputs_signed: string[];
  foreign_inputs: string[];
  issuance: null | { asset_id: string; token_id: string | null; amount: string; token_amount: string; contract_hash: string };
  sighash: string;
}

export function rawReview(overrides: Partial<RawReview> = {}): RawReview {
  return {
    kind: "transfer",
    network: "ECX Alpha",
    genesis_hash: GENESIS,
    balance_changes: [{ asset_id: ECX, amount: "-100000" }],
    fee: 500,
    external_outputs: [{ address: ADDRESS_2, asset_id: ECX, amount: "100000" }],
    inputs_signed: [`${txid(1)}:0`],
    foreign_inputs: [],
    issuance: null,
    sighash: "ALL",
    ...overrides,
  };
}

export function preparedJson(review: RawReview, reviewHash = "c".repeat(64)): string {
  return JSON.stringify({ pset_base64: PSET, review, review_hash: reviewHash });
}
