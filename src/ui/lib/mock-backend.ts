/**
 * Illustrative in-memory backend for the standalone preview and screenshots.
 * Sample data only — nothing here touches keys, storage or the network.
 */
import type { WalletSnapshot } from "../../adapters/elementsplus-wasm.js";
import type { TxReview } from "../../adapters/wallet-core.js";
import type { ApprovalResult, ApprovalView, OperationSummary } from "../../background/controller.js";
import type { ConnectedSite, WalletSettings } from "../../background/settings.js";
import type { TokenInfo } from "../../background/token-registry.js";
import type { ActivityEntry } from "../../network/activity.js";
import { NETWORK_IDENTITY } from "../../network/identity.js";
import type { Backend, PendingRequestView, Tokens, TransferDraft, WalletStatus } from "./backend.js";

const ECX = NETWORK_IDENTITY.nativeAssetId;
export const SAMPLE = Object.freeze({
  alpha: "a1fa".padEnd(64, "3"),
  orbit: "0b17".padEnd(64, "7"),
  unknown: "a91c04".padEnd(60, "5") + "77e3",
  address: "elements1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3jmpdlq",
  other: "elements1qxvenxvenxvenxvenxvenxvenxvenxven0cnkz9",
  maker: "elements1qg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyshmfyt",
});
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const tokens: Tokens = {
  [ECX]: { assetId: ECX, name: NETWORK_IDENTITY.displayName, ticker: "ECX", precision: 8, verified: true, native: true, tokenFor: null },
  [SAMPLE.alpha]: { assetId: SAMPLE.alpha, name: "Alpha", ticker: "ALPHA", precision: 0, verified: true, native: false, tokenFor: null },
  [SAMPLE.orbit]: { assetId: SAMPLE.orbit, name: "Orbit", ticker: "ORBIT", precision: 2, verified: true, native: false, tokenFor: null },
  [SAMPLE.unknown]: { assetId: SAMPLE.unknown, name: "Unknown asset", ticker: "", precision: 0, verified: false, native: false, tokenFor: null } satisfies TokenInfo,
};

const snapshot: WalletSnapshot = {
  tipHeight: 104_220,
  receiveAddress: SAMPLE.address,
  primaryAddress: SAMPLE.address,
  syncedAt: new Date().toISOString(),
  balances: [
    { assetId: ECX, amount: "128450000000", confirmed: "128450000000", utxoCount: 3 },
    { assetId: SAMPLE.alpha, amount: "12000", confirmed: "12000", utxoCount: 1 },
    { assetId: SAMPLE.orbit, amount: "35025", confirmed: "35025", utxoCount: 1 },
    { assetId: SAMPLE.unknown, amount: "1000000", confirmed: "1000000", utxoCount: 1 },
  ],
};

const now = Math.floor(Date.now() / 1000);
const entries: ActivityEntry[] = [
  { txid: "f1".repeat(32), kind: "sent", confirmed: false, blockHeight: null, blockTime: null, deltas: [{ assetId: ECX, amount: "-2500000000" }], fee: "420", counterparty: SAMPLE.other, issuedAssetId: null, complete: true },
  { txid: "f2".repeat(32), kind: "swap", confirmed: true, blockHeight: 104_200, blockTime: now - 3_600, deltas: [{ assetId: SAMPLE.alpha, amount: "5000" }, { assetId: ECX, amount: "-10000000000" }], fee: null, counterparty: null, issuedAssetId: null, complete: true },
  { txid: "f3".repeat(32), kind: "received", confirmed: true, blockHeight: 104_150, blockTime: now - 7_200, deltas: [{ assetId: ECX, amount: "50000000000" }], fee: null, counterparty: SAMPLE.maker, issuedAssetId: null, complete: true },
  { txid: "f4".repeat(32), kind: "issuance", confirmed: true, blockHeight: 103_000, blockTime: now - 2 * 86_400, deltas: [{ assetId: SAMPLE.orbit, amount: "100000" }], fee: "530", counterparty: null, issuedAssetId: SAMPLE.orbit, complete: true },
  { txid: "f5".repeat(32), kind: "sent", confirmed: true, blockHeight: 102_900, blockTime: now - 2 * 86_400 - 600, deltas: [{ assetId: SAMPLE.orbit, amount: "-64975" }], fee: "400", counterparty: SAMPLE.other, issuedAssetId: null, complete: true },
];

function review(partial: Partial<TxReview>): TxReview {
  return {
    kind: "transfer",
    network: NETWORK_IDENTITY.displayName,
    genesisHash: NETWORK_IDENTITY.genesisHash,
    balanceChanges: [],
    fee: "210",
    externalOutputs: [],
    inputsSigned: [`${"c3".repeat(32)}:1`],
    foreignInputs: [],
    issuance: null,
    sighash: "ALL",
    ...partial,
  };
}

function view(reviewValue: TxReview, operation: OperationSummary, origin = "https://your-dex.example"): ApprovalView {
  return {
    approvalId: "previewapprovalid00000",
    approvalToken: "p".repeat(43),
    reviewHash: "9e3f1c0b7a52d8e4f6a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b",
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    origin,
    operation,
    review: reviewValue,
    tokens,
  };
}

export const SAMPLE_APPROVALS: Record<string, ApprovalView> = {
  swap: view(review({
    kind: "swap_take",
    balanceChanges: [{ assetId: ECX, amount: "-10000000000" }, { assetId: SAMPLE.alpha, amount: "5000" }],
    fee: "340",
    externalOutputs: [{ address: SAMPLE.maker, assetId: ECX, amount: "10000000000" }],
    foreignInputs: [`${"d4".repeat(32)}:0`],
  }), { kind: "swap_take", offerCount: 1, feeRate: 2 }),
  offer: view(review({
    kind: "offer_split",
    balanceChanges: [],
    fee: "260",
  }), { kind: "swap_offer", giveAsset: SAMPLE.alpha, giveAmount: "2500", wantAsset: ECX, wantAmount: "5000000000", needsSplit: true, feeRate: 2 }),
  issue: view(review({
    kind: "issuance",
    balanceChanges: [{ assetId: SAMPLE.orbit, amount: "100000000" }],
    fee: "530",
    issuance: { assetId: SAMPLE.orbit, tokenId: null, amount: "100000000", tokenAmount: "0", contractHash: "7c".repeat(32) },
  }), { kind: "issuance", name: "Orbit", ticker: "ORBIT", precision: 2, feeRate: 2 }),
  send: view(review({
    kind: "transfer",
    balanceChanges: [{ assetId: ECX, amount: "-2500000000" }],
    externalOutputs: [{ address: SAMPLE.other, assetId: ECX, amount: "2500000000" }],
  }), { kind: "transfer", feeRate: 2 }, "wallet"),
  unknown: view(review({
    kind: "transfer",
    balanceChanges: [{ assetId: SAMPLE.unknown, amount: "-250000" }],
    externalOutputs: [{ address: SAMPLE.other, assetId: SAMPLE.unknown, amount: "250000" }],
  }), { kind: "transfer", feeRate: 2 }),
};

export class MockBackend implements Backend {
  unlocked: boolean;
  initialized: boolean;
  request: PendingRequestView | undefined;
  settings: WalletSettings = {
    explorerUrl: NETWORK_IDENTITY.explorerUrl,
    registryUrl: "https://your-dex.example/api/assets",
    dexUrl: "https://your-dex.example",
    autoLockMinutes: 15,
  };
  sitesList: ConnectedSite[] = [
    { origin: "https://your-dex.example", connectedAt: new Date(Date.now() - 86_400_000).toISOString() },
    { origin: "https://launchpad.example", connectedAt: new Date(Date.now() - 6 * 86_400_000).toISOString() },
  ];

  constructor(options: { unlocked?: boolean; initialized?: boolean; request?: PendingRequestView } = {}) {
    this.unlocked = options.unlocked ?? true;
    this.initialized = options.initialized ?? true;
    this.request = options.request;
  }

  async status(): Promise<WalletStatus> {
    return {
      initialized: this.initialized,
      unlocked: this.unlocked,
      primaryAddress: this.initialized ? SAMPLE.address : null,
      network: {
        name: NETWORK_IDENTITY.displayName,
        id: NETWORK_IDENTITY.id,
        genesisHash: NETWORK_IDENTITY.genesisHash,
        policyAsset: ECX,
        defaultExplorerUrl: NETWORK_IDENTITY.explorerUrl,
      },
      settings: this.settings,
    };
  }
  async touch(): Promise<void> {}
  async generateMnemonic(): Promise<string> { return "orbit pulse lantern velvet copper meadow ribbon hollow quarter spice anchor violin"; }
  async validateMnemonic(mnemonic: string): Promise<boolean> { return mnemonic.split(" ").length === 12; }
  async createVault(): Promise<void> { this.initialized = true; this.unlocked = true; }
  async unlock(): Promise<void> { this.unlocked = true; if (this.request !== undefined) this.request = { ...this.request, locked: false }; }
  async lock(): Promise<void> { this.unlocked = false; }
  async revealPhrase(): Promise<string> { return MNEMONIC; }
  async snapshot(): Promise<{ snapshot: WalletSnapshot; tokens: Tokens }> { return { snapshot, tokens }; }
  async history(): Promise<{ entries: readonly ActivityEntry[]; tokens: Tokens }> { return { entries, tokens }; }
  async updateSettings(patch: Partial<WalletSettings>): Promise<{ settings: WalletSettings; unlocked: boolean }> {
    this.settings = { ...this.settings, ...patch };
    return { settings: this.settings, unlocked: this.unlocked };
  }
  async sites(): Promise<readonly ConnectedSite[]> { return this.sitesList; }
  async revokeSite(origin: string): Promise<void> { this.sitesList = this.sitesList.filter((site) => site.origin !== origin); }
  async prepareTransfer(draft: TransferDraft): Promise<ApprovalView> {
    return view(review({
      balanceChanges: [{ assetId: draft.assetId, amount: `-${draft.amount}` }],
      externalOutputs: [{ address: draft.recipient, assetId: draft.assetId, amount: draft.amount }],
      fee: String(410 * draft.feeRate),
    }), { kind: "transfer", feeRate: draft.feeRate }, "wallet");
  }
  async approve(): Promise<ApprovalResult> { return { txid: "ab".repeat(32) }; }
  async reject(): Promise<void> {}
  async describeRequest(): Promise<PendingRequestView> { return this.request ?? { status: "gone" }; }
  async resolveRequest(): Promise<{ result?: ApprovalResult }> { return { result: { txid: "ab".repeat(32) } }; }
  openTab(): void {}
}
