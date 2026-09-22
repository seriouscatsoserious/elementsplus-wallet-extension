import type { EcxAlphaIdentity } from "../network/identity.js";

export interface LwkCapabilities {
  readonly mnemonic: boolean;
  readonly walletSync: boolean;
  readonly explicitTransactions: boolean;
  readonly issuance: boolean;
  readonly reissuance: boolean;
  readonly burning: boolean;
  readonly confidentialTransactions: false;
  readonly dex: false;
}

export interface WalletAsset {
  readonly assetId: string;
  readonly ticker: string | null;
  readonly name: string | null;
  readonly amountAtomic: string;
  readonly confirmedAtomic: string;
  readonly isNative: boolean;
}

export interface WalletSnapshot {
  readonly chain: {
    readonly genesisHash: string;
    readonly nativeAssetId: string;
    /**
     * An explorer-backed wallet trusts the configured backend for chain data.
     * It does not independently validate header continuity or proof of work.
     */
    readonly backend: "explorer";
    readonly headerChainVerified: false;
    readonly transactionPolicy: "explicit-only";
  };
  readonly tipHeight: number;
  readonly tipHash: string;
  readonly receiveAddress: string;
  readonly assets: readonly WalletAsset[];
  readonly syncedAt: string;
}

export interface TransferDraft {
  readonly assetId: string;
  readonly destination: string;
  readonly amountAtomic: string;
  readonly feeRate: string;
  readonly explicitOutputsOnly: true;
}

export interface IssueDraft {
  readonly assetAmountAtomic: string;
  readonly tokenAmountAtomic: string;
  readonly assetDestination: string;
  readonly tokenDestination: string;
  readonly explicitOutputsOnly: true;
}

export interface ReissueDraft {
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly destination: string;
  readonly explicitOutputsOnly: true;
}

export interface BurnDraft {
  readonly assetId: string;
  readonly amountAtomic: string;
  readonly explicitOutputsOnly: true;
}

export interface TransferSummary {
  readonly kind: "transfer";
  readonly networkKey: string;
  readonly genesisHash: string;
  readonly assetId: string;
  readonly destination: string;
  readonly amountAtomic: string;
  readonly networkFeeAssetId: string;
  readonly networkFeeAtomic: string;
  readonly feeRate: string;
  readonly transactionPolicy: "explicit-only";
}

export interface PreparedTransaction {
  /** Canonical base64 PSET. This remains inside the background controller. */
  readonly pset: string;
  /**
   * Domain-separated commitment recomputed by the local Rust core from the
   * exact serialized PSET. The controller binds this value into its one-time
   * approval and the core requires it again before signing.
   */
  readonly coreReviewHash: string;
  /**
   * Adapter-derived review data for the exact PSET above. The adapter must
   * reject omitted external outputs or any PSET/summary disagreement.
   */
  readonly summary: TransferSummary;
}

export interface SignedTransaction {
  readonly rawTransactionHex: string;
  readonly txid: string;
}

export interface LwkWalletSession {
  sync(signal: AbortSignal): Promise<WalletSnapshot>;
  prepareTransfer(draft: TransferDraft, requiredInput?: string): Promise<PreparedTransaction>;
  prepareIssue(draft: IssueDraft): Promise<PreparedTransaction>;
  prepareReissue(draft: ReissueDraft): Promise<PreparedTransaction>;
  prepareBurn(draft: BurnDraft): Promise<PreparedTransaction>;
  signPrepared(transaction: PreparedTransaction): Promise<SignedTransaction>;
  broadcastSigned(transaction: SignedTransaction): Promise<string>;
  destroy(): void;
}

export interface LwkWalletAdapter {
  readonly implementation: string;
  readonly available: boolean;
  readonly capabilities: LwkCapabilities;
  generateMnemonic(): Promise<string>;
  validateMnemonic(mnemonic: string): Promise<boolean>;
  openWallet(mnemonic: string, identity: EcxAlphaIdentity): Promise<LwkWalletSession>;
}

export class LwkUnavailableError extends Error {
  override readonly name = "LwkUnavailableError";

  constructor(operation: string) {
    super(`LWK adapter unavailable; ${operation} is disabled`);
  }
}

const NO_CAPABILITIES: LwkCapabilities = Object.freeze({
  mnemonic: false,
  walletSync: false,
  explicitTransactions: false,
  issuance: false,
  reissuance: false,
  burning: false,
  confidentialTransactions: false,
  dex: false,
});

/** Fail-closed placeholder. No fake keys, balances, addresses, or transactions. */
export class UnavailableLwkAdapter implements LwkWalletAdapter {
  readonly implementation = "not-installed";
  readonly available = false;
  readonly capabilities = NO_CAPABILITIES;

  async generateMnemonic(): Promise<string> {
    throw new LwkUnavailableError("recovery phrase generation");
  }

  async validateMnemonic(_mnemonic: string): Promise<boolean> {
    throw new LwkUnavailableError("recovery phrase validation");
  }

  async openWallet(_mnemonic: string, _identity: EcxAlphaIdentity): Promise<LwkWalletSession> {
    throw new LwkUnavailableError("wallet access");
  }
}
