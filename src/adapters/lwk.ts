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
    readonly headerChainVerified: true;
    readonly explicitOutputsOnly: true;
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

export interface PreparedTransaction {
  readonly pset: string;
  readonly summaryHash: string;
}

export interface LwkWalletSession {
  sync(signal: AbortSignal): Promise<WalletSnapshot>;
  prepareTransfer(draft: TransferDraft): Promise<PreparedTransaction>;
  prepareIssue(draft: IssueDraft): Promise<PreparedTransaction>;
  prepareReissue(draft: ReissueDraft): Promise<PreparedTransaction>;
  prepareBurn(draft: BurnDraft): Promise<PreparedTransaction>;
  signAndBroadcast(transaction: PreparedTransaction): Promise<string>;
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
