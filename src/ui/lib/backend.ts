/**
 * Typed client for the background worker. The UI never handles keys: it sees
 * public status, balances, reviews and one-time approval tokens only.
 */
import type { WalletSnapshot } from "../../adapters/elementsplus-wasm.js";
import type { ApprovalResult, ApprovalView } from "../../background/controller.js";
import type { ConnectedSite, WalletSettings } from "../../background/settings.js";
import type { TokenInfo } from "../../background/token-registry.js";
import type { ActivityEntry } from "../../network/activity.js";
import { getExtensionApi, sendExtensionMessage } from "../../platform/browser.js";
import type { AnyNetworkProfileId } from "../../network/profiles.js";
import { isPlainRecord } from "../../shared/validation.js";

export interface NetworkInfo {
  readonly name: string;
  readonly id: AnyNetworkProfileId;
  readonly genesisHash: string;
  readonly policyAsset: string;
  readonly defaultExplorerUrl: string;
}

export interface WalletStatus {
  readonly initialized: boolean;
  readonly unlocked: boolean;
  readonly primaryAddress: string | null;
  readonly network: NetworkInfo;
  readonly settings: WalletSettings;
}

export type Tokens = Record<string, TokenInfo>;

export interface PendingRequestView {
  readonly status: "pending" | "gone" | "failed";
  readonly requestId?: string;
  readonly origin?: string;
  readonly method?: string;
  readonly kind?: "connect" | "unlock" | "transaction";
  readonly locked?: boolean;
  readonly approval?: ApprovalView;
  readonly message?: string;
}

export interface TransferDraft {
  readonly assetId: string;
  readonly recipient: string;
  readonly amount: string;
  readonly feeRate: number;
}

export interface Backend {
  status(): Promise<WalletStatus>;
  touch(): Promise<void>;
  generateMnemonic(): Promise<string>;
  validateMnemonic(mnemonic: string): Promise<boolean>;
  createVault(password: string, mnemonic: string, replace: boolean): Promise<void>;
  unlock(password: string): Promise<void>;
  lock(): Promise<void>;
  revealPhrase(password: string): Promise<string>;
  snapshot(): Promise<{ readonly snapshot: WalletSnapshot; readonly tokens: Tokens }>;
  history(): Promise<{ readonly entries: readonly ActivityEntry[]; readonly tokens: Tokens }>;
  updateSettings(patch: Partial<WalletSettings>): Promise<{ readonly settings: WalletSettings; readonly unlocked: boolean }>;
  sites(): Promise<readonly ConnectedSite[]>;
  revokeSite(origin: string): Promise<void>;
  prepareTransfer(draft: TransferDraft): Promise<ApprovalView>;
  approve(view: ApprovalView): Promise<ApprovalResult>;
  reject(approvalId: string): Promise<void>;
  describeRequest(requestId: string): Promise<PendingRequestView>;
  resolveRequest(requestId: string, approved: boolean, approval?: ApprovalView): Promise<{ readonly result?: ApprovalResult }>;
  openTab(url: string): void;
}

export class BackendError extends Error {
  override readonly name = "BackendError";
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

async function call<T>(message: Record<string, unknown>): Promise<T> {
  const response = await sendExtensionMessage<unknown>(message);
  if (!isPlainRecord(response) || typeof response["ok"] !== "boolean") throw new BackendError("MALFORMED", "The wallet background returned a malformed response");
  if (response["ok"] === true) return response["result"] as T;
  const error = isPlainRecord(response["error"]) ? response["error"] : {};
  throw new BackendError(
    typeof error["code"] === "string" ? error["code"] : "OPERATION_FAILED",
    typeof error["message"] === "string" ? error["message"] : "Wallet operation failed",
  );
}

export class ExtensionBackend implements Backend {
  status(): Promise<WalletStatus> { return call({ type: "wallet.status" }); }
  async touch(): Promise<void> { await call({ type: "wallet.touch" }); }
  async generateMnemonic(): Promise<string> { return (await call<{ mnemonic: string }>({ type: "mnemonic.generate" })).mnemonic; }
  async validateMnemonic(mnemonic: string): Promise<boolean> { return (await call<{ valid: boolean }>({ type: "mnemonic.validate", mnemonic })).valid; }
  async createVault(password: string, mnemonic: string, replace: boolean): Promise<void> {
    await call({ type: "vault.create", password, mnemonic, ...(replace ? { replace: true } : {}) });
  }
  async unlock(password: string): Promise<void> { await call({ type: "wallet.unlock", password }); }
  async lock(): Promise<void> { await call({ type: "wallet.lock" }); }
  async revealPhrase(password: string): Promise<string> { return (await call<{ mnemonic: string }>({ type: "vault.reveal", password })).mnemonic; }
  snapshot(): Promise<{ snapshot: WalletSnapshot; tokens: Tokens }> { return call({ type: "wallet.snapshot" }); }
  history(): Promise<{ entries: readonly ActivityEntry[]; tokens: Tokens }> { return call({ type: "wallet.history" }); }
  updateSettings(patch: Partial<WalletSettings>): Promise<{ settings: WalletSettings; unlocked: boolean }> { return call({ type: "settings.update", patch }); }
  async sites(): Promise<readonly ConnectedSite[]> { return (await call<{ sites: ConnectedSite[] }>({ type: "sites.list" })).sites; }
  async revokeSite(origin: string): Promise<void> { await call({ type: "sites.revoke", origin }); }
  prepareTransfer(draft: TransferDraft): Promise<ApprovalView> {
    return call({ type: "tx.prepare", operation: { kind: "transfer", ...draft } });
  }
  approve(view: ApprovalView): Promise<ApprovalResult> {
    return call({ type: "tx.approve", approvalId: view.approvalId, approvalToken: view.approvalToken, reviewHash: view.reviewHash });
  }
  async reject(approvalId: string): Promise<void> { await call({ type: "tx.reject", approvalId }); }
  describeRequest(requestId: string): Promise<PendingRequestView> { return call({ type: "approval.get", requestId }); }
  resolveRequest(requestId: string, approved: boolean, approval?: ApprovalView): Promise<{ result?: ApprovalResult }> {
    return call({
      type: "approval.resolve",
      requestId,
      approved,
      ...(approved && approval !== undefined ? { approvalToken: approval.approvalToken, reviewHash: approval.reviewHash } : {}),
    });
  }
  openTab(url: string): void {
    void getExtensionApi().tabs.create({ url });
  }
}
