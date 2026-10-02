/**
 * dApp provider router (spec §3.3). Requests arrive from content-script ports;
 * the origin is supplied by the service worker from the port's sender, never
 * from the page payload. Approvals happen in a separate extension window.
 */
import type { WalletSnapshot } from "../adapters/elementsplus-wasm.js";
import type { NetworkIdentity } from "../network/identity.js";
import { hasExactKeys, isPlainRecord, ValidationError } from "../shared/validation.js";
import { unrefTimer, type ApprovalResult, type ApprovalView } from "./controller.js";
import { validateOperation, type WalletOperation } from "./operations.js";
import type { ConnectedSite } from "./settings.js";

export const ProviderErrorCode = Object.freeze({
  USER_REJECTED: 4001,
  UNAUTHORIZED: 4100,
  UNSUPPORTED_METHOD: 4200,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
} as const);

export class ProviderError extends Error {
  override readonly name = "ProviderError";
  constructor(readonly code: number, message: string) {
    super(message);
  }
}

export type ProviderResponse =
  | { readonly result: unknown }
  | { readonly error: { readonly code: number; readonly message: string } };

export interface RouterController {
  isUnlocked(): boolean;
  primaryAddress(): Promise<string | null>;
  snapshot(): Promise<WalletSnapshot>;
  prepare(operation: WalletOperation, origin: string): Promise<ApprovalView>;
  approve(approvalId: string, approvalToken: string, reviewHash: string): Promise<ApprovalResult>;
  reject(approvalId: string): void;
}

export interface RouterPermissions {
  has(origin: string): Promise<boolean>;
  grant(origin: string, now: Date): Promise<void>;
  revoke(origin: string): Promise<boolean>;
  list(): Promise<ConnectedSite[]>;
}

export interface RouterDependencies {
  readonly controller: RouterController;
  readonly permissions: RouterPermissions;
  readonly identity: NetworkIdentity;
  /** Open `approve.html?id=<requestId>`; resolves to a window id when known. */
  readonly openApproval: (requestId: string) => Promise<number | undefined>;
  readonly closeWindow?: (windowId: number) => void;
  readonly emit: (origin: string, event: "accountsChanged" | "disconnect", data: unknown) => void;
  readonly randomId: () => string;
  readonly now?: () => Date;
  readonly requestTimeoutMilliseconds?: number;
}

export type RequestKind = "connect" | "unlock" | "transaction";

interface PendingRequest {
  readonly id: string;
  readonly origin: string;
  readonly method: string;
  readonly kind: RequestKind;
  readonly operation: WalletOperation | undefined;
  windowId: number | undefined;
  approvalId: string | undefined;
  readonly settle: (outcome: { ok: true; value: ApprovalResult | true } | { ok: false; error: ProviderError }) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

const MAX_PENDING_PER_ORIGIN = 3;
const MAX_PENDING_TOTAL = 12;
const DEFAULT_REQUEST_TIMEOUT_MS = 10 * 60 * 1_000;

const TRANSACTION_METHODS: Record<string, { kind: WalletOperation["kind"]; params: readonly string[] }> = {
  ep_sendTransfer: { kind: "transfer", params: ["assetId", "amount", "recipient"] },
  ep_makeSwapOffer: { kind: "swap_offer", params: ["giveAsset", "giveAmount", "wantAsset", "wantAmount"] },
  ep_takeSwapOffers: { kind: "swap_take", params: ["offers"] },
  ep_cancelSwapOffer: { kind: "cancel", params: ["txid", "vout"] },
  ep_issueAsset: { kind: "issuance", params: ["name", "ticker", "precision", "amount", "tokenAmount"] },
};

export function errorResponse(error: unknown): ProviderResponse {
  if (error instanceof ProviderError) return { error: { code: error.code, message: error.message } };
  if (error instanceof ValidationError) return { error: { code: ProviderErrorCode.INVALID_PARAMS, message: error.message } };
  const message = error instanceof Error && error.message.length < 300 ? error.message : "Internal wallet error";
  return { error: { code: ProviderErrorCode.INTERNAL, message } };
}

function paramsRecord(params: unknown): Record<string, unknown> {
  if (params === undefined || params === null) return {};
  // Accept `[ {...} ]` (JSON-RPC positional style) or `{...}`.
  const value = Array.isArray(params) && params.length === 1 ? params[0] : params;
  if (!isPlainRecord(value)) throw new ProviderError(ProviderErrorCode.INVALID_PARAMS, "params must be an object");
  return value;
}

export class ProviderRouter {
  readonly #deps: RouterDependencies;
  readonly #now: () => Date;
  readonly #pending = new Map<string, PendingRequest>();

  constructor(dependencies: RouterDependencies) {
    this.#deps = dependencies;
    this.#now = dependencies.now ?? (() => new Date());
  }

  /** Handle one provider request from `origin` (already authenticated by the caller). */
  async request(origin: string, raw: unknown): Promise<ProviderResponse> {
    try {
      if (!isPlainRecord(raw) || typeof raw["method"] !== "string" || !hasExactKeys(raw, ["method"], ["params"])) {
        throw new ProviderError(ProviderErrorCode.INVALID_PARAMS, "request must be { method, params? }");
      }
      return { result: await this.#route(origin, raw["method"], raw["params"]) };
    } catch (error) {
      return errorResponse(error);
    }
  }

  async #route(origin: string, method: string, params: unknown): Promise<unknown> {
    switch (method) {
      case "ep_connect": {
        if (params !== undefined && params !== null && !(Array.isArray(params) && params.length === 0)) {
          paramsRecord(params);
        }
        if (await this.#deps.permissions.has(origin)) {
          const address = await this.#deps.controller.primaryAddress();
          if (address !== null) return this.#connectResult(address);
        }
        await this.#ask(origin, method, "connect", undefined);
        return this.#connectResult(await this.#address(origin, method));
      }
      case "ep_disconnect":
        if (await this.#deps.permissions.revoke(origin)) this.#notifyDisconnect(origin);
        return null;
      case "ep_getAddress":
        await this.#requireConnected(origin);
        return { address: await this.#address(origin, method) };
      case "ep_getBalances": {
        await this.#requireConnected(origin);
        if (!this.#deps.controller.isUnlocked()) await this.#ask(origin, method, "unlock", undefined);
        const snapshot = await this.#deps.controller.snapshot();
        return snapshot.balances.map((balance) => ({ assetId: balance.assetId, amount: balance.amount, confirmed: balance.confirmed }));
      }
      default: {
        const spec = TRANSACTION_METHODS[method];
        if (spec === undefined) throw new ProviderError(ProviderErrorCode.UNSUPPORTED_METHOD, `Unsupported method ${method}`);
        await this.#requireConnected(origin);
        const record = paramsRecord(params);
        if (!hasExactKeys(record, spec.params, ["feeRate"])) {
          throw new ProviderError(ProviderErrorCode.INVALID_PARAMS, `${method} expects { ${spec.params.join(", ")} }`);
        }
        let operation: WalletOperation;
        try {
          operation = validateOperation({ ...record, kind: spec.kind });
        } catch (error) {
          throw new ProviderError(ProviderErrorCode.INVALID_PARAMS, error instanceof Error ? error.message : "invalid params");
        }
        const outcome = await this.#ask(origin, method, "transaction", operation);
        return this.#transactionResult(method, outcome === true ? {} : outcome);
      }
    }
  }

  #connectResult(address: string): unknown {
    return {
      address,
      network: {
        name: this.#deps.identity.displayName,
        genesisHash: this.#deps.identity.genesisHash,
        policyAsset: this.#deps.identity.nativeAssetId,
      },
    };
  }

  #transactionResult(method: string, result: ApprovalResult): unknown {
    switch (method) {
      case "ep_makeSwapOffer":
        return { offer: result.offer, ...(result.splitTxid === undefined ? {} : { splitTxid: result.splitTxid }) };
      case "ep_issueAsset":
        return {
          txid: result.txid,
          assetId: result.assetId,
          ...(result.tokenId === undefined ? {} : { tokenId: result.tokenId }),
          contract: result.contract,
          vin: result.vin,
        };
      default:
        return { txid: result.txid };
    }
  }

  async #requireConnected(origin: string): Promise<void> {
    if (!(await this.#deps.permissions.has(origin))) {
      throw new ProviderError(ProviderErrorCode.UNAUTHORIZED, "Not connected. Call ep_connect first.");
    }
  }

  async #address(origin: string, method: string): Promise<string> {
    let address = await this.#deps.controller.primaryAddress();
    if (address === null) {
      await this.#ask(origin, method, "unlock", undefined);
      address = await this.#deps.controller.primaryAddress();
    }
    if (address === null) throw new ProviderError(ProviderErrorCode.INTERNAL, "Wallet address is unavailable");
    return address;
  }

  #ask(origin: string, method: string, kind: RequestKind, operation: WalletOperation | undefined): Promise<ApprovalResult | true> {
    const forOrigin = [...this.#pending.values()].filter((entry) => entry.origin === origin).length;
    if (forOrigin >= MAX_PENDING_PER_ORIGIN || this.#pending.size >= MAX_PENDING_TOTAL) {
      return Promise.reject(new ProviderError(ProviderErrorCode.INTERNAL, "Too many pending wallet requests"));
    }
    return new Promise((resolve, reject) => {
      const id = this.#deps.randomId();
      const timer = setTimeout(() => this.#finish(id, { ok: false, error: new ProviderError(ProviderErrorCode.USER_REJECTED, "Request timed out") }),
        this.#deps.requestTimeoutMilliseconds ?? DEFAULT_REQUEST_TIMEOUT_MS);
      unrefTimer(timer);
      const entry: PendingRequest = {
        id,
        origin,
        method,
        kind,
        operation,
        windowId: undefined,
        approvalId: undefined,
        timer,
        settle: (outcome) => outcome.ok ? resolve(outcome.value) : reject(outcome.error),
      };
      this.#pending.set(id, entry);
      this.#deps.openApproval(id).then(
        (windowId) => {
          if (this.#pending.get(id) === entry) entry.windowId = windowId;
          else if (windowId !== undefined) this.#deps.closeWindow?.(windowId);
        },
        () => this.#finish(id, { ok: false, error: new ProviderError(ProviderErrorCode.INTERNAL, "Could not open the approval window") }),
      );
    });
  }

  #finish(id: string, outcome: { ok: true; value: ApprovalResult | true } | { ok: false; error: ProviderError }): void {
    const entry = this.#pending.get(id);
    if (entry === undefined) return;
    this.#pending.delete(id);
    clearTimeout(entry.timer);
    if (entry.approvalId !== undefined && !outcome.ok) this.#deps.controller.reject(entry.approvalId);
    entry.settle(outcome);
  }

  // ---- Approval-window API (extension pages only) ----

  /** Describe a pending request; prepares the transaction once the wallet is unlocked. */
  async describe(requestId: string): Promise<unknown> {
    const entry = this.#pending.get(requestId);
    if (entry === undefined) return { status: "gone" };
    const base = { status: "pending", requestId, origin: entry.origin, method: entry.method, kind: entry.kind };
    const unlocked = this.#deps.controller.isUnlocked();
    if (entry.kind !== "transaction") return { ...base, locked: !unlocked };
    if (!unlocked) return { ...base, locked: true };
    try {
      const approval = await this.#deps.controller.prepare(entry.operation!, entry.origin);
      if (entry.approvalId !== undefined) this.#deps.controller.reject(entry.approvalId);
      entry.approvalId = approval.approvalId;
      return { ...base, locked: false, approval };
    } catch (error) {
      const response = errorResponse(error);
      const message = "error" in response ? response.error.message : "Could not prepare the transaction";
      this.#finish(requestId, { ok: false, error: new ProviderError(ProviderErrorCode.INTERNAL, message) });
      return { ...base, status: "failed", message };
    }
  }

  /** Approve or reject a pending request from the approval window. */
  async resolve(raw: unknown): Promise<unknown> {
    if (!isPlainRecord(raw) || !hasExactKeys(raw, ["requestId", "approved"], ["approvalToken", "reviewHash"]) || typeof raw["approved"] !== "boolean") {
      throw new ValidationError("approval decision is malformed");
    }
    const requestId = raw["requestId"];
    const entry = typeof requestId === "string" ? this.#pending.get(requestId) : undefined;
    if (entry === undefined) throw new ValidationError("this request is no longer pending");
    if (!raw["approved"]) {
      this.#finish(entry.id, { ok: false, error: new ProviderError(ProviderErrorCode.USER_REJECTED, "User rejected the request") });
      return { done: true };
    }
    switch (entry.kind) {
      case "connect":
        if (!this.#deps.controller.isUnlocked()) throw new ValidationError("unlock the wallet first");
        await this.#deps.permissions.grant(entry.origin, this.#now());
        this.#finish(entry.id, { ok: true, value: true });
        return { done: true };
      case "unlock":
        if (!this.#deps.controller.isUnlocked()) throw new ValidationError("unlock the wallet first");
        this.#finish(entry.id, { ok: true, value: true });
        return { done: true };
      case "transaction": {
        const approvalToken = raw["approvalToken"];
        const reviewHash = raw["reviewHash"];
        if (entry.approvalId === undefined || typeof approvalToken !== "string" || typeof reviewHash !== "string") {
          throw new ValidationError("approval token and review hash are required");
        }
        const approvalId = entry.approvalId;
        entry.approvalId = undefined;
        try {
          const result = await this.#deps.controller.approve(approvalId, approvalToken, reviewHash);
          this.#finish(entry.id, { ok: true, value: result });
          return { done: true, result };
        } catch (error) {
          const response = errorResponse(error);
          const message = "error" in response ? response.error.message : "Transaction failed";
          this.#finish(entry.id, { ok: false, error: new ProviderError(ProviderErrorCode.INTERNAL, message) });
          throw error;
        }
      }
    }
  }

  /** The approval window was closed without a decision. */
  windowClosed(windowId: number): void {
    for (const entry of this.#pending.values()) {
      if (entry.windowId === windowId) {
        this.#finish(entry.id, { ok: false, error: new ProviderError(ProviderErrorCode.USER_REJECTED, "User closed the approval window") });
      }
    }
  }

  pendingCount(): number {
    return this.#pending.size;
  }

  async listSites(): Promise<ConnectedSite[]> {
    return this.#deps.permissions.list();
  }

  async revokeSite(origin: string): Promise<boolean> {
    const revoked = await this.#deps.permissions.revoke(origin);
    if (revoked) this.#notifyDisconnect(origin);
    return revoked;
  }

  #notifyDisconnect(origin: string): void {
    this.#deps.emit(origin, "accountsChanged", []);
    this.#deps.emit(origin, "disconnect", { code: ProviderErrorCode.UNAUTHORIZED, message: "Disconnected" });
  }
}
