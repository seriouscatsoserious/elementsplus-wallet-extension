/**
 * Background wallet controller. Owns the decrypted session; extension pages
 * and the dApp router talk to it only through validated messages/methods.
 *
 * Security properties:
 * - The vault is AES-GCM encrypted under a PBKDF2 password key (vault.ts).
 * - Keys exist only inside the WASM session while unlocked; auto-lock destroys it.
 * - Every signature requires a one-time approval token bound to the exact core
 *   review hash, with an expiry. Tokens are consumed before signing.
 * - Every core review is checked against the exact request before it is shown.
 */
import type { SwapOffer, TxReview } from "../adapters/wallet-core.js";
import type { WalletAddress, WalletSession, WalletSnapshot } from "../adapters/elementsplus-wasm.js";
import type { ActivityEntry } from "../network/activity.js";
import type { EcxAlphaIdentity } from "../network/identity.js";
import type { ExtensionStorageArea } from "../platform/browser.js";
import { bytesToBase64 } from "../shared/base64.js";
import { hasExactKeys, isPlainRecord, normalizeMnemonic, requireString, ValidationError } from "../shared/validation.js";
import { decryptVault, encryptVault, VaultAuthenticationError, type VaultStore } from "../vault.js";
import {
  checkReview,
  checkSwapOfferReview,
  validateOperation,
  type PreparedPlan,
  type WalletOperation,
} from "./operations.js";
import { ACCOUNT_STORAGE_KEY, SITES_STORAGE_KEY, type SettingsStore, type WalletSettings } from "./settings.js";
import type { TokenInfo } from "./token-registry.js";

export type WalletResponse<T = unknown> =
  | { readonly ok: true; readonly result: T }
  | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };

export const DEFAULT_APPROVAL_TIMEOUT_MILLISECONDS = 5 * 60 * 1_000;
export const DEFAULT_SYNC_TIMEOUT_MILLISECONDS = 45_000;
const MAX_PENDING_APPROVALS = 8;
const TOKEN_BYTES = 32;

export interface WalletOpener {
  generateMnemonic(): Promise<string>;
  validateMnemonic(mnemonic: string): Promise<boolean>;
  open(mnemonic: string, explorerUrl: string): Promise<WalletSession>;
  /** Locate the issuance input of a signed transaction (for `ep_issueAsset`'s `vin`). */
  findIssuanceVin?(rawTxHex: string, txid: string, contract: Record<string, unknown>, assetId: string, inputCount: number): Promise<number>;
}

export interface TokenLookup {
  lookup(assetIds: readonly string[]): Promise<Record<string, TokenInfo>>;
  cached(assetIds: readonly string[]): Promise<Record<string, TokenInfo>>;
  /** Remember the metadata of an asset this wallet issued (ids derived by the core from the contract). */
  rememberIssued?(issued: { readonly assetId: string; readonly tokenId: string | null; readonly contract: Record<string, unknown> }): Promise<void>;
  clear(): Promise<void>;
}

export type ActivityLoader = (options: {
  readonly explorerUrl: string;
  readonly addresses: readonly WalletAddress[];
  readonly policyAsset: string;
}) => Promise<ActivityEntry[]>;

export interface ControllerDependencies {
  readonly vaultStore: VaultStore;
  readonly storage: ExtensionStorageArea;
  readonly wallets: WalletOpener;
  readonly settings: SettingsStore;
  readonly identity: EcxAlphaIdentity;
  readonly tokens?: TokenLookup;
  readonly activity?: ActivityLoader;
  readonly crypto?: Crypto;
  readonly now?: () => Date;
  readonly approvalTimeoutMilliseconds?: number;
  readonly syncTimeoutMilliseconds?: number;
  /** Called after the wallet locks (manually, by timer, or by settings change). */
  readonly onLock?: () => void;
}

/** What an approval surface shows. Contains no secrets except the one-time token. */
export interface ApprovalView {
  readonly approvalId: string;
  readonly approvalToken: string;
  readonly reviewHash: string;
  readonly expiresAt: string;
  readonly origin: string;
  readonly operation: OperationSummary;
  readonly review: TxReview;
  readonly tokens: Record<string, TokenInfo>;
}

/** Display summary of the request (the review is still the source of truth). */
export type OperationSummary =
  | { readonly kind: "transfer"; readonly feeRate: number }
  | { readonly kind: "issuance"; readonly name: string; readonly ticker: string; readonly precision: number; readonly feeRate: number }
  | { readonly kind: "swap_offer"; readonly giveAsset: string; readonly giveAmount: string; readonly wantAsset: string;
      readonly wantAmount: string; readonly needsSplit: boolean; readonly feeRate: number }
  | { readonly kind: "swap_take"; readonly offerCount: number; readonly feeRate: number }
  | { readonly kind: "cancel"; readonly outpoint: string; readonly feeRate: number };

export interface ApprovalResult {
  readonly txid?: string;
  readonly offer?: SwapOffer;
  readonly splitTxid?: string;
  readonly assetId?: string;
  readonly tokenId?: string;
  readonly contract?: Record<string, unknown>;
  readonly vin?: number;
}

interface PendingApproval {
  readonly id: string;
  readonly token: string;
  readonly origin: string;
  readonly operation: WalletOperation;
  readonly plan: PreparedPlan;
  readonly session: WalletSession;
  readonly expiresAtMilliseconds: number;
}

export class WalletLockedError extends Error {
  override readonly name = "WalletLockedError";
  constructor() { super("Wallet is locked"); }
}

function randomToken(provider: Crypto, length: number): string {
  const bytes = provider.getRandomValues(new Uint8Array(length));
  try {
    return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  } finally {
    bytes.fill(0);
  }
}

/** Do not keep a non-browser host (tests, Node tooling) alive for a timer. */
export function unrefTimer(timer: unknown): void {
  (timer as { unref?: () => void } | undefined)?.unref?.();
}

function fixedLengthEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function exact(raw: Record<string, unknown>, keys: readonly string[], optional: readonly string[] = []): void {
  if (!hasExactKeys(raw, ["type", ...keys], optional)) throw new ValidationError("wallet request contains unexpected or missing fields");
}

function token(value: unknown, field: string, length: number): string {
  if (typeof value !== "string" || !new RegExp(`^[A-Za-z0-9_-]{${length}}$`, "u").test(value)) {
    throw new ValidationError(`${field} is malformed`);
  }
  return value;
}

function hash(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) throw new ValidationError(`${field} is malformed`);
  return value;
}

export function failure(error: unknown): WalletResponse<never> {
  if (error instanceof VaultAuthenticationError) return { ok: false, error: { code: "WRONG_PASSWORD", message: "Incorrect password" } };
  if (error instanceof WalletLockedError) return { ok: false, error: { code: "LOCKED", message: error.message } };
  if (error instanceof ValidationError) return { ok: false, error: { code: "INVALID_REQUEST", message: error.message } };
  if (error instanceof Error && error.message.length > 0 && error.message.length < 300) {
    return { ok: false, error: { code: "OPERATION_FAILED", message: error.message } };
  }
  return { ok: false, error: { code: "OPERATION_FAILED", message: "Wallet operation failed" } };
}

function summarize(operation: WalletOperation, plan: PreparedPlan): OperationSummary {
  switch (operation.kind) {
    case "transfer": return { kind: "transfer", feeRate: operation.feeRate };
    case "issuance": return { kind: "issuance", name: operation.name, ticker: operation.ticker, precision: operation.precision, feeRate: operation.feeRate };
    case "swap_offer": return {
      kind: "swap_offer",
      giveAsset: operation.giveAsset,
      giveAmount: operation.giveAmount,
      wantAsset: operation.wantAsset,
      wantAmount: operation.wantAmount,
      needsSplit: plan.offeredOutpoint === null,
      feeRate: operation.feeRate,
    };
    case "swap_take": return { kind: "swap_take", offerCount: operation.offers.length, feeRate: operation.feeRate };
    case "cancel": return { kind: "cancel", outpoint: `${operation.txid}:${operation.vout}`, feeRate: operation.feeRate };
  }
}

export class WalletController {
  readonly #deps: ControllerDependencies;
  readonly #crypto: Crypto;
  readonly #now: () => Date;
  readonly #approvalTimeout: number;
  readonly #syncTimeout: number;
  #session: WalletSession | undefined;
  #pending = new Map<string, PendingApproval>();
  #lastActivity = 0;
  #autoLockMilliseconds = 15 * 60 * 1_000;
  #autoLockTimer: ReturnType<typeof setTimeout> | undefined;
  #queue: Promise<void> = Promise.resolve();

  constructor(dependencies: ControllerDependencies) {
    this.#deps = dependencies;
    this.#crypto = dependencies.crypto ?? globalThis.crypto;
    this.#now = dependencies.now ?? (() => new Date());
    this.#approvalTimeout = dependencies.approvalTimeoutMilliseconds ?? DEFAULT_APPROVAL_TIMEOUT_MILLISECONDS;
    this.#syncTimeout = dependencies.syncTimeoutMilliseconds ?? DEFAULT_SYNC_TIMEOUT_MILLISECONDS;
    if (!Number.isSafeInteger(this.#approvalTimeout) || this.#approvalTimeout < 1_000) throw new ValidationError("approval timeout is invalid");
    if (!Number.isSafeInteger(this.#syncTimeout) || this.#syncTimeout < 10) throw new ValidationError("sync timeout is invalid");
  }

  /** Serialize all state-changing work. */
  #serial<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(work);
    this.#queue = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Entry point for messages from extension pages (popup, tab, approval window). */
  handle(raw: unknown): Promise<WalletResponse> {
    return this.#serial(async () => {
      try {
        return { ok: true as const, result: await this.#dispatch(raw) };
      } catch (error) {
        return failure(error);
      }
    });
  }

  async #dispatch(raw: unknown): Promise<unknown> {
    if (!isPlainRecord(raw) || typeof raw["type"] !== "string") throw new ValidationError("wallet request is malformed");
    this.#expireIfIdle();
    this.#expireApprovals();
    switch (raw["type"]) {
      case "wallet.status":
        exact(raw, []);
        return this.#status();
      case "wallet.touch":
        exact(raw, []);
        if (this.#session !== undefined) this.#touch();
        return { unlocked: this.#session !== undefined };
      case "mnemonic.generate":
        exact(raw, []);
        return { mnemonic: await this.#deps.wallets.generateMnemonic() };
      case "mnemonic.validate": {
        exact(raw, ["mnemonic"]);
        let valid = false;
        try {
          valid = await this.#deps.wallets.validateMnemonic(normalizeMnemonic(requireString(raw["mnemonic"], "mnemonic", 512)));
        } catch {
          valid = false;
        }
        return { valid };
      }
      case "vault.create": {
        exact(raw, ["password", "mnemonic"], ["replace"]);
        const password = requireString(raw["password"], "password", 1024);
        const mnemonic = normalizeMnemonic(requireString(raw["mnemonic"], "mnemonic", 512));
        if (raw["replace"] !== undefined && typeof raw["replace"] !== "boolean") throw new ValidationError("replace must be a boolean");
        if (await this.#deps.vaultStore.exists() && raw["replace"] !== true) throw new ValidationError("a wallet already exists");
        if (!(await this.#deps.wallets.validateMnemonic(mnemonic))) throw new ValidationError("recovery phrase is not valid");
        const settings = await this.#deps.settings.get();
        const session = await this.#deps.wallets.open(mnemonic, settings.explorerUrl);
        const encrypted = await encryptVault({
          schemaVersion: 1,
          walletId: randomToken(this.#crypto, 16),
          mnemonic,
          createdAt: this.#now().toISOString(),
          networkKey: this.#deps.identity.key,
          genesisHash: this.#deps.identity.genesisHash,
          explicitOutputsOnly: true,
        }, password, this.#crypto);
        this.#lock();
        if (raw["replace"] === true) {
          await this.#deps.vaultStore.replace(encrypted);
          // A restored wallet starts with no connected sites.
          await this.#deps.storage.remove([SITES_STORAGE_KEY, ACCOUNT_STORAGE_KEY]);
        } else {
          await this.#deps.vaultStore.write(encrypted);
        }
        await this.#adopt(session, settings);
        return { created: true, unlocked: true };
      }
      case "wallet.unlock": {
        exact(raw, ["password"]);
        const password = requireString(raw["password"], "password", 1024);
        const payload = await decryptVault(await this.#deps.vaultStore.read(), password, this.#crypto);
        const settings = await this.#deps.settings.get();
        const session = await this.#deps.wallets.open(payload.mnemonic, settings.explorerUrl);
        this.#lock();
        await this.#adopt(session, settings);
        return { unlocked: true };
      }
      case "wallet.lock":
        exact(raw, []);
        this.#lock();
        return { unlocked: false };
      case "vault.reveal": {
        exact(raw, ["password"]);
        const payload = await decryptVault(await this.#deps.vaultStore.read(), requireString(raw["password"], "password", 1024), this.#crypto);
        if (this.#session !== undefined) this.#touch();
        return { mnemonic: payload.mnemonic };
      }
      case "wallet.snapshot": {
        exact(raw, []);
        const snapshot = await this.snapshot();
        return { snapshot, tokens: await this.#tokens(snapshot.balances.map((balance) => balance.assetId), true) };
      }
      case "wallet.history": {
        exact(raw, []);
        const session = this.#requireSession();
        if (this.#deps.activity === undefined) return { entries: [], tokens: {} };
        const settings = await this.#deps.settings.get();
        const entries = await this.#deps.activity({
          explorerUrl: settings.explorerUrl,
          addresses: await session.walletAddresses(),
          policyAsset: this.#deps.identity.nativeAssetId,
        });
        const assets = new Set(entries.flatMap((entry) => entry.deltas.map((delta) => delta.assetId)));
        return { entries, tokens: await this.#tokens([...assets], false) };
      }
      case "tokens.lookup": {
        exact(raw, ["assetIds"]);
        const ids = raw["assetIds"];
        if (!Array.isArray(ids) || ids.length > 500 || ids.some((id) => typeof id !== "string" || !/^[0-9a-f]{64}$/u.test(id))) {
          throw new ValidationError("assetIds is malformed");
        }
        return { tokens: await this.#tokens(ids as string[], true) };
      }
      case "settings.get":
        exact(raw, []);
        return { settings: await this.#deps.settings.get() };
      case "settings.update": {
        exact(raw, ["patch"]);
        const before = await this.#deps.settings.get();
        const settings = await this.#deps.settings.update(raw["patch"]);
        this.#autoLockMilliseconds = settings.autoLockMinutes * 60_000;
        if (settings.registryUrl !== before.registryUrl || settings.explorerUrl !== before.explorerUrl) await this.#deps.tokens?.clear();
        // The session is bound to its explorer; switching explorers requires a fresh unlock.
        if (settings.explorerUrl !== before.explorerUrl) this.#lock();
        else if (this.#session !== undefined) this.#touch();
        return { settings, unlocked: this.#session !== undefined };
      }
      case "tx.prepare": {
        exact(raw, ["operation"]);
        // Wallet UI may only build plain transfers; everything else comes from dApps.
        const operation = validateOperation(raw["operation"]);
        if (operation.kind !== "transfer") throw new ValidationError("only transfers can be prepared from the wallet UI");
        return await this.#prepareApproval(operation, "wallet");
      }
      case "tx.approve": {
        exact(raw, ["approvalId", "approvalToken", "reviewHash"]);
        return await this.#approve(
          token(raw["approvalId"], "approvalId", 22),
          token(raw["approvalToken"], "approvalToken", 43),
          hash(raw["reviewHash"], "reviewHash"),
        );
      }
      case "tx.reject": {
        exact(raw, ["approvalId"]);
        this.#pending.delete(token(raw["approvalId"], "approvalId", 22));
        return { rejected: true };
      }
      default:
        throw new ValidationError("wallet request type is unsupported");
    }
  }

  // ---- API used by the dApp provider router (same serialization queue) ----

  isUnlocked(): boolean {
    this.#expireIfIdle();
    return this.#session !== undefined;
  }

  /** The account's stable public address (external/0); available while locked once known. */
  async primaryAddress(): Promise<string | null> {
    if (this.isUnlocked()) return this.#session!.primaryAddress();
    const stored = (await this.#deps.storage.get(ACCOUNT_STORAGE_KEY))[ACCOUNT_STORAGE_KEY];
    return isPlainRecord(stored) && typeof stored["primaryAddress"] === "string" ? stored["primaryAddress"] : null;
  }

  snapshot(): Promise<WalletSnapshot> {
    const session = this.#requireSession();
    this.#touch();
    return this.#withTimeout((signal) => session.sync(signal));
  }

  /** Prepare + check an operation for an origin; returns the approval view. */
  prepare(operation: WalletOperation, origin: string): Promise<ApprovalView> {
    return this.#serial(() => {
      this.#expireIfIdle();
      this.#expireApprovals();
      return this.#prepareApproval(operation, origin);
    });
  }

  approve(approvalId: string, approvalToken: string, reviewHash: string): Promise<ApprovalResult> {
    return this.#serial(() => {
      this.#expireIfIdle();
      return this.#approve(approvalId, approvalToken, reviewHash);
    });
  }

  reject(approvalId: string): void {
    this.#pending.delete(approvalId);
  }

  // ---- internals ----

  async #status(): Promise<unknown> {
    const settings = await this.#deps.settings.get();
    return {
      initialized: await this.#deps.vaultStore.exists(),
      unlocked: this.#session !== undefined,
      primaryAddress: await this.primaryAddress(),
      network: {
        name: this.#deps.identity.displayName,
        mode: this.#deps.identity.mode,
        genesisHash: this.#deps.identity.genesisHash,
        policyAsset: this.#deps.identity.nativeAssetId,
        defaultExplorerUrl: this.#deps.identity.explorerUrl,
      },
      settings,
    };
  }

  async #adopt(session: WalletSession, settings: WalletSettings): Promise<void> {
    this.#session = session;
    this.#autoLockMilliseconds = settings.autoLockMinutes * 60_000;
    this.#touch();
    await this.#deps.storage.set({ [ACCOUNT_STORAGE_KEY]: { primaryAddress: session.primaryAddress() } });
  }

  async #tokens(assetIds: readonly string[], verifyNew: boolean): Promise<Record<string, TokenInfo>> {
    if (this.#deps.tokens === undefined) return {};
    try {
      return verifyNew ? await this.#deps.tokens.lookup(assetIds) : await this.#deps.tokens.cached(assetIds);
    } catch {
      return await this.#deps.tokens.cached(assetIds).catch(() => ({}));
    }
  }

  #requireSession(): WalletSession {
    if (this.#session === undefined) throw new WalletLockedError();
    return this.#session;
  }

  async #prepareApproval(operation: WalletOperation, origin: string): Promise<ApprovalView> {
    const session = this.#requireSession();
    if (this.#pending.size >= MAX_PENDING_APPROVALS) throw new ValidationError("too many pending approvals; finish or reject one first");
    const plan = await this.#withTimeout(() => session.plan(operation));
    checkReview(operation, plan, { genesisHash: this.#deps.identity.genesisHash, policyAsset: this.#deps.identity.nativeAssetId });
    const id = randomToken(this.#crypto, 16);
    const approvalToken = randomToken(this.#crypto, TOKEN_BYTES);
    const expiresAtMilliseconds = this.#now().getTime() + this.#approvalTimeout;
    // UI-originated transfers: preparing again replaces the previous one.
    if (origin === "wallet") for (const [key, value] of this.#pending) if (value.origin === "wallet") this.#pending.delete(key);
    this.#pending.set(id, Object.freeze({ id, token: approvalToken, origin, operation, plan, session, expiresAtMilliseconds }));
    this.#touch();
    const review = plan.prepared.review;
    const assets = new Set<string>([
      this.#deps.identity.nativeAssetId,
      ...review.balanceChanges.map((delta) => delta.assetId),
      ...review.externalOutputs.map((output) => output.assetId),
    ]);
    if (operation.kind === "swap_offer") assets.add(operation.giveAsset).add(operation.wantAsset);
    const tokens = { ...await this.#tokens([...assets], true) };
    if (operation.kind === "issuance" && review.issuance !== null) {
      // The core derived these ids from exactly this contract: label the new asset with it.
      tokens[review.issuance.assetId] = Object.freeze({
        assetId: review.issuance.assetId, name: operation.name, ticker: operation.ticker, precision: operation.precision,
        verified: true, native: false, tokenFor: null,
      });
      if (review.issuance.tokenId !== null) {
        tokens[review.issuance.tokenId] = Object.freeze({
          assetId: review.issuance.tokenId, name: `${operation.name} reissuance token`, ticker: `${operation.ticker}-RT`, precision: 0,
          verified: true, native: false, tokenFor: review.issuance.assetId,
        });
      }
    }
    return Object.freeze({
      approvalId: id,
      approvalToken,
      reviewHash: plan.prepared.reviewHash,
      expiresAt: new Date(expiresAtMilliseconds).toISOString(),
      origin,
      operation: summarize(operation, plan),
      review,
      tokens,
    });
  }

  async #approve(approvalId: string, approvalToken: string, reviewHash: string): Promise<ApprovalResult> {
    const pending = this.#pending.get(approvalId);
    // Consume before any comparison or signing; a failed attempt must be prepared again.
    this.#pending.delete(approvalId);
    if (
      pending === undefined
      || this.#session === undefined
      || pending.session !== this.#session
      || pending.expiresAtMilliseconds <= this.#now().getTime()
      || !fixedLengthEqual(pending.token, approvalToken)
      || !fixedLengthEqual(pending.plan.prepared.reviewHash, reviewHash)
    ) throw new ValidationError("approval is expired, invalid, or already used");
    const session = pending.session;
    const { operation, plan } = pending;
    const signed = session.sign(plan.prepared, reviewHash);
    this.#touch();
    if (signed.offer !== null) {
      if (operation.kind !== "swap_offer" || plan.offeredOutpoint === null) throw new ValidationError("core returned an unexpected offer");
      return { offer: signed.offer, txid: signed.txid };
    }
    if (operation.kind === "swap_offer" && plan.offeredOutpoint !== null) throw new ValidationError("core did not return the swap offer");
    const txid = await session.broadcast(signed.rawTxHex!, signed.txid);
    if (txid !== signed.txid) throw new ValidationError("explorer accepted a different transaction");
    this.#touch();
    if (operation.kind === "swap_offer") {
      // Second stage of the same approval: the offer terms were approved with the split.
      const next = await session.planOfferAfterSplit(operation, signed, plan.splitReceiveIndex ?? 0);
      checkSwapOfferReview(operation, next.prepared.review, next.offeredOutpoint);
      const offer = session.sign(next.prepared, next.prepared.reviewHash);
      if (offer.offer === null) throw new ValidationError("core did not return the swap offer");
      return { offer: offer.offer, splitTxid: txid };
    }
    if (operation.kind === "issuance") {
      const issuance = plan.prepared.review.issuance!;
      const contract = { name: operation.name, ticker: operation.ticker, precision: operation.precision, version: 0 };
      const vin = this.#deps.wallets.findIssuanceVin === undefined
        ? 0
        : await this.#deps.wallets.findIssuanceVin(signed.rawTxHex!, txid, contract, issuance.assetId, plan.prepared.review.inputsSigned.length);
      await this.#deps.tokens?.rememberIssued?.({ assetId: issuance.assetId, tokenId: issuance.tokenId, contract }).catch(() => undefined);
      return {
        txid,
        assetId: issuance.assetId,
        ...(issuance.tokenId === null ? {} : { tokenId: issuance.tokenId }),
        contract,
        vin,
      };
    }
    return { txid };
  }

  async #withTimeout<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("The explorer did not respond in time"));
      }, this.#syncTimeout);
    });
    try {
      return await Promise.race([work(controller.signal), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  #expireIfIdle(): void {
    if (this.#session !== undefined && this.#now().getTime() - this.#lastActivity >= this.#autoLockMilliseconds) this.#lock();
  }

  #expireApprovals(): void {
    const now = this.#now().getTime();
    for (const [id, pending] of this.#pending) if (pending.expiresAtMilliseconds <= now) this.#pending.delete(id);
  }

  #touch(): void {
    this.#lastActivity = this.#now().getTime();
    if (this.#autoLockTimer !== undefined) clearTimeout(this.#autoLockTimer);
    this.#autoLockTimer = setTimeout(() => {
      void this.#serial(async () => this.#expireIfIdle());
    }, this.#autoLockMilliseconds);
    unrefTimer(this.#autoLockTimer);
  }

  #lock(): void {
    if (this.#autoLockTimer !== undefined) clearTimeout(this.#autoLockTimer);
    this.#autoLockTimer = undefined;
    const wasUnlocked = this.#session !== undefined;
    this.#session?.destroy();
    this.#session = undefined;
    this.#pending.clear();
    this.#lastActivity = 0;
    if (wasUnlocked) this.#deps.onLock?.();
  }
}
