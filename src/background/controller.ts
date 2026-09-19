import type {
  LwkWalletAdapter,
  LwkWalletSession,
  PreparedTransaction,
  TransferDraft,
  TransferSummary,
  WalletAsset,
  WalletSnapshot,
} from "../adapters/lwk.js";
import { LwkUnavailableError } from "../adapters/lwk.js";
import { resolveEcxAlphaAddress } from "../network/ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "../network/identity.js";
import { base64ToBytes, bytesToBase64 } from "../shared/base64.js";
import { hasExactKeys, isPlainRecord, normalizeMnemonic, requireString, ValidationError } from "../shared/validation.js";
import { decryptVault, encryptVault, VaultAuthenticationError, VaultStore } from "../vault.js";

export type WalletResponse<T = unknown> =
  | { readonly ok: true; readonly result: T }
  | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };

export interface PrepareSendRequest {
  readonly type: "transaction.prepare-send";
  readonly assetId: string;
  readonly destination: string;
  readonly amountAtomic: string;
  readonly feeRate: string;
}

export interface ApproveAndBroadcastRequest {
  readonly type: "transaction.approve-and-broadcast";
  readonly approvalToken: string;
  readonly summaryHash: string;
}

export interface PreparedSendApproval {
  readonly approvalToken: string;
  readonly expiresAt: string;
  readonly summaryHash: string;
  readonly summary: TransferSummary;
}

export interface BroadcastTransactionResult {
  readonly txid: string;
}

interface ControllerDependencies {
  readonly vaultStore: VaultStore;
  readonly adapter: LwkWalletAdapter;
  readonly crypto?: Crypto;
  readonly now?: () => Date;
  readonly autoLockMilliseconds?: number;
  readonly syncTimeoutMilliseconds?: number;
  readonly approvalTimeoutMilliseconds?: number;
}

export const DEFAULT_AUTO_LOCK_MILLISECONDS = 5 * 60 * 1_000;
export const DEFAULT_SYNC_TIMEOUT_MILLISECONDS = 30_000;
export const DEFAULT_APPROVAL_TIMEOUT_MILLISECONDS = 2 * 60 * 1_000;
const MAX_ASSETS = 1_000;
const MAX_U64 = 18_446_744_073_709_551_615n;
const MAX_PSET_BYTES = 1024 * 1024;
const PSET_MAGIC = Object.freeze([0x70, 0x73, 0x65, 0x74, 0xff] as const);
const APPROVAL_TOKEN_BYTES = 32;

interface PendingApproval {
  readonly token: string;
  readonly summaryHash: string;
  readonly expiresAtMilliseconds: number;
  readonly transaction: PreparedTransaction;
  readonly session: LwkWalletSession;
}

class CapabilityUnavailableError extends Error {
  override readonly name = "CapabilityUnavailableError";
}

function requireExactRequest(raw: Record<string, unknown>, keys: readonly string[]): void {
  if (!hasExactKeys(raw, ["type", ...keys])) throw new ValidationError("wallet request contains unexpected or missing fields");
}

function randomWalletId(provider: Crypto): string {
  const bytes = provider.getRandomValues(new Uint8Array(16));
  try {
    return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  } finally {
    bytes.fill(0);
  }
}

function randomApprovalToken(provider: Crypto): string {
  const bytes = provider.getRandomValues(new Uint8Array(APPROVAL_TOKEN_BYTES));
  try {
    return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  } finally {
    bytes.fill(0);
  }
}

function failure(error: unknown): WalletResponse<never> {
  if (error instanceof VaultAuthenticationError) {
    return { ok: false, error: { code: "VAULT_AUTHENTICATION_FAILED", message: error.message } };
  }
  if (error instanceof LwkUnavailableError) {
    return { ok: false, error: { code: "LWK_UNAVAILABLE", message: error.message } };
  }
  if (error instanceof CapabilityUnavailableError) {
    return { ok: false, error: { code: "CAPABILITY_UNAVAILABLE", message: error.message } };
  }
  if (error instanceof ValidationError) {
    return { ok: false, error: { code: "INVALID_REQUEST", message: error.message } };
  }
  return { ok: false, error: { code: "OPERATION_FAILED", message: "Wallet operation failed" } };
}

function atomicAmount(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value) || BigInt(value) > MAX_U64) {
    throw new ValidationError(`${field} is not a canonical unsigned 64-bit amount`);
  }
  return value;
}

function positiveAtomicAmount(value: unknown, field: string): string {
  const amount = atomicAmount(value, field);
  if (amount === "0") throw new ValidationError(`${field} must be greater than zero`);
  return amount;
}

function assetId(value: unknown, field: string): string {
  const id = requireString(value, field, 64);
  if (!/^[0-9a-f]{64}$/u.test(id)) throw new ValidationError(`${field} is malformed`);
  return id;
}

function feeRate(value: unknown): string {
  const rate = requireString(value, "feeRate", 32);
  if (!/^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{0,7}[1-9])?$/u.test(rate) || rate === "0") {
    throw new ValidationError("feeRate must be a positive canonical decimal");
  }
  return rate;
}

function canonicalExplicitAddress(value: unknown, field: string): string {
  const supplied = requireString(value, field, 1_000);
  try {
    const resolved = resolveEcxAlphaAddress(supplied);
    if (resolved.confidential) throw new ValidationError(`${field} must be an explicit ECX Alpha address`);
    return resolved.canonical;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    throw new ValidationError(`${field} is not a valid ECX Alpha address`);
  }
}

function validatePreparedTransfer(value: unknown, draft: TransferDraft): PreparedTransaction {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["pset", "coreReviewHash", "summary"])) {
    throw new ValidationError("prepared transaction is malformed");
  }
  const pset = requireString(value["pset"], "prepared transaction PSET", Math.ceil(MAX_PSET_BYTES / 3) * 4);
  const psetBytes = base64ToBytes(pset, "prepared transaction PSET", MAX_PSET_BYTES);
  try {
    if (psetBytes.length < PSET_MAGIC.length || PSET_MAGIC.some((byte, index) => psetBytes[index] !== byte)) {
      throw new ValidationError("prepared transaction does not contain a PSET");
    }
  } finally {
    psetBytes.fill(0);
  }
  const coreReviewHash = requireString(value["coreReviewHash"], "core review hash", 64);
  if (!/^[0-9a-f]{64}$/u.test(coreReviewHash)) {
    throw new ValidationError("prepared transaction core review hash is malformed");
  }
  const summary = value["summary"];
  if (!isPlainRecord(summary) || !hasExactKeys(summary, [
    "kind", "networkKey", "genesisHash", "assetId", "destination", "amountAtomic",
    "networkFeeAssetId", "networkFeeAtomic", "feeRate", "transactionPolicy",
  ])) throw new ValidationError("prepared transaction summary is malformed");
  if (
    summary["kind"] !== "transfer"
    || summary["networkKey"] !== ECX_ALPHA_IDENTITY.key
    || summary["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || summary["transactionPolicy"] !== "explicit-only"
  ) throw new ValidationError("prepared transaction summary has the wrong network or policy");
  const checkedSummary: TransferSummary = Object.freeze({
    kind: "transfer",
    networkKey: ECX_ALPHA_IDENTITY.key,
    genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
    assetId: assetId(summary["assetId"], "summary.assetId"),
    destination: canonicalExplicitAddress(summary["destination"], "summary.destination"),
    amountAtomic: positiveAtomicAmount(summary["amountAtomic"], "summary.amountAtomic"),
    networkFeeAssetId: assetId(summary["networkFeeAssetId"], "summary.networkFeeAssetId"),
    networkFeeAtomic: positiveAtomicAmount(summary["networkFeeAtomic"], "summary.networkFeeAtomic"),
    feeRate: feeRate(summary["feeRate"]),
    transactionPolicy: "explicit-only",
  });
  if (
    checkedSummary.assetId !== draft.assetId
    || checkedSummary.destination !== draft.destination
    || checkedSummary.amountAtomic !== draft.amountAtomic
    || checkedSummary.feeRate !== draft.feeRate
    || checkedSummary.networkFeeAssetId !== ECX_ALPHA_IDENTITY.nativeAssetId
  ) throw new ValidationError("prepared transaction summary does not match the requested transfer");
  return Object.freeze({ pset, coreReviewHash, summary: checkedSummary });
}

async function transactionSummaryHash(provider: Crypto, transaction: PreparedTransaction): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify({
    domain: "elementsplus-transfer-approval-v2",
    pset: transaction.pset,
    coreReviewHash: transaction.coreReviewHash,
    summary: transaction.summary,
  }));
  try {
    const digest = new Uint8Array(await provider.subtle.digest("SHA-256", encoded));
    try {
      return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    } finally {
      digest.fill(0);
    }
  } finally {
    encoded.fill(0);
  }
}

function approvalToken(value: unknown): string {
  const token = requireString(value, "approvalToken", 43);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) throw new ValidationError("approvalToken is malformed");
  return token;
}

function summaryHash(value: unknown): string {
  const hash = requireString(value, "summaryHash", 64);
  if (!/^[0-9a-f]{64}$/u.test(hash)) throw new ValidationError("summaryHash is malformed");
  return hash;
}

function fixedLengthEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function nullableLabel(value: unknown, field: string, maximumLength: number): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw new ValidationError(`${field} is malformed`);
  }
  return value;
}

function validateAsset(value: unknown, index: number): WalletAsset {
  if (!isPlainRecord(value) || !hasExactKeys(value, [
    "assetId", "ticker", "name", "amountAtomic", "confirmedAtomic", "isNative",
  ])) throw new ValidationError(`assets[${index}] is malformed`);
  const assetId = requireString(value["assetId"], `assets[${index}].assetId`, 64);
  if (!/^[0-9a-f]{64}$/u.test(assetId)) throw new ValidationError(`assets[${index}].assetId is malformed`);
  if (typeof value["isNative"] !== "boolean") throw new ValidationError(`assets[${index}].isNative is malformed`);
  if ((assetId === ECX_ALPHA_IDENTITY.nativeAssetId) !== value["isNative"]) {
    throw new ValidationError(`assets[${index}] has an invalid native-asset marker`);
  }
  return Object.freeze({
    assetId,
    ticker: nullableLabel(value["ticker"], `assets[${index}].ticker`, 16),
    name: nullableLabel(value["name"], `assets[${index}].name`, 128),
    amountAtomic: atomicAmount(value["amountAtomic"], `assets[${index}].amountAtomic`),
    confirmedAtomic: atomicAmount(value["confirmedAtomic"], `assets[${index}].confirmedAtomic`),
    isNative: value["isNative"],
  });
}

/** Validate the untrusted runtime boundary returned by a future WASM adapter. */
export function validateWalletSnapshot(value: unknown): WalletSnapshot {
  if (!isPlainRecord(value) || !hasExactKeys(value, [
    "chain", "tipHeight", "tipHash", "receiveAddress", "assets", "syncedAt",
  ])) throw new ValidationError("wallet snapshot is malformed");
  const chain = value["chain"];
  if (
    !isPlainRecord(chain)
    || !hasExactKeys(chain, [
      "genesisHash", "nativeAssetId", "backend", "headerChainVerified", "transactionPolicy",
    ])
    || chain["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || chain["nativeAssetId"] !== ECX_ALPHA_IDENTITY.nativeAssetId
    || chain["backend"] !== "explorer"
    || chain["headerChainVerified"] !== false
    || chain["transactionPolicy"] !== "explicit-only"
  ) throw new ValidationError("wallet snapshot chain identity or trust metadata is invalid");
  const tipHeight = value["tipHeight"];
  if (typeof tipHeight !== "number" || !Number.isSafeInteger(tipHeight) || tipHeight < 0) {
    throw new ValidationError("wallet snapshot height is malformed");
  }
  const tipHash = requireString(value["tipHash"], "tipHash", 64);
  if (!/^[0-9a-f]{64}$/u.test(tipHash)) throw new ValidationError("wallet snapshot tip hash is malformed");
  const suppliedReceiveAddress = requireString(value["receiveAddress"], "receiveAddress", 1_000);
  let receiveAddress: string;
  try {
    const resolved = resolveEcxAlphaAddress(suppliedReceiveAddress);
    if (resolved.confidential) {
      throw new ValidationError("wallet snapshot receive address is confidential");
    }
    receiveAddress = resolved.canonical;
  } catch (error) {
    if (error instanceof ValidationError) throw error;
    throw new ValidationError("wallet snapshot receive address is not valid for ECX Alpha");
  }
  if (!Array.isArray(value["assets"]) || value["assets"].length === 0 || value["assets"].length > MAX_ASSETS) {
    throw new ValidationError("wallet snapshot asset list is malformed");
  }
  const assets = value["assets"].map(validateAsset);
  if (new Set(assets.map((asset) => asset.assetId)).size !== assets.length) {
    throw new ValidationError("wallet snapshot contains duplicate assets");
  }
  if (assets.filter((asset) => asset.isNative).length !== 1) {
    throw new ValidationError("wallet snapshot must contain exactly one native ECX entry");
  }
  const syncedAt = requireString(value["syncedAt"], "syncedAt", 32);
  const timestamp = new Date(syncedAt);
  if (!Number.isFinite(timestamp.getTime()) || timestamp.toISOString() !== syncedAt) {
    throw new ValidationError("wallet snapshot timestamp is malformed");
  }
  return Object.freeze({
    chain: Object.freeze({
      genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
      nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      backend: "explorer",
      headerChainVerified: false,
      transactionPolicy: "explicit-only",
    }),
    tipHeight,
    tipHash,
    receiveAddress,
    assets: Object.freeze(assets),
    syncedAt,
  });
}

export class WalletController {
  readonly #vaultStore: VaultStore;
  readonly #adapter: LwkWalletAdapter;
  readonly #crypto: Crypto;
  readonly #now: () => Date;
  readonly #autoLockMilliseconds: number;
  readonly #syncTimeoutMilliseconds: number;
  readonly #approvalTimeoutMilliseconds: number;
  #session: LwkWalletSession | undefined;
  #pendingApproval: PendingApproval | undefined;
  #lastActivityMilliseconds = 0;
  #autoLockTimer: ReturnType<typeof setTimeout> | undefined;
  #operationQueue: Promise<void> = Promise.resolve();

  constructor(dependencies: ControllerDependencies) {
    this.#vaultStore = dependencies.vaultStore;
    this.#adapter = dependencies.adapter;
    this.#crypto = dependencies.crypto ?? globalThis.crypto;
    this.#now = dependencies.now ?? (() => new Date());
    this.#autoLockMilliseconds = dependencies.autoLockMilliseconds ?? DEFAULT_AUTO_LOCK_MILLISECONDS;
    this.#syncTimeoutMilliseconds = dependencies.syncTimeoutMilliseconds ?? DEFAULT_SYNC_TIMEOUT_MILLISECONDS;
    this.#approvalTimeoutMilliseconds = dependencies.approvalTimeoutMilliseconds ?? DEFAULT_APPROVAL_TIMEOUT_MILLISECONDS;
    if (!Number.isSafeInteger(this.#autoLockMilliseconds) || this.#autoLockMilliseconds < 1_000) {
      throw new ValidationError("auto-lock interval is invalid");
    }
    if (!Number.isSafeInteger(this.#syncTimeoutMilliseconds) || this.#syncTimeoutMilliseconds < 10) {
      throw new ValidationError("wallet sync timeout is invalid");
    }
    if (!Number.isSafeInteger(this.#approvalTimeoutMilliseconds) || this.#approvalTimeoutMilliseconds < 1_000) {
      throw new ValidationError("transaction approval timeout is invalid");
    }
  }

  handle(request: PrepareSendRequest): Promise<WalletResponse<PreparedSendApproval>>;
  handle(request: ApproveAndBroadcastRequest): Promise<WalletResponse<BroadcastTransactionResult>>;
  handle(raw: unknown): Promise<WalletResponse>;
  handle(raw: unknown): Promise<WalletResponse> {
    const operation = this.#operationQueue.then(() => this.#handleSerialized(raw));
    this.#operationQueue = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async #handleSerialized(raw: unknown): Promise<WalletResponse> {
    try {
      if (!isPlainRecord(raw) || typeof raw["type"] !== "string") {
        throw new ValidationError("wallet request is malformed");
      }
      this.#expireIfIdle();
      this.#expirePendingApproval();
      switch (raw["type"]) {
        case "wallet.status":
          requireExactRequest(raw, []);
          return {
            ok: true,
            result: {
              initialized: await this.#vaultStore.exists(),
              unlocked: this.#session !== undefined,
              adapter: {
                available: this.#adapter.available,
                implementation: this.#adapter.implementation,
                capabilities: this.#adapter.capabilities,
              },
              network: ECX_ALPHA_IDENTITY,
            },
          };
        case "mnemonic.generate":
          requireExactRequest(raw, []);
          return { ok: true, result: { mnemonic: await this.#adapter.generateMnemonic() } };
        case "vault.create": {
          requireExactRequest(raw, ["password", "mnemonic", "identityAcknowledged"]);
          if (!this.#adapter.available) throw new LwkUnavailableError("wallet creation");
          if (await this.#vaultStore.exists()) throw new ValidationError("wallet vault already exists");
          const password = requireString(raw["password"], "password", 1024);
          const mnemonic = normalizeMnemonic(requireString(raw["mnemonic"], "mnemonic", 512));
          if (raw["identityAcknowledged"] !== true) throw new ValidationError("ECX Alpha identity must be acknowledged");
          if (!(await this.#adapter.validateMnemonic(mnemonic))) throw new ValidationError("recovery phrase checksum is invalid");
          const probe = await this.#adapter.openWallet(mnemonic, ECX_ALPHA_IDENTITY);
          probe.destroy();
          const encrypted = await encryptVault({
            schemaVersion: 1,
            walletId: randomWalletId(this.#crypto),
            mnemonic,
            createdAt: this.#now().toISOString(),
            networkKey: ECX_ALPHA_IDENTITY.key,
            genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
            explicitOutputsOnly: true,
          }, password, this.#crypto);
          await this.#vaultStore.write(encrypted);
          return { ok: true, result: { created: true } };
        }
        case "wallet.unlock": {
          requireExactRequest(raw, ["password"]);
          if (!this.#adapter.available) throw new LwkUnavailableError("wallet unlock");
          const password = requireString(raw["password"], "password", 1024);
          const payload = await decryptVault(await this.#vaultStore.read(), password, this.#crypto);
          this.#lock();
          this.#session = await this.#adapter.openWallet(payload.mnemonic, ECX_ALPHA_IDENTITY);
          this.#touch();
          return { ok: true, result: { unlocked: true } };
        }
        case "wallet.lock":
          requireExactRequest(raw, []);
          this.#lock();
          return { ok: true, result: { unlocked: false } };
        case "wallet.activity":
          requireExactRequest(raw, []);
          if (this.#session !== undefined) this.#touch();
          return { ok: true, result: { acknowledged: true } };
        case "wallet.snapshot": {
          requireExactRequest(raw, []);
          if (this.#session === undefined) throw new ValidationError("wallet is locked");
          return { ok: true, result: await this.#synchronizeSnapshot(this.#session) };
        }
        case "transaction.prepare-send": {
          requireExactRequest(raw, ["assetId", "destination", "amountAtomic", "feeRate"]);
          if (this.#session === undefined) throw new ValidationError("wallet is locked");
          if (!this.#adapter.capabilities.explicitTransactions) {
            throw new CapabilityUnavailableError("Wallet adapter does not support explicit transfers");
          }
          const draft: TransferDraft = Object.freeze({
            assetId: assetId(raw["assetId"], "assetId"),
            destination: canonicalExplicitAddress(raw["destination"], "destination"),
            amountAtomic: positiveAtomicAmount(raw["amountAtomic"], "amountAtomic"),
            feeRate: feeRate(raw["feeRate"]),
            explicitOutputsOnly: true,
          });
          const transaction = validatePreparedTransfer(await this.#session.prepareTransfer(draft), draft);
          const hash = await transactionSummaryHash(this.#crypto, transaction);
          const token = randomApprovalToken(this.#crypto);
          const expiresAtMilliseconds = this.#now().getTime() + this.#approvalTimeoutMilliseconds;
          // Only one review can be pending. Preparing again invalidates the old review.
          this.#pendingApproval = Object.freeze({
            token,
            summaryHash: hash,
            expiresAtMilliseconds,
            transaction,
            session: this.#session,
          });
          this.#touch();
          return {
            ok: true,
            result: Object.freeze({
              approvalToken: token,
              expiresAt: new Date(expiresAtMilliseconds).toISOString(),
              summaryHash: hash,
              summary: transaction.summary,
            }),
          };
        }
        case "transaction.approve-and-broadcast": {
          requireExactRequest(raw, ["approvalToken", "summaryHash"]);
          const pending = this.#pendingApproval;
          // Consume before every comparison/signing path. A failed attempt must be prepared again.
          this.#pendingApproval = undefined;
          const requestedToken = approvalToken(raw["approvalToken"]);
          const requestedHash = summaryHash(raw["summaryHash"]);
          if (
            pending === undefined
            || this.#session === undefined
            || pending.session !== this.#session
            || pending.expiresAtMilliseconds <= this.#now().getTime()
            || !fixedLengthEqual(pending.token, requestedToken)
            || !fixedLengthEqual(pending.summaryHash, requestedHash)
          ) throw new ValidationError("transaction approval is expired, invalid, or already used");
          const txid = await pending.session.signAndBroadcast(pending.transaction);
          if (!/^[0-9a-f]{64}$/u.test(txid)) throw new ValidationError("wallet adapter returned a malformed transaction id");
          this.#touch();
          return { ok: true, result: Object.freeze({ txid }) };
        }
        default:
          throw new ValidationError("wallet request type is unsupported");
      }
    } catch (error) {
      return failure(error);
    }
  }

  #expireIfIdle(): void {
    if (
      this.#session !== undefined
      && this.#now().getTime() - this.#lastActivityMilliseconds >= this.#autoLockMilliseconds
    ) this.#lock();
  }

  #expirePendingApproval(): void {
    if (
      this.#pendingApproval !== undefined
      && this.#pendingApproval.expiresAtMilliseconds <= this.#now().getTime()
    ) this.#pendingApproval = undefined;
  }

  #touch(): void {
    this.#lastActivityMilliseconds = this.#now().getTime();
    if (this.#autoLockTimer !== undefined) clearTimeout(this.#autoLockTimer);
    this.#autoLockTimer = setTimeout(() => {
      const operation = this.#operationQueue.then(() => this.#expireIfIdle());
      this.#operationQueue = operation.then(() => undefined, () => undefined);
    }, this.#autoLockMilliseconds);
  }

  async #synchronizeSnapshot(session: LwkWalletSession): Promise<WalletSnapshot> {
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), this.#syncTimeoutMilliseconds);
    const aborted = new Promise<never>((_resolve, reject) => {
      abortController.signal.addEventListener(
        "abort",
        () => reject(new Error("Wallet synchronization timed out")),
        { once: true },
      );
    });
    try {
      return validateWalletSnapshot(await Promise.race([
        session.sync(abortController.signal),
        aborted,
      ]));
    } finally {
      clearTimeout(timeout);
    }
  }

  #lock(): void {
    if (this.#autoLockTimer !== undefined) clearTimeout(this.#autoLockTimer);
    this.#autoLockTimer = undefined;
    this.#session?.destroy();
    this.#session = undefined;
    this.#pendingApproval = undefined;
    this.#lastActivityMilliseconds = 0;
  }
}
