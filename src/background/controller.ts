import type { LwkWalletAdapter, LwkWalletSession, WalletAsset, WalletSnapshot } from "../adapters/lwk.js";
import { LwkUnavailableError } from "../adapters/lwk.js";
import { resolveEcxAlphaAddress } from "../network/ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "../network/identity.js";
import { bytesToBase64 } from "../shared/base64.js";
import { hasExactKeys, isPlainRecord, normalizeMnemonic, requireString, ValidationError } from "../shared/validation.js";
import { decryptVault, encryptVault, VaultAuthenticationError, VaultStore } from "../vault.js";

export type WalletResponse<T = unknown> =
  | { readonly ok: true; readonly result: T }
  | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };

interface ControllerDependencies {
  readonly vaultStore: VaultStore;
  readonly adapter: LwkWalletAdapter;
  readonly crypto?: Crypto;
  readonly now?: () => Date;
  readonly autoLockMilliseconds?: number;
  readonly syncTimeoutMilliseconds?: number;
}

export const DEFAULT_AUTO_LOCK_MILLISECONDS = 5 * 60 * 1_000;
export const DEFAULT_SYNC_TIMEOUT_MILLISECONDS = 30_000;
const MAX_ASSETS = 1_000;
const MAX_U64 = 18_446_744_073_709_551_615n;

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

function failure(error: unknown): WalletResponse<never> {
  if (error instanceof VaultAuthenticationError) {
    return { ok: false, error: { code: "VAULT_AUTHENTICATION_FAILED", message: error.message } };
  }
  if (error instanceof LwkUnavailableError) {
    return { ok: false, error: { code: "LWK_UNAVAILABLE", message: error.message } };
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
    || !hasExactKeys(chain, ["genesisHash", "nativeAssetId", "headerChainVerified", "explicitOutputsOnly"])
    || chain["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || chain["nativeAssetId"] !== ECX_ALPHA_IDENTITY.nativeAssetId
    || chain["headerChainVerified"] !== true
    || chain["explicitOutputsOnly"] !== true
  ) throw new ValidationError("wallet snapshot chain identity is not authenticated");
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
      headerChainVerified: true,
      explicitOutputsOnly: true,
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
  #session: LwkWalletSession | undefined;
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
    if (!Number.isSafeInteger(this.#autoLockMilliseconds) || this.#autoLockMilliseconds < 1_000) {
      throw new ValidationError("auto-lock interval is invalid");
    }
    if (!Number.isSafeInteger(this.#syncTimeoutMilliseconds) || this.#syncTimeoutMilliseconds < 10) {
      throw new ValidationError("wallet sync timeout is invalid");
    }
  }

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
          this.#session?.destroy();
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
    this.#lastActivityMilliseconds = 0;
  }
}
