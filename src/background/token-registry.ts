/**
 * Token metadata (spec §3.2). A registry entry is trusted only after the
 * wallet core recomputes the asset id from the explorer's raw issuance
 * transaction and the registry's contract (`verify_asset_issuance`).
 */
import type { VerifiedIssuance } from "../adapters/wallet-core.js";
import type { FetchImplementation } from "../network/ecx-alpha.js";
import { esploraApiBase, fetchJson, fetchText, HttpError } from "../network/http.js";
import type { ExtensionStorageArea } from "../platform/browser.js";
import { isPlainRecord } from "../shared/validation.js";

export const TOKEN_CACHE_KEY = "elementsplus.tokens.v1";
const HEX_32 = /^[0-9a-f]{64}$/u;
const RETRY_UNVERIFIED_MS = 10 * 60 * 1_000;
/**
 * A registry miss (404) or an unreachable registry/explorer is usually
 * temporary — e.g. a token the user just launched is registered a moment after
 * its issuance is broadcast — so it is retried much sooner than an entry that
 * failed verification.
 */
const RETRY_MISSING_MS = 20 * 1_000;
const MAX_CACHE_ENTRIES = 2_000;
// Control, bidi-override and zero-width characters enable visual spoofing.
const UNSAFE_TEXT = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/u;

export interface TokenInfo {
  readonly assetId: string;
  readonly name: string;
  readonly ticker: string;
  readonly precision: number;
  readonly verified: boolean;
  readonly native: boolean;
  /** For a reissuance token, the asset it controls. */
  readonly tokenFor: string | null;
}

interface CachedEntry {
  readonly status: "verified" | "unverified";
  /** Unverified because the entry could not be fetched (not because it failed verification). */
  readonly missing?: boolean;
  readonly name?: string;
  readonly ticker?: string;
  readonly precision?: number;
  readonly tokenFor?: string | null;
  readonly checkedAt: number;
}

interface CacheRecord {
  readonly registryUrl: string;
  readonly explorerUrl: string;
  readonly entries: Record<string, CachedEntry>;
}

export interface ContractMetadata {
  readonly name: string;
  readonly ticker: string;
  readonly precision: number;
}

export interface TokenRegistryDependencies {
  readonly storage: ExtensionStorageArea;
  readonly verifyIssuance: (request: {
    readonly rawTxHex: string;
    readonly expectedTxid: string;
    readonly vin: number;
    readonly contract: Record<string, unknown>;
  }) => Promise<VerifiedIssuance>;
  readonly fetchImpl: FetchImplementation;
  readonly endpoints: () => Promise<{ readonly registryUrl: string; readonly explorerUrl: string }>;
  readonly nativeAsset: { readonly assetId: string; readonly name: string; readonly ticker: string };
  readonly now?: () => number;
}

export function unknownToken(assetId: string): TokenInfo {
  return Object.freeze({ assetId, name: "Unknown asset", ticker: "", precision: 0, verified: false, native: false, tokenFor: null });
}

/** Validate an issuer contract's display fields. Returns null if unsafe or malformed. */
export function contractMetadata(contract: unknown, nativeTicker: string): ContractMetadata | null {
  if (!isPlainRecord(contract)) return null;
  const { name, ticker, precision } = contract;
  if (typeof name !== "string" || name.trim().length === 0 || name.length > 64 || UNSAFE_TEXT.test(name)) return null;
  if (typeof ticker !== "string" || !/^[A-Za-z0-9.-]{3,24}$/u.test(ticker)) return null;
  if (typeof precision !== "number" || !Number.isSafeInteger(precision) || precision < 0 || precision > 8) return null;
  // Anyone can issue a token called "ECX"; never let one impersonate the native asset.
  if (ticker.toUpperCase() === nativeTicker.toUpperCase()) return null;
  return { name: name.trim(), ticker, precision };
}

export class TokenRegistry {
  readonly #deps: TokenRegistryDependencies;
  readonly #now: () => number;
  readonly #inflight = new Map<string, Promise<CachedEntry>>();

  constructor(dependencies: TokenRegistryDependencies) {
    this.#deps = dependencies;
    this.#now = dependencies.now ?? Date.now;
  }

  native(): TokenInfo {
    const { assetId, name, ticker } = this.#deps.nativeAsset;
    return Object.freeze({ assetId, name, ticker, precision: 8, verified: true, native: true, tokenFor: null });
  }

  /** Cached metadata only (no network). */
  async cached(assetIds: readonly string[]): Promise<Record<string, TokenInfo>> {
    const cache = await this.#readCache(await this.#deps.endpoints());
    const result: Record<string, TokenInfo> = {};
    for (const assetId of assetIds) result[assetId] = this.#toInfo(assetId, cache.entries[assetId]);
    return result;
  }

  /** Resolve metadata, verifying new registry entries. Never throws for per-asset failures. */
  async lookup(assetIds: readonly string[]): Promise<Record<string, TokenInfo>> {
    const endpoints = await this.#deps.endpoints();
    const cache = await this.#readCache(endpoints);
    const result: Record<string, TokenInfo> = {};
    const entries = { ...cache.entries };
    let changed = false;
    for (const assetId of new Set(assetIds)) {
      if (!HEX_32.test(assetId)) continue;
      if (assetId === this.#deps.nativeAsset.assetId) {
        result[assetId] = this.native();
        continue;
      }
      let entry = entries[assetId];
      const stale = entry === undefined
        || (entry.status === "unverified" && this.#now() - entry.checkedAt > (entry.missing === true ? RETRY_MISSING_MS : RETRY_UNVERIFIED_MS));
      if (stale && endpoints.registryUrl !== "") {
        entry = await this.#resolve(assetId, endpoints);
        entries[assetId] = entry;
        changed = true;
      }
      result[assetId] = this.#toInfo(assetId, entry);
    }
    if (changed) await this.#writeCache(endpoints, entries);
    return result;
  }

  /**
   * Record an asset this wallet just issued. The core derived `assetId` (and
   * `tokenId`) from exactly this contract while building the transaction the
   * user approved, which is the same proof `verify_asset_issuance` gives for a
   * registry entry. Without this the new token stays "Unknown asset" until the
   * registry lists it and the next lookup runs.
   */
  async rememberIssued(issued: { readonly assetId: string; readonly tokenId: string | null; readonly contract: Record<string, unknown> }): Promise<void> {
    if (!HEX_32.test(issued.assetId) || (issued.tokenId !== null && !HEX_32.test(issued.tokenId))) return;
    const metadata = contractMetadata(issued.contract, this.#deps.nativeAsset.ticker);
    if (metadata === null) return;
    const endpoints = await this.#deps.endpoints();
    const cache = await this.#readCache(endpoints);
    const checkedAt = this.#now();
    const entries: Record<string, CachedEntry> = { ...cache.entries, [issued.assetId]: { status: "verified", ...metadata, tokenFor: null, checkedAt } };
    if (issued.tokenId !== null) {
      entries[issued.tokenId] = { status: "verified", name: `${metadata.name} reissuance token`, ticker: `${metadata.ticker}-RT`, precision: 0, tokenFor: issued.assetId, checkedAt };
    }
    await this.#writeCache(endpoints, entries);
  }

  async clear(): Promise<void> {
    await this.#deps.storage.remove(TOKEN_CACHE_KEY);
  }

  #toInfo(assetId: string, entry: CachedEntry | undefined): TokenInfo {
    if (assetId === this.#deps.nativeAsset.assetId) return this.native();
    if (entry?.status !== "verified" || entry.name === undefined || entry.ticker === undefined || entry.precision === undefined) {
      return unknownToken(assetId);
    }
    return Object.freeze({
      assetId,
      name: entry.name,
      ticker: entry.ticker,
      precision: entry.precision,
      verified: true,
      native: false,
      tokenFor: entry.tokenFor ?? null,
    });
  }

  #resolve(assetId: string, endpoints: { readonly registryUrl: string; readonly explorerUrl: string }): Promise<CachedEntry> {
    const key = `${endpoints.registryUrl}|${assetId}`;
    let pending = this.#inflight.get(key);
    if (pending === undefined) {
      pending = this.#verify(assetId, endpoints).finally(() => this.#inflight.delete(key));
      this.#inflight.set(key, pending);
    }
    return pending;
  }

  async #verify(assetId: string, endpoints: { readonly registryUrl: string; readonly explorerUrl: string }): Promise<CachedEntry> {
    const unverified: CachedEntry = Object.freeze({ status: "unverified", checkedAt: this.#now() });
    const missing: CachedEntry = Object.freeze({ status: "unverified", missing: true, checkedAt: this.#now() });
    let entry: unknown;
    try {
      entry = await fetchJson(`${endpoints.registryUrl}/${assetId}`, { fetchImpl: this.#deps.fetchImpl, maxBytes: 64 * 1024 });
    } catch {
      // Not registered (yet), registry unreachable or a bad response: retry soon.
      return missing;
    }
    try {
      if (!isPlainRecord(entry)) return unverified;
      const txid = entry["issuance_txid"];
      const vin = entry["issuance_vin"];
      const contract = entry["contract"];
      if (typeof txid !== "string" || !HEX_32.test(txid) || typeof vin !== "number" || !Number.isSafeInteger(vin) || vin < 0 || !isPlainRecord(contract)) {
        return unverified;
      }
      const metadata = contractMetadata(contract, this.#deps.nativeAsset.ticker);
      if (metadata === null) return unverified;
      let rawTxHex: string;
      try {
        rawTxHex = (await fetchText(`${esploraApiBase(endpoints.explorerUrl)}/tx/${txid}/hex`, {
          fetchImpl: this.#deps.fetchImpl,
          accept: "text/plain",
          maxBytes: 8 * 1024 * 1024 + 2,
        })).trim();
      } catch {
        // The explorer may not have the issuance yet.
        return missing;
      }
      if (!/^(?:[0-9a-f]{2})+$/u.test(rawTxHex)) return unverified;
      const verified = await this.#deps.verifyIssuance({ rawTxHex, expectedTxid: txid, vin, contract });
      if (verified.assetId === assetId) {
        return Object.freeze({ status: "verified", ...metadata, tokenFor: null, checkedAt: this.#now() });
      }
      if (verified.tokenId === assetId) {
        return Object.freeze({
          status: "verified",
          name: `${metadata.name} reissuance token`,
          ticker: `${metadata.ticker}-RT`,
          precision: 0,
          tokenFor: verified.assetId,
          checkedAt: this.#now(),
        });
      }
      return unverified;
    } catch (error) {
      // 404 from the registry or a verification failure: unknown asset.
      if (error instanceof HttpError || error instanceof Error) return unverified;
      return unverified;
    }
  }

  async #readCache(endpoints: { readonly registryUrl: string; readonly explorerUrl: string }): Promise<CacheRecord> {
    const stored = (await this.#deps.storage.get(TOKEN_CACHE_KEY))[TOKEN_CACHE_KEY];
    if (
      !isPlainRecord(stored)
      || stored["registryUrl"] !== endpoints.registryUrl
      || stored["explorerUrl"] !== endpoints.explorerUrl
      || !isPlainRecord(stored["entries"])
    ) return { ...endpoints, entries: {} };
    const entries: Record<string, CachedEntry> = {};
    for (const [assetId, raw] of Object.entries(stored["entries"])) {
      if (!HEX_32.test(assetId) || !isPlainRecord(raw) || typeof raw["checkedAt"] !== "number") continue;
      if (raw["status"] === "verified") {
        const { name, ticker, precision } = raw;
        if (
          typeof name !== "string" || name.length === 0 || name.length > 100 || UNSAFE_TEXT.test(name)
          || typeof ticker !== "string" || !/^[A-Za-z0-9.-]{3,27}$/u.test(ticker)
          || ticker.toUpperCase() === this.#deps.nativeAsset.ticker.toUpperCase()
          || typeof precision !== "number" || !Number.isSafeInteger(precision) || precision < 0 || precision > 8
        ) continue;
        entries[assetId] = {
          status: "verified",
          name,
          ticker,
          precision,
          tokenFor: typeof raw["tokenFor"] === "string" && HEX_32.test(raw["tokenFor"]) ? raw["tokenFor"] : null,
          checkedAt: raw["checkedAt"],
        };
      } else {
        entries[assetId] = { status: "unverified", ...(raw["missing"] === true ? { missing: true } : {}), checkedAt: raw["checkedAt"] };
      }
    }
    return { ...endpoints, entries };
  }

  async #writeCache(endpoints: { readonly registryUrl: string; readonly explorerUrl: string }, entries: Record<string, CachedEntry>): Promise<void> {
    const keys = Object.keys(entries);
    const bounded = keys.length > MAX_CACHE_ENTRIES
      ? Object.fromEntries(keys.slice(keys.length - MAX_CACHE_ENTRIES).map((key) => [key, entries[key]]))
      : entries;
    await this.#deps.storage.set({ [TOKEN_CACHE_KEY]: { ...endpoints, entries: bounded } });
  }
}
