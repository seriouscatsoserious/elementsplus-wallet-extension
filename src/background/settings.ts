import { ECX_ALPHA_IDENTITY } from "../network/identity.js";
import { normalizeEndpoint } from "../network/http.js";
import type { ExtensionStorageArea } from "../platform/browser.js";
import { hasExactKeys, isPlainRecord, ValidationError } from "../shared/validation.js";

export const SETTINGS_STORAGE_KEY = "elementsplus.settings.v1";
export const SITES_STORAGE_KEY = "elementsplus.sites.v1";
export const ACCOUNT_STORAGE_KEY = "elementsplus.account.v1";
export const AUTO_LOCK_CHOICES = Object.freeze([1, 5, 15, 30, 60] as const);
export const DEFAULT_AUTO_LOCK_MINUTES = 15;

export interface WalletSettings {
  readonly explorerUrl: string;
  /** Token registry base, e.g. `https://dex.example/api/assets`. Empty = disabled. */
  readonly registryUrl: string;
  /** DEX web app opened by the Swap button. Empty = not configured. */
  readonly dexUrl: string;
  readonly autoLockMinutes: number;
}

export function defaultSettings(): WalletSettings {
  const dexUrl = ECX_ALPHA_IDENTITY.dexUrl;
  return Object.freeze({
    explorerUrl: ECX_ALPHA_IDENTITY.explorerUrl,
    registryUrl: dexUrl === "" ? "" : `${dexUrl.replace(/\/+$/u, "")}/api/assets`,
    dexUrl,
    autoLockMinutes: DEFAULT_AUTO_LOCK_MINUTES,
  });
}

function optionalEndpoint(value: unknown, label: string): string {
  if (value === "") return "";
  if (typeof value !== "string" || value.length > 512) throw new ValidationError(`${label} is malformed`);
  try {
    return normalizeEndpoint(value, label);
  } catch (error) {
    throw new ValidationError(error instanceof Error ? error.message : `${label} is invalid`);
  }
}

export function validateSettingsPatch(value: unknown): Partial<WalletSettings> {
  if (!isPlainRecord(value) || !hasExactKeys(value, [], ["explorerUrl", "registryUrl", "dexUrl", "autoLockMinutes"])) {
    throw new ValidationError("settings update contains unexpected fields");
  }
  const patch: { -readonly [K in keyof WalletSettings]?: WalletSettings[K] } = {};
  if (value["explorerUrl"] !== undefined) {
    const url = optionalEndpoint(value["explorerUrl"], "Explorer URL");
    if (url === "") throw new ValidationError("Explorer URL is required");
    patch.explorerUrl = url;
  }
  if (value["registryUrl"] !== undefined) patch.registryUrl = optionalEndpoint(value["registryUrl"], "Token list URL");
  if (value["dexUrl"] !== undefined) patch.dexUrl = optionalEndpoint(value["dexUrl"], "DEX URL");
  if (value["autoLockMinutes"] !== undefined) {
    if (!(AUTO_LOCK_CHOICES as readonly unknown[]).includes(value["autoLockMinutes"])) {
      throw new ValidationError("auto-lock timer is not one of the offered choices");
    }
    patch.autoLockMinutes = value["autoLockMinutes"] as number;
  }
  return patch;
}

export class SettingsStore {
  #cache: WalletSettings | undefined;

  constructor(private readonly storage: ExtensionStorageArea) {}

  async get(): Promise<WalletSettings> {
    if (this.#cache !== undefined) return this.#cache;
    const stored = (await this.storage.get(SETTINGS_STORAGE_KEY))[SETTINGS_STORAGE_KEY];
    let merged = defaultSettings();
    if (stored !== undefined) {
      try {
        merged = Object.freeze({ ...merged, ...validateSettingsPatch(stored) });
      } catch {
        // Corrupt settings fall back to the reviewed defaults.
      }
    }
    this.#cache = merged;
    return merged;
  }

  async update(rawPatch: unknown): Promise<WalletSettings> {
    const patch = validateSettingsPatch(rawPatch);
    const next = Object.freeze({ ...(await this.get()), ...patch });
    const defaults = defaultSettings();
    const toStore: Record<string, unknown> = {};
    for (const key of Object.keys(next) as (keyof WalletSettings)[]) {
      if (next[key] !== defaults[key]) toStore[key] = next[key];
    }
    await this.storage.set({ [SETTINGS_STORAGE_KEY]: toStore });
    this.#cache = next;
    return next;
  }

  async reset(): Promise<WalletSettings> {
    await this.storage.remove(SETTINGS_STORAGE_KEY);
    this.#cache = undefined;
    return this.get();
  }
}

export interface ConnectedSite {
  readonly origin: string;
  readonly connectedAt: string;
}

export function validateOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 300) throw new ValidationError("origin is malformed");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ValidationError("origin is malformed");
  }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== value) {
    throw new ValidationError("origin must be an http(s) origin");
  }
  return value;
}

/** Per-origin dApp connection permissions (spec §3.3). */
export class SitePermissions {
  constructor(private readonly storage: ExtensionStorageArea) {}

  async #read(): Promise<Record<string, ConnectedSite>> {
    const stored = (await this.storage.get(SITES_STORAGE_KEY))[SITES_STORAGE_KEY];
    if (!isPlainRecord(stored)) return {};
    const result: Record<string, ConnectedSite> = {};
    for (const [origin, entry] of Object.entries(stored)) {
      if (isPlainRecord(entry) && typeof entry["connectedAt"] === "string") {
        try {
          result[validateOrigin(origin)] = Object.freeze({ origin, connectedAt: entry["connectedAt"] });
        } catch {
          // Drop malformed entries.
        }
      }
    }
    return result;
  }

  async list(): Promise<ConnectedSite[]> {
    return Object.values(await this.#read()).sort((a, b) => b.connectedAt.localeCompare(a.connectedAt));
  }

  async has(origin: string): Promise<boolean> {
    return Object.hasOwn(await this.#read(), origin);
  }

  async grant(origin: string, now: Date): Promise<void> {
    const sites = await this.#read();
    sites[validateOrigin(origin)] = { origin, connectedAt: now.toISOString() };
    await this.storage.set({ [SITES_STORAGE_KEY]: sites });
  }

  async revoke(origin: string): Promise<boolean> {
    const sites = await this.#read();
    if (!Object.hasOwn(sites, origin)) return false;
    delete sites[origin];
    await this.storage.set({ [SITES_STORAGE_KEY]: sites });
    return true;
  }
}
