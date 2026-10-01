import type { TokenInfo } from "../../background/token-registry.js";
import { formatAtomic } from "../../shared/amount.js";
import { h } from "./dom.js";
import type { Tokens } from "./backend.js";

const PALETTE = 6;

export function tokenFor(tokens: Tokens, assetId: string): TokenInfo {
  return tokens[assetId] ?? { assetId, name: "Unknown asset", ticker: "", precision: 0, verified: false, native: false, tokenFor: null };
}

export function shortId(value: string, head = 6, tail = 4): string {
  return value.length <= head + tail + 1 ? value : `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function shortAddress(address: string): string {
  const separator = address.indexOf("1");
  const prefix = separator > 0 ? separator + 4 : 8;
  return shortId(address, prefix, 5);
}

/** Display symbol: verified ticker, else a truncated asset id. */
export function symbol(token: TokenInfo): string {
  return token.verified && token.ticker !== "" ? token.ticker : shortId(token.assetId, 6, 4);
}

export function displayName(token: TokenInfo): string {
  return token.verified ? token.name : "Unknown asset";
}

export function amount(value: bigint | string, token: TokenInfo, options: { signed?: boolean; minFraction?: number } = {}): string {
  const minFraction = options.minFraction ?? (token.native ? 2 : 0);
  return formatAtomic(value, token.precision, { minFraction, signed: options.signed ?? false });
}

export function amountWithSymbol(value: bigint | string, token: TokenInfo, options: { signed?: boolean; minFraction?: number } = {}): string {
  return `${amount(value, token, options)} ${symbol(token)}`;
}

function paletteIndex(assetId: string): number {
  let hash = 0;
  for (let index = 0; index < 8; index += 1) hash = (hash * 31 + assetId.charCodeAt(index)) >>> 0;
  return hash % PALETTE;
}

/** Circular token avatar (class-based colours; no inline styles under the CSP). */
export function avatar(token: TokenInfo, size: "" | "sm" | "lg" = ""): HTMLElement {
  if (token.native) return h("span", { class: `tk native ${size}`, "aria-hidden": "true" }, "ECX");
  if (!token.verified) return h("span", { class: `tk unknown ${size}`, "aria-hidden": "true" }, "?");
  const letters = token.ticker.replace(/[^A-Za-z0-9]/gu, "").slice(0, 2).toUpperCase() || "?";
  return h("span", { class: `tk c${paletteIndex(token.assetId)} ${size}`, "aria-hidden": "true" }, letters);
}

export function unverifiedTag(token: TokenInfo): HTMLElement | null {
  return token.verified ? null : h("span", { class: "tag" }, "UNVERIFIED");
}

export function dayLabel(seconds: number, now = new Date()): string {
  const date = new Date(seconds * 1000);
  const startOfDay = (value: Date) => new Date(value.getFullYear(), value.getMonth(), value.getDate()).getTime();
  const days = Math.round((startOfDay(now) - startOfDay(date)) / 86_400_000);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  return date.toLocaleDateString("en-US", { month: "short", day: "numeric", ...(date.getFullYear() !== now.getFullYear() ? { year: "numeric" } : {}) });
}

export function explorerTxUrl(explorerUrl: string, txid: string): string {
  return `${explorerUrl.replace(/\/+$/u, "").replace(/\/api$/u, "")}/tx/${txid}`;
}
