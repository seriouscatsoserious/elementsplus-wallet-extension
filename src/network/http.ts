import type { FetchImplementation } from "./esplora.js";

export class HttpError extends Error {
  override readonly name = "HttpError";
  constructor(message: string, readonly status: number | null = null) {
    super(message);
  }
}

export interface FetchOptions {
  readonly fetchImpl: FetchImplementation;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly method?: "GET" | "POST";
  readonly body?: string;
  readonly accept?: string;
  readonly contentType?: string;
}

async function readBounded(response: Response, maxBytes: number): Promise<string> {
  const length = response.headers.get("Content-Length");
  if (length !== null && (!/^[0-9]+$/u.test(length) || Number(length) > maxBytes)) throw new HttpError("response is too large");
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("response too large");
        throw new HttpError("response is too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new HttpError("response is not UTF-8");
  }
}

/** Fetch text with a timeout, a byte cap, no credentials and no redirects. */
export async function fetchText(url: URL | string, options: FetchOptions): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  try {
    const headers: Record<string, string> = { Accept: options.accept ?? "application/json" };
    if (options.contentType !== undefined) headers["Content-Type"] = options.contentType;
    const init: RequestInit = {
      method: options.method ?? "GET",
      headers,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal: controller.signal,
    };
    if (options.body !== undefined) init.body = options.body;
    const response = await options.fetchImpl(url, init);
    const text = await readBounded(response, options.maxBytes ?? 1024 * 1024);
    if (!response.ok) throw new HttpError(`request failed (${response.status})`, response.status);
    return text;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    if (controller.signal.aborted) throw new HttpError("request timed out");
    throw new HttpError("network request failed");
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchJson(url: URL | string, options: FetchOptions): Promise<unknown> {
  const text = await fetchText(url, options);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpError("response is not JSON");
  }
}

/**
 * Validate a user-configured endpoint. HTTPS everywhere; plain HTTP only for
 * loopback development servers. No credentials, query or fragment.
 */
export function normalizeEndpoint(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new TypeError(`${label} is not a valid URL`);
  }
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new TypeError(`${label} must use HTTPS (HTTP is allowed only on localhost)`);
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "") {
    throw new TypeError(`${label} must not contain credentials, a query or a fragment`);
  }
  return parsed.toString().replace(/\/+$/u, "");
}

/** Esplora REST base (`…/api`) for an explorer URL. */
export function esploraApiBase(explorerUrl: string): string {
  const parsed = new URL(explorerUrl);
  let pathname = parsed.pathname.replace(/\/+$/u, "");
  if (!pathname.endsWith("/api")) pathname += "/api";
  parsed.pathname = pathname;
  return parsed.toString().replace(/\/$/u, "");
}
