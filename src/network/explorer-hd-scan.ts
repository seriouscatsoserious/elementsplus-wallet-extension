import {
  EcxAlphaAddressError,
  type FetchImplementation,
  resolveEcxAlphaAddress,
} from "./ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "./identity.js";
import { isPlainRecord } from "../shared/validation.js";

export const EXPLORER_HD_CHAINS = Object.freeze(["external", "change"] as const);

export type ExplorerHdChain = (typeof EXPLORER_HD_CHAINS)[number];

export interface ExplorerHdDerivationRequest {
  readonly chain: ExplorerHdChain;
  readonly index: number;
}

/** Public-only material returned by the wallet engine for one HD index. */
export interface ExplorerHdDerivedAddress {
  readonly chain: ExplorerHdChain;
  readonly index: number;
  readonly address: string;
  readonly scriptPubKeyHex: string;
}

export type ExplorerHdAddressDeriver = (
  request: ExplorerHdDerivationRequest,
) => ExplorerHdDerivedAddress | Promise<ExplorerHdDerivedAddress>;

export interface ExplorerHdExpectedOutput {
  readonly chain: ExplorerHdChain;
  readonly index: number;
  readonly address: string;
  readonly scriptPubKeyHex: string;
  readonly vout: number;
}

export interface ExplorerHdRawTransactionVerificationRequest {
  readonly expectedTxid: string;
  readonly rawTransactionHex: string;
  readonly expectedWalletOutputs: readonly ExplorerHdExpectedOutput[];
}

/**
 * Authenticated output data produced by the caller's local transaction parser.
 * The callback must compute `txid` from the supplied bytes, not echo the request.
 */
export interface ExplorerHdVerifiedOutput {
  readonly vout: number;
  readonly scriptPubKeyHex: string;
  readonly assetId: string;
  readonly valueAtomic: string;
}

export interface ExplorerHdVerifiedTransaction {
  readonly txid: string;
  readonly outputs: readonly ExplorerHdVerifiedOutput[];
}

export type ExplorerHdRawTransactionVerifier = (
  request: ExplorerHdRawTransactionVerificationRequest,
) => ExplorerHdVerifiedTransaction | Promise<ExplorerHdVerifiedTransaction>;

export interface ExplorerHdScanOptions {
  readonly explorerUrl?: string;
  readonly fetchImpl?: FetchImplementation;
  readonly requestTimeoutMs?: number;
  readonly gapLimit?: number;
  /** Inclusive, unhardened derivation-index ceiling. */
  readonly maximumIndex?: number;
  /** Number of indexes scheduled per discovery page. */
  readonly pageSize?: number;
  /** Global bound for address scans and transaction verification. */
  readonly concurrency?: number;
}

export interface ExplorerHdAddressStats {
  readonly fundedOutputCount: number;
  readonly spentOutputCount: number;
  readonly transactionCount: number;
}

export interface ExplorerHdConfirmationStatus {
  readonly confirmed: boolean;
  readonly blockHeight?: number;
  readonly blockHash?: string;
  readonly blockTime?: number;
}

export interface ExplorerHdScannedAddress extends ExplorerHdDerivedAddress {
  readonly used: boolean;
  readonly chainStats: ExplorerHdAddressStats;
  readonly mempoolStats: ExplorerHdAddressStats;
}

export interface ExplorerHdVerifiedUtxo extends ExplorerHdExpectedOutput {
  readonly txid: string;
  readonly assetId: string;
  readonly valueAtomic: string;
  readonly status: ExplorerHdConfirmationStatus;
}

export interface ExplorerHdFundingTransaction {
  readonly txid: string;
  readonly rawTransactionHex: string;
  readonly outputs: readonly ExplorerHdVerifiedOutput[];
}

export interface ExplorerHdChainScan {
  readonly chain: ExplorerHdChain;
  readonly lastScannedIndex: number;
  readonly highestUsedIndex: number | null;
  readonly nextUnusedIndex: number;
  readonly trailingUnused: number;
  readonly pagesScanned: number;
}

export interface ExplorerHdTip {
  readonly height: number;
  readonly hash: string;
}

/**
 * Deterministically ordered input for a wallet snapshot.
 *
 * `headerChainVerified` is deliberately false: matching immutable identity pins,
 * validating transaction bytes locally, and asking Esplora for a tip do not prove
 * header continuity or consensus validity.
 */
export interface ExplorerHdSnapshotInput {
  readonly source: {
    readonly kind: "esplora";
    readonly explorerApiUrl: string;
    readonly genesisHash: string;
    readonly nativeAssetId: string;
    readonly identityPinsMatched: true;
    readonly headerChainVerified: false;
  };
  readonly tip: ExplorerHdTip;
  readonly scan: {
    readonly gapLimit: number;
    readonly maximumIndex: number;
    readonly pageSize: number;
    readonly chains: readonly ExplorerHdChainScan[];
  };
  readonly addresses: readonly ExplorerHdScannedAddress[];
  readonly utxos: readonly ExplorerHdVerifiedUtxo[];
  readonly fundingTransactions: readonly ExplorerHdFundingTransaction[];
}

export class ExplorerHdScanError extends Error {
  override readonly name = "ExplorerHdScanError";
  readonly status: number | null;

  constructor(message: string, status: number | null = null, options?: ErrorOptions) {
    super(message, options);
    this.status = status;
  }
}

const HEX_32_BYTES = /^[0-9a-f]{64}$/u;
const EVEN_LOWER_HEX = /^(?:[0-9a-f]{2})+$/u;
const CANONICAL_ATOMIC_AMOUNT = /^(?:0|[1-9][0-9]*)$/u;
const MAX_U64 = 18_446_744_073_709_551_615n;
const MAX_ADDRESS_RESPONSE_BYTES = 1024 * 1024;
const MAX_RAW_TRANSACTION_BYTES = 4 * 1024 * 1024;
const MAX_RAW_TRANSACTION_TEXT_BYTES = MAX_RAW_TRANSACTION_BYTES * 2 + 2;
const MAX_UTXOS_PER_ADDRESS = 100_000;
const MAX_VERIFIED_OUTPUTS = 100_000;
const MAXIMUM_INDEX_LIMIT = 0x7fff_ffff;
const MAX_GAP_LIMIT = 10_000;
const MAX_PAGE_SIZE = 256;
const MAX_CONCURRENCY = 32;

interface RawExplorerUtxo {
  readonly txid: string;
  readonly vout: number;
  readonly status: ExplorerHdConfirmationStatus;
  readonly explorerAssetId?: string;
  readonly explorerValueAtomic?: string;
}

interface AddressScanResult {
  readonly address: ExplorerHdScannedAddress;
  readonly utxos: readonly RawExplorerUtxo[];
}

interface MutableUtxoReference extends RawExplorerUtxo, ExplorerHdExpectedOutput {}

function explorerApiUrl(explorerUrl: string): string {
  const parsed = new URL(explorerUrl);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new TypeError("explorer URL must use HTTP(S)");
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new TypeError("explorer URL must not contain credentials");
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    throw new TypeError("explorer URL must not contain a query or fragment");
  }
  let pathname = parsed.pathname.replace(/\/+$/u, "");
  if (!pathname.endsWith("/api")) pathname += "/api";
  parsed.pathname = pathname;
  return parsed.toString().replace(/\/$/u, "");
}

function positiveIntegerOption(
  value: number,
  label: string,
  maximum: number,
): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new TypeError(`${label} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
    || value > maximum
  ) {
    throw new ExplorerHdScanError(`${label} is not an in-range non-negative integer`);
  }
  return value;
}

function lowercaseHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX_32_BYTES.test(value)) {
    throw new ExplorerHdScanError(`${label} is not a 32-byte lowercase hex value`);
  }
  return value;
}

function atomicAmount(value: unknown, label: string): string {
  let amount: string;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new ExplorerHdScanError(`${label} is not a safe non-negative integer`);
    }
    amount = String(value);
  } else if (typeof value === "string" && CANONICAL_ATOMIC_AMOUNT.test(value)) {
    amount = value;
  } else {
    throw new ExplorerHdScanError(`${label} is not a canonical atomic amount`);
  }
  if (BigInt(amount) > MAX_U64) {
    throw new ExplorerHdScanError(`${label} exceeds uint64`);
  }
  return amount;
}

function scriptHex(value: unknown, label: string): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 20_000
    || !EVEN_LOWER_HEX.test(value)
  ) {
    throw new ExplorerHdScanError(`${label} is not bounded lowercase byte hex`);
  }
  return value;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainRecord(value)) throw new ExplorerHdScanError(`${label} is not an object`);
  return value;
}

function stats(value: unknown, label: string): ExplorerHdAddressStats {
  const data = asRecord(value, label);
  const fundedOutputCount = nonNegativeInteger(
    data["funded_txo_count"],
    `${label}.funded_txo_count`,
  );
  const spentOutputCount = nonNegativeInteger(
    data["spent_txo_count"],
    `${label}.spent_txo_count`,
  );
  const transactionCount = nonNegativeInteger(data["tx_count"], `${label}.tx_count`);
  return Object.freeze({
    fundedOutputCount,
    spentOutputCount,
    transactionCount,
  });
}

function hasActivity(value: ExplorerHdAddressStats): boolean {
  return value.fundedOutputCount !== 0
    || value.spentOutputCount !== 0
    || value.transactionCount !== 0;
}

function confirmationStatus(value: unknown, label: string): ExplorerHdConfirmationStatus {
  const data = asRecord(value, label);
  if (typeof data["confirmed"] !== "boolean") {
    throw new ExplorerHdScanError(`${label}.confirmed is not a boolean`);
  }
  if (!data["confirmed"]) {
    if (
      data["block_height"] !== undefined
      || data["block_hash"] !== undefined
      || data["block_time"] !== undefined
    ) {
      throw new ExplorerHdScanError(`${label} has block metadata for an unconfirmed output`);
    }
    return Object.freeze({ confirmed: false });
  }
  return Object.freeze({
    confirmed: true,
    blockHeight: nonNegativeInteger(data["block_height"], `${label}.block_height`),
    blockHash: lowercaseHash(data["block_hash"], `${label}.block_hash`),
    blockTime: nonNegativeInteger(data["block_time"], `${label}.block_time`),
  });
}

function parseDerivedAddress(
  value: unknown,
  request: ExplorerHdDerivationRequest,
): ExplorerHdDerivedAddress {
  const data = asRecord(value, `derived ${request.chain} address ${request.index}`);
  if (data["chain"] !== request.chain || data["index"] !== request.index) {
    throw new ExplorerHdScanError("address deriver returned a different chain or index");
  }
  const rawAddress = data["address"];
  if (typeof rawAddress !== "string" || rawAddress !== rawAddress.trim()) {
    throw new ExplorerHdScanError("address deriver returned a malformed address");
  }
  let address: string;
  try {
    address = resolveEcxAlphaAddress(rawAddress).canonical;
  } catch (error) {
    if (error instanceof EcxAlphaAddressError) {
      throw new ExplorerHdScanError("address deriver returned a non-ECX address", null, {
        cause: error,
      });
    }
    throw error;
  }
  return Object.freeze({
    chain: request.chain,
    index: request.index,
    address,
    scriptPubKeyHex: scriptHex(
      data["scriptPubKeyHex"],
      `derived ${request.chain} address ${request.index}.scriptPubKeyHex`,
    ),
  });
}

function parseUtxos(value: unknown, label: string): readonly RawExplorerUtxo[] {
  if (!Array.isArray(value)) throw new ExplorerHdScanError(`${label} is not an array`);
  if (value.length > MAX_UTXOS_PER_ADDRESS) {
    throw new ExplorerHdScanError(`${label} exceeds the UTXO-count limit`);
  }
  const outpoints = new Set<string>();
  return Object.freeze(value.map((entry, index) => {
    const data = asRecord(entry, `${label}[${index}]`);
    const txid = lowercaseHash(data["txid"], `${label}[${index}].txid`);
    const vout = nonNegativeInteger(data["vout"], `${label}[${index}].vout`, 0xffff_ffff);
    const outpoint = `${txid}:${vout}`;
    if (outpoints.has(outpoint)) {
      throw new ExplorerHdScanError(`${label} contains a duplicate outpoint`);
    }
    outpoints.add(outpoint);

    const hasValue = data["value"] !== undefined && data["value"] !== null;
    const hasAsset = data["asset"] !== undefined && data["asset"] !== null;
    if (hasValue !== hasAsset) {
      throw new ExplorerHdScanError(`${label}[${index}] has incomplete explicit output data`);
    }
    return Object.freeze({
      txid,
      vout,
      status: confirmationStatus(data["status"], `${label}[${index}].status`),
      ...(hasAsset
        ? {
          explorerAssetId: lowercaseHash(data["asset"], `${label}[${index}].asset`),
          explorerValueAtomic: atomicAmount(data["value"], `${label}[${index}].value`),
        }
        : {}),
    });
  }));
}

function parseVerifiedTransaction(
  value: unknown,
  expectedTxid: string,
): ExplorerHdVerifiedTransaction {
  const data = asRecord(value, `verification for ${expectedTxid}`);
  const txid = lowercaseHash(data["txid"], "verified transaction.txid");
  if (txid !== expectedTxid) {
    throw new ExplorerHdScanError("raw transaction verifier returned the wrong txid");
  }
  const rawOutputs = data["outputs"];
  if (!Array.isArray(rawOutputs) || rawOutputs.length > MAX_VERIFIED_OUTPUTS) {
    throw new ExplorerHdScanError("raw transaction verifier returned an invalid output list");
  }
  const seenVouts = new Set<number>();
  const outputs = rawOutputs.map((entry, index) => {
    const output = asRecord(entry, `verified transaction.outputs[${index}]`);
    const vout = nonNegativeInteger(
      output["vout"],
      `verified transaction.outputs[${index}].vout`,
      0xffff_ffff,
    );
    if (seenVouts.has(vout)) {
      throw new ExplorerHdScanError("raw transaction verifier returned duplicate output indexes");
    }
    seenVouts.add(vout);
    return Object.freeze({
      vout,
      scriptPubKeyHex: scriptHex(
        output["scriptPubKeyHex"],
        `verified transaction.outputs[${index}].scriptPubKeyHex`,
      ),
      assetId: lowercaseHash(output["assetId"], `verified transaction.outputs[${index}].assetId`),
      valueAtomic: atomicAmount(
        output["valueAtomic"],
        `verified transaction.outputs[${index}].valueAtomic`,
      ),
    });
  });
  outputs.sort((left, right) => left.vout - right.vout);
  return Object.freeze({ txid, outputs: Object.freeze(outputs) });
}

class WorkPool {
  private active = 0;
  private readonly queue: (() => void)[] = [];

  constructor(private readonly limit: number) {}

  async run<T>(operation: () => Promise<T>): Promise<T> {
    if (this.active >= this.limit) {
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active += 1;
    try {
      return await operation();
    } finally {
      this.active -= 1;
      this.queue.shift()?.();
    }
  }
}

async function boundedResponseText(response: Response, maximumBytes: number): Promise<string> {
  const contentLength = response.headers.get("Content-Length");
  if (contentLength !== null) {
    if (!/^[0-9]+$/u.test(contentLength) || Number(contentLength) > maximumBytes) {
      throw new ExplorerHdScanError("explorer returned an invalid or oversized Content-Length");
    }
  }
  if (response.body === null) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteLength += value.byteLength;
      if (byteLength > maximumBytes) {
        await reader.cancel("response too large");
        throw new ExplorerHdScanError("explorer response exceeds its byte limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch (error) {
    throw new ExplorerHdScanError("explorer returned invalid UTF-8", null, { cause: error });
  }
}

/** Explorer-backed HD discovery with local raw-transaction verification. */
export class ExplorerHdScanner {
  readonly explorerApiUrl: string;
  readonly requestTimeoutMs: number;
  readonly gapLimit: number;
  readonly maximumIndex: number;
  readonly pageSize: number;
  readonly concurrency: number;

  private readonly fetchImpl: FetchImplementation;
  private readonly deriveAddress: ExplorerHdAddressDeriver;
  private readonly verifyRawTransaction: ExplorerHdRawTransactionVerifier;
  private readonly pool: WorkPool;

  constructor(
    deriveAddress: ExplorerHdAddressDeriver,
    verifyRawTransaction: ExplorerHdRawTransactionVerifier,
    options: ExplorerHdScanOptions = {},
  ) {
    this.explorerApiUrl = explorerApiUrl(options.explorerUrl ?? ECX_ALPHA_IDENTITY.explorerUrl);
    this.requestTimeoutMs = positiveIntegerOption(
      options.requestTimeoutMs ?? 10_000,
      "request timeout",
      300_000,
    );
    this.gapLimit = positiveIntegerOption(options.gapLimit ?? 20, "gap limit", MAX_GAP_LIMIT);
    const maximumIndex = options.maximumIndex ?? 999;
    if (
      !Number.isSafeInteger(maximumIndex)
      || maximumIndex < 0
      || maximumIndex > MAXIMUM_INDEX_LIMIT
    ) {
      throw new TypeError(
        `maximum index must be an integer between 0 and ${MAXIMUM_INDEX_LIMIT}`,
      );
    }
    this.maximumIndex = maximumIndex;
    this.pageSize = positiveIntegerOption(options.pageSize ?? 20, "page size", MAX_PAGE_SIZE);
    this.concurrency = positiveIntegerOption(
      options.concurrency ?? 4,
      "concurrency",
      MAX_CONCURRENCY,
    );
    if (typeof deriveAddress !== "function" || typeof verifyRawTransaction !== "function") {
      throw new TypeError("address deriver and raw transaction verifier are required");
    }
    const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (fetchImpl === undefined) throw new TypeError("Fetch API is unavailable");
    this.fetchImpl = fetchImpl;
    this.deriveAddress = deriveAddress;
    this.verifyRawTransaction = verifyRawTransaction;
    this.pool = new WorkPool(this.concurrency);
  }

  private async getText(
    path: string,
    maximumBytes: number,
    outerSignal: AbortSignal,
  ): Promise<string> {
    if (outerSignal.aborted) throw new ExplorerHdScanError("HD scan was aborted");
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    outerSignal.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      const response = await this.fetchImpl(`${this.explorerApiUrl}${path}`, {
        method: "GET",
        headers: { Accept: "text/plain, application/json" },
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new ExplorerHdScanError(`explorer request failed (${response.status})`, response.status);
      }
      return await boundedResponseText(response, maximumBytes);
    } catch (error) {
      if (error instanceof ExplorerHdScanError) throw error;
      if (controller.signal.aborted) {
        throw new ExplorerHdScanError(
          outerSignal.aborted ? "HD scan was aborted" : "explorer request timed out",
          null,
          { cause: error },
        );
      }
      throw new ExplorerHdScanError("explorer request failed", null, { cause: error });
    } finally {
      clearTimeout(timeout);
      outerSignal.removeEventListener("abort", abort);
    }
  }

  private async getJson(path: string, signal: AbortSignal): Promise<unknown> {
    const body = await this.getText(path, MAX_ADDRESS_RESPONSE_BYTES, signal);
    try {
      return JSON.parse(body) as unknown;
    } catch (error) {
      throw new ExplorerHdScanError("explorer returned invalid JSON", null, { cause: error });
    }
  }

  private async verifyIdentityPins(signal: AbortSignal): Promise<void> {
    const genesis = await this.getText("/block-height/0", 256, signal);
    const assetValue = await this.getJson(`/asset/${ECX_ALPHA_IDENTITY.nativeAssetId}`, signal);
    if (genesis.trim() !== ECX_ALPHA_IDENTITY.genesisHash) {
      throw new ExplorerHdScanError("explorer does not match the pinned ECX genesis");
    }
    const asset = asRecord(assetValue, "policy asset");
    if (asset["asset_id"] !== ECX_ALPHA_IDENTITY.nativeAssetId) {
      throw new ExplorerHdScanError("explorer does not match the pinned ECX native asset");
    }
  }

  private async scanAddress(
    chain: ExplorerHdChain,
    index: number,
    signal: AbortSignal,
  ): Promise<AddressScanResult> {
    if (signal.aborted) throw new ExplorerHdScanError("HD scan was aborted");
    const derived = parseDerivedAddress(
      await this.deriveAddress(Object.freeze({ chain, index })),
      { chain, index },
    );
    const path = `/address/${encodeURIComponent(derived.address)}`;
    const summaryValue = await this.getJson(path, signal);
    const summary = asRecord(summaryValue, `${chain} address ${index}`);
    if (summary["address"] !== undefined) {
      if (typeof summary["address"] !== "string") {
        throw new ExplorerHdScanError("explorer returned a malformed address echo");
      }
      let echoedAddress: string;
      try {
        echoedAddress = resolveEcxAlphaAddress(summary["address"]).canonical;
      } catch (error) {
        throw new ExplorerHdScanError("explorer returned an invalid address echo", null, {
          cause: error,
        });
      }
      if (echoedAddress !== derived.address) {
        throw new ExplorerHdScanError("explorer returned statistics for a different address");
      }
    }
    const chainStats = stats(summary["chain_stats"], `${chain} address ${index}.chain_stats`);
    const mempoolStats = stats(
      summary["mempool_stats"],
      `${chain} address ${index}.mempool_stats`,
    );
    const utxos = parseUtxos(
      await this.getJson(`${path}/utxo`, signal),
      `${chain} address ${index}.utxos`,
    );
    const expectedUtxoCount = chainStats.fundedOutputCount
      + mempoolStats.fundedOutputCount
      - chainStats.spentOutputCount
      - mempoolStats.spentOutputCount;
    if (
      expectedUtxoCount < 0
      || expectedUtxoCount !== utxos.length
    ) {
      throw new ExplorerHdScanError(
        `${chain} address ${index} has inconsistent statistics and UTXOs`,
      );
    }
    const used = hasActivity(chainStats) || hasActivity(mempoolStats);
    if (!used && utxos.length !== 0) {
      throw new ExplorerHdScanError(`${chain} address ${index} has UTXOs but no activity`);
    }
    return Object.freeze({
      address: Object.freeze({ ...derived, used, chainStats, mempoolStats }),
      utxos,
    });
  }

  private async scanChain(
    chain: ExplorerHdChain,
    signal: AbortSignal,
  ): Promise<{
    readonly state: ExplorerHdChainScan;
    readonly addresses: readonly ExplorerHdScannedAddress[];
    readonly utxos: readonly MutableUtxoReference[];
  }> {
    const addresses: ExplorerHdScannedAddress[] = [];
    const utxos: MutableUtxoReference[] = [];
    let index = 0;
    let trailingUnused = 0;
    let highestUsedIndex: number | null = null;
    let pagesScanned = 0;

    while (trailingUnused < this.gapLimit) {
      if (index > this.maximumIndex) {
        throw new ExplorerHdScanError(
          `${chain} scan reached maximum index before satisfying the gap limit`,
        );
      }
      const end = Math.min(index + this.pageSize - 1, this.maximumIndex);
      const indexes = Array.from({ length: end - index + 1 }, (_, offset) => index + offset);
      pagesScanned += 1;
      const page = await Promise.all(indexes.map((candidateIndex) =>
        this.pool.run(async () => await this.scanAddress(chain, candidateIndex, signal)),
      ));

      for (const result of page) {
        addresses.push(result.address);
        for (const utxo of result.utxos) {
          utxos.push(Object.freeze({
            ...utxo,
            chain,
            index: result.address.index,
            address: result.address.address,
            scriptPubKeyHex: result.address.scriptPubKeyHex,
          }));
        }
        if (result.address.used) {
          highestUsedIndex = result.address.index;
          trailingUnused = 0;
        } else {
          trailingUnused += 1;
        }
        index = result.address.index + 1;
        if (trailingUnused >= this.gapLimit) break;
      }
    }

    const nextUnusedIndex = highestUsedIndex === null ? 0 : highestUsedIndex + 1;
    return Object.freeze({
      state: Object.freeze({
        chain,
        lastScannedIndex: index - 1,
        highestUsedIndex,
        nextUnusedIndex,
        trailingUnused,
        pagesScanned,
      }),
      addresses: Object.freeze(addresses),
      utxos: Object.freeze(utxos),
    });
  }

  private async verifyFundingTransactions(
    references: readonly MutableUtxoReference[],
    signal: AbortSignal,
  ): Promise<{
    readonly transactions: readonly ExplorerHdFundingTransaction[];
    readonly utxos: readonly ExplorerHdVerifiedUtxo[];
  }> {
    const byTxid = new Map<string, MutableUtxoReference[]>();
    const seenOutpoints = new Set<string>();
    for (const reference of references) {
      const outpoint = `${reference.txid}:${reference.vout}`;
      if (seenOutpoints.has(outpoint)) {
        throw new ExplorerHdScanError("explorer returned one outpoint for multiple wallet addresses");
      }
      seenOutpoints.add(outpoint);
      const existing = byTxid.get(reference.txid);
      if (existing === undefined) byTxid.set(reference.txid, [reference]);
      else existing.push(reference);
    }

    const txids = [...byTxid.keys()].sort();
    const verified = await Promise.all(txids.map((txid) => this.pool.run(async () => {
      const rawTransactionHex = (
        await this.getText(`/tx/${txid}/hex`, MAX_RAW_TRANSACTION_TEXT_BYTES, signal)
      ).trim();
      if (
        rawTransactionHex.length === 0
        || rawTransactionHex.length > MAX_RAW_TRANSACTION_BYTES * 2
        || !EVEN_LOWER_HEX.test(rawTransactionHex)
      ) {
        throw new ExplorerHdScanError("explorer returned malformed raw transaction hex");
      }
      const transactionReferences = byTxid.get(txid);
      if (transactionReferences === undefined) throw new Error("missing transaction references");
      const expectedWalletOutputs = Object.freeze(transactionReferences
        .map((reference) => Object.freeze({
          chain: reference.chain,
          index: reference.index,
          address: reference.address,
          scriptPubKeyHex: reference.scriptPubKeyHex,
          vout: reference.vout,
        }))
        .sort((left, right) => left.vout - right.vout));
      let verificationValue: ExplorerHdVerifiedTransaction;
      try {
        verificationValue = await this.verifyRawTransaction(Object.freeze({
          expectedTxid: txid,
          rawTransactionHex,
          expectedWalletOutputs,
        }));
      } catch (error) {
        throw new ExplorerHdScanError("local raw transaction verification failed", null, {
          cause: error,
        });
      }
      const verification = parseVerifiedTransaction(verificationValue, txid);
      return Object.freeze({ txid, rawTransactionHex, verification, transactionReferences });
    })));

    const transactions: ExplorerHdFundingTransaction[] = [];
    const utxos: ExplorerHdVerifiedUtxo[] = [];
    for (const item of verified) {
      const outputsByVout = new Map(item.verification.outputs.map((output) => [output.vout, output]));
      for (const reference of item.transactionReferences) {
        const output = outputsByVout.get(reference.vout);
        if (output === undefined) {
          throw new ExplorerHdScanError("verified transaction is missing a wallet UTXO");
        }
        if (output.scriptPubKeyHex !== reference.scriptPubKeyHex) {
          throw new ExplorerHdScanError("verified funding output script does not match derivation");
        }
        if (
          reference.explorerAssetId !== undefined
          && reference.explorerAssetId !== output.assetId
        ) {
          throw new ExplorerHdScanError("verified funding output asset disagrees with explorer");
        }
        if (
          reference.explorerValueAtomic !== undefined
          && reference.explorerValueAtomic !== output.valueAtomic
        ) {
          throw new ExplorerHdScanError("verified funding output value disagrees with explorer");
        }
        utxos.push(Object.freeze({
          chain: reference.chain,
          index: reference.index,
          address: reference.address,
          scriptPubKeyHex: reference.scriptPubKeyHex,
          txid: reference.txid,
          vout: reference.vout,
          assetId: output.assetId,
          valueAtomic: output.valueAtomic,
          status: reference.status,
        }));
      }
      transactions.push(Object.freeze({
        txid: item.txid,
        rawTransactionHex: item.rawTransactionHex,
        outputs: item.verification.outputs,
      }));
    }
    utxos.sort((left, right) => {
      if (left.txid < right.txid) return -1;
      if (left.txid > right.txid) return 1;
      return left.vout - right.vout;
    });
    return Object.freeze({
      transactions: Object.freeze(transactions),
      utxos: Object.freeze(utxos),
    });
  }

  private async getTip(signal: AbortSignal): Promise<ExplorerHdTip> {
    const hash = lowercaseHash(
      (await this.getText("/blocks/tip/hash", 256, signal)).trim(),
      "tip hash",
    );
    const block = asRecord(await this.getJson(`/block/${hash}`, signal), "tip block");
    if (lowercaseHash(block["id"], "tip block.id") !== hash) {
      throw new ExplorerHdScanError("explorer returned a different tip block");
    }
    return Object.freeze({
      height: nonNegativeInteger(block["height"], "tip block.height"),
      hash,
    });
  }

  async scan(signal?: AbortSignal): Promise<ExplorerHdSnapshotInput> {
    const controller = new AbortController();
    const abort = (): void => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    try {
      await this.verifyIdentityPins(controller.signal);
      let chainResults: readonly [
        Awaited<ReturnType<ExplorerHdScanner["scanChain"]>>,
        Awaited<ReturnType<ExplorerHdScanner["scanChain"]>>,
      ];
      try {
        chainResults = await Promise.all([
          this.scanChain("external", controller.signal),
          this.scanChain("change", controller.signal),
        ]);
      } catch (error) {
        controller.abort();
        throw error;
      }

      const [external, change] = chainResults;
      const addresses = [...external.addresses, ...change.addresses];
      const addressKeys = new Set<string>();
      const scripts = new Set<string>();
      for (const address of addresses) {
        if (addressKeys.has(address.address)) {
          throw new ExplorerHdScanError("address deriver returned a duplicate address");
        }
        if (scripts.has(address.scriptPubKeyHex)) {
          throw new ExplorerHdScanError("address deriver returned a duplicate script");
        }
        addressKeys.add(address.address);
        scripts.add(address.scriptPubKeyHex);
      }

      const funding = await this.verifyFundingTransactions(
        [...external.utxos, ...change.utxos],
        controller.signal,
      );
      const tip = await this.getTip(controller.signal);
      return Object.freeze({
        source: Object.freeze({
          kind: "esplora" as const,
          explorerApiUrl: this.explorerApiUrl,
          genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
          nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
          identityPinsMatched: true as const,
          headerChainVerified: false as const,
        }),
        tip,
        scan: Object.freeze({
          gapLimit: this.gapLimit,
          maximumIndex: this.maximumIndex,
          pageSize: this.pageSize,
          chains: Object.freeze([external.state, change.state]),
        }),
        addresses: Object.freeze(addresses),
        utxos: funding.utxos,
        fundingTransactions: funding.transactions,
      });
    } finally {
      signal?.removeEventListener("abort", abort);
    }
  }
}
