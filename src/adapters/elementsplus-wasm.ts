import type {
  BurnDraft,
  IssueDraft,
  LwkCapabilities,
  LwkWalletAdapter,
  LwkWalletSession,
  PreparedTransaction,
  ReissueDraft,
  SignedTransaction,
  TransferDraft,
  WalletAsset,
  WalletSnapshot,
} from "./lwk.js";
import type { FetchImplementation } from "../network/ecx-alpha.js";
import { resolveEcxAlphaAddress } from "../network/ecx-alpha.js";
import {
  ExplorerHdScanner,
  type ExplorerHdAddressDeriver,
  type ExplorerHdRawTransactionVerifier,
  type ExplorerHdScanOptions,
  type ExplorerHdSnapshotInput,
} from "../network/explorer-hd-scan.js";
import { ECX_ALPHA_IDENTITY, type EcxAlphaIdentity } from "../network/identity.js";
import { hasExactKeys, isPlainRecord, normalizeMnemonic, ValidationError } from "../shared/validation.js";

const HEX_32_BYTES = /^[0-9a-f]{64}$/u;
const EVEN_LOWER_HEX = /^(?:[0-9a-f]{2})+$/u;
const CANONICAL_ATOMIC_AMOUNT = /^(?:0|[1-9][0-9]*)$/u;
const MAX_SAFE_ATOMIC = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_BROADCAST_RESPONSE_BYTES = 256;
const BROADCAST_TIMEOUT_MS = 20_000;

const IMPLEMENTED_CAPABILITIES: LwkCapabilities = Object.freeze({
  mnemonic: true,
  walletSync: true,
  explicitTransactions: true,
  issuance: false,
  reissuance: false,
  burning: false,
  confidentialTransactions: false,
  dex: false,
});

export interface WasmWalletCoreInstance {
  derive_address_json(branch: "external" | "change", index: number): string;
  prepare_send_json(requestJson: string): string;
  sign_prepared_json(preparedJson: string, approvedReviewHash: string): string;
  verify_raw_transaction_json(requestJson: string): string;
  free(): void;
}

export interface WasmWalletCoreConstructor {
  new (mnemonic: string): WasmWalletCoreInstance;
}

export interface ElementsPlusWalletCoreBindings {
  readonly WasmWalletCore: WasmWalletCoreConstructor;
  generate_mnemonic(): string;
  validate_mnemonic(mnemonic: string): boolean;
}

export type ElementsPlusWalletCoreLoader = () => Promise<ElementsPlusWalletCoreBindings>;

interface Scanner {
  scan(signal?: AbortSignal): Promise<ExplorerHdSnapshotInput>;
}

export type ElementsPlusScannerFactory = (
  deriveAddress: ExplorerHdAddressDeriver,
  verifyRawTransaction: ExplorerHdRawTransactionVerifier,
  options: ExplorerHdScanOptions,
) => Scanner;

export interface ElementsPlusWasmAdapterOptions {
  readonly loadCore: ElementsPlusWalletCoreLoader;
  readonly fetchImpl?: FetchImplementation;
  readonly scannerFactory?: ElementsPlusScannerFactory;
  readonly now?: () => Date;
}

interface CoreDerivedAddress {
  readonly branch: "external" | "change";
  readonly index: number;
  readonly nativeAddress: string;
  readonly scriptPubKeyHex: string;
}

interface CoreReview {
  readonly network: string;
  readonly genesisHash: string;
  readonly policyAsset: string;
  readonly recipient: string;
  readonly amount: number;
  readonly fee: number;
  readonly change: number;
  readonly changeAddress: string | null;
  readonly totalInput: number;
  readonly inputCount: number;
  readonly selectedOutpoints: readonly string[];
}

interface CorePreparedSend {
  readonly json: string;
  readonly pset: string;
  readonly reviewHash: string;
  readonly review: CoreReview;
}

interface CoreSignedTransaction {
  readonly rawTransactionHex: string;
  readonly txid: string;
  readonly reviewHash: string;
}

export class ElementsPlusAdapterError extends Error {
  override readonly name = "ElementsPlusAdapterError";
}

function fail(message: string): never {
  throw new ElementsPlusAdapterError(message);
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainRecord(value)) fail(`${label} is malformed`);
  return value;
}

function parseJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return fail(`${label} is not valid JSON`);
  }
}

function exactString(
  value: unknown,
  label: string,
  maximumLength: number,
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    return fail(`${label} is malformed`);
  }
  return value;
}

function hash(value: unknown, label: string): string {
  const result = exactString(value, label, 64);
  if (!HEX_32_BYTES.test(result)) fail(`${label} is malformed`);
  return result;
}

function byteHex(value: unknown, label: string, maximumLength: number): string {
  const result = exactString(value, label, maximumLength);
  if (!EVEN_LOWER_HEX.test(result)) fail(`${label} is malformed`);
  return result;
}

function safeInteger(value: unknown, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < 0
    || value > maximum
  ) fail(`${label} is not a safe non-negative integer`);
  return value;
}

function safeAtomicNumber(value: string, label: string): number {
  if (!CANONICAL_ATOMIC_AMOUNT.test(value)) fail(`${label} is not a canonical atomic amount`);
  const amount = BigInt(value);
  if (amount > MAX_SAFE_ATOMIC) {
    fail(`${label} exceeds the current browser signing boundary`);
  }
  return Number(amount);
}

function outputAtomicString(value: unknown, label: string): string {
  if (typeof value === "number") return String(safeInteger(value, label));
  if (typeof value === "string" && CANONICAL_ATOMIC_AMOUNT.test(value)) {
    if (BigInt(value) > MAX_SAFE_ATOMIC) fail(`${label} exceeds the current browser signing boundary`);
    return value;
  }
  return fail(`${label} is malformed`);
}

function parseCoreDerivedAddress(
  json: string,
  expectedBranch: "external" | "change",
  expectedIndex: number,
): CoreDerivedAddress {
  const value = record(parseJson(json, "derived address"), "derived address");
  if (!hasExactKeys(value, [
    "branch", "index", "derivation_path", "native_address", "lwk_alias", "script_pubkey_hex",
  ])) fail("derived address has unexpected fields");
  if (value["branch"] !== expectedBranch || value["index"] !== expectedIndex) {
    fail("wallet core derived a different branch or index");
  }
  const nativeAddress = resolveEcxAlphaAddress(exactString(
    value["native_address"],
    "derived native address",
    1_000,
  ));
  if (nativeAddress.confidential) fail("wallet core derived a confidential address");
  const alias = resolveEcxAlphaAddress(exactString(value["lwk_alias"], "derived alias", 1_000));
  if (alias.canonical !== nativeAddress.canonical || alias.confidential) {
    fail("wallet core address aliases do not identify the same explicit script");
  }
  return Object.freeze({
    branch: expectedBranch,
    index: expectedIndex,
    nativeAddress: nativeAddress.canonical,
    scriptPubKeyHex: byteHex(value["script_pubkey_hex"], "derived script", 20_000),
  });
}

function parseCoreVerifiedTransaction(value: string, expectedTxid: string): {
  readonly txid: string;
  readonly outputs: readonly {
    readonly vout: number;
    readonly scriptPubKeyHex: string;
    readonly assetId: string;
    readonly valueAtomic: string;
  }[];
} {
  const data = record(parseJson(value, "verified transaction"), "verified transaction");
  if (!hasExactKeys(data, ["txid", "outputs"])) {
    fail("verified transaction has unexpected fields");
  }
  const txid = hash(data["txid"], "verified transaction txid");
  if (txid !== expectedTxid) fail("wallet core verified a different transaction");
  if (!Array.isArray(data["outputs"]) || data["outputs"].length > 100_000) {
    fail("verified transaction output list is malformed");
  }
  const seen = new Set<number>();
  const outputs = data["outputs"].map((raw, index) => {
    const output = record(raw, `verified output ${index}`);
    if (!hasExactKeys(output, ["vout", "scriptPubKeyHex", "assetId", "valueAtomic"])) {
      fail(`verified output ${index} has unexpected fields`);
    }
    const vout = safeInteger(output["vout"], `verified output ${index} vout`, 0xffff_ffff);
    if (seen.has(vout)) fail("wallet core returned a duplicate verified output");
    seen.add(vout);
    return Object.freeze({
      vout,
      scriptPubKeyHex: byteHex(
        output["scriptPubKeyHex"],
        `verified output ${index} script`,
        20_000,
      ),
      assetId: hash(output["assetId"], `verified output ${index} asset`),
      valueAtomic: outputAtomicString(
        output["valueAtomic"],
        `verified output ${index} value`,
      ),
    });
  });
  return Object.freeze({ txid, outputs: Object.freeze(outputs) });
}

function nullableCanonicalAddress(value: unknown, label: string): string | null {
  if (value === null) return null;
  const address = resolveEcxAlphaAddress(exactString(value, label, 1_000));
  if (address.confidential) fail(`${label} is confidential`);
  return address.canonical;
}

function parseCoreReview(value: unknown): CoreReview {
  const review = record(value, "core review");
  if (!hasExactKeys(review, [
    "network", "genesis_hash", "policy_asset", "recipient_native_address", "amount", "fee",
    "change", "change_native_address", "total_input", "input_count", "selected_outpoints",
  ])) fail("core review has unexpected fields");
  if (!Array.isArray(review["selected_outpoints"]) || review["selected_outpoints"].length > 100_000) {
    fail("core review outpoint list is malformed");
  }
  const selectedOutpoints = review["selected_outpoints"].map((value, index) => {
    const outpoint = exactString(value, `selected outpoint ${index}`, 80);
    if (!/^[0-9a-f]{64}:[0-9]{1,10}$/u.test(outpoint)) fail(`selected outpoint ${index} is malformed`);
    return outpoint;
  });
  if (new Set(selectedOutpoints).size !== selectedOutpoints.length) {
    fail("core review contains duplicate outpoints");
  }
  const parsed = Object.freeze({
    network: exactString(review["network"], "core review network", 64),
    genesisHash: hash(review["genesis_hash"], "core review genesis"),
    policyAsset: hash(review["policy_asset"], "core review policy asset"),
    recipient: nullableCanonicalAddress(
      review["recipient_native_address"],
      "core review recipient",
    ) ?? fail("core review recipient is missing"),
    amount: safeInteger(review["amount"], "core review amount"),
    fee: safeInteger(review["fee"], "core review fee"),
    change: safeInteger(review["change"], "core review change"),
    changeAddress: nullableCanonicalAddress(
      review["change_native_address"],
      "core review change address",
    ),
    totalInput: safeInteger(review["total_input"], "core review total input"),
    inputCount: safeInteger(review["input_count"], "core review input count", 100_000),
    selectedOutpoints: Object.freeze(selectedOutpoints),
  });
  if (
    parsed.amount === 0
    || parsed.fee === 0
    || parsed.inputCount === 0
    || parsed.inputCount !== parsed.selectedOutpoints.length
    || BigInt(parsed.amount) + BigInt(parsed.fee) + BigInt(parsed.change) !== BigInt(parsed.totalInput)
    || (parsed.change === 0) !== (parsed.changeAddress === null)
  ) fail("core review values are internally inconsistent");
  return parsed;
}

function parseCorePrepared(value: string): CorePreparedSend {
  const data = record(parseJson(value, "prepared send"), "prepared send");
  if (!hasExactKeys(data, ["pset_base64", "review", "review_hash"])) {
    fail("prepared send has unexpected fields");
  }
  return Object.freeze({
    json: value,
    pset: exactString(data["pset_base64"], "prepared PSET", 1_500_000),
    reviewHash: hash(data["review_hash"], "core review hash"),
    review: parseCoreReview(data["review"]),
  });
}

function parseCoreSigned(value: string): CoreSignedTransaction {
  const data = record(parseJson(value, "signed transaction"), "signed transaction");
  if (!hasExactKeys(data, ["raw_tx_hex", "txid", "review_hash"])) {
    fail("signed transaction has unexpected fields");
  }
  return Object.freeze({
    rawTransactionHex: byteHex(data["raw_tx_hex"], "raw transaction", 8 * 1024 * 1024),
    txid: hash(data["txid"], "signed transaction txid"),
    reviewHash: hash(data["review_hash"], "signed transaction review hash"),
  });
}

function parseFeeRate(value: string): { readonly numerator: bigint; readonly denominator: bigint } {
  if (!/^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?$/u.test(value)) {
    fail("fee rate is malformed");
  }
  const [whole = "", fraction = ""] = value.split(".");
  const denominator = 10n ** BigInt(fraction.length);
  const numerator = BigInt(whole) * denominator + BigInt(fraction === "" ? "0" : fraction);
  if (numerator === 0n) fail("fee rate must be positive");
  return Object.freeze({ numerator, denominator });
}

function feeForVbytes(rate: ReturnType<typeof parseFeeRate>, vbytes: number): bigint {
  const scaled = rate.numerator * BigInt(vbytes);
  return (scaled + rate.denominator - 1n) / rate.denominator;
}

/**
 * Conservative explicit-Elements P2WPKH fee estimate. We always reserve room
 * for recipient, change and fee outputs. Overestimating is intentional until
 * the core exposes an exact unsigned-weight estimator.
 */
function estimateFee(
  utxos: readonly { readonly txid: string; readonly vout: number; readonly valueAtomic: string }[],
  amount: bigint,
  feeRate: string,
): bigint {
  const rate = parseFeeRate(feeRate);
  const sorted = [...utxos].sort((left, right) => {
    if (left.txid < right.txid) return -1;
    if (left.txid > right.txid) return 1;
    return left.vout - right.vout;
  });
  let fee = 1n;
  for (let iteration = 0; iteration < sorted.length + 2; iteration += 1) {
    const target = amount + fee;
    let available = 0n;
    let inputCount = 0;
    for (const utxo of sorted) {
      available += BigInt(utxo.valueAtomic);
      inputCount += 1;
      if (available >= target) break;
    }
    if (available < target) fail("insufficient confirmed or unconfirmed ECX funds");
    const conservativeVbytes = 24 + inputCount * 110 + 2 * 80 + 50;
    const next = feeForVbytes(rate, conservativeVbytes);
    const normalized = next === 0n ? 1n : next;
    if (normalized === fee) return fee;
    fee = normalized;
  }
  return fee;
}

async function boundedResponseText(response: Response, maximumBytes: number): Promise<string> {
  const length = response.headers.get("Content-Length");
  if (length !== null && (!/^[0-9]+$/u.test(length) || Number(length) > maximumBytes)) {
    fail("broadcast response is oversized");
  }
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel("response too large");
        fail("broadcast response is oversized");
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
    return fail("broadcast response is not UTF-8");
  } finally {
    bytes.fill(0);
  }
}

class ElementsPlusWasmSession implements LwkWalletSession {
  readonly #core: WasmWalletCoreInstance;
  readonly #scanner: Scanner;
  readonly #fetchImpl: FetchImplementation;
  readonly #now: () => Date;
  readonly #prepared = new Map<string, string>();
  #destroyed = false;

  constructor(
    core: WasmWalletCoreInstance,
    scannerFactory: ElementsPlusScannerFactory,
    fetchImpl: FetchImplementation,
    now: () => Date,
  ) {
    this.#core = core;
    this.#fetchImpl = fetchImpl;
    this.#now = now;
    const deriveAddress: ExplorerHdAddressDeriver = ({ chain, index }) => {
      this.#assertOpen();
      const derived = parseCoreDerivedAddress(
        this.#core.derive_address_json(chain, index),
        chain,
        index,
      );
      return Object.freeze({
        chain,
        index,
        address: derived.nativeAddress,
        scriptPubKeyHex: derived.scriptPubKeyHex,
      });
    };
    const verifyRawTransaction: ExplorerHdRawTransactionVerifier = (request) => {
      this.#assertOpen();
      const expectedWalletOutputs = request.expectedWalletOutputs.map((output) => Object.freeze({
        vout: output.vout,
        scriptPubKeyHex: output.scriptPubKeyHex,
      }));
      return parseCoreVerifiedTransaction(this.#core.verify_raw_transaction_json(JSON.stringify({
        expectedTxid: request.expectedTxid,
        rawTransactionHex: request.rawTransactionHex,
        expectedWalletOutputs,
      })), request.expectedTxid);
    };
    this.#scanner = scannerFactory(deriveAddress, verifyRawTransaction, Object.freeze({
      explorerUrl: ECX_ALPHA_IDENTITY.explorerUrl,
      fetchImpl,
    }));
  }

  async sync(signal: AbortSignal): Promise<WalletSnapshot> {
    this.#assertOpen();
    const scan = await this.#scanner.scan(signal);
    this.#assertOpen();
    return this.#snapshot(scan);
  }

  async prepareTransfer(draft: TransferDraft, requiredInput?: string): Promise<PreparedTransaction> {
    this.#assertOpen();
    if (!draft.explicitOutputsOnly || draft.assetId !== ECX_ALPHA_IDENTITY.nativeAssetId) {
      fail("this wallet currently sends only explicit native ECX");
    }
    const amount = BigInt(draft.amountAtomic);
    if (amount === 0n || amount > MAX_SAFE_ATOMIC) {
      fail("send amount exceeds the current browser signing boundary");
    }

    // Refresh immediately before construction so a stale snapshot cannot be
    // used to select an already-spent explorer UTXO.
    const scan = await this.#scanner.scan();
    this.#assertOpen();
    const nativeUtxos = scan.utxos.filter((utxo) =>
      utxo.assetId === ECX_ALPHA_IDENTITY.nativeAssetId
      && (requiredInput === undefined || `${utxo.txid}:${utxo.vout}` === requiredInput)
    );
    if (requiredInput !== undefined && nativeUtxos.length !== 1) {
      fail("configured preconfirmation principal is not an unspent wallet output");
    }
    const fee = estimateFee(nativeUtxos, amount, draft.feeRate);
    if (fee > MAX_SAFE_ATOMIC) fail("network fee exceeds the current browser signing boundary");
    const changeState = scan.scan.chains.find((chain) => chain.chain === "change");
    if (changeState === undefined) fail("scanner did not return a change branch");
    const request = Object.freeze({
      recipient: draft.destination,
      amount: Number(amount),
      fee: Number(fee),
      change_index: changeState.nextUnusedIndex,
      utxos: nativeUtxos.map((utxo) => Object.freeze({
        txid: utxo.txid,
        vout: utxo.vout,
        value: safeAtomicNumber(utxo.valueAtomic, "UTXO value"),
        asset_id: utxo.assetId,
        script_pubkey_hex: utxo.scriptPubKeyHex,
        branch: utxo.chain,
        index: utxo.index,
      })),
    });
    const prepared = parseCorePrepared(this.#core.prepare_send_json(JSON.stringify(request)));
    if (
      prepared.review.network !== ECX_ALPHA_IDENTITY.displayName
      || prepared.review.genesisHash !== ECX_ALPHA_IDENTITY.genesisHash
      || prepared.review.policyAsset !== ECX_ALPHA_IDENTITY.nativeAssetId
      || prepared.review.recipient !== draft.destination
      || prepared.review.amount !== request.amount
      || prepared.review.fee !== request.fee
      || (requiredInput !== undefined && (prepared.review.selectedOutpoints.length !== 1 || prepared.review.selectedOutpoints[0] !== requiredInput))
    ) fail("wallet core review does not match the requested transfer");

    // The controller itself permits only one pending approval; mirror that
    // bound here so abandoned preparations cannot accumulate secret state.
    this.#prepared.clear();
    this.#prepared.set(`${prepared.reviewHash}:${prepared.pset}`, prepared.json);
    return Object.freeze({
      pset: prepared.pset,
      coreReviewHash: prepared.reviewHash,
      summary: Object.freeze({
        kind: "transfer" as const,
        networkKey: ECX_ALPHA_IDENTITY.key,
        genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
        assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        destination: prepared.review.recipient,
        amountAtomic: String(prepared.review.amount),
        networkFeeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        networkFeeAtomic: String(prepared.review.fee),
        feeRate: draft.feeRate,
        transactionPolicy: "explicit-only" as const,
      }),
    });
  }

  async prepareIssue(_draft: IssueDraft): Promise<PreparedTransaction> {
    return fail("asset issuance is not implemented by this wallet core");
  }

  async prepareReissue(_draft: ReissueDraft): Promise<PreparedTransaction> {
    return fail("asset reissuance is not implemented by this wallet core");
  }

  async prepareBurn(_draft: BurnDraft): Promise<PreparedTransaction> {
    return fail("asset burning is not implemented by this wallet core");
  }

  async signPrepared(transaction: PreparedTransaction): Promise<SignedTransaction> {
    this.#assertOpen();
    const key = `${transaction.coreReviewHash}:${transaction.pset}`;
    let preparedJson = this.#prepared.get(key);
    // Consume locally before signing or network access, matching the
    // controller's one-time approval semantics.
    this.#prepared.clear();
    if (preparedJson === undefined) fail("prepared transaction is unknown or already consumed");
    try {
      const signed = parseCoreSigned(this.#core.sign_prepared_json(
        preparedJson,
        transaction.coreReviewHash,
      ));
      if (signed.reviewHash !== transaction.coreReviewHash) {
        fail("signed transaction review commitment changed");
      }
      return Object.freeze({ rawTransactionHex: signed.rawTransactionHex, txid: signed.txid });
    } finally {
      preparedJson = "";
    }
  }

  async broadcastSigned(transaction: SignedTransaction): Promise<string> {
    if (!HEX_32_BYTES.test(transaction.txid)
      || !EVEN_LOWER_HEX.test(transaction.rawTransactionHex)
      || transaction.rawTransactionHex.length > 8 * 1024 * 1024) {
      fail("signed transaction is malformed");
    }
    return await this.#broadcast({
      rawTransactionHex: transaction.rawTransactionHex,
      txid: transaction.txid,
      reviewHash: "0".repeat(64),
    });
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#prepared.clear();
    this.#core.free();
  }

  #assertOpen(): void {
    if (this.#destroyed) fail("wallet session is destroyed");
  }

  #snapshot(scan: ExplorerHdSnapshotInput): WalletSnapshot {
    if (
      scan.source.genesisHash !== ECX_ALPHA_IDENTITY.genesisHash
      || scan.source.nativeAssetId !== ECX_ALPHA_IDENTITY.nativeAssetId
      || scan.source.identityPinsMatched !== true
      || scan.source.headerChainVerified !== false
    ) fail("scanner returned the wrong chain identity or trust model");
    const totals = new Map<string, { total: bigint; confirmed: bigint }>();
    totals.set(ECX_ALPHA_IDENTITY.nativeAssetId, { total: 0n, confirmed: 0n });
    for (const utxo of scan.utxos) {
      const current = totals.get(utxo.assetId) ?? { total: 0n, confirmed: 0n };
      const value = BigInt(utxo.valueAtomic);
      current.total += value;
      if (utxo.status.confirmed) current.confirmed += value;
      totals.set(utxo.assetId, current);
    }
    const assets: WalletAsset[] = [...totals.entries()].map(([assetId, amount]) => Object.freeze({
      assetId,
      ticker: assetId === ECX_ALPHA_IDENTITY.nativeAssetId ? "ECX" : null,
      name: assetId === ECX_ALPHA_IDENTITY.nativeAssetId ? "ECX Alpha" : null,
      amountAtomic: amount.total.toString(),
      confirmedAtomic: amount.confirmed.toString(),
      isNative: assetId === ECX_ALPHA_IDENTITY.nativeAssetId,
    }));
    assets.sort((left, right) => {
      if (left.isNative !== right.isNative) return left.isNative ? -1 : 1;
      return left.assetId.localeCompare(right.assetId, "en");
    });
    const external = scan.scan.chains.find((chain) => chain.chain === "external");
    if (external === undefined) fail("scanner did not return an external branch");
    let receiveAddress = scan.addresses.find((address) =>
      address.chain === "external" && address.index === external.nextUnusedIndex
    )?.address;
    if (receiveAddress === undefined) {
      receiveAddress = parseCoreDerivedAddress(
        this.#core.derive_address_json("external", external.nextUnusedIndex),
        "external",
        external.nextUnusedIndex,
      ).nativeAddress;
    }
    return Object.freeze({
      chain: Object.freeze({
        genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
        nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        backend: "explorer" as const,
        headerChainVerified: false as const,
        transactionPolicy: "explicit-only" as const,
      }),
      tipHeight: scan.tip.height,
      tipHash: scan.tip.hash,
      receiveAddress,
      assets: Object.freeze(assets),
      syncedAt: this.#now().toISOString(),
    });
  }

  async #broadcast(signed: CoreSignedTransaction): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), BROADCAST_TIMEOUT_MS);
    try {
      const url = new URL("/api/tx", ECX_ALPHA_IDENTITY.explorerUrl);
      const response = await this.#fetchImpl(url, {
        method: "POST",
        headers: {
          Accept: "text/plain",
          "Content-Type": "text/plain",
        },
        body: signed.rawTransactionHex,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        signal: controller.signal,
      });
      const body = (await boundedResponseText(response, MAX_BROADCAST_RESPONSE_BYTES)).trim();
      if (!response.ok) fail(`transaction broadcast failed (${response.status})`);
      if (!HEX_32_BYTES.test(body) || body !== signed.txid) {
        fail("broadcast backend returned a different transaction id");
      }
      return body;
    } catch (error) {
      if (error instanceof ElementsPlusAdapterError) throw error;
      if (controller.signal.aborted) fail("transaction broadcast timed out");
      return fail("transaction broadcast failed");
    } finally {
      clearTimeout(timeout);
    }
  }
}

/** Real, fail-closed adapter backed only by the packaged Rust/WASM core. */
export class ElementsPlusWasmAdapter implements LwkWalletAdapter {
  readonly implementation = "elementsplus-wallet-core-wasm/0.1.0+esplora";
  readonly available = true;
  readonly capabilities = IMPLEMENTED_CAPABILITIES;
  readonly #loadCore: ElementsPlusWalletCoreLoader;
  readonly #fetchImpl: FetchImplementation;
  readonly #scannerFactory: ElementsPlusScannerFactory;
  readonly #now: () => Date;
  #bindings: Promise<ElementsPlusWalletCoreBindings> | undefined;

  constructor(options: ElementsPlusWasmAdapterOptions) {
    if (typeof options.loadCore !== "function") throw new TypeError("wallet core loader is required");
    const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (fetchImpl === undefined) throw new TypeError("Fetch API is unavailable");
    this.#loadCore = options.loadCore;
    this.#fetchImpl = fetchImpl;
    this.#scannerFactory = options.scannerFactory
      ?? ((derive, verify, scannerOptions) => new ExplorerHdScanner(derive, verify, scannerOptions));
    this.#now = options.now ?? (() => new Date());
  }

  async generateMnemonic(): Promise<string> {
    const mnemonic = normalizeMnemonic((await this.#core()).generate_mnemonic());
    if (!(await this.validateMnemonic(mnemonic))) fail("wallet core generated an invalid mnemonic");
    return mnemonic;
  }

  async validateMnemonic(mnemonic: string): Promise<boolean> {
    return (await this.#core()).validate_mnemonic(normalizeMnemonic(mnemonic));
  }

  async openWallet(mnemonic: string, identity: EcxAlphaIdentity): Promise<LwkWalletSession> {
    if (
      identity.key !== ECX_ALPHA_IDENTITY.key
      || identity.genesisHash !== ECX_ALPHA_IDENTITY.genesisHash
      || identity.nativeAssetId !== ECX_ALPHA_IDENTITY.nativeAssetId
      || identity.sidechainSlot !== ECX_ALPHA_IDENTITY.sidechainSlot
      || identity.transactionPolicy !== "explicit-only"
    ) fail("refusing to open a wallet for an unpinned chain identity");
    const bindings = await this.#core();
    const normalized = normalizeMnemonic(mnemonic);
    if (!bindings.validate_mnemonic(normalized)) fail("invalid recovery phrase");
    let core: WasmWalletCoreInstance | undefined;
    try {
      core = new bindings.WasmWalletCore(normalized);
      return new ElementsPlusWasmSession(
        core,
        this.#scannerFactory,
        this.#fetchImpl,
        this.#now,
      );
    } catch (error) {
      core?.free();
      if (error instanceof ElementsPlusAdapterError || error instanceof ValidationError) throw error;
      return fail("wallet core refused to open the recovery phrase");
    }
  }

  async #core(): Promise<ElementsPlusWalletCoreBindings> {
    this.#bindings ??= this.#loadCore().then((bindings) => {
      if (
        typeof bindings.generate_mnemonic !== "function"
        || typeof bindings.validate_mnemonic !== "function"
        || typeof bindings.WasmWalletCore !== "function"
      ) fail("packaged wallet core exports are incomplete");
      return bindings;
    });
    return await this.#bindings;
  }
}
