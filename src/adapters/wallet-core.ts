/**
 * The single integration point between TypeScript and the Rust/WASM signing
 * core (V2 spec §1.3). Every JSON value crossing this boundary is parsed and
 * validated here; nothing else in the extension touches the raw bindings.
 */
import { resolveEcxAddress } from "../network/esplora.js";
import type { NetworkIdentity } from "../network/identity.js";
import { hasExactKeys, isPlainRecord, normalizeMnemonic } from "../shared/validation.js";

export const HEX_32 = /^[0-9a-f]{64}$/u;
const EVEN_HEX = /^(?:[0-9a-f]{2})+$/u;
const UNSIGNED = /^(?:0|[1-9][0-9]*)$/u;
const SIGNED = /^-?(?:0|[1-9][0-9]*)$/u;
const OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/u;
export const MAX_U64 = 18_446_744_073_709_551_615n;
const MAX_LIST = 10_000;

// ---------------------------------------------------------------------------
// Raw binding shapes (mirrors src/wasm/elementsplus_wallet_core.d.ts)
// ---------------------------------------------------------------------------

export interface WasmWalletCoreInstance {
  derive_address_json(branch: string, index: number): string;
  verify_raw_transaction_json(requestJson: string): string;
  prepare_transfer_json(requestJson: string): string;
  prepare_issuance_json(requestJson: string): string;
  prepare_offer_split_json(requestJson: string): string;
  prepare_swap_offer_json(requestJson: string): string;
  take_swap_offers_json(requestJson: string): string;
  prepare_cancel_json(requestJson: string): string;
  sign_prepared_json(preparedJson: string, approvedReviewHash: string): string;
  /** Network-aware offer decoding (the free function uses the compiled profile). */
  decode_offer_json(offerJson: string, prevoutRawTxHex: string): string;
  free(): void;
}

export interface WasmWalletCoreConstructor {
  new (mnemonic: string): WasmWalletCoreInstance;
  readonly forRegtest?: (
    mnemonic: string,
    genesisHash: string,
    policyAsset: string,
    displayName: string,
  ) => WasmWalletCoreInstance;
}

export interface WalletCoreBindings {
  readonly WasmWalletCore: WasmWalletCoreConstructor;
  generate_mnemonic(): string;
  validate_mnemonic(mnemonic: string): boolean;
  verify_asset_issuance_json(requestJson: string): string;
  decode_offer_json(offerJson: string, prevoutRawTxHex: string): string;
}

// ---------------------------------------------------------------------------
// Validated, camelCase domain types
// ---------------------------------------------------------------------------

export type TxKind = "transfer" | "issuance" | "swap_offer" | "swap_take" | "offer_split" | "cancel";
export type Sighash = "ALL" | "SINGLE|ANYONECANPAY";

export interface AssetDelta { readonly assetId: string; readonly amount: string }
export interface ExternalOutput { readonly address: string; readonly assetId: string; readonly amount: string }
export interface IssuanceReview {
  readonly assetId: string;
  readonly tokenId: string | null;
  readonly amount: string;
  readonly tokenAmount: string;
  readonly contractHash: string;
}

/** Spec §1.1. Signed decimal strings for deltas, unsigned for everything else. */
export interface TxReview {
  readonly kind: TxKind;
  readonly network: string;
  readonly genesisHash: string;
  readonly balanceChanges: readonly AssetDelta[];
  readonly fee: string;
  readonly externalOutputs: readonly ExternalOutput[];
  readonly inputsSigned: readonly string[];
  readonly foreignInputs: readonly string[];
  readonly issuance: IssuanceReview | null;
  readonly sighash: Sighash;
}

export interface PreparedTx {
  /** Original core JSON. Passed back verbatim to `sign_prepared_json`; never leaves the worker. */
  readonly json: string;
  readonly psetBase64: string;
  readonly review: TxReview;
  readonly reviewHash: string;
}

/** Spec §2 wire format; kept snake_case because it is shared with the DEX. */
export interface SwapOffer {
  readonly version: 1;
  readonly network: string;
  readonly genesis_hash: string;
  readonly tx: string;
  readonly give: { readonly asset_id: string; readonly amount: string };
  readonly want: { readonly asset_id: string; readonly amount: string };
}

export interface SignResult {
  readonly txid: string;
  readonly reviewHash: string;
  readonly rawTxHex: string | null;
  readonly offer: SwapOffer | null;
}

export interface DecodedOffer {
  readonly giveAsset: string;
  readonly giveAmount: string;
  readonly wantAsset: string;
  readonly wantAmount: string;
  readonly outpoint: string;
  readonly makerAddress: string;
}

export interface VerifiedIssuance {
  readonly assetId: string;
  readonly tokenId: string | null;
  readonly contractHash: string;
}

export interface DerivedAddress {
  readonly branch: "external" | "change";
  readonly index: number;
  readonly address: string;
  readonly scriptPubKeyHex: string;
}

export interface VerifiedTransactionOutput {
  readonly vout: number;
  readonly scriptPubKeyHex: string;
  readonly assetId: string;
  readonly valueAtomic: string;
}

export interface VerifiedTransaction {
  readonly txid: string;
  readonly outputs: readonly VerifiedTransactionOutput[];
}

/** `VerifiedUtxo` request shape (spec §1.3). */
export interface CoreUtxo {
  readonly txid: string;
  readonly vout: number;
  readonly value: string;
  readonly asset_id: string;
  readonly script_pubkey_hex: string;
  readonly branch: "external" | "change";
  readonly index: number;
}

export interface AssetContract {
  readonly name: string;
  readonly ticker: string;
  readonly precision: number;
  readonly version: 0;
  readonly issuer_pubkey?: string;
}

export type CoreRequest =
  | { readonly op: "transfer"; readonly recipient: string; readonly asset_id: string; readonly amount: string;
      readonly fee_rate_sat_vb: number; readonly utxos: readonly CoreUtxo[]; readonly change_index: number }
  | { readonly op: "issuance"; readonly contract: AssetContract; readonly amount: string; readonly token_amount: string;
      readonly fee_rate: number; readonly utxos: readonly CoreUtxo[]; readonly change_index: number; readonly receive_index: number }
  | { readonly op: "offer_split"; readonly asset_id: string; readonly amount: string; readonly fee_rate: number;
      readonly utxos: readonly CoreUtxo[]; readonly change_index: number; readonly receive_index: number }
  | { readonly op: "swap_offer"; readonly utxo: CoreUtxo; readonly want_asset: string; readonly want_amount: string;
      readonly receive_index: number }
  | { readonly op: "swap_take"; readonly offers: readonly { readonly offer: SwapOffer; readonly prevout_raw_tx_hex: string }[];
      readonly fee_rate: number; readonly utxos: readonly CoreUtxo[]; readonly change_index: number; readonly receive_index: number }
  | { readonly op: "cancel"; readonly utxo: CoreUtxo; readonly change_index: number; readonly fee_rate: number;
      readonly other_utxos: readonly CoreUtxo[] };

export class WalletCoreError extends Error {
  override readonly name = "WalletCoreError";
}

function fail(message: string): never {
  throw new WalletCoreError(message);
}

function parseJson(text: unknown, label: string): unknown {
  if (typeof text !== "string") fail(`${label} is not a string`);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return fail(`${label} is not valid JSON`);
  }
}

function rec(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!isPlainRecord(value) || !hasExactKeys(value, required, optional)) fail(`${label} has missing or unexpected fields`);
  return value;
}

function str(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) fail(`${label} is malformed`);
  return value;
}

export function hash32(value: unknown, label: string): string {
  const result = str(value, label, 64);
  if (!HEX_32.test(result)) fail(`${label} is not 32-byte lowercase hex`);
  return result;
}

function hex(value: unknown, label: string, max: number): string {
  const result = str(value, label, max);
  if (!EVEN_HEX.test(result)) fail(`${label} is not lowercase byte hex`);
  return result;
}

function nonNegativeInt(value: unknown, label: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) {
    fail(`${label} is not an in-range integer`);
  }
  return value;
}

/** Unsigned u64 amount; accepts a decimal string or a safe integer number. */
export function unsignedAmount(value: unknown, label: string): string {
  const text = typeof value === "number" ? String(nonNegativeInt(value, label)) : str(value, label, 20);
  if (!UNSIGNED.test(text) || BigInt(text) > MAX_U64) fail(`${label} is not a canonical u64 amount`);
  return text;
}

function signedAmount(value: unknown, label: string): string {
  const text = str(value, label, 21);
  if (!SIGNED.test(text) || text === "-0") fail(`${label} is not a canonical signed amount`);
  const amount = BigInt(text);
  if (amount > MAX_U64 || -amount > MAX_U64) fail(`${label} exceeds u64`);
  return text;
}

function outpoint(value: unknown, label: string): string {
  const text = str(value, label, 85);
  const canonical = text.startsWith("[elements]") ? text.slice(10) : text;
  if (!OUTPOINT.test(canonical)) fail(`${label} is not txid:vout`);
  return canonical;
}

function list<T>(value: unknown, label: string, parse: (entry: unknown, index: number) => T): T[] {
  if (!Array.isArray(value) || value.length > MAX_LIST) fail(`${label} is not a bounded list`);
  return value.map(parse);
}

function explicitAddress(value: unknown, label: string): string {
  const supplied = str(value, label, 200);
  let resolved;
  try {
    resolved = resolveEcxAddress(supplied);
  } catch {
    return fail(`${label} is not an address on this network`);
  }
  if (resolved.confidential) fail(`${label} is confidential`);
  return resolved.canonical;
}

const KINDS: Record<string, TxKind> = {
  transfer: "transfer",
  issuance: "issuance",
  swapoffer: "swap_offer",
  swaptake: "swap_take",
  offersplit: "offer_split",
  cancel: "cancel",
};

function kind(value: unknown): TxKind {
  const text = str(value, "review kind", 32).toLowerCase().replaceAll("_", "");
  return KINDS[text] ?? fail("review kind is unknown");
}

function sighash(value: unknown): Sighash {
  if (value === "ALL" || value === "SINGLE|ANYONECANPAY") return value;
  return fail("review sighash is unsupported");
}

export function parseTxReview(value: unknown): TxReview {
  const data = rec(value, "review", [
    "kind", "network", "genesis_hash", "balance_changes", "fee", "external_outputs",
    "inputs_signed", "foreign_inputs", "sighash",
  ], ["issuance"]);
  const balanceChanges = list(data["balance_changes"], "balance changes", (entry, index) => {
    const delta = rec(entry, `balance change ${index}`, ["asset_id", "amount"]);
    return Object.freeze({
      assetId: hash32(delta["asset_id"], `balance change ${index} asset`),
      amount: signedAmount(delta["amount"], `balance change ${index} amount`),
    });
  });
  if (new Set(balanceChanges.map((delta) => delta.assetId)).size !== balanceChanges.length) {
    fail("review lists an asset twice");
  }
  const externalOutputs = list(data["external_outputs"], "external outputs", (entry, index) => {
    const output = rec(entry, `external output ${index}`, ["address", "asset_id", "amount"]);
    return Object.freeze({
      address: explicitAddress(output["address"], `external output ${index} address`),
      assetId: hash32(output["asset_id"], `external output ${index} asset`),
      amount: unsignedAmount(output["amount"], `external output ${index} amount`),
    });
  });
  const inputsSigned = list(data["inputs_signed"], "signed inputs", (entry, index) => outpoint(entry, `signed input ${index}`));
  const foreignInputs = list(data["foreign_inputs"], "foreign inputs", (entry, index) => outpoint(entry, `foreign input ${index}`));
  if (new Set([...inputsSigned, ...foreignInputs]).size !== inputsSigned.length + foreignInputs.length) {
    fail("review lists an input twice");
  }
  let issuance: IssuanceReview | null = null;
  if (data["issuance"] !== undefined && data["issuance"] !== null) {
    const raw = rec(data["issuance"], "issuance review", ["asset_id", "amount", "token_amount", "contract_hash"], ["token_id"]);
    issuance = Object.freeze({
      assetId: hash32(raw["asset_id"], "issued asset"),
      tokenId: raw["token_id"] === undefined || raw["token_id"] === null ? null : hash32(raw["token_id"], "issued token"),
      amount: unsignedAmount(raw["amount"], "issued amount"),
      tokenAmount: unsignedAmount(raw["token_amount"], "issued token amount"),
      contractHash: hash32(raw["contract_hash"], "contract hash"),
    });
  }
  return Object.freeze({
    kind: kind(data["kind"]),
    network: str(data["network"], "review network", 64),
    genesisHash: hash32(data["genesis_hash"], "review genesis"),
    balanceChanges: Object.freeze(balanceChanges),
    fee: unsignedAmount(data["fee"], "review fee"),
    externalOutputs: Object.freeze(externalOutputs),
    inputsSigned: Object.freeze(inputsSigned),
    foreignInputs: Object.freeze(foreignInputs),
    issuance,
    sighash: sighash(data["sighash"]),
  });
}

export function parsePreparedTx(json: unknown): PreparedTx {
  const data = rec(parseJson(json, "prepared transaction"), "prepared transaction", ["pset_base64", "review", "review_hash"]);
  const psetBase64 = str(data["pset_base64"], "PSET", 2_000_000);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(psetBase64) || !psetBase64.startsWith("cHNldP8")) {
    fail("prepared transaction does not contain a base64 PSET");
  }
  return Object.freeze({
    json: json as string,
    psetBase64,
    review: parseTxReview(data["review"]),
    reviewHash: hash32(data["review_hash"], "review hash"),
  });
}

export function parseSwapOffer(value: unknown): SwapOffer {
  const data = rec(value, "offer", ["version", "network", "genesis_hash", "tx", "give", "want"]);
  if (data["version"] !== 1) fail("offer version is unsupported");
  const leg = (raw: unknown, label: string) => {
    const legData = rec(raw, label, ["asset_id", "amount"]);
    return Object.freeze({
      asset_id: hash32(legData["asset_id"], `${label} asset`),
      amount: unsignedAmount(legData["amount"], `${label} amount`),
    });
  };
  return Object.freeze({
    version: 1 as const,
    network: str(data["network"], "offer network", 64),
    genesis_hash: hash32(data["genesis_hash"], "offer genesis"),
    tx: hex(data["tx"], "offer transaction", 200_000),
    give: leg(data["give"], "offer give"),
    want: leg(data["want"], "offer want"),
  });
}

export function parseSignResult(json: unknown): SignResult {
  const data = rec(parseJson(json, "signed transaction"), "signed transaction", ["txid", "review_hash"], ["raw_tx_hex", "offer"]);
  const rawTxHex = data["raw_tx_hex"] === undefined || data["raw_tx_hex"] === null
    ? null
    : hex(data["raw_tx_hex"], "raw transaction", 8 * 1024 * 1024);
  const offer = data["offer"] === undefined || data["offer"] === null ? null : parseSwapOffer(data["offer"]);
  if ((rawTxHex === null) === (offer === null)) fail("signed result must contain exactly one of a transaction or an offer");
  return Object.freeze({
    txid: hash32(data["txid"], "signed txid"),
    reviewHash: hash32(data["review_hash"], "signed review hash"),
    rawTxHex,
    offer,
  });
}

export function parseDecodedOffer(json: unknown): DecodedOffer {
  const data = rec(parseJson(json, "decoded offer"), "decoded offer", [
    "give_asset", "give_amount", "want_asset", "want_amount", "outpoint", "maker_address",
  ]);
  return Object.freeze({
    giveAsset: hash32(data["give_asset"], "offer give asset"),
    giveAmount: unsignedAmount(data["give_amount"], "offer give amount"),
    wantAsset: hash32(data["want_asset"], "offer want asset"),
    wantAmount: unsignedAmount(data["want_amount"], "offer want amount"),
    outpoint: outpoint(data["outpoint"], "offer outpoint"),
    makerAddress: explicitAddress(data["maker_address"], "offer maker address"),
  });
}

export function parseVerifiedIssuance(json: unknown): VerifiedIssuance {
  const data = rec(parseJson(json, "issuance verification"), "issuance verification", ["asset_id", "token_id", "contract_hash"]);
  return Object.freeze({
    assetId: hash32(data["asset_id"], "verified asset"),
    tokenId: data["token_id"] === null ? null : hash32(data["token_id"], "verified token"),
    contractHash: hash32(data["contract_hash"], "verified contract hash"),
  });
}

export function parseDerivedAddress(json: unknown, branch: "external" | "change", index: number): DerivedAddress {
  const data = rec(parseJson(json, "derived address"), "derived address", [
    "branch", "index", "derivation_path", "native_address", "lwk_alias", "script_pubkey_hex",
  ]);
  if (data["branch"] !== branch || data["index"] !== index) fail("core derived a different branch or index");
  const address = explicitAddress(data["native_address"], "derived address");
  if (explicitAddress(data["lwk_alias"], "derived alias") !== address) fail("derived aliases disagree");
  return Object.freeze({ branch, index, address, scriptPubKeyHex: hex(data["script_pubkey_hex"], "derived script", 20_000) });
}

export function parseVerifiedTransaction(json: unknown, expectedTxid: string): VerifiedTransaction {
  const data = rec(parseJson(json, "verified transaction"), "verified transaction", ["txid", "outputs"]);
  const txid = hash32(data["txid"], "verified txid");
  if (txid !== expectedTxid) fail("core verified a different transaction");
  const seen = new Set<number>();
  const outputs = list(data["outputs"], "verified outputs", (entry, index) => {
    const output = rec(entry, `verified output ${index}`, ["vout", "scriptPubKeyHex", "assetId", "valueAtomic"]);
    const vout = nonNegativeInt(output["vout"], `verified output ${index} vout`, 0xffff_ffff);
    if (seen.has(vout)) fail("core returned a duplicate output");
    seen.add(vout);
    return Object.freeze({
      vout,
      scriptPubKeyHex: hex(output["scriptPubKeyHex"], `verified output ${index} script`, 20_000),
      assetId: hash32(output["assetId"], `verified output ${index} asset`),
      valueAtomic: unsignedAmount(output["valueAtomic"], `verified output ${index} value`),
    });
  });
  return Object.freeze({ txid, outputs: Object.freeze(outputs) });
}

/** A wallet instance opened from a mnemonic. Owns the WASM object. */
export class WalletCoreSession {
  readonly #core: WasmWalletCoreInstance;
  #freed = false;

  constructor(core: WasmWalletCoreInstance) {
    this.#core = core;
  }

  deriveAddress(branch: "external" | "change", index: number): DerivedAddress {
    this.#open();
    return parseDerivedAddress(this.#core.derive_address_json(branch, index), branch, index);
  }

  verifyRawTransaction(request: {
    readonly expectedTxid: string;
    readonly rawTransactionHex: string;
    readonly expectedWalletOutputs: readonly { readonly vout: number; readonly scriptPubKeyHex: string }[];
  }): VerifiedTransaction {
    this.#open();
    return parseVerifiedTransaction(this.#core.verify_raw_transaction_json(JSON.stringify({
      expectedTxid: request.expectedTxid,
      rawTransactionHex: request.rawTransactionHex,
      expectedWalletOutputs: request.expectedWalletOutputs.map(({ vout, scriptPubKeyHex }) => ({ vout, scriptPubKeyHex })),
    })), request.expectedTxid);
  }

  prepare(request: CoreRequest): PreparedTx {
    this.#open();
    const { op, ...body } = request;
    const json = JSON.stringify(body);
    switch (op) {
      case "transfer": return parsePreparedTx(this.#core.prepare_transfer_json(json));
      case "issuance": return parsePreparedTx(this.#core.prepare_issuance_json(json));
      case "offer_split": return parsePreparedTx(this.#core.prepare_offer_split_json(json));
      case "swap_offer": return parsePreparedTx(this.#core.prepare_swap_offer_json(json));
      case "swap_take": return parsePreparedTx(this.#core.take_swap_offers_json(json));
      case "cancel": return parsePreparedTx(this.#core.prepare_cancel_json(json));
    }
  }

  sign(prepared: PreparedTx, approvedReviewHash: string): SignResult {
    this.#open();
    if (!HEX_32.test(approvedReviewHash) || approvedReviewHash !== prepared.reviewHash) {
      fail("approved review hash does not match the prepared transaction");
    }
    const result = parseSignResult(this.#core.sign_prepared_json(prepared.json, approvedReviewHash));
    if (result.reviewHash !== approvedReviewHash) fail("core signed a different review");
    return result;
  }

  /** Verify an offer against its funding transaction on this wallet's network. */
  decodeOffer(offer: SwapOffer, prevoutRawTxHex: string): DecodedOffer {
    this.#open();
    return parseDecodedOffer(this.#core.decode_offer_json(JSON.stringify(offer), prevoutRawTxHex));
  }

  free(): void {
    if (this.#freed) return;
    this.#freed = true;
    this.#core.free();
  }

  #open(): void {
    if (this.#freed) fail("wallet core session is closed");
  }
}

/** Module-level (keyless) core functions plus wallet construction. */
export class WalletCore {
  readonly #load: () => Promise<WalletCoreBindings>;
  #bindings: Promise<WalletCoreBindings> | undefined;

  constructor(load: () => Promise<WalletCoreBindings>) {
    this.#load = load;
  }

  async generateMnemonic(): Promise<string> {
    const mnemonic = normalizeMnemonic((await this.#core()).generate_mnemonic());
    if (!(await this.validateMnemonic(mnemonic))) fail("core generated an invalid mnemonic");
    return mnemonic;
  }

  async validateMnemonic(mnemonic: string): Promise<boolean> {
    return (await this.#core()).validate_mnemonic(normalizeMnemonic(mnemonic)) === true;
  }

  async open(mnemonic: string, identity: NetworkIdentity): Promise<WalletCoreSession> {
    const bindings = await this.#core();
    const normalized = normalizeMnemonic(mnemonic);
    if (!bindings.validate_mnemonic(normalized)) fail("invalid recovery phrase");
    let instance: WasmWalletCoreInstance;
    if (identity.id === "elementsplus-regtest") {
      const factory = bindings.WasmWalletCore.forRegtest;
      if (typeof factory !== "function") fail("regtest artifact is missing its test-only constructor");
      instance = factory(normalized, identity.genesisHash, identity.nativeAssetId, identity.displayName);
    } else {
      instance = new bindings.WasmWalletCore(normalized);
    }
    return new WalletCoreSession(instance);
  }

  async verifyAssetIssuance(request: {
    readonly rawTxHex: string;
    readonly expectedTxid: string;
    readonly vin: number;
    readonly contract: Record<string, unknown>;
  }): Promise<VerifiedIssuance> {
    const bindings = await this.#core();
    return parseVerifiedIssuance(bindings.verify_asset_issuance_json(JSON.stringify({
      raw_tx_hex: request.rawTxHex,
      expected_txid: request.expectedTxid,
      vin: request.vin,
      contract: request.contract,
    })));
  }

  async decodeOffer(offer: SwapOffer, prevoutRawTxHex: string): Promise<DecodedOffer> {
    const bindings = await this.#core();
    return parseDecodedOffer(bindings.decode_offer_json(JSON.stringify(offer), prevoutRawTxHex));
  }

  #core(): Promise<WalletCoreBindings> {
    this.#bindings ??= this.#load().then((bindings) => {
      for (const name of ["generate_mnemonic", "validate_mnemonic", "verify_asset_issuance_json", "decode_offer_json"] as const) {
        if (typeof bindings[name] !== "function") fail(`packaged wallet core is missing ${name}`);
      }
      if (typeof bindings.WasmWalletCore !== "function") fail("packaged wallet core is missing WasmWalletCore");
      return bindings;
    });
    this.#bindings.catch(() => { this.#bindings = undefined; });
    return this.#bindings;
  }
}
