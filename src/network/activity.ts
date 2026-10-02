/**
 * Wallet activity from Esplora `/address/:addr/txs` (Liquid/electrs JSON).
 *
 * DISPLAY-ONLY: this data comes straight from the configured explorer and is
 * not verified by the wallet core. It must never be used to build or approve
 * transactions, and the UI must not label it as verified.
 *
 * Confidential wallet outputs carry no explicit asset/value in Esplora JSON.
 * When an `unblind` callback is supplied (the unlocked session unblinds them
 * locally with the wallet core), their amounts are filled in and the entry is
 * marked `confidential`; otherwise they stay uncounted (`complete: false`).
 */
import type { FetchImplementation } from "./esplora.js";
import { esploraApiBase, fetchJson } from "./http.js";
import { isPlainRecord } from "../shared/validation.js";

const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX = /^(?:[0-9a-f]{2})*$/u;
export const ESPLORA_CHAIN_PAGE = 25;
const MAX_PAGES_PER_ADDRESS = 8;

export interface EsploraOutput {
  readonly scriptPubKeyHex: string;
  readonly address: string | null;
  readonly type: string;
  /** null when the output is confidential (no explicit asset/value). */
  readonly assetId: string | null;
  readonly value: bigint | null;
}

export interface EsploraInput {
  readonly txid: string;
  readonly vout: number;
  readonly isCoinbase: boolean;
  readonly prevout: EsploraOutput | null;
  readonly issuance: { readonly assetId: string; readonly isReissuance: boolean } | null;
}

export interface EsploraTx {
  readonly txid: string;
  readonly confirmed: boolean;
  readonly blockHeight: number | null;
  readonly blockTime: number | null;
  readonly vin: readonly EsploraInput[];
  readonly vout: readonly EsploraOutput[];
}

export type ActivityKind = "received" | "sent" | "self" | "swap" | "issuance";

export interface ActivityEntry {
  readonly txid: string;
  readonly kind: ActivityKind;
  readonly confirmed: boolean;
  readonly blockHeight: number | null;
  readonly blockTime: number | null;
  /** Net change per asset, excluding a fee this wallet paid. Signed decimal strings. */
  readonly deltas: readonly { readonly assetId: string; readonly amount: string }[];
  /** Fee in the policy asset when this wallet funded every input, else null. */
  readonly fee: string | null;
  readonly counterparty: string | null;
  readonly issuedAssetId: string | null;
  /** False if some wallet-relevant amounts were confidential and could not be counted. */
  readonly complete: boolean;
  /** Present (true) only when some wallet amount was confidential and was unblinded locally. */
  readonly confidential?: true;
}

/** Locally unblinded wallet outputs keyed by `txid:vout`. */
export type UnblindedOutputs = ReadonlyMap<string, { readonly assetId: string; readonly valueAtomic: string }>;

export type ConfidentialUnblinder = (
  refs: readonly { readonly txid: string; readonly vout: number; readonly scriptPubKeyHex: string }[],
) => Promise<UnblindedOutputs>;

export class ActivityParseError extends Error {
  override readonly name = "ActivityParseError";
}

function fail(message: string): never {
  throw new ActivityParseError(message);
}

function int(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) fail(`${label} is not a non-negative integer`);
  return value;
}

function hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX_32.test(value)) fail(`${label} is not a 32-byte hex value`);
  return value;
}

function parseOutput(value: unknown, label: string): EsploraOutput {
  if (!isPlainRecord(value)) fail(`${label} is not an object`);
  const script = value["scriptpubkey"];
  if (typeof script !== "string" || script.length > 20_000 || !HEX.test(script)) fail(`${label}.scriptpubkey is malformed`);
  const address = value["scriptpubkey_address"];
  const type = value["scriptpubkey_type"];
  // Values beyond 2^53 cannot survive JSON.parse exactly: count them as unknown.
  const hasValue = typeof value["value"] === "number" && Number.isSafeInteger(value["value"]) && value["value"] >= 0;
  const hasAsset = typeof value["asset"] === "string";
  return Object.freeze({
    scriptPubKeyHex: script,
    address: typeof address === "string" && address.length <= 200 ? address : null,
    type: typeof type === "string" ? type.slice(0, 32) : "unknown",
    assetId: hasValue && hasAsset ? hash(value["asset"], `${label}.asset`) : null,
    value: hasValue && hasAsset ? BigInt(int(value["value"], `${label}.value`)) : null,
  });
}

export function parseEsploraTx(value: unknown): EsploraTx {
  if (!isPlainRecord(value)) fail("transaction is not an object");
  const txid = hash(value["txid"], "txid");
  const status = value["status"];
  if (!isPlainRecord(status) || typeof status["confirmed"] !== "boolean") fail(`${txid} status is malformed`);
  const confirmed = status["confirmed"];
  const vin = value["vin"];
  const vout = value["vout"];
  if (!Array.isArray(vin) || !Array.isArray(vout) || vin.length > 10_000 || vout.length > 10_000) {
    fail(`${txid} inputs or outputs are malformed`);
  }
  return Object.freeze({
    txid,
    confirmed,
    blockHeight: confirmed ? int(status["block_height"], "block_height") : null,
    blockTime: confirmed ? int(status["block_time"], "block_time") : null,
    vin: Object.freeze(vin.map((raw, index): EsploraInput => {
      if (!isPlainRecord(raw)) fail(`${txid} vin ${index} is malformed`);
      const isCoinbase = raw["is_coinbase"] === true;
      const issuance = raw["issuance"];
      return Object.freeze({
        txid: isCoinbase ? "0".repeat(64) : hash(raw["txid"], `vin ${index} txid`),
        vout: isCoinbase ? 0 : int(raw["vout"], `vin ${index} vout`),
        isCoinbase,
        prevout: raw["prevout"] === null || raw["prevout"] === undefined ? null : parseOutput(raw["prevout"], `vin ${index} prevout`),
        issuance: isPlainRecord(issuance) && typeof issuance["asset_id"] === "string" && HEX_32.test(issuance["asset_id"])
          ? Object.freeze({ assetId: issuance["asset_id"], isReissuance: issuance["is_reissuance"] === true })
          : null,
      });
    })),
    vout: Object.freeze(vout.map((raw, index) => parseOutput(raw, `${txid} vout ${index}`))),
  });
}

/** Compute the wallet-relative view of one transaction. */
export function computeActivity(
  tx: EsploraTx,
  walletScripts: ReadonlySet<string>,
  policyAsset: string,
  unblinded: UnblindedOutputs = new Map(),
): ActivityEntry {
  const totals = new Map<string, bigint>();
  const add = (assetId: string, amount: bigint) => totals.set(assetId, (totals.get(assetId) ?? 0n) + amount);
  let complete = true;
  let confidential = false;
  // Explorer amounts, or the locally unblinded ones for confidential outputs.
  const amountOf = (output: EsploraOutput, outpoint: string): { assetId: string; value: bigint } | null => {
    if (output.assetId !== null && output.value !== null) return { assetId: output.assetId, value: output.value };
    const known = unblinded.get(outpoint);
    if (known === undefined) return null;
    confidential = true;
    return { assetId: known.assetId, value: BigInt(known.valueAtomic) };
  };
  let ownInputs = 0;
  let foreignInputs = 0;
  let issuedAssetId: string | null = null;
  for (const input of tx.vin) {
    if (input.prevout !== null && walletScripts.has(input.prevout.scriptPubKeyHex)) {
      ownInputs += 1;
      const spent = amountOf(input.prevout, `${input.txid}:${input.vout}`);
      if (spent === null) complete = false;
      else add(spent.assetId, -spent.value);
      if (input.issuance !== null && !input.issuance.isReissuance) issuedAssetId = input.issuance.assetId;
    } else {
      foreignInputs += 1;
    }
  }
  let fee = 0n;
  for (const [index, output] of tx.vout.entries()) {
    if (output.type === "fee") {
      if (output.assetId === policyAsset && output.value !== null) fee += output.value;
      continue;
    }
    if (walletScripts.has(output.scriptPubKeyHex)) {
      const received = amountOf(output, `${tx.txid}:${index}`);
      if (received === null) complete = false;
      else add(received.assetId, received.value);
    }
  }
  const paidFee = ownInputs > 0 && foreignInputs === 0;
  if (paidFee && fee > 0n) add(policyAsset, fee);
  const deltas = [...totals.entries()]
    .filter(([, amount]) => amount !== 0n)
    .sort(([left, a], [right, b]) => (a < 0n) !== (b < 0n) ? (a < 0n ? 1 : -1) : left.localeCompare(right))
    .map(([assetId, amount]) => Object.freeze({ assetId, amount: amount.toString() }));
  const hasPositive = deltas.some((delta) => !delta.amount.startsWith("-"));
  const hasNegative = deltas.some((delta) => delta.amount.startsWith("-"));
  let kind: ActivityKind;
  if (ownInputs === 0) kind = "received";
  else if (issuedAssetId !== null) kind = "issuance";
  else if (foreignInputs > 0 || (hasPositive && hasNegative)) kind = "swap";
  else if (!hasNegative) kind = "self";
  else kind = "sent";
  let counterparty: string | null = null;
  if (kind === "received") {
    counterparty = tx.vin.find((input) => input.prevout?.address != null)?.prevout?.address ?? null;
  } else if (kind === "sent") {
    counterparty = tx.vout.find((output) => output.type !== "fee" && !walletScripts.has(output.scriptPubKeyHex) && output.address !== null)?.address ?? null;
  }
  return Object.freeze({
    txid: tx.txid,
    kind,
    confirmed: tx.confirmed,
    blockHeight: tx.blockHeight,
    blockTime: tx.blockTime,
    deltas: Object.freeze(deltas),
    fee: paidFee ? fee.toString() : null,
    counterparty,
    issuedAssetId,
    complete,
    ...(confidential ? { confidential: true as const } : {}),
  });
}

/** Wallet outputs and spent wallet prevouts whose explorer amounts are confidential. */
export function confidentialWalletOutputs(
  txs: readonly EsploraTx[],
  walletScripts: ReadonlySet<string>,
): { txid: string; vout: number; scriptPubKeyHex: string }[] {
  const refs = new Map<string, { txid: string; vout: number; scriptPubKeyHex: string }>();
  const hidden = (output: EsploraOutput) =>
    walletScripts.has(output.scriptPubKeyHex) && (output.assetId === null || output.value === null);
  for (const tx of txs) {
    for (const [vout, output] of tx.vout.entries()) {
      if (output.type !== "fee" && hidden(output)) refs.set(`${tx.txid}:${vout}`, { txid: tx.txid, vout, scriptPubKeyHex: output.scriptPubKeyHex });
    }
    for (const input of tx.vin) {
      if (input.prevout !== null && hidden(input.prevout)) {
        refs.set(`${input.txid}:${input.vout}`, { txid: input.txid, vout: input.vout, scriptPubKeyHex: input.prevout.scriptPubKeyHex });
      }
    }
  }
  return [...refs.values()];
}

/** Fetch every page of an address's history (bounded). */
export async function fetchAddressTransactions(
  explorerUrl: string,
  address: string,
  fetchImpl: FetchImplementation,
  maxPages = MAX_PAGES_PER_ADDRESS,
): Promise<EsploraTx[]> {
  const api = esploraApiBase(explorerUrl);
  const result: EsploraTx[] = [];
  let url = `${api}/address/${encodeURIComponent(address)}/txs`;
  for (let page = 0; page < maxPages; page += 1) {
    const body = await fetchJson(url, { fetchImpl, maxBytes: 4 * 1024 * 1024 });
    if (!Array.isArray(body)) fail("address history is not a list");
    const txs = body.map(parseEsploraTx);
    result.push(...txs);
    const confirmed = txs.filter((tx) => tx.confirmed);
    if (confirmed.length < ESPLORA_CHAIN_PAGE) break;
    url = `${api}/address/${encodeURIComponent(address)}/txs/chain/${confirmed[confirmed.length - 1]!.txid}`;
  }
  return result;
}

export interface LoadActivityOptions {
  readonly explorerUrl: string;
  readonly addresses: readonly { readonly address: string; readonly scriptPubKeyHex: string }[];
  readonly policyAsset: string;
  readonly fetchImpl: FetchImplementation;
  readonly limit?: number;
  /** Unblind confidential wallet amounts locally (unlocked session only). */
  readonly unblind?: ConfidentialUnblinder;
}

/** Merge per-address histories into wallet activity, newest first (pending on top). */
export async function loadActivity(options: LoadActivityOptions): Promise<ActivityEntry[]> {
  const scripts = new Set(options.addresses.map((entry) => entry.scriptPubKeyHex));
  const byTxid = new Map<string, EsploraTx>();
  const queue = [...options.addresses];
  const workers = Array.from({ length: Math.min(4, queue.length) }, async () => {
    for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
      for (const tx of await fetchAddressTransactions(options.explorerUrl, next.address, options.fetchImpl)) {
        const known = byTxid.get(tx.txid);
        if (known === undefined || (!known.confirmed && tx.confirmed)) byTxid.set(tx.txid, tx);
      }
    }
  });
  await Promise.all(workers);
  const txs = [...byTxid.values()];
  let unblinded: UnblindedOutputs = new Map();
  const hidden = options.unblind === undefined ? [] : confidentialWalletOutputs(txs, scripts);
  if (options.unblind !== undefined && hidden.length > 0) {
    try {
      unblinded = await options.unblind(hidden);
    } catch {
      // Display-only: confidential amounts simply stay uncounted.
    }
  }
  return sortActivity(txs.map((tx) => computeActivity(tx, scripts, options.policyAsset, unblinded)))
    .slice(0, options.limit ?? 200);
}

export function sortActivity(entries: ActivityEntry[]): ActivityEntry[] {
  return entries.sort((left, right) => {
    if (left.confirmed !== right.confirmed) return left.confirmed ? 1 : -1;
    const height = (right.blockHeight ?? 0) - (left.blockHeight ?? 0);
    return height !== 0 ? height : left.txid.localeCompare(right.txid);
  });
}
