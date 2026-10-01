/**
 * Wallet operations (what a user or dApp asks for), request validation, and
 * the exact-request checks every core review must pass before it is shown or
 * signed. A review that does not match the request is rejected outright.
 */
import {
  HEX_32,
  MAX_U64,
  parseSwapOffer,
  type DecodedOffer,
  type PreparedTx,
  type SwapOffer,
  type TxReview,
} from "../adapters/wallet-core.js";
import { resolveEcxAlphaAddress } from "../network/ecx-alpha.js";
import { FEE_PRESETS } from "../shared/amount.js";
import { hasExactKeys, isPlainRecord, ValidationError } from "../shared/validation.js";

export const MIN_FEE_RATE = 1;
export const MAX_FEE_RATE = 1_000;
/** Upper bound on vbytes used to sanity-check a core-computed fee. */
const MAX_FEE_VBYTES = 100_000n;
const MAX_OFFERS = 20;

export type WalletOperation =
  | { readonly kind: "transfer"; readonly assetId: string; readonly recipient: string; readonly amount: string; readonly feeRate: number }
  | { readonly kind: "issuance"; readonly name: string; readonly ticker: string; readonly precision: number;
      readonly amount: string; readonly tokenAmount: string; readonly feeRate: number }
  | { readonly kind: "swap_offer"; readonly giveAsset: string; readonly giveAmount: string; readonly wantAsset: string;
      readonly wantAmount: string; readonly feeRate: number }
  | { readonly kind: "swap_take"; readonly offers: readonly SwapOffer[]; readonly feeRate: number }
  | { readonly kind: "cancel"; readonly txid: string; readonly vout: number; readonly feeRate: number };

/** Extra facts the session learned while preparing (used by the checks). */
export interface PreparedPlan {
  readonly prepared: PreparedTx;
  /** swap_offer only: the exact UTXO offered directly, or null when a split runs first. */
  readonly offeredOutpoint?: string | null;
  /** swap_offer with split: wallet receive index whose output becomes the offered UTXO. */
  readonly splitReceiveIndex?: number;
  /** swap_take only: core-decoded offers (verified against their prevout transactions). */
  readonly decodedOffers?: readonly DecodedOffer[];
}

function amount(value: unknown, field: string, allowZero = false): string {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value) || BigInt(value) > MAX_U64) {
    throw new ValidationError(`${field} must be a decimal string of atomic units`);
  }
  if (!allowZero && value === "0") throw new ValidationError(`${field} must be greater than zero`);
  return value;
}

function asset(value: unknown, field: string): string {
  if (typeof value !== "string" || !HEX_32.test(value)) throw new ValidationError(`${field} must be a 32-byte hex asset id`);
  return value;
}

export function feeRate(value: unknown): number {
  if (value === undefined) return FEE_PRESETS.standard.satPerVbyte;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < MIN_FEE_RATE || value > MAX_FEE_RATE) {
    throw new ValidationError(`feeRate must be an integer from ${MIN_FEE_RATE} to ${MAX_FEE_RATE} sat/vB`);
  }
  return value;
}

export function explicitAddress(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 200) throw new ValidationError(`${field} is malformed`);
  let resolved;
  try {
    resolved = resolveEcxAlphaAddress(value.trim());
  } catch {
    throw new ValidationError(`${field} is not a valid address on this network`);
  }
  if (resolved.confidential) throw new ValidationError(`${field} must be an explicit (non-confidential) address`);
  return resolved.canonical;
}

function exact(raw: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  if (!hasExactKeys(raw, required, optional)) throw new ValidationError("request contains unexpected or missing fields");
}

/** Validate a UI/dApp operation into its canonical form. */
export function validateOperation(raw: unknown): WalletOperation {
  if (!isPlainRecord(raw) || typeof raw["kind"] !== "string") throw new ValidationError("operation is malformed");
  switch (raw["kind"]) {
    case "transfer":
      exact(raw, ["kind", "assetId", "recipient", "amount"], ["feeRate"]);
      return Object.freeze({
        kind: "transfer",
        assetId: asset(raw["assetId"], "assetId"),
        recipient: explicitAddress(raw["recipient"], "recipient"),
        amount: amount(raw["amount"], "amount"),
        feeRate: feeRate(raw["feeRate"]),
      });
    case "issuance": {
      exact(raw, ["kind", "name", "ticker", "precision", "amount", "tokenAmount"], ["feeRate"]);
      const name = raw["name"];
      const ticker = raw["ticker"];
      const precision = raw["precision"];
      if (typeof name !== "string" || name.trim().length === 0 || name.length > 64 || /[\u0000-\u001f\u007f‪-‮⁦-⁩]/u.test(name)) {
        throw new ValidationError("name must be 1–64 printable characters");
      }
      if (typeof ticker !== "string" || !/^[A-Za-z0-9.-]{3,24}$/u.test(ticker)) {
        throw new ValidationError("ticker must be 3–24 letters, digits, '.' or '-'");
      }
      if (typeof precision !== "number" || !Number.isSafeInteger(precision) || precision < 0 || precision > 8) {
        throw new ValidationError("precision must be an integer from 0 to 8");
      }
      return Object.freeze({
        kind: "issuance",
        name: name.trim(),
        ticker,
        precision,
        amount: amount(raw["amount"], "amount"),
        tokenAmount: amount(raw["tokenAmount"], "tokenAmount", true),
        feeRate: feeRate(raw["feeRate"]),
      });
    }
    case "swap_offer": {
      exact(raw, ["kind", "giveAsset", "giveAmount", "wantAsset", "wantAmount"], ["feeRate"]);
      const giveAsset = asset(raw["giveAsset"], "giveAsset");
      const wantAsset = asset(raw["wantAsset"], "wantAsset");
      if (giveAsset === wantAsset) throw new ValidationError("giveAsset and wantAsset must differ");
      return Object.freeze({
        kind: "swap_offer",
        giveAsset,
        giveAmount: amount(raw["giveAmount"], "giveAmount"),
        wantAsset,
        wantAmount: amount(raw["wantAmount"], "wantAmount"),
        feeRate: feeRate(raw["feeRate"]),
      });
    }
    case "swap_take": {
      exact(raw, ["kind", "offers"], ["feeRate"]);
      const offers = raw["offers"];
      if (!Array.isArray(offers) || offers.length === 0 || offers.length > MAX_OFFERS) {
        throw new ValidationError(`offers must contain 1–${MAX_OFFERS} offers`);
      }
      let parsed: SwapOffer[];
      try {
        parsed = offers.map((offer) => parseSwapOffer(typeof offer === "string" ? JSON.parse(offer) as unknown : offer));
      } catch {
        throw new ValidationError("offers contain a malformed offer");
      }
      if (new Set(parsed.map((offer) => offer.tx)).size !== parsed.length) throw new ValidationError("offers contain duplicates");
      return Object.freeze({ kind: "swap_take", offers: Object.freeze(parsed), feeRate: feeRate(raw["feeRate"]) });
    }
    case "cancel": {
      exact(raw, ["kind", "txid", "vout"], ["feeRate"]);
      const vout = raw["vout"];
      if (typeof vout !== "number" || !Number.isSafeInteger(vout) || vout < 0 || vout > 0xffff_ffff) {
        throw new ValidationError("vout must be an output index");
      }
      return Object.freeze({ kind: "cancel", txid: asset(raw["txid"], "txid"), vout, feeRate: feeRate(raw["feeRate"]) });
    }
    default:
      throw new ValidationError("operation kind is unsupported");
  }
}

export interface ReviewContext {
  readonly genesisHash: string;
  readonly policyAsset: string;
}

function deltas(review: TxReview): Map<string, bigint> {
  return new Map(review.balanceChanges.map((delta) => [delta.assetId, BigInt(delta.amount)]));
}

function expectDeltas(review: TxReview, expected: ReadonlyMap<string, bigint>): void {
  const actual = deltas(review);
  for (const [assetId, value] of actual) if (value !== 0n && expected.get(assetId) !== value) {
    throw new ValidationError("review balance changes do not match the request");
  }
  for (const [assetId, value] of expected) if (value !== 0n && actual.get(assetId) !== value) {
    throw new ValidationError("review balance changes do not match the request");
  }
}

function add(map: Map<string, bigint>, assetId: string, value: bigint): void {
  map.set(assetId, (map.get(assetId) ?? 0n) + value);
}

function expectFee(review: TxReview, rate: number, allowZero = false): void {
  const fee = BigInt(review.fee);
  if ((!allowZero && fee === 0n) || fee > BigInt(rate) * MAX_FEE_VBYTES) throw new ValidationError("review fee is out of range");
}

/**
 * Exact-request validation: the core's review of the PSET must express exactly
 * the requested effect. Called by the controller for every prepared plan.
 */
export function checkReview(operation: WalletOperation, plan: PreparedPlan, context: ReviewContext): void {
  const review = plan.prepared.review;
  if (review.genesisHash !== context.genesisHash) throw new ValidationError("review is for a different network");
  if (review.inputsSigned.length === 0) throw new ValidationError("review signs no wallet inputs");
  const sighashFor = (kind: TxReview["kind"]) => kind === "swap_offer" ? "SINGLE|ANYONECANPAY" : "ALL";
  if (review.sighash !== sighashFor(review.kind)) throw new ValidationError("review sighash does not match its kind");
  switch (operation.kind) {
    case "transfer": {
      if (review.kind !== "transfer" || review.issuance !== null || review.foreignInputs.length !== 0) {
        throw new ValidationError("review is not a plain transfer");
      }
      const [output, ...rest] = review.externalOutputs;
      if (
        output === undefined || rest.length !== 0
        || output.address !== operation.recipient
        || output.assetId !== operation.assetId
        || output.amount !== operation.amount
      ) throw new ValidationError("review recipient does not match the request");
      expectFee(review, operation.feeRate);
      expectDeltas(review, new Map([[operation.assetId, -BigInt(operation.amount)]]));
      return;
    }
    case "issuance": {
      const issuance = review.issuance;
      if (
        review.kind !== "issuance" || issuance === null || review.externalOutputs.length !== 0 || review.foreignInputs.length !== 0
        || issuance.amount !== operation.amount || issuance.tokenAmount !== operation.tokenAmount
        || (operation.tokenAmount === "0") !== (issuance.tokenId === null)
      ) throw new ValidationError("review is not the requested issuance");
      expectFee(review, operation.feeRate);
      const expected = new Map([[issuance.assetId, BigInt(operation.amount)]]);
      if (issuance.tokenId !== null) expected.set(issuance.tokenId, BigInt(operation.tokenAmount));
      expectDeltas(review, expected);
      return;
    }
    case "swap_offer": {
      if (plan.offeredOutpoint === null) {
        // Split first: a pure self-send that only reshapes wallet coins.
        if (review.kind !== "offer_split" || review.externalOutputs.length !== 0 || review.foreignInputs.length !== 0 || review.issuance !== null) {
          throw new ValidationError("review is not the requested offer preparation");
        }
        expectFee(review, operation.feeRate);
        expectDeltas(review, new Map());
        return;
      }
      checkSwapOfferReview(operation, review, plan.offeredOutpoint ?? "");
      return;
    }
    case "swap_take": {
      const offers = plan.decodedOffers ?? [];
      if (
        review.kind !== "swap_take" || review.issuance !== null || offers.length !== operation.offers.length
        || review.foreignInputs.length !== offers.length
      ) throw new ValidationError("review is not the requested swap");
      const foreign = new Set(review.foreignInputs);
      const expected = new Map<string, bigint>();
      const unmatched = [...review.externalOutputs];
      for (const offer of offers) {
        if (!foreign.has(offer.outpoint)) throw new ValidationError("review does not spend the offered inputs");
        add(expected, offer.giveAsset, BigInt(offer.giveAmount));
        add(expected, offer.wantAsset, -BigInt(offer.wantAmount));
        const index = unmatched.findIndex((output) =>
          output.address === offer.makerAddress && output.assetId === offer.wantAsset && output.amount === offer.wantAmount);
        if (index === -1) throw new ValidationError("review does not pay the offer makers exactly");
        unmatched.splice(index, 1);
      }
      if (unmatched.length !== 0) throw new ValidationError("review pays an unexpected recipient");
      expectFee(review, operation.feeRate);
      expectDeltas(review, expected);
      return;
    }
    case "cancel": {
      const outpoint = `${operation.txid}:${operation.vout}`;
      if (
        review.kind !== "cancel" || review.externalOutputs.length !== 0 || review.foreignInputs.length !== 0
        || review.issuance !== null || !review.inputsSigned.includes(outpoint)
      ) throw new ValidationError("review is not the requested cancellation");
      expectFee(review, operation.feeRate);
      expectDeltas(review, new Map());
      return;
    }
  }
}

/** Check the offer review (direct, or the second stage after a split). */
export function checkSwapOfferReview(
  operation: Extract<WalletOperation, { kind: "swap_offer" }>,
  review: TxReview,
  offeredOutpoint: string,
): void {
  if (
    review.kind !== "swap_offer" || review.sighash !== "SINGLE|ANYONECANPAY" || review.issuance !== null
    || review.foreignInputs.length !== 0 || review.externalOutputs.length !== 0
    || review.inputsSigned.length !== 1 || review.inputsSigned[0] !== offeredOutpoint || review.fee !== "0"
  ) throw new ValidationError("review is not the requested swap offer");
  expectDeltas(review, new Map([
    [operation.giveAsset, -BigInt(operation.giveAmount)],
    [operation.wantAsset, BigInt(operation.wantAmount)],
  ]));
}

/** First input outpoint of a serialized Elements transaction (offers have exactly one). */
export function firstInputOutpoint(txHex: string): string {
  if (!/^(?:[0-9a-f]{2})+$/u.test(txHex) || txHex.length < 2 * 46) throw new ValidationError("offer transaction is malformed");
  const bytes = txHex.match(/../gu)!.map((byte) => parseInt(byte, 16));
  // version (4) | witness flag (1) | vin count varint | prev txid (32, LE) | prev vout (4, LE)
  if (bytes[5] !== 1) throw new ValidationError("offer transaction must have exactly one input");
  const txid = bytes.slice(6, 38).reverse().map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const vout = (bytes[38]! | (bytes[39]! << 8) | (bytes[40]! << 16) | (bytes[41]! << 24)) >>> 0;
  // Elements reuses the top two bits of the index for issuance/peg-in flags.
  return `${txid}:${vout & 0x3fff_ffff}`;
}
