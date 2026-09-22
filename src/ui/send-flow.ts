import type { TransferSummary } from "../adapters/lwk.js";
import { resolveEcxAlphaAddress } from "../network/ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "../network/identity.js";
import { hasExactKeys, isPlainRecord } from "../shared/validation.js";

const MAX_U64 = 18_446_744_073_709_551_615n;
const HASH_32_BYTES = /^[0-9a-f]{64}$/u;
const APPROVAL_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const POSITIVE_CANONICAL_DECIMAL = /^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{0,7}[1-9])?$/u;

export interface SendDraft {
  readonly assetId: string;
  readonly destination: string;
  readonly amountAtomic: string;
  readonly feeRate: string;
}

export interface PreparedSendApproval {
  readonly approvalToken: string;
  readonly expiresAt: string;
  readonly summaryHash: string;
  readonly summary: TransferSummary;
}

export interface BroadcastTransactionResult {
  readonly txid: string;
  readonly settlement: "broadcast" | "preconfirmed";
}

export class SendFlowValidationError extends Error {
  override readonly name = "SendFlowValidationError";
}

function fail(message: string): never {
  throw new SendFlowValidationError(message);
}

function positiveAtomicAmount(value: string): string {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) fail("Amount must be a canonical whole number of atomic units");
  const amount = BigInt(value);
  if (amount === 0n) fail("Amount must be greater than zero");
  if (amount > MAX_U64) fail("Amount is too large");
  return value;
}

function positiveFeeRate(value: string): string {
  if (!POSITIVE_CANONICAL_DECIMAL.test(value) || value === "0") {
    fail("Fee rate must be a positive canonical decimal");
  }
  return value;
}

function explicitCanonicalAddress(value: string): string {
  let address: ReturnType<typeof resolveEcxAlphaAddress>;
  try {
    address = resolveEcxAlphaAddress(value);
  } catch {
    fail("Destination is not a valid ECX Alpha address");
  }
  if (address.confidential) fail("Destination must be an explicit ECX Alpha address");
  return address.canonical;
}

export function parseSendDraft(input: {
  readonly destination: string;
  readonly amountAtomic: string;
  readonly feeRate: string;
}): SendDraft {
  return Object.freeze({
    assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
    destination: explicitCanonicalAddress(input.destination),
    amountAtomic: positiveAtomicAmount(input.amountAtomic),
    feeRate: positiveFeeRate(input.feeRate),
  });
}

function parseTransferSummary(value: unknown): TransferSummary {
  if (!isPlainRecord(value) || !hasExactKeys(value, [
    "kind", "networkKey", "genesisHash", "assetId", "destination", "amountAtomic",
    "networkFeeAssetId", "networkFeeAtomic", "feeRate", "transactionPolicy",
  ])) fail("Prepared transaction summary is malformed");
  if (
    value["kind"] !== "transfer"
    || value["networkKey"] !== ECX_ALPHA_IDENTITY.key
    || value["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || value["assetId"] !== ECX_ALPHA_IDENTITY.nativeAssetId
    || value["networkFeeAssetId"] !== ECX_ALPHA_IDENTITY.nativeAssetId
    || value["transactionPolicy"] !== "explicit-only"
    || typeof value["destination"] !== "string"
    || typeof value["amountAtomic"] !== "string"
    || typeof value["networkFeeAtomic"] !== "string"
    || typeof value["feeRate"] !== "string"
  ) fail("Prepared transaction summary has the wrong network, asset, or policy");

  const destination = explicitCanonicalAddress(value["destination"]);
  const amountAtomic = positiveAtomicAmount(value["amountAtomic"]);
  const networkFeeAtomic = positiveAtomicAmount(value["networkFeeAtomic"]);
  const feeRate = positiveFeeRate(value["feeRate"]);
  return Object.freeze({
    kind: "transfer",
    networkKey: ECX_ALPHA_IDENTITY.key,
    genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
    assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
    destination,
    amountAtomic,
    networkFeeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
    networkFeeAtomic,
    feeRate,
    transactionPolicy: "explicit-only",
  });
}

export function parsePreparedSendApproval(
  value: unknown,
  requested: SendDraft,
  nowMilliseconds = Date.now(),
): PreparedSendApproval {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["approvalToken", "expiresAt", "summaryHash", "summary"])) {
    fail("Prepared transaction response is malformed");
  }
  if (typeof value["approvalToken"] !== "string" || !APPROVAL_TOKEN.test(value["approvalToken"])) {
    fail("Prepared transaction approval token is malformed");
  }
  if (typeof value["summaryHash"] !== "string" || !HASH_32_BYTES.test(value["summaryHash"])) {
    fail("Prepared transaction summary hash is malformed");
  }
  if (typeof value["expiresAt"] !== "string") fail("Prepared transaction expiry is malformed");
  const expiresAtMilliseconds = Date.parse(value["expiresAt"]);
  if (!Number.isFinite(expiresAtMilliseconds) || new Date(expiresAtMilliseconds).toISOString() !== value["expiresAt"]) {
    fail("Prepared transaction expiry is malformed");
  }
  if (expiresAtMilliseconds <= nowMilliseconds) fail("Prepared transaction approval has already expired");

  const summary = parseTransferSummary(value["summary"]);
  if (
    summary.assetId !== requested.assetId
    || summary.destination !== requested.destination
    || summary.amountAtomic !== requested.amountAtomic
    || summary.feeRate !== requested.feeRate
  ) fail("Prepared transaction does not match the requested transfer");

  return Object.freeze({
    approvalToken: value["approvalToken"],
    expiresAt: value["expiresAt"],
    summaryHash: value["summaryHash"],
    summary,
  });
}

export function parseBroadcastTransactionResult(value: unknown): BroadcastTransactionResult {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["txid", "settlement"]) || typeof value["txid"] !== "string" || !HASH_32_BYTES.test(value["txid"])
    || (value["settlement"] !== "broadcast" && value["settlement"] !== "preconfirmed")) {
    fail("Broadcast response contains a malformed transaction ID");
  }
  return Object.freeze({ txid: value["txid"], settlement: value["settlement"] });
}
