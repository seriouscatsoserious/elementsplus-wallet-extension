import { ECX_ALPHA_IDENTITY } from "./identity.js";

export type FetchImplementation = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface EcxAlphaEsploraOptions {
  readonly explorerUrl?: string;
  readonly fetchImpl?: FetchImplementation;
  readonly requestTimeoutMs?: number;
}

export interface VerifiedEcxAlphaIdentity {
  readonly genesisHash: string;
  readonly policyAssetId: string;
  readonly explorerApiUrl: string;
  readonly verifiedAt: string;
}

export interface EcxAlphaTip {
  readonly height: number;
  readonly hash: string;
  readonly timestamp: number;
  readonly transactionCount: number;
  readonly size: number;
  readonly weight: number;
  readonly previousBlockHash?: string;
}

export interface EcxAlphaMempool {
  readonly count: number;
  readonly virtualSize: number;
  readonly totalFeeAtomic: number;
  readonly feeHistogram: readonly (readonly [feeRate: number, virtualSize: number])[];
}

export interface EcxAlphaFeeEstimate {
  readonly confirmationTargetBlocks: number;
  readonly satsPerVbyte: number;
}

export interface EcxAlphaFeeStatus {
  readonly available: boolean;
  readonly estimates: readonly EcxAlphaFeeEstimate[];
}

export interface EcxAlphaNetworkStatus {
  readonly identity: VerifiedEcxAlphaIdentity;
  readonly tip: EcxAlphaTip;
  readonly mempool: EcxAlphaMempool;
  readonly fees: EcxAlphaFeeStatus;
  readonly sampledAt: string;
}

export interface EcxAlphaAddress {
  readonly confidential: boolean;
  readonly notation: "canonical" | "lwk-alias";
  readonly witnessVersion: number;
  readonly witnessProgramLength: number;
  readonly canonical: string;
  readonly alias: string;
}

export interface AddressTransactionStats {
  readonly fundedOutputCount: number;
  readonly spentOutputCount: number;
  readonly transactionCount: number;
}

export interface EcxAlphaAddressSummary {
  readonly address: EcxAlphaAddress;
  readonly chain: AddressTransactionStats;
  readonly mempool: AddressTransactionStats;
}

export const ECX_ALPHA_ADDRESS_HRPS = Object.freeze({
  canonical: Object.freeze({
    unconfidential: "elements",
    confidential: "elementsl",
  }),
  lwkAlias: Object.freeze({
    unconfidential: "ert",
    confidential: "el",
  }),
} as const);

/** HTTP/backend failure. This never represents a chain-identity mismatch. */
export class EcxAlphaApiError extends Error {
  override readonly name = "EcxAlphaApiError";
  readonly status: number | null;

  constructor(message: string, status: number | null = null, options?: ErrorOptions) {
    super(message, options);
    this.status = status;
  }
}

/** Fail-closed error raised when an explorer is not the pinned ECX Alpha chain. */
export class EcxAlphaIdentityError extends Error {
  override readonly name = "EcxAlphaIdentityError";
}

export class EcxAlphaAddressError extends Error {
  override readonly name = "EcxAlphaAddressError";
}

const HEX_32_BYTES = /^[0-9a-f]{64}$/u;
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const MAX_EXPLORER_RESPONSE_BYTES = 1024 * 1024;
const CHARSET_REVERSE = new Map(
  Array.from(CHARSET, (character, index) => [character, index] as const),
);

type AddressEncoding = "bech32" | "bech32m" | "blech32" | "blech32m";

interface ChecksumProfile {
  readonly checksumLength: number;
  readonly maximumLength: number;
  readonly shift: bigint;
  readonly mask: bigint;
  readonly legacyConstant: bigint;
  readonly modernConstant: bigint;
  readonly generators: readonly bigint[];
  readonly legacyName: AddressEncoding;
  readonly modernName: AddressEncoding;
}

const BECH32_PROFILE: ChecksumProfile = Object.freeze({
  checksumLength: 6,
  maximumLength: 90,
  shift: 25n,
  mask: 0x1ffffffn,
  legacyConstant: 1n,
  modernConstant: 0x2bc830a3n,
  generators: Object.freeze([
    0x3b6a57b2n,
    0x26508e6dn,
    0x1ea119fan,
    0x3d4233ddn,
    0x2a1462b3n,
  ]),
  legacyName: "bech32",
  modernName: "bech32m",
});

const BLECH32_PROFILE: ChecksumProfile = Object.freeze({
  checksumLength: 12,
  maximumLength: 1000,
  shift: 55n,
  mask: 0x7fffffffffffffn,
  legacyConstant: 1n,
  modernConstant: 0x455972a3350f7a1n,
  generators: Object.freeze([
    0x7d52fba40bd886n,
    0x5e8dbf1a03950cn,
    0x1c3a3c74072a18n,
    0x385d72fa0e5139n,
    0x7093e5a608865bn,
  ]),
  legacyName: "blech32",
  modernName: "blech32m",
});

interface DecodedAddress {
  readonly hrp: string;
  readonly values: readonly number[];
  readonly encoding: AddressEncoding;
  readonly profile: ChecksumProfile;
}

function hrpExpand(hrp: string): number[] {
  return [
    ...Array.from(hrp, (character) => character.charCodeAt(0) >> 5),
    0,
    ...Array.from(hrp, (character) => character.charCodeAt(0) & 31),
  ];
}

function polymod(values: readonly number[], profile: ChecksumProfile): bigint {
  let checksum = 1n;
  for (const value of values) {
    const high = checksum >> profile.shift;
    checksum = ((checksum & profile.mask) << 5n) ^ BigInt(value);
    for (let index = 0; index < profile.generators.length; index += 1) {
      if (((high >> BigInt(index)) & 1n) === 0n) continue;
      const generator = profile.generators[index];
      if (generator === undefined) throw new Error("missing checksum generator");
      checksum ^= generator;
    }
  }
  return checksum;
}

function addressProfile(hrp: string): {
  readonly profile: ChecksumProfile;
  readonly confidential: boolean;
  readonly notation: "canonical" | "lwk-alias";
} {
  if (hrp === ECX_ALPHA_ADDRESS_HRPS.canonical.unconfidential) {
    return { profile: BECH32_PROFILE, confidential: false, notation: "canonical" };
  }
  if (hrp === ECX_ALPHA_ADDRESS_HRPS.lwkAlias.unconfidential) {
    return { profile: BECH32_PROFILE, confidential: false, notation: "lwk-alias" };
  }
  if (hrp === ECX_ALPHA_ADDRESS_HRPS.canonical.confidential) {
    return { profile: BLECH32_PROFILE, confidential: true, notation: "canonical" };
  }
  if (hrp === ECX_ALPHA_ADDRESS_HRPS.lwkAlias.confidential) {
    return { profile: BLECH32_PROFILE, confidential: true, notation: "lwk-alias" };
  }
  throw new EcxAlphaAddressError(`unsupported ECX Alpha address prefix: ${hrp}`);
}

function decodeChecksummedAddress(address: string): DecodedAddress {
  if (address.length === 0) throw new EcxAlphaAddressError("address is empty");
  let sawLowercase = false;
  let sawUppercase = false;
  for (const character of address) {
    const code = character.charCodeAt(0);
    if (code < 33 || code > 126) {
      throw new EcxAlphaAddressError("address contains a non-printable character");
    }
    if (character >= "a" && character <= "z") sawLowercase = true;
    if (character >= "A" && character <= "Z") sawUppercase = true;
  }
  if (sawLowercase && sawUppercase) {
    throw new EcxAlphaAddressError("mixed-case witness address");
  }

  const normalized = address.toLowerCase();
  const separator = normalized.lastIndexOf("1");
  if (separator <= 0) throw new EcxAlphaAddressError("invalid witness address separator");
  const hrp = normalized.slice(0, separator);
  const { profile } = addressProfile(hrp);
  if (
    normalized.length > profile.maximumLength ||
    separator + 1 + profile.checksumLength > normalized.length
  ) {
    throw new EcxAlphaAddressError("invalid witness address length");
  }

  const encoded = normalized.slice(separator + 1);
  const allValues: number[] = [];
  for (const character of encoded) {
    const value = CHARSET_REVERSE.get(character);
    if (value === undefined) throw new EcxAlphaAddressError("invalid witness address character");
    allValues.push(value);
  }

  const checksum = polymod([...hrpExpand(hrp), ...allValues], profile);
  let encoding: AddressEncoding;
  if (checksum === profile.legacyConstant) encoding = profile.legacyName;
  else if (checksum === profile.modernConstant) encoding = profile.modernName;
  else throw new EcxAlphaAddressError("invalid witness address checksum");

  return {
    hrp,
    values: allValues.slice(0, -profile.checksumLength),
    encoding,
    profile,
  };
}

function encodeChecksummedAddress(
  hrp: string,
  values: readonly number[],
  encoding: AddressEncoding,
  profile: ChecksumProfile,
): string {
  const constant =
    encoding === profile.modernName ? profile.modernConstant : profile.legacyConstant;
  const expanded = [...hrpExpand(hrp), ...values];
  const padding = Array.from({ length: profile.checksumLength }, () => 0);
  const checksum = polymod([...expanded, ...padding], profile) ^ constant;
  const checksumValues = Array.from({ length: profile.checksumLength }, (_, index) =>
    Number((checksum >> BigInt(5 * (profile.checksumLength - 1 - index))) & 31n),
  );
  return `${hrp}1${[...values, ...checksumValues]
    .map((value) => CHARSET[value])
    .join("")}`;
}

function convertBits(
  values: readonly number[],
  fromBits: number,
  toBits: number,
  pad: boolean,
): number[] | null {
  let accumulator = 0;
  let bitCount = 0;
  const result: number[] = [];
  const maximumValue = (1 << toBits) - 1;
  const maximumAccumulator = (1 << (fromBits + toBits - 1)) - 1;

  for (const value of values) {
    if (value < 0 || value >> fromBits) return null;
    accumulator = ((accumulator << fromBits) | value) & maximumAccumulator;
    bitCount += fromBits;
    while (bitCount >= toBits) {
      bitCount -= toBits;
      result.push((accumulator >> bitCount) & maximumValue);
    }
  }

  if (pad && bitCount > 0) result.push((accumulator << (toBits - bitCount)) & maximumValue);
  if (!pad && (bitCount >= fromBits || ((accumulator << (toBits - bitCount)) & maximumValue))) {
    return null;
  }
  return result;
}

/**
 * Validate an ECX Alpha witness address and return both supported spellings.
 * Checksums are recomputed; this is deliberately not a textual prefix swap.
 */
export function resolveEcxAlphaAddress(address: string): EcxAlphaAddress {
  const decoded = decodeChecksummedAddress(address.trim());
  const details = addressProfile(decoded.hrp);
  const witnessVersion = decoded.values[0];
  if (witnessVersion === undefined || witnessVersion > 16) {
    throw new EcxAlphaAddressError("invalid witness version");
  }
  if (witnessVersion === 0 && decoded.encoding !== details.profile.legacyName) {
    throw new EcxAlphaAddressError("witness v0 requires the legacy checksum");
  }
  if (witnessVersion !== 0 && decoded.encoding !== details.profile.modernName) {
    throw new EcxAlphaAddressError("witness v1+ requires the modern checksum");
  }

  const decodedBytes = convertBits(decoded.values.slice(1), 5, 8, false);
  if (decodedBytes === null) throw new EcxAlphaAddressError("invalid witness address padding");
  const witnessProgram = details.confidential ? decodedBytes.slice(33) : decodedBytes;
  if (details.confidential && decodedBytes.length < 35) {
    throw new EcxAlphaAddressError("confidential address is missing its blinding public key");
  }
  if (witnessProgram.length < 2 || witnessProgram.length > 40) {
    throw new EcxAlphaAddressError("invalid witness program length");
  }
  if (witnessVersion === 0 && witnessProgram.length !== 20 && witnessProgram.length !== 32) {
    throw new EcxAlphaAddressError("witness v0 program must be 20 or 32 bytes");
  }

  const canonicalHrp = details.confidential
    ? ECX_ALPHA_ADDRESS_HRPS.canonical.confidential
    : ECX_ALPHA_ADDRESS_HRPS.canonical.unconfidential;
  const aliasHrp = details.confidential
    ? ECX_ALPHA_ADDRESS_HRPS.lwkAlias.confidential
    : ECX_ALPHA_ADDRESS_HRPS.lwkAlias.unconfidential;

  return Object.freeze({
    confidential: details.confidential,
    notation: details.notation,
    witnessVersion,
    witnessProgramLength: witnessProgram.length,
    canonical: encodeChecksummedAddress(
      canonicalHrp,
      decoded.values,
      decoded.encoding,
      decoded.profile,
    ),
    alias: encodeChecksummedAddress(aliasHrp, decoded.values, decoded.encoding, decoded.profile),
  });
}

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

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new EcxAlphaApiError(`${label} response is not an object`);
  }
  return value as Record<string, unknown>;
}

function nonNegativeNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new EcxAlphaApiError(`${label} is not a non-negative number`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  const parsed = nonNegativeNumber(value, label);
  if (!Number.isSafeInteger(parsed)) throw new EcxAlphaApiError(`${label} is not an integer`);
  return parsed;
}

function hash32(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX_32_BYTES.test(value)) {
    throw new EcxAlphaApiError(`${label} is not a 32-byte lowercase hex value`);
  }
  return value;
}

function transactionStats(value: unknown, label: string): AddressTransactionStats {
  const data = asRecord(value, label);
  return Object.freeze({
    fundedOutputCount: nonNegativeInteger(data["funded_txo_count"], `${label}.funded_txo_count`),
    spentOutputCount: nonNegativeInteger(data["spent_txo_count"], `${label}.spent_txo_count`),
    transactionCount: nonNegativeInteger(data["tx_count"], `${label}.tx_count`),
  });
}

async function boundedResponseText(response: Response): Promise<string> {
  const contentLength = response.headers.get("Content-Length");
  if (contentLength !== null) {
    if (!/^[0-9]+$/u.test(contentLength)) {
      throw new EcxAlphaApiError("ECX Alpha explorer returned an invalid Content-Length");
    }
    if (Number(contentLength) > MAX_EXPLORER_RESPONSE_BYTES) {
      throw new EcxAlphaApiError("ECX Alpha explorer response exceeds the 1 MiB limit");
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
      if (byteLength > MAX_EXPLORER_RESPONSE_BYTES) {
        await reader.cancel("response too large");
        throw new EcxAlphaApiError("ECX Alpha explorer response exceeds the 1 MiB limit");
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
    throw new EcxAlphaApiError("ECX Alpha explorer returned invalid UTF-8", null, {
      cause: error,
    });
  }
}

/**
 * Dependency-free, read-only client for an ECX Alpha-compatible Esplora API.
 * It intentionally exposes no transaction broadcast, RPC, signing, or DEX path.
 */
export class EcxAlphaEsploraClient {
  readonly explorerApiUrl: string;
  readonly requestTimeoutMs: number;
  private readonly fetchImpl: FetchImplementation;

  constructor(options: EcxAlphaEsploraOptions = {}) {
    this.explorerApiUrl = explorerApiUrl(options.explorerUrl ?? ECX_ALPHA_IDENTITY.explorerUrl);
    this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
    if (!Number.isSafeInteger(this.requestTimeoutMs) || this.requestTimeoutMs <= 0) {
      throw new TypeError("request timeout must be a positive integer");
    }

    const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (fetchImpl === undefined) throw new TypeError("Fetch API is unavailable");
    this.fetchImpl = fetchImpl;
  }

  private async getText(path: string): Promise<string> {
    const controller = new AbortController();
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
        throw new EcxAlphaApiError(
          `ECX Alpha explorer request failed (${response.status})`,
          response.status,
        );
      }
      return await boundedResponseText(response);
    } catch (error) {
      if (error instanceof EcxAlphaApiError) throw error;
      if (controller.signal.aborted) {
        throw new EcxAlphaApiError("ECX Alpha explorer request timed out", null, {
          cause: error,
        });
      }
      throw new EcxAlphaApiError("ECX Alpha explorer request failed", null, { cause: error });
    } finally {
      clearTimeout(timeout);
    }
  }

  private async getJson(path: string): Promise<unknown> {
    const body = await this.getText(path);
    try {
      return JSON.parse(body) as unknown;
    } catch (error) {
      throw new EcxAlphaApiError("ECX Alpha explorer returned invalid JSON", null, {
        cause: error,
      });
    }
  }

  /** Verify both immutable identity pins. Call before trusting any explorer data. */
  async verifyIdentity(): Promise<VerifiedEcxAlphaIdentity> {
    const policyAssetPath = `/asset/${ECX_ALPHA_IDENTITY.nativeAssetId}`;
    const [genesisBody, assetBody] = await Promise.all([
      this.getText("/block-height/0"),
      this.getJson(policyAssetPath),
    ]);

    const actualGenesis = genesisBody.trim();
    if (actualGenesis !== ECX_ALPHA_IDENTITY.genesisHash) {
      throw new EcxAlphaIdentityError(
        `wrong chain: expected genesis ${ECX_ALPHA_IDENTITY.genesisHash}, received ${actualGenesis}`,
      );
    }

    const asset = asRecord(assetBody, "policy asset");
    const actualAsset = asset["asset_id"];
    if (actualAsset !== ECX_ALPHA_IDENTITY.nativeAssetId) {
      throw new EcxAlphaIdentityError(
        `wrong policy asset: expected ${ECX_ALPHA_IDENTITY.nativeAssetId}`,
      );
    }

    return Object.freeze({
      genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
      policyAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      explorerApiUrl: this.explorerApiUrl,
      verifiedAt: new Date().toISOString(),
    });
  }

  async getTip(): Promise<EcxAlphaTip> {
    const hash = hash32((await this.getText("/blocks/tip/hash")).trim(), "tip hash");
    const block = asRecord(await this.getJson(`/block/${hash}`), "tip block");
    const returnedHash = hash32(block["id"], "tip block.id");
    if (returnedHash !== hash) throw new EcxAlphaApiError("tip block hash changed unexpectedly");

    const previous = block["previousblockhash"];
    return Object.freeze({
      height: nonNegativeInteger(block["height"], "tip block.height"),
      hash,
      timestamp: nonNegativeInteger(block["timestamp"], "tip block.timestamp"),
      transactionCount: nonNegativeInteger(block["tx_count"], "tip block.tx_count"),
      size: nonNegativeInteger(block["size"], "tip block.size"),
      weight: nonNegativeInteger(block["weight"], "tip block.weight"),
      ...(previous === undefined
        ? {}
        : { previousBlockHash: hash32(previous, "tip block.previousblockhash") }),
    });
  }

  async getMempool(): Promise<EcxAlphaMempool> {
    const mempool = asRecord(await this.getJson("/mempool"), "mempool");
    const rawHistogram = mempool["fee_histogram"];
    if (!Array.isArray(rawHistogram)) {
      throw new EcxAlphaApiError("mempool.fee_histogram is not an array");
    }
    const feeHistogram = rawHistogram.map((entry, index) => {
      if (!Array.isArray(entry) || entry.length !== 2) {
        throw new EcxAlphaApiError(`mempool.fee_histogram[${index}] is invalid`);
      }
      return Object.freeze([
        nonNegativeNumber(entry[0], `mempool.fee_histogram[${index}][0]`),
        nonNegativeNumber(entry[1], `mempool.fee_histogram[${index}][1]`),
      ] as const);
    });

    return Object.freeze({
      count: nonNegativeInteger(mempool["count"], "mempool.count"),
      virtualSize: nonNegativeInteger(mempool["vsize"], "mempool.vsize"),
      totalFeeAtomic: nonNegativeNumber(mempool["total_fee"], "mempool.total_fee"),
      feeHistogram: Object.freeze(feeHistogram),
    });
  }

  async getFeeStatus(): Promise<EcxAlphaFeeStatus> {
    const feeEstimates = asRecord(await this.getJson("/fee-estimates"), "fee estimates");
    const estimates: EcxAlphaFeeEstimate[] = [];
    for (const [target, feeRate] of Object.entries(feeEstimates)) {
      if (!/^[1-9][0-9]*$/u.test(target)) {
        throw new EcxAlphaApiError(`invalid fee-estimate target: ${target}`);
      }
      estimates.push(
        Object.freeze({
          confirmationTargetBlocks: Number(target),
          satsPerVbyte: nonNegativeNumber(feeRate, `fee estimate ${target}`),
        }),
      );
    }
    estimates.sort((left, right) =>
      left.confirmationTargetBlocks - right.confirmationTargetBlocks,
    );
    return Object.freeze({
      available: estimates.length > 0,
      estimates: Object.freeze(estimates),
    });
  }

  async getNetworkStatus(): Promise<EcxAlphaNetworkStatus> {
    const identity = await this.verifyIdentity();
    const [tip, mempool, fees] = await Promise.all([
      this.getTip(),
      this.getMempool(),
      this.getFeeStatus(),
    ]);
    return Object.freeze({
      identity,
      tip,
      mempool,
      fees,
      sampledAt: new Date().toISOString(),
    });
  }

  /** Query address counts using the canonical ECX spelling, accepting either input spelling. */
  async getAddressSummary(address: string): Promise<EcxAlphaAddressSummary> {
    const resolved = resolveEcxAlphaAddress(address);
    const response = asRecord(
      await this.getJson(`/address/${encodeURIComponent(resolved.canonical)}`),
      "address",
    );
    return Object.freeze({
      address: resolved,
      chain: transactionStats(response["chain_stats"], "address.chain_stats"),
      mempool: transactionStats(response["mempool_stats"], "address.mempool_stats"),
    });
  }
}
