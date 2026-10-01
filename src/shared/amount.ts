/** Decimal-string ↔ atomic BigInt conversion. Never uses floating point. */

export const MAX_U64 = 18_446_744_073_709_551_615n;
export const MAX_PRECISION = 8;

/** Fee presets in sat/vB (integers, spec §3.1). */
export const FEE_PRESETS = Object.freeze({
  slow: Object.freeze({ label: "Slow", satPerVbyte: 1 }),
  standard: Object.freeze({ label: "Standard", satPerVbyte: 2 }),
  fast: Object.freeze({ label: "Fast", satPerVbyte: 5 }),
} as const);
export type FeePreset = keyof typeof FEE_PRESETS;
export const DEFAULT_FEE_PRESET: FeePreset = "standard";

export class AmountError extends Error {
  override readonly name = "AmountError";
}

function checkPrecision(precision: number): void {
  if (!Number.isSafeInteger(precision) || precision < 0 || precision > MAX_PRECISION) {
    throw new AmountError("asset precision must be an integer from 0 to 8");
  }
}

/**
 * Parse user input such as "1,234.5" into atomic units. Accepts an optional
 * thousands separator (",", " " or "_") and a single "." decimal point.
 */
export function parseDecimalAmount(input: string, precision: number): bigint {
  checkPrecision(precision);
  const text = input.trim().replace(/[,_ ]/gu, "");
  if (text.length === 0) throw new AmountError("Enter an amount");
  if (text.length > 40) throw new AmountError("Amount is too long");
  const match = /^([0-9]*)(?:\.([0-9]*))?$/u.exec(text);
  if (match === null || (match[1] === "" && (match[2] ?? "") === "")) throw new AmountError("Amount must be a positive number");
  const whole = match[1] === "" ? "0" : match[1]!;
  const fraction = match[2] ?? "";
  if (fraction.length > precision) {
    throw new AmountError(precision === 0 ? "This asset has no decimal places" : `Use at most ${precision} decimal places`);
  }
  const atomic = BigInt(whole) * 10n ** BigInt(precision) + BigInt(fraction.padEnd(precision, "0") || "0");
  if (atomic > MAX_U64) throw new AmountError("Amount is too large");
  return atomic;
}

function group(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/gu, ",");
}

export interface FormatOptions {
  /** Keep at least this many fractional digits (default 0 = trim trailing zeros). */
  readonly minFraction?: number;
  /** Insert thousands separators (default true). */
  readonly grouping?: boolean;
  /** Prefix "+" for positive values (default false). */
  readonly signed?: boolean;
}

/** Format atomic units as a decimal string using the asset precision. */
export function formatAtomic(value: bigint | string, precision: number, options: FormatOptions = {}): string {
  checkPrecision(precision);
  let atomic = typeof value === "bigint" ? value : BigInt(value);
  const negative = atomic < 0n;
  if (negative) atomic = -atomic;
  const scale = 10n ** BigInt(precision);
  const whole = (atomic / scale).toString();
  let fraction = precision === 0 ? "" : (atomic % scale).toString().padStart(precision, "0");
  const minFraction = Math.min(options.minFraction ?? 0, precision);
  while (fraction.length > minFraction && fraction.endsWith("0")) fraction = fraction.slice(0, -1);
  const body = `${options.grouping === false ? whole : group(whole)}${fraction === "" ? "" : `.${fraction}`}`;
  const sign = negative ? "−" : options.signed === true && atomic !== 0n ? "+" : "";
  return `${sign}${body}`;
}

/** Plain machine-readable decimal (no grouping, ASCII minus) for input fields. */
export function atomicToDecimalInput(value: bigint, precision: number): string {
  return formatAtomic(value, precision, { grouping: false }).replace("−", "-");
}

/**
 * Conservative explicit-Elements size estimate for a transfer (P2WPKH inputs,
 * recipient + two change outputs + fee output). Used only for display and the
 * "Use max" suggestion; the core computes the real fee.
 */
export function estimateTransferVbytes(inputCount: number): number {
  const inputs = Math.max(1, inputCount);
  return 24 + inputs * 110 + 3 * 80 + 50;
}

export function estimateFeeAtomic(inputCount: number, satPerVbyte: number): bigint {
  return BigInt(estimateTransferVbytes(inputCount)) * BigInt(Math.max(1, Math.trunc(satPerVbyte)));
}
