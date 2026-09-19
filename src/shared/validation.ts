export type JsonRecord = Record<string, unknown>;

export class ValidationError extends Error {
  override readonly name = "ValidationError";
}

export function isPlainRecord(value: unknown): value is JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

export function hasExactKeys(
  value: JsonRecord,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

export function requireString(value: unknown, field: string, maximumLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw new ValidationError(`${field} must contain between 1 and ${maximumLength} characters`);
  }
  return value;
}

export function normalizeMnemonic(value: string): string {
  const mnemonic = value.normalize("NFKD").trim().replace(/\s+/g, " ");
  const words = mnemonic.split(" ");
  if (
    ![12, 15, 18, 21, 24].includes(words.length)
    || words.some((word) => !/^[a-z]{2,16}$/.test(word))
  ) {
    throw new ValidationError("recovery phrase has an invalid shape");
  }
  return mnemonic;
}
