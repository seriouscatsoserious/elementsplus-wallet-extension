import type { ExtensionStorageArea } from "./platform/browser.js";
import { ECX_ALPHA_IDENTITY } from "./network/identity.js";
import { base64ToBytes, bytesToBase64 } from "./shared/base64.js";
import { hasExactKeys, isPlainRecord, normalizeMnemonic, requireString, ValidationError } from "./shared/validation.js";

export const VAULT_STORAGE_KEY = "elementsplus.ecxAlpha.encryptedVault.v1";
export const VAULT_SCHEME = "pbkdf2-sha256-600k+a256gcm-v1";
export const PBKDF2_ITERATIONS = 600_000;

const AES_KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = 32 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
type CryptoBytes = Uint8Array<ArrayBuffer>;

export interface WalletVaultPayload {
  readonly schemaVersion: 1;
  readonly walletId: string;
  readonly mnemonic: string;
  readonly createdAt: string;
  readonly networkKey: typeof ECX_ALPHA_IDENTITY.key;
  readonly genesisHash: typeof ECX_ALPHA_IDENTITY.genesisHash;
  readonly explicitOutputsOnly: true;
}

export interface EncryptedVaultRecord {
  readonly scheme: typeof VAULT_SCHEME;
  readonly kdf: { readonly salt: string; readonly iterations: typeof PBKDF2_ITERATIONS };
  readonly wrappedKey: { readonly iv: string; readonly ciphertext: string };
  readonly payload: { readonly iv: string; readonly ciphertext: string };
}

export class VaultAuthenticationError extends Error {
  override readonly name = "VaultAuthenticationError";
  constructor() { super("Unable to unlock vault"); }
}

function randomBytes(provider: Crypto, length: number): CryptoBytes {
  return provider.getRandomValues(new Uint8Array(new ArrayBuffer(length)));
}

function passwordBytes(password: string): CryptoBytes {
  const bytes = encoder.encode(password);
  if (bytes.length < 12 || bytes.length > 1024) {
    bytes.fill(0);
    throw new ValidationError("password must contain between 12 and 1024 UTF-8 bytes");
  }
  return bytes;
}

async function deriveWrappingKey(provider: Crypto, password: string, salt: CryptoBytes): Promise<CryptoKey> {
  const bytes = passwordBytes(password);
  try {
    const material = await provider.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveKey"]);
    return provider.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    bytes.fill(0);
  }
}

function associatedData(purpose: "wrapped-key" | "payload"): CryptoBytes {
  return encoder.encode(`${VAULT_SCHEME}:${ECX_ALPHA_IDENTITY.genesisHash}:${purpose}`);
}

function decodeExact(value: string, field: string, length: number): CryptoBytes {
  const bytes = base64ToBytes(value, field, length);
  if (bytes.byteLength !== length) {
    bytes.fill(0);
    throw new ValidationError(`${field} has an invalid length`);
  }
  return bytes;
}

export function validateVaultPayload(value: unknown): WalletVaultPayload {
  if (
    !isPlainRecord(value)
    || !hasExactKeys(value, ["schemaVersion", "walletId", "mnemonic", "createdAt", "networkKey", "genesisHash", "explicitOutputsOnly"])
    || value["schemaVersion"] !== 1
    || value["networkKey"] !== ECX_ALPHA_IDENTITY.key
    || value["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || value["explicitOutputsOnly"] !== true
  ) throw new ValidationError("vault payload identity is malformed or unsupported");
  const walletId = requireString(value["walletId"], "walletId", 64);
  if (!/^[A-Za-z0-9_-]{22,64}$/.test(walletId)) throw new ValidationError("walletId is malformed");
  const createdAt = requireString(value["createdAt"], "createdAt", 32);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(createdAt)) {
    throw new ValidationError("createdAt is malformed");
  }
  return {
    schemaVersion: 1,
    walletId,
    mnemonic: normalizeMnemonic(requireString(value["mnemonic"], "mnemonic", 512)),
    createdAt,
    networkKey: ECX_ALPHA_IDENTITY.key,
    genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
    explicitOutputsOnly: true,
  };
}

export function validateEncryptedVaultRecord(value: unknown): EncryptedVaultRecord {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["scheme", "kdf", "wrappedKey", "payload"]) || value["scheme"] !== VAULT_SCHEME) {
    throw new ValidationError("encrypted vault record is malformed or unsupported");
  }
  const kdf = value["kdf"];
  const wrappedKey = value["wrappedKey"];
  const payload = value["payload"];
  if (
    !isPlainRecord(kdf) || !hasExactKeys(kdf, ["salt", "iterations"]) || kdf["iterations"] !== PBKDF2_ITERATIONS
    || !isPlainRecord(wrappedKey) || !hasExactKeys(wrappedKey, ["iv", "ciphertext"])
    || !isPlainRecord(payload) || !hasExactKeys(payload, ["iv", "ciphertext"])
  ) throw new ValidationError("encrypted vault record is malformed or unsupported");
  const salt = requireString(kdf["salt"], "kdf.salt", 128);
  const wrappedIv = requireString(wrappedKey["iv"], "wrappedKey.iv", 128);
  const wrappedCiphertext = requireString(wrappedKey["ciphertext"], "wrappedKey.ciphertext", 512);
  const payloadIv = requireString(payload["iv"], "payload.iv", 128);
  const payloadCiphertext = requireString(payload["ciphertext"], "payload.ciphertext", Math.ceil(MAX_CIPHERTEXT_BYTES / 3) * 4);
  decodeExact(salt, "kdf.salt", SALT_BYTES).fill(0);
  decodeExact(wrappedIv, "wrappedKey.iv", IV_BYTES).fill(0);
  decodeExact(wrappedCiphertext, "wrappedKey.ciphertext", AES_KEY_BYTES + 16).fill(0);
  decodeExact(payloadIv, "payload.iv", IV_BYTES).fill(0);
  const payloadBytes = base64ToBytes(payloadCiphertext, "payload.ciphertext", MAX_CIPHERTEXT_BYTES);
  if (payloadBytes.byteLength <= 16) {
    payloadBytes.fill(0);
    throw new ValidationError("payload.ciphertext is too short");
  }
  payloadBytes.fill(0);
  return {
    scheme: VAULT_SCHEME,
    kdf: { salt, iterations: PBKDF2_ITERATIONS },
    wrappedKey: { iv: wrappedIv, ciphertext: wrappedCiphertext },
    payload: { iv: payloadIv, ciphertext: payloadCiphertext },
  };
}

export async function encryptVault(value: WalletVaultPayload, password: string, provider: Crypto = globalThis.crypto): Promise<EncryptedVaultRecord> {
  const payload = validateVaultPayload(value);
  const salt = randomBytes(provider, SALT_BYTES);
  const wrappedKeyIv = randomBytes(provider, IV_BYTES);
  const payloadIv = randomBytes(provider, IV_BYTES);
  const dataKeyBytes = randomBytes(provider, AES_KEY_BYTES);
  const plaintext = encoder.encode(JSON.stringify(payload));
  try {
    const wrappingKey = await deriveWrappingKey(provider, password, salt);
    const dataKey = await provider.subtle.importKey("raw", dataKeyBytes, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const wrapped = await provider.subtle.encrypt(
      { name: "AES-GCM", iv: wrappedKeyIv, additionalData: associatedData("wrapped-key"), tagLength: 128 },
      wrappingKey,
      dataKeyBytes,
    );
    const encrypted = await provider.subtle.encrypt(
      { name: "AES-GCM", iv: payloadIv, additionalData: associatedData("payload"), tagLength: 128 },
      dataKey,
      plaintext,
    );
    return {
      scheme: VAULT_SCHEME,
      kdf: { salt: bytesToBase64(salt), iterations: PBKDF2_ITERATIONS },
      wrappedKey: { iv: bytesToBase64(wrappedKeyIv), ciphertext: bytesToBase64(new Uint8Array(wrapped)) },
      payload: { iv: bytesToBase64(payloadIv), ciphertext: bytesToBase64(new Uint8Array(encrypted)) },
    };
  } finally {
    dataKeyBytes.fill(0);
    plaintext.fill(0);
  }
}

export async function decryptVault(value: unknown, password: string, provider: Crypto = globalThis.crypto): Promise<WalletVaultPayload> {
  const record = validateEncryptedVaultRecord(value);
  const salt = decodeExact(record.kdf.salt, "kdf.salt", SALT_BYTES);
  const wrappedIv = decodeExact(record.wrappedKey.iv, "wrappedKey.iv", IV_BYTES);
  const wrappedCiphertext = decodeExact(record.wrappedKey.ciphertext, "wrappedKey.ciphertext", AES_KEY_BYTES + 16);
  const payloadIv = decodeExact(record.payload.iv, "payload.iv", IV_BYTES);
  const payloadCiphertext = base64ToBytes(record.payload.ciphertext, "payload.ciphertext", MAX_CIPHERTEXT_BYTES);
  let dataKeyBytes: CryptoBytes | undefined;
  let plaintext: CryptoBytes | undefined;
  try {
    const wrappingKey = await deriveWrappingKey(provider, password, salt);
    dataKeyBytes = new Uint8Array(await provider.subtle.decrypt(
      { name: "AES-GCM", iv: wrappedIv, additionalData: associatedData("wrapped-key"), tagLength: 128 },
      wrappingKey,
      wrappedCiphertext,
    ));
    const dataKey = await provider.subtle.importKey("raw", dataKeyBytes, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    plaintext = new Uint8Array(await provider.subtle.decrypt(
      { name: "AES-GCM", iv: payloadIv, additionalData: associatedData("payload"), tagLength: 128 },
      dataKey,
      payloadCiphertext,
    ));
    return validateVaultPayload(JSON.parse(decoder.decode(plaintext)) as unknown);
  } catch (error) {
    if (error instanceof ValidationError && error.message.startsWith("password must")) throw error;
    throw new VaultAuthenticationError();
  } finally {
    salt.fill(0);
    wrappedCiphertext.fill(0);
    payloadCiphertext.fill(0);
    dataKeyBytes?.fill(0);
    plaintext?.fill(0);
  }
}

export class VaultStore {
  constructor(private readonly storage: ExtensionStorageArea) {}
  async exists(): Promise<boolean> {
    return (await this.storage.get(VAULT_STORAGE_KEY))[VAULT_STORAGE_KEY] !== undefined;
  }
  async read(): Promise<EncryptedVaultRecord> {
    const value = (await this.storage.get(VAULT_STORAGE_KEY))[VAULT_STORAGE_KEY];
    if (value === undefined) throw new ValidationError("wallet vault has not been created");
    return validateEncryptedVaultRecord(value);
  }
  async write(record: EncryptedVaultRecord): Promise<void> {
    if (await this.exists()) throw new ValidationError("wallet vault already exists; refusing to overwrite it");
    await this.storage.set({ [VAULT_STORAGE_KEY]: validateEncryptedVaultRecord(record) });
  }
}
