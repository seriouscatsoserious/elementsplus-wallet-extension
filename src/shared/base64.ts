import { ValidationError } from "./validation.js";

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.length)));
  }
  return btoa(binary);
}

export function base64ToBytes(encoded: string, field: string, maximumBytes: number): Uint8Array<ArrayBuffer> {
  if (
    encoded.length === 0
    || encoded.length > Math.ceil(maximumBytes / 3) * 4
    || !BASE64_PATTERN.test(encoded)
  ) {
    throw new ValidationError(`${field} is not canonical base64`);
  }
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    throw new ValidationError(`${field} is not canonical base64`);
  }
  if (binary.length > maximumBytes) throw new ValidationError(`${field} exceeds its size limit`);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (bytesToBase64(bytes) !== encoded) throw new ValidationError(`${field} is not canonical base64`);
  return bytes;
}
