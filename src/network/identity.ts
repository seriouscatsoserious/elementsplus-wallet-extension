import { BUILD_NETWORK_PROFILE } from "./build-profile.js";

export const ECX_ALPHA_IDENTITY = Object.freeze({ ...BUILD_NETWORK_PROFILE });

export type EcxAlphaIdentity = typeof ECX_ALPHA_IDENTITY;

export function abbreviatedHash(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("identity hash must be 32-byte lowercase hex");
  }
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}
