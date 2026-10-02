import { BUILD_NETWORK_PROFILE } from "./build-profile.js";

/** The single network identity compiled into this artifact. */
export const NETWORK_IDENTITY = Object.freeze({ ...BUILD_NETWORK_PROFILE });

export type NetworkIdentity = typeof NETWORK_IDENTITY;

export function abbreviatedHash(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("identity hash must be 32-byte lowercase hex");
  }
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}
