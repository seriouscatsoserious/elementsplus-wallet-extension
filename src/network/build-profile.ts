/**
 * Compile-time wallet profile.
 *
 * Every extension artifact is built for exactly one network profile
 * (`scripts/build.mjs --profile <id>`); the build overwrites the compiled copy
 * of this module with that profile's frozen identity and `check-artifact.mjs`
 * verifies it. The source value below is only the fixture the unit tests run
 * against: the archived ECX Alpha identity, which no build can select.
 */
import { ECX_ALPHA_ARCHIVED_PROFILE, toWalletBuildProfile, type WalletBuildProfile } from "./profiles.js";

export type { WalletBuildProfile } from "./profiles.js";

export const BUILD_NETWORK_PROFILE: WalletBuildProfile = toWalletBuildProfile(ECX_ALPHA_ARCHIVED_PROFILE, {
  allowArchived: true,
});
