// Shared `--profile <id>` handling for the build scripts. The registry is the
// erasable-TypeScript source module itself (Node >= 24 strips types), so the
// scripts and the extension can never disagree about a profile.
import { NetworkProfileError, SELECTABLE_PROFILE_IDS, selectableProfile } from "../src/network/profiles.ts";

export function profileArgument(argv, fallback = process.env["ELEMENTSPLUS_NETWORK_PROFILE"]) {
  const index = argv.indexOf("--profile");
  const inline = argv.find((argument) => argument.startsWith("--profile="));
  const value = index >= 0 ? argv[index + 1] : inline?.slice("--profile=".length) ?? fallback;
  if (value === undefined || value === "" || value.startsWith("--")) {
    process.stderr.write(`Choose a network profile: --profile <${SELECTABLE_PROFILE_IDS.join("|")}>\n`);
    process.exit(2);
  }
  return value;
}

/** Resolve a buildable profile or exit with the registry's explanation. */
export function refuseUnselectable(id) {
  try {
    return selectableProfile(id);
  } catch (error) {
    if (!(error instanceof NetworkProfileError)) throw error;
    process.stderr.write(`Refusing to build: ${error.message}\n`);
    process.exit(3);
  }
}
