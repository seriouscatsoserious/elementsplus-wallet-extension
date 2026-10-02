// `npm run build`: build and check one artifact per buildable network profile.
//
// Public profiles that are still pending (sidechain genesis, pegged asset and
// Esplora not yet published) are reported and skipped, never guessed. The
// disposable regtest artifact is always built: against the local chain in
// .regtest/network.json when one exists, otherwise against the synthetic CI
// fixture so the WASM, packaging and artifact checks stay exercised.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { missingPins, NETWORK_PROFILES } from "../src/network/profiles.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function run(script, args) {
  const result = spawnSync(process.execPath, [path.join("scripts", script), ...args], { cwd: root, stdio: "inherit" });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const pending = [];
for (const profile of NETWORK_PROFILES) {
  if (profile.kind !== "public" || profile.status === "archived") continue;
  if (profile.status === "pending") {
    pending.push(profile);
    continue;
  }
  run("build-wasm.mjs", ["--profile", profile.id]);
  run("build.mjs", ["--profile", profile.id]);
  run("check-artifact.mjs", ["--profile", profile.id]);
}

const localNetwork = path.join(root, ".regtest", "network.json");
const networkFile = existsSync(localNetwork)
  ? localNetwork
  : path.join(root, "scripts", "fixtures", "ci-regtest-network.json");
process.stdout.write(`Building elementsplus-regtest against ${path.relative(root, networkFile)}\n`);
run("build-regtest.mjs", ["--network-file", networkFile]);
run("check-artifact.mjs", ["--profile", "elementsplus-regtest"]);

for (const profile of pending) {
  process.stdout.write(
    `PENDING ${profile.id} (${profile.displayName}): not built; missing ${missingPins(profile).join(", ")}. `
    + "See docs/NETWORKS.md.\n",
  );
}
