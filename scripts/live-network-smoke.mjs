#!/usr/bin/env node

import assert from "node:assert/strict";
import { rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { NetworkProfileError, selectableProfile, toWalletBuildProfile } from "../src/network/profiles.ts";

const profileId = process.env.ECX_LIVE_PROFILE ?? "ecx-beta";
if (process.env.ECX_LIVE_TEST !== "1") {
  console.log(`Skipped live ${profileId} smoke test (set ECX_LIVE_TEST=1 to run).`);
  process.exit(0);
}
let profile;
try {
  profile = toWalletBuildProfile(selectableProfile(profileId));
} catch (error) {
  if (!(error instanceof NetworkProfileError)) throw error;
  console.error(`Cannot run the live smoke test: ${error.message}`);
  process.exit(3);
}

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const extensionRoot = join(scriptDirectory, "..");
const compiler = join(extensionRoot, "node_modules", "typescript", "bin", "tsc");
const buildDirectory = mkdtempSync(join(tmpdir(), "elementsplus-live-smoke-"));

try {
  const compile = spawnSync(
    process.execPath,
    [
      compiler,
      "--project",
      join(extensionRoot, "tsconfig.json"),
      "--outDir",
      buildDirectory,
      "--noEmit",
      "false",
    ],
    { cwd: extensionRoot, encoding: "utf8" },
  );
  if (compile.status !== 0) {
    process.stderr.write(compile.stdout ?? "");
    process.stderr.write(compile.stderr ?? "");
    throw new Error("Unable to compile the live smoke-test fixture");
  }

  writeFileSync(
    join(buildDirectory, "src", "network", "build-profile.js"),
    `export const BUILD_NETWORK_PROFILE = Object.freeze(${JSON.stringify(profile)});\n`,
  );
  const networkModule = await import(
    pathToFileURL(join(buildDirectory, "src", "network", "esplora.js")).href
  );
  const identityModule = await import(
    pathToFileURL(join(buildDirectory, "src", "network", "identity.js")).href
  );
  const { EcxEsploraClient, resolveEcxAddress } = networkModule;
  const { NETWORK_IDENTITY } = identityModule;

  const client = new EcxEsploraClient();
  const status = await client.getNetworkStatus();

  assert.equal(status.identity.genesisHash, NETWORK_IDENTITY.genesisHash);
  assert.equal(status.identity.policyAssetId, NETWORK_IDENTITY.nativeAssetId);
  assert(status.tip.height >= 0);
  assert(/^[0-9a-f]{64}$/u.test(status.tip.hash));

  // LWK alias spelling of a fixed witness program (v11 alias HRP is `ert`).
  const alias = "ert1qw508d6qejxtdg4y5r3zarvary0c5xw7kuu73e0";
  const address = resolveEcxAddress(alias);
  const summary = await client.getAddressSummary(alias);
  assert.equal(summary.address.canonical, address.canonical);

  console.log(
    JSON.stringify(
      {
        ok: true,
        explorer: status.identity.explorerApiUrl,
        genesis: status.identity.genesisHash,
        policyAsset: status.identity.policyAssetId,
        tip: status.tip,
        mempool: status.mempool,
        fees: status.fees,
        aliasLookup: {
          alias,
          canonical: address.canonical,
          transactions: summary.chain.transactionCount,
        },
      },
      null,
      2,
    ),
  );
} finally {
  rmSync(buildDirectory, { recursive: true, force: true });
}
