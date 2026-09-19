#!/usr/bin/env node

import assert from "node:assert/strict";
import { rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

if (process.env.ECX_ALPHA_LIVE_TEST !== "1") {
  console.log("Skipped live ECX Alpha smoke test (set ECX_ALPHA_LIVE_TEST=1 to run).");
  process.exit(0);
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

  const networkModule = await import(
    pathToFileURL(join(buildDirectory, "src", "network", "ecx-alpha.js")).href
  );
  const identityModule = await import(
    pathToFileURL(join(buildDirectory, "src", "network", "identity.js")).href
  );
  const { EcxAlphaEsploraClient, resolveEcxAlphaAddress } = networkModule;
  const { ECX_ALPHA_IDENTITY } = identityModule;

  const client = new EcxAlphaEsploraClient();
  const status = await client.getNetworkStatus();

  assert.equal(status.identity.genesisHash, ECX_ALPHA_IDENTITY.genesisHash);
  assert.equal(status.identity.policyAssetId, ECX_ALPHA_IDENTITY.nativeAssetId);
  assert(status.tip.height >= 0);
  assert(/^[0-9a-f]{64}$/u.test(status.tip.hash));

  const alias = "ert1qw508d6qejxtdg4y5r3zarvary0c5xw7kuu73e0";
  const address = resolveEcxAlphaAddress(alias);
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
