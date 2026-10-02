import { spawnSync } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ELEMENTSPLUS_REGTEST_PROFILE, toWalletBuildProfile } from "../src/network/profiles.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const stateDirectory = path.join(root, ".regtest");
// `--network-file <path>` builds against other local chain parameters (CI uses
// scripts/fixtures/ci-regtest-network.json when no local chain exists).
const networkFlag = process.argv.indexOf("--network-file");
const networkPath = path.resolve(networkFlag >= 0 ? process.argv[networkFlag + 1] : path.join(stateDirectory, "network.json"));
const profilePath = path.join(stateDirectory, "build-profile.json");
const outputDirectory = path.join(stateDirectory, "dist");
const hash = /^[0-9a-f]{64}$/u;

function run(command, args, environment = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: "pipe",
    env: { ...process.env, ...environment },
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    process.exit(result.status ?? 1);
  }
  if (result.stdout) process.stdout.write(result.stdout);
}

await access(networkPath);
const network = JSON.parse(await readFile(networkPath, "utf8"));
if (!hash.test(network.genesisHash) || !hash.test(network.nativeAssetId)) {
  throw new Error(`${networkPath} has invalid chain parameters`);
}
const explorer = new URL(network.explorerUrl);
if (explorer.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(explorer.hostname)) {
  throw new Error("regtest explorer must be an HTTP loopback URL");
}

const profile = toWalletBuildProfile(ELEMENTSPLUS_REGTEST_PROFILE, {
  local: {
    genesisHash: network.genesisHash,
    nativeAssetId: network.nativeAssetId,
    explorerUrl: explorer.origin,
    dexUrl: typeof network.dexUrl === "string" ? network.dexUrl : "",
  },
});

await mkdir(stateDirectory, { recursive: true });
await writeFile(profilePath, `${JSON.stringify(profile, null, 2)}\n`, "utf8");
run(process.execPath, ["scripts/build-wasm.mjs", "--profile", profile.id]);
run(process.execPath, ["scripts/build.mjs", "--profile", profile.id], {
  ELEMENTSPLUS_BUILD_PROFILE: profilePath,
  ELEMENTSPLUS_TARGETS: "chromium",
});

const extensionDirectory = path.join(outputDirectory, "chromium");
const manifest = JSON.parse(await readFile(path.join(extensionDirectory, "manifest.json"), "utf8"));
if (!manifest.name.includes(profile.displayName) || !manifest.description.includes("DISPOSABLE")
  || manifest.host_permissions?.[0] !== `${explorer.origin}/*`) {
  throw new Error("regtest extension manifest was not isolated from the production artifact");
}
const bindingsPath = path.join(extensionDirectory, "src", "wasm", "elementsplus_wallet_core.js");
const wasmPath = path.join(extensionDirectory, "src", "wasm", "elementsplus_wallet_core_bg.wasm");
const bindings = await import(`${pathToFileURL(bindingsPath).href}?regtest=${Date.now()}`);
bindings.initSync({ module: await readFile(wasmPath) });
if (typeof bindings.WasmWalletCore.forRegtest !== "function") {
  throw new Error("regtest WASM does not expose its test-only constructor");
}
if (bindings.network_profile_id() !== profile.id) {
  throw new Error(`regtest WASM was compiled for ${bindings.network_profile_id()}, not ${profile.id}`);
}
const core = bindings.WasmWalletCore.forRegtest(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  network.genesisHash,
  network.nativeAssetId,
  profile.displayName,
);
try {
  const derived = JSON.parse(core.derive_address_json("external", 0));
  if (typeof derived.native_address !== "string" || !derived.native_address.startsWith("ert1")) {
    throw new Error("regtest WASM derived an address for the wrong network");
  }
} finally {
  core.free();
}

process.stdout.write(`Regtest extension ready: ${extensionDirectory}\n`);
