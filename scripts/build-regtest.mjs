import { spawnSync } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const stateDirectory = path.join(root, ".regtest");
const networkPath = path.join(stateDirectory, "network.json");
const profilePath = path.join(stateDirectory, "build-profile.json");
const wasmDirectory = path.join(root, ".wasm-bindgen-regtest");
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
  throw new Error(".regtest/network.json has invalid chain parameters");
}
const explorer = new URL(network.explorerUrl);
if (explorer.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(explorer.hostname)) {
  throw new Error("regtest explorer must be an HTTP loopback URL");
}

const profile = Object.freeze({
  mode: "elementsplus-regtest",
  key: `elementsplus-regtest-${network.genesisHash.slice(0, 12)}`,
  displayName: "Elements+ LOCAL REGTEST",
  implementation: "Elements+ functional-test node",
  sidechainSlot: 24,
  genesisHash: network.genesisHash,
  nativeAssetId: network.nativeAssetId,
  parentGenesisHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  bech32Hrp: "ert",
  blech32Hrp: "el",
  aliasBech32Hrp: "elements",
  aliasBlech32Hrp: "elementsl",
  explorerUrl: explorer.origin,
  transactionPolicy: "explicit-only",
});

await mkdir(stateDirectory, { recursive: true });
await writeFile(profilePath, `${JSON.stringify(profile, null, 2)}\n`, "utf8");
run(process.execPath, ["scripts/build-wasm.mjs"], {
  ELEMENTSPLUS_WASM_FEATURES: "wasm,regtest",
  ELEMENTSPLUS_WASM_OUTPUT: wasmDirectory,
});
run(process.execPath, ["scripts/build.mjs"], {
  ELEMENTSPLUS_BUILD_PROFILE: profilePath,
  ELEMENTSPLUS_DIST: outputDirectory,
  ELEMENTSPLUS_TARGETS: "chromium",
  ELEMENTSPLUS_WASM_DIR: wasmDirectory,
});

const extensionDirectory = path.join(outputDirectory, "chromium");
const manifest = JSON.parse(await readFile(path.join(extensionDirectory, "manifest.json"), "utf8"));
if (!manifest.name.includes("LOCAL REGTEST") || manifest.host_permissions?.[0] !== `${explorer.origin}/*`) {
  throw new Error("regtest extension manifest was not isolated from the production artifact");
}
const bindingsPath = path.join(extensionDirectory, "src", "wasm", "elementsplus_wallet_core.js");
const wasmPath = path.join(extensionDirectory, "src", "wasm", "elementsplus_wallet_core_bg.wasm");
const bindings = await import(`${pathToFileURL(bindingsPath).href}?regtest=${Date.now()}`);
bindings.initSync({ module: await readFile(wasmPath) });
if (typeof bindings.WasmWalletCore.forRegtest !== "function") {
  throw new Error("regtest WASM does not expose its test-only constructor");
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
