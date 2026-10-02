import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { profileArgument, refuseUnselectable } from "./profile-args.mjs";
import { toWalletBuildProfile } from "../src/network/profiles.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// Checks the artifact built for exactly one network profile.
const profile = refuseUnselectable(profileArgument(process.argv.slice(2)));
const regtest = profile.kind === "local-regtest";
const artifactRoot = path.join(root, regtest ? ".regtest/dist" : "dist");
const targets = regtest ? ["chromium"] : ["chromium", "firefox"];
const required = [
  "manifest.json",
  "src/background/service-worker.js",
  "src/network/esplora.js",
  "src/wasm/elementsplus_wallet_core.js",
  "src/wasm/elementsplus_wallet_core_bg.wasm",
  "src/ui/wallet.html",
  "src/ui/wallet.js",
  "src/ui/preview.html",
  "src/ui/preview.js",
  "src/ui/wallet.css",
  "src/ui/approve.html",
  "src/ui/approve.js",
  "src/content/content-script.js",
  "src/content/inpage.js",
  "src/ui/fonts/Geist-Variable.woff2",
  "src/ui/fonts/GeistMono-Variable.woff2",
  "src/ui/fonts/LICENSE-Geist-OFL.txt",
];
const pageMatches = ["http://*/*", "https://*/*"];
const expectedContentScripts = [{
  matches: pageMatches,
  js: ["src/content/content-script.js"],
  run_at: "document_start",
  all_frames: false,
}];
const expectedWebAccessible = [{ resources: ["src/content/inpage.js"], matches: pageMatches }];
const allowedExtensions = new Set([".css", ".html", ".js", ".json", ".wasm", ".woff2", ".txt"]);
const maximumArtifactBytes = 12 * 1024 * 1024;
const forbiddenSource = [
  [/(?:^|[^a-z])eval\s*\(/iu, "eval"],
  [/new\s+Function\s*\(/u, "new Function"],
  [/\.innerHTML\s*=/u, "innerHTML assignment"],
  [/storage\.sync/u, "synchronized extension storage"],
  [/<script[^>]+src=["']https?:\/\//iu, "remote script"],
];

async function listFiles(directory) {
  const result = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await listFiles(absolute));
    else if (entry.isFile()) result.push(absolute);
    else throw new Error(`Artifact contains a non-regular entry: ${absolute}`);
  }
  return result;
}

const walletCoreDigests = [];
for (const target of targets) {
  const directory = path.join(artifactRoot, target);
  for (const relative of required) {
    const file = path.join(directory, relative);
    if (!(await stat(file)).isFile()) throw new Error(`Missing artifact: ${target}/${relative}`);
  }
  const { BUILD_NETWORK_PROFILE: compiled } = await import(
    `${pathToFileURL(path.join(directory, "src", "network", "build-profile.js")).href}?${target}`
  );
  if (compiled?.id !== profile.id || !Object.isFrozen(compiled)) {
    throw new Error(`${target} artifact is compiled for ${compiled?.id}, not ${profile.id}`);
  }
  if (!regtest && !isDeepStrictEqual({ ...compiled }, { ...toWalletBuildProfile(profile) })) {
    throw new Error(`${target} compiled identity differs from the ${profile.id} registry pins`);
  }
  const explorerOrigin = new URL(compiled.explorerUrl).origin;
  const expectedHosts = [`${explorerOrigin}/*`];
  const manifest = JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8"));
  if (manifest.name !== `Elements+ Wallet — ${compiled.displayName}` || JSON.stringify(manifest).includes("{{")) {
    throw new Error(`${target} manifest is not labelled for ${compiled.displayName}`);
  }
  if (manifest.manifest_version !== 3 || manifest.permissions.join(",") !== "storage") {
    throw new Error(`${target} manifest has an unexpected permission surface`);
  }
  if (manifest.action?.default_popup !== "src/ui/wallet.html") {
    throw new Error(`${target} must open the reviewed wallet surface directly`);
  }
  if (JSON.stringify(manifest.host_permissions) !== JSON.stringify(expectedHosts)) {
    throw new Error(`${target} manifest must grant only the profile's explorer host`);
  }
  if ("optional_host_permissions" in manifest || "externally_connectable" in manifest) {
    throw new Error(`${target} manifest exposes an unexpected extension boundary`);
  }
  // The dApp provider (spec §3.3) is the only page-facing boundary: one
  // isolated-world bridge and one web-accessible page script, top frame only.
  if (JSON.stringify(manifest.content_scripts) !== JSON.stringify(expectedContentScripts)) {
    throw new Error(`${target} manifest content scripts differ from the reviewed provider bridge`);
  }
  if (JSON.stringify(manifest.web_accessible_resources) !== JSON.stringify(expectedWebAccessible)) {
    throw new Error(`${target} manifest exposes unexpected web-accessible resources`);
  }
  for (const name of ["content-script.js", "inpage.js"]) {
    const source = await readFile(path.join(directory, "src", "content", name), "utf8");
    if (/^\s*(?:import|export)\b/mu.test(source) || /chrome\.storage|browser\.storage|WasmWalletCore/u.test(source)) {
      throw new Error(`${target}/src/content/${name} must be a classic script with no wallet or storage access`);
    }
  }
  const csp = manifest.content_security_policy?.extension_pages;
  if (
    typeof csp !== "string"
    || !csp.includes("default-src 'none'")
    || !csp.includes("script-src 'self' 'wasm-unsafe-eval'")
    || !csp.includes(`connect-src ${explorerOrigin} `)
    || !csp.includes("font-src 'self'")
    || /\b(?:ws|wss):/u.test(csp)
    || csp.includes("'unsafe-inline'")
    || csp.includes("'unsafe-eval'")
  ) {
    throw new Error(`${target} manifest CSP is not fail-closed`);
  }
  for (const name of ["wallet.html", "approve.html", "preview.html"]) {
    const html = await readFile(path.join(directory, "src", "ui", name), "utf8");
    if (/\sstyle\s*=/iu.test(html) || /<script(?![^>]*\bsrc=)[^>]*>/iu.test(html)) {
      throw new Error(`${target}/${name} contains CSP-blocked inline content`);
    }
  }
  const css = await readFile(path.join(directory, "src", "ui", "wallet.css"), "utf8");
  if (/gradient\s*\(/iu.test(css)) throw new Error(`${target} UI contains a forbidden gradient`);
  const preview = await readFile(path.join(directory, "src", "ui", "preview.html"), "utf8");
  if (!preview.includes('src="preview.js"') || preview.includes('src="wallet.js"')) {
    throw new Error(`${target} preview is not independent from the WebExtension runtime`);
  }

  const wasmPath = path.join(directory, "src", "wasm", "elementsplus_wallet_core_bg.wasm");
  const wasmBytes = await readFile(wasmPath);
  if (!WebAssembly.validate(wasmBytes)) throw new Error(`${target} wallet core WASM is invalid`);
  walletCoreDigests.push(createHash("sha256").update(wasmBytes).digest("hex"));
  const bindings = await import(
    `${pathToFileURL(path.join(directory, "src", "wasm", "elementsplus_wallet_core.js")).href}?${target}`
  );
  bindings.initSync({ module: wasmBytes });
  for (const name of ["verify_asset_issuance_json", "decode_offer_json"]) {
    if (typeof bindings[name] !== "function") throw new Error(`${target} wallet core is missing ${name}`);
  }
  if ("verify_preconfirmation_receipt" in bindings) {
    throw new Error(`${target} wallet core still exposes preconfirmation verification`);
  }
  if (bindings.network_profile_id() !== profile.id) {
    throw new Error(`${target} wallet core was compiled for ${bindings.network_profile_id()}, not ${profile.id}`);
  }
  if (regtest !== (typeof bindings.WasmWalletCore.forRegtest === "function")) {
    throw new Error(`${target} artifact ${regtest ? "lacks" : "exposes"} the test-only network constructor`);
  }
  const publicTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  if (!bindings.validate_mnemonic(publicTestMnemonic)) {
    throw new Error(`${target} packaged wallet core rejected the public BIP39 test vector`);
  }
  let generatedMnemonic = bindings.generate_mnemonic();
  if (
    !bindings.validate_mnemonic(generatedMnemonic)
    || generatedMnemonic.split(" ").length !== 12
  ) throw new Error(`${target} packaged wallet core mnemonic generation failed`);
  generatedMnemonic = "";
  let core;
  if (regtest) {
    // The regtest core has no compiled pins; the plain constructor must refuse.
    let refused = false;
    try {
      new bindings.WasmWalletCore(publicTestMnemonic).free();
    } catch {
      refused = true;
    }
    if (!refused) throw new Error(`${target} regtest core accepted the compiled-profile constructor`);
    core = bindings.WasmWalletCore.forRegtest(
      publicTestMnemonic, compiled.genesisHash, compiled.nativeAssetId, compiled.displayName,
    );
  } else {
    core = new bindings.WasmWalletCore(publicTestMnemonic);
  }
  try {
    const derived = JSON.parse(core.derive_address_json("external", 0));
    const recipient = JSON.parse(core.derive_address_json("external", 1));
    if (
      derived.branch !== "external"
      || derived.index !== 0
      || typeof derived.native_address !== "string"
      || !derived.native_address.startsWith(`${compiled.bech32Hrp}1`)
    ) throw new Error(`${target} packaged wallet core derivation smoke test failed`);
    // Confidential receive is opt-in: off by default, SLIP-77 when requested.
    const confidential = JSON.parse(core.derive_address_json("external", 0, true));
    if (
      "confidential_address" in derived
      || typeof core.set_confidential_receive !== "function"
      || confidential.native_address !== derived.native_address
      || typeof confidential.confidential_address !== "string"
      || !confidential.confidential_address.startsWith(`${compiled.blech32Hrp}1`)
    ) throw new Error(`${target} packaged wallet core confidential derivation smoke test failed`);
    const prepared = JSON.parse(core.prepare_transfer_json(JSON.stringify({
      recipient: recipient.native_address,
      asset_id: compiled.nativeAssetId,
      amount: "1000",
      fee_rate: 1,
      change_index: 0,
      utxos: [{
        txid: "1".repeat(64),
        vout: 0,
        value: "10000",
        asset_id: compiled.nativeAssetId,
        script_pubkey_hex: derived.script_pubkey_hex,
        branch: "external",
        index: 0,
      }],
    })));
    if (
      prepared.review?.kind !== "transfer"
      || prepared.review.external_outputs?.[0]?.amount !== "1000"
      || prepared.review.sighash !== "ALL"
    ) throw new Error(`${target} packaged wallet core review smoke test failed`);
    const signed = JSON.parse(core.sign_prepared_json(
      JSON.stringify(prepared),
      prepared.review_hash,
    ));
    if (
      !/^[0-9a-f]{64}$/u.test(signed.txid)
      || signed.review_hash !== prepared.review_hash
      || !/^(?:[0-9a-f]{2})+$/u.test(signed.raw_tx_hex)
    ) throw new Error(`${target} packaged wallet core signing smoke test failed`);
    const verified = JSON.parse(core.verify_raw_transaction_json(JSON.stringify({
      expectedTxid: signed.txid,
      rawTransactionHex: signed.raw_tx_hex,
      expectedWalletOutputs: [{ vout: 0, scriptPubKeyHex: recipient.script_pubkey_hex }],
    })));
    if (
      verified.txid !== signed.txid
      || verified.outputs?.[0]?.assetId !== compiled.nativeAssetId
      || verified.outputs?.[0]?.valueAtomic !== 1_000
    ) throw new Error(`${target} packaged wallet core raw-transaction verification failed`);
  } finally {
    core.free();
  }

  let totalBytes = 0;
  for (const file of await listFiles(directory)) {
    const extension = path.extname(file);
    if (!allowedExtensions.has(extension)) {
      throw new Error(`${target} artifact contains an unexpected file: ${path.relative(directory, file)}`);
    }
    const metadata = await stat(file);
    totalBytes += metadata.size;
    if (extension === ".js" || extension === ".html") {
      const source = await readFile(file, "utf8");
      for (const [pattern, label] of forbiddenSource) {
        if (pattern.test(source)) {
          throw new Error(`${target}/${path.relative(directory, file)} contains ${label}`);
        }
      }
    }
  }
  if (totalBytes > maximumArtifactBytes) {
    throw new Error(`${target} artifact exceeds ${maximumArtifactBytes} bytes`);
  }
}

if (new Set(walletCoreDigests).size !== 1) {
  throw new Error("Chromium and Firefox packages contain different wallet core WASM bytes");
}

process.stdout.write(`Artifact policy checks passed for ${profile.id} (${targets.join(", ")})\n`);
