import { createHash } from "node:crypto";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const required = [
  "manifest.json",
  "src/background/service-worker.js",
  "src/network/ecx-alpha.js",
  "src/wasm/elementsplus_wallet_core.js",
  "src/wasm/elementsplus_wallet_core_bg.wasm",
  "src/ui/wallet.html",
  "src/ui/wallet.js",
  "src/ui/preview.html",
  "src/ui/preview.js",
  "src/ui/wallet.css",
];
const expectedHosts = ["https://explorer.bitnames.info/*"];
const allowedExtensions = new Set([".css", ".html", ".js", ".json", ".wasm"]);
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
for (const target of ["chromium", "firefox"]) {
  const directory = path.join(root, "dist", target);
  for (const relative of required) {
    const file = path.join(directory, relative);
    if (!(await stat(file)).isFile()) throw new Error(`Missing artifact: ${target}/${relative}`);
  }
  const manifest = JSON.parse(await readFile(path.join(directory, "manifest.json"), "utf8"));
  if (manifest.manifest_version !== 3 || manifest.permissions.join(",") !== "storage") {
    throw new Error(`${target} manifest has an unexpected permission surface`);
  }
  if (manifest.action?.default_popup !== "src/ui/wallet.html") {
    throw new Error(`${target} must open the reviewed wallet surface directly`);
  }
  if (JSON.stringify(manifest.host_permissions) !== JSON.stringify(expectedHosts)) {
    throw new Error(`${target} manifest must grant only the pinned explorer host`);
  }
  if ("optional_host_permissions" in manifest || "content_scripts" in manifest || "externally_connectable" in manifest) {
    throw new Error(`${target} manifest exposes an unexpected extension boundary`);
  }
  const csp = manifest.content_security_policy?.extension_pages;
  if (
    typeof csp !== "string"
    || !csp.includes("default-src 'none'")
    || !csp.includes("script-src 'self' 'wasm-unsafe-eval'")
    || !csp.includes("connect-src https://explorer.bitnames.info")
    || csp.includes("'unsafe-inline'")
    || csp.includes("'unsafe-eval'")
  ) {
    throw new Error(`${target} manifest CSP is not fail-closed`);
  }
  for (const name of ["wallet.html", "preview.html"]) {
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
  const core = new bindings.WasmWalletCore(publicTestMnemonic);
  try {
    const derived = JSON.parse(core.derive_address_json("external", 0));
    const recipient = JSON.parse(core.derive_address_json("external", 1));
    if (
      derived.branch !== "external"
      || derived.index !== 0
      || typeof derived.native_address !== "string"
      || !derived.native_address.startsWith("elements1")
    ) throw new Error(`${target} packaged wallet core derivation smoke test failed`);
    const prepared = JSON.parse(core.prepare_send_json(JSON.stringify({
      recipient: recipient.native_address,
      amount: 1_000,
      fee: 400,
      change_index: 0,
      utxos: [{
        txid: "1".repeat(64),
        vout: 0,
        value: 10_000,
        asset_id: "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4",
        script_pubkey_hex: derived.script_pubkey_hex,
        branch: "external",
        index: 0,
      }],
    })));
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
      || verified.outputs?.[0]?.assetId !== "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4"
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

process.stdout.write("Artifact policy checks passed\n");
