import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generatedDirectory } from "./build-paths.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const buildDirectory = path.join(root, ".build");
const outputDirectory = await generatedDirectory(root,
  process.env["ELEMENTSPLUS_DIST"] ?? path.join(root, "dist"), ["dist", ".regtest/dist"]);
const wasmDirectory = path.resolve(process.env["ELEMENTSPLUS_WASM_DIR"] ?? path.join(root, ".wasm-bindgen"));
const profilePath = process.env["ELEMENTSPLUS_BUILD_PROFILE"];
const buildProfile = profilePath === undefined
  ? undefined
  : JSON.parse(await readFile(path.resolve(profilePath), "utf8"));
const targets = (process.env["ELEMENTSPLUS_TARGETS"] ?? "chromium,firefox")
  .split(",")
  .map((target) => target.trim())
  .filter(Boolean);
if (targets.length === 0 || targets.some((target) => !["chromium", "firefox"].includes(target))) {
  throw new Error("Build targets must be chromium or firefox");
}
if (buildProfile === undefined) {
  if (outputDirectory !== path.join(root, "dist") || wasmDirectory !== path.join(root, ".wasm-bindgen")) {
    throw new Error("Production builds require the production output and WASM directories");
  }
} else {
  const explorer = new URL(buildProfile.explorerUrl);
  if (buildProfile.mode !== "elementsplus-regtest" || !buildProfile.displayName.includes("LOCAL REGTEST")
    || explorer.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(explorer.hostname)
    || outputDirectory !== path.join(root, ".regtest", "dist")
    || wasmDirectory !== path.join(root, ".wasm-bindgen-regtest")) {
    throw new Error("Regtest profile, loopback explorer, WASM and output must remain isolated");
  }
}
const fixedTime = new Date("2000-01-01T00:00:00.000Z");

function compile() {
  const executable = process.platform === "win32" ? "tsc.cmd" : "tsc";
  const result = spawnSync(
    path.join(root, "node_modules", ".bin", executable),
    ["--project", path.join(root, "tsconfig.json"), "--outDir", buildDirectory],
    { cwd: root, encoding: "utf8", stdio: "pipe" },
  );
  if (result.status !== 0) {
    process.stderr.write(result.stdout);
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
}

function transformStatic(name, contents) {
  if (buildProfile === undefined || !/\.(?:html|css)$/u.test(name)) return contents;
  return contents
    .replaceAll("ECX Alpha", buildProfile.displayName)
    .replaceAll("Alpha ECX", "REGTEST ECX")
    .replaceAll("672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd", buildProfile.genesisHash)
    .replaceAll("672af009…96fa5bcd", `${buildProfile.genesisHash.slice(0, 8)}…${buildProfile.genesisHash.slice(-8)}`)
    .replaceAll("62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4", buildProfile.nativeAssetId)
    .replaceAll("62dce3bd…8f1d2da4", `${buildProfile.nativeAssetId.slice(0, 8)}…${buildProfile.nativeAssetId.slice(-8)}`)
    .replaceAll("sidechain slot 24", "isolated functional chain")
    .replaceAll("slot 24", "local test chain");
}

async function copyStatic(source, destination) {
  const entries = await readdir(source, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (entry.isDirectory()) await copyStatic(sourcePath, destinationPath);
    else if (entry.isFile() && /\.(?:css|html)$/u.test(entry.name)) {
      await mkdir(path.dirname(destinationPath), { recursive: true });
      const contents = await readFile(sourcePath, "utf8");
      await writeFile(destinationPath, transformStatic(entry.name, contents), "utf8");
    }
  }
}

async function copyTree(source, destination) {
  await mkdir(destination, { recursive: true });
  const entries = await readdir(source, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (entry.isDirectory()) await copyTree(sourcePath, destinationPath);
    else if (entry.isFile()) await copyFile(sourcePath, destinationPath);
  }
}

async function writePreview(targetDirectory) {
  const source = path.join(root, "src", "ui", "wallet.html");
  const html = transformStatic("preview.html", await readFile(source, "utf8")).replace(
    '<script type="module" src="wallet.js"></script>',
    '<script type="module" src="preview.js"></script>',
  );
  if (html.includes('src="wallet.js"')) throw new Error("Unable to generate standalone preview");
  await writeFile(path.join(targetDirectory, "src", "ui", "preview.html"), html, "utf8");
}

async function normalizeTimes(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) await normalizeTimes(entryPath);
    else await utimes(entryPath, fixedTime, fixedTime);
  }
  await utimes(directory, fixedTime, fixedTime);
}

await rm(buildDirectory, { recursive: true, force: true });
await rm(outputDirectory, { recursive: true, force: true });
compile();

if (buildProfile !== undefined) {
  await writeFile(
    path.join(buildDirectory, "src", "network", "build-profile.js"),
    `export const BUILD_NETWORK_PROFILE = Object.freeze(${JSON.stringify(buildProfile, null, 2)});\n`,
    "utf8",
  );
}

for (const target of targets) {
  const targetDirectory = path.join(outputDirectory, target);
  await mkdir(targetDirectory, { recursive: true });
  await copyTree(path.join(buildDirectory, "src"), path.join(targetDirectory, "src"));
  await copyTree(wasmDirectory, path.join(targetDirectory, "src", "wasm"));
  await copyFile(
    path.join(root, "vendor", "elementsplus-preconf", "client", "monitor.mjs"),
    path.join(targetDirectory, "src", "preconf", "monitor.js"),
  );
  await copyStatic(path.join(root, "src"), path.join(targetDirectory, "src"));
  await writePreview(targetDirectory);
  const manifest = JSON.parse(await readFile(path.join(root, "manifest", `${target}.json`), "utf8"));
  if (buildProfile !== undefined) {
    const explorer = new URL(buildProfile.explorerUrl);
    manifest.name = `Elements+ Wallet — ${buildProfile.displayName}`;
    manifest.description = "DISPOSABLE local Elements+ regtest wallet. Never use valuable keys or funds.";
    manifest.host_permissions = [`${explorer.origin}/*`];
    manifest.content_security_policy.extension_pages = manifest.content_security_policy.extension_pages
      .replace("https://explorer.bitnames.info", explorer.origin);
    if (target === "firefox" && manifest.browser_specific_settings?.gecko !== undefined) {
      manifest.browser_specific_settings.gecko.id = "elementsplus-wallet@local-regtest.invalid";
    }
  }
  await writeFile(path.join(targetDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await normalizeTimes(targetDirectory);
  if (!(await stat(path.join(targetDirectory, "src", "ui", "preview.html"))).isFile()) {
    throw new Error(`Missing ${target} preview artifact`);
  }
}

await rm(buildDirectory, { recursive: true, force: true });
process.stdout.write(`Built ${targets.map((target) => path.join(outputDirectory, target)).join(" and ")} (including standalone previews)\n`);
