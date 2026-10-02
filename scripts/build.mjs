import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generatedDirectory } from "./build-paths.mjs";
import { profileArgument, refuseUnselectable } from "./profile-args.mjs";
import { toWalletBuildProfile } from "../src/network/profiles.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const buildDirectory = path.join(root, ".build");
// One artifact per network profile. Public profiles take their pins from the
// registry (pending ones are refused); the local regtest profile needs the
// identity file written by scripts/build-regtest.mjs.
const profile = refuseUnselectable(profileArgument(process.argv.slice(2)));
const regtest = profile.kind === "local-regtest";
const outputDirectory = await generatedDirectory(root,
  path.join(root, regtest ? ".regtest/dist" : "dist"), ["dist", ".regtest/dist"]);
const wasmDirectory = path.join(root, regtest ? ".wasm-bindgen-regtest" : ".wasm-bindgen");
let buildProfile;
if (regtest) {
  const profilePath = process.env["ELEMENTSPLUS_BUILD_PROFILE"];
  if (profilePath === undefined) throw new Error("The regtest artifact is built by scripts/build-regtest.mjs");
  buildProfile = JSON.parse(await readFile(path.resolve(profilePath), "utf8"));
  const explorer = new URL(buildProfile.explorerUrl);
  if (buildProfile.id !== profile.id || buildProfile.displayName !== profile.displayName
    || explorer.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(explorer.hostname)) {
    throw new Error("Regtest profile, loopback explorer, WASM and output must remain isolated");
  }
} else {
  buildProfile = toWalletBuildProfile(profile);
}
const defaultTargets = regtest ? "chromium" : "chromium,firefox";
const targets = (process.env["ELEMENTSPLUS_TARGETS"] ?? defaultTargets)
  .split(",")
  .map((target) => target.trim())
  .filter(Boolean);
if (targets.length === 0 || targets.some((target) => !["chromium", "firefox"].includes(target))) {
  throw new Error("Build targets must be chromium or firefox");
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

async function copyStatic(source, destination) {
  const entries = await readdir(source, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (entry.isDirectory()) await copyStatic(sourcePath, destinationPath);
    else if (entry.isFile() && /\.(?:css|html)$/u.test(entry.name)) {
      await mkdir(path.dirname(destinationPath), { recursive: true });
      const contents = await readFile(sourcePath, "utf8");
      await writeFile(destinationPath, contents, "utf8");
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
  const html = (await readFile(source, "utf8")).replace(
    '<script type="module" src="wallet.js"></script>',
    '<script type="module" src="preview.js"></script>',
  );
  if (html.includes('src="wallet.js"')) throw new Error("Unable to generate standalone preview");
  await writeFile(path.join(targetDirectory, "src", "ui", "preview.html"), html, "utf8");
}

// Geist (SIL Open Font License 1.1) from the pinned `geist` npm package;
// the extension CSP forbids remote fonts.
const fontSources = [
  ["geist-sans/Geist-Variable.woff2", "Geist-Variable.woff2"],
  ["geist-mono/GeistMono-Variable.woff2", "GeistMono-Variable.woff2"],
];

async function copyFonts(destination) {
  const fontRoot = path.join(root, "node_modules", "geist", "dist", "fonts");
  await mkdir(destination, { recursive: true });
  for (const [source, name] of fontSources) await copyFile(path.join(fontRoot, source), path.join(destination, name));
  await copyFile(path.join(root, "node_modules", "geist", "LICENSE.txt"), path.join(destination, "LICENSE-Geist-OFL.txt"));
}

// Content scripts and the page-world provider are classic scripts. tsc marks
// every file in this ESM package as a module (`export {};`); remove only that
// marker and refuse anything that still imports or exports.
async function finalizeContentScripts(directory) {
  for (const name of ["content-script.js", "inpage.js"]) {
    const file = path.join(directory, name);
    const source = (await readFile(file, "utf8")).replace(/\nexport \{\};\n?$/u, "\n");
    if (/^\s*(?:import|export)\b/mu.test(source)) throw new Error(`${name} must be a classic script without imports or exports`);
    await writeFile(file, source, "utf8");
  }
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

// The selected profile's pins replace the source fixture in every artifact.
await writeFile(
  path.join(buildDirectory, "src", "network", "build-profile.js"),
  `export const BUILD_NETWORK_PROFILE = Object.freeze(${JSON.stringify(buildProfile, null, 2)});\n`,
  "utf8",
);

for (const target of targets) {
  const targetDirectory = path.join(outputDirectory, target);
  await mkdir(targetDirectory, { recursive: true });
  await copyTree(path.join(buildDirectory, "src"), path.join(targetDirectory, "src"));
  await copyTree(wasmDirectory, path.join(targetDirectory, "src", "wasm"));
  await copyFonts(path.join(targetDirectory, "src", "ui", "fonts"));
  await finalizeContentScripts(path.join(targetDirectory, "src", "content"));
  await copyStatic(path.join(root, "src"), path.join(targetDirectory, "src"));
  await writePreview(targetDirectory);
  const explorer = new URL(buildProfile.explorerUrl);
  const template = await readFile(path.join(root, "manifest", `${target}.json`), "utf8");
  const manifest = JSON.parse(template
    .replaceAll("{{NETWORK_DISPLAY_NAME}}", buildProfile.displayName)
    .replaceAll("{{NETWORK_ESPLORA_ORIGIN}}", explorer.origin)
    .replaceAll("{{NETWORK_PROFILE_ID}}", buildProfile.id));
  if (JSON.stringify(manifest).includes("{{")) throw new Error(`${target} manifest has an unresolved placeholder`);
  if (regtest) {
    manifest.description = "DISPOSABLE local Elements+ regtest wallet. Never use valuable keys or funds.";
    if (typeof buildProfile.dexUrl === "string" && buildProfile.dexUrl !== "") {
      const dex = new URL(buildProfile.dexUrl);
      if (dex.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(dex.hostname)) {
        throw new Error("Regtest DEX URL must be a loopback HTTP URL");
      }
    }
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
process.stdout.write(`Built ${profile.id} (${buildProfile.displayName}): ${targets.map((target) => path.join(outputDirectory, target)).join(" and ")} (including standalone previews)\n`);
