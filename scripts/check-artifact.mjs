import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const required = [
  "manifest.json",
  "src/background/service-worker.js",
  "src/network/ecx-alpha.js",
  "src/ui/wallet.html",
  "src/ui/wallet.js",
  "src/ui/preview.html",
  "src/ui/preview.js",
  "src/ui/wallet.css",
];
const expectedHosts = ["https://explorer.bitnames.info/*"];
const allowedExtensions = new Set([".css", ".html", ".js", ".json"]);
const maximumArtifactBytes = 2 * 1024 * 1024;
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

process.stdout.write("Artifact policy checks passed\n");
