import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const buildDirectory = path.join(root, ".build");
const outputDirectory = path.join(root, "dist");
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
      await copyFile(sourcePath, destinationPath);
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

for (const target of ["chromium", "firefox"]) {
  const targetDirectory = path.join(outputDirectory, target);
  await mkdir(targetDirectory, { recursive: true });
  await copyTree(path.join(buildDirectory, "src"), path.join(targetDirectory, "src"));
  await copyStatic(path.join(root, "src"), path.join(targetDirectory, "src"));
  await writePreview(targetDirectory);
  const manifest = JSON.parse(await readFile(path.join(root, "manifest", `${target}.json`), "utf8"));
  await writeFile(path.join(targetDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await normalizeTimes(targetDirectory);
  if (!(await stat(path.join(targetDirectory, "src", "ui", "preview.html"))).isFile()) {
    throw new Error(`Missing ${target} preview artifact`);
  }
}

await rm(buildDirectory, { recursive: true, force: true });
process.stdout.write("Built dist/chromium and dist/firefox (including standalone previews)\n");
