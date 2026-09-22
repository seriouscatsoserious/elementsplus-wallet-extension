import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, ".test-build");
const executable = process.platform === "win32" ? "tsc.cmd" : "tsc";

await rm(output, { recursive: true, force: true });
const compilation = spawnSync(
  path.join(root, "node_modules", ".bin", executable),
  ["--project", path.join(root, "tsconfig.json"), "--outDir", output],
  { cwd: root, encoding: "utf8", stdio: "pipe" },
);
if (compilation.status !== 0) {
  process.stderr.write(compilation.stdout);
  process.stderr.write(compilation.stderr);
  process.exit(compilation.status ?? 1);
}
await mkdir(path.join(output, "src", "preconf"), { recursive: true });
await copyFile(
  path.join(root, "vendor", "elementsplus-preconf", "client", "monitor.mjs"),
  path.join(output, "src", "preconf", "monitor.js"),
);

const testDirectory = path.join(output, "test", "unit");
const testFiles = (await readdir(testDirectory))
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => path.join(testDirectory, name));
if (testFiles.length === 0) throw new Error("No compiled unit tests found");
const tests = spawnSync(process.execPath, ["--test", ...testFiles], {
  cwd: root,
  encoding: "utf8",
  stdio: "inherit",
});
await rm(output, { recursive: true, force: true });
process.exit(tests.status ?? 1);
