import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = path.join(root, "rust", "wallet-core", "Cargo.toml");
const output = path.join(root, ".wasm-bindgen");
const targetWasm = path.join(
  root,
  "rust",
  "wallet-core",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "elementsplus_wallet_core.wasm",
);
const wasmBindgenVersion = "0.2.108";

function run(command, args, environment = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: "pipe",
    env: { ...process.env, ...environment },
  });
  if (result.error !== undefined) {
    throw new Error(`Unable to run ${command}: ${result.error.message}`, { cause: result.error });
  }
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    process.exit(result.status ?? 1);
  }
  return result.stdout.trim();
}

const reportedVersion = run("wasm-bindgen", ["--version"]);
if (reportedVersion !== `wasm-bindgen ${wasmBindgenVersion}`) {
  throw new Error(
    `Expected wasm-bindgen ${wasmBindgenVersion}, received ${reportedVersion || "no version"}. `
    + `Install it with: cargo install wasm-bindgen-cli --version ${wasmBindgenVersion} --locked`,
  );
}

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
run("cargo", [
  "build",
  "--manifest-path", manifest,
  "--locked",
  "--release",
  "--target", "wasm32-unknown-unknown",
  "--features", "wasm",
], {
  CARGO_INCREMENTAL: "0",
  SOURCE_DATE_EPOCH: "946684800",
});
run("wasm-bindgen", [
  targetWasm,
  "--target", "web",
  "--no-typescript",
  "--out-dir", output,
  "--out-name", "elementsplus_wallet_core",
]);

const generatedWasm = path.join(output, "elementsplus_wallet_core_bg.wasm");
const generatedJavaScript = path.join(output, "elementsplus_wallet_core.js");
for (const file of [generatedWasm, generatedJavaScript]) {
  if (!(await stat(file)).isFile()) throw new Error(`Missing generated WASM artifact: ${file}`);
}
// getrandom 0.2 asks wasm-bindgen to emit a legacy `new Function("return
// this")` fallback after checking globalThis/self/window/global. MV3 forbids
// dynamic code construction. Every supported target has globalThis, so replace
// that unreachable compatibility fallback with an explicit failure. Match the
// generated shim exactly and fail the build if upstream output changes.
const glue = await readFile(generatedJavaScript, "utf8");
const dynamicFunctionShim = /(\s+__wbg_new_no_args_[0-9a-f]+: function\()arg0, arg1(\) \{)\n\s+const ret = new Function\(getStringFromWasm0\(arg0, arg1\)\);\n\s+return ret;\n\s+\},/u;
if (!dynamicFunctionShim.test(glue)) {
  throw new Error("Expected wasm-bindgen dynamic-Function compatibility shim was not found");
}
const hardenedGlue = glue.replace(
  dynamicFunctionShim,
  "$1$2\n            throw new Error('dynamic Function construction is disabled');\n        },",
);
if (/\bnew\s+Function\s*\(|(?:^|[^a-z])eval\s*\(/iu.test(hardenedGlue)) {
  throw new Error("Generated wallet core glue still contains dynamic code evaluation");
}
await writeFile(generatedJavaScript, hardenedGlue, "utf8");
const digest = createHash("sha256").update(await readFile(generatedWasm)).digest("hex");
process.stdout.write(`Built packaged wallet core WASM (${digest})\n`);
