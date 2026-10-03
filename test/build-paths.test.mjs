import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { generatedDirectory } from "../scripts/build-paths.mjs";

test("build cleanup accepts only explicitly named generated directories", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "elementsplus-build-path-"));
  try {
    const allowed = ["dist", ".regtest/dist"];
    assert.equal(await generatedDirectory(root, path.join(root, "dist"), allowed), path.join(root, "dist"));
    assert.equal(await generatedDirectory(root, path.join(root, ".regtest/dist"), allowed), path.join(root, ".regtest/dist"));
    for (const candidate of [root, path.parse(root).root, path.join(root, "src"), path.join(root, ".regtest"), path.join(root, "..", "elsewhere")]) {
      await assert.rejects(generatedDirectory(root, candidate, allowed), /generated directories/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("build cleanup rejects symlinked output parents", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "elementsplus-build-symlink-"));
  try {
    await mkdir(path.join(root, "real"));
    await symlink(path.join(root, "real"), path.join(root, ".regtest"), process.platform === "win32" ? "junction" : "dir");
    await assert.rejects(generatedDirectory(root, path.join(root, ".regtest/dist"), [".regtest/dist"]), /symbolic links/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("builds refuse pending and archived network profiles before compiling", async () => {
  const { spawnSync } = await import("node:child_process");
  const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
  for (const script of ["build-wasm.mjs", "build.mjs", "check-artifact.mjs"]) {
    for (const [id, reason] of [["ecx-mainnet", /pending/u], ["ecx-alpha", /archived/u], ["nope", /unknown/u]]) {
      const result = spawnSync(process.execPath, [path.join(root, "scripts", script), "--profile", id], {
        cwd: root, encoding: "utf8", env: { ...process.env, ELEMENTSPLUS_NETWORK_PROFILE: "" },
      });
      assert.equal(result.status, 3, `${script} ${id}: ${result.stderr}`);
      assert.match(result.stderr, /Refusing to build/u);
      assert.match(result.stderr, reason);
    }
  }
});
