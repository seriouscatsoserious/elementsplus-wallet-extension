// End-to-end check of the built Chromium extension's dApp provider in real
// Chrome (including branded Chrome 137+, which ignores --load-extension): the
// extension is loaded over a CDP pipe with Extensions.loadUnpacked.
//
//   npm run build && node scripts/provider-e2e.mjs [screenshotDir]
//
// Creates a disposable vault in a throwaway profile, serves a dApp page on
// 127.0.0.1, and checks injection, error codes, the Connect approval window,
// origin-bound permissions, window-close rejection, and disconnect.
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const root = path.resolve(import.meta.dirname, "..");
const extension = path.resolve(process.env["EXTENSION_DIST"] ?? path.join(root, "dist", "chromium"));
const screenshots = process.argv[2];
const chromeBinary = process.env["CHROME_BIN"] ?? ["/usr/bin/google-chrome", "/usr/bin/chromium"].find((file) => existsSync(file));
const { BUILD_NETWORK_PROFILE: compiledProfile } = await import(
  pathToFileURL(path.join(extension, "src", "network", "build-profile.js")).href
);
const ECX = compiledProfile.nativeAssetId;
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

class PipeCdp {
  #next = 1;
  #pending = new Map();
  #buffer = "";
  constructor(input, output) {
    this.input = input;
    output.on("data", (chunk) => {
      this.#buffer += chunk.toString("utf8");
      for (let end = this.#buffer.indexOf("\0"); end >= 0; end = this.#buffer.indexOf("\0")) {
        const message = JSON.parse(this.#buffer.slice(0, end));
        this.#buffer = this.#buffer.slice(end + 1);
        const pending = this.#pending.get(message.id);
        if (pending === undefined) continue;
        this.#pending.delete(message.id);
        if (message.error !== undefined) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
      }
    });
  }
  send(method, params = {}, sessionId) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.input.write(`${JSON.stringify({ id, method, params, ...(sessionId === undefined ? {} : { sessionId }) })}\0`);
    });
  }
}

async function main() {
  assert(chromeBinary !== undefined, "Set CHROME_BIN to a Chrome or Chromium binary");
  assert(existsSync(path.join(extension, "manifest.json")), `No built extension at ${extension}; run npm run build`);
  const profile = await mkdtemp(path.join(tmpdir(), "elementsplus-provider-e2e-"));
  const chrome = spawn(chromeBinary, [
    "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
    ...(process.env["CHROME_NO_SANDBOX"] === "1" ? ["--no-sandbox"] : []),
    `--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check", "--disable-sync", "about:blank",
  ], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
  const cdp = new PipeCdp(chrome.stdio[3], chrome.stdio[4]);
  const evaluate = async (sessionId, expression) => {
    const result = await cdp.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true }, sessionId);
    if (result.exceptionDetails !== undefined) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
    return result.result.value;
  };
  const waitFor = async (sessionId, expression, label, timeout = 30_000) => {
    for (const end = Date.now() + timeout; Date.now() < end; await delay(100)) {
      try {
        if (await evaluate(sessionId, expression) === true) return;
      } catch {
        // Page still loading.
      }
    }
    throw new Error(`Timed out: ${label}`);
  };
  const attach = async (targetId) => {
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    return sessionId;
  };
  const waitTarget = async (predicate, label) => {
    for (const end = Date.now() + 15_000; Date.now() < end; await delay(100)) {
      const { targetInfos } = await cdp.send("Target.getTargets");
      const found = targetInfos.find(predicate);
      if (found !== undefined) return found;
    }
    throw new Error(`No target: ${label}`);
  };
  const shot = async (sessionId, name) => {
    if (screenshots === undefined) return;
    const { data } = await cdp.send("Page.captureScreenshot", { format: "png" }, sessionId);
    await writeFile(path.join(screenshots, `${name}.png`), Buffer.from(data, "base64"));
  };
  const server = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>dapp</title><script>window.__initialized=false;window.addEventListener('elementsplus#initialized',()=>{window.__initialized=true})</script><p>dapp</p>");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const pageUrl = `http://127.0.0.1:${server.address().port}/`;
  try {
    const { id } = await cdp.send("Extensions.loadUnpacked", { path: extension });
    const { targetId: walletTarget } = await cdp.send("Target.createTarget", { url: `chrome-extension://${id}/src/ui/wallet.html` });
    const wallet = await attach(walletTarget);
    await waitFor(wallet, "document.querySelector('#app')?.dataset.screen === 'welcome'", "onboarding screen");
    const created = await evaluate(wallet, `(async () => {
      const generated = await chrome.runtime.sendMessage({ type: "mnemonic.generate" });
      return chrome.runtime.sendMessage({ type: "vault.create", password: "disposable e2e password", mnemonic: generated.result.mnemonic });
    })()`);
    assert(created?.ok === true, `vault.create failed: ${JSON.stringify(created)}`);

    const { targetId: pageTarget } = await cdp.send("Target.createTarget", { url: pageUrl });
    const page = await attach(pageTarget);
    await waitFor(page, "window.elementsplus?.isElementsPlus === true && window.__initialized === true", "provider injection + elementsplus#initialized");
    const code = (expression) => evaluate(page, `${expression}.then(() => "resolved", (error) => error.code)`);
    assert(await code(`window.elementsplus.request({ method: "ep_getAddress" })`) === 4100, "unconnected ep_getAddress must be 4100");
    assert(await code(`window.elementsplus.request({ method: "eth_accounts" })`) === 4200, "unknown method must be 4200");

    await evaluate(page, `window.__connect = window.elementsplus.request({ method: "ep_connect" }).then((result) => ({ result }), (error) => ({ code: error.code })); true`);
    const connectWindow = await waitTarget((target) => target.url.includes("/src/ui/approve.html"), "connect window");
    const approval = await attach(connectWindow.targetId);
    await waitFor(approval, "!!document.querySelector('.account-card')", "connect screen");
    await shot(approval, "e2e-approve-connect");
    await evaluate(approval, `[...document.querySelectorAll(".foot .btn")].find((button) => button.textContent.includes("Connect")).click(); true`);
    const connected = await evaluate(page, "window.__connect");
    assert(typeof connected?.result?.address === "string" && connected.result.network?.policyAsset === ECX, `ep_connect failed: ${JSON.stringify(connected)}`);
    const address = await evaluate(page, `window.elementsplus.request({ method: "ep_getAddress" })`);
    assert(address.address === connected.result.address, "ep_getAddress differs from ep_connect");
    assert(await code(`window.elementsplus.request({ method: "ep_sendTransfer", params: { amount: 5 } })`) === -32602, "malformed params must be -32602");

    // A different origin (localhost vs 127.0.0.1) is not connected.
    const { targetId: otherTarget } = await cdp.send("Target.createTarget", { url: pageUrl.replace("127.0.0.1", "localhost") });
    const other = await attach(otherTarget);
    await waitFor(other, "window.elementsplus?.isElementsPlus === true", "provider on second origin");
    assert(await evaluate(other, `window.elementsplus.request({ method: "ep_getAddress" }).then(() => "resolved", (error) => error.code)`) === 4100, "permission leaked across origins");

    await evaluate(page, `window.__send = window.elementsplus.request({ method: "ep_sendTransfer", params: { assetId: "${ECX}", amount: "1000", recipient: "${address.address}" } }).then((result) => ({ result }), (error) => ({ code: error.code })); true`);
    const sendWindow = await waitTarget((target) => target.url.includes("/src/ui/approve.html") && target.targetId !== connectWindow.targetId, "send window");
    await cdp.send("Target.closeTarget", { targetId: sendWindow.targetId });
    const rejected = await evaluate(page, "window.__send");
    assert(rejected?.code === 4001, `closing the approval window must reject with 4001, got ${JSON.stringify(rejected)}`);

    assert(await evaluate(page, `window.elementsplus.request({ method: "ep_disconnect" })`) === null, "ep_disconnect must return null");
    assert(await code(`window.elementsplus.request({ method: "ep_getAddress" })`) === 4100, "disconnect must revoke the origin");
    process.stdout.write("PASS: provider injection, 4100/4200/-32602/4001 errors, Connect window, origin binding and disconnect\n");
  } finally {
    server.close();
    try { await cdp.send("Browser.close"); } catch {}
    await Promise.race([new Promise((resolve) => chrome.once("exit", resolve)), delay(3_000)]);
    if (chrome.exitCode === null) chrome.kill("SIGKILL");
    await rm(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }).catch(() => undefined);
  }
}

await main().catch((error) => {
  process.stderr.write(`FAIL: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
