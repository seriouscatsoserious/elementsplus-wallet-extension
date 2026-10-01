import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const output = path.join(root, "artifacts", "wallet-screens");
const chromeBinary = process.env["CHROME_BIN"]
  ?? path.join(root, ".local", "browsers", "chrome", "linux-153.0.8010.52", "chrome-linux64", "chrome");
// Illustrated UI preview, not evidence of a funded transaction.
const baseUrl = process.env["WALLET_PREVIEW_URL"] ?? "http://127.0.0.1:43198/src/ui/preview.html";

const screens = [
  ["dashboard", "dashboard"],
  ["assets", "assets"],
  ["send", "send"],
  ["review", "review"],
  ["sent", "sent"],
  ["receive", "receive"],
  ["issue", "issue"],
  ["manage", "manage"],
  ["setup-create", "setup"],
  ["setup-import", "setup"],
  ["network", "network"],
];

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

class Cdp {
  #socket;
  #next = 1;
  #pending = new Map();

  static async connect(url) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", reject, { once: true });
    });
    return new Cdp(socket);
  }

  constructor(socket) {
    this.#socket = socket;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (typeof message.id !== "number") return;
      const pending = this.#pending.get(message.id);
      if (pending === undefined) return;
      this.#pending.delete(message.id);
      if (message.error !== undefined) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    });
  }

  send(method, params = {}, sessionId) {
    const id = this.#next++;
    const message = { id, method, params };
    if (sessionId !== undefined) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify(message));
    });
  }

  close() { this.#socket.close(); }
}

async function launch(profile) {
  let resolveDebugger;
  const debuggerUrl = new Promise((resolve) => { resolveDebugger = resolve; });
  const child = spawn(chromeBinary, [
    "--headless=new",
    ...(process.env["CHROME_NO_SANDBOX"] === "1" ? ["--no-sandbox"] : []),
    "--remote-debugging-port=0",
    "--remote-allow-origins=*",
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--metrics-recording-only",
    "--password-store=basic",
    "--use-mock-keychain",
    "--window-size=480,840",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    const match = chunk.match(/DevTools listening on (ws:\/\/[^\s]+)/u);
    if (match !== null) resolveDebugger(match[1]);
  });
  return { child, debuggerUrl: await debuggerUrl };
}

async function evaluate(cdp, sessionId, expression) {
  const response = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  }, sessionId);
  if (response.exceptionDetails !== undefined) {
    throw new Error(response.exceptionDetails.exception?.description ?? response.exceptionDetails.text);
  }
  return response.result?.value;
}

const decorate = `(() => {
  const text = (id, value) => { const node = document.getElementById(id); if (node) node.textContent = value; };
  text("network-live", "Pins match · height 104");
  document.getElementById("network-live")?.setAttribute("data-state", "ready");
  text("footer-net", "Connected · pins match");
  text("footer-clock", "08:55:20 UTC");
  text("vault-state", "Unlocked");
  text("account-state", "Unlocked");
  text("adapter-state", "Ready");
  text("footer-status", "Explicit signing ready");
  text("ecx-balance", "1,000,000 atomic");
  text("balance-caption", "Explorer-reported explicit UTXO total");
  text("chain-tip", "104");
  text("mempool-count", "0");
  text("receive-address", "ert1q6rz28mcfaxtmd6v789l9rrlrusdprr9p69dllk");
  text("send-capability-status", "Explicit native ECX signing is ready. Review every value before approval.");
  text("send-available", "Available 1,000,000 szats");
  text("review-destination", "ert1q6rz28mcfaxtmd6v789l9rrlrusdprr9p69dllk");
  text("review-amount", "100,000 szats");
  text("review-asset", "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23");
  text("review-fee", "140 szats");
  text("review-fee-asset", "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23");
  text("review-fee-rate", "0.1 szats/vbyte");
  text("review-policy", "Explicit / non-confidential only");
  text("review-expiry", "90 seconds");
  text("review-summary-hash", "3f2ad7b948c92e23da1c031d621d93f11676dc3683400293d18b1a94ec92cd11");
  text("approval-status", "Ready for one-time approval.");
  text("broadcast-txid", "dc9f22e2f452e12b62fb4797eb71d394d9ab13c51c816304c794773df422620a");
  text("post-broadcast-status", "Preconfirmed · awaiting block settlement");
  text("preconfirmation-timing", "Example: two configured relays, 384 ms (illustration only)");
  const notice = document.getElementById("runtime-notice");
  if (notice) { notice.textContent = "Wallet synchronized with the pinned Elements+ network."; notice.className = "notice success"; }
  for (const selector of ["[data-wallet-action='send']", "[data-wallet-action='receive']", "#send-form fieldset", "#unlock-password", "#unlock-wallet", "#lock-wallet", "#copy-receive-address", "#approve-broadcast"]) {
    document.querySelector(selector)?.removeAttribute("disabled");
  }
  const assetRows = document.querySelectorAll("#dashboard-assets tr, #asset-inventory tr");
  for (const row of assetRows) {
    const amount = row.querySelector(".amount strong");
    const status = row.querySelector(".amount small");
    if (amount) amount.textContent = "1,000,000 atomic";
    if (status) status.textContent = "1,000,000 confirmed";
  }
  return true;
})()`;

async function main() {
  await mkdir(output, { recursive: true });
  const profile = await mkdtemp(path.join(tmpdir(), "elements-wallet-capture-"));
  const chrome = await launch(profile);
  const cdp = await Cdp.connect(chrome.debuggerUrl);
  try {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: 400,
      height: 620,
      deviceScaleFactor: 1,
      mobile: false,
    }, sessionId);
    for (const [name, view] of screens) {
      await cdp.send("Page.navigate", { url: `${baseUrl}?screen=${name}#${view}` }, sessionId);
      for (let attempt = 0; attempt < 100; attempt += 1) {
        if (await evaluate(cdp, sessionId, "document.readyState === 'complete' && document.querySelector('.wallet-app') !== null")) break;
        await delay(50);
      }
      await delay(100);
      await evaluate(cdp, sessionId, decorate);
      if (name === "setup-import") {
        await evaluate(cdp, sessionId, "document.querySelector('#restore-tab').click(); true");
      }
      const { data } = await cdp.send("Page.captureScreenshot", {
        format: "png",
        fromSurface: true,
        captureBeyondViewport: false,
      }, sessionId);
      await writeFile(path.join(output, `${name}.png`), Buffer.from(data, "base64"));
    }
  } finally {
    try { await cdp.send("Browser.close"); } catch {}
    cdp.close();
    if (chrome.child.exitCode === null) chrome.child.kill("SIGKILL");
    await rm(profile, { recursive: true, force: true });
  }
}

await main();
