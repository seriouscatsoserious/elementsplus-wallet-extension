import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const extensionDirectory = path.resolve(process.env["EXTENSION_DIST"] ?? path.join(root, "dist", "chromium"));
const chromeBinary = process.env["CHROME_BIN"] ?? "/usr/bin/google-chrome";
// Expectations default to the network profile compiled into the artifact.
const { BUILD_NETWORK_PROFILE: compiledProfile } = await import(
  pathToFileURL(path.join(extensionDirectory, "src", "network", "build-profile.js")).href
);
const expectedGenesis = process.env["EXPECTED_GENESIS"] ?? compiledProfile.genesisHash;
const expectedNativeAsset = process.env["EXPECTED_NATIVE_ASSET"] ?? compiledProfile.nativeAssetId;
const expectedAddressHrp = process.env["EXPECTED_ADDRESS_HRP"] ?? compiledProfile.bech32Hrp;
const startupTimeoutMilliseconds = 30_000;
const operationTimeoutMilliseconds = 90_000;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function withTimeout(promise, milliseconds, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${milliseconds} ms`)), milliseconds);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

class CdpConnection {
  #socket;
  #nextId = 1;
  #pending = new Map();
  #listeners = new Set();

  static async connect(url) {
    const socket = new WebSocket(url);
    await withTimeout(new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", () => reject(new Error("CDP WebSocket connection failed")), { once: true });
    }), startupTimeoutMilliseconds, "CDP connection");
    return new CdpConnection(socket);
  }

  constructor(socket) {
    this.#socket = socket;
    socket.addEventListener("message", (event) => this.#receive(String(event.data)));
    socket.addEventListener("close", () => {
      for (const { reject } of this.#pending.values()) reject(new Error("CDP WebSocket closed"));
      this.#pending.clear();
    });
  }

  onEvent(listener) {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  send(method, params = {}, sessionId) {
    const id = this.#nextId;
    this.#nextId += 1;
    const message = { id, method, params };
    if (sessionId !== undefined) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#socket.send(JSON.stringify(message));
    });
  }

  close() {
    this.#socket.close();
  }

  #receive(raw) {
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      return;
    }
    if (typeof message.id === "number") {
      const pending = this.#pending.get(message.id);
      if (pending === undefined) return;
      this.#pending.delete(message.id);
      if (message.error !== undefined) pending.reject(new Error(`CDP ${message.error.code}: ${message.error.message}`));
      else pending.resolve(message.result);
      return;
    }
    for (const listener of this.#listeners) listener(message);
  }
}

async function verifyArtifact() {
  await access(chromeBinary);
  await access(path.join(extensionDirectory, "manifest.json"));
  const manifest = JSON.parse(await readFile(path.join(extensionDirectory, "manifest.json"), "utf8"));
  assert(manifest.manifest_version === 3, "Chromium artifact is not Manifest V3");
  assert(manifest.background?.service_worker === "src/background/service-worker.js", "Unexpected service worker entry");
  assert(manifest.action?.default_popup === "src/ui/wallet.html", "Unexpected extension popup entry");
}

async function launchChrome(profileDirectory) {
  const stderrChunks = [];
  let stderrLength = 0;
  let resolveDebugger;
  let rejectDebugger;
  const debuggerUrl = new Promise((resolve, reject) => {
    resolveDebugger = resolve;
    rejectDebugger = reject;
  });
  const chromeArguments = [
    "--headless=new",
    "--remote-debugging-port=0",
    "--remote-allow-origins=*",
    `--user-data-dir=${profileDirectory}`,
    `--disable-extensions-except=${extensionDirectory}`,
    `--load-extension=${extensionDirectory}`,
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
  ];
  // Some isolated Linux CI hosts disable unprivileged user namespaces. Keep
  // Chromium's unsafe workaround explicit instead of weakening normal runs.
  if (process.env["CHROME_NO_SANDBOX"] === "1") chromeArguments.unshift("--no-sandbox");
  const child = spawn(chromeBinary, chromeArguments, { stdio: ["ignore", "ignore", "pipe"] });

  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderrChunks.push(chunk);
    stderrLength += chunk.length;
    while (stderrLength > 64 * 1024 && stderrChunks.length > 1) stderrLength -= stderrChunks.shift().length;
    const match = stderrChunks.join("").match(/DevTools listening on (ws:\/\/[^\s]+)/u);
    if (match !== null) resolveDebugger(match[1]);
  });
  child.once("error", rejectDebugger);
  child.once("exit", (code, signal) => {
    rejectDebugger(new Error(`Chrome exited before CDP was ready (${String(code ?? signal)})`));
  });

  try {
    return {
      child,
      debuggerUrl: await withTimeout(debuggerUrl, startupTimeoutMilliseconds, "Chrome startup"),
      diagnostic: () => stderrChunks.join("").split("\n").filter(Boolean).slice(-8).join("\n"),
    };
  } catch (error) {
    child.kill("SIGKILL");
    const diagnostic = stderrChunks.join("").split("\n").filter(Boolean).slice(-8).join("\n");
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}${diagnostic.length === 0 ? "" : `\nChrome diagnostics:\n${diagnostic}`}`,
    );
  }
}

async function waitForExtensionId(cdp) {
  const deadline = Date.now() + startupTimeoutMilliseconds;
  while (Date.now() < deadline) {
    const { targetInfos } = await cdp.send("Target.getTargets");
    const target = targetInfos.find((candidate) => (
      candidate.type === "service_worker" || candidate.type === "background_page"
    ) && candidate.url.startsWith("chrome-extension://")
      && new URL(candidate.url).pathname === "/src/background/service-worker.js");
    if (target !== undefined) return new URL(target.url).host;
    await delay(100);
  }
  throw new Error("No Elements+ MV3 service worker appeared; Chrome-branded builds 137+ ignore --load-extension, so set CHROME_BIN to Chromium or Chrome for Testing");
}

async function evaluate(cdp, sessionId, expression, label) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  }, sessionId);
  if (result.exceptionDetails !== undefined) {
    const description = result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "unknown exception";
    throw new Error(`${label} failed: ${description}`);
  }
  return result.result?.value;
}

async function waitForExpression(cdp, sessionId, predicate, label, timeoutMilliseconds = operationTimeoutMilliseconds) {
  const deadline = Date.now() + timeoutMilliseconds;
  let last;
  while (Date.now() < deadline) {
    last = await evaluate(cdp, sessionId, predicate, label);
    if (last === true) return;
    await delay(100);
  }
  throw new Error(`${label} timed out`);
}

const initializeHarnessExpression = `(() => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const password = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  bytes.fill(0);
  Object.defineProperty(globalThis, "__elementsPlusSmoke", {
    configurable: true,
    value: {
      password,
      async request(message) {
        return chrome.runtime.sendMessage(message);
      },
    },
  });
  return true;
})()`;

async function runWalletSmoke(cdp, sessionId) {
  await evaluate(cdp, sessionId, initializeHarnessExpression, "Initialize in-page harness");

  const initial = await evaluate(cdp, sessionId, `(async () => {
    const response = await __elementsPlusSmoke.request({ type: "wallet.status" });
    if (!response?.ok) return { ok: false };
    const value = response.result;
    return {
      ok: true,
      initialized: value.initialized,
      unlocked: value.unlocked,
      genesisHash: value.network?.genesisHash,
      policyAsset: value.network?.policyAsset,
      screen: document.querySelector("#app")?.dataset.screen ?? null,
    };
  })()`, "Read initial wallet status");
  assert(initial?.ok === true, "Background wallet.status failed");
  assert(initial.initialized === false && initial.unlocked === false, "Fresh profile did not start uninitialized and locked");
  assert(initial.genesisHash === expectedGenesis && initial.policyAsset === expectedNativeAsset, "Background reported the wrong chain identity");
  assert(initial.screen === "welcome", "Fresh profile did not show onboarding");

  const created = await evaluate(cdp, sessionId, `(async () => {
    const generated = await __elementsPlusSmoke.request({ type: "mnemonic.generate" });
    if (!generated?.ok) return { ok: false, step: "generate" };
    const mnemonic = generated.result.mnemonic;
    const words = mnemonic.split(" ").length;
    const response = await __elementsPlusSmoke.request({ type: "vault.create", password: __elementsPlusSmoke.password, mnemonic });
    return { ok: response?.ok === true, words, error: response?.error?.message };
  })()`, "Create encrypted disposable vault");
  assert(created?.ok === true && created.words === 12, `Vault creation failed: ${created?.error ?? created?.step}`);

  const snapshotCheck = await evaluate(cdp, sessionId, `(async () => {
    const response = await __elementsPlusSmoke.request({ type: "wallet.snapshot" });
    if (!response?.ok) return { ok: false, error: response?.error?.message };
    const { snapshot } = response.result;
    const native = snapshot.balances.find((entry) => entry.assetId === ${JSON.stringify(expectedNativeAsset)});
    return {
      ok: true,
      canonicalAddress: snapshot.receiveAddress.startsWith(${JSON.stringify(`${expectedAddressHrp}1`)}),
      primaryAddress: snapshot.primaryAddress.startsWith(${JSON.stringify(`${expectedAddressHrp}1`)}),
      validTip: Number.isSafeInteger(snapshot.tipHeight) && snapshot.tipHeight >= 0,
      nativeEntry: native !== undefined && /^\\d+$/u.test(native.amount),
    };
  })()`, "Verify explorer-backed wallet snapshot");
  assert(snapshotCheck?.ok === true, `Live wallet snapshot request failed: ${snapshotCheck?.error}`);
  for (const field of ["canonicalAddress", "primaryAddress", "validTip", "nativeEntry"]) {
    assert(snapshotCheck[field] === true, `Wallet snapshot assertion failed: ${field}`);
  }

  const insufficientFunds = await evaluate(cdp, sessionId, `(async () => {
    const snapshot = await __elementsPlusSmoke.request({ type: "wallet.snapshot" });
    if (!snapshot?.ok) return { failedClosed: false };
    const response = await __elementsPlusSmoke.request({
      type: "tx.prepare",
      operation: { kind: "transfer", assetId: ${JSON.stringify(expectedNativeAsset)}, recipient: snapshot.result.snapshot.receiveAddress, amount: "1", feeRate: 1 },
    });
    return { failedClosed: response?.ok === false, leakedApproval: response?.result?.approvalToken !== undefined };
  })()`, "Exercise insufficient-funds prepare");
  assert(insufficientFunds?.failedClosed === true && insufficientFunds.leakedApproval === false, "Unfunded send did not fail closed before approval");

  const relock = await evaluate(cdp, sessionId, `(async () => {
    await __elementsPlusSmoke.request({ type: "wallet.lock" });
    const locked = await __elementsPlusSmoke.request({ type: "wallet.status" });
    const snapshot = await __elementsPlusSmoke.request({ type: "wallet.snapshot" });
    const unlock = await __elementsPlusSmoke.request({ type: "wallet.unlock", password: __elementsPlusSmoke.password });
    return { locked: locked?.result?.unlocked === false, snapshotRefused: snapshot?.error?.code === "LOCKED", unlocked: unlock?.ok === true };
  })()`, "Lock and unlock");
  assert(relock?.locked === true && relock.snapshotRefused === true && relock.unlocked === true, "Lock/unlock cycle failed");

  await evaluate(cdp, sessionId, `(() => {
    __elementsPlusSmoke.password = "";
    delete globalThis.__elementsPlusSmoke;
    return true;
  })()`, "Clear disposable in-page credentials");
}

/** The provider is injected into http(s) pages and refuses unconnected origins. */
async function runProviderSmoke(cdp) {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>dapp</title><p>dapp</p>");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { targetId } = await cdp.send("Target.createTarget", { url: `http://127.0.0.1:${server.address().port}/` });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await waitForExpression(cdp, sessionId, "window.elementsplus?.isElementsPlus === true", "Wait for injected provider");
    const result = await evaluate(cdp, sessionId, `(async () => {
      const codes = {};
      for (const method of ["ep_getAddress", "ep_getBalances", "ep_sendTransfer", "nope"]) {
        try { await window.elementsplus.request({ method, params: {} }); codes[method] = "resolved"; }
        catch (error) { codes[method] = error.code; }
      }
      return codes;
    })()`, "Probe provider error codes");
    assert(result.ep_getAddress === 4100 && result.ep_getBalances === 4100 && result.ep_sendTransfer === 4100, "Unconnected origin was not refused with 4100");
    assert(result.nope === 4200, "Unknown method was not refused with 4200");
    await cdp.send("Target.closeTarget", { targetId });
  } finally {
    server.close();
  }
}

async function main() {
  await verifyArtifact();
  const profileDirectory = await mkdtemp(path.join(tmpdir(), "elementsplus-extension-smoke-"));
  let chrome;
  let cdp;
  let failure;
  try {
    chrome = await launchChrome(profileDirectory);
    cdp = await CdpConnection.connect(chrome.debuggerUrl);
    await cdp.send("Target.setDiscoverTargets", { discover: true });
    const extensionId = await waitForExtensionId(cdp);
    if (process.env["PRINT_EXTENSION_ID"] === "1") process.stdout.write(`Extension ID: ${extensionId}\n`);
    const { targetId } = await cdp.send("Target.createTarget", {
      url: `chrome-extension://${extensionId}/src/ui/wallet.html`,
    });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    await waitForExpression(cdp, sessionId, "document.readyState === 'complete'", "Wait for extension popup");
    const loadedExtensionId = await evaluate(cdp, sessionId, "globalThis.chrome?.runtime?.id ?? null", "Verify extension execution context");
    assert(loadedExtensionId === extensionId, "Chrome did not load the expected unpacked extension context");
    await waitForExpression(cdp, sessionId, "document.querySelector('#app')?.dataset.screen === 'welcome'", "Wait for onboarding screen");
    await withTimeout(runWalletSmoke(cdp, sessionId), 4 * operationTimeoutMilliseconds, "Headless extension smoke test");
    await withTimeout(runProviderSmoke(cdp), operationTimeoutMilliseconds, "Provider smoke test");
    process.stdout.write("PASS: built Chromium extension completed vault, lock/unlock, live sync, fail-closed send and provider-boundary smoke checks\n");
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    if (cdp !== undefined) {
      try { await cdp.send("Browser.close"); } catch {}
      cdp.close();
    }
    if (chrome?.child !== undefined && chrome.child.exitCode === null && chrome.child.signalCode === null) {
      chrome.child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => chrome.child.once("exit", resolve)),
        delay(2_000),
      ]);
      if (chrome.child.exitCode === null && chrome.child.signalCode === null) chrome.child.kill("SIGKILL");
    }
    try {
      await rm(profileDirectory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    } catch (error) {
      if (failure === undefined) throw error;
      process.stderr.write("Warning: Chrome profile cleanup did not complete\n");
    }
    if (failure !== undefined && chrome !== undefined) {
      const diagnostic = chrome.diagnostic();
      if (diagnostic.length > 0) process.stderr.write(`Chrome diagnostics (last lines):\n${diagnostic}\n`);
    }
  }
}

await main().catch((error) => {
  process.stderr.write(`FAIL: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
