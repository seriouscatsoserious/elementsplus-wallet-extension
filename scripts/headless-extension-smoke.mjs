import { spawn } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const extensionDirectory = path.resolve(process.env["EXTENSION_DIST"] ?? path.join(root, "dist", "chromium"));
const chromeBinary = process.env["CHROME_BIN"] ?? "/usr/bin/google-chrome";
const expectedImplementation = "elementsplus-wallet-core-wasm/0.1.0+esplora";
const expectedGenesis = "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd";
const expectedNativeAsset = "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4";
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
      setValue(selector, value) {
        const node = document.querySelector(selector);
        if (!(node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement)) throw new Error("Expected form control");
        node.value = value;
        node.dispatchEvent(new Event("input", { bubbles: true }));
        node.dispatchEvent(new Event("change", { bubbles: true }));
      },
      click(selector) {
        const node = document.querySelector(selector);
        if (!(node instanceof HTMLElement)) throw new Error("Expected clickable element");
        node.click();
      },
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
      available: value.adapter?.available,
      implementation: value.adapter?.implementation,
      capabilities: value.adapter?.capabilities,
      genesisHash: value.network?.genesisHash,
      nativeAssetId: value.network?.nativeAssetId,
    };
  })()`, "Read initial wallet status");
  assert(initial?.ok === true, "Background wallet.status failed");
  assert(initial.initialized === false && initial.unlocked === false, "Fresh profile did not start uninitialized and locked");
  assert(initial.available === true, "Built extension did not load the real wallet adapter");
  assert(initial.implementation === expectedImplementation, "Unexpected wallet adapter implementation");
  assert(initial.genesisHash === expectedGenesis && initial.nativeAssetId === expectedNativeAsset, "Background reported the wrong chain identity");
  assert(initial.capabilities?.mnemonic === true, "Mnemonic capability is unavailable");
  assert(initial.capabilities?.walletSync === true, "Wallet synchronization capability is unavailable");
  assert(initial.capabilities?.explicitTransactions === true, "Explicit transaction capability is unavailable");
  for (const capability of ["issuance", "reissuance", "burning", "confidentialTransactions", "dex"]) {
    assert(initial.capabilities?.[capability] === false, `Unsafe or unfinished capability is enabled: ${capability}`);
  }

  await evaluate(cdp, sessionId, `(() => {
    __elementsPlusSmoke.click('[data-view-link="setup"]');
    __elementsPlusSmoke.click("#generate-phrase");
    return true;
  })()`, "Generate disposable recovery phrase");
  await waitForExpression(cdp, sessionId, `(() => {
    const node = document.querySelector("#generated-phrase");
    if (!(node instanceof HTMLElement)) return false;
    const count = node.textContent.trim().split(/\\s+/u).length;
    return [12, 15, 18, 21, 24].includes(count);
  })()`, "Wait for generated recovery phrase");

  await evaluate(cdp, sessionId, `(() => {
    __elementsPlusSmoke.setValue("#setup-password", __elementsPlusSmoke.password);
    __elementsPlusSmoke.setValue("#setup-confirm", __elementsPlusSmoke.password);
    const backup = document.querySelector("#backup-ack");
    const identity = document.querySelector("#identity-ack");
    if (!(backup instanceof HTMLInputElement) || !(identity instanceof HTMLInputElement)) throw new Error("Missing setup acknowledgements");
    backup.checked = true;
    identity.checked = true;
    document.querySelector("#setup-form")?.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
    return true;
  })()`, "Create encrypted disposable vault");
  await waitForExpression(cdp, sessionId, `(async () => {
    const response = await __elementsPlusSmoke.request({ type: "wallet.status" });
    return response?.ok === true && response.result.initialized === true && response.result.unlocked === false;
  })()`, "Wait for encrypted vault creation");

  const unlockAndWaitForSnapshot = async (label) => {
    await evaluate(cdp, sessionId, `(() => {
      __elementsPlusSmoke.setValue("#unlock-password", __elementsPlusSmoke.password);
      document.querySelector("#unlock-form")?.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
      return true;
    })()`, label);
    await waitForExpression(cdp, sessionId, `(async () => {
      const response = await __elementsPlusSmoke.request({ type: "wallet.status" });
      return response?.ok === true && response.result.unlocked === true;
    })()`, `${label}: wait for unlock`);
    await waitForExpression(cdp, sessionId, `(() => {
      const address = document.querySelector("#receive-address")?.textContent?.trim() ?? "";
      const notice = document.querySelector("#runtime-notice")?.textContent ?? "";
      return /^elements1[02-9ac-hj-np-z]+$/u.test(address) && /snapshot loaded/i.test(notice);
    })()`, `${label}: wait for live explorer snapshot`);
  };

  await unlockAndWaitForSnapshot("Unlock disposable vault");
  const snapshotCheck = await evaluate(cdp, sessionId, `(async () => {
    const response = await __elementsPlusSmoke.request({ type: "wallet.snapshot" });
    if (!response?.ok) return { ok: false };
    const value = response.result;
    const native = value.assets?.find((asset) => asset.isNative === true);
    return {
      ok: true,
      canonicalAddress: /^elements1[02-9ac-hj-np-z]+$/u.test(value.receiveAddress),
      genesisMatches: value.chain?.genesisHash === ${JSON.stringify(expectedGenesis)},
      nativeAssetMatches: value.chain?.nativeAssetId === ${JSON.stringify(expectedNativeAsset)},
      explorerBacked: value.chain?.backend === "explorer",
      headerChainUnverified: value.chain?.headerChainVerified === false,
      explicitOnly: value.chain?.transactionPolicy === "explicit-only",
      validTip: Number.isSafeInteger(value.tipHeight) && value.tipHeight >= 0 && /^[0-9a-f]{64}$/u.test(value.tipHash),
      nativeEntry: native?.assetId === ${JSON.stringify(expectedNativeAsset)} && /^\\d+$/u.test(native.amountAtomic),
    };
  })()`, "Verify explorer-backed wallet snapshot");
  assert(snapshotCheck?.ok === true, "Live wallet snapshot request failed");
  for (const field of ["canonicalAddress", "genesisMatches", "nativeAssetMatches", "explorerBacked", "headerChainUnverified", "explicitOnly", "validTip", "nativeEntry"]) {
    assert(snapshotCheck[field] === true, `Wallet snapshot assertion failed: ${field}`);
  }

  const insufficientFunds = await evaluate(cdp, sessionId, `(async () => {
    const snapshot = await __elementsPlusSmoke.request({ type: "wallet.snapshot" });
    if (!snapshot?.ok) return { failedClosed: false };
    const response = await __elementsPlusSmoke.request({
      type: "transaction.prepare-send",
      assetId: ${JSON.stringify(expectedNativeAsset)},
      destination: snapshot.result.receiveAddress,
      amountAtomic: "1",
      feeRate: "1",
    });
    return {
      failedClosed: response?.ok === false,
      leakedApproval: response?.result?.approvalToken !== undefined,
    };
  })()`, "Exercise insufficient-funds prepare-send");
  assert(insufficientFunds?.failedClosed === true && insufficientFunds.leakedApproval === false, "Unfunded send did not fail closed before approval");

  await evaluate(cdp, sessionId, `(() => {
    __elementsPlusSmoke.click("#lock-wallet");
    return true;
  })()`, "Lock wallet");
  await waitForExpression(cdp, sessionId, `(async () => {
    const response = await __elementsPlusSmoke.request({ type: "wallet.status" });
    return response?.ok === true && response.result.unlocked === false;
  })()`, "Wait for wallet lock");
  await unlockAndWaitForSnapshot("Unlock wallet after lock");

  await evaluate(cdp, sessionId, `(() => {
    const input = document.querySelector("#unlock-password");
    if (input instanceof HTMLInputElement) input.value = "";
    __elementsPlusSmoke.password = "";
    delete globalThis.__elementsPlusSmoke;
    return true;
  })()`, "Clear disposable in-page credentials");
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
    const { targetId } = await cdp.send("Target.createTarget", {
      url: `chrome-extension://${extensionId}/src/ui/wallet.html`,
    });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    await waitForExpression(cdp, sessionId, "document.readyState === 'complete'", "Wait for extension popup");
    const loadedExtensionId = await evaluate(cdp, sessionId, "globalThis.chrome?.runtime?.id ?? null", "Verify extension execution context");
    assert(loadedExtensionId === extensionId, "Chrome did not load the expected unpacked extension context");
    await withTimeout(runWalletSmoke(cdp, sessionId), 4 * operationTimeoutMilliseconds, "Headless extension smoke test");
    process.stdout.write("PASS: built Chromium extension completed real-adapter vault, lock/unlock, live sync, trust-boundary, and fail-closed send smoke checks\n");
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
