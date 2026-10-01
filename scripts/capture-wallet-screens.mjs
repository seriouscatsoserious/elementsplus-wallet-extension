// Render every wallet screen from the standalone preview (sample data, no
// extension runtime, no WASM) and save PNG screenshots.
//
//   node scripts/capture-wallet-screens.mjs [outputDir]
//
// Uses Chrome DevTools Protocol directly (no npm dependency). Chrome is taken
// from CHROME_BIN, a Playwright browser under /opt/pw-browsers or
// ~/.cache/ms-playwright, or the system google-chrome / chromium.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const output = path.resolve(process.argv[2] ?? process.env["WALLET_SCREENS_DIR"] ?? path.join(root, "artifacts", "wallet-screens"));
const site = path.join(root, ".preview-build");
const scale = Number(process.env["CAPTURE_SCALE"] ?? "2");

const screens = [
  "lock", "welcome", "show-phrase", "confirm-phrase", "import", "password",
  "home", "manage", "activity", "send", "confirm", "sent", "receive",
  "settings", "settings-network", "settings-sites", "settings-phrase", "settings-advanced",
].map((name) => [name, `screen=${name}`]);
const approvals = ["connect", "locked", "swap", "offer", "issue", "unknown"].map((name) => [`approve-${name}`, `approve=${name}`]);

function findChrome() {
  if (process.env["CHROME_BIN"]) return process.env["CHROME_BIN"];
  for (const base of ["/opt/pw-browsers", path.join(homedir(), ".cache", "ms-playwright")]) {
    if (!existsSync(base)) continue;
    for (const entry of readdirSync(base).filter((name) => name.startsWith("chromium")).sort().reverse()) {
      for (const candidate of ["chrome-linux/chrome", "chrome-linux64/chrome"]) {
        const file = path.join(base, entry, candidate);
        if (existsSync(file)) return file;
      }
    }
  }
  for (const candidate of ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error("No Chrome/Chromium found; set CHROME_BIN");
}

async function copyStatic(source, destination) {
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(destination, entry.name);
    if (entry.isDirectory()) await copyStatic(from, to);
    else if (/\.(?:css|html)$/u.test(entry.name)) {
      await mkdir(path.dirname(to), { recursive: true });
      await copyFile(from, to);
    }
  }
}

async function buildPreview() {
  await rm(site, { recursive: true, force: true });
  const tsc = spawnSync(path.join(root, "node_modules", ".bin", "tsc"), ["--project", path.join(root, "tsconfig.json"), "--outDir", site], { cwd: root, encoding: "utf8" });
  if (tsc.status !== 0) throw new Error(`tsc failed:\n${tsc.stdout}${tsc.stderr}`);
  await copyStatic(path.join(root, "src"), path.join(site, "src"));
  const fonts = path.join(site, "src", "ui", "fonts");
  await mkdir(fonts, { recursive: true });
  await copyFile(path.join(root, "node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2"), path.join(fonts, "Geist-Variable.woff2"));
  await copyFile(path.join(root, "node_modules/geist/dist/fonts/geist-mono/GeistMono-Variable.woff2"), path.join(fonts, "GeistMono-Variable.woff2"));
  const html = (await readFile(path.join(root, "src", "ui", "wallet.html"), "utf8")).replace('src="wallet.js"', 'src="preview.js"');
  await writeFile(path.join(site, "src", "ui", "preview.html"), html);
}

function serve() {
  const types = { ".css": "text/css", ".html": "text/html", ".js": "text/javascript", ".woff2": "font/woff2" };
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const target = path.resolve(site, `.${decodeURIComponent(url.pathname)}`);
      if (!target.startsWith(site)) throw new Error("outside");
      const body = await readFile(target);
      response.writeHead(200, { "Content-Type": types[path.extname(target)] ?? "application/octet-stream" });
      response.end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

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
  const child = spawn(findChrome(), [
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
    "--hide-scrollbars",
    "--font-render-hinting=none",
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
  const response = await cdp.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (response.exceptionDetails !== undefined) throw new Error(response.exceptionDetails.exception?.description ?? response.exceptionDetails.text);
  return response.result?.value;
}

async function main() {
  await buildPreview();
  await mkdir(output, { recursive: true });
  const server = await serve();
  const base = `http://127.0.0.1:${server.address().port}/src/ui/preview.html`;
  const profile = await mkdtemp(path.join(tmpdir(), "elements-wallet-capture-"));
  const chrome = await launch(profile);
  const cdp = await Cdp.connect(chrome.debuggerUrl);
  const errors = [];
  try {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Log.enable", {}, sessionId);
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 360, height: 600, deviceScaleFactor: scale, mobile: false }, sessionId);
    for (const [name, query] of [...screens, ...approvals]) {
      await cdp.send("Page.navigate", { url: `${base}?${query}` }, sessionId);
      for (let attempt = 0; attempt < 100; attempt += 1) {
        if (await evaluate(cdp, sessionId, "document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('#app > .screen') && !document.querySelector('.spin.lg') && !document.querySelector('.skeleton')")) break;
        await delay(50);
      }
      await delay(150);
      const problem = await evaluate(cdp, sessionId, `(() => {
        const app = document.querySelector('#app');
        const overflow = [...document.querySelectorAll('#app *')].find((node) => node.scrollWidth > node.clientWidth + 1 && getComputedStyle(node).overflowX === 'visible' && node.clientWidth > 0 && !(node instanceof SVGElement));
        return app.scrollWidth > 360 ? 'app overflows horizontally' : overflow ? 'overflow: ' + overflow.className : '';
      })()`);
      if (problem) errors.push(`${name}: ${problem}`);
      const { data } = await cdp.send("Page.captureScreenshot", { format: "png", fromSurface: true, captureBeyondViewport: false }, sessionId);
      await writeFile(path.join(output, `${name}.png`), Buffer.from(data, "base64"));
      process.stdout.write(`captured ${name}\n`);
    }
  } finally {
    try { await cdp.send("Browser.close"); } catch {}
    cdp.close();
    if (chrome.child.exitCode === null) chrome.child.kill("SIGKILL");
    server.close();
    await rm(profile, { recursive: true, force: true });
    await rm(site, { recursive: true, force: true });
  }
  if (errors.length > 0) process.stdout.write(`Layout warnings:\n  ${errors.join("\n  ")}\n`);
  process.stdout.write(`Screens written to ${output}\n`);
}

await main();
