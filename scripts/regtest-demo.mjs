// Local demo helper for the disposable Elements+ regtest chain: a faucet web
// page and an auto-miner, so the wallet and DEX can be clicked through without
// the node CLI. Regtest only: it spends the node's `miner` wallet.
import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const datadir = process.env["ELEMENTSPLUS_REGTEST_DATADIR"] ?? path.join(root, ".regtest", "node");
const rpcPort = Number(process.env["ELEMENTSPLUS_REGTEST_RPC_PORT"] ?? "18884");
const port = Number(process.env["ELEMENTSPLUS_FAUCET_PORT"] ?? "43200");
const mineEveryMs = Number(process.env["ELEMENTSPLUS_MINE_EVERY_MS"] ?? "4000");
const FAUCET_AMOUNT = "10";

async function rpc(method, params = [], wallet = "") {
  const cookie = readFileSync(path.join(datadir, "elementsregtest", ".cookie"), "utf8").trim();
  const response = await fetch(`http://127.0.0.1:${rpcPort}/${wallet ? `wallet/${wallet}` : ""}`, {
    method: "POST",
    headers: { Authorization: `Basic ${Buffer.from(cookie).toString("base64")}`, "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "1.0", id: Date.now(), method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = await response.json();
  if (body.error) throw new Error(body.error.message ?? `${method} failed`);
  return body.result;
}

let minerAddress;
async function mine(count = 1) {
  minerAddress ??= await rpc("getnewaddress", [], "miner");
  return rpc("generatetoaddress", [count, minerAddress], "miner");
}

async function fund(address) {
  const info = await rpc("validateaddress", [address]);
  if (info?.isvalid !== true) throw new Error("That is not a valid address on this test chain.");
  // Send to the explicit (unconfidential) form so the wallet sees plain amounts.
  const target = info.unconfidential ?? address;
  const txid = await rpc("sendtoaddress", [target, FAUCET_AMOUNT], "miner");
  await mine(1);
  return txid;
}

const page = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test ECX faucet</title>
<style>body{margin:0;background:#0B0C0F;color:#ECEDEF;font:15px/1.5 system-ui,sans-serif;padding:48px 16px}
main{max-width:520px;margin:0 auto;display:grid;gap:14px}h1{margin:0;font-size:24px}p{margin:0;color:#9A9DA6}
input{height:46px;border-radius:12px;border:1px solid #23262D;background:#16181D;color:#ECEDEF;padding:0 14px;font:inherit}
button{height:48px;border-radius:12px;border:0;background:#8FA8FF;color:#0E0F13;font:600 15px system-ui}
#out{min-height:24px;word-break:break-all}</style>
<main><h1>Test ECX faucet</h1><p>Local Elements+ test chain. Paste your wallet's receive address to get ${FAUCET_AMOUNT} test ECX. It confirms immediately.</p>
<label for="a">Receive address</label><input id="a" placeholder="ert1q…" autocomplete="off" spellcheck="false">
<button id="b" type="button">Send ${FAUCET_AMOUNT} test ECX</button><p id="out" role="status"></p></main>
<script>document.getElementById("b").onclick=async()=>{const o=document.getElementById("out");o.textContent="Sending…";
try{const r=await fetch("/faucet",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({address:document.getElementById("a").value.trim()})});
const j=await r.json();o.textContent=r.ok?"Sent and confirmed. Transaction "+j.txid:j.error}catch(e){o.textContent=String(e)}}</script>`;

http.createServer(async (request, response) => {
  const reply = (status, value, type = "application/json") => {
    response.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store" });
    response.end(type === "application/json" ? JSON.stringify(value) : value);
  };
  try {
    if (request.method === "GET" && request.url === "/") return reply(200, page, "text/html; charset=utf-8");
    if (request.method === "POST" && request.url === "/faucet") {
      let body = "";
      for await (const chunk of request) { body += chunk; if (body.length > 4096) throw new Error("request too large"); }
      const { address } = JSON.parse(body || "{}");
      if (typeof address !== "string" || address.length < 10) return reply(400, { error: "Paste a receive address first." });
      return reply(200, { txid: await fund(address) });
    }
    reply(404, { error: "not found" });
  } catch (error) {
    reply(400, { error: error instanceof Error ? error.message : String(error) });
  }
}).listen(port, "127.0.0.1", () => {
  process.stdout.write(`Faucet: http://127.0.0.1:${port}  (auto-mining every ${mineEveryMs / 1000}s when transactions are waiting)\n`);
});

setInterval(async () => {
  try {
    if ((await rpc("getrawmempool")).length > 0) await mine(1);
  } catch { /* node restarting; try again next tick */ }
}, mineEveryMs).unref?.();
