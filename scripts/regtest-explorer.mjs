import { execFile } from "node:child_process";
import http from "node:http";
import { promisify } from "node:util";

const execute = promisify(execFile);
const cli = process.env["ELEMENTSPLUS_REGTEST_CLI"];
const datadir = process.env["ELEMENTSPLUS_REGTEST_DATADIR"];
const port = Number(process.env["ELEMENTSPLUS_EXPLORER_PORT"] ?? "43199");
const rpcPort = process.env["ELEMENTSPLUS_REGTEST_RPC_PORT"] ?? "18884";
if (!cli || !datadir || !Number.isSafeInteger(port) || port < 1024 || port > 65535) {
  throw new Error("regtest explorer requires CLI, datadir, and a valid unprivileged port");
}

const baseArguments = ["-chain=elementsregtest", `-datadir=${datadir}`, `-rpcport=${rpcPort}`];
let scanQueue = Promise.resolve();

async function command(method, ...args) {
  const { stdout } = await execute(cli, [...baseArguments, method, ...args], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30_000,
  });
  return stdout.trim();
}

async function rpc(method, ...args) {
  const output = await command(method, ...args);
  if (output === "") return null;
  try { return JSON.parse(output); } catch { return output; }
}

function atomic(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error("node returned an invalid amount");
  }
  const result = Math.round(value * 100_000_000);
  if (!Number.isSafeInteger(result)) throw new Error("node amount exceeds JavaScript safety boundary");
  return result;
}

function json(response, status, value) {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    "Content-Type": "application/json; charset=utf-8",
  });
  response.end(body);
}

function text(response, status, value) {
  const body = `${value}\n`;
  response.writeHead(status, {
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    "Content-Type": "text/plain; charset=utf-8",
  });
  response.end(body);
}

async function descriptorFor(address) {
  const result = await rpc("getdescriptorinfo", `addr(${address})`);
  if (typeof result?.descriptor !== "string") throw new Error("node rejected the address descriptor");
  return result.descriptor;
}

async function scanAddress(address) {
  const operation = scanQueue.then(async () => {
    const descriptor = await descriptorFor(address);
    const result = await rpc("scantxoutset", "start", JSON.stringify([descriptor]));
    if (result?.success !== true || !Array.isArray(result.unspents)) {
      throw new Error("node UTXO scan failed");
    }
    const unspents = [];
    for (const item of result.unspents) {
      const confirmed = Number.isSafeInteger(item.height) && item.height > 0;
      let status = { confirmed: false };
      if (confirmed) {
        const blockHash = await command("getblockhash", String(item.height));
        const header = await rpc("getblockheader", blockHash, "true");
        status = {
          confirmed: true,
          block_height: item.height,
          block_hash: blockHash,
          block_time: header.time,
        };
      }
      unspents.push({
        txid: item.txid,
        vout: item.vout,
        status,
        asset: item.asset,
        value: atomic(item.amount),
      });
    }
    return unspents;
  });
  scanQueue = operation.then(() => undefined, () => undefined);
  return await operation;
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 8 * 1024 * 1024) throw new Error("request body is too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function route(request, response) {
  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Origin": "*",
    });
    response.end();
    return;
  }
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  const path = url.pathname;
  if (request.method === "GET" && path === "/health") {
    const [height, genesis, sidechain] = await Promise.all([
      rpc("getblockcount"),
      command("getblockhash", "0"),
      rpc("getsidechaininfo"),
    ]);
    json(response, 200, { ok: true, height, genesis, asset: sidechain.pegged_asset });
    return;
  }
  if (!path.startsWith("/api/")) {
    text(response, 404, "not found");
    return;
  }
  const apiPath = path.slice(4);
  if (request.method === "GET" && apiPath === "/block-height/0") {
    text(response, 200, await command("getblockhash", "0"));
    return;
  }
  if (request.method === "GET" && apiPath.startsWith("/asset/")) {
    const asset = apiPath.slice("/asset/".length);
    const sidechain = await rpc("getsidechaininfo");
    if (asset !== sidechain.pegged_asset) return json(response, 404, { error: "unknown asset" });
    json(response, 200, { asset_id: asset });
    return;
  }
  if (request.method === "GET" && apiPath === "/blocks/tip/hash") {
    text(response, 200, await command("getbestblockhash"));
    return;
  }
  if (request.method === "GET" && apiPath.startsWith("/block/")) {
    const blockHash = apiPath.slice("/block/".length);
    const block = await rpc("getblock", blockHash, "1");
    json(response, 200, {
      id: block.hash,
      height: block.height,
      timestamp: block.time,
      tx_count: block.nTx,
      size: block.size,
      weight: block.weight,
      ...(block.previousblockhash ? { previousblockhash: block.previousblockhash } : {}),
    });
    return;
  }
  if (request.method === "GET" && apiPath === "/mempool") {
    const mempool = await rpc("getmempoolinfo");
    json(response, 200, {
      count: mempool.size,
      vsize: mempool.bytes,
      total_fee: atomic(mempool.total_fee ?? 0),
      fee_histogram: [],
    });
    return;
  }
  if (request.method === "GET" && apiPath === "/fee-estimates") {
    json(response, 200, { "1": 0.1, "2": 0.1, "6": 0.1 });
    return;
  }
  const addressMatch = apiPath.match(/^\/address\/([^/]+)(\/utxo)?$/u);
  if (request.method === "GET" && addressMatch !== null) {
    const address = decodeURIComponent(addressMatch[1]);
    const validation = await rpc("validateaddress", address);
    if (validation?.isvalid !== true) return json(response, 400, { error: "invalid address" });
    const unspents = await scanAddress(address);
    if (addressMatch[2] === "/utxo") return json(response, 200, unspents);
    const count = unspents.length;
    json(response, 200, {
      address,
      chain_stats: { funded_txo_count: count, spent_txo_count: 0, tx_count: count },
      mempool_stats: { funded_txo_count: 0, spent_txo_count: 0, tx_count: 0 },
    });
    return;
  }
  const transactionStatusMatch = apiPath.match(/^\/tx\/([0-9a-f]{64})\/status$/u);
  if (request.method === "GET" && transactionStatusMatch !== null) {
    const transaction = await rpc("getrawtransaction", transactionStatusMatch[1], "true");
    if (!transaction.blockhash || !transaction.confirmations) {
      json(response, 200, { confirmed: false });
      return;
    }
    const block = await rpc("getblockheader", transaction.blockhash, "true");
    json(response, 200, {
      confirmed: true,
      block_height: block.height,
      block_hash: block.hash,
      block_time: block.time,
    });
    return;
  }
  const transactionMatch = apiPath.match(/^\/tx\/([0-9a-f]{64})\/hex$/u);
  if (request.method === "GET" && transactionMatch !== null) {
    text(response, 200, await command("getrawtransaction", transactionMatch[1], "false"));
    return;
  }
  if (request.method === "POST" && apiPath === "/tx") {
    const raw = await readBody(request);
    if (!/^(?:[0-9a-f]{2})+$/u.test(raw)) return text(response, 400, "malformed transaction");
    text(response, 200, await command("sendrawtransaction", raw));
    return;
  }
  text(response, 404, "not found");
}

const server = http.createServer((request, response) => {
  void route(request, response).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    json(response, 500, { error: message.slice(0, 500) });
  });
});
server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`Elements+ regtest explorer bridge listening on 127.0.0.1:${port}\n`);
});
