// Loopback Esplora-compatible bridge for the disposable Elements+ regtest node.
//
// It keeps a small in-memory index (address -> txids, outpoint -> spender)
// built from the node's blocks and mempool, so the wallet and DEX can use the
// same Esplora endpoints they use on a public explorer. Regtest only: the
// index is rebuilt from genesis on start and after any reorg.
import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

const datadir = process.env["ELEMENTSPLUS_REGTEST_DATADIR"];
const port = Number(process.env["ELEMENTSPLUS_EXPLORER_PORT"] ?? "43199");
const rpcPort = Number(process.env["ELEMENTSPLUS_REGTEST_RPC_PORT"] ?? "18884");
if (!datadir || !Number.isSafeInteger(port) || port < 1024 || port > 65535) {
  throw new Error("regtest explorer requires a datadir and a valid unprivileged port");
}
const PAGE = 25;

let rpcId = 0;
async function rpc(method, ...params) {
  const cookie = readFileSync(path.join(datadir, "elementsregtest", ".cookie"), "utf8").trim();
  const response = await fetch(`http://127.0.0.1:${rpcPort}/`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(cookie).toString("base64")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "1.0", id: ++rpcId, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const body = await response.json();
  if (body.error) {
    const error = new Error(body.error.message ?? `${method} failed`);
    error.code = body.error.code;
    throw error;
  }
  return body.result;
}

function atomic(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error("node returned an invalid amount");
  }
  const result = Math.round(value * 100_000_000);
  if (!Number.isSafeInteger(result)) throw new Error("node amount exceeds JavaScript safety boundary");
  return result;
}

// ---- index -----------------------------------------------------------------

const index = {
  tipHeight: -1,
  blockHashes: [],              // height -> hash
  blocks: new Map(),            // hash -> { height, time }
  txs: new Map(),               // txid -> { tx (esplora json), order }
  addressTxs: new Map(),        // address -> Set<txid>
  spends: new Map(),            // "txid:vout" -> { txid, vin }
  mempool: new Set(),
  order: 0,
};

function resetIndex() {
  index.tipHeight = -1;
  index.blockHashes = [];
  index.blocks.clear();
  index.txs.clear();
  index.addressTxs.clear();
  index.spends.clear();
  index.mempool.clear();
}

function outputJson(output) {
  const script = output.scriptPubKey ?? {};
  const isFee = script.type === "fee" || (script.hex === "" && output.value !== undefined);
  const result = {
    scriptpubkey: script.hex ?? "",
    scriptpubkey_asm: script.asm ?? "",
    scriptpubkey_type: isFee ? "fee" : mapScriptType(script.type),
  };
  const address = script.address ?? script.addresses?.[0];
  if (address) result.scriptpubkey_address = address;
  if (typeof output.asset === "string") result.asset = output.asset;
  else result.assetcommitment = output.assetcommitment;
  if (typeof output.value === "number") result.value = atomic(output.value);
  else result.valuecommitment = output.valuecommitment;
  return result;
}

function mapScriptType(type) {
  switch (type) {
    case "witness_v0_keyhash": return "v0_p2wpkh";
    case "witness_v0_scripthash": return "v0_p2wsh";
    case "witness_v1_taproot": return "v1_p2tr";
    case "scripthash": return "p2sh";
    case "pubkeyhash": return "p2pkh";
    case "nulldata": return "op_return";
    default: return type ?? "unknown";
  }
}

function statusFor(blockHash) {
  if (!blockHash) return { confirmed: false };
  const block = index.blocks.get(blockHash);
  if (!block) return { confirmed: false };
  return { confirmed: true, block_height: block.height, block_hash: blockHash, block_time: block.time };
}

function addTx(raw, blockHash) {
  const existing = index.txs.get(raw.txid);
  if (existing) {
    existing.blockHash = blockHash ?? existing.blockHash;
    return;
  }
  const vin = raw.vin.map((input, n) => {
    if (input.coinbase !== undefined) {
      return { is_coinbase: true, is_pegin: false, sequence: input.sequence };
    }
    const entry = {
      txid: input.txid,
      vout: input.vout,
      is_coinbase: false,
      is_pegin: input.is_pegin === true,
      sequence: input.sequence,
      witness: input.txinwitness ?? [],
    };
    if (input.issuance) {
      entry.issuance = {
        asset_id: input.issuance.asset,
        is_reissuance: input.issuance.isreissuance === true,
        asset_blinding_nonce: input.issuance.assetBlindingNonce,
        asset_entropy: input.issuance.assetEntropy,
        contract_hash: input.issuance.contract_hash,
        token: input.issuance.token,
        assetamount: typeof input.issuance.assetamount === "number" ? atomic(input.issuance.assetamount) : undefined,
        tokenamount: typeof input.issuance.tokenamount === "number" ? atomic(input.issuance.tokenamount) : undefined,
      };
    }
    index.spends.set(`${input.txid}:${input.vout}`, { txid: raw.txid, vin: n });
    return entry;
  });
  const vout = raw.vout.map(outputJson);
  const record = {
    txid: raw.txid,
    version: raw.version,
    locktime: raw.locktime,
    size: raw.size,
    weight: raw.weight ?? raw.vsize * 4,
    vin,
    vout,
    hex: raw.hex,
    order: ++index.order,
    blockHash,
  };
  index.txs.set(raw.txid, record);
  for (const output of vout) {
    if (!output.scriptpubkey_address) continue;
    let set = index.addressTxs.get(output.scriptpubkey_address);
    if (!set) index.addressTxs.set(output.scriptpubkey_address, (set = new Set()));
    set.add(raw.txid);
  }
}

// Inputs reference their prevout's address only once the prevout is indexed.
function linkInputs(record) {
  for (const input of record.vin) {
    if (input.is_coinbase) continue;
    const previous = index.txs.get(input.txid);
    const prevout = previous?.vout[input.vout];
    if (!prevout?.scriptpubkey_address) continue;
    let set = index.addressTxs.get(prevout.scriptpubkey_address);
    if (!set) index.addressTxs.set(prevout.scriptpubkey_address, (set = new Set()));
    set.add(record.txid);
  }
}

function dropTx(txid) {
  const record = index.txs.get(txid);
  if (!record) return;
  for (const input of record.vin) {
    if (!input.is_coinbase) index.spends.delete(`${input.txid}:${input.vout}`);
  }
  for (const set of index.addressTxs.values()) set.delete(txid);
  index.txs.delete(txid);
}

let syncing = null;
async function sync() {
  if (syncing) return syncing;
  syncing = (async () => {
    const tip = await rpc("getblockcount");
    if (index.tipHeight >= 0) {
      const knownHash = await rpc("getblockhash", index.tipHeight).catch(() => null);
      if (knownHash !== index.blockHashes[index.tipHeight]) resetIndex();
    }
    for (let height = index.tipHeight + 1; height <= tip; height += 1) {
      const hash = await rpc("getblockhash", height);
      const block = await rpc("getblock", hash, 2);
      index.blockHashes[height] = hash;
      index.blocks.set(hash, { height, time: block.time });
      for (const raw of block.tx) {
        addTx(raw, hash);
        index.mempool.delete(raw.txid);
      }
      for (const raw of block.tx) linkInputs(index.txs.get(raw.txid));
      index.tipHeight = height;
    }
    const mempool = new Set(await rpc("getrawmempool"));
    for (const txid of index.mempool) {
      if (!mempool.has(txid) && !index.txs.get(txid)?.blockHash) dropTx(txid);
    }
    index.mempool = new Set([...index.mempool].filter((txid) => mempool.has(txid)));
    for (const txid of mempool) {
      if (index.txs.has(txid)) continue;
      const raw = await rpc("getrawtransaction", txid, true).catch(() => null);
      if (!raw) continue;
      addTx(raw, null);
      index.mempool.add(txid);
    }
    for (const txid of index.mempool) linkInputs(index.txs.get(txid));
  })().finally(() => { syncing = null; });
  return syncing;
}

function esploraTx(record) {
  const vin = record.vin.map((input) => {
    if (input.is_coinbase) return { ...input };
    const previous = index.txs.get(input.txid);
    const prevout = previous?.vout[input.vout];
    return prevout ? { ...input, prevout } : { ...input, prevout: null };
  });
  const feeOutput = record.vout.find((output) => output.scriptpubkey_type === "fee");
  return {
    txid: record.txid,
    version: record.version,
    locktime: record.locktime,
    size: record.size,
    weight: record.weight,
    fee: feeOutput?.value ?? 0,
    vin,
    vout: record.vout,
    status: statusFor(record.blockHash),
  };
}

function addressTxids(address) {
  const set = index.addressTxs.get(address) ?? new Set();
  const records = [...set].map((txid) => index.txs.get(txid)).filter(Boolean);
  const height = (record) => index.blocks.get(record.blockHash)?.height ?? Infinity;
  records.sort((left, right) => height(right) - height(left) || right.order - left.order);
  return records;
}

function addressStats(address) {
  const stats = () => ({ funded_txo_count: 0, funded_txo_sum: 0, spent_txo_count: 0, spent_txo_sum: 0, tx_count: 0 });
  const chain = stats();
  const mempool = stats();
  for (const record of addressTxids(address)) {
    const bucket = record.blockHash ? chain : mempool;
    bucket.tx_count += 1;
    record.vout.forEach((output) => {
      if (output.scriptpubkey_address !== address) return;
      bucket.funded_txo_count += 1;
      bucket.funded_txo_sum += output.value ?? 0;
    });
    for (const input of record.vin) {
      if (input.is_coinbase) continue;
      const prevout = index.txs.get(input.txid)?.vout[input.vout];
      if (prevout?.scriptpubkey_address !== address) continue;
      bucket.spent_txo_count += 1;
      bucket.spent_txo_sum += prevout.value ?? 0;
    }
  }
  return { address, chain_stats: chain, mempool_stats: mempool };
}

function addressUtxos(address) {
  const result = [];
  for (const record of addressTxids(address)) {
    record.vout.forEach((output, vout) => {
      if (output.scriptpubkey_address !== address) return;
      if (index.spends.has(`${record.txid}:${vout}`)) return;
      const utxo = { txid: record.txid, vout, status: statusFor(record.blockHash) };
      if (output.asset) utxo.asset = output.asset;
      if (output.value !== undefined) utxo.value = output.value;
      result.push(utxo);
    });
  }
  return result;
}

function outspend(txid, vout) {
  const spend = index.spends.get(`${txid}:${vout}`);
  if (!spend) return { spent: false };
  const record = index.txs.get(spend.txid);
  return { spent: true, txid: spend.txid, vin: spend.vin, status: statusFor(record?.blockHash) };
}

// ---- http --------------------------------------------------------------------

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Cache-Control": "no-store",
};

function json(response, status, value) {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, { ...headers, "Content-Length": Buffer.byteLength(body), "Content-Type": "application/json; charset=utf-8" });
  response.end(body);
}

function text(response, status, value) {
  const body = `${value}`;
  response.writeHead(status, { ...headers, "Content-Length": Buffer.byteLength(body), "Content-Type": "text/plain; charset=utf-8" });
  response.end(body);
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

const TXID = "([0-9a-f]{64})";

async function route(request, response) {
  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      ...headers,
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    });
    response.end();
    return;
  }
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  const pathname = url.pathname;
  await sync();
  if (request.method === "GET" && pathname === "/health") {
    const sidechain = await rpc("getsidechaininfo");
    json(response, 200, { ok: true, height: index.tipHeight, genesis: index.blockHashes[0], asset: sidechain.pegged_asset });
    return;
  }
  if (!pathname.startsWith("/api/")) return text(response, 404, "not found");
  const api = pathname.slice(4);
  let match;

  if (request.method === "POST" && api === "/tx") {
    const raw = await readBody(request);
    if (!/^(?:[0-9a-f]{2})+$/u.test(raw)) return text(response, 400, "malformed transaction");
    try {
      const txid = await rpc("sendrawtransaction", raw);
      await sync();
      return text(response, 200, txid);
    } catch (error) {
      return text(response, 400, `sendrawtransaction RPC error: ${error.message}`);
    }
  }
  if (request.method !== "GET") return text(response, 405, "method not allowed");

  if (api === "/blocks/tip/hash") return text(response, 200, index.blockHashes[index.tipHeight]);
  if (api === "/blocks/tip/height") return text(response, 200, String(index.tipHeight));
  if ((match = api.match(/^\/block-height\/(\d+)$/u))) {
    const hash = index.blockHashes[Number(match[1])];
    return hash ? text(response, 200, hash) : text(response, 404, "Block not found");
  }
  if ((match = api.match(/^\/block\/([0-9a-f]{64})$/u))) {
    const block = await rpc("getblock", match[1], 1);
    return json(response, 200, {
      id: block.hash, height: block.height, timestamp: block.time, tx_count: block.nTx,
      size: block.size, weight: block.weight,
      ...(block.previousblockhash ? { previousblockhash: block.previousblockhash } : {}),
    });
  }
  if (api === "/mempool") {
    const info = await rpc("getmempoolinfo");
    return json(response, 200, { count: info.size, vsize: info.bytes, total_fee: atomic(info.total_fee ?? 0), fee_histogram: [] });
  }
  if (api === "/mempool/txids") return json(response, 200, [...index.mempool]);
  if (api === "/fee-estimates") return json(response, 200, { "1": 1, "2": 1, "3": 1, "6": 1, "144": 1 });
  if ((match = api.match(/^\/asset\/([0-9a-f]{64})$/u))) {
    const sidechain = await rpc("getsidechaininfo");
    if (match[1] === sidechain.pegged_asset) return json(response, 200, { asset_id: match[1] });
    for (const record of index.txs.values()) {
      const input = record.vin.find((candidate) => candidate.issuance?.asset_id === match[1]);
      if (input) {
        return json(response, 200, {
          asset_id: match[1],
          issuance_txin: { txid: record.txid, vin: record.vin.indexOf(input) },
          contract_hash: input.issuance.contract_hash,
          reissuance_token: input.issuance.token,
          status: statusFor(record.blockHash),
        });
      }
    }
    return json(response, 404, { error: "unknown asset" });
  }
  if ((match = api.match(/^\/address\/([^/]+)(\/utxo|\/txs|\/txs\/mempool|\/txs\/chain(?:\/([0-9a-f]{64}))?)?$/u))) {
    const address = decodeURIComponent(match[1]);
    const validation = await rpc("validateaddress", address);
    if (validation?.isvalid !== true) return text(response, 400, "Invalid Bitcoin address");
    const canonical = validation.address ?? address;
    const suffix = match[2];
    if (suffix === undefined) return json(response, 200, addressStats(canonical));
    if (suffix === "/utxo") return json(response, 200, addressUtxos(canonical));
    const records = addressTxids(canonical);
    const mempool = records.filter((record) => !record.blockHash);
    const chain = records.filter((record) => record.blockHash);
    if (suffix === "/txs") {
      return json(response, 200, [...mempool.slice(0, 50), ...chain.slice(0, PAGE)].map(esploraTx));
    }
    if (suffix === "/txs/mempool") return json(response, 200, mempool.slice(0, 50).map(esploraTx));
    const after = match[3];
    const start = after ? chain.findIndex((record) => record.txid === after) + 1 : 0;
    if (after && start === 0) return json(response, 200, []);
    return json(response, 200, chain.slice(start, start + PAGE).map(esploraTx));
  }
  if ((match = api.match(new RegExp(`^/tx/${TXID}(/hex|/status|/outspends|/outspend/(\\d+))?$`, "u")))) {
    const record = index.txs.get(match[1]);
    if (!record) return text(response, 404, "Transaction not found");
    if (match[2] === undefined) return json(response, 200, esploraTx(record));
    if (match[2] === "/hex") return text(response, 200, record.hex);
    if (match[2] === "/status") return json(response, 200, statusFor(record.blockHash));
    if (match[2] === "/outspends") return json(response, 200, record.vout.map((_, vout) => outspend(record.txid, vout)));
    const vout = Number(match[3]);
    if (vout >= record.vout.length) return text(response, 404, "Output not found");
    return json(response, 200, outspend(record.txid, vout));
  }
  text(response, 404, "not found");
}

const server = http.createServer((request, response) => {
  void route(request, response).catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    json(response, 500, { error: message.slice(0, 500) });
  });
});
await sync();
server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`Elements+ regtest explorer bridge listening on 127.0.0.1:${port} (indexed to ${index.tipHeight})\n`);
});
setInterval(() => { void sync().catch(() => undefined); }, 2_000).unref();
