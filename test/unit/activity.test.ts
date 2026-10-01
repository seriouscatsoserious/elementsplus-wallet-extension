import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { computeActivity, fetchAddressTransactions, loadActivity, parseEsploraTx } from "../../src/network/activity.js";
import { ADDRESS_1, ADDRESS_2, ADDRESS_3, ECX, SCRIPT_1, SCRIPT_2, SCRIPT_3, TOKEN_A, txid } from "./helpers.js";

const WALLET = new Set([SCRIPT_1]);

function out(script: string, address: string | null, asset: string, value: number, type = "v0_p2wpkh") {
  return { scriptpubkey: script, scriptpubkey_address: address ?? undefined, scriptpubkey_type: type, asset, value };
}
function fee(value: number) {
  return { scriptpubkey: "", scriptpubkey_type: "fee", asset: ECX, value };
}
function input(n: number, prevout: object | null, issuance?: object) {
  return { txid: txid(n), vout: 0, is_coinbase: false, prevout, ...(issuance === undefined ? {} : { issuance }) };
}
function tx(id: number, vin: object[], vout: object[], confirmed: number | null = 100) {
  return {
    txid: txid(id),
    vin,
    vout,
    status: confirmed === null ? { confirmed: false } : { confirmed: true, block_height: confirmed, block_hash: "e".repeat(64), block_time: 1_790_000_000 + confirmed },
  };
}

describe("activity deltas", () => {
  it("classifies a receive with the sender as counterparty", () => {
    const entry = computeActivity(parseEsploraTx(tx(1, [input(9, out(SCRIPT_2, ADDRESS_2, ECX, 6000))], [out(SCRIPT_1, ADDRESS_1, ECX, 5000), fee(1000)])), WALLET, ECX);
    assert.equal(entry.kind, "received");
    assert.deepEqual(entry.deltas, [{ assetId: ECX, amount: "5000" }]);
    assert.equal(entry.fee, null);
    assert.equal(entry.counterparty, ADDRESS_2);
    assert.equal(entry.complete, true);
  });

  it("classifies a send and excludes the fee this wallet paid", () => {
    const raw = tx(2, [input(8, out(SCRIPT_1, ADDRESS_1, ECX, 10_000))], [out(SCRIPT_3, ADDRESS_3, ECX, 2_500), out(SCRIPT_1, ADDRESS_1, ECX, 7_300), fee(200)], null);
    const entry = computeActivity(parseEsploraTx(raw), WALLET, ECX);
    assert.equal(entry.kind, "sent");
    assert.equal(entry.confirmed, false);
    assert.deepEqual(entry.deltas, [{ assetId: ECX, amount: "-2500" }]);
    assert.equal(entry.fee, "200");
    assert.equal(entry.counterparty, ADDRESS_3);
  });

  it("classifies a token send with ECX change (fee only in ECX)", () => {
    const raw = tx(3, [input(7, out(SCRIPT_1, ADDRESS_1, TOKEN_A, 500)), input(6, out(SCRIPT_1, ADDRESS_1, ECX, 1000))],
      [out(SCRIPT_3, ADDRESS_3, TOKEN_A, 500), out(SCRIPT_1, ADDRESS_1, ECX, 700), fee(300)]);
    const entry = computeActivity(parseEsploraTx(raw), WALLET, ECX);
    assert.equal(entry.kind, "sent");
    assert.deepEqual(entry.deltas, [{ assetId: TOKEN_A, amount: "-500" }]);
  });

  it("classifies a swap with foreign inputs and keeps both legs", () => {
    const raw = tx(4, [input(5, out(SCRIPT_2, ADDRESS_2, TOKEN_A, 50)), input(4, out(SCRIPT_1, ADDRESS_1, ECX, 2000))],
      [out(SCRIPT_2, ADDRESS_2, ECX, 900), out(SCRIPT_1, ADDRESS_1, TOKEN_A, 50), out(SCRIPT_1, ADDRESS_1, ECX, 1000), fee(100)]);
    const entry = computeActivity(parseEsploraTx(raw), WALLET, ECX);
    assert.equal(entry.kind, "swap");
    assert.deepEqual(entry.deltas, [{ assetId: TOKEN_A, amount: "50" }, { assetId: ECX, amount: "-1000" }]);
    assert.equal(entry.fee, null);
  });

  it("classifies an issuance and a pure self-transfer", () => {
    const issuance = tx(5, [input(3, out(SCRIPT_1, ADDRESS_1, ECX, 1000), { asset_id: TOKEN_A, is_reissuance: false })],
      [out(SCRIPT_1, ADDRESS_1, TOKEN_A, 1_000_000), out(SCRIPT_1, ADDRESS_1, ECX, 900), fee(100)]);
    const entry = computeActivity(parseEsploraTx(issuance), WALLET, ECX);
    assert.equal(entry.kind, "issuance");
    assert.equal(entry.issuedAssetId, TOKEN_A);
    assert.deepEqual(entry.deltas, [{ assetId: TOKEN_A, amount: "1000000" }]);
    const self = tx(6, [input(2, out(SCRIPT_1, ADDRESS_1, ECX, 1000))], [out(SCRIPT_1, ADDRESS_1, ECX, 900), fee(100)]);
    const selfEntry = computeActivity(parseEsploraTx(self), WALLET, ECX);
    assert.equal(selfEntry.kind, "self");
    assert.deepEqual(selfEntry.deltas, []);
  });

  it("marks confidential wallet outputs as incomplete instead of guessing", () => {
    const raw = tx(7, [input(1, out(SCRIPT_2, ADDRESS_2, ECX, 10))], [{ scriptpubkey: SCRIPT_1, scriptpubkey_type: "v0_p2wpkh", valuecommitment: "08aa", assetcommitment: "0aaa" }]);
    const entry = computeActivity(parseEsploraTx(raw), WALLET, ECX);
    assert.equal(entry.complete, false);
    assert.deepEqual(entry.deltas, []);
  });

  it("rejects malformed explorer JSON", () => {
    assert.throws(() => parseEsploraTx({ txid: "zz" }));
    assert.throws(() => parseEsploraTx({ ...tx(1, [], []), status: { confirmed: "yes" } }));
  });
});

describe("activity loading", () => {
  it("paginates confirmed history 25 at a time and merges across addresses", async () => {
    const urls: string[] = [];
    const shared = tx(200, [], [out(SCRIPT_1, ADDRESS_1, ECX, 1), out(SCRIPT_2, ADDRESS_2, ECX, 1)], 500);
    const page1 = [
      tx(100, [], [out(SCRIPT_1, ADDRESS_1, ECX, 1)], null),
      shared,
      ...Array.from({ length: 24 }, (_, i) => tx(201 + i, [], [out(SCRIPT_1, ADDRESS_1, ECX, 1)], 499 - i)),
    ];
    const page2 = [tx(300, [], [out(SCRIPT_1, ADDRESS_1, ECX, 1)], 10)];
    const fetchImpl = async (input: RequestInfo | URL): Promise<Response> => {
      const url = String(input);
      urls.push(url);
      const body = url.endsWith(`/address/${ADDRESS_1}/txs`) ? page1
        : url.endsWith(`/txs/chain/${txid(224)}`) ? page2
        : url.endsWith(`/address/${ADDRESS_2}/txs`) ? [shared]
        : [];
      return new Response(JSON.stringify(body), { status: 200 });
    };
    const all = await fetchAddressTransactions("https://explorer.example", ADDRESS_1, fetchImpl);
    assert.equal(all.length, 27);
    assert.deepEqual(urls, [
      `https://explorer.example/api/address/${ADDRESS_1}/txs`,
      `https://explorer.example/api/address/${ADDRESS_1}/txs/chain/${txid(224)}`,
    ]);
    const entries = await loadActivity({
      explorerUrl: "https://explorer.example",
      addresses: [{ address: ADDRESS_1, scriptPubKeyHex: SCRIPT_1 }, { address: ADDRESS_2, scriptPubKeyHex: SCRIPT_2 }],
      policyAsset: ECX,
      fetchImpl,
    });
    assert.equal(entries.length, 27);
    assert.equal(entries[0]!.txid, txid(100));
    assert.equal(entries[0]!.confirmed, false);
    assert.equal(entries.at(-1)!.txid, txid(300));
    // tx 200 pays both wallet addresses: counted once with both outputs.
    assert.deepEqual(entries.find((entry) => entry.txid === txid(200))!.deltas, [{ assetId: ECX, amount: "2" }]);
  });
});
