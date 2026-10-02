import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parsePreparedTx,
  parseSignResult,
  parseTxReview,
  WalletCore,
  WalletCoreError,
  WalletCoreSession,
  type WalletCoreBindings,
  type WasmWalletCoreInstance,
} from "../../src/adapters/wallet-core.js";
import { NETWORK_IDENTITY } from "../../src/network/identity.js";
import { ADDRESS_1, ADDRESS_2, ECX, GENESIS, MNEMONIC, preparedJson, rawReview, SCRIPT_1, TOKEN_A, txid } from "./helpers.js";

class FakeCore implements WasmWalletCoreInstance {
  calls: { method: string; args: unknown[] }[] = [];
  freed = 0;
  prepared = preparedJson(rawReview());
  signed = JSON.stringify({ txid: txid(9), review_hash: "c".repeat(64), raw_tx_hex: "0200" });
  #record(method: string, ...args: unknown[]) { this.calls.push({ method, args }); }
  derive_address_json(branch: string, index: number): string {
    this.#record("derive", branch, index);
    return JSON.stringify({ branch, index, derivation_path: "m/84'/1'/0'/0/0", native_address: ADDRESS_1, lwk_alias: ADDRESS_1, script_pubkey_hex: SCRIPT_1 });
  }
  verify_raw_transaction_json(request: string): string { this.#record("verify", JSON.parse(request)); return "{}"; }
  prepare_transfer_json(request: string): string { this.#record("transfer", JSON.parse(request)); return this.prepared; }
  prepare_issuance_json(request: string): string { this.#record("issuance", JSON.parse(request)); return this.prepared; }
  prepare_offer_split_json(request: string): string { this.#record("split", JSON.parse(request)); return this.prepared; }
  prepare_swap_offer_json(request: string): string { this.#record("offer", JSON.parse(request)); return this.prepared; }
  take_swap_offers_json(request: string): string { this.#record("take", JSON.parse(request)); return this.prepared; }
  prepare_cancel_json(request: string): string { this.#record("cancel", JSON.parse(request)); return this.prepared; }
  sign_prepared_json(prepared: string, hash: string): string { this.#record("sign", prepared, hash); return this.signed; }
  decode_offer_json(offer: string, prevout: string): string {
    this.#record("decode", JSON.parse(offer), prevout);
    return JSON.stringify({ give_asset: "a".repeat(64), give_amount: "5", want_asset: "b".repeat(64), want_amount: "9", outpoint: `${"4".repeat(64)}:1`, maker_address: ADDRESS_1 });
  }
  free(): void { this.freed += 1; }
}

describe("wallet core adapter (fake core)", () => {
  it("parses a §1.1 review into camelCase and normalizes kinds", () => {
    const review = parseTxReview(rawReview({ kind: "SwapTake", fee: 3 as number }));
    assert.equal(review.kind, "swap_take");
    assert.equal(review.fee, "3");
    assert.deepEqual(review.balanceChanges, [{ assetId: ECX, amount: "-100000" }]);
    assert.deepEqual(review.externalOutputs, [{ address: ADDRESS_2, assetId: ECX, amount: "100000" }]);
    assert.equal(parseTxReview(rawReview({ kind: "offer_split" })).kind, "offer_split");
  });

  it("rejects unknown fields, unknown kinds, malformed amounts and duplicate inputs", () => {
    assert.throws(() => parseTxReview({ ...rawReview(), extra: 1 }), WalletCoreError);
    assert.throws(() => parseTxReview(rawReview({ kind: "burn" })), /kind/u);
    assert.throws(() => parseTxReview(rawReview({ balance_changes: [{ asset_id: ECX, amount: "1.5" }] })), /amount/u);
    assert.throws(() => parseTxReview(rawReview({ balance_changes: [{ asset_id: ECX, amount: "-0" }] })), /amount/u);
    assert.throws(() => parseTxReview(rawReview({ inputs_signed: [`${txid(1)}:0`], foreign_inputs: [`${txid(1)}:0`] })), /twice/u);
    assert.throws(() => parseTxReview(rawReview({ sighash: "NONE" })), /sighash/u);
    assert.throws(() => parseTxReview(rawReview({ external_outputs: [{ address: "bc1qnotours", asset_id: ECX, amount: "1" }] })), /address/u);
  });

  it("requires a base64 PSET and a 32-byte review hash", () => {
    assert.equal(parsePreparedTx(preparedJson(rawReview())).reviewHash, "c".repeat(64));
    assert.throws(() => parsePreparedTx(JSON.stringify({ pset_base64: "AAAA", review: rawReview(), review_hash: "c".repeat(64) })), /PSET/u);
    assert.throws(() => parsePreparedTx(preparedJson(rawReview(), "C".repeat(64))), /review hash/u);
  });

  it("requires exactly one of raw_tx_hex or offer in a sign result", () => {
    assert.throws(() => parseSignResult(JSON.stringify({ txid: txid(1), review_hash: "c".repeat(64) })), /exactly one/u);
    const offer = { version: 1, network: "ecx-alpha", genesis_hash: GENESIS, tx: "0200", give: { asset_id: TOKEN_A, amount: "5" }, want: { asset_id: ECX, amount: "9" } };
    const parsed = parseSignResult(JSON.stringify({ txid: txid(1), review_hash: "c".repeat(64), offer }));
    assert.deepEqual(parsed.offer, offer);
    assert.equal(parsed.rawTxHex, null);
  });

  it("dispatches each operation to its binding with a snake_case body (no op tag)", () => {
    const fake = new FakeCore();
    const session = new WalletCoreSession(fake);
    const utxo = { txid: txid(1), vout: 0, value: "1000", asset_id: ECX, script_pubkey_hex: SCRIPT_1, branch: "external" as const, index: 0 };
    session.prepare({ op: "transfer", recipient: ADDRESS_2, asset_id: ECX, amount: "10", fee_rate_sat_vb: 2, utxos: [utxo], change_index: 3 });
    session.prepare({ op: "cancel", utxo, change_index: 1, fee_rate: 1, other_utxos: [] });
    session.prepare({ op: "swap_offer", utxo, want_asset: TOKEN_A, want_amount: "5", receive_index: 2 });
    assert.deepEqual(fake.calls.map((call) => call.method), ["transfer", "cancel", "offer"]);
    assert.deepEqual(fake.calls[0]!.args[0], { recipient: ADDRESS_2, asset_id: ECX, amount: "10", fee_rate_sat_vb: 2, utxos: [utxo], change_index: 3 });
  });

  it("signs only the approved hash and checks the signed commitment", () => {
    const fake = new FakeCore();
    const session = new WalletCoreSession(fake);
    const prepared = session.prepare({ op: "transfer", recipient: ADDRESS_2, asset_id: ECX, amount: "10", fee_rate_sat_vb: 2, utxos: [], change_index: 0 });
    assert.throws(() => session.sign(prepared, "d".repeat(64)), /does not match/u);
    assert.equal(fake.calls.filter((call) => call.method === "sign").length, 0);
    const signed = session.sign(prepared, "c".repeat(64));
    assert.equal(signed.txid, txid(9));
    assert.equal(fake.calls.at(-1)!.args[0], prepared.json);
    fake.signed = JSON.stringify({ txid: txid(9), review_hash: "e".repeat(64), raw_tx_hex: "0200" });
    assert.throws(() => session.sign(prepared, "c".repeat(64)), /different review/u);
    session.free();
    session.free();
    assert.equal(fake.freed, 1);
    assert.throws(() => session.deriveAddress("external", 0), /closed/u);
  });

  it("loads bindings once, verifies exports, and maps keyless calls", async () => {
    const fake = new FakeCore();
    let loads = 0;
    let issuanceRequest: unknown;
    const bindings = {
      WasmWalletCore: function WasmWalletCore() { return fake; } as unknown as WalletCoreBindings["WasmWalletCore"],
      generate_mnemonic: () => MNEMONIC,
      validate_mnemonic: (m: string) => m === MNEMONIC,
      verify_asset_issuance_json: (request: string) => {
        issuanceRequest = JSON.parse(request);
        return JSON.stringify({ asset_id: TOKEN_A, token_id: null, contract_hash: "f".repeat(64) });
      },
      decode_offer_json: () => JSON.stringify({ give_asset: TOKEN_A, give_amount: "5", want_asset: ECX, want_amount: "9", outpoint: `${txid(4)}:1`, maker_address: ADDRESS_1 }),
    };
    const core = new WalletCore(async () => { loads += 1; return bindings; });
    assert.equal(await core.generateMnemonic(), MNEMONIC);
    assert.equal(await core.validateMnemonic(MNEMONIC), true);
    const verified = await core.verifyAssetIssuance({ rawTxHex: "00", expectedTxid: txid(2), vin: 1, contract: { name: "A" } });
    assert.deepEqual(issuanceRequest, { raw_tx_hex: "00", expected_txid: txid(2), vin: 1, contract: { name: "A" } });
    assert.equal(verified.assetId, TOKEN_A);
    const session = await core.open(MNEMONIC, NETWORK_IDENTITY);
    assert.equal(session.deriveAddress("external", 0).address, ADDRESS_1);
    assert.equal(loads, 1);
    await assert.rejects(core.open(MNEMONIC, { ...NETWORK_IDENTITY, id: "elementsplus-regtest" }), /regtest/u);
    const incomplete = new WalletCore(async () => ({ ...bindings, decode_offer_json: undefined } as unknown as WalletCoreBindings));
    await assert.rejects(incomplete.generateMnemonic(), /decode_offer_json/u);
  });
});
