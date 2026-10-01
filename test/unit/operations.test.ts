import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parsePreparedTx, type DecodedOffer } from "../../src/adapters/wallet-core.js";
import { checkReview, firstInputOutpoint, validateOperation, type WalletOperation } from "../../src/background/operations.js";
import { ValidationError } from "../../src/shared/validation.js";
import { ADDRESS_2, ADDRESS_3, ECX, GENESIS, preparedJson, rawReview, TOKEN_A, TOKEN_B, txid, type RawReview } from "./helpers.js";

const context = { genesisHash: GENESIS, policyAsset: ECX };
const plan = (review: RawReview, extra: object = {}) => ({ prepared: parsePreparedTx(preparedJson(review)), ...extra });
const transfer = validateOperation({ kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "100000", feeRate: 2 });

describe("operation validation", () => {
  it("canonicalizes valid requests and applies the standard fee preset", () => {
    const op = validateOperation({ kind: "transfer", assetId: ECX, recipient: ` ${ADDRESS_2} `, amount: "5" });
    assert.deepEqual(op, { kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "5", feeRate: 2 });
  });

  it("rejects extra fields, floats, zero amounts and bad fee rates", () => {
    const bad = [
      { kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "5", memo: "x" },
      { kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: 5 },
      { kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "0" },
      { kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "5", feeRate: 0.5 },
      { kind: "transfer", assetId: ECX, recipient: "bc1qxyz", amount: "5" },
      { kind: "issuance", name: "", ticker: "AAA", precision: 0, amount: "1", tokenAmount: "0" },
      { kind: "issuance", name: "Alpha", ticker: "A", precision: 0, amount: "1", tokenAmount: "0" },
      { kind: "issuance", name: "Alpha", ticker: "ALPHA", precision: 9, amount: "1", tokenAmount: "0" },
      { kind: "swap_offer", giveAsset: ECX, giveAmount: "1", wantAsset: ECX, wantAmount: "2" },
      { kind: "swap_take", offers: [] },
      { kind: "cancel", txid: txid(1), vout: -1 },
      { kind: "burn" },
    ];
    for (const raw of bad) assert.throws(() => validateOperation(raw), ValidationError, JSON.stringify(raw));
  });
});

describe("exact-request review checks", () => {
  it("accepts a transfer review that matches exactly", () => {
    checkReview(transfer, plan(rawReview()), context);
  });

  it("rejects transfer reviews that differ from the request", () => {
    const cases: Partial<RawReview>[] = [
      { external_outputs: [{ address: ADDRESS_3, asset_id: ECX, amount: "100000" }] },
      { external_outputs: [{ address: ADDRESS_2, asset_id: ECX, amount: "100001" }] },
      { external_outputs: [{ address: ADDRESS_2, asset_id: ECX, amount: "100000" }, { address: ADDRESS_3, asset_id: ECX, amount: "1" }] },
      { balance_changes: [{ asset_id: ECX, amount: "-100000" }, { asset_id: TOKEN_A, amount: "-1" }] },
      { balance_changes: [{ asset_id: ECX, amount: "-200000" }] },
      { fee: 0 },
      { fee: 2 * 100_000 + 1 },
      { kind: "cancel" },
      { foreign_inputs: [`${txid(7)}:0`] },
      { genesis_hash: "0".repeat(64) },
      { sighash: "SINGLE|ANYONECANPAY" },
      { inputs_signed: [] },
    ];
    for (const overrides of cases) {
      assert.throws(() => checkReview(transfer, plan(rawReview(overrides)), context), ValidationError, JSON.stringify(overrides));
    }
  });

  it("checks issuance amounts and the token leg", () => {
    const op = validateOperation({ kind: "issuance", name: "Alpha", ticker: "ALPHA", precision: 2, amount: "1000", tokenAmount: "1" });
    const review = rawReview({
      kind: "issuance",
      external_outputs: [],
      balance_changes: [{ asset_id: TOKEN_A, amount: "1000" }, { asset_id: TOKEN_B, amount: "1" }],
      issuance: { asset_id: TOKEN_A, token_id: TOKEN_B, amount: "1000", token_amount: "1", contract_hash: "f".repeat(64) },
    });
    checkReview(op, plan(review), context);
    assert.throws(() => checkReview(op, plan({ ...review, balance_changes: [{ asset_id: TOKEN_A, amount: "1000" }] }), context));
    assert.throws(() => checkReview(op, plan({ ...review, external_outputs: [{ address: ADDRESS_2, asset_id: TOKEN_A, amount: "1" }] }), context));
  });

  it("checks direct swap offers and offer splits", () => {
    const op = validateOperation({ kind: "swap_offer", giveAsset: TOKEN_A, giveAmount: "50", wantAsset: ECX, wantAmount: "900" });
    const offerReview = rawReview({
      kind: "swap_offer",
      sighash: "SINGLE|ANYONECANPAY",
      fee: 0,
      external_outputs: [],
      balance_changes: [{ asset_id: TOKEN_A, amount: "-50" }, { asset_id: ECX, amount: "900" }],
      inputs_signed: [`${txid(3)}:1`],
    });
    checkReview(op, plan(offerReview, { offeredOutpoint: `${txid(3)}:1` }), context);
    assert.throws(() => checkReview(op, plan(offerReview, { offeredOutpoint: `${txid(3)}:2` }), context));
    assert.throws(() => checkReview(op, plan({ ...offerReview, balance_changes: [{ asset_id: TOKEN_A, amount: "-50" }, { asset_id: ECX, amount: "899" }] }, { offeredOutpoint: `${txid(3)}:1` }), context));
    const split = rawReview({ kind: "offer_split", external_outputs: [], balance_changes: [] });
    checkReview(op, plan(split, { offeredOutpoint: null }), context);
    assert.throws(() => checkReview(op, plan({ ...split, external_outputs: [{ address: ADDRESS_2, asset_id: ECX, amount: "1" }] }, { offeredOutpoint: null }), context));
  });

  it("checks that a swap take pays each maker exactly and receives each offered asset", () => {
    const offer = { version: 1 as const, network: "ecx-alpha", genesis_hash: GENESIS, tx: "00", give: { asset_id: TOKEN_A, amount: "50" }, want: { asset_id: ECX, amount: "900" } };
    const op: WalletOperation = { kind: "swap_take", offers: [offer], feeRate: 2 };
    const decoded: DecodedOffer = { giveAsset: TOKEN_A, giveAmount: "50", wantAsset: ECX, wantAmount: "900", outpoint: `${txid(5)}:0`, makerAddress: ADDRESS_3 };
    const review = rawReview({
      kind: "swap_take",
      foreign_inputs: [`${txid(5)}:0`],
      external_outputs: [{ address: ADDRESS_3, asset_id: ECX, amount: "900" }],
      balance_changes: [{ asset_id: TOKEN_A, amount: "50" }, { asset_id: ECX, amount: "-900" }],
    });
    checkReview(op, plan(review, { decodedOffers: [decoded] }), context);
    assert.throws(() => checkReview(op, plan({ ...review, external_outputs: [{ address: ADDRESS_2, asset_id: ECX, amount: "900" }] }, { decodedOffers: [decoded] }), context), /makers/u);
    assert.throws(() => checkReview(op, plan({ ...review, foreign_inputs: [`${txid(6)}:0`] }, { decodedOffers: [decoded] }), context));
  });

  it("reads the first input outpoint of an Elements transaction", () => {
    const prev = "11".repeat(31) + "22";
    const reversed = prev.match(/../gu)!.reverse().join("");
    const hex = `02000000` + `01` + `01` + prev + `03000040` + "00".repeat(8);
    assert.equal(firstInputOutpoint(hex), `${reversed}:3`);
    assert.throws(() => firstInputOutpoint(`0200000001` + `02` + "00".repeat(60)));
  });
});
