import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ElementsPlusWalletSession } from "../../src/adapters/elementsplus-wasm.js";
import {
  parseDerivedAddress,
  parseTxReview,
  parseVerifiedTransaction,
  WalletCore,
  WalletCoreError,
  WalletCoreSession,
  type WalletCoreBindings,
  type WasmWalletCoreInstance,
} from "../../src/adapters/wallet-core.js";
import { computeActivity, loadActivity, parseEsploraTx } from "../../src/network/activity.js";
import type { FetchImplementation } from "../../src/network/esplora.js";
import {
  ExplorerHdScanError,
  ExplorerHdScanner,
  type ExplorerHdRawTransactionVerifier,
  type ExplorerHdSnapshotInput,
} from "../../src/network/explorer-hd-scan.js";
import { NETWORK_IDENTITY } from "../../src/network/identity.js";
import { ADDRESS_2, ADDRESS_3, ADDRESS_4, ECX, MNEMONIC, preparedJson, rawReview, SCRIPT_2, SCRIPT_3, SCRIPT_4, TOKEN_A, txid } from "./helpers.js";

// Real SLIP-77 derivations of the public BIP39 test vector (Rust core output).
const DERIVED = [
  {
    native_address: "elements1q6rz28mcfaxtmd6v789l9rrlrusdprr9p0zjmyw",
    lwk_alias: "ert1q6rz28mcfaxtmd6v789l9rrlrusdprr9p69dllk",
    script_pubkey_hex: "0014d0c4a3ef09e997b6e99e397e518fe3e41a118ca1",
    confidential_address: "elementsl1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2zsdg58tu8j53m",
    confidential_lwk_alias: "el1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z0z676mna6kdq",
    blinding_pubkey_hex: "028cc0e189e069238a18901f4e29c634b04cbade2f8a98ef62a7fdc75020d9b464",
  },
  {
    native_address: "elements1qd7spv5q28348xl4myc8zmh983w5jx32cad9yh0",
    lwk_alias: "ert1qd7spv5q28348xl4myc8zmh983w5jx32cg26qvh",
    script_pubkey_hex: "00146fa016500a3c6a737ebb260e2ddca78ba9234558",
    confidential_address: "elementsl1qqv8pmjjq942l6cjq69ygtt6gvmdmhesqmzazmwfsq7zwvan4kewdqmaqzegq50r2wdltkfsw9hw20zafydz4slsqgjf0r8wtr",
    confidential_lwk_alias: "el1qqv8pmjjq942l6cjq69ygtt6gvmdmhesqmzazmwfsq7zwvan4kewdqmaqzegq50r2wdltkfsw9hw20zafydz4sqljz0eqe0vhc",
    blinding_pubkey_hex: "030e1dca402d55fd6240d14885af4866dbbbe600d8ba2db9300784e67675b65cd0",
  },
] as const;

const BLINDING = {
  asset_commitment_hex: `0a${"11".repeat(32)}`,
  value_commitment_hex: `08${"22".repeat(32)}`,
  asset_blinder_hex: "33".repeat(32),
  value_blinder_hex: "44".repeat(32),
};
const BLINDING_CAMEL = {
  assetCommitmentHex: BLINDING.asset_commitment_hex,
  valueCommitmentHex: BLINDING.value_commitment_hex,
  assetBlinderHex: BLINDING.asset_blinder_hex,
  valueBlinderHex: BLINDING.value_blinder_hex,
};

function derivedJson(branch: string, index: number, confidential: boolean): string {
  const entry = DERIVED[index % DERIVED.length]!;
  const base = {
    branch,
    index,
    derivation_path: `84'/1'/0'/0/${index}`,
    native_address: entry.native_address,
    lwk_alias: entry.lwk_alias,
    script_pubkey_hex: entry.script_pubkey_hex,
  };
  return JSON.stringify(confidential
    ? {
      ...base,
      confidential_address: entry.confidential_address,
      confidential_lwk_alias: entry.confidential_lwk_alias,
      blinding_pubkey_hex: entry.blinding_pubkey_hex,
    }
    : base);
}

/** Fake core: confidential default, recorded calls, canned verification. */
class FakeCtCore implements WasmWalletCoreInstance {
  calls: { method: string; args: unknown[] }[] = [];
  confidentialDefault = false;
  verifyResult: (request: { expectedTxid: string; expectedWalletOutputs: { vout: number; scriptPubKeyHex: string }[] }) => unknown
    = (request) => ({ txid: request.expectedTxid, outputs: [] });
  derive_address_json(branch: string, index: number, confidential?: boolean | null): string {
    this.calls.push({ method: "derive", args: confidential === undefined ? [branch, index] : [branch, index, confidential] });
    return derivedJson(branch, index, confidential ?? this.confidentialDefault);
  }
  set_confidential_receive(enabled: boolean): void {
    this.calls.push({ method: "set_confidential_receive", args: [enabled] });
    this.confidentialDefault = enabled;
  }
  verify_raw_transaction_json(request: string): string {
    const parsed = JSON.parse(request) as Parameters<FakeCtCore["verifyResult"]>[0];
    this.calls.push({ method: "verify", args: [parsed] });
    return JSON.stringify(this.verifyResult(parsed));
  }
  #prepare(method: string, request: string): string {
    this.calls.push({ method, args: [JSON.parse(request)] });
    return preparedJson(rawReview());
  }
  prepare_transfer_json(request: string): string { return this.#prepare("transfer", request); }
  prepare_issuance_json(request: string): string { return this.#prepare("issuance", request); }
  prepare_offer_split_json(request: string): string { return this.#prepare("split", request); }
  prepare_swap_offer_json(request: string): string { return this.#prepare("offer", request); }
  take_swap_offers_json(request: string): string { return this.#prepare("take", request); }
  prepare_cancel_json(request: string): string { return this.#prepare("cancel", request); }
  sign_prepared_json(): string { throw new Error("not used"); }
  decode_offer_json(): string { throw new Error("not used"); }
  free(): void {}
}

function bindingsFor(instance: WasmWalletCoreInstance): WalletCoreBindings {
  const Ctor = function WasmWalletCore() { return instance; } as unknown as WalletCoreBindings["WasmWalletCore"];
  return {
    WasmWalletCore: Ctor,
    generate_mnemonic: () => MNEMONIC,
    validate_mnemonic: () => true,
    verify_asset_issuance_json: () => "{}",
    decode_offer_json: () => "{}",
  };
}

describe("confidential transactions: core adapter", () => {
  it("parses confidential derivations and keeps explicit ones byte-identical", () => {
    const plain = parseDerivedAddress(derivedJson("external", 0, false), "external", 0);
    assert.deepEqual(Object.keys(plain), ["branch", "index", "address", "scriptPubKeyHex"]);
    const ct = parseDerivedAddress(derivedJson("external", 0, true), "external", 0);
    assert.equal(ct.address, DERIVED[0].native_address);
    assert.equal(ct.confidentialAddress, DERIVED[0].confidential_address);
    const incomplete = JSON.parse(derivedJson("external", 0, true)) as Record<string, unknown>;
    delete incomplete["blinding_pubkey_hex"];
    assert.throws(() => parseDerivedAddress(JSON.stringify(incomplete), "external", 0), /incomplete/u);
    const swapped = { ...JSON.parse(derivedJson("external", 0, true)) as Record<string, unknown>, confidential_address: DERIVED[0].native_address };
    assert.throws(() => parseDerivedAddress(JSON.stringify(swapped), "external", 0), /not confidential/u);
  });

  it("passes the confidential override only when requested", () => {
    const fake = new FakeCtCore();
    const session = new WalletCoreSession(fake);
    session.deriveAddress("external", 0);
    assert.equal(session.deriveAddress("external", 1, true).confidentialAddress, DERIVED[1].confidential_address);
    assert.deepEqual(fake.calls.map((call) => call.args), [["external", 0], ["external", 1, true]]);
    // A core that ignores the override is caught.
    fake.derive_address_json = (branch: string, index: number) => derivedJson(branch, index, true);
    assert.throws(() => session.deriveAddress("external", 0, false), WalletCoreError);
  });

  it("opens with confidential receive only when the profile asks for it", async () => {
    const fake = new FakeCtCore();
    const core = new WalletCore(async () => bindingsFor(fake));
    await core.open(MNEMONIC, NETWORK_IDENTITY);
    assert.equal(fake.calls.length, 0);
    await core.open(MNEMONIC, NETWORK_IDENTITY, { confidentialReceive: true });
    assert.deepEqual(fake.calls, [{ method: "set_confidential_receive", args: [true] }]);
    const legacy = new FakeCtCore();
    (legacy as { set_confidential_receive?: unknown }).set_confidential_receive = undefined;
    const old = new WalletCore(async () => bindingsFor(legacy));
    await assert.rejects(old.open(MNEMONIC, NETWORK_IDENTITY, { confidentialReceive: true }), /confidential receive/u);
  });

  it("parses unblinded outputs and rejects malformed blinding data", () => {
    const json = (blinding: unknown) => JSON.stringify({
      txid: txid(1),
      outputs: [{ vout: 0, scriptPubKeyHex: SCRIPT_2, assetId: ECX, valueAtomic: 5000, blinding }],
    });
    const parsed = parseVerifiedTransaction(json(BLINDING), txid(1));
    assert.deepEqual(parsed.outputs[0]?.blinding, BLINDING_CAMEL);
    assert.throws(() => parseVerifiedTransaction(json({ ...BLINDING, value_commitment_hex: "02".repeat(33) }), txid(1)), /commitment/u);
    assert.throws(() => parseVerifiedTransaction(json({ ...BLINDING, extra: 1 }), txid(1)), /unexpected/u);
    const explicit = parseVerifiedTransaction(JSON.stringify({
      txid: txid(1),
      outputs: [{ vout: 0, scriptPubKeyHex: SCRIPT_2, assetId: ECX, valueAtomic: 5000 }],
    }), txid(1));
    assert.equal("blinding" in explicit.outputs[0]!, false);
  });

  it("parses confidential reviews and keeps swaps explicit", () => {
    const ctOutput = { address: DERIVED[0].confidential_lwk_alias, asset_id: ECX, amount: "100000", confidential: true };
    const review = parseTxReview({ ...rawReview({ external_outputs: [ctOutput as never] }), confidential: true });
    assert.equal(review.confidential, true);
    assert.deepEqual(review.externalOutputs[0], {
      address: DERIVED[0].confidential_address, assetId: ECX, amount: "100000", confidential: true,
    });
    // A confidential address without the flag (or vice versa) is refused.
    assert.throws(() => parseTxReview({ ...rawReview({ external_outputs: [{ ...ctOutput, confidential: undefined } as never] }), confidential: true }), /confidential/u);
    assert.throws(() => parseTxReview(rawReview({ external_outputs: [ctOutput as never] })), /not marked confidential/u);
    assert.throws(() => parseTxReview({ ...rawReview({ kind: "swap_take" }), confidential: true }), /explicit/u);
    assert.throws(() => parseTxReview({ ...rawReview(), confidential: false }), /true/u);
    assert.equal("confidential" in parseTxReview(rawReview()), false);
  });
});

// --- Scanner ---------------------------------------------------------------

const BLOCK_HASH = "f".repeat(64);

function explorer(utxo: Record<string, unknown>): FetchImplementation {
  const used = DERIVED[0].native_address;
  return async (input) => {
    const path = new URL(input.toString()).pathname;
    if (path === "/api/block-height/0") return new Response(NETWORK_IDENTITY.genesisHash);
    if (path === `/api/asset/${ECX}`) return Response.json({ asset_id: ECX });
    if (path === "/api/blocks/tip/hash") return new Response(BLOCK_HASH);
    if (path === `/api/block/${BLOCK_HASH}`) return Response.json({ id: BLOCK_HASH, height: 50 });
    if (/^\/api\/tx\/[0-9a-f]{64}\/hex$/u.test(path)) return new Response("0200");
    const match = /^\/api\/address\/([^/]+)(\/utxo)?$/u.exec(path);
    if (match === null) return new Response("not found", { status: 404 });
    const isUsed = decodeURIComponent(match[1]!) === used;
    if (match[2] === "/utxo") return Response.json(isUsed ? [utxo] : []);
    const stats = { funded_txo_count: isUsed ? 1 : 0, funded_txo_sum: 0, spent_txo_count: 0, spent_txo_sum: 0, tx_count: isUsed ? 1 : 0 };
    const empty = { funded_txo_count: 0, funded_txo_sum: 0, spent_txo_count: 0, spent_txo_sum: 0, tx_count: 0 };
    return Response.json({ address: decodeURIComponent(match[1]!), chain_stats: stats, mempool_stats: empty });
  };
}

function ctScanner(utxo: Record<string, unknown>, verify: ExplorerHdRawTransactionVerifier): ExplorerHdScanner {
  return new ExplorerHdScanner(
    // Two distinct derivations per chain; the used one is external:0.
    ({ chain, index }) => {
      const [address, scriptPubKeyHex] = chain === "external"
        ? (index === 0 ? [DERIVED[0].native_address, DERIVED[0].script_pubkey_hex] : [ADDRESS_3, SCRIPT_3])
        : [ADDRESS_4, SCRIPT_4];
      return { chain, index: index, address, scriptPubKeyHex };
    },
    verify,
    { explorerUrl: "https://explorer.example", fetchImpl: explorer(utxo), gapLimit: 1, maximumIndex: 3, pageSize: 1, concurrency: 1 },
  );
}

const STATUS = { confirmed: true, block_height: 40, block_hash: "e".repeat(64), block_time: 1_790_000_000 };

function blindedVerifier(valueAtomic = "7000"): ExplorerHdRawTransactionVerifier {
  return (request) => ({
    txid: request.expectedTxid,
    outputs: request.expectedWalletOutputs.map((output) => ({
      vout: output.vout,
      scriptPubKeyHex: output.scriptPubKeyHex,
      assetId: ECX,
      valueAtomic,
      blinding: BLINDING_CAMEL,
    })),
  });
}

describe("confidential transactions: scanner", () => {
  it("accepts a confidential UTXO that the core unblinds and carries its blinding", async () => {
    const snapshot = await ctScanner({ txid: txid(7), vout: 1, status: STATUS }, blindedVerifier()).scan();
    assert.equal(snapshot.utxos.length, 1);
    assert.equal(snapshot.utxos[0]?.valueAtomic, "7000");
    assert.deepEqual(snapshot.utxos[0]?.blinding, BLINDING_CAMEL);
  });

  it("cross-checks explorer commitments when the explorer reports them", async () => {
    const withCommitments = {
      txid: txid(7), vout: 1, status: STATUS,
      assetcommitment: BLINDING.asset_commitment_hex, valuecommitment: BLINDING.value_commitment_hex,
    };
    assert.equal((await ctScanner(withCommitments, blindedVerifier()).scan()).utxos.length, 1);
    await assert.rejects(
      ctScanner({ ...withCommitments, valuecommitment: `09${"55".repeat(32)}` }, blindedVerifier()).scan(),
      (error: unknown) => error instanceof ExplorerHdScanError && /commitments disagree/u.test(error.message),
    );
    await assert.rejects(
      ctScanner({ txid: txid(7), vout: 1, status: STATUS, value: 7000, asset: ECX }, blindedVerifier()).scan(),
      /confidential output as explicit/u,
    );
    await assert.rejects(
      ctScanner({ ...withCommitments, value: 7000, asset: ECX }, blindedVerifier()).scan(),
      /mixes explicit and confidential/u,
    );
  });

  it("fails closed when the core cannot unblind a wallet output", async () => {
    await assert.rejects(
      ctScanner({ txid: txid(7), vout: 1, status: STATUS }, () => { throw new Error("does not unblind"); }).scan(),
      /local raw transaction verification failed/u,
    );
  });
});

// --- Session ---------------------------------------------------------------

function snapshotWith(utxos: ExplorerHdSnapshotInput["utxos"]): ExplorerHdSnapshotInput {
  return {
    source: {
      kind: "esplora",
      explorerApiUrl: "https://explorer.example/api",
      genesisHash: NETWORK_IDENTITY.genesisHash,
      nativeAssetId: ECX,
      identityPinsMatched: true,
      headerChainVerified: false,
    },
    tip: { height: 50, hash: BLOCK_HASH },
    scan: {
      gapLimit: 1,
      maximumIndex: 3,
      pageSize: 1,
      chains: [
        { chain: "external", lastScannedIndex: 1, highestUsedIndex: 0, nextUnusedIndex: 1, trailingUnused: 1, pagesScanned: 2 },
        { chain: "change", lastScannedIndex: 0, highestUsedIndex: null, nextUnusedIndex: 0, trailingUnused: 1, pagesScanned: 1 },
      ],
    },
    addresses: [],
    utxos,
    fundingTransactions: [],
  };
}

const EXPLICIT_UTXO = {
  chain: "external" as const, index: 0, address: DERIVED[0].native_address, scriptPubKeyHex: DERIVED[0].script_pubkey_hex,
  vout: 0, txid: txid(1), assetId: ECX, valueAtomic: "3000", status: { confirmed: true },
};
const CT_UTXO = {
  ...EXPLICIT_UTXO, txid: txid(2), vout: 1, valueAtomic: "5000", blinding: BLINDING_CAMEL,
};

function session(fake: FakeCtCore, options: { confidentialReceive?: boolean; fetchImpl?: FetchImplementation; utxos?: ExplorerHdSnapshotInput["utxos"] } = {}) {
  const derives: unknown[] = [];
  const wallet = new ElementsPlusWalletSession(new WalletCoreSession(fake), new WalletCore(async () => bindingsFor(fake)), {
    identity: NETWORK_IDENTITY,
    explorerUrl: "https://explorer.example",
    fetchImpl: options.fetchImpl ?? (async () => new Response("", { status: 404 })),
    ...(options.confidentialReceive === undefined ? {} : { confidentialReceive: options.confidentialReceive }),
    scannerFactory: (derive) => ({
      scan: async () => {
        derives.push(await derive({ chain: "external", index: 0 }));
        return snapshotWith(options.utxos ?? [EXPLICIT_UTXO, CT_UTXO]);
      },
    }),
  });
  return { wallet, derives };
}

describe("confidential transactions: wallet session", () => {
  it("counts confidential funds in balances", async () => {
    const { wallet } = session(new FakeCtCore());
    const snapshot = await wallet.sync();
    assert.deepEqual(snapshot.balances.map((entry) => [entry.assetId, entry.amount, entry.utxoCount]), [[ECX, "8000", 2]]);
    // CT disabled: the receive address stays unconfidential.
    assert.equal(snapshot.receiveAddress, DERIVED[1].native_address);
  });

  it("passes blinding to the core only for confidential UTXOs", async () => {
    const fake = new FakeCtCore();
    const { wallet } = session(fake);
    await wallet.plan({ kind: "transfer", assetId: ECX, recipient: ADDRESS_2, amount: "100", feeRate: 1 });
    const request = fake.calls.find((call) => call.method === "transfer")?.args[0] as { utxos: Record<string, unknown>[] };
    assert.deepEqual(Object.keys(request.utxos[0]!), ["txid", "vout", "value", "asset_id", "script_pubkey_hex", "branch", "index"]);
    assert.deepEqual(request.utxos[1]!["blinding"], BLINDING);
  });

  it("never offers a confidential coin directly; it splits to an explicit output", async () => {
    const fake = new FakeCtCore();
    const { wallet } = session(fake, { utxos: [CT_UTXO] });
    const plan = await wallet.plan({
      kind: "swap_offer", giveAsset: ECX, giveAmount: "5000", wantAsset: TOKEN_A, wantAmount: "1", feeRate: 1,
    } as never);
    assert.equal(plan.offeredOutpoint, null);
    assert.deepEqual(fake.calls.filter((call) => call.method === "offer" || call.method === "split").map((call) => call.method), ["split"]);
  });

  it("shows a confidential receive address when the profile enables CT, scanning by script", async () => {
    const fake = new FakeCtCore();
    const core = new WalletCore(async () => bindingsFor(fake));
    const coreSession = await core.open(MNEMONIC, NETWORK_IDENTITY, { confidentialReceive: true });
    const derives: unknown[] = [];
    const wallet = new ElementsPlusWalletSession(coreSession, core, {
      identity: NETWORK_IDENTITY,
      explorerUrl: "https://explorer.example",
      fetchImpl: async () => new Response("", { status: 404 }),
      confidentialReceive: true,
      scannerFactory: (derive) => ({
        scan: async () => {
          derives.push(await derive({ chain: "external", index: 0 }));
          return snapshotWith([EXPLICIT_UTXO]);
        },
      }),
    });
    const snapshot = await wallet.sync();
    assert.equal(snapshot.receiveAddress, DERIVED[1].confidential_address);
    assert.equal(wallet.primaryAddress(), DERIVED[0].native_address);
    assert.deepEqual(derives, [{ chain: "external", index: 0, address: DERIVED[0].native_address, scriptPubKeyHex: DERIVED[0].script_pubkey_hex }]);
  });

  it("unblinds confidential wallet outputs for activity, skipping foreign ones", async () => {
    const fake = new FakeCtCore();
    fake.verifyResult = (request) => {
      const [output] = request.expectedWalletOutputs;
      if (output!.vout === 2) throw new Error("does not unblind");
      return { txid: request.expectedTxid, outputs: [{ ...output, assetId: ECX, valueAtomic: 4200, blinding: BLINDING }] };
    };
    const fetched: string[] = [];
    const { wallet } = session(fake, {
      fetchImpl: async (input) => {
        fetched.push(new URL(input.toString()).pathname);
        return new Response("0200");
      },
    });
    const result = await wallet.unblindOutputs([
      { txid: txid(5), vout: 1, scriptPubKeyHex: SCRIPT_2 },
      { txid: txid(5), vout: 2, scriptPubKeyHex: SCRIPT_2 },
    ]);
    assert.deepEqual([...result.entries()], [[`${txid(5)}:1`, { assetId: ECX, valueAtomic: "4200" }]]);
    assert.deepEqual(fetched, [`/api/tx/${txid(5)}/hex`]);
  });
});

// --- Activity --------------------------------------------------------------

const WALLET = new Set([SCRIPT_2]);
const STATUS_JSON = { confirmed: true, block_height: 60, block_hash: "e".repeat(64), block_time: 1_790_000_060 };

function ctOut(script: string) {
  return {
    scriptpubkey: script, scriptpubkey_type: "v0_p2wpkh",
    assetcommitment: BLINDING.asset_commitment_hex, valuecommitment: BLINDING.value_commitment_hex,
  };
}

describe("confidential transactions: activity", () => {
  const received = {
    txid: txid(20),
    status: STATUS_JSON,
    vin: [{ txid: txid(19), vout: 0, is_coinbase: false, prevout: ctOut(`0014${"99".repeat(20)}`) }],
    vout: [ctOut(SCRIPT_2), ctOut(`0014${"98".repeat(20)}`), { scriptpubkey: "", scriptpubkey_type: "fee", asset: ECX, value: 300 }],
  };

  it("stays incomplete without unblinding and is exact with it", () => {
    const tx = parseEsploraTx(received);
    const blind = computeActivity(tx, WALLET, ECX);
    assert.equal(blind.complete, false);
    assert.equal("confidential" in blind, false);
    const seen = computeActivity(tx, WALLET, ECX, new Map([[`${txid(20)}:0`, { assetId: ECX, valueAtomic: "9000" }]]));
    assert.equal(seen.complete, true);
    assert.equal(seen.confidential, true);
    assert.equal(seen.kind, "received");
    assert.deepEqual(seen.deltas, [{ assetId: ECX, amount: "9000" }]);
  });

  it("asks the session to unblind only hidden wallet amounts", async () => {
    const requested: unknown[] = [];
    const fetchImpl: FetchImplementation = async () => Response.json([received]);
    const entries = await loadActivity({
      explorerUrl: "https://explorer.example",
      addresses: [{ address: DERIVED[0].native_address, scriptPubKeyHex: SCRIPT_2 }],
      policyAsset: ECX,
      fetchImpl,
      unblind: async (refs) => {
        requested.push(...refs);
        return new Map([[`${txid(20)}:0`, { assetId: ECX, valueAtomic: "9000" }]]);
      },
    });
    assert.deepEqual(requested, [{ txid: txid(20), vout: 0, scriptPubKeyHex: SCRIPT_2 }]);
    assert.deepEqual(entries[0]?.deltas, [{ assetId: ECX, amount: "9000" }]);
    assert.equal(entries[0]?.confidential, true);
  });
});
