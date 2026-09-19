import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  ElementsPlusWasmAdapter,
  type ElementsPlusScannerFactory,
  type WasmWalletCoreInstance,
} from "../../src/adapters/elementsplus-wasm.js";
import type { FetchImplementation } from "../../src/network/ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";

const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADDRESS = "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh";
const ALIAS = "ert1qw508d6qejxtdg4y5r3zarvary0c5xw7kuu73e0";
const SCRIPT = `0014${"75".repeat(20)}`;
const FUNDING_TXID = "a".repeat(64);
const REVIEW_HASH = "b".repeat(64);
const SIGNED_TXID = "c".repeat(64);
const TIP_HASH = "d".repeat(64);

class FakeWalletCore implements WasmWalletCoreInstance {
  freed = 0;
  signCalls = 0;
  lastPrepareRequest: Record<string, unknown> | undefined;

  constructor(readonly mnemonic: string) {}

  derive_address_json(branch: "external" | "change", index: number): string {
    return JSON.stringify({
      branch,
      index,
      derivation_path: `m/84'/1'/0'/${branch === "external" ? 0 : 1}/${index}`,
      native_address: ADDRESS,
      lwk_alias: ALIAS,
      script_pubkey_hex: SCRIPT,
    });
  }

  prepare_send_json(requestJson: string): string {
    const request = JSON.parse(requestJson) as Record<string, unknown>;
    this.lastPrepareRequest = request;
    assert.equal(request["amount"], 500);
    assert.equal(request["fee"], 344);
    assert.equal(request["recipient"], ADDRESS);
    return JSON.stringify({
      pset_base64: "cHNldP8=",
      review: {
        network: ECX_ALPHA_IDENTITY.displayName,
        genesis_hash: ECX_ALPHA_IDENTITY.genesisHash,
        policy_asset: ECX_ALPHA_IDENTITY.nativeAssetId,
        recipient_native_address: ADDRESS,
        amount: 500,
        fee: 344,
        change: 9_156,
        change_native_address: ADDRESS,
        total_input: 10_000,
        input_count: 1,
        selected_outpoints: [`${FUNDING_TXID}:0`],
      },
      review_hash: REVIEW_HASH,
    });
  }

  sign_prepared_json(preparedJson: string, approvedReviewHash: string): string {
    this.signCalls += 1;
    assert.equal(approvedReviewHash, REVIEW_HASH);
    assert.equal((JSON.parse(preparedJson) as { review_hash: string }).review_hash, REVIEW_HASH);
    return JSON.stringify({
      raw_tx_hex: "00",
      txid: SIGNED_TXID,
      review_hash: REVIEW_HASH,
    });
  }

  verify_raw_transaction_json(requestJson: string): string {
    const request = JSON.parse(requestJson) as {
      expectedTxid: string;
      expectedWalletOutputs: { vout: number; scriptPubKeyHex: string }[];
    };
    return JSON.stringify({
      txid: request.expectedTxid,
      outputs: request.expectedWalletOutputs.map((output) => ({
        ...output,
        assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
        valueAtomic: 10_000,
      })),
    });
  }

  free(): void { this.freed += 1; }
}

function scannerFactory(): ElementsPlusScannerFactory {
  return (deriveAddress, verifyRawTransaction, options) => ({
    async scan(signal) {
      if (signal?.aborted) throw new Error("aborted");
      assert.equal(options.explorerUrl, ECX_ALPHA_IDENTITY.explorerUrl);
      const external = await deriveAddress({ chain: "external", index: 0 });
      const change = await deriveAddress({ chain: "change", index: 0 });
      const verification = await verifyRawTransaction({
        expectedTxid: FUNDING_TXID,
        rawTransactionHex: "00",
        expectedWalletOutputs: [{ ...external, vout: 0 }],
      });
      assert.equal(verification.outputs[0]?.valueAtomic, "10000");
      const emptyStats = Object.freeze({
        fundedOutputCount: 0,
        spentOutputCount: 0,
        transactionCount: 0,
      });
      const usedStats = Object.freeze({
        fundedOutputCount: 1,
        spentOutputCount: 0,
        transactionCount: 1,
      });
      return Object.freeze({
        source: Object.freeze({
          kind: "esplora" as const,
          explorerApiUrl: `${ECX_ALPHA_IDENTITY.explorerUrl}/api`,
          genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
          nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
          identityPinsMatched: true as const,
          headerChainVerified: false as const,
        }),
        tip: Object.freeze({ height: 225, hash: TIP_HASH }),
        scan: Object.freeze({
          gapLimit: 20,
          maximumIndex: 999,
          pageSize: 20,
          chains: Object.freeze([
            Object.freeze({
              chain: "external" as const,
              lastScannedIndex: 20,
              highestUsedIndex: 0,
              nextUnusedIndex: 1,
              trailingUnused: 20,
              pagesScanned: 2,
            }),
            Object.freeze({
              chain: "change" as const,
              lastScannedIndex: 19,
              highestUsedIndex: null,
              nextUnusedIndex: 0,
              trailingUnused: 20,
              pagesScanned: 1,
            }),
          ]),
        }),
        addresses: Object.freeze([
          Object.freeze({ ...external, used: true, chainStats: usedStats, mempoolStats: emptyStats }),
          Object.freeze({ ...change, used: false, chainStats: emptyStats, mempoolStats: emptyStats }),
        ]),
        utxos: Object.freeze([Object.freeze({
          ...external,
          txid: FUNDING_TXID,
          vout: 0,
          assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
          valueAtomic: "10000",
          status: Object.freeze({
            confirmed: true as const,
            blockHeight: 224,
            blockHash: "e".repeat(64),
            blockTime: 1_800_000_000,
          }),
        })]),
        fundingTransactions: Object.freeze([Object.freeze({
          txid: FUNDING_TXID,
          rawTransactionHex: "00",
          outputs: verification.outputs,
        })]),
      });
    },
  });
}

describe("Elements+ WASM adapter", () => {
  it("reports only implemented capabilities and keeps the mnemonic in the local core", async () => {
    let opened: FakeWalletCore | undefined;
    const adapter = new ElementsPlusWasmAdapter({
      loadCore: async () => ({
        WasmWalletCore: class extends FakeWalletCore {
          constructor(mnemonic: string) {
            super(mnemonic);
            opened = this;
          }
        },
        generate_mnemonic: () => MNEMONIC,
        validate_mnemonic: (mnemonic) => mnemonic === MNEMONIC,
      }),
      scannerFactory: scannerFactory(),
      fetchImpl: async () => new Response(SIGNED_TXID),
    });
    assert.equal(adapter.available, true);
    assert.deepEqual(adapter.capabilities, {
      mnemonic: true,
      walletSync: true,
      explicitTransactions: true,
      issuance: false,
      reissuance: false,
      burning: false,
      confidentialTransactions: false,
      dex: false,
    });
    assert.equal(await adapter.generateMnemonic(), MNEMONIC);
    assert.equal(await adapter.validateMnemonic(MNEMONIC), true);
    const session = await adapter.openWallet(MNEMONIC, ECX_ALPHA_IDENTITY);
    assert.equal(opened?.mnemonic, MNEMONIC);
    session.destroy();
    assert.equal(opened?.freed, 1);
    await assert.rejects(session.sync(new AbortController().signal), /destroyed/u);
  });

  it("scans verified explicit UTXOs, binds the core review, signs once, and broadcasts", async () => {
    let opened: FakeWalletCore | undefined;
    let broadcastCalls = 0;
    const fetchImpl: FetchImplementation = async (input, init) => {
      broadcastCalls += 1;
      assert.equal(String(input), `${ECX_ALPHA_IDENTITY.explorerUrl}/api/tx`);
      assert.equal(init?.method, "POST");
      assert.equal(init?.body, "00");
      return new Response(SIGNED_TXID, { status: 200 });
    };
    const adapter = new ElementsPlusWasmAdapter({
      loadCore: async () => ({
        WasmWalletCore: class extends FakeWalletCore {
          constructor(mnemonic: string) {
            super(mnemonic);
            opened = this;
          }
        },
        generate_mnemonic: () => MNEMONIC,
        validate_mnemonic: (mnemonic) => mnemonic === MNEMONIC,
      }),
      scannerFactory: scannerFactory(),
      fetchImpl,
      now: () => new Date("2026-09-19T12:00:00.000Z"),
    });
    const session = await adapter.openWallet(MNEMONIC, ECX_ALPHA_IDENTITY);
    const snapshot = await session.sync(new AbortController().signal);
    assert.equal(snapshot.tipHeight, 225);
    assert.equal(snapshot.chain.headerChainVerified, false);
    assert.equal(snapshot.assets[0]?.amountAtomic, "10000");
    assert.equal(snapshot.assets[0]?.confirmedAtomic, "10000");
    assert.equal(snapshot.syncedAt, "2026-09-19T12:00:00.000Z");

    const prepared = await session.prepareTransfer({
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
      explicitOutputsOnly: true,
    });
    assert.equal(prepared.pset, "cHNldP8=");
    assert.equal(prepared.coreReviewHash, REVIEW_HASH);
    assert.equal(prepared.summary.networkFeeAtomic, "344");
    assert.equal(await session.signAndBroadcast(prepared), SIGNED_TXID);
    assert.equal(opened?.signCalls, 1);
    assert.equal(broadcastCalls, 1);
    await assert.rejects(session.signAndBroadcast(prepared), /already consumed/u);
    assert.equal(opened?.signCalls, 1);
    session.destroy();
  });

  it("fails closed when the broadcaster returns a different txid", async () => {
    const adapter = new ElementsPlusWasmAdapter({
      loadCore: async () => ({
        WasmWalletCore: FakeWalletCore,
        generate_mnemonic: () => MNEMONIC,
        validate_mnemonic: () => true,
      }),
      scannerFactory: scannerFactory(),
      fetchImpl: async () => new Response("f".repeat(64), { status: 200 }),
    });
    const session = await adapter.openWallet(MNEMONIC, ECX_ALPHA_IDENTITY);
    const prepared = await session.prepareTransfer({
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: ADDRESS,
      amountAtomic: "500",
      feeRate: "1",
      explicitOutputsOnly: true,
    });
    await assert.rejects(session.signAndBroadcast(prepared), /different transaction id/u);
    session.destroy();
  });
});
