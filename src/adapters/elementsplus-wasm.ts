/**
 * Unlocked wallet session: explorer HD scan + the WASM signing core.
 * Builds core requests from freshly scanned, core-verified UTXOs.
 */
import {
  WalletCore,
  WalletCoreError,
  WalletCoreSession,
  type CoreRequest,
  type CoreUtxo,
  type PreparedTx,
  type SignResult,
} from "./wallet-core.js";
import type { PreparedPlan, WalletOperation } from "../background/operations.js";
import { firstInputOutpoint } from "../background/operations.js";
import type { FetchImplementation } from "../network/esplora.js";
import {
  ExplorerHdScanner,
  type ExplorerHdAddressDeriver,
  type ExplorerHdRawTransactionVerifier,
  type ExplorerHdScanOptions,
  type ExplorerHdSnapshotInput,
} from "../network/explorer-hd-scan.js";
import { esploraApiBase, fetchText } from "../network/http.js";
import type { NetworkIdentity } from "../network/identity.js";

export interface AssetBalance {
  readonly assetId: string;
  readonly amount: string;
  readonly confirmed: string;
  readonly utxoCount: number;
}

export interface WalletSnapshot {
  readonly tipHeight: number;
  readonly receiveAddress: string;
  readonly primaryAddress: string;
  readonly balances: readonly AssetBalance[];
  readonly syncedAt: string;
}

export interface WalletAddress {
  readonly address: string;
  readonly scriptPubKeyHex: string;
}

/** What the controller needs from an unlocked wallet. Faked in tests. */
export interface WalletSession {
  sync(signal?: AbortSignal): Promise<WalletSnapshot>;
  primaryAddress(): string;
  walletAddresses(): Promise<readonly WalletAddress[]>;
  plan(operation: WalletOperation): Promise<PreparedPlan>;
  /** After a broadcast offer-split, prepare the offer on the new exact-amount output. */
  planOfferAfterSplit(
    operation: Extract<WalletOperation, { kind: "swap_offer" }>,
    split: SignResult,
    receiveIndex: number,
  ): Promise<{ readonly prepared: PreparedTx; readonly offeredOutpoint: string }>;
  sign(prepared: PreparedTx, approvedReviewHash: string): SignResult;
  broadcast(rawTxHex: string, txid: string): Promise<string>;
  destroy(): void;
}

interface Scanner {
  scan(signal?: AbortSignal): Promise<ExplorerHdSnapshotInput>;
}

export type ScannerFactory = (
  derive: ExplorerHdAddressDeriver,
  verify: ExplorerHdRawTransactionVerifier,
  options: ExplorerHdScanOptions,
) => Scanner;

export interface SessionOptions {
  readonly identity: NetworkIdentity;
  readonly explorerUrl: string;
  readonly fetchImpl: FetchImplementation;
  readonly scannerFactory?: ScannerFactory;
  readonly now?: () => Date;
}

function fail(message: string): never {
  throw new WalletCoreError(message);
}

export class ElementsPlusWalletSession implements WalletSession {
  readonly #core: WalletCoreSession;
  readonly #module: WalletCore;
  readonly #options: SessionOptions;
  readonly #scanner: Scanner;
  readonly #primary: string;
  #lastScan: ExplorerHdSnapshotInput | undefined;
  #destroyed = false;

  constructor(core: WalletCoreSession, module: WalletCore, options: SessionOptions) {
    this.#core = core;
    this.#module = module;
    this.#options = options;
    const derive: ExplorerHdAddressDeriver = ({ chain, index }) => {
      this.#assertOpen();
      const derived = this.#core.deriveAddress(chain, index);
      return Object.freeze({ chain, index, address: derived.address, scriptPubKeyHex: derived.scriptPubKeyHex });
    };
    const verify: ExplorerHdRawTransactionVerifier = (request) => {
      this.#assertOpen();
      return this.#core.verifyRawTransaction({
        expectedTxid: request.expectedTxid,
        rawTransactionHex: request.rawTransactionHex,
        expectedWalletOutputs: request.expectedWalletOutputs,
      });
    };
    const factory = options.scannerFactory ?? ((d, v, o) => new ExplorerHdScanner(d, v, o));
    this.#scanner = factory(derive, verify, Object.freeze({ explorerUrl: options.explorerUrl, fetchImpl: options.fetchImpl }));
    this.#primary = this.#core.deriveAddress("external", 0).address;
  }

  primaryAddress(): string {
    return this.#primary;
  }

  async sync(signal?: AbortSignal): Promise<WalletSnapshot> {
    const scan = await this.#scan(signal);
    const totals = new Map<string, { total: bigint; confirmed: bigint; count: number }>();
    totals.set(this.#options.identity.nativeAssetId, { total: 0n, confirmed: 0n, count: 0 });
    for (const utxo of scan.utxos) {
      const entry = totals.get(utxo.assetId) ?? { total: 0n, confirmed: 0n, count: 0 };
      const value = BigInt(utxo.valueAtomic);
      entry.total += value;
      entry.count += 1;
      if (utxo.status.confirmed) entry.confirmed += value;
      totals.set(utxo.assetId, entry);
    }
    const native = this.#options.identity.nativeAssetId;
    const balances = [...totals.entries()]
      .map(([assetId, entry]) => Object.freeze({
        assetId,
        amount: entry.total.toString(),
        confirmed: entry.confirmed.toString(),
        utxoCount: entry.count,
      }))
      .sort((a, b) => a.assetId === native ? -1 : b.assetId === native ? 1 : a.assetId.localeCompare(b.assetId));
    return Object.freeze({
      tipHeight: scan.tip.height,
      receiveAddress: this.#receiveAddress(scan),
      primaryAddress: this.#primary,
      balances: Object.freeze(balances),
      syncedAt: (this.#options.now ?? (() => new Date()))().toISOString(),
    });
  }

  async walletAddresses(): Promise<readonly WalletAddress[]> {
    const scan = this.#lastScan ?? await this.#scan();
    const used = scan.addresses.filter((entry) => entry.used);
    const list = used.length > 0 ? used : scan.addresses.filter((entry) => entry.chain === "external" && entry.index === 0);
    return list.map((entry) => Object.freeze({ address: entry.address, scriptPubKeyHex: entry.scriptPubKeyHex }));
  }

  async plan(operation: WalletOperation): Promise<PreparedPlan> {
    // Always rescan so a stale snapshot cannot select already-spent coins.
    const scan = await this.#scan();
    const utxos = this.#utxos(scan);
    const changeIndex = this.#nextIndex(scan, "change");
    const receiveIndex = this.#nextIndex(scan, "external");
    switch (operation.kind) {
      case "transfer":
        return { prepared: this.#prepare({
          op: "transfer",
          recipient: operation.recipient,
          asset_id: operation.assetId,
          amount: operation.amount,
          fee_rate_sat_vb: operation.feeRate,
          utxos,
          change_index: changeIndex,
        }) };
      case "issuance":
        return { prepared: this.#prepare({
          op: "issuance",
          contract: { name: operation.name, ticker: operation.ticker, precision: operation.precision, version: 0 },
          amount: operation.amount,
          token_amount: operation.tokenAmount,
          fee_rate: operation.feeRate,
          utxos,
          change_index: changeIndex,
          receive_index: receiveIndex,
        }) };
      case "swap_offer": {
        const exactUtxo = utxos.find((utxo) => utxo.asset_id === operation.giveAsset && utxo.value === operation.giveAmount);
        if (exactUtxo !== undefined) {
          return {
            prepared: this.#prepare({
              op: "swap_offer",
              utxo: exactUtxo,
              want_asset: operation.wantAsset,
              want_amount: operation.wantAmount,
              receive_index: receiveIndex,
            }),
            offeredOutpoint: `${exactUtxo.txid}:${exactUtxo.vout}`,
          };
        }
        return {
          prepared: this.#prepare({
            op: "offer_split",
            asset_id: operation.giveAsset,
            amount: operation.giveAmount,
            fee_rate: operation.feeRate,
            utxos,
            change_index: changeIndex,
            receive_index: receiveIndex,
          }),
          offeredOutpoint: null,
          splitReceiveIndex: receiveIndex,
        };
      }
      case "swap_take": {
        const inputs = [];
        const decodedOffers = [];
        for (const offer of operation.offers) {
          const [prevTxid] = firstInputOutpoint(offer.tx).split(":");
          const prevoutRawTxHex = await this.#rawTransaction(prevTxid!);
          const decoded = this.#core.decodeOffer(offer, prevoutRawTxHex);
          if (
            decoded.giveAsset !== offer.give.asset_id || decoded.giveAmount !== offer.give.amount
            || decoded.wantAsset !== offer.want.asset_id || decoded.wantAmount !== offer.want.amount
          ) fail("offer summary does not match its signed transaction");
          decodedOffers.push(decoded);
          inputs.push({ offer, prevout_raw_tx_hex: prevoutRawTxHex });
        }
        return {
          prepared: this.#prepare({
            op: "swap_take",
            offers: inputs,
            fee_rate: operation.feeRate,
            utxos,
            change_index: changeIndex,
            receive_index: receiveIndex,
          }),
          decodedOffers,
        };
      }
      case "cancel": {
        const target = utxos.find((utxo) => utxo.txid === operation.txid && utxo.vout === operation.vout);
        if (target === undefined) fail("that offer's coin is not an unspent output of this wallet");
        return {
          prepared: this.#prepare({
            op: "cancel",
            utxo: target,
            change_index: changeIndex,
            fee_rate: operation.feeRate,
            other_utxos: utxos.filter((utxo) => utxo !== target),
          }),
        };
      }
    }
  }

  async planOfferAfterSplit(
    operation: Extract<WalletOperation, { kind: "swap_offer" }>,
    split: SignResult,
    receiveIndex: number,
  ): Promise<{ readonly prepared: PreparedTx; readonly offeredOutpoint: string }> {
    this.#assertOpen();
    if (split.rawTxHex === null) fail("offer preparation did not produce a transaction");
    const destination = this.#core.deriveAddress("external", receiveIndex);
    // Find the exact-amount output locally from the signed bytes (no explorer trust).
    let found: { vout: number; value: string; assetId: string } | undefined;
    for (let vout = 0; vout < 64 && found === undefined; vout += 1) {
      try {
        const verified = this.#core.verifyRawTransaction({
          expectedTxid: split.txid,
          rawTransactionHex: split.rawTxHex,
          expectedWalletOutputs: [{ vout, scriptPubKeyHex: destination.scriptPubKeyHex }],
        });
        const output = verified.outputs.find((entry) => entry.vout === vout);
        if (output !== undefined && output.assetId === operation.giveAsset && output.valueAtomic === operation.giveAmount) {
          found = { vout, value: output.valueAtomic, assetId: output.assetId };
        }
      } catch {
        // Not this vout.
      }
    }
    if (found === undefined) fail("offer preparation did not create the expected output");
    const utxo: CoreUtxo = Object.freeze({
      txid: split.txid,
      vout: found.vout,
      value: found.value,
      asset_id: found.assetId,
      script_pubkey_hex: destination.scriptPubKeyHex,
      branch: "external",
      index: receiveIndex,
    });
    const scan = this.#lastScan ?? await this.#scan();
    return {
      prepared: this.#prepare({
        op: "swap_offer",
        utxo,
        want_asset: operation.wantAsset,
        want_amount: operation.wantAmount,
        receive_index: this.#nextIndex(scan, "external") === receiveIndex ? receiveIndex + 1 : this.#nextIndex(scan, "external"),
      }),
      offeredOutpoint: `${split.txid}:${found.vout}`,
    };
  }

  sign(prepared: PreparedTx, approvedReviewHash: string): SignResult {
    this.#assertOpen();
    return this.#core.sign(prepared, approvedReviewHash);
  }

  async broadcast(rawTxHex: string, txid: string): Promise<string> {
    this.#assertOpen();
    if (!/^(?:[0-9a-f]{2})+$/u.test(rawTxHex) || !/^[0-9a-f]{64}$/u.test(txid)) fail("signed transaction is malformed");
    let body: string;
    try {
      body = (await fetchText(`${esploraApiBase(this.#options.explorerUrl)}/tx`, {
        fetchImpl: this.#options.fetchImpl,
        method: "POST",
        body: rawTxHex,
        accept: "text/plain",
        contentType: "text/plain",
        maxBytes: 4_096,
        timeoutMs: 20_000,
      })).trim();
    } catch (error) {
      return fail(`broadcast failed: ${error instanceof Error ? error.message : "network error"}`);
    }
    if (body !== txid) fail("explorer accepted a different transaction id");
    return body;
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#lastScan = undefined;
    this.#core.free();
  }

  #prepare(request: CoreRequest): PreparedTx {
    this.#assertOpen();
    return this.#core.prepare(request);
  }

  async #scan(signal?: AbortSignal): Promise<ExplorerHdSnapshotInput> {
    this.#assertOpen();
    const scan = await this.#scanner.scan(signal);
    this.#assertOpen();
    const identity = this.#options.identity;
    if (
      scan.source.genesisHash !== identity.genesisHash
      || scan.source.nativeAssetId !== identity.nativeAssetId
      || scan.source.identityPinsMatched !== true
    ) fail("explorer is not serving the pinned network");
    this.#lastScan = scan;
    return scan;
  }

  #utxos(scan: ExplorerHdSnapshotInput): CoreUtxo[] {
    return scan.utxos.map((utxo) => Object.freeze({
      txid: utxo.txid,
      vout: utxo.vout,
      value: utxo.valueAtomic,
      asset_id: utxo.assetId,
      script_pubkey_hex: utxo.scriptPubKeyHex,
      branch: utxo.chain,
      index: utxo.index,
    }));
  }

  #nextIndex(scan: ExplorerHdSnapshotInput, chain: "external" | "change"): number {
    const state = scan.scan.chains.find((entry) => entry.chain === chain);
    if (state === undefined) fail(`scanner did not return the ${chain} branch`);
    return state.nextUnusedIndex;
  }

  #receiveAddress(scan: ExplorerHdSnapshotInput): string {
    const index = this.#nextIndex(scan, "external");
    return scan.addresses.find((entry) => entry.chain === "external" && entry.index === index)?.address
      ?? this.#core.deriveAddress("external", index).address;
  }

  async #rawTransaction(txid: string): Promise<string> {
    const hex = (await fetchText(`${esploraApiBase(this.#options.explorerUrl)}/tx/${txid}/hex`, {
      fetchImpl: this.#options.fetchImpl,
      accept: "text/plain",
      maxBytes: 8 * 1024 * 1024 + 2,
    })).trim();
    if (!/^(?:[0-9a-f]{2})+$/u.test(hex)) fail("explorer returned a malformed raw transaction");
    return hex;
  }

  #assertOpen(): void {
    if (this.#destroyed) fail("wallet session is closed");
  }
}

/** Opens sessions for the controller. */
export class ElementsPlusWalletFactory {
  constructor(
    readonly core: WalletCore,
    private readonly options: Omit<SessionOptions, "explorerUrl">,
  ) {}

  generateMnemonic(): Promise<string> {
    return this.core.generateMnemonic();
  }

  validateMnemonic(mnemonic: string): Promise<boolean> {
    return this.core.validateMnemonic(mnemonic);
  }

  /** Find which input of a signed issuance carries `assetId` (registry needs `issuance_vin`). */
  async findIssuanceVin(
    rawTxHex: string,
    txid: string,
    contract: Record<string, unknown>,
    assetId: string,
    inputCount: number,
  ): Promise<number> {
    for (let vin = 0; vin < Math.max(1, inputCount); vin += 1) {
      try {
        const verified = await this.core.verifyAssetIssuance({ rawTxHex, expectedTxid: txid, vin, contract });
        if (verified.assetId === assetId) return vin;
      } catch {
        // Not the issuance input.
      }
    }
    return fail("could not locate the issuance input");
  }

  async open(mnemonic: string, explorerUrl: string): Promise<WalletSession> {
    const session = await this.core.open(mnemonic, this.options.identity);
    try {
      return new ElementsPlusWalletSession(session, this.core, { ...this.options, explorerUrl });
    } catch (error) {
      session.free();
      throw error;
    }
  }
}
