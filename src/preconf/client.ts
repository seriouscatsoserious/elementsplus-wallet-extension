import type { SignedTransaction } from "../adapters/lwk.js";
import type { PreconfirmationClient } from "../background/controller.js";
import type { ExtensionStorageArea } from "../platform/browser.js";
import { hasExactKeys, isPlainRecord } from "../shared/validation.js";
import { ReceiptMonitor } from "./monitor.js";

const STORAGE_KEY = "elementsplus.preconfirmation.v1";
const HASH = /^[0-9a-f]{64}$/u;
const OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/u;
const SIGNATURE = /^[0-9a-f]{128}$/u;
const REQUEST_TIMEOUT_MS = 20_000;

export interface PreconfirmationRuntimeConfig {
  readonly version: 1;
  readonly endpoint: string;
  readonly relayUrls: readonly string[];
  readonly profile: string;
  readonly bond: string;
  readonly authToken: string;
  readonly operatorConfig: Readonly<Record<string, unknown>>;
  readonly protectedOutput: string;
}

interface Receipt {
  readonly bond: string;
  readonly txid: string;
  readonly signature: string;
}

type VerifyReceipt = (configJson: string, receiptJson: string) => boolean;
type WebSocketConstructor = typeof WebSocket;

function parseEndpoint(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > 2_048) throw new Error(`${label} is malformed`);
  const url = new URL(value);
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "wss:" && !(url.protocol === "ws:" && loopback)) || url.username !== "" || url.password !== "" || url.hash !== "") {
    throw new Error(`${label} requires wss (or loopback ws) without credentials or fragments`);
  }
  return url.href;
}

export function parsePreconfirmationConfig(value: unknown): PreconfirmationRuntimeConfig {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["version", "endpoint", "relayUrls", "profile", "bond", "authToken", "operatorConfig"])) {
    throw new Error("preconfirmation configuration is malformed");
  }
  if (value["version"] !== 1 || typeof value["profile"] !== "string" || !HASH.test(value["profile"])
    || typeof value["bond"] !== "string" || !OUTPOINT.test(value["bond"])
    || typeof value["authToken"] !== "string" || value["authToken"].length < 32 || value["authToken"].length > 1_024
    || !isPlainRecord(value["operatorConfig"]) || !Array.isArray(value["relayUrls"])
    || value["relayUrls"].length < 2 || value["relayUrls"].length > 8) {
    throw new Error("preconfirmation configuration is malformed");
  }
  const operatorConfig = value["operatorConfig"];
  if (typeof operatorConfig["protected_output"] !== "string" || !OUTPOINT.test(operatorConfig["protected_output"])) {
    throw new Error("operator configuration has a malformed protected output");
  }
  const relayUrls = value["relayUrls"].map((url, index) => parseEndpoint(url, `relay ${index}`));
  if (new Set(relayUrls).size !== relayUrls.length) throw new Error("preconfirmation relays must be distinct");
  return Object.freeze({
    version: 1,
    endpoint: parseEndpoint(value["endpoint"], "signer endpoint"),
    relayUrls: Object.freeze(relayUrls),
    profile: value["profile"],
    bond: value["bond"],
    authToken: value["authToken"],
    operatorConfig: Object.freeze({ ...operatorConfig }),
    protectedOutput: operatorConfig["protected_output"],
  });
}

function parseReceipt(value: unknown, expectedBond: string, expectedTxid: string): Receipt {
  if (!isPlainRecord(value) || !hasExactKeys(value, ["bond", "txid", "signature"])
    || value["bond"] !== expectedBond || value["txid"] !== expectedTxid
    || typeof value["signature"] !== "string" || !SIGNATURE.test(value["signature"])) {
    throw new Error("preconfirmation receipt is malformed or for a different transaction");
  }
  return Object.freeze({ bond: expectedBond, txid: expectedTxid, signature: value["signature"] });
}

export class StoredPreconfirmationClient implements PreconfirmationClient {
  readonly #storage: ExtensionStorageArea;
  readonly #verify: VerifyReceipt;
  readonly #WebSocket: WebSocketConstructor;
  #socket: WebSocket | undefined;
  #ready: Promise<WebSocket> | undefined;
  #config: PreconfirmationRuntimeConfig | undefined;
  #monitor: ReceiptMonitor | undefined;
  #accepted = new Map<string, string>();
  #compromised = false;

  constructor(storage: ExtensionStorageArea, verify: VerifyReceipt, WebSocketImpl: WebSocketConstructor = WebSocket) {
    this.#storage = storage;
    this.#verify = verify;
    this.#WebSocket = WebSocketImpl;
  }

  async isEnabled(): Promise<boolean> {
    const stored = await this.#storage.get(STORAGE_KEY);
    return stored[STORAGE_KEY] !== undefined;
  }

  async requiredInput(): Promise<string> {
    return (await this.#loadConfig()).protectedOutput;
  }

  async preconfirm(transaction: SignedTransaction): Promise<{ readonly txid: string }> {
    if (!HASH.test(transaction.txid) || !/^(?:[0-9a-f]{2})+$/u.test(transaction.rawTransactionHex)) {
      throw new Error("signed transaction is malformed");
    }
    const config = await this.#loadConfig();
    if (this.#compromised) throw new Error("conflicting operator receipts were observed; preconfirmation is disabled");
    const socket = await this.#connect(config);
    const requestId = crypto.randomUUID();
    const response = await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("preconfirmation signer timed out")), REQUEST_TIMEOUT_MS);
      const listener = (event: MessageEvent<unknown>) => {
        let message: unknown;
        try { message = typeof event.data === "string" ? JSON.parse(event.data) : undefined; } catch { message = undefined; }
        if (!isPlainRecord(message) || message["request_id"] !== requestId) return;
        clearTimeout(timer);
        socket.removeEventListener("message", listener);
        if (message["type"] === "error") reject(new Error(typeof message["reason"] === "string" ? message["reason"] : "preconfirmation rejected"));
        else resolve(message);
      };
      socket.addEventListener("message", listener);
      socket.send(JSON.stringify({ type: "preconfirm", request_id: requestId, bond: config.bond, raw_tx: transaction.rawTransactionHex }));
    });
    if (!isPlainRecord(response) || !hasExactKeys(response, ["type", "request_id", "receipt", "relay_acks"])
      || response["type"] !== "preconfirmed" || typeof response["relay_acks"] !== "number"
      || !Number.isSafeInteger(response["relay_acks"]) || response["relay_acks"] !== config.relayUrls.length) {
      throw new Error("preconfirmation signer response is malformed");
    }
    const receipt = parseReceipt(response["receipt"], config.bond, transaction.txid);
    if (!this.#verify(JSON.stringify(config.operatorConfig), JSON.stringify(receipt))) {
      throw new Error("preconfirmation receipt signature is invalid");
    }
    const monitor = this.#receiptMonitor(config);
    this.#accepted.set(receipt.bond, receipt.txid);
    await this.#waitForObservation(monitor, receipt);
    return Object.freeze({ txid: transaction.txid });
  }

  disconnect(): void {
    this.#socket?.close(1000, "wallet locked");
    this.#socket = undefined;
    this.#ready = undefined;
    this.#monitor?.stop();
    this.#monitor = undefined;
    this.#accepted.clear();
    this.#compromised = false;
    this.#config = undefined;
  }

  async #loadConfig(): Promise<PreconfirmationRuntimeConfig> {
    if (this.#config !== undefined) return this.#config;
    const stored = await this.#storage.get(STORAGE_KEY);
    this.#config = parsePreconfirmationConfig(stored[STORAGE_KEY]);
    return this.#config;
  }

  async #connect(config: PreconfirmationRuntimeConfig): Promise<WebSocket> {
    if (this.#socket?.readyState === 1) return this.#socket;
    if (this.#ready !== undefined) return await this.#ready;
    this.#ready = new Promise<WebSocket>((resolve, reject) => {
      const socket = new this.#WebSocket(config.endpoint);
      const timer = setTimeout(() => { socket.close(); reject(new Error("preconfirmation signer connection timed out")); }, REQUEST_TIMEOUT_MS);
      socket.addEventListener("open", () => socket.send(JSON.stringify({ type: "authenticate", token: config.authToken, profile: config.profile })), { once: true });
      socket.addEventListener("message", (event: MessageEvent<unknown>) => {
        let message: unknown;
        try { message = typeof event.data === "string" ? JSON.parse(event.data) : undefined; } catch { message = undefined; }
        if (isPlainRecord(message) && hasExactKeys(message, ["type", "profile"])
          && message["type"] === "ready" && message["profile"] === config.profile) {
          clearTimeout(timer); this.#socket = socket; resolve(socket);
        }
      });
      socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("preconfirmation signer connection failed")); }, { once: true });
      socket.addEventListener("close", () => { if (this.#socket === socket) this.#socket = undefined; this.#ready = undefined; });
    });
    try { return await this.#ready; } finally { this.#ready = undefined; }
  }

  #receiptMonitor(config: PreconfirmationRuntimeConfig): ReceiptMonitor {
    if (this.#monitor !== undefined) return this.#monitor;
    const configJson = JSON.stringify(config.operatorConfig);
    const monitor = new ReceiptMonitor({
      profile: config.profile,
      bonds: [config.bond],
      relays: config.relayUrls,
      WebSocketImpl: this.#WebSocket,
      verifyReceipt: (receipt) => this.#verify(configJson, JSON.stringify(receipt)),
    });
    monitor.addEventListener("change", () => {
      for (const [bond, txid] of this.#accepted) {
        if (monitor.observation(bond, txid).conflicted) this.#compromised = true;
      }
    });
    monitor.start();
    this.#monitor = monitor;
    return monitor;
  }

  async #waitForObservation(monitor: ReceiptMonitor, receipt: Receipt): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const inspect = () => {
        const observation = monitor.observation(receipt.bond, receipt.txid);
        if (observation.conflicted) {
          cleanup(); reject(new Error("conflicting preconfirmation detected"));
        } else if (observation.monitoringReady && observation.observedEverywhere) {
          cleanup(); resolve();
        }
      };
      const cleanup = () => { clearTimeout(timer); monitor.removeEventListener("change", inspect); };
      const timer = setTimeout(() => { cleanup(); reject(new Error("relay observation timed out")); }, REQUEST_TIMEOUT_MS);
      monitor.addEventListener("change", inspect);
      inspect();
    });
  }
}
