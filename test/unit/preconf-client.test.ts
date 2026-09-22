import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parsePreconfirmationConfig, StoredPreconfirmationClient } from "../../src/preconf/client.js";
import type { ExtensionStorageArea } from "../../src/platform/browser.js";

const valid = {
  version: 1,
  endpoint: "ws://127.0.0.1:8788",
  relayUrls: ["wss://relay-one.example.test/preconf", "wss://relay-two.example.test/preconf"],
  profile: "1".repeat(64),
  bond: `${"2".repeat(64)}:3`,
  authToken: "x".repeat(32),
  operatorConfig: { protected_output: `${"3".repeat(64)}:4` },
};

describe("preconfirmation configuration", () => {
  it("accepts a pinned fixed session and derives its protected input", () => {
    const config = parsePreconfirmationConfig(valid);
    assert.equal(config.protectedOutput, `${"3".repeat(64)}:4`);
    assert.equal(config.endpoint, "ws://127.0.0.1:8788/");
  });

  it("rejects plaintext remote endpoints and unknown fields", () => {
    assert.throws(() => parsePreconfirmationConfig({ ...valid, endpoint: "ws://example.test" }), /requires wss/u);
    assert.throws(() => parsePreconfirmationConfig({ ...valid, surprise: true }), /malformed/u);
  });

  it("authenticates once and requires its receipt in both relay snapshots", async () => {
    const txid = "4".repeat(64);
    const receipt = { bond: valid.bond, txid, signature: "5".repeat(128) };
    class MemoryStorage implements ExtensionStorageArea {
      async get() { return { "elementsplus.preconfirmation.v1": valid }; }
      async set() {}
      async remove() {}
    }
    class FakeSocket {
      readyState = 0;
      readonly #listeners = new Map<string, Set<(event: { data?: string }) => void>>();
      constructor(readonly url: string) { queueMicrotask(() => { this.readyState = 1; this.#emit("open", {}); }); }
      addEventListener(type: string, listener: (event: { data?: string }) => void) {
        const listeners = this.#listeners.get(type) ?? new Set(); listeners.add(listener); this.#listeners.set(type, listeners);
      }
      removeEventListener(type: string, listener: (event: { data?: string }) => void) { this.#listeners.get(type)?.delete(listener); }
      send(text: string) {
        const message = JSON.parse(text) as Record<string, unknown>;
        if (message["type"] === "authenticate") this.#message({ type: "ready", profile: valid.profile });
        else if (message["type"] === "preconfirm") this.#message({ type: "preconfirmed", request_id: message["request_id"], receipt, relay_acks: 2 });
        else if (message["type"] === "subscribe") {
          this.#message({ type: "begin", profile: valid.profile, stream: "6".repeat(64), from: 0, through: 1 });
          this.#message({ type: "event", event: { seq: 1, receipt, conflict_with: null } });
          this.#message({ type: "caught_up", cursor: { stream: "6".repeat(64), seq: 1 } });
        }
      }
      close() { this.readyState = 3; }
      #message(value: unknown) { queueMicrotask(() => this.#emit("message", { data: JSON.stringify(value) })); }
      #emit(type: string, event: { data?: string }) { for (const listener of this.#listeners.get(type) ?? []) listener(event); }
    }
    let verifications = 0;
    const client = new StoredPreconfirmationClient(
      new MemoryStorage(),
      () => { verifications += 1; return true; },
      FakeSocket as unknown as typeof WebSocket,
    );
    assert.equal(await client.isEnabled(), true);
    assert.deepEqual(await client.preconfirm({ txid, rawTransactionHex: "00" }), { txid });
    assert.equal(verifications, 3);
    client.disconnect();
  });
});
