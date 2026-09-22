# Fixed-session preconfirmation prototype

This branch joins the merged Elements+ operator-bond covenant to the browser wallet and a new operator signer. It is a test implementation, not a production security claim or audit.

## User flow

The visible flow remains `review → approve → preconfirmed → confirmed`. The wallet signs locally. The preconfer never receives the mnemonic or any wallet private key.

When preconfirmation is configured, the wallet deliberately spends the profile's exact `protected_output`. It sends the already-signed raw transaction over an authenticated WebSocket. The signer checks the live chain, the funded/unspent operator bond, the transaction's protected input, and node mempool acceptance. It then signs and fsyncs one decision for that bond, publishes the receipt to every configured relay, waits for durable acknowledgements, and broadcasts through the trusted node.

The wallet verifies the Schnorr receipt locally with the vendored merged covenant code. It independently replays at least two distinct relay snapshots, requires its receipt to be present in both, and rejects any valid same-bond receipt for another txid before showing `Preconfirmed`.

## Hard limits of this milestone

- A deployment profile contains exactly one session. It protects one specific principal output and permits one txid. After that output is spent, a new funded bond/session/profile must be provisioned. Automatic rolling sessions are not implemented.
- Relay checks are caught-up snapshots at acceptance time. Continuous post-acceptance conflict alerts and persisted cursors are the next milestone.
- The signer is centralized and online. The bond makes equivocation punishable; it does not make the service available and does not identify which victim should receive collateral.
- Two relays reduce a single-relay omission attack, but operators should deploy them independently. A fully partitioned recipient can still accept stale information.
- Normal block confirmation remains the final settlement. “Preconfirmed” is explicitly not “confirmed.”
- The node RPC schema and live covenant-funding transaction must be tested on the actual Elements+ network before funds are used.

## Provisioning

Build the signer with:

```sh
cargo build --release --manifest-path services/preconfer-signer/Cargo.toml
```

Copy `services/preconfer-signer/config.example.json`, place the merged relay `profile.json` beside it, and create two mode-`0600` files:

- `preconfer.secret`: one 32-byte secret key encoded as 64 lowercase hex characters;
- `wallet.secret`: 32–1024 bytes of random authentication material.

The preconfer public key in every profile session must match the secret. Put TLS and client rate limits in front of the loopback signer and relays. Never put RPC credentials in browser configuration.

Before creating the single-session profile, compile the operator configuration into its exact funding template:

```sh
cargo run --release --manifest-path services/preconfer-signer/Cargo.toml \
  --bin preconf-bond -- operator-config.json
```

The tool outputs the covenant scriptPubKey, `raw(...)` descriptor, native asset and atomic collateral amount without moving funds. Use the trusted Elements+ wallet/node to fund that exact explicit output, wait for confirmation, and then use its real `txid:vout` as the profile's only `bond`. This deliberately keeps wallet spending authority out of the signer service.

The extension reads `elementsplus.preconfirmation.v1` from `storage.local`. Until a settings screen exists, provision the test extension from its own developer-tools console:

```js
await chrome.storage.local.set({
  "elementsplus.preconfirmation.v1": {
    version: 1,
    endpoint: "wss://signer.example/preconfirm",
    relayUrls: ["wss://relay-one.example/preconf", "wss://relay-two.example/preconf"],
    profile: "<64-lowercase-hex profile id printed by the signer>",
    bond: "<bond-txid>:<vout>",
    authToken: "<contents of wallet.secret>",
    operatorConfig: {
      genesis: "<genesis>",
      fee_asset: "<asset id>",
      preconfer: "<x-only public key>",
      protected_output: "<principal-txid>:<vout>",
      epoch: "<decimal epoch>",
      collateral: 100000,
      active_until: 1000,
      refund_height: 1010
    }
  }
});
```

With no such storage key, the existing explorer broadcast path is unchanged.

## Required live test

Before public use, run an isolated funded network test that proves:

1. the node reports the expected genesis, fee asset, bond script and exact collateral;
2. one wallet send reaches `Preconfirmed` and then a block confirmation;
3. an identical retry is idempotent;
4. a second txid for the same bond is refused after process restart;
5. either relay missing the receipt prevents wallet acceptance;
6. a valid conflicting receipt causes rejection;
7. an expired, spent, wrong-chain, wrong-script or underfunded bond is refused.
