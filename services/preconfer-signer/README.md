# Elements+ preconfer signer

This is the operator-only half of the fixed-session preconfirmation prototype. It accepts locally signed transactions over a persistent authenticated WebSocket; it never holds user wallet keys.

The service refuses to start on a profile/key mismatch, a torn or mismatched journal, permissive secret-file modes, or fewer than two relay endpoints. A signed decision is fsynced before relay publication and broadcast. Once a bond has a decision, only the identical txid is retryable.

Run:

```sh
cargo run --release --manifest-path services/preconfer-signer/Cargo.toml -- services/preconfer-signer/config.json
```

Compile an operator configuration into the exact covenant funding template:

```sh
cargo run --release --manifest-path services/preconfer-signer/Cargo.toml \
  --bin preconf-bond -- operator-config.json
```

The output includes the scriptPubKey, raw descriptor, asset and exact atomic collateral amount. Fund that output, confirm it, then put its real `txid:vout` into the single-session relay profile. The tool does not control an operator wallet or move funds.

Expose the loopback listener only through an authenticated, rate-limited TLS reverse proxy. See `../../docs/PRECONFIRMATIONS.md` for provisioning and unresolved limits.
