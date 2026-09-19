# Elements+ / LWK adapter

This directory is the narrow compatibility boundary between LWK and the live
ECX Alpha Elements+ chain. It is **not a wallet** and it is **not a DEX**.

What is implemented and tested:

- immutable upstream and ECX Alpha release pins;
- the exact policy asset, child genesis, parent genesis and native address
  parameters;
- parsing and consensus hashing for both the 79-byte pre-activation headers and
  the 203-byte ECX extended headers served by the live explorer;
- explicit-output balance accounting;
- an explicit-only PSET preview and final-transaction guard.
- deterministic headless mnemonic/key/address derivation followed by PSET
  construction, LWK software signing, Miniscript finalization, wire encoding
  and decoding of a synthetic explicit policy-asset P2WPKH spend.

What is intentionally not claimed:

- Stock LWK cannot yet perform a full Esplora scan of this chain. Its
  `elements::BlockHeader` cannot represent ECX state/inbox header fields.
- Stock LWK's normal balance/UTXO surfaces omit explicit UTXOs, its Rust
  `explicit_utxos()` escape hatch is not exposed through `lwk_wasm`, and its
  transaction-detail path can reject explicit inputs. The browser adapter must
  close those gaps before wallet sync or signing is enabled.
- `Network::CustomElements` still uses generic Elements `ert`/`el` address
  parameters. The ECX node accepts those aliases for witness addresses, but
  they are not chain identity. The extension must pin and verify genesis and
  policy asset before displaying a balance or signing.
- Confidential recipients and blinded outputs are rejected as a conservative
  **wallet policy**. The last published desktop-r2 binary activates an
  explicit-only consensus rule at height 84, while current repository `master`
  re-enables confidential payments without creating a new chain identity. The
  live validator revision cannot be distinguished from genesis alone. An
  explicit transaction is valid under either rule set, so this adapter stays
  inside their safe intersection until the deployment is confirmed.
- LiquiDEX, order relay, swaps and every other DEX concern are out of scope.

Run the deterministic checks:

```sh
cargo test --locked
```

The headless spend is an offline conformance fixture. It proves the pinned
signer and explicit transaction path; it neither connects to the explorer nor
claims that stock LWK can scan ECX's extended headers.

See [PATCH_PLAN.md](PATCH_PLAN.md) for the remaining LWK integration patch and
[docs/compatibility-audit.md](docs/compatibility-audit.md) for the evidence.
