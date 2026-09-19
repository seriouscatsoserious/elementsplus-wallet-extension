# Elements+ wallet core

This crate is the smallest current **offline signing core** for the ECX Alpha
browser-wallet prototype. It pins the audited LWK revision and ECX chain
identity through `elementsplus-lwk-adapter` and supports only one conservative
transaction shape:

- BIP39 English 12-word mnemonic;
- `m/84'/1'/0'/0/index` receive and `m/84'/1'/0'/1/index` change paths;
- unconfidential P2WPKH (`elements1...`, with equivalent `ert1...` alias);
- explicit ECX policy-asset inputs and outputs;
- one recipient, optional wallet-owned change, and one explicit fee output.

The core verifies caller-supplied UTXOs belong to the mnemonic, selects them in
a deterministic outpoint order, builds a PSET, and produces a human review
summary. `sign_prepared` reparses the PSET, independently recomputes the
summary, and requires approval of a domain-separated SHA-256 commitment to the
exact serialized PSET. It then uses the pinned LWK software signer, finalizes
and verifies every P2WPKH witness, confirms no non-witness data changed, checks
all outputs remain explicit, and returns raw transaction hex plus txid.

## What this does not do

This is not yet a complete wallet and deliberately makes no claim to be one.

- It does not scan ECX headers, discover UTXOs, prove explorer responses,
  estimate fees, track spends, or broadcast.
- `VerifiedUtxo` means *the caller* verified chain inclusion and spend status.
  The core checks ownership and transaction invariants, not chain state.
- It does not support confidential addresses, issuance, peg-ins, arbitrary
  scripts, multiple assets, or a DEX.
- It does not resolve the current live-network deployment ambiguity: the old
  desktop release and current Elements+ `master` share genesis while differing
  in confidential-output policy. Explicit transactions are the safe common
  subset.

Before real funds or public test coins are used, the sidechain maintainer must
confirm the exact live validator commit/binaries and provide a supported
funding/deposit route (or a funded sidechain UTXO). A scanner must also verify
ECX's extended headers or the product must clearly disclose that it trusts the
configured explorer.

## Verify

```sh
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
```

The `headless` integration test uses only public BIP39 test vectors and
synthetic outpoints. It proves mnemonic → native/alias address → deterministic
multi-input PSET → review commitment → LWK signatures → final witnesses → raw
transaction/txid, including mutation, foreign-script, and duplicate-input
rejection. It does not broadcast.

`verify_raw_transaction` is the scanner's fail-closed local decoding boundary.
Given an expected txid, raw consensus transaction hex, and expected wallet
vout/scripts, it recomputes the txid and returns only matching, fully explicit
P2WPKH outputs with exact atomic `u64` values. It deliberately does not prove
confirmation, inclusion, or unspent status.

There is also an ignored, opt-in funded regtest test. It discovers the running
node's genesis and policy asset, asks the node wallet to fund a core-derived
address, signs a real child transaction in the core, broadcasts it through
`elements-cli`, and verifies that exact txid entered the mempool:

```sh
ELEMENTS_CLI=/path/to/elements-cli \
ELEMENTS_DATADIR=/path/to/disposable/regtest \
ELEMENTS_RPCPORT=19843 \
ELEMENTS_RPCWALLET=funding \
cargo test --locked --test funded_elements -- --ignored --nocapture
```

This spends disposable regtest coins and therefore refuses to run unless
`ELEMENTS_DATADIR` is explicitly set.

For a browser build, install the Rust WASM target and compile the optional JSON
wrapper:

```sh
rustup target add wasm32-unknown-unknown
cargo check --locked --target wasm32-unknown-unknown --features wasm
```

The intended MV3 architecture is to instantiate `WasmWalletCore` only in an
offscreen document or extension worker, never in a content script. Keep the
mnemonic inside the encrypted extension vault, pass only PSET/review data to
the UI, and keep scanning and broadcasting in separate adapters. The
`wasm-bindgen` wrapper generates an explicit JavaScript `.free()` method; call
it when locking the wallet so Rust drops the signer and LWK performs its
best-effort secret zeroization.
