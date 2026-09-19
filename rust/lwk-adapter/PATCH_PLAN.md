# Minimal upstream patch plan

The adapter proves that transaction handling is viable, but it must not be
presented as a working LWK scanner until the header type boundary is fixed.

## 1. Add an ECX-aware header representation to rust-elements

Pin `ElementsProject/rust-elements` tag `elements-0.25.3` (peeled commit
`4a3805948eadeb4d02cb552198260b658f8b0949`). Add an opt-in `EcxBlockHeader`
type rather than heuristically interpreting BIP9 bits in every Elements
network. Port the decoder and hash calculation from `src/lib.rs` and retain all
fields:

- optional withdrawal bundle hash (bit 30);
- optional BMM proof hash (bit 20);
- exchange state root (bit 19);
- forced inbox root (bit 18);
- deposit inbox root (bit 17);
- parent height when both inbox roots are present;
- three processed/backlog cursors (bit 16).

Do not discard fields and then calculate a stock Elements hash. That silently
produces a different block identity.

Acceptance tests: the four live fixtures in `tests/live_vectors.rs` must parse,
consume every byte and hash to the explorer's block IDs.

## 2. Make LWK wallet updates carry a network-aware header

At LWK revision `55671e82...`, these concrete sites assume
`elements::BlockHeader`:

- `lwk_wollet/src/update.rs` (`Update.tip` and persistence);
- `lwk_wollet/src/clients/asyncr/esplora.rs` (`tip`, `header`, `get_headers`);
- blocking and Electrum backend traits;
- `lwk_app/src/blockchain_client.rs` and the WASM/UniFFI header wrappers.

Introduce an enum such as `ChainHeader::{Elements(BlockHeader),
Ecx(EcxBlockHeader)}` with common `height()`, `time()` and `block_hash()`
accessors. Persist the variant explicitly by bumping the LWK update encoding;
do not auto-detect ECX from version bits during generic deserialization.

The Esplora client must select the ECX decoder from an explicit network
profile. It must verify `/block-height/0` equals the pinned genesis before its
first scan and after changing endpoint configuration.

## 3. Expose one hard-coded WASM network profile

Add `Network.ecxAlpha()` to `lwk_wasm/src/network.rs`. It must hard-code all
three values in `UPSTREAM_PINS.toml`; do not accept them from a web page or
remote config. The public explorer URL can remain an explicit application
argument so a user may select a trusted/self-hosted backend.

For receive addresses, use witness descriptors only. LWK's generic `ert1...`
addresses are accepted by the pinned node as an alias. The UI may render the
same script as native `elements1...` with `NATIVE_ADDRESS_PARAMS`. Never use
generic Elements Base58 aliases: the node did not add those aliases.

## 4. Complete the explicit-UTXO path through WASM

Current pinned LWK has useful building blocks, including Rust-side
`explicit_utxos()`, `addExplicitRecipient`, and explicit output fields. It is
not a complete browser-wallet path. In the pinned revision, the normal wallet
balance and UTXO APIs omit explicit UTXOs, `explicit_utxos()` is not exported
by `lwk_wasm`, and transaction detail inspection can reject a PSET whose input
is unblinded.

Add a WASM-visible explicit-UTXO enumeration and per-asset balance API. Then
make PSET construction and review accept explicit inputs while preserving the
existing confidential-wallet behavior for other network profiles. The review
model must classify recipient, change, fee, issuance/reissuance, and peg fields
and bind the exact approved summary to the PSET that is signed. Finally add two
release-policy gates:

1. call `preview_explicit_pset` immediately before user confirmation/signing;
2. call `validate_explicit_transaction` immediately before broadcast.

Wallet receive addresses must be unconfidential, and the builder must use the
explicit-recipient path. Any blinding key/commitment in a candidate PSET is a
hard error for this release profile. The adapter's current preview helper is an
explicitness/output-inventory guard only; it is not yet the complete approval
binding described above.

## 5. Required integration tests

1. Network constructor returns the frozen child genesis, Bitcoin parent genesis
   and policy asset.
2. Endpoint with the wrong height-zero hash fails closed before scanning.
3. Scan across heights 84/85, persist, reload and rescan without changing the
   tip hash.
4. Discover and sum an explicit policy-asset UTXO from the live-compatible
   indexer fixture through both Rust and WASM APIs.
5. Build, preview, sign and decode an explicit PSET; verify recipient, change
   and fee asset/amounts.
6. Reject a confidential address, blinding intent, amount commitment or asset
   commitment before signing.
7. Verify a native `elements1...` address and its LWK `ert1...` alias compile to
   the same script.
8. Persist/reload the explicit UTXO set and prove the ordinary WASM balance and
   transaction-history surfaces do not silently omit it.
9. Compile `lwk_wasm` for `wasm32-unknown-unknown` and run the browser tests.

Only after all nine pass should the browser extension use LWK's scanner in a
live build.
