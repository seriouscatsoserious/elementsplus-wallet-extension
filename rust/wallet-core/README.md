# Elements+ wallet core

This crate is the **offline signing core** for the Elements+ browser wallet
and `epw` (spec: `docs/V2-SPEC.md` §1–§2). It pins the audited LWK revision
through `elementsplus-lwk-adapter` and takes chain identity from the typed
profile registry in `src/network.rs` (`ecx-beta`, `ecx-mainnet`,
`elementsplus-regtest`; archived `ecx-alpha` for historical vectors only; see
`docs/NETWORKS.md`). `WalletCore::for_profile` refuses pending profiles whose
sidechain pins are not yet published. The WASM constructor uses only the
profile compiled in via `ELEMENTSPLUS_NETWORK_PROFILE` (set by
`scripts/build-wasm.mjs`); the regtest build adds `forRegtest`.

- BIP39 English 12-word mnemonic;
- `m/84'/1'/0'/0/index` receive and `m/84'/1'/0'/1/index` change paths;
- unconfidential P2WPKH in the profile's native encoding (ECX Alpha used
  `elements1...` with an equivalent `ert1...` alias), and opt-in confidential
  P2WPKH (`elementsl1...` / `el1...`, SLIP-77);
- explicit inputs and outputs of **any asset**, plus confidential (blinded)
  ones in transfers, issuances, offer splits and cancels (see below); the fee
  is always one explicit policy-asset output.

Operations, each returning `PreparedTx { pset_base64, review, review_hash }`:
`prepare_transfer`, `prepare_issuance` (explicit new issuance, contract hash
over canonical sorted-key JSON), `prepare_offer_split`, `prepare_swap_offer`
(maker, one whole UTXO, `SIGHASH_SINGLE|ANYONECANPAY`), `take_swap_offers`
(taker, maker pairs at indices `0..n`, maker witnesses preserved, taker inputs
`SIGHASH_ALL`), and `prepare_cancel`. Fees are computed from an upper-bound
size estimate × `fee_rate` (1–1000 sat/vB), never supplied by the caller.

Every operation produces one `TxReview` recomputed **from the PSET alone**:
kind, per-asset net balance change (excluding fee), fee, outputs paying
non-wallet scripts, inputs signed, foreign (maker) inputs, issuance details,
and the sighash. A wallet input/output is one whose single BIP32 derivation
under this wallet's fingerprint re-derives to its script; everything else is
external. `review_hash = SHA256("ECX_ALPHA_TX_REVIEW_V2\0" ‖ PSET ‖ review
JSON)`. `sign_prepared` re-parses the PSET, recomputes the review and hash,
refuses any mismatch with the prepared review or the approved hash, signs
only wallet inputs with the declared sighash via the pinned LWK signer,
finalizes them itself (maker witnesses are never rebuilt), verifies every
input signature against a recomputed sighash, and returns raw transaction hex
— or, for swap offers, the signed offer JSON (§2).

`decode_offer` checks the offer's `network` (profile id) and `genesis_hash`,
then verifies it against its funding transaction (which must
hash to the offered txid) and the maker's 0x83 signature.
`verify_asset_issuance` recomputes contract hash → entropy → asset/token ids
from an issuance input.

## Confidential transactions

- **Keys.** A SLIP-77 master blinding key is derived from the BIP39 seed
  exactly as LWK/Green do (`SwSigner::slip77_master_blinding_key`); each
  script's blinding key derives from it.
- **Addresses.** `derive_address` stays unconfidential unless
  `set_confidential_receive(true)` (default **off**; the WASM wrapper exposes
  the same switch). `derive_address_with(branch, index, Some(bool))`
  overrides per call. Confidential results add `confidential_address`,
  `confidential_lwk_alias` and `blinding_pubkey_hex`; `native_address` keeps
  naming the script, so explorer lookups are unchanged.
- **Receiving.** `WalletCore::verify_raw_transaction` (the keyless free
  function stays explicit-only) unblinds fully confidential wallet outputs
  with the script's key: `TxOut::unblind` rewinds and thereby verifies the
  rangeproof against the value commitment and recomputes the asset
  generator; the recovered secrets must re-open both commitments, a
  surjection proof must be present, and the value must be in the money range.
  Anything that does not unblind with our key fails verification. The output
  gains `blinding {asset_commitment_hex, value_commitment_hex,
  asset_blinder_hex, value_blinder_hex}` (blinders in Elements RPC byte
  order). The surjection proof itself is not verified here (it needs the
  spent prevouts); consensus checked it for confirmed transactions.
- **Spending.** `VerifiedUtxo.blinding` (as returned above) makes a UTXO
  spendable; the core re-opens the commitments for the claimed asset/value
  and refuses tampered blinders or values. A confidential input carries the
  confidential prevout plus PSET v2 explicit value/asset proofs, so the PSET
  alone proves its exact amount. Outputs: a confidential recipient address
  gets a blinded output, an unconfidential one an explicit output; change is
  blinded to our own key whenever any input is confidential, otherwise
  explicit; the fee is always explicit. If confidential inputs would leave no
  blinded output, coin selection reserves a policy change of at least the
  dust limit. Blinding (`blind_last`, explicit inputs contribute zero
  blinders, issuances stay explicit) happens before the review, so the review
  hash commits to the blinded PSET bytes; re-blinding yields a new hash.
- **Review.** For confidential PSETs the review verifies every input and
  output explicit-value/asset proof, runs `verify_tx_amt_proofs` (commitment
  balance, rangeproofs, surjection proofs against the prevouts), requires
  blinded wallet outputs to unblind with our key to exactly the reviewed
  amounts, and sets `confidential: true` (external blinded outputs show their
  confidential address and `confidential: true`). Deltas stay exact.
  Explicit reviews and their JSON are unchanged. Signing re-runs the proof
  checks on the final transaction.
- **Fees.** The size model adds an upper bound per blinded output (52-bit
  rangeproof ≤ 4174 bytes, surjection proof ≤ 162 bytes) to the explicit
  P2WPKH model.
- **Swaps stay explicit.** `prepare_swap_offer` refuses a confidential UTXO
  (`WalletError::Confidential`, "split it … first"); `take_swap_offers` never
  selects confidential UTXOs and explains an underfunded take; the analyzer
  rejects any confidential data in swap PSETs. `prepare_offer_split` always
  produces an explicit offerable output, so confidential funds can still be
  listed on the DEX.

## What this does not do

- It does not scan ECX headers, discover UTXOs, prove explorer responses,
  track spends, or broadcast.
- `VerifiedUtxo` means *the caller* verified chain inclusion and spend status.
  The core checks ownership and transaction invariants, not chain state.
- It does not support blinded issuance, reissuance, peg-ins, arbitrary
  scripts, confidential swaps, or partial fills of an offer.
- Confidential outputs require a network whose validators accept them (the
  Elements+ node enabled confidential payments on 2026-09-16; the old desktop
  release enforced explicit outputs). Confidential receive therefore stays a
  per-profile opt-in, and explicit transactions remain the default.

## Verify

```sh
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
```

`tests/headless.rs` uses only public BIP39 test vectors and synthetic funding
transactions. It covers every operation end-to-end (prepare → review → sign →
decode) plus adversarial cases: wrong sighash, tampered offers, prevout txid
mismatch, review and approval mismatch, overflow, foreign outputs disguised as
change, foreign inputs, tampered maker witnesses, and issuance contract
mismatch. It does not broadcast.

`verify_raw_transaction` is the scanner's fail-closed local decoding boundary.
Given an expected txid, raw consensus transaction hex, and expected wallet
vout/scripts, it recomputes the txid and returns only matching, fully explicit
P2WPKH outputs with exact atomic `u64` values (the `WalletCore` method also
returns confidential outputs that unblind with the wallet's key). It
deliberately does not prove confirmation, inclusion, or unspent status.

`tests/confidential.rs` covers SLIP-77 derivation, unblinding own outputs and
refusing foreign-blinded or corrupted ones, confidential → explicit and
confidential → confidential transfers, explicit inputs → confidential
recipient, mixed inputs with blinded asset and policy change, the forced
blinded change, exact review deltas, tampered blinders/values/PSET proofs,
re-blinding changing the review hash, swap refusal plus split-then-offer, and
confidentially funded issuance and cancel.

`tests/funded_elements.rs` holds ignored, opt-in tests against a real
Elements+ regtest node started like `scripts/regtest-stack.mjs` (descriptor
wallet `miner` with mined coins). With freshly generated mnemonics they fund
wallets, then issue an asset, transfer it, split an exact output, make a
maker offer, take it with a second wallet, cancel a second offer and prove the
stale offer is rejected by `testmempoolaccept`; and have the node wallet pay a
confidential wallet address (blinded by default), unblind it, spend it back to
a confidential node address, offer-split the blinded change into an explicit
output, and spend the rest to an unconfidential address, with the node
confirming the exact received amounts — every transaction is broadcast and
mined:

```sh
ELEMENTS_CLI=/path/to/elements-functional-test-cli \
ELEMENTS_DATADIR=/path/to/disposable/regtest \
ELEMENTS_RPCPORT=19901 \
cargo test --locked --test funded_elements -- --ignored --test-threads=1
```

This spends disposable regtest coins and therefore refuses to run unless
`ELEMENTS_DATADIR` is explicitly set (`ELEMENTS_CHAIN` defaults to
`elementsregtest`, `ELEMENTS_RPCWALLET` to `miner`).

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
