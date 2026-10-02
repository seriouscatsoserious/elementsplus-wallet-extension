# Elements+ Wallet

An experimental browser-extension wallet for the Elements+ sidechain on eCash
(ECX). It is **not** a Liquid wallet and never falls back to Liquid, Elements
regtest, or another chain.

Each artifact is built for exactly one **network profile** from the typed
registry in [`src/network/profiles.ts`](src/network/profiles.ts) (mirrored in
`rust/wallet-core/src/network.rs`); the profile's pins are compiled in and are
never user-editable. See [`docs/NETWORKS.md`](docs/NETWORKS.md).

| Profile | Display name | Status |
|---|---|---|
| `ecx-beta` | eCash Beta · Elements | pending: v11 identity pinned (betanet slot 24), no public sidechain Esplora yet |
| `ecx-mainnet` | eCash · Elements | pending: nothing published (mainnet planned ~2026-10-31) |
| `elementsplus-regtest` | Elements+ local regtest | live (disposable local chain) |
| `ecx-alpha` | ECX Alpha (archived) | archived: retired chain, kept for historical tests only |

Start with [the project handoff](docs/HANDOFF.md) for architecture, upstream
status, remaining security work, and moving development to another machine.

Wallet v2 follows [`docs/V2-SPEC.md`](docs/V2-SPEC.md): every transaction
(transfer, issuance, swap offer/take, cancel) goes through one wallet-computed
review, a one-time approval bound to its review hash, local signing and explorer
broadcast. Preconfirmations were removed from the wallet; the parked sources in
`services/` and `vendor/elementsplus-preconf` are no longer built or tested here.

The extension packages a pinned Rust/LWK-derived WASM core. It generates and
validates BIP39 mnemonics locally, derives explicit P2WPKH addresses, discovers
HD-wallet activity through the pinned explorer, locally consensus-decodes every
funding transaction, builds an exact PSET, binds it to a one-time human approval,
signs locally, and submits the raw transaction to the explorer's broadcast API.
The explorer remains trusted for chain inclusion, spend status, and tip data;
the wallet does not validate the header chain.

## Scope

- Onboarding (create → show phrase → confirm 3 words → password; import/restore)
- Lock gate with configurable auto-lock
- Home (balances per asset, verified token metadata, UNVERIFIED tags), Activity
  (explorer history, display-only), Send → Confirm, Receive with QR, Settings
- dApp provider `window.elementsplus` (spec §3.3) with per-origin connections
  and an approval window for transfers, issuance and swaps
- Explicit/non-confidential transaction policy only
- `src/ui/preview.html` renders every screen with illustrative sample data
  (`npm run capture` writes screenshots); the extension itself shows no demo data

## Development

```sh
rustup toolchain install 1.89.0 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.108 --locked
npm ci --ignore-scripts
npm run check
```

`npm run build` builds and checks one artifact per buildable profile. While
`ecx-beta` and `ecx-mainnet` are pending it builds only the regtest artifact
(`.regtest/dist/chromium`; against `.regtest/network.json` when a local chain
exists, else the synthetic CI fixture) and prints which profiles are pending.
A single public profile is built with

```sh
ELEMENTSPLUS_NETWORK_PROFILE=ecx-beta npm run build:profile   # or: node scripts/build.mjs --profile ecx-beta
```

which refuses (exit 3, naming the missing pins) while the profile is pending.
The build compiles `rust/wallet-core` with its lockfile and
`ELEMENTSPLUS_NETWORK_PROFILE`, generates local `wasm-bindgen` glue, removes the
legacy dynamic-Function compatibility fallback, and packages the same WASM
bytes into both browser artifacts. No code is loaded from a CDN or at runtime.

Load `dist/chromium` as an unpacked Chromium extension or
`dist/firefox` as a temporary Firefox add-on.

For the disposable, funded, full-node preconfirmation harness, see
[`docs/REGTEST-WALLET.md`](docs/REGTEST-WALLET.md). It builds the separate
`elementsplus-regtest` artifact and does not relax a public artifact's chain
pins.

For the complete copy-pasteable local browser handoff, see
[docs/LOCAL-TESTING.md](docs/LOCAL-TESTING.md).

The unit tests do not require a live node; initial dependency installation and
builds may need network access. To opt
into a read-only smoke test against a live profile's explorer
(`ECX_LIVE_PROFILE`, default `ecx-beta`; refused while it is pending), run:

```sh
ECX_LIVE_TEST=1 npm run test:live
```

The smoke test fails unless the explorer serves the pinned genesis and policy
asset, then reads its tip, mempool, fee estimates, and one alias-address query.
It never uses node RPC, broadcasts transactions, signs, or invokes DEX APIs.
