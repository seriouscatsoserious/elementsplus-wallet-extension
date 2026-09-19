# Elements+ Wallet

An experimental browser-extension wallet for the ECX Alpha Elements+ drivechain
fork. It is **not** a Liquid wallet and never falls back to Liquid, Elements
regtest, or another chain.

The extension packages a pinned Rust/LWK-derived WASM core. It generates and
validates BIP39 mnemonics locally, derives explicit P2WPKH addresses, discovers
HD-wallet activity through the pinned explorer, locally consensus-decodes every
funding transaction, builds an exact PSET, binds it to a one-time human approval,
signs locally, and submits the raw transaction to the explorer's broadcast API.
The explorer remains trusted for chain inclusion, spend status, and tip data;
the wallet does not validate the header chain.

## Scope

- Create/restore onboarding surfaces
- Locked and unlocked wallet states
- Dashboard, assets, native-ECX send, and receive flows
- Explicit/non-confidential transaction policy
- Issuance, reissuance, burn, confidential transactions, DEX, swaps, and
  counterparties remain disabled
- No fabricated demo data

## Development

```sh
rustup toolchain install 1.89.0 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.108 --locked
npm ci
npm run check
```

The build compiles `rust/wallet-core` with its lockfile, generates local
`wasm-bindgen` glue, removes the legacy dynamic-Function compatibility fallback,
and packages the same WASM bytes into both browser artifacts. No code is loaded
from a CDN or at runtime.

Load `dist/chromium` as an unpacked Chromium extension or
`dist/firefox` as a temporary Firefox add-on.

For the complete copy-pasteable local browser handoff, see
[docs/LOCAL-TESTING.md](docs/LOCAL-TESTING.md).

The default tests are fully mocked and do not require network access. To opt
into a read-only smoke test against the configured ECX Alpha explorer, run:

```sh
ECX_ALPHA_LIVE_TEST=1 npm run test:live
```

The smoke test fails unless the explorer serves the pinned genesis and policy
asset, then reads its tip, mempool, fee estimates, and one alias-address query.
It never uses node RPC, broadcasts transactions, signs, or invokes DEX APIs.
