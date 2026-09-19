# Local browser testing

This repository builds the ECX Alpha Elements+ wallet extension for Chromium
and Firefox. It packages its Rust/WASM signing core locally and supports wallet
creation/restoration, explicit address derivation, explorer-backed balance
discovery, native-ECX transfer review, local signing, and explorer broadcast.
Issuance, reissuance, burning, confidential outputs, and non-native sends remain
deliberately disabled.

Never import a recovery phrase that controls anything valuable.

## Requirements

- Git and GitHub CLI (`gh`), authenticated to GitHub
- Node.js 24 or newer
- Rust/Cargo with `rustup` (the repository pins Rust 1.89.0)
- a platform C/C++ build toolchain (`clang` is used on the tested Linux host)
- the `wasm32-unknown-unknown` Rust target
- `wasm-bindgen-cli` exactly 0.2.108
- Chrome, Brave, or Edge for the first test

Install the pinned WASM build prerequisites once:

```sh
rustup toolchain install 1.89.0 --profile minimal --target wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.108 --locked
```

## Clone, test, and build

### macOS, Linux, or Git Bash

```sh
gh auth login
gh repo clone seriouscatsoserious/elementsplus-wallet-extension
cd elementsplus-wallet-extension
./scripts/bootstrap-local.sh
```

### Windows PowerShell

```powershell
gh auth login
gh repo clone seriouscatsoserious/elementsplus-wallet-extension
Set-Location elementsplus-wallet-extension
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap-local.ps1
```

The bootstrap installs locked Node development dependencies, runs the
TypeScript check and all unit tests, compiles the locked Rust core, validates
the extension artifact policy, and builds both browser targets. It does not
install the extension or handle wallet keys.

## Load it in a Chromium browser

1. Open `chrome://extensions`. Use `brave://extensions` in Brave or
   `edge://extensions` in Edge.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the repository's `dist/chromium` directory.
5. Pin **Elements+ Wallet — ECX Alpha**, then click its toolbar icon.

Expected behavior:

- the Windows 98-styled 400-by-620 wallet opens directly;
- the network control changes from **Checking network** to **PINS MATCH** when
  `explorer.bitnames.info` serves the pinned genesis and native asset;
- wallet setup can generate a new local recovery phrase;
- after creating and unlocking a disposable test wallet, synchronization shows
  an `elements1...` receive address and explorer-backed balances;
- send and receive are enabled, while issue/reissue/burn remain disabled.

Use only a new disposable phrase and valueless test coins. A zero balance is
expected until that derived sidechain address is funded.

## Preview every screen

After the build, run:

```sh
npm run preview
```

Open these local-only preview URLs:

```text
http://127.0.0.1:43198/#dashboard
http://127.0.0.1:43198/#assets
http://127.0.0.1:43198/#send
http://127.0.0.1:43198/#receive
http://127.0.0.1:43198/#issue
http://127.0.0.1:43198/#manage
http://127.0.0.1:43198/#setup
http://127.0.0.1:43198/#network
```

Preview mode never calls WebExtension APIs, creates keys, or displays fake
balances. Stop the preview server with `Ctrl-C`.

## Optional live explorer smoke test

```sh
ECX_ALPHA_LIVE_TEST=1 npm run test:live
```

PowerShell:

```powershell
$env:ECX_ALPHA_LIVE_TEST = "1"
npm run test:live
```

This performs read-only requests and fails closed unless the explorer matches
the pinned ECX Alpha genesis and policy asset. It never signs or broadcasts.

## Automated installed-extension smoke test

After `npm run build`, follow
[HEADLESS-EXTENSION-SMOKE.md](HEADLESS-EXTENSION-SMOKE.md) to exercise the real
Manifest V3 worker, packaged WASM core, encrypted vault, lock/unlock, live
wallet scan, and fail-closed unfunded send in a disposable browser profile.

## Final live-coin proof

The remaining public-network test needs a small amount of valueless native
sidechain ECX:

1. Create a new disposable wallet in the extension and copy its `elements1...`
   receive address. Never share its recovery phrase.
2. Ask the Elements+ operator for a small explicit native-ECX UTXO at that
   address, or for the supported public deposit/faucet procedure, and ensure a
   miner is online to confirm it.
3. Refresh the wallet, prepare a small send to a second disposable Elements+
   address, verify every review field, then approve and broadcast once.
4. Confirm the returned transaction ID in the explorer before retrying.

Before enabling confidential transactions, also obtain the exact commit/tag of
the validator currently deployed behind the public network. Explicit native
sends do not depend on that unresolved deployment distinction.

## Update after another push

```sh
git pull --ff-only
./scripts/bootstrap-local.sh
```

Then return to the browser's extensions page and click **Reload** on the
unpacked extension card.
