# Local browser testing

This repository builds the ECX Alpha Elements+ wallet extension for Chromium
and Firefox. The current milestone supports the complete extension shell,
navigation, encrypted-vault internals, and read-only ECX Alpha identity/status
checks. The LWK wallet adapter is not connected yet, so mnemonic generation,
address derivation, balances, signing, broadcasting, issuance, reissuance, and
burning remain deliberately disabled.

Never import a recovery phrase that controls anything valuable.

## Requirements

- Git and GitHub CLI (`gh`), authenticated to GitHub
- Node.js 24 or newer
- Chrome, Brave, or Edge for the first test

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

The bootstrap installs locked development dependencies, runs the TypeScript
check and all unit tests, validates the extension artifact policy, and builds
both browser targets. It does not install the extension or handle wallet keys.

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
- the balance remains blank and wallet actions remain disabled;
- the notice reports that the wallet engine is not installed.

Those disabled states are expected and are not a browser-installation failure.

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

## Update after another push

```sh
git pull --ff-only
./scripts/bootstrap-local.sh
```

Then return to the browser's extensions page and click **Reload** on the
unpacked extension card.
