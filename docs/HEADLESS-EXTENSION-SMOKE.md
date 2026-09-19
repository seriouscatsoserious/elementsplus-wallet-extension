# Headless Chromium extension smoke test

This test launches the actual unpacked Manifest V3 Chromium artifact in a fresh, disposable Chrome profile. It talks to Chrome through the DevTools Protocol using Node's built-in WebSocket client; it does not add Puppeteer or another browser-test dependency.

The test verifies the real WASM adapter and capability mask, creates a fresh mnemonic without returning or printing it, creates an encrypted disposable vault, locks and unlocks it, completes a read-only live explorer synchronization, validates the canonical `elements1` receive address and explicit explorer-backed trust metadata, and confirms an unfunded send fails before an approval token is issued.

Run it after building the extension:

```sh
npm run build
npm run test:extension
```

Requirements:

- Node 24 or newer
- Chromium or Chrome for Testing with Manifest V3 extension support
- network access to the pinned Elements+ explorer
- a built `dist/chromium` artifact

The default browser path is `/usr/bin/google-chrome`, but official Chrome-branded builds 137 and newer intentionally ignore `--load-extension`. On those releases, point `CHROME_BIN` at Chromium or [Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/). The extension artifact defaults to `dist/chromium`.

```sh
CHROME_BIN=/path/to/chromium EXTENSION_DIST=/path/to/dist/chromium node scripts/headless-extension-smoke.mjs
```

On an isolated Linux CI host that disables Chromium's user-namespace sandbox,
the test can explicitly opt into Chromium's unsafe test-only workaround:

```sh
CHROME_NO_SANDBOX=1 CHROME_BIN=/path/to/chrome-for-testing npm run test:extension
```

Do not use `CHROME_NO_SANDBOX=1` for ordinary browsing or a persistent profile.

No recovery phrase or vault password is emitted. The test generates both only within the temporary extension context, closes Chrome, and removes only the exact profile directory it created under the operating-system temporary directory.
