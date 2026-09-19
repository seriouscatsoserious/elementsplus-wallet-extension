# Security posture

This is alpha software for valueless test assets only.

- The ECX Alpha identity pins are compiled into the extension. Explorer data is
  displayed only when its height-zero hash and policy asset match those pins.
  This detects accidental misconfiguration; it does not authenticate a
  compromised explorer or replace header-chain validation by the wallet.
- The only signer is the packaged, revision-pinned Rust/WASM wallet core. There
  is no JavaScript fallback signer, runtime download, or CDN dependency.
- Explorer UTXOs are accepted only after the local core consensus-decodes the
  raw funding transaction, recomputes its txid, matches the derived P2WPKH
  script, and confirms explicit asset/value/nonce fields. This still does not
  prove chain inclusion or unspent status; the explorer remains trusted for
  those facts.
- Every transfer approval commits to the exact serialized PSET, the Rust core's
  domain-separated review hash, and the normalized display summary. Approval
  tokens are random, expire, and are consumed before signing is attempted.
- Vault material is encrypted with a random data-encryption key wrapped by a
  PBKDF2-SHA-256 derived key and AES-256-GCM.
- Decrypted wallet material is kept only in the background worker's memory. A
  lock clears pending preparations and calls the WASM core's destructor; worker
  termination discards the entire instance. JavaScript strings cannot be
  reliably zeroized, so this is not equivalent to hardware-backed key storage.
- Extension pages use a restrictive content security policy. The sole relaxed
  directive is `'wasm-unsafe-eval'`, required by Chromium and Firefox to compile
  packaged WebAssembly. No remote scripts, dynamic `Function`, inline scripts,
  telemetry, or page-injected provider are included.
- This phase sends only the native ECX policy asset using explicit outputs.
  Issuance, reissuance, burns, confidential transactions, and arbitrary assets
  remain disabled until separately implemented and reviewed.
- The bundled public explorer is suitable for testnet prototyping, not private
  wallet synchronization: address queries disclose the wallet's scripts to
  that service. A production build should support a trusted/self-hosted,
  identity-pinned backend before wallet sync is enabled.

Do not import a seed that controls anything valuable. This code has not been
independently audited.
