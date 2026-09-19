# Security posture

This is alpha software for valueless test assets only.

- The ECX Alpha identity pins are compiled into the extension. Explorer data is
  displayed only when its height-zero hash and policy asset match those pins.
  This detects accidental misconfiguration; it does not authenticate a
  compromised explorer or replace header-chain validation by the wallet.
- LWK is unavailable by default. Missing cryptography disables wallet actions;
  it never triggers a JavaScript fallback signer.
- Enabling a future LWK adapter requires reviewed proof of ECX header
  continuity, explicit-UTXO discovery, descriptor ownership of every displayed
  receive address, and exact PSET-to-approval binding. A boolean adapter claim
  is not a substitute for those integration tests.
- Vault material is encrypted with a random data-encryption key wrapped by a
  PBKDF2-SHA-256 derived key and AES-256-GCM.
- Decrypted wallet material is kept only in the background worker's memory and
  is discarded on lock or worker termination.
- Extension pages use a restrictive content security policy. No remote scripts,
  inline scripts, telemetry, or page-injected provider are included.
- This phase supports explicit/non-confidential outputs only. Confidential
  transaction construction must remain disabled until separately reviewed.
- The bundled public explorer is suitable for testnet prototyping, not private
  wallet synchronization: address queries disclose the wallet's scripts to
  that service. A production build should support a trusted/self-hosted,
  identity-pinned backend before wallet sync is enabled.

Do not import a seed that controls anything valuable. This code has not been
independently audited.
