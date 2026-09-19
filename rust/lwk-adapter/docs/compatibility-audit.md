# Compatibility audit — 2026-09-19

## Published binary and current source

The last published binary is the **explicit-only desktop-r2** release:

- tag: `elements-alpha-cad1fc1fb-desktop-r2`;
- peeled commit: `b2b928fd65e02901d8a98ee38adfe35dfb0f379f`;
- explicit-only activation: height 84;
- LWK witness aliases added by the release: `ert` and `el`;
- native witness HRPs: `elements` and `elementsl`.

Current repository `master`, commit
`4041a8ba5d9c0870dbe22c188bce28410c10348a`, re-enabled confidential payments.
Because it kept the same genesis and network identity, genesis and policy-asset
checks cannot reveal which validator revision a peer runs. Mixing those
validation versions is a deployment hazard. This adapter therefore fails
closed on every confidential output as wallet policy; explicit transactions
remain compatible with both versions.

## Live explorer observations

`https://explorer.bitnames.info/api` returned the following on 2026-09-19:

| Height | Header size | Version | Block hash |
| ---: | ---: | ---: | --- |
| 0 | 79 bytes | `0x00000001` | `672af009bd90...96fa5bcd` |
| 84 | 79 bytes | `0x20000000` | `f70e9da264de...f59d3e8d` |
| 85 | 203 bytes | `0x200f0000` | `20d149b745f6...74ac66aa` |
| 223 | 203 bytes | `0x200f0000` | `c34d7de42dc2...b9a4a99d98` |

The 124-byte increase at height 85 is exactly:

- three 32-byte roots;
- one 4-byte parent height;
- three 8-byte cursors.

Stock rust-elements 0.25.3 consumes the ordinary header fields but has no place
for these bytes and cannot reproduce the correct block hash. This is the main
integration blocker.

## Stock LWK: reusable pieces and missing browser surfaces

At revision `55671e82c0cc713ece341f74704ff39255c633ec`, LWK already:

- models explicit outputs as zero blinding factors during wallet discovery;
- provides a Rust-side `explicit_utxos()` escape hatch;
- provides `addExplicitRecipient`;
- exposes PSET output asset, amount, fee status and `isFullyExplicit`;
- includes explicit-send binding coverage.

However, its normal balance and UTXO APIs intentionally omit explicit UTXOs,
`explicit_utxos()` is not exposed in `lwk_wasm`, and PSET detail inspection can
reject an explicit input as "not blinded." The pinned upstream e2e test for an
unblinded UTXO records exactly that behavior. Consequently, a browser wallet
also needs explicit-UTXO enumeration/balance and explicit-input transaction
review exposed through WASM. Network/header plumbing and policy gates alone
are not sufficient.

## Security boundary

The application must check the height-zero block hash against the frozen
genesis before accepting an endpoint. That check detects a wrong-chain endpoint
but does not authenticate a compromised explorer that can echo the expected
value. Wallet data requires continuity validation with the ECX-aware header
parser (and the intended parent-chain/BMM trust model), not merely an explorer
hostname, address HRP, policy asset, or reported chain name. Seeds are for node
discovery, not wallet identity.

No secret material belongs in this adapter. Seed encryption, unlock lifetime,
extension-origin isolation and signing approval remain responsibilities of the
browser extension's vault and UI.
