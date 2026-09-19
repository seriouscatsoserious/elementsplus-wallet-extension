# Elements+ Wallet

An experimental browser-extension wallet scaffold for the ECX Alpha Elements+
drivechain fork. It is **not** a Liquid wallet and must never silently fall back
to Liquid, Elements regtest, or another chain.

This phase supplies the extension shell, encrypted-vault primitive, pinned
network identity, read-only endpoint status with identity-pin matching, UI states, and an explicit
adapter boundary for LWK. It does not yet derive keys, show wallet balances,
build transactions, or sign anything. Those features remain fail-closed until
a reviewed LWK adapter is installed.

## Scope

- Create/restore onboarding surfaces
- Locked and unlocked wallet states
- Dashboard, assets, send, receive, issue, reissue, and burn screens
- Explicit/non-confidential transaction policy
- No DEX, LiquiDEX, swaps, counterparties, or fabricated demo data

## Development

```sh
npm install
npm run check
```

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
