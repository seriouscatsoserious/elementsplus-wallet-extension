# Elements+ wallet project handoff — 2026-10-01

## What we are building

A self-custodial browser-extension wallet for JK's **Elements+ drivechain fork**,
with an opt-in fast preconfirmation path. The eventual product goal is a familiar
wallet for sending tokens and connecting to a token-launch/trading site. The
current implementation is a narrow prototype, not that completed product.

This project began as a BitAssets wallet, then pivoted to Elements+. It is not
stock Liquid, Bitcoin Cash/eCash XEC, a Solana wallet, or the separate bECX bridge
hot-wallet automation on the server. Never import those funded wallets or their
backup files into this extension to test it.

## Repositories and branches

- Wallet and signer: <https://github.com/seriouscatsoserious/elementsplus-wallet-extension>
- This handoff and previously unpushed funded-regtest work:
  `handoff/funded-regtest-20261001`.
- Wallet/signer foundation: [wallet PR #1](https://github.com/seriouscatsoserious/elementsplus-wallet-extension/pull/1), already merged.
- Separate UI work: [wallet PR #2](https://github.com/seriouscatsoserious/elementsplus-wallet-extension/pull/2),
  `feat/modern-wallet-ui`, open at this check. It removes the Windows 98 theme.
  This handoff preserves that branch and does **not** merge or overwrite it.
- Node: <https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation>.
  [PR #5](https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation/pull/5)
  added the original user-bond experiment;
  [PR #6](https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation/pull/6)
  added the distinct **operator-funded bond and realtime relay**. Both are merged.

### Latest Elements+ source check

Fetched upstream and fast-forwarded the local node-source checkout on October 1.
Published `master` was `006d2a30b1df340f5d77ca9af21e1c3df18b551b` (September 20).
Its last code change, JK's `24e38861010513c57953e9bac1f0aa4c3254fa2d`, shares
Taproot/execution/witness helpers between the two bond protocols and adds
execution-environment tests. It does not change contract source, signature
domains, or public APIs. All 29 upstream files in the wallet's vendored crate
were compared byte-for-byte and already match this revision.

The funded harness pins the same commit. New clones now explicitly check out
that pin rather than assuming whatever upstream HEAD happens to be. Existing
node-source edits are not overwritten. No live node binary, datadir, network
configuration, or consensus rules were changed for this handoff.

If JK supplies a newer branch/repository, compare that explicit revision before
updating the pin. Published source is not proof of the revision running on the
public network. Do not change genesis/asset pins just because ECX's parent
network or dashboard was renamed.

## What exists today

| Component | Location and responsibility |
| --- | --- |
| Browser UI | `src/ui/`: setup, lock/unlock, balances, assets, receive, send review and status. Chromium and Firefox artifacts. |
| Vault/controller | `src/vault.ts`, `src/background/`: encrypted local vault, unlock lifetime, exact one-time approval and signing boundary. |
| Signing core | `rust/wallet-core/`, `rust/lwk-adapter/`: pinned LWK-derived Rust/WASM, mnemonic/address handling, explicit native-asset PSET construction and local signing. |
| Explorer adapter | `src/network/`, `src/adapters/`: pinned genesis/native asset, HD discovery, local validation of raw funding transaction bytes. Explorer still supplies chain/spend/tip status. |
| Wallet preconf client | `src/preconf/`: authenticated signer WebSocket, local BIP340 receipt verification, subscriptions to multiple receipt relays. |
| Operator service | `services/preconfer-signer/`: checks the trusted node and bond, durably journals one signed decision, publishes receipts and broadcasts the user-signed transaction. No user wallet key custody. |
| Bond/relay primitives | `vendor/elementsplus-preconf/`: exact upstream Simplicity covenant, receipt verification, durable realtime relays, monitor reference client. |
| Funded local harness | `scripts/regtest-*.mjs`, `docs/REGTEST-WALLET.md`: separate functional-test node, explorer adapter, signer, two relays and distinctly labeled regtest wallet build. |

The ordinary wallet supports **explicit native-asset sends**, not general token
trading yet. Asset issuance/reissuance/burn, non-native sends, confidential
transfers, a DEX, browser dApp provider, and automatic rolling preconf sessions
are not implemented/enabled. Seeing an Assets or Issue screen is not proof the
corresponding transaction feature exists.

## Preconfirmation flow and trust

1. The browser constructs, reviews, and signs the user's transaction locally.
2. The operator checks the actual protected input, funded bond, chain and node
   mempool acceptance, then fsyncs its signed promise before publishing it.
3. Configured relays verify and persist the receipt; the signer broadcasts the
   transaction to its Elements+ node.
4. The wallet checks the signature and requires its receipt in every configured
   relay's synchronized stream before displaying **Preconfirmed**.
5. An actual sidechain block is still needed for **Confirmed**.

The signer and relays use persistent WebSockets, not periodic one-off HTTP
queries. The browser monitor continues while its client is alive and marks
observed conflicts in memory; browser lock/suspension/restart is not a reliable
always-on watcher. There is no automatic slashing broadcaster yet.

Collateral belongs to the **operator**, separate from the user's principal.
Two conflicting valid promises for the same bond/session can spend that bond
entirely as miner fees. This is a punishment, **not compensation to the victim**,
not guaranteed inclusion, and not proof that hidden conflicting promises cannot
exist. Two relay URLs on one host do not provide independent security.

Each profile protects exactly one UTXO and one transaction ID. Another send
needs a new funded bond/session/profile. Different RBF txids in the same signing
domain count as equivocation: do not improvise retries or fee replacement.
The absolute refund deadline remains; the proposed two-stage exit and safe
repeated off-chain transfers are not implemented.

The wallet verifies transaction bytes and receipt signatures, but does not
independently validate the header/BMM chain or fully authenticate the live bond
state. Those are important remaining trust boundaries, not just UI work.

## Continue on another machine

Install Git, Node 24+, Rust 1.89.0 with `wasm32-unknown-unknown`,
`wasm-bindgen-cli` 0.2.108 and a C/C++ toolchain. Then:

```sh
git clone --branch handoff/funded-regtest-20261001 https://github.com/seriouscatsoserious/elementsplus-wallet-extension.git
cd elementsplus-wallet-extension
./scripts/bootstrap-local.sh
```

The repository is public; cloning does not require GitHub credentials.
Load `dist/chromium` via your browser's **Load unpacked** button. Use only a new
disposable phrase. Read [LOCAL-TESTING.md](LOCAL-TESTING.md) for platform details
and [REGTEST-WALLET.md](REGTEST-WALLET.md) for actual funded preconfirmation tests.
The normal artifact and `LOCAL REGTEST` artifact are deliberately separate.

The existing Hetzner server is reached with `ssh helsinki`. That alias currently
logs in as root; development should run as `codexhost`, not root. The old wallet
worktree is:

```text
/home/codexhost/Documents/Codex/2026-08-23-okay-so-on-this-hedsnr-box/elementsplus-preconf-wallet
```

`~/Documents/...` is wrong under the root SSH login. On October 1, all five
old regtest services were stopped and some old disposable state belonged to
root. Do not fix that by copying keys into Git or restarting everything as root.
Use the clean, unprivileged checkout instructions in REGTEST-WALLET.md. Leave
the full ECX node, livestream, and bECX/Solana bridge services alone.

Do not transfer `.regtest/`, `.local/`, browser profiles, RPC cookies, signer
secrets, backup archives, or funded server-wallet state. Create fresh test state
on the new machine. Build artifacts and screenshots are excluded from Git.
`capture-wallet-screens.mjs` decorates a static preview with illustrative values;
its images are not evidence of live balances or successful transactions.

## Next work, in priority order

1. **Automatic watchtower/slashing broadcaster.** Persist authenticated receipts
   and conflict evidence, independently validate the bond and chain, build the
   existing covenant's penalty witness, and broadcast idempotently. Resume after
   crashes, track confirmation/reorgs and the refund deadline, and surface
   failures. Never make the service a custodian of user keys.
2. **Adversarial funded end-to-end tests.** Prove real node acceptance and mined
   settlement of a conflicting-receipt penalty, plus restart, duplicate delivery,
   partition, expired/refunded bond and reorg behavior. A happy-path send alone
   does not test enforcement or economic safety.
3. **Wallet monitoring/recovery.** Persist verified evidence and accepted state,
   show later conflict/disconnection status, independently validate bond state,
   and define safe fee-bumping, retry and refund policies.
4. **Product scope.** Safely automate session/bond lifecycle; then add reviewed
   non-native token sends/issuance and the wallet-provider/DEX integration.
   Keep `Preconfirmed` distinct from settlement and specify receiver exposure
   limits; do not advertise Solana-like finality.
5. Confirm the actual public deployment/activation with JK, test with valueless
   public-network coins, and obtain independent security review before valuable
   funds. No claim that a MetaMask-style audit is complete is made here.

## Verification

The handoff work is checked with `npm run check`, native Rust wallet/adapter
tests, upstream bond/relay tests, and the real relay-process integration tests.
For precise results of the current checkout, rerun those commands; screenshots
are not test results. A public explorer smoke test is read-only and separate
from funded regtest and mainnet readiness.

On October 1, `npm run check` passed (53 wallet unit tests, two build-path safety
tests, three signer tests, nine monitor tests, both browser builds and artifact
policy). Native Rust wallet/adapter tests, the upstream covenant/relay suite and
the real-process relay integration test also passed. No fresh funded browser
transaction or slashing transaction was performed during this handoff.

The live explorer test was attempted but **failed with HTTP 502** from
`https://explorer.bitnames.info/api`. Public network identity/sync could not be
verified at that time. A clone/build does not fix that endpoint; use regtest for
isolated tests, or have JK confirm the current public explorer and deployment.
Do not bypass the wallet's identity checks to suppress the error.

See also [SECURITY.md](../SECURITY.md), [PRECONFIRMATIONS.md](PRECONFIRMATIONS.md)
and the vendored [operator/relay specification](../vendor/elementsplus-preconf/OPERATOR-RELAY.md).
