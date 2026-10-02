# epw — headless Elements+ wallet (CLI + MCP)

`epw` is a headless, agent-friendly wallet for the Elements+ eCash sidechain (explicit
outputs only), spec `docs/V2-SPEC.md` §6.2. It uses the same signing core as
the browser extension (`rust/wallet-core`): every transaction is built by the
core, its review is recomputed from the PSET, and signing is bound to the
review hash.

```
cargo build --release          # binary: target/release/epw  (Rust 1.89)
```

## Setup

```sh
export EPW_HOME=~/.config/epw         # default; holds keystore, config, policy, audit log
epw init                              # new 12-word mnemonic, shown ONCE
epw import < mnemonic.txt             # or interactively (hidden prompt)
```

The password comes from `EPW_PASSWORD` or a terminal prompt. The keystore
(`keystore.json`, mode 0600) is the mnemonic encrypted with
XChaCha20-Poly1305 under an Argon2id key (64 MiB, t=3, p=1, random salt and
nonce, KDF parameters bound as associated data). epw never prints the
mnemonic except on `init`; no MCP tool can read it.

### Config (`config.toml`)

```sh
epw config get
epw config set network elementsplus-regtest    # or ecx-beta (default) / ecx-mainnet
epw config set esplora_url http://127.0.0.1:43199/api   # default: the profile's
epw config set dex_url http://127.0.0.1:8790            # default: the profile's
epw config set registry_url https://…/api/assets   # default <dex_url>/api/assets
epw config set fee_rate 1                       # sat/vB; gap_limit (20) too
epw config discover   # regtest: genesis from Esplora, policy asset from DEX /api/health
```

`network` is a profile id from the shared registry (`docs/NETWORKS.md`):
`ecx-beta` (eCash Beta · Elements, slot 24), `ecx-mainnet` (eCash · Elements)
and `elementsplus-regtest` (`regtest` is accepted as a legacy spelling). Public
profiles pin genesis hash and policy asset in the wallet core and cannot be
overridden. **`ecx-beta` and `ecx-mainnet` are pending** until their sidechain
genesis hash, pegged asset and Esplora URL are published: every command that
needs the chain refuses with an explanatory error instead of guessing. The
retired `ecx-alpha` chain is archived and refused.

Regtest needs `genesis_hash` and `policy_asset`; they are auto-discovered on
first use if missing (the DEX genesis must match the explorer's).

## Trust model

- **Explorer**: gap-limit-20 discovery on the external and change branches
  (as the extension's scanner does), address stats cross-checked against the
  UTXO list, explorer genesis pinned to the configured one, and every funding
  transaction fetched raw and verified with `verify_raw_transaction` before a
  UTXO is spendable. Non-explicit outputs are skipped. History is explorer
  data shown for display only.
- **DEX**: untrusted. Quotes are recomputed: each offer is decoded with
  `decode_offer` against its prevout fetched from Esplora (txid-checked),
  must be for the requested pair, totals must equal the server's claim and
  must not overshoot, and the offer output must be unspent. `swap` refuses if
  the price impact against the best offer exceeds `--max-slippage-bps`
  (default 100).
- **Registry**: entries are only used after `verify_asset_issuance` succeeds
  on the raw issuance tx; verified metadata is cached in
  `state-<genesis>.json`. Tickers resolve only if verified and unique (the
  policy asset is `ECX`); otherwise use the 64-hex id. Unknown assets have
  precision 0.

## Commands

All commands accept `--json`. Amounts are decimals in the asset's precision
(`1.5`) or `atomic:<n>`; assets are a verified unique ticker or a 64-hex id.

| command | |
|---|---|
| `epw address` | next unused receive address |
| `epw balances` | per-asset confirmed / unconfirmed / in open offers |
| `epw history [--limit N]` | per-tx balance changes |
| `epw send <asset> <amount> <address>` | transfer |
| `epw issue --name --ticker --precision --amount [--token-amount N] [--register]` | explicit issuance (+ registry POST) |
| `epw quote <sell> <buy> <amount> [--exact-out]` | verified quote |
| `epw swap <sell> <buy> <amount> [--exact-out] [--max-slippage-bps N]` | quote → take |
| `epw offer make <give> <amt> <want> <amt> [--post]` | split (if no exact UTXO) + maker offer, one approval |
| `epw offer list` / `epw offer cancel <txid:vout>` / `epw offer post <txid:vout>` | maker offers |
| `epw markets`, `epw book <base> <quote>` | DEX data |
| `epw review <file>` / `epw sign <file> --approve <hash>` | two-step flows |
| `epw policy show` | effective policy and rolling 24 h spend |
| `epw mcp` | MCP server on stdio |

Mutating commands also take `--fee-rate N` and `--prepare-only` (write the
bundle to `pending/` and print its review and approval hash without signing).

Exit codes: `0` ok, `1` error, `3` approval required (bundle parked),
`4` refused by policy, `5` signed/broadcast but the DEX/registry POST failed
(retry with `epw offer post`).

## Signing policy (`policy.toml`)

Every signature — CLI, `epw sign`, MCP — goes through one gate
(`src/gate.rs::authorize_and_sign` → `src/policy.rs::evaluate`):

1. each PSET's review is recomputed by the core and must equal the stored
   review/hash;
2. the policy is evaluated on those reviews;
3. confirmation is obtained if `mode = "confirm"`;
4. the core signs, and the audit log (`audit.jsonl`, JSONL, append-only)
   gets a `signed` entry with time, kind, review, txid and spend. Refusals,
   parked bundles, user rejections and broadcasts are logged too.

**Spend** of an approval = Σ |negative `balance_changes`| per asset, plus
the fee for the policy asset, summed over all transactions approved together
(e.g. split + offer). Received assets never offset spend. A signed swap offer
counts as spent when signed (it can be taken at any time). Rolling 24 h spend
is reconstructed from `signed` audit entries; a corrupt audit log fails
closed.

```toml
mode = "auto"                       # or "confirm" (default)
allowed_recipients = ["ert1q…"]     # optional; compared by script, not HRP
allowed_dex_urls = ["http://127.0.0.1:8790"]

[limits.policy]                     # "policy" = the network fee asset (ECX)
per_tx = "0.5"                      # decimal in asset precision, or "atomic:<n>"
per_24h = "2"

[limits.<64-hex asset id>]          # tickers are not accepted as keys
per_tx = "atomic:500000"
per_24h = "atomic:600000"
```

Rules:

- **Limits** (`per_tx`, `per_24h`) are hard caps in both modes; a human
  confirmation cannot override them.
- **Auto mode**: every asset an approval spends must have a limit entry with
  at least one of `per_tx`/`per_24h`, and DEX operations (swap, posted
  offers) require the configured DEX in `allowed_dex_urls`. The default
  policy (confirm, no limits) therefore refuses everything in auto mode until
  limits are set.
- **Confirm mode**: on a terminal, epw shows the review and asks `y/N`
  (on `/dev/tty`). Without a terminal, and always via MCP, nothing is signed:
  the bundle is parked in `pending/<approval_hash>.json` and the result has
  `status: "approval_required"`, the review, the `approval_hash` and an
  `approve_command`. A human approves with
  `epw review <file>` then `epw sign <file> --approve <approval_hash>`.
- **`allowed_recipients`**: if set, every external output must pay a listed
  address. Maker outputs of DEX-routed swap takes are exempt (bounded by
  limits and `allowed_dex_urls`); a swap take without DEX context is not.
- **`allowed_dex_urls`**: if set, the configured DEX must be listed for swaps
  and posted offers.
- The approval hash of a single transaction is its core `review_hash`; for a
  multi-transaction bundle it is
  `SHA256("EPW_APPROVAL_BUNDLE_V1\0" ‖ review_hash₁ ‖ … ‖ review_hashₙ)`.

Note: `--approve` is the human's approval. An agent that has a shell and
`EPW_PASSWORD` can run `epw sign` itself; give agents only the MCP server
(the password in its environment), not a shell, if confirm mode must hold.

## MCP server

`epw mcp` speaks MCP 2025-06-18 (newline-delimited JSON-RPC 2.0 on stdio:
`initialize`, `ping`, `tools/list`, `tools/call`). The keystore is unlocked
once at startup from **`EPW_PASSWORD`** (required: stdin carries the
protocol, so there is no prompt); every tool, read-only or not, runs against
that unlocked wallet.

Tools: `get_address`, `get_balances`, `get_history`, `get_markets`,
`get_order_book`, `get_quote`, `list_offers`, `get_policy`, `swap`,
`make_offer`, `cancel_offer`, `send`, `issue_asset`. Results are returned as
`structuredContent` (plus the same JSON as text). Tool failures and policy
refusals are tool results with `isError: true` (refusals include the policy
decision); `approval_required` is a normal result.

Claude Code (`.mcp.json`) / Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "epw": {
      "command": "/path/to/epw",
      "args": ["mcp"],
      "env": {
        "EPW_HOME": "/home/me/.config/epw",
        "EPW_PASSWORD": "…"
      }
    }
  }
}
```

(`claude mcp add epw --env EPW_PASSWORD=… -- /path/to/epw mcp` does the same
for Claude Code.)

## Tests

```sh
cargo test                                  # unit tests (policy, amounts, keystore, MCP with a fake backend, …)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Opt-in live test against a regtest node, the Esplora bridge and a DEX server
(spends disposable node funds; refuses to run without `ELEMENTS_DATADIR`).
It runs the full flow twice — once through the CLI, once through `epw mcp`
with a scripted JSON-RPC client — with two fresh keystores: fund, issue +
register, two posted offers, quote + swap by the second wallet (confirm mode,
approved via `epw sign`), offer list, cancel, history, and policy refusals.

```sh
ELEMENTS_CLI=…/elements-functional-test-cli ELEMENTS_DATADIR=…/.regtest/node \
ELEMENTS_RPCPORT=18884 EPW_TEST_ESPLORA=http://127.0.0.1:43199/api \
EPW_TEST_DEX=http://127.0.0.1:8791 EPW_TEST_DIR=/tmp/epw-itest \
cargo test --test funded_regtest -- --ignored --test-threads=1 --nocapture
```

Offers carry the wallet's profile id as `"network"` (`elementsplus-regtest`
here), so the DEX server must run with `NETWORK_NAME=elementsplus-regtest`
(its default is still `ecx-alpha`).
