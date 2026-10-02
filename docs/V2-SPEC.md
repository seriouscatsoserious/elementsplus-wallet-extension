# Wallet v2 + DEX — build spec

Contract shared by the wallet extension (`elementsplus-wallet-extension`, branch
`feat/wallet-v2`) and the DEX (`elementsplus-dex`). Change this file first if an
interface has to move.

Mockup: https://claude.ai/artifact/UCNxQ2hbsQp93rFVbrQdyM (wallet popup 360×600,
DEX desktop pages). Dark theme, accent `#8FA8FF`, surfaces `#0E0F13` / `#16181D`,
borders `#23262D`, muted text `#9A9DA6`, positive `#4FC3A1`, negative/asks
`#FF8A5B`, fonts Geist / Geist Mono (bundle locally in the extension: its CSP
forbids remote fonts; fall back to system-ui).

## 0. Ground rules

- Explicit outputs by default. Each wallet build / `epw` config is pinned to
  one **network profile** (`docs/NETWORKS.md`: `ecx-beta`, `ecx-mainnet`,
  `elementsplus-regtest`; `ecx-alpha` archived) by genesis and policy asset;
  nothing here relaxes the existing identity checks. Pending profiles are
  refused, never guessed. Confidential funds received from other wallets are
  seen and spendable (§1.4); confidential receive addresses are a per-profile
  opt-in, and swap offers and takes stay explicit-only.
- All amounts cross JSON boundaries as **decimal strings of atomic units**
  (`"2500000"`), never floats. Display precision comes from asset metadata
  (`precision`, default 0 for unknown assets, 8 for ECX).
- Keys never leave the extension service worker. Every signature requires an
  explicit user approval of a review computed **by the wallet from the PSET**,
  never from dApp-supplied text.
- Preconfirmations are removed from the wallet. The code moves to the DEX repo
  under `preconf/` (parked, not wired up).
- Asset issuance, swaps, multi-asset sends all go through one review/sign path.

## 1. Rust signing core (`rust/wallet-core`)

### 1.1 One review model for every transaction

```rust
pub struct TxReview {
    pub kind: TxKind,                 // Transfer | Issuance | SwapOffer | SwapTake | OfferSplit | Cancel
    pub network: String,
    pub genesis_hash: String,
    /// Net effect on this wallet, per asset, excluding the fee. Signed decimal strings.
    pub balance_changes: Vec<AssetDelta>,   // { asset_id, amount: "-100000000" }
    pub fee: u64,                     // policy asset, atomic
    /// Outputs paying scripts that are NOT this wallet's.
    pub external_outputs: Vec<ExternalOutput>, // { address, asset_id, amount }
    pub inputs_signed: Vec<String>,   // "txid:vout" this wallet will sign
    pub foreign_inputs: Vec<String>,  // inputs owned by others (swap makers)
    pub issuance: Option<IssuanceReview>, // { asset_id, token_id?, amount, token_amount, contract_hash }
    pub sighash: String,              // "ALL" or "SINGLE|ANYONECANPAY"
}
```

`review_hash` = SHA256(domain `ECX_ALPHA_TX_REVIEW_V2\0` ‖ unsigned PSET bytes
‖ canonical review JSON). Signing recomputes both and refuses on mismatch.

Wallet-owned outputs (change, received swap legs, issuance outputs) must carry
a bip32 derivation that re-derives to the output script, or they are treated
as external.

### 1.2 Operations (each returns `PreparedTx { pset_base64, review, review_hash }`)

| Function | Notes |
|---|---|
| `prepare_transfer({recipient, asset_id, amount, fee_rate_sat_vb, utxos, change_index})` | Any asset. Coin-select asset inputs, then policy inputs for the fee. Outputs: recipient, asset change (if any), policy change (if any), fee. Fee computed from a size estimate × rate (min 1 sat/vB), not caller-supplied. |
| `prepare_issuance({contract, amount, token_amount, fee_rate, utxos, change_index, receive_index})` | `contract` = `{"name","ticker","precision","version":0,"issuer_pubkey"?}`; contract hash via `ContractHash::from_json_contract` on the canonical (sorted-key, no-whitespace) JSON. One policy input carries the issuance; asset (and token if `token_amount > 0`) paid to wallet addresses; explicit, non-blinded issuance. |
| `prepare_swap_offer({utxo, want_asset, want_amount, receive_index})` | **Maker.** Exactly one input (the whole UTXO is offered) and one output (wallet address receiving `want_amount` of `want_asset`). Signed `SIGHASH_SINGLE|ANYONECANPAY` (0x83). |
| `prepare_offer_split({asset_id, amount, fee_rate, utxos, change_index, receive_index})` | Self-send creating an output of exactly `amount` so it can be offered. The UI chains split + offer behind one approval (§3.3). |
| `take_swap_offers({offers, fee_rate, utxos, change_index, receive_index})` | **Taker.** Maker input/output pairs first, at matching indices 0..n-1 (required by SINGLE). Then taker inputs paying every maker output's asset plus the fee, taker outputs receiving each maker input's asset, change per asset, fee last. Taker signs its inputs `SIGHASH_ALL`. Maker witnesses are preserved untouched. |
| `prepare_cancel({utxo, change_index, fee_rate, other_utxos})` | Spend an offered UTXO back to self (invalidates the offer). |
| `sign_prepared(prepared, approved_review_hash)` | Signs only wallet inputs, with the sighash the review declares. Swap offers return the offer (§2) instead of a broadcastable tx. |
| `verify_asset_issuance({raw_tx_hex, expected_txid, vin, contract})` | Recompute contract hash → entropy → asset id / token id from the issuance input; return them or fail. Used to trust token metadata. |
| `decode_offer(offer_json, prevout_raw_tx_hex)` | Verify the prevout tx hashes to the offered input's txid, read asset/value/script, verify the 0x83 signature, return `{give_asset, give_amount, want_asset, want_amount, outpoint, maker_address}`. |

Prevouts for maker inputs are never taken from the offer alone: callers pass
the raw funding tx, verified locally by txid.

### 1.3 WASM surface (`src/wasm/elementsplus_wallet_core.d.ts`)

All request/response JSON is snake_case, amounts as decimal strings except
`fee`/`fee_rate` numbers are allowed (integers). Existing
`verify_raw_transaction_json` keeps its camelCase shape.

```ts
export function generate_mnemonic(): string;
export function validate_mnemonic(m: string): boolean;
export function verify_asset_issuance_json(req: string): string; // {asset_id, token_id|null, contract_hash}
export function decode_offer_json(offer: string, prevout_raw_tx_hex: string): string; // DecodedOffer
export class WasmWalletCore {
  constructor(mnemonic: string);
  static forRegtest?(mnemonic: string, genesisHash: string, policyAsset: string, displayName: string): WasmWalletCore;
  derive_address_json(branch: string, index: number, confidential?: boolean | null): string;
  set_confidential_receive(enabled: boolean): void;
  confidential_receive(): boolean;
  verify_raw_transaction_json(req: string): string;
  prepare_transfer_json(req: string): string;   // PreparedTx
  prepare_issuance_json(req: string): string;
  prepare_offer_split_json(req: string): string;
  prepare_swap_offer_json(req: string): string;
  take_swap_offers_json(req: string): string;   // req.offers: [{ offer, prevout_raw_tx_hex }]
  prepare_cancel_json(req: string): string;
  sign_prepared_json(prepared: string, approved_review_hash: string): string;
  // → { txid, review_hash, raw_tx_hex?: string, offer?: Offer }
  free(): void;
}
```

`utxos` entries keep the existing `VerifiedUtxo` shape (`txid, vout, value,
asset_id, script_pubkey_hex, branch, index`) but any asset is accepted, plus
an optional `blinding` object for confidential UTXOs (§1.4).

### 1.4 Confidential transactions

- `derive_address_json(branch, index, confidential?)`; `set_confidential_receive(bool)`
  (default off). Confidential derivations add `confidential_address`,
  `confidential_lwk_alias`, `blinding_pubkey_hex` (SLIP-77 from the seed).
- `verify_raw_transaction_json` (instance method) unblinds confidential wallet
  outputs with the wallet's key and adds `blinding: {asset_commitment_hex,
  value_commitment_hex, asset_blinder_hex, value_blinder_hex}`; outputs that
  do not unblind fail verification. Pass `blinding` back unchanged in a
  `VerifiedUtxo` to spend.
- Transfers, issuances, offer splits and cancels may spend confidential
  UTXOs. Recipient output follows the address type; change is confidential
  iff any input is; the fee is explicit. Outputs are blinded before the
  review, which is recomputed from the PSET (explicit value/asset proofs on
  every confidential input and output, full proof verification) and marks
  `confidential: true` on the review and on blinded external outputs.
- Swap offers refuse confidential UTXOs; takes never select them; offer
  splits always create an explicit offerable output.

## 2. Swap offer format (LiquiDEX-style, explicit)

```json
{
  "version": 1,
  "network": "ecx-beta",
  "genesis_hash": "<hex>",
  "tx": "<hex of a 1-input 1-output Elements tx; input witness = [sig||0x83, pubkey]>",
  "give": { "asset_id": "<hex>", "amount": "1000" },
  "want": { "asset_id": "<hex>", "amount": "5000" }
}
```

`network` is the maker wallet's **network profile id** (`ecx-beta`,
`ecx-mainnet`, `elementsplus-regtest`; historical offers from the retired
chain say `ecx-alpha`). It is not a display name. Consumers (wallet core, DEX
server, DEX web) match an offer on **both** `genesis_hash` and `network` =
their own profile id, and reject any mismatch; the profile id alone is not an
identity (the archived `ecx-alpha` and `ecx-beta` share the v11 genesis). The
DEX server's `NETWORK_NAME` must therefore be set to the profile id it serves
(its default is still the legacy `ecx-alpha`).

`give`/`want` are convenience copies; every consumer re-derives them from
`tx` + the verified prevout and rejects mismatches. Price = want/give in atomic
units; UIs scale by precision. Whole-UTXO offers only (no partial fills of a
single offer); a taker fills one or more whole offers.

## 3. Wallet extension

### 3.1 Screens (match the mockup)

Lock gate (full screen) → onboarding (Create / Import → show phrase → confirm
3 random words → password) → Home (account chip, network pill, lock button,
balance, Receive/Send/Swap, token list with Manage; unverified assets tagged)
→ Activity (pending / dated groups, per-tx deltas) → Send (token picker, decimal
amount + Use max, fee preset Slow/Standard/Fast) → Confirm (big delta, To,
network, fee, total, collapsed details incl. review hash) → Receive (real QR,
address, copy) → Settings (network & endpoints, token list URL, connected
sites, lock timer, reveal phrase behind password, advanced: genesis/asset pins).
dApp approval windows: Connect, and one Approve window rendering any
`TxReview` (swap / offer / issuance / transfer).

Bottom nav: Wallet · Activity · Settings. Swap button opens the DEX URL in a tab.

### 3.2 Token metadata

Configurable registry URL (default: DEX server `/api/assets`). For each asset
id with a balance: fetch `{contract, issuance_txid, issuance_vin}`, fetch the
raw issuance tx from the explorer, run `verify_asset_issuance`. Verified →
show name/ticker/precision. Otherwise "Unknown asset" + UNVERIFIED tag,
truncated id, precision 0. ECX is built in.

### 3.3 dApp provider

Content script injects `window.elementsplus` on http(s) pages. EIP-1193-shaped:

```ts
interface ElementsPlusProvider {
  isElementsPlus: true;
  request(args: { method: string; params?: unknown }): Promise<unknown>;
  on(event: "accountsChanged" | "disconnect", handler: (...a: unknown[]) => void): void;
  removeListener(event: string, handler: (...a: unknown[]) => void): void;
}
```

Also dispatch `window.dispatchEvent(new Event("elementsplus#initialized"))`.

| method | params | result | approval |
|---|---|---|---|
| `ep_connect` | – | `{ address, network: { name, genesisHash, policyAsset } }` | Connect window (per-origin, remembered) |
| `ep_disconnect` | – | `null` | none |
| `ep_getAddress` | – | `{ address }` | connected |
| `ep_getBalances` | – | `[{ assetId, amount, confirmed }]` | connected |
| `ep_sendTransfer` | `{ assetId, amount, recipient }` | `{ txid }` | Approve window |
| `ep_makeSwapOffer` | `{ giveAsset, giveAmount, wantAsset, wantAmount }` | `{ offer, splitTxid? }` | one Approve window covering split (if needed) + offer |
| `ep_takeSwapOffers` | `{ offers: Offer[] }` | `{ txid }` | Approve window |
| `ep_cancelSwapOffer` | `{ txid, vout }` | `{ txid }` | Approve window |
| `ep_issueAsset` | `{ name, ticker, precision, amount, tokenAmount }` | `{ txid, assetId, tokenId?, contract, vin }` | Approve window |

Errors: `{ code, message }` with `4001` user rejected, `4100` unauthorized
(not connected), `4200` unsupported method, `-32602` invalid params, `-32603`
internal. The wallet locks → requests needing keys open the popup to unlock
first.

Message path: page `postMessage` → content script → `chrome.runtime` port →
service worker. Origin comes from `sender.origin`/`sender.url`, never from the
page payload. Approvals open `src/ui/approve.html?id=…` via
`chrome.windows.create({type:"popup"})`.

Manifest additions: `content_scripts` (`<all_urls>`, `run_at: document_start`,
isolated world) plus a `web_accessible_resources` inpage script; permissions
stay minimal (`storage`); host permissions for configured explorer/registry.

## 4. DEX (`elementsplus-dex`)

### 4.1 Server (Rust, axum + rusqlite bundled + elements)

Config: `ESPLORA_URL`, `LISTEN`, `DB_PATH`, `GENESIS_HASH`, `POLICY_ASSET`.

| Endpoint | Behaviour |
|---|---|
| `GET /api/health` | `{ ok, tip }` |
| `GET /api/assets` / `GET /api/assets/:id` | verified registry entries `{ asset_id, token_id, contract, issuance_txid, issuance_vin, icon_url? }` |
| `POST /api/assets` | `{ issuance_txid, vin, contract }` → fetch raw tx, verify contract commitment (same algorithm as §1.2), store |
| `GET /api/markets` | pairs with ≥1 offer or trade: `{ base, quote, last_price, change_24h, volume_24h, best_bid, best_ask }`; quote is ECX unless both non-native |
| `GET /api/markets/:base/:quote/book` | `{ bids: [Offer+price], asks: [...] }` |
| `GET /api/markets/:base/:quote/trades` | recent fills `{ txid, price, base_amount, quote_amount, time }` |
| `GET /api/markets/:base/:quote/candles?interval=1h` | OHLCV from fills |
| `POST /api/offers` | validate (decode, prevout fetched from Esplora and txid-verified, 0x83 sig verified with sighash, outpoint unspent via `/tx/:txid/outspend/:vout`, network match), store |
| `GET /api/offers?maker=<address>` | a maker's open offers |
| background task | every ~5 s: check open offers' outspends; spent by a tx paying the maker output → record trade; otherwise mark cancelled |

Offers are public; anyone can take. Server never holds keys.

### 4.2 Web app (Vite + React + TypeScript)

Pages per mockup: **Swap** (pick pair, amount → choose cheapest set of whole
asks/bids, show rate, impact, min received; `ep_takeSwapOffers`), **Markets**
(market list, price chart from candles, order book, limit order form →
`ep_makeSwapOffer` → `POST /api/offers`; your open orders with Cancel →
`ep_cancelSwapOffer`), **Launch** (form → `ep_issueAsset` → `POST /api/assets`,
optional listing → `ep_makeSwapOffer`). Wallet connect button using
`window.elementsplus`; "Install wallet" state when absent.

## 5. Regtest harness

`npm run regtest:start` builds/starts the pinned node + loopback Esplora bridge
(no signer/relays). Bridge must additionally serve `GET /tx/:txid` (Esplora
JSON with `vin[].prevout`), `GET /tx/:txid/outspend/:vout`,
`GET /address/:addr/txs`. The DEX server runs against the same bridge.

## 6. Agent access

Agents (scripts, LLM agents, bots) must be able to use the DEX and a wallet
without a browser.

### 6.1 DEX server

- `GET /api/openapi.json`: OpenAPI 3.1 document for every endpoint, with
  examples. `GET /llms.txt`: short plain-text guide (what the DEX is, the
  trade flow, links to the OpenAPI doc and SPEC offer format).
- `GET /api/quote?sell=<asset>&buy=<asset>&amount=<atomic>&side=exact_in|exact_out`:
  returns `{ offers: [Offer], sell_amount, buy_amount, price, price_impact_bps,
  unfilled }`, using the same whole-offer greedy routing as the web Swap page
  (the web app should call this instead of routing locally).
- Machine-friendly errors: `{ error: { code, message } }` with stable
  snake_case codes (`offer_spent`, `bad_signature`, `unknown_asset`, …).
- `POST` endpoints accept an `Idempotency-Key` header.
- Read endpoints support `?limit=&cursor=` pagination.

### 6.2 Headless wallet (`rust/wallet-cli` in the wallet repo, binary `epw`)

Uses `elementsplus-wallet-core` natively; same review model and signing path
as the extension.

- Keys: `epw init` (new mnemonic) / `epw import` writes an encrypted keystore
  (`~/.config/epw/`, scrypt or argon2 + XChaCha20-Poly1305); unlock via
  `EPW_PASSWORD` or prompt. Never prints the mnemonic except on `init`.
- Config: network = profile id (`ecx-beta` | `ecx-mainnet` |
  `elementsplus-regtest` with genesis/policy asset; `regtest` accepted as a
  legacy spelling; pending/archived profiles refused), Esplora URL and DEX URL
  (default: the profile's), registry URL.
- **Policy file** enforced before signing: per-asset max per transaction and
  per rolling 24 h, allowed recipient addresses (optional), allowed DEX URL,
  `require_confirmation` (interactive y/N) vs `auto` for agents. Every
  signature is appended to an audit log (JSONL: time, kind, review, txid).
- Commands (all support `--json`; default human output):
  `address`, `balances`, `history`, `send <asset> <amount> <address>`,
  `issue --name --ticker --precision --amount [--token-amount] [--register]`,
  `quote <sell> <buy> <amount>`, `swap <sell> <buy> <amount> [--max-slippage-bps]`
  (quote → take), `offer make <give> <amt> <want> <amt> [--post]`,
  `offer list`, `offer cancel <txid:vout>`, `review <prepared.json>` and
  `sign <prepared.json> --approve <review_hash>` for two-step flows.
- `epw mcp`: MCP server over stdio exposing the same operations as tools
  (`get_balances`, `get_address`, `get_markets`, `get_order_book`,
  `get_quote`, `swap`, `make_offer`, `cancel_offer`, `send`, `issue_asset`,
  `get_history`). Mutating tools return the review and the policy decision;
  they sign only if the policy allows it.
- amounts accepted as decimal with asset precision or `atomic:<n>`.
