# Instant — non-custodial fast confirmation for the Elements+ DEX

Status: **design + feasibility prototype**. Not audited, not deployed. Everything in
§4 runs today against the pinned Elements+ Simplicity interpreter and a live
local regtest node (§15). All other sections are protocol that still has to be built.

Contents: 1 Goals · 2 Actors · 3 Notation and constants · 4 Contracts ·
5 Operator lifecycle · 6 Lockbox lifecycle · 7 Watchtower · 8 What a wallet checks before showing "Done" ·
9 DEX flows · 10 What the wallet automates · 11 Reward split · 12 Timeouts ·
13 Threat model · 14 What this does NOT guarantee · 15 Prototype and results ·
16 Open questions for JK

---

## 1. Goals and how the design meets them

| Requirement | Mechanism |
| --- | --- |
| Swap shows "Done" in ~1 s, final in the next block | The wallet gets an operator **promise** (one BIP340 signature per lockbox input) over the exact transaction. On chain, the coins cannot move without such a promise before EXPIRY. Signing a second promise is slashable (§4, §8). |
| Nobody custodies funds; operators can never move them | Every lockbox spending path needs the **owner's** signature. The operator only co-signs, and only before EXPIRY matters (§4.1). |
| Operator disappears or refuses → funds come back automatically after a short timeout; automatic failover | Owner-only exit at absolute height `EXPIRY`. The wallet renews lockboxes while online, so funds are delayed by at most the remaining lifetime (default ≤ 12 h; §6, §12). After that the wallet exits straight into a lockbox under another operator. |
| Anyone can be an operator; no allowlist | An operator is a key plus a confirmed **pooled bond** UTXO. Wallets verify the bond on chain from a self-certifying signed announcement (§5). |
| Anyone can run a watchtower and get paid for proving cheating | The penalty path is open to anyone. 1/8 of the bond goes to an output the reporter chooses and 7/8 is provably burned (§4.2, §7, §11). |
| Makers are offline; orders are pre-signed | The lockbox has a **PAIRED** owner authorization (own input + same-index output, like SIGHASH_SINGLE\|ANYONECANPAY). The operator's promise still commits to the whole transaction (§4.1, §9). |

Gaps in JK's prototype that this closes:
1. **One bond for many lockboxes.** Promises bind `(lockbox outpoint, tx commitment)` and the operator key, not a bond outpoint. Any bond UTXO under that key can be slashed with any equivocation by the key.
2. **A promise did not stop the owner broadcasting without the operator.** The lockbox covenant now requires the promise for every cooperative spend. So every on-chain spend carries a promise in its witness, and any second promise is evidence.
3. **The penalty went 100% to miners.** It is now 12.5% to the reporter and 87.5% provably burned to `OP_RETURN`.
4. **Offline makers.** The PAIRED authorization handles them.

## 2. Actors

- **Owner / user wallet**: holds the lockbox owner key. Usually a wallet that runs everything in §10 automatically.
- **Maker**: an owner who pre-signs PAIRED orders and goes offline.
- **Taker**: an owner who completes a maker's order into a transaction.
- **Operator**: holds an operator key, funds pooled bonds, runs the promise API (§5.4) and broadcasts promised transactions.
- **Watchtower**: anyone who collects promises (relays, its own users, the chain) and submits penalty transactions.
- **Relay**: a receipt-gossip server as in JK's design (`preconf/vendor/elementsplus-preconf/OPERATOR-RELAY.md`). It is not trusted for validity.
- **DEX server**: an order book, as today. It relays orders and is not trusted.

## 3. Notation and constants

All hashes are SHA-256 over 32-byte internal/consensus byte order (not reversed RPC
hex). Integers are big-endian. `||` means concatenation. BIP340 signatures are 64 bytes.
Output scripts are Taproot with the BIP341 NUMS internal key
`50929b74…3ac0` and **exactly one** Simplicity leaf (leaf version `0xbe`). This is
JK's construction (`preconf/.../src/lib.rs::bond_taproot`). Receivers MUST
re-derive the script from parameters and reject any other tree or internal key.

| Name | Value |
| --- | --- |
| `PROMISE_TAG` | `"ECX/Instant/Promise/v1"` |
| `PAIRED_TAG` | `"ECX/Instant/PairedAuth/v1"` |
| `ANNOUNCE_TAG` | `"ECX/Instant/Announce/v1"` |
| `REWARD_SHIFT` | 3 (reporter share = ⌊bond/8⌋), fixed in the contract |
| `BURN_SCRIPT` | `0x6a` (bare `OP_RETURN`), fixed in the contract by its SHA-256 |
| `PROMISE_MARGIN` (S) | 6 blocks |
| `CHALLENGE_WINDOW` (W) | 144 blocks |
| `BOND_MIN_CONFIRMATIONS` | 2 |
| `DEFAULT_LIFETIME` (L) | 72 blocks for balance lockboxes. Maker-order lockboxes: user-chosen, default 1008, max 4032 |
| `RENEW_BELOW` | 36 blocks |
| `MIN_BOND` | 0.01 native unit (policy only) |

These are policy constants in `src/policy.rs`, except `REWARD_SHIFT` and `BURN_SCRIPT`, which are consensus-enforced by the contract.

### 3.1 Transaction commitment (index-free)

```
tx_commitment(T) = SHA256( jet::tx_hash() || jet::input_script_sigs_hash() )
```

`tx_hash` is the Elements Simplicity jet (pinned source
`src/simplicity/elements/env.c`, lines 629–637):
`SHA256(version[4] || lock_time[4] || inputs_hash || outputs_hash || issuances_hash || output_surjection_proofs_hash || input_utxos_hash)`.
It covers every outpoint, sequence and annex, every output (asset, amount, nonce,
script, range-proof hash), issuances, surjection proofs and the spent UTXOs
(asset, amount, script). `input_script_sigs_hash` is added because `tx_hash` omits
scriptSigs while the txid commits to them. Therefore **`tx_commitment` determines the txid**:
two transactions with equal commitments have equal txids. The commitment also covers witness proofs, which is why Instant is explicit-only (§4.4).
The host implementation is `src/hash.rs::tx_commitment` (explicit-only; it rejects peg-ins,
issuances and annexes). It is validated byte for byte because the real programs verify
host-produced signatures over it, including a two-input, two-asset swap.

### 3.2 Signed messages

```
promise_digest(lockbox, T) = SHA256( SHA256(PROMISE_TAG) || genesis[32]
                                     || lockbox_txid[32] || lockbox_vout[4]
                                     || tx_commitment(T)[32] )            -- signed by OPERATOR

paired_digest(lockbox, out) = SHA256( SHA256(PAIRED_TAG) || genesis[32]
                                      || lockbox_txid[32] || lockbox_vout[4]
                                      || output_hash(out)[32] )           -- signed by OWNER (maker)
output_hash(out) = SHA256( asset_conf || amount_conf || nonce_conf
                           || SHA256(scriptPubKey) || SHA256(range_proof) )   -- = jet::output_hash

ALL authorization                                                         -- signed by OWNER
  = jet::sig_all_hash() = SHA256(genesis || genesis || tx_hash || tap_env_hash || index[4])
```

The promise digest deliberately binds only the outpoint and the transaction.
Outpoints are globally unique, so "two promises for the same outpoint with different
commitments" is exactly equivocation, and the bond can check it without knowing anything
about the lockbox. The operator key never signs anything else except bond refunds
(`sig_all_hash`, untagged but structurally different) and announcements (`ANNOUNCE_TAG`).

## 4. Contracts

Sources: `contracts/lockbox.simf` and `contracts/pooled_bond.simf`, compiled with
SimplicityHL `=0.7.2` (JK's pin) through `src/lib.rs::compile`.

### 4.1 Lockbox

Parameters (committed in the CMR, and therefore in the address): `PROMISE_DOMAIN = SHA256(PROMISE_TAG)`,
`PAIRED_DOMAIN = SHA256(PAIRED_TAG)`, `GENESIS`, `OWNER` (x-only), `OPERATOR` (x-only), `EXPIRY` (u32 absolute height).

Always checked: `genesis_block_hash == GENESIS`; `OWNER != OPERATOR`; `0 < EXPIRY < 500000000`;
the current input has no peg-in, new issuance or reissuance.

Witness `ACTION : Either<(Auth, Signature), Signature>` with `Auth = Either<Signature, Signature>`:

| Path | Witness | Spending condition |
| --- | --- | --- |
| Cooperative, ALL | `Left((Left(owner_sig), promise))` | `bip340(OWNER, sig_all_hash, owner_sig)` **and** `bip340(OPERATOR, promise_digest(current outpoint, tx), promise)` |
| Cooperative, PAIRED | `Left((Right(owner_sig), promise))` | `bip340(OWNER, paired_digest(current outpoint, output[current_index]), owner_sig)` (fails if that output does not exist) **and** the same promise check |
| Exit | `Right(owner_sig)` | `check_lock_height(EXPIRY)` (the tx's height lock must be at least EXPIRY, and a disabled lock time does not count) **and** `bip340(OWNER, sig_all_hash, owner_sig)` |

Consequences (each one is tested; see §15):
- The operator alone can never spend, because every path verifies `OWNER`.
- Before EXPIRY, every confirmed spend carries `bip340(OPERATOR, promise_digest(...))` in its witness.
- A promise for transaction A does not authorize transaction B. A change to any output, fee, lock time, sequence, input or spent UTXO changes the commitment.
- A promise for lockbox X cannot be used on lockbox Y.
- A PAIRED order is valid in **any** transaction that places the maker's input at index i and the maker's wanted output at index i. Everything else (taker inputs, change, fee) is the taker's choice, but the operator's promise pins it.
- After EXPIRY the cooperative path still works. The operator simply stops issuing promises S blocks earlier (§8).

Witness layout for deserialization: a Simplicity witness bit string, with values in program order. Watchtowers do not depend on the layout (§7).

### 4.2 Pooled operator bond

Parameters: `PROMISE_DOMAIN`, `GENESIS`, `FEE_ASSET` (native ECX), `OPERATOR`,
`REFUND_HEIGHT`, `BURN_SCRIPT_HASH = SHA256(0x6a)`. The amount is **not** a parameter.
The same script can hold many UTXOs (top-ups), and each one is slashable separately.

Always checked: genesis; `0 < REFUND_HEIGHT < 500000000`; no peg-in or issuance on the current input;
the current input is explicit `FEE_ASSET` with amount `bond > 0`.

Witness `ACTION : Either<Evidence, Signature>` with
`Evidence = (Outpoint lockbox, (u256 c1, Signature s1), (u256 c2, Signature s2))`:

| Path | Spending condition |
| --- | --- |
| Penalty (anyone, any time while unspent) | `c1 != c2`; `bip340(OPERATOR, SHA256(PROMISE_DOMAIN‖GENESIS‖lockbox‖cᵢ), sᵢ)` for both; exactly **1 input, 3 outputs**: out0 explicit `FEE_ASSET`, any script (reporter); out1 `scriptPubKey == OP_RETURN` with explicit `FEE_ASSET` amount `== bond − ⌊bond/8⌋`; out2 is a fee output in `FEE_ASSET`; `out0 + out2 == ⌊bond/8⌋` (overflow-checked) |
| Refund | `check_lock_height(REFUND_HEIGHT)` and `bip340(OPERATOR, sig_all_hash, sig)` |

The reporter pays the network fee out of its 1/8 share and may spend all of it on the fee.
The burn is provably unspendable. A block producer who is, or colludes with, the operator
can recapture at most the 1/8 share and the fee, never the 7/8. (JK's original sent everything to fees.
On a BMM sidechain the block producer collects fees, so an operator that is also the producer
could mine its own slash and lose nothing. Burning closes that hole.)

### 4.3 Measured costs (pinned C interpreter, node-derived budget)

| Spend | Program | Witness | Budget |
| --- | --- | --- | --- |
| Lockbox cooperative ALL | 531 B | 129 B | 782 WU |
| Lockbox cooperative PAIRED | 707 B | 129 B | 958 WU |
| Lockbox exit | 306 B | 65 B | 493 WU |
| Bond penalty | 936 B | 229 B | 1287 WU |
| Bond refund | 399 B | 65 B | 586 WU |

The two-lockbox swap mined on regtest is 749 vB (2994 WU) and paid a 2000-sat fee.

### 4.4 Feasibility notes (pinned Simplicity, node `4041a8ba…` `src/simplicity` tree `69c15c21…`)

- **All required jets exist and work**: `tx_hash`, `input_script_sigs_hash`, `output_hash`,
  `output_script_hash`, `sig_all_hash`, `current_prev_outpoint`, `current_index`, `output_amount`,
  `output_is_fee`, `num_inputs/outputs`, `check_lock_height`, `right_shift_64`, `subtract_64`,
  `add_64`, `bip_0340_verify` and the SHA-256 context jets.
- **Relative timelocks are NOT usable.** `check_lock_distance` and `check_lock_duration` are
  `simplicity_broken_do_not_use_*` in this version (`elementsJets.c:1969–1980`). So the lockbox
  timeout is an **absolute height**. This turns out to be the better choice anyway: the cutoff is the
  same for an unconfirmed lockbox and a confirmed one, so operators and wallets can reason about chains
  of unconfirmed lockboxes without knowing confirmation heights.
- **Simplicity cannot read chain state.** A covenant cannot see whether a promise is "stale"
  or whether another transaction confirmed. Hence: (a) the promise is permanent per outpoint;
  (b) promise-acceptance cut-offs (S, W, exposure) are off-chain policy, not consensus; and
  (c) a commit-reveal scheme to stop reward front-running is not expressible without extra
  machinery (§14).
- **Explicit-only.** `tx_hash` commits to range and surjection proofs. Two blindings of the "same"
  confidential transaction would have different commitments and look like equivocation. Instant
  therefore requires explicit amounts and assets in every promised transaction, which is already the DEX
  default (`docs/V2-SPEC.md` §0, §2). Lockboxes themselves accept any output, but wallets fund them
  explicitly.
- **Mempool:** spends need `sendrawtransaction <hex> 0 <maxburnamount>`. The node's default
  `maxburnamount=0` client guard rejects the penalty's OP_RETURN burn. `testmempoolaccept`
  and policy accept it, and so did `destroyamount`.

No consensus change, new jet or activation is needed.

## 5. Operator lifecycle

### 5.1 Key and bond
1. Generate an operator key and use it **only** for Instant promises, announcements and bond refunds.
2. Fund one or more explicit native-asset outputs to `pooled_bond(GENESIS, ECX, OPERATOR, REFUND_HEIGHT)`.
   Recommended: REFUND_HEIGHT ≥ tip + 30 days. **Roll** by funding a new bond with a later refund
   height well before the old one stops being eligible (§8 rule B3). There is no in-place extension;
   that would need covenant self-recursion and is not worth the complexity.
3. After REFUND_HEIGHT, refund. Wallets stop counting a bond once `tip + S + W > REFUND_HEIGHT` for the
   lockboxes they use, so a refund never races open promises.

### 5.2 Announcement (no registry)

```
announcement = { genesis, fee_asset, operator, sequence (u64, monotonic),
                 bonds: [ {outpoint, refund_height} ] (1..16), api_url (https, ≤256 B) }
signed digest = SHA256( SHA256(ANNOUNCE_TAG) || genesis[32] || fee_asset[32] || operator[32]
                        || sequence[8] || n_bonds[1] || n × (txid[32] || vout[4] || refund_height[4])
                        || url_len[2] || url )
```

`src/announce.rs` implements the encoding, signing, verification and `expected_bond_script`.
The operator posts it to any relay or DEX (for example `POST /v1/instant/operators` on the DEX server,
stored verbatim). **Nothing in it is trusted.** For every bond, the wallet (a) recompiles
the bond script from `(genesis, fee_asset, operator, refund_height)`, (b) fetches
`GET /api/tx/:txid` from its own Esplora and checks the output's scriptpubkey equals it, the asset is the
native asset (explicit), and the value is at least `MIN_BOND`, (c) checks `GET /api/tx/:txid/outspend/:vout`
reports it unspent and the funding transaction has at least 2 confirmations. Wallets keep the highest valid
`sequence` per operator. A bogus announcement wastes a few HTTP calls and nothing more.

### 5.3 Signing invariant (the one rule an operator must never break)

> For each lockbox outpoint, sign a promise for **at most one** `tx_commitment`, ever.

Implement it as a durable write-ahead log: `INSERT (outpoint, commitment)` with fsync **before**
signing. On a repeat request with the same commitment, return the same promise. On a different
commitment, refuse permanently, even after expiry and even if the first transaction never
confirmed. Run one signer per key (HA needs a single-writer log; two hot replicas sharing a key
without consensus will eventually equivocate and be slashed). Key compromise has the same effect:
it can burn the bond but cannot move user funds.

### 5.4 Promise API (HTTPS, JSON; amounts are decimal strings)

`POST /v1/promise`
```
{ "tx": <hex, all non-promise witness data may be empty>,
  "spent": [<hex TxOut per input>],
  "lockboxes": [ { "index": i, "owner": <xonly>, "expiry": h,
                   "auth": {"mode": "all"|"paired", "sig": <hex64>} } ],
  "value_at_risk": "<native-asset atomic units>" }
```
The operator checks:
1. Either every input is a lockbox (§8 rule A1), or the transaction is *mixed*: it has some plain input, and
   **no** lockbox input uses PAIRED authorization. Every lockbox owner then signed ALL over this exact
   transaction, including the plain input, so it can only grief itself. Such receipts are marked
   `"instant": false`. A PAIRED (maker) lockbox is never promised in a mixed transaction. For its own inputs, it recompiles each lockbox from
   `(genesis, owner, OPERATOR, expiry)` and requires the script to match `spent[i]`.
2. `tip + S < expiry` for each of its own lockboxes, and its eligible bond cover is enough (§8 rule B).
3. Each lockbox outpoint is confirmed, or is an output of a transaction this operator (or another
   eligible operator, by policy) has already promised, with at most 3 unconfirmed ancestors.
4. Explicit-only, no issuance, peg-in or annex. Fee rate is at least `max(2 × estimatesmartfee(2), floor)`.
5. The WAL invariant (§5.3) holds for every one of its outpoints.
6. The fully assembled transaction (owner auth plus promise) passes `testmempoolaccept`. JK's
   `check_authorized_transaction` pattern applies here.

Then it signs, assembles the witnesses, broadcasts, publishes receipts to relays, and returns
`{ "txid", "promises": [{index, lockbox, commitment, sig}], "receipt": {seq, in_flight, bonds} }`.
The receipt is signed by the operator key under its own tag (`"ECX/Instant/Receipt/v1"`, off-chain only). Target latency is well under 1 s. The response, not the broadcast, is the "Done" trigger (§8).

`GET /v1/status` returns the signed tip, bonds, published in-flight exposure and constants.
`GET /v1/promises?since=seq` returns the operator's own append-only promise log for watchtowers.

### 5.5 Exposure rule (operator side)

`in_flight` = the sum of `value_at_risk` over promised transactions that are not yet confirmed at
depth ≥ 1. Refuse if `in_flight + value_at_risk > Σ eligible bonds × 7/8`. The cover is 7/8, not 1,
because a self-reporting operator recovers 1/8 (§11). One bond cannot cap hidden promises; §8 and §14
cover what wallets do about that.

## 6. Lockbox lifecycle

**Derivation and recovery.** Owner key = wallet HD key at a dedicated, non-address path (to be fixed by the wallet spec, e.g. a separate account branch).
`EXPIRY` is always on the grid `k × 36`, so a seed restore can rediscover lockboxes by scanning
`(key i, operator ∈ known announcements, expiry ∈ grid around the restore height)`. The wallet also
keeps a journal of `(owner index, operator, expiry, outpoint)` in its encrypted backup. **Losing the
parameters means losing the ability to spend** (the Simplicity program cannot be rebuilt without them), so this is mandatory.

1. **Fund.** An ordinary explicit payment to the lockbox address. It becomes usable for instant spends
   after 1 confirmation, or immediately if it is itself an output of a promised transaction.
2. **Cooperative spend.** The owner signs ALL (or PAIRED for a maker order), the operator promises,
   the transaction is broadcast and confirms next block. Outputs the owner keeps (change, received assets) go to new lockboxes with a fresh `EXPIRY = grid(tip + L)`, so an active wallet never needs separate renewals.
3. **Renewal.** While the wallet is online and a lockbox has `EXPIRY − tip < RENEW_BELOW`, it spends
   all such lockboxes in one self-transfer to a fresh lockbox (promised, so the funds stay instantly usable).
   Live maker orders on renewed lockboxes are re-signed and republished; the old orders die automatically
   because their outpoint is promised to the renewal.
4. **Exit.** If the operator is down, refusing, or out of eligible bond: once `tip ≥ EXPIRY` the wallet
   signs an exit with `nLockTime = EXPIRY` and a non-final sequence. It pays to a new lockbox under a
   **different** healthy operator. One confirmation later, the funds are instant again.
5. **Failover policy.** Health = `/v1/status` responds, the signed tip is within 2 blocks, and there is eligible cover. After
   2 failed promise requests or 3 failed status polls, the wallet marks the operator unhealthy. It routes new
   lockboxes (change, received funds, renewals) to the best healthy operator, then exits old ones at EXPIRY.
   Optionally the wallet keeps balances split across two operators, so one failure only delays part of
   the balance.

**Why not a backup-operator spending path?** A second operator B can only safely take over once
A's promises can no longer be pending, which means after a height cut-off. That is the same bound as
a shorter EXPIRY, at the cost of a bigger script and a two-operator trust surface. Shorter lifetimes
plus automatic renewal do the same job more simply.

## 7. Watchtower

Inputs: receipts from relays and its own clients, operator promise logs, and chain data from Esplora.

1. **Two published receipts** for the same lockbox with different commitments: that is evidence directly.
2. **Receipt plus chain.** For a held receipt `(lockbox, c1, s1)`, watch `GET /api/tx/:txid/outspend/:vout`.
   When the spender's commitment `c2 ≠ c1`, fetch the spender and its prevouts, compute `c2`
   (`hash::tx_commitment`), and recover `s2` from the witness with
   `watchtower::find_signature`. This scans every 512-bit window of the witness bit string for a valid
   operator signature over `promise_digest(lockbox, c2)`. It is layout-independent and cannot produce a
   false positive, because it is a signature check. If the spend was an exit (no promise), there is no
   evidence: that is the S-margin risk in §13, not equivocation.
3. Build the penalty for **every** unspent bond UTXO of the key (each is separately slashable):
   `[reporter: ⌊b/8⌋ − fee, OP_RETURN: b − ⌊b/8⌋, fee]`. Broadcast it with `maxburnamount` set and send it
   to as many miners and peers as possible (§14 on front-running).

A victim is a natural watchtower: it holds `P1` and sees `P2` on chain the moment the conflicting
transaction confirms. The live run D (§15) does exactly this.

## 8. What a wallet checks before showing "Done"

Shared implementation: `src/policy.rs::check_promise`. A wallet shows **Done** only when all of these hold
(otherwise it shows "Submitted — confirms in ~10 min"):

- **A1** Every input of the transaction is a lockbox (of any operator). One plain input can be double-spent
  without any promise. In that case there is no instant guarantee for *anyone* in the transaction.
- **A2** Each lockbox input has a valid promise from its own operator for exactly this transaction (local BIP340 verification),
  and a valid owner authorization (local Simplicity execution, or the operator's `testmempoolaccept`).
- **A3** Each lockbox outpoint is confirmed, or is the output of a transaction that itself passed A–C, with chain depth ≤ 3.
- **A4** Explicit-only, fee rate at least policy, and the transaction is in the wallet's own Esplora mempool (or accepted on broadcast).
- **B1** `tip + S < EXPIRY` for every lockbox input.
- **B2** The operator has at least one bond that is confirmed (≥ 2 confirmations), unspent, has the correct script (§5.2), and has
  `refund_height ≥ max(EXPIRY of its inputs) + W`. Only bonds like that count as "eligible".
- **B3** `published_in_flight + value_at_risk ≤ 7/8 × Σ eligible bonds`. `published_in_flight` is the sum of
  unconfirmed receipts for that operator visible on ≥ 2 independent relays, not the operator's self-report.
  `value_at_risk` is the wallet's *own* valuation of what it is about to rely on, in the native asset at the DEX mid price.
- **C1** The wallet has published its receipt to ≥ 2 relays and one relay other than the one it submitted to echoes it.

Why B3 counts *published* receipts: an operator can hide promises it gives to accomplices, but those are not
victims. Honest parties who rely on a promise publish it (C1), so the victim-side exposure is observable.
Concurrency and relay eclipse still leave residual risk (§14).

## 9. DEX flows

### 9.1 Lockbox order (offer v2, extends `docs/V2-SPEC.md` §2)

```json
{ "version": 2, "kind": "instant-lockbox", "network": "<profile id>", "genesis_hash": "<hex>",
  "lockbox": { "outpoint": "<txid>:<vout>", "owner": "<xonly>", "operator": "<xonly>", "expiry": 123456 },
  "paired_output": "<hex TxOut: explicit want asset/amount/script>",
  "paired_sig": "<hex64 BIP340 over paired_digest>",
  "give": {"asset_id": "...", "amount": "..."}, "want": {"asset_id": "...", "amount": "..."} }
```
Consumers re-derive everything: the lockbox script from its params equals the prevout script (via Esplora); the give leg
equals the prevout's explicit asset and amount; the want leg equals `paired_output`; `paired_sig` verifies; the operator is
announced and healthy; and `tip + S < expiry`. As today, it is whole-UTXO only. The maker's wanted output may itself
be a lockbox script, so the maker's proceeds stay instant-usable.

### 9.2 Instant take (taker in a lockbox, maker in a lockbox)
1. The taker selects orders and builds T: maker inputs at indices 0..k−1 paired with outputs 0..k−1, then the taker's lockbox
   inputs, then taker outputs (received asset and change into fresh taker lockboxes) and the fee.
2. The taker signs ALL for its own inputs.
3. **Ordering rule.** Request promises from the operator(s) of the *taker's own* lockboxes first and from makers' operators
   last. If a maker's operator then refuses, only the taker's own lockboxes are stuck, and only until their expiry. Wallets
   prefer orders whose operator equals their own, so most takes need a single request.
4. Run the §8 checks and show **Done**. The operator broadcasts and the next block confirms.

Live run B (§15) is this flow: a token maker with a PAIRED order, an ECX taker, both promised, mined.

### 9.3 Cancel race
A maker cancels by asking its operator to promise a self-spend. The operator serializes: whichever of
take or cancel reaches its WAL first gets the promise, and the other is refused. The cancel is instant too.
An offline maker cannot cancel, but nobody else can spend its lockbox outside a valid take of its order. If the
operator is down, neither takes nor cancels happen until EXPIRY, and then the maker's wallet exits.

### 9.4 Mixed cases (no instant guarantee)
- **Taker without lockbox funds, maker in a lockbox.** The operator refuses (PAIRED lockbox in a mixed transaction, §5.4
  step 1), because a taker who double-spends its plain input would leave the maker's lockbox stuck until EXPIRY (a cheap
  griefing attack on offline makers). The wallet first moves funds into a
  lockbox (1 block) or takes plain (v1) orders on the normal slow path.
- **Plain maker order (v1 P2WPKH) with a lockbox taker.** This is allowed as a normal (mixed) transaction. The taker's
  lockbox needs a promise, which the operator gives (§5.4 step 1) because only ALL-authorized lockboxes are involved, and
  the only party a later plain double-spend could harm is the requester itself. The UI shows "confirms in ~10 min", not "Done".
- **Cross-operator transactions.** These are allowed. Each operator promises only its own lockboxes and checks only its own cover.

### 9.5 Chained trades
Received assets land in a fresh lockbox output of T1, which can be spent at once in T2 (A3 allows up to 3
unconfirmed ancestors). If T1 were undone by equivocation, T2 is also invalid. In a pure DEX chain
**nobody loses principal**, because every trade is atomic and each party keeps its original coins. What can be lost is
reliance outside the DEX (withdrawals, payments, bridges) and price or opportunity. That is what the bond covers (§14).

## 10. What the wallet automates (the user never sees sessions)

On first use: pick a healthy operator (§5.2, §6.5) and move spendable balance into lockboxes
(1 block, shown once as "Enabling instant swaps"). In the background, every block:
refresh bond eligibility, operator health and relay exposure; renew lockboxes below `RENEW_BELOW`;
exit expired lockboxes of unhealthy operators into healthy ones; re-sign and republish maker orders after renewals;
run the watchtower check (§7) for its own receipts; and journal lockbox parameters into the backup.
On Swap: build the transaction, run §8, and show **Done** or **Submitted**. The user sees one button and one result.

## 11. Reporter reward split: ⌊bond/8⌋ to the reporter, the rest burned

- **Self-report griefing.** An operator that equivocates and reports itself recovers at most 1/8 and still
  loses ≥ 7/8. Because miners can front-run the reward (§14), it may recover nothing. The required
  "< 50%, operator loses ≥ the rest" holds with a wide margin.
- **Exposure accounting stays honest.** The guaranteed loss per bond is 7/8 B, so every cover
  computation uses 7/8 (§5.5, §8 B3). A larger share would shrink the usable cover proportionally: at 1/4 only 75% of
  each bond counts.
- **The incentive is still large.** Watchtower costs are monitoring plus one transaction fee. At the policy minimum
  bond (0.01) the reward is 0.00125. On a realistic operator bond (≥ 100 ECX) it is ≥ 12.5 ECX.
- **Exact and cheap in Simplicity.** A `right_shift_64(3)` with no division edge cases, so floor rounding is consensus-exact.
- **The burn goes to `OP_RETURN`, not fees**, so a colluding block producer cannot recover the 7/8 (§4.2).

## 12. Timeouts and why

| Parameter | Value | Reasoning |
| --- | --- | --- |
| Lockbox EXPIRY (absolute) | balances: tip + 72 (~12 h); maker orders: user-chosen, default 1008 (7 d) | The worst-case delay if the operator dies equals the remaining lifetime. 12 h is short, and renewal while online costs one small batched transaction about every 6 h (with any trade, renewal is free). Offline makers accept a longer worst case in exchange for long-lived orders. Relative locks are unavailable (§4.4). |
| Promise margin S | 6 blocks (~1 h) | A promised transaction must confirm before the owner's exit path opens. The operator broadcasts immediately, so normally it confirms in 1 block. S covers fee spikes and short censorship. |
| Challenge window W | 144 blocks (~1 day) | Every conflicting spend is visible by EXPIRY at the latest: a promise is issued only before EXPIRY − S, and any coin spend reveals the promise. W gives watchtowers a day to get a penalty mined before the bond can be refunded (bond refund height ≥ EXPIRY + W). |
| Bond refund | ≥ 30 days ahead, rolled | So that wallets can create lockboxes up to EXPIRY ≤ refund − W. |

## 13. Threat model

| Threat | Outcome | Defence / residual |
| --- | --- | --- |
| Operator equivocation (two promises, same lockbox) | At most one transaction confirms. The other holder sees the on-chain promise at once. | Penalty: 1/8 to the reporter, 7/8 burned (any bond UTXO of the key). Tested live (run D). Residual: the bond does not compensate victims; exposure is capped only by policy (B3). |
| Operator offline or refusing | Promises are unavailable and lockboxes are frozen until EXPIRY. | Owner-only exit at EXPIRY into another operator, automated (§6). Delay ≤ L (≤ 12 h by default). Tested live (run C). |
| Operator steals | Impossible: every path verifies the OWNER signature. | Tested ("operator alone cannot spend"). |
| User double-spends its own lockbox | Without a promise there is no spend before EXPIRY. A second promise is refused (WAL). | Residual: after EXPIRY the exit path. Promises stop at EXPIRY − S. |
| Taker griefs an offline maker with a plain input | The maker's lockbox would be stuck. | The operator never promises a PAIRED (maker) lockbox in a mixed transaction (§5.4 step 1, §9.4). |
| Operator B refuses after operator A signed (cross-operator) | A's lockbox is stuck until EXPIRY. | Ordering rule (§9.2): only the requester's own lockboxes are exposed. Bounded by EXPIRY. |
| Maker cancel race | Serialized by the operator WAL. The loser gets a refusal, not a fake "Done". | §9.3. |
| Relay withholding or eclipse | The wallet under-counts in-flight exposure. | ≥ 2 relays plus an echo (C1). Evidence itself needs no relay (the chain carries P2). Residual: concurrent over-commitment. |
| Reorg | A confirmed promised transaction can return to the mempool. A conflicting spend still needs a second promise (slashable) or EXPIRY. | Shallow reorgs near EXPIRY combined with an owner exit are the residual. S gives ≥ 5 blocks of headroom normally. BMM reorg behaviour needs JK's input (§16). |
| Fee spike or censorship > S blocks | The promised transaction is not mined before EXPIRY, and the owner can exit, invalidating it. **Not slashable.** | Fee floor at promise time, operator rebroadcast, recipients CPFP through their lockbox output. Residual: documented. |
| Bond expiry / refund race | An operator refunds right after equivocating. | B2 requires refund ≥ EXPIRY + W. The penalty is valid after REFUND_HEIGHT while unspent, but then races the refund. |
| Reward front-running | A miner or watcher copies the evidence and changes the reporter output. | The operator is slashed regardless. Commit-reveal is not expressible with the pinned jets without relative locks (§14). |
| Self-slash griefing | The operator recovers ≤ 1/8. | §11. |
| Operator key compromise | The attacker can burn the bond and refuse service. It cannot move funds. | Rotate the key; wallets exit at EXPIRY. |
| Lost lockbox parameters | Funds cannot be spent. | Deterministic grid plus a backup journal (§6). |
| Promise replay across chains or lockboxes | Rejected (genesis and outpoint are in the digest). | Tested. |

## 14. What Instant does NOT guarantee

- **No compensation.** Slashing punishes; it does not refund anyone. Victims get the 1/8 share only if they win the race to report.
- **No hard exposure cap.** One bond cannot stop an operator from signing more promises than it covers.
  The cap in §8 B3 is policy, built on published receipts, and can be beaten by concurrency, relay eclipse or
  undervalued tokens. An operator willing to lose its bond can cheat up to the reliance others place on it.
- **No guarantee against slow confirmation.** If a promised transaction is not mined within S blocks (fee spike,
  censorship by BMM block producers), the owner's exit after EXPIRY can invalidate it, and **nobody is slashed**.
- **No confidentiality.** Explicit amounts only. Promises and evidence are public.
- **No liveness.** If every healthy operator is down, there are no instant swaps. Funds return only after EXPIRY.
- **No reporter-reward exclusivity.** Front-running of the 1/8 share is possible. A commit-reveal fix would need the
  bond to verify that a commitment output existed ≥ k blocks earlier. With no working relative lock jets and no
  chain-state access, that is not expressible today.
- **No protection for mixed transactions** (any plain input) and none for reliance on transactions deeper than A3 allows.
- **No safety if the wallet loses lockbox parameters** or the owner key.
- **Not audited.** The prototype uses public test keys.

## 15. Prototype and results

Layout (`instant/`): `contracts/lockbox.simf`, `contracts/pooled_bond.simf`;
`src/{lib,hash,lockbox,bond,watchtower,policy,announce}.rs`; `tests/contracts.rs` (real program execution);
`tests/fork_vm.c` + `scripts/check-fork.mjs` (pinned node C interpreter, adapted from JK's harness to take an input index);
`examples/vectors.rs` (interpreter fixtures); `examples/live_regtest.rs` (funded run). Rust 1.89, `simplicityhl =0.7.2`.

```sh
cd instant
cargo test                                    # 6 unit + 19 covenant tests, all pass
cargo clippy --all-targets -- -D warnings     # clean
cargo fmt --check                             # clean
node scripts/check-fork.mjs ../../.local/elementsplus-node   # 19/19
cargo run --example live_regtest              # local regtest only; refuses other chains
```

Interpreter negatives are built so that **only** the property under test is wrong. Signatures inside the
witness are re-signed bit-for-bit for the mutated transaction, so, for example, "premature exit" carries a
valid owner signature and fails only on the height lock. Fixture CMRs (test params): lockbox
`2760614db58ac7504f4f95601a9ac3c0ae249bf42e4495595a1fdc32442588aa`, bond
`7edb0945e4b718d58fb9642a8f633c07915ac65e3464b1e8d40ed94b5dea747f`.

Live run (local `elementsregtest`, genesis `cd179c84…396f`, Simplicity active, 2026-10-04, all mined):

| Scenario | Txid | Node-level negatives (testmempoolaccept) |
| --- | --- | --- |
| A lockbox funding | `8066a6fa0b6391c8d68c202605d52715cc9f2d052bb685baf9a2486f0906fd70` | |
| A cooperative spend (ALL + promise) | `18316118fcab64e1e9b30f927c38a03ff3ef9cd34dfbbaf0a5f8aaf952b044c0` | promise for another tx and zero promise: both rejected, "Assertion failed inside jet" |
| B maker lockbox funding (token) | `eda60dbc7fa564690deeb7ddaef6eae363e0822b42809713599fb8bdfe728ee7` | |
| B taker lockbox funding (ECX) | `9de1746e7c0f0da823609171211902e12e7417834d51bb80d1806d92ba54c14d` | |
| B instant swap (maker PAIRED + taker ALL, both promised) | `e6f5cd56c3b2411d8b9c85f7487ff7e1812383c6d5cd0665e80a5400cd92ee34` | taker shortchanges maker (operator re-promised): rejected |
| C lockbox funding (EXPIRY 328) | `a154f13bc968849590543e18ce57249106197bf4b3b919050022c9c8825e4dc2` | |
| C timeout exit | `9920577ded5ff7a0d9e09154db439960da9db01f36204590c95ec0600b86bc27` | at tip 325: `non-final`; lock time EXPIRY−1: script rejection |
| D pooled bond funding (0.08) | `f8718f991c66819324069eefd2852ded7403343a9d5ac339d8988a206a5d82e4` | |
| D lockbox funding | `a78fa0f941441187970077af4ddd5f32db9ac11c964eb0087809016b50afeafe` | |
| D conflicting promised spend | `52c8a86f96ba6359649b602b36b3a2785379e396cc75e3f35335886067746dd9` | victim's promised transaction afterwards: `missing-inputs` |
| D slash: evidence from the chain witness plus the held promise; reporter 0.00998, OP_RETURN 0.07, fee 0.00002 | `6be915cb9b41b3f26256b8d7970f1ec7d5e12d5404d4cd8a887d59e9a562895a` | reporter 50%: rejected; burn as fee instead of OP_RETURN: rejected |
| E bond funding (REFUND_HEIGHT 337) | `3624c51eebecddb8272384b60ee738d15313f7f311396f976d01ee13d53f507c` | |
| E bond refund | `4d1becdf46a853687223eae273e9c762d35e5da80669cdad922958cab8c18e39` | at tip 334: `non-final` |

Mempool rejections are reported as `non-mandatory-script-verify-flag (...)`, the mempool's policy-flag
wording. The script itself fails, so blocks would reject it too, but block-level negative tests were not run.

Not built yet: the operator service, relay v2 receipts, wallet integration, the offer v2 parser in the DEX server, and
browser/WASM bindings. The prototype has a host verifier (`policy`, `announce`, `watchtower`) and the covenants.

## 16. Open questions for JK

1. **BMM reorg profile.** What reorg depth should wallets assume on Elements+ with BIP301 blind merged mining?
   This sets S (and whether S = 6 is enough) and the A3 chain-depth limit.
2. **Relative locks.** Is there a plan to ship a fixed `check_lock_distance` in Elements+ Simplicity? It would allow
   commit-reveal for reporter rewards and lockbox lifetimes counted from confirmation.
3. **Burn vs fees.** Do you agree with burning 7/8 to `OP_RETURN` instead of paying miners (the BMM producer-recapture argument in §4.2)?
   Should the node's default `maxburnamount` stay a client-side guard only?
4. **Fee asset authentication.** On ECX beta and mainnet, is the policy asset the bond asset, and how should wallets
   authenticate it (your PROTOCOL.md integration gate 1)?
5. **Relay reuse.** Can your relay generalise from a fixed-session profile to a dynamic, announcement-verified
   operator set with per-lockbox-outpoint conflict retention (the "first two distinct commitments" rule maps 1:1)?
6. **Standardness.** Are Simplicity spends of these sizes (≤ 936 B program, ≤ 1.3 kWU budget) and value-carrying
   OP_RETURN outputs standard on the beta network, as they are on regtest?
7. **Native enforcement.** Would you consider a future node-level "lockbox outpoint promise" index, so that relays/nodes
   reject a second promised spend at P2P level? It is not required for soundness; it would cut the equivocation window.
