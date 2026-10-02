# Peg research: moving ECX between the eCash L1 and the Elements+ sidechain (slot 24)

Research date: 2026-10-02. This document is read-only research. Nothing was run against the betanet enforcer.

## Sources

| Short name | Source |
|---|---|
| **node** | `.local/elementsplus-node` at master `006d2a30` (JK's Elements+ node) |
| **enforcer** | `LayerTwo-Labs/bip300301_enforcer` @ `1753fc0` (2026-09-30) |
| **spec** | `LayerTwo-Labs/bip300_bip301_specifications` @ `26c8a11` |
| **frontends** | `LayerTwo-Labs/drivechain-frontends` @ `c2903a6` (2026-09-30) |
| **fastwd** | `LayerTwo-Labs/fast-withdraw-server-go` @ `53ae9a0` |
| **electrs** | `ekulkisnek/electrs-blockstream`, branch `codex/alpha-explorer-20260911` @ `93bc4d4`. It contains `agent/drivechain-peg-lifecycle-indexing` @ `cd73e97`. The default `new-index` branch is stock Blockstream. |
| **esplora-ui** | `ekulkisnek/esplora-liquid-drivechain`, `master` @ `3ec9d7e` plus `codex/alpha-explorer-20260911` @ `af39a73` |
| **L1 Esplora** | `https://esplora.beta.ecash.ninja`, queried live and read-only (tip 970848 at the time of writing) |

The LayerTwo and JK clones are under `/tmp/claude-1000/-home-joshua-Github/02db4458-b01f-5a68-9bcd-4bc6ee3ce6d7/scratchpad/research/`.

---

## 0. Summary

1. **This is a native BIP300 peg, not a Liquid federated peg.**
   - `getpeginaddress` and `claimpegin` are disabled when the node runs with a drivechain slot. They fail with "Legacy federated peg-ins are disabled on a Drivechain network; use importdrivechaindeposit" (`node src/wallet/rpc/elements.cpp:679-681`, `node src/pegins.cpp:550-557`).
   - `drivechain-frontends/liquid-signet-integration.md:93-109`, which tells you to use `getpeginaddress`/`claimpegin`, is out of date and does not apply.
2. **Deposit = an L1 M5 transaction.** It does two things:
   - It spends slot 24's current treasury UTXO (the CTIP) and creates a new treasury output `OP_DRIVECHAIN 0x01 0x18 OP_TRUE` whose value is the old value plus the deposit.
   - The output **immediately after** the treasury output is `OP_RETURN <UTF-8 Elements address>`.
   - After 1 L1 confirmation (100 historically; see §1.5), anyone can submit a **signature-free, fee-free** sidechain "claim" transaction. It mints exactly that value of the explicit pegged asset (ECX policy asset) to the committed address. The user ends up with an ordinary UTXO.
3. **Withdraw = an irreversible sidechain burn followed by a BIP300 M6.**
   - The burn is an `OP_RETURN <parent genesis> <L1 scriptPubKey> <8-byte BE L1 fee>` output of the pegged asset.
   - After 6 sidechain confirmations, an operator turns the burn into a one-payout M6 with `submitdrivechainwithdrawal`.
   - L1 miners must then upvote that M6 **more than 13,150 times within 26,300 blocks** (betanet uses mainnet withdrawal constants), and every upvote for one bundle downvotes the others in the same slot. In practice that means at least ~91 days per withdrawal, one at a time per slot.
   - No fast-withdraw exists for Elements.
4. **A browser wallet can build and sign the L1 deposit itself** from the same BIP39 seed. The L1 is Bitcoin-format, uses BIP84 `bc1q` addresses, and the opcode byte on betanet is `0xb7`. The L1 Esplora has every endpoint it needs, including CTIP discovery through `/scripthash`.
   - The wallet can also build the sidechain claim transaction and the withdrawal burn itself.
   - It **cannot** submit the M6. That needs an operator with mutual-TLS access to an enforcer that produces L1 blocks.
5. **Blocker: JK's public node is not betanet-ready.** Master is frozen to the retired alpha parent:
   - parent checkpoint height 995347, which is above the betanet tip
   - treasury opcode `OP_NOP5`, but betanet uses `OP_NOP8`
   - alphanet vote thresholds of 72/144
   - The betanet slot-24 proposal still matches master's proposal description, including hashId2 `28406cdece9df4823d01a88eca6b5793560fea88`, which is embedded in `PROPOSAL_DESCRIPTION_HEX`. A betanet build from JK is therefore expected but not published.
   - No slot-24 treasury exists on betanet yet. `/scripthash/<sha256(b7011851)>/utxo` returned `[]`.

---

## 1. Deposit (L1 → sidechain)

### 1.1 Exact L1 transaction format (M5)

Consensus is defined by the enforcer and mirrored by JK's parent replay.

| Item | Requirement | Citation |
|---|---|---|
| Treasury script | `OP_DRIVECHAIN OP_PUSHBYTES_1 <slot> OP_TRUE`. **Betanet:** `b7 01 18 51` (`OP_NOP8`). Alphanet and plain BIP300: `b4 01 18 51` (`OP_NOP5`). | enforcer `lib/types.rs:919-947` (`OpDrivechain`), `lib/types.rs:155-168` (betanet preset `op_drivechain: NOP8`); frontends `sidechain-orchestrator/m8.go:3-14` (`opDrivechain = 0xb7`). JK's node hardcodes `OP_NOP5`: `node src/mainchainrpc.cpp:818-823`. |
| Inputs | If the slot already has a CTIP, the transaction **must** spend it. The CTIP is anyone-can-spend: empty scriptSig, no witness (enforcer sets `final_script_sig = ""`). The user's own inputs fund the rest. For the first deposit (no CTIP), no treasury input is needed. | enforcer `lib/wallet/mod.rs:1117-1143`, `lib/validator/task/mod.rs:798-814` (`OldCtipUnspent`); node `src/mainchainrpc.cpp:1745-1760` (rejects a "parallel treasury output") |
| Treasury output | Exactly one output with the slot-24 treasury script. Value = old CTIP value + deposit (delta > 0). One M5 transaction can deposit to several slots but cannot also be an M6. | enforcer `lib/validator/task/mod.rs:741-772, 857-880`, `lib/messages.rs:877-890` (`create_m5_deposit_output`); node `src/mainchainrpc.cpp:1737-1779` |
| Address output | **At index treasury_vout + 1.** `scriptPubKey = OP_RETURN <single push of address bytes>`, value 0. Nothing may follow the push. | enforcer `lib/validator/task/mod.rs:861-874`, `lib/messages.rs:848-860`; node `src/mainchainrpc.cpp:1823-1830` |
| Other outputs | Change outputs can go anywhere else. LayerTwo puts the treasury and OP_RETURN first (`deposit_txordering`). | enforcer `lib/wallet/mod.rs:1007-1108` |
| Deposit identity | The deposit outpoint is the **new treasury outpoint** (`deposit_txid:treasury_vout`), not a user output. | node `src/mainchainrpc.cpp:1841-1843` |

A real betanet M5 (slot 9, Thunder) was decoded from the L1 Esplora as a reference: `c7e5f3cbfee54b243bcba5f78cb00dbd78e028f49570b83614893ff2557341a1`.

```
version 1, fee 418 sat, weight 810
vin0  prev CTIP  spk b7010951 value 633270000   scriptSig ""  witness none
vin1  user P2WPKH (witness sig+pubkey)
vout0 b7010951                              value 865370000   (= 633270000 + 232100000 deposit)
vout1 6a1c <28 ASCII bytes "3Jqd8jQW…85b">  value 0           (sidechain address)
vout2 user P2WPKH change
```

### 1.2 Sidechain address encoding

- **Bytes:** The OP_RETURN payload is the raw UTF-8 address string. It has **no** `s24_…_checksum` wrapper.
  - That wrapper only exists for user input. BitWindow strips it before building the M5 (`frontends bitwindow/server/drivechain/utils.go:18-60`, `bitwindow/server/api/wallet/wallet.go:605-631`). The wrapper is formatted by `sidechain_core/lib/bitcoin.dart:76-93`, and the field is defined in `enforcer proto/cusf/mainchain/v1/wallet.proto:85-99`.
  - JK's node requires 1..128 bytes (`node src/pegins.cpp:1049-1050`, `src/drivechain_parent_replay.cpp:130-137`). The enforcer path also requires printable ASCII 0x21–0x7e (`node src/drivechain_peg.cpp:455-468`).
- **Validity is enforced by consensus at claim time.** The claim must `DecodeDestination(address)` on `-chain=elements`, and the minted output's scriptPubKey must equal `GetScriptForDestination(dest)` (`node src/pegins.cpp:728-753`).
  - **A deposit whose OP_RETURN is not a valid Elements+ address can never be claimed.** Its value is permanently stuck in the treasury. The wallet must validate the address before signing.
- **Accepted forms** (`node src/elements_drivechain_identity.h:43-60`, `src/key_io.cpp` with the alias added in `eabc702dba`, `doc/lwk-address-compatibility.md`):

  | Form | Prefix |
  |---|---|
  | Canonical unconfidential segwit | `elements1…` (bech32/bech32m, HRP `elements`) |
  | Canonical confidential segwit | `elementsl1…` (blech32, HRP `elementsl`) |
  | Base58 | P2PKH prefix 68, P2SH prefix 13, confidential prefix 6 |
  | LWK aliases (input only) | `ert1…` / `el1…` |

- **Recommendation: always put the canonical unconfidential `elements1q…` / `elements1p…` string in the OP_RETURN.**
  - The minted output is **explicit** whatever the address says. A blinding key is ignored (the claim output is built with `GetScriptForDestination`, `node src/wallet/rpc/elements.cpp:2091`).
  - The LWK aliases were only added on 2026-09-12. Whether a deposit to `el1…`/`ert1…` can be claimed depends on the node version, and that is a permanent-loss risk.
  - LayerTwo's orchestrator also uses the unconfidential address (`frontends sidechain-orchestrator/sidechain/elements/node.go:108-125`).
  - Our wallet already handles both canonical and LWK-alias HRPs (`src/network/ecx-alpha.ts:77-212`). It must re-encode to the canonical HRP before writing the OP_RETURN.

### 1.3 Amounts and fees

- **Minimum:**
  - The enforcer only requires a positive delta.
  - JK's node requires `value_sats > 0` (`node src/wallet/rpc/elements.cpp:2049-2050`).
  - The elements network sets no `pegin_minimum` (`node src/kernel/chainparams.cpp:1116-1122`; the default `PeginMinimum()` has amount 0).
  - No protocol minimum exists, so pick a UI minimum (for example ≥ 10,000 sat). The OP_RETURN output is 0-value, so L1 dust rules only apply to change.
- **Fees:**
  - On L1 the user pays an ordinary miner fee (the example above paid 418 sat, about 2 sat/vB). Use L1 Esplora `/fee-estimates`.
  - There is **no** peg fee.
  - The sidechain claim can be **zero-fee**. The canonical 1-in/1-out claim is admitted to the mempool below the min relay fee (`node src/validation.cpp:2057-2060`) and placed ahead of feerate selection in block templates (`node src/node/miner.cpp:640-665`, `src/pegins.cpp:756-768` `IsCanonicalFeeFreeDrivechainDeposit`).
  - Optional wallet fee sponsorship never reduces the minted amount (`node src/wallet/rpc/elements.cpp:2105-2147`).

### 1.4 Replay protection and keys on the L1

- ECX is a Bitcoin-mainnet hard fork. L1 addresses use the mainnet `bc` HRP (`node src/elements_drivechain_identity.h:46-47, 59-60`), so BIP84 `m/84'/0'/0'` yields the **same keys and addresses as real Bitcoin**.
- LayerTwo's wallets stamp every ECX transaction with **nLockTime = 499999999 and every input's nSequence = 0xfffffffe** before signing. A patched ECX node accepts this as final; stock Bitcoin rejects it as non-final (`frontends sidechain-orchestrator/replay/replay.go:1-50`, `replay_locktime_integration_test.go:20-60`).
- A browser L1 signer **must** do the same. It should also consider a dedicated account rather than `m/84'/0'/0'`, so that coins on a seed shared with real BTC are not swept or deanonymised.
- Note: the enforcer's own wallet historically used `m/84'/1'/0'` even on mainnet (`frontends sidechain-orchestrator/wallet/service.go:1853-1870`). Pick a path deliberately and document it.

### 1.5 L1 confirmations before the sidechain credits

- **Consensus:** 1 confirmation. The required depth is `pegin_min_depth` = 100 from the frozen identity (`node src/elements_drivechain_identity.h:79`), but from sidechain height 64 the live chain uses a one-confirmation upgrade, `ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT{64}` (`node src/chainparams.h:31`, `src/chainparams.cpp:113-135`). The live value is exposed by `getsidechaininfo.pegin_confirmation_depth` (`node src/rpc/blockchain.cpp:4655-4664`).
- `doc/drivechain-peg-operations.md:32` still says 100. **That document is stale.** Confirm with JK which depth the betanet build uses.
- **Additional conditions** (`node src/mainchainrpc.cpp:1979-2034`):
  - The deposit's parent block must be in the node's authenticated parent replay.
  - It must be at or after the slot-24 proposal activation height.
  - The sidechain must then produce a block, which needs BMM on L1.
  - In practice the credit takes 1 L1 block, plus replay sync, plus the next BMM sidechain block.

### 1.6 How the sidechain mints the deposit

**Nothing is automatic.** No code path in the node creates claims on its own: `CreateDrivechainDepositPeginWitness` is only called from the wallet RPC. Someone must broadcast a claim transaction. There are two ways:

1. **`importdrivechaindeposit`**:

   ```
   importdrivechaindeposit <mainchain_txid> <treasury_vout> <mainchain_block_hash> <address> <value_sats> [fee_sats=0]
   ```

   - Any node with *some* wallet loaded can run it. The wallet does not need to own the address: "Permissionless relayers may sponsor…" (`node src/wallet/rpc/elements.cpp:1972-2190`; doc `doc/drivechain-peg-operations.md:24-46`).
2. **Build the claim yourself** (feasible in our wallet with rust-elements 0.25). The canonical fee-free form (`node src/wallet/rpc/elements.cpp:2087-2103`, witness layout `src/pegins.cpp:1041-1070`, consensus checks `src/pegins.cpp:495-545, 700-753`) is:
   - Elements transaction, version 2, locktime 0.
   - `vin[0]`: prevout = `(L1 deposit txid, treasury vout)`, `is_pegin = true`, empty scriptSig, sequence `0xffffffff`.
   - `vin[0]` pegin witness with **8 stack items**:
     1. value: CAmount int64 little-endian, 8 bytes
     2. pegged asset id, 32 bytes (internal order)
     3. parent genesis hash, 32 bytes (internal order): Bitcoin genesis `000000000019d6…8ce26f`
     4. claim script `0x51` (`OP_TRUE`)
     5. marker ASCII `"drivechain-deposit-v2"`
     6. mainchain txid, 32 bytes (internal order)
     7. mainchain block hash, 32 bytes (internal order)
     8. address bytes, exactly as in the OP_RETURN
   - Exactly one output paying the committed address's scriptPubKey with **explicit** pegged asset and **explicit** value equal to the deposit. No nonce commitment.
   - No fee output.
   - Broadcast it through the sidechain Esplora `POST /tx`. JK's alpha gateway only allows `POST /api/tx` (`esplora-ui codex/alpha-explorer-20260911 tools/serve.py:42-58`).

**Result:**
- The user gets a normal **explicit UTXO of the policy/pegged asset** at their address. In the alpha identity this is `62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4` (`node src/elements_drivechain_identity.h:317-318`). It may change if JK re-freezes the identity for betanet.
- The claim txid is deterministic, so re-submission is idempotent. Front-running is harmless because the output always goes to the committed address.
- Double claims are prevented by the standard pegin-claimed set.

### 1.7 Tools that can build the L1 deposit today

| Tool | Status |
|---|---|
| Enforcer wallet gRPC `WalletService.CreateDepositTransaction{sidechain_id, address, value_sats, fee_sats}` | Works. It finds the CTIP, builds, signs (BDK, its own wallet), and broadcasts over RPC with a P2P nonstandard fallback (`enforcer proto/cusf/mainchain/v1/wallet.proto:36, 85-103`, `lib/wallet/mod.rs:1227-1330`). `ListSidechainDepositTransactions` lists them (`wallet.proto:49-51, 140-146`; `lib/wallet/mod.rs:1477`). It needs the operator's enforcer wallet, so it is not usable from a browser. |
| BitWindow / drivechaind | Builds the M5 itself for Electrum and Core wallet backends (`frontends bitwindow/server/api/wallet/wallet.go:597-670`). It walks the CTIP chain through unconfirmed deposits with `/outspend`, up to 21 ancestors (`frontends sidechain-orchestrator/api/deposit_chain.go:42-117`). Users can paste `s24_<elements1…>_<checksum>`. **However, the launcher refuses to run Elements on betanet:** "elements alpha runs only on eCash Alphanet" (`frontends sidechain-orchestrator/sidechain/elements/node.go:51-54`). |
| Bitcoin Core RPC | Possible with `createrawtransaction` and `fundrawtransaction`, adding the CTIP as a foreign input with empty scriptSig. There is no dedicated RPC. |
| JK's node | Only *claims* deposits (`importdrivechaindeposit`). It has no M5 builder. |

### 1.8 Can the browser wallet do the L1 deposit itself? Yes.

**Signing.** Use rust-bitcoin 0.32, already pulled in by rust-elements 0.25 in `rust/wallet-core`, compiled to wasm, with BIP84 keys from the same seed.
- The user's inputs are P2WPKH (BIP143 sighash).
- The CTIP input is legacy and unsigned, so the wallet needs the CTIP **value**. That is only required if any input is legacy, but the value is needed anyway to compute the new treasury value.
- Apply the replay locktime and sequence before signing.

**L1 data from `https://esplora.beta.ecash.ninja`** (stock Esplora REST, no `/api` prefix; verified live):

| Need | Endpoint |
|---|---|
| Funding UTXOs and history | `GET /address/:addr/utxo`, `/address/:addr/txs` (BIP84 gap-limit scan) |
| Current CTIP | `GET /scripthash/<sha256(b7011851)>/utxo`, where the scripthash for slot 24 on betanet is `541891c183992f0303947a0574b05a30c7b3e60130552046957abc5c5386e656` (**not** byte-reversed). Today it returns `[]`, meaning no deposit yet. The same query for slot 9 (`b7010951`) returns its CTIP, so the method works. |
| Walk unconfirmed deposits | `GET /tx/:txid/outspend/:vout`, then `/tx/:txid` (LayerTwo algorithm, `deposit_chain.go:50-86`) |
| CTIP value | `GET /tx/:txid` (prevout value) |
| Fee rate | `GET /fee-estimates` |
| Broadcast | `POST /tx` |
| Confirmations | `GET /tx/:txid/status`, `/blocks/tip/height`; also needed to pass the L1 block hash to the claim |

**Caveats:**
- Esplora knows nothing about BIP300. Anyone can pay a junk output to `b7011851`, and the scripthash will list it. The wallet needs an authenticated CTIP: either the enforcer `ValidatorService.GetCtip` (`enforcer proto/cusf/mainchain/v1/validator.proto:101`) via some public read-only proxy, or a walk from a trusted starting CTIP.
- A deposit that spends a non-canonical "CTIP" is invalid under the CUSF rules and will not be credited.
- Two wallets depositing at once race for the same CTIP. The loser's transaction is a double-spend, so the wallet must rebuild and RBF. The orchestrator handles this with `DepositWatchEngine` (`frontends sidechain-orchestrator/engines/deposit_watch_engine.go`).
- Standardness: the enforcer warns that nodes without the drivechain patch reject `OP_DRIVECHAIN` outputs with `-26 scriptpubkey` (`enforcer lib/wallet/error.rs:19-31`). Betanet nodes evidently relay them: confirmed M5s exist, and LayerTwo broadcasts M5s through Electrum and Esplora sources. **Test `POST /tx` on esplora.beta with a tiny deposit before shipping.**

---

## 2. Withdraw (sidechain → L1)

### 2.1 Sidechain request: the burn transaction

**RPC:**

```
sendtomainchain "<bc1… or hex:<spk>>" <payout_amount> false true <mainchainfee>
```

Amounts are in coins; the arguments are subtractfeefromamount (must be false), verbose, and mainchainfee (`node src/wallet/rpc/elements.cpp:966-1210`, doc `doc/drivechain-peg-operations.md:48-66`). The verbose result gives `txid`, `withdrawal_vout`, `burn_amount`, `payout_amount`, `mainchain_fee`, `bitcoin_script_pub_key`, `status:"awaiting_confirmation"`, and a `next_step` hint.

**Exact burn output**, which our wallet can build with rust-elements (`node src/drivechain_withdrawal.cpp:117-143, 194-262`):
- Asset is the **explicit** pegged asset, value is **explicit** `burn = payout + mainchain_fee`, nonce is null, and the output witness is empty.
- `scriptPubKey` is exactly this, with minimal pushes:

  ```
  OP_RETURN
    <32 bytes: parent genesis, internal byte order = 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000>
    <L1 destination scriptPubKey, 1..128 bytes>
    <8 bytes: mainchain_fee in sats, big-endian>
  ```

**Rules:**
- Exactly one burn per Elements transaction (`node src/rpc/blockchain.cpp:4843-4848`).
- The destination type must be P2PK, P2PKH, P2SH, bare multisig, P2WPKH, P2WSH, or P2TR (`node src/wallet/rpc/elements.cpp:1054-1069`).
- The payout must clear L1 dust at 3,000 sat/kvB: about 294 sat for P2WPKH and 546 sat for P2PKH (`elements.cpp:1076-1093`).
- The burn must exceed the fee (`drivechain_withdrawal.cpp:58-77`).
- The whole OP_RETURN must fit standard datacarrier (83 bytes). P2WPKH, P2WSH, and P2TR destinations fit.
- The sidechain network fee is paid separately, as normal.
- **The burn is irreversible.** No refund path exists (`doc/drivechain-peg-operations.md:50-52, 91-96, 107-108`).
- Withdrawals are consensus-enabled on `-chain=elements` (`node src/kernel/chainparams.cpp:897`).

**Fees the user pays:**
1. The sidechain transaction fee.
2. `mainchain_fee`, which the M6 later pays to L1 miners. The user chooses it.

No peg fee exists.

### 2.2 From burn to L1 payout: lifecycle

1. **Wait for 6 sidechain confirmations.** Then anyone with node access runs `submitdrivechainwithdrawal <txid> <vout> <blockhash> 6` (`node src/rpc/blockchain.cpp:5040-5086`).
   - The node re-authenticates the burn and derives a **one-payout blinded M6** with three outputs: OP_RETURN fee, OP_RETURN 74-byte `"ELWD"‖v1‖elements_genesis‖slot‖burn_txid‖burn_vout` reference, and the payout (`node src/drivechain_withdrawal.cpp:8-24, 406-461`).
   - It submits through `cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle` over mutual TLS (`node src/init.cpp:570-610`). That RPC is **deprecated** in the enforcer and "will be removed"; it is an alias for `BlockProducerService.ProposeWithdrawalBundle` (`enforcer proto/cusf/mainchain/v1/wallet.proto:28-34`).
   - **The browser cannot do this step.** It needs an operator service.
   - `ProposeWithdrawalBundle` only stores the bundle in **that enforcer's block-producer database** (`enforcer block_producer.proto:200-205`). It is only proposed (M3) if that enforcer actually mines or produces L1 blocks.
2. **M3 proposal on L1, then M4 votes.**
   - Betanet `Thresholds::BETANET` = MAINNET for withdrawals: `withdrawal_bundle_max_age = 26_300`, `withdrawal_bundle_inclusion_threshold = 13_150` (`enforcer lib/types.rs:48-60, 155-168`; `spec bip300.md:13-17`).
   - The M6 is included in the first block where votes > 13,150 and age ≤ 26,300 (`spec bip300.md:296-341, 984, 1031`).
   - Each upvote for an M6ID **downvotes every other pending M6ID in the slot** (`spec bip300.md:321-334`), so bundles compete. Because Elements uses **one burn = one M6**, this is a serial queue.
   - **Minimum about 13,151 blocks (about 91 days) per withdrawal**, and only if every miner ACKs it.
   - Miner policy is configurable: NONE, KNOWN, ALL, or ALARM (`enforcer block_producer.proto:93-107, 192-198`).
3. **M6 lands.**
   - It spends the CTIP at vout 0 with exactly one input.
   - JK's local rule allows at most one slot-24 M6 per parent block (`node src/elements_drivechain_identity.h:72-78`, `src/mainchainrpc.cpp:1781-1822`).
4. **Mismatch to fix.** JK's frozen identity still carries the ALPHANET constants 144/72 (`node src/elements_drivechain_identity.h:120-125`, matching `enforcer lib/types.rs:76-88`). The replay's vote check (`mainchainrpc.cpp:1801-1806`) is looser than betanet's, so it is harmless in practice, but it must be re-frozen to match.

### 2.3 Status tracking

| Source | What it gives |
|---|---|
| Sidechain wallet | `gettransaction` for the burn's confirmations |
| `getdrivechainwithdrawalbundle txid vout blockhash [minconf=1]` | Read-only: `m6id`, `blinded_m6`, amounts, `paid_on_parent_chain`, `parent_payment_blockhash/blockheight` (`node src/rpc/blockchain.cpp:4955-5038`) |
| `getdrivechainpegevents [start] [count≤10000] [include_l1]` | Events `withdrawal`/`sidechain_confirmed`, `bundle_commitment`, and L1 `withdrawal_bundle` with status `submitted`/`succeeded`/`failed` and acknowledgement `pending`/`accepted`/`rejected` (`node src/rpc/blockchain.cpp:4451-4567`, `src/drivechain_peg.cpp:600-822`) |
| Indexer | `GET /drivechain/pegs?include_l1=true` (see §3) |
| Vote progress | Only from enforcer `ValidatorService.GetWithdrawalBundleProposals` (`validator.proto:117`). The node does not expose it, so a public read-only proxy is needed to show "X / 13,150 ACKs". |

### 2.4 Fast withdraw

- **Nothing exists for Elements.**
- `fast-withdraw-server-go` is a custodial service: the user pays L2 coins to a quoted address and the operator pays L1 BTC from Bitcoin Core with an Ed25519-signed quote (`fastwd README.md`). It supports only **Thunder and BitNames** through flags `-thunder-rpc` and `-bitnames-rpc` and their RPC shapes `get_new_address`, `get_transaction`, `get_block_hash` (`fastwd cmd/fastwithdraw/main.go:44-55`, `sidechain/sidechain.go:36-40, 129-292`).
- An Elements `Observer` adapter would be a small addition: `getnewaddress`, `gettransaction`, `getblockhash`, and explicit-asset checks.
- JK's node and git history contain no fast-withdraw hooks.
- Given the 3-month BIP300 latency, a fast-withdraw or swap service (custodial like fastwd, or HTLC atomic swaps between the L1 and Elements) is effectively **required** for a usable "Withdraw" button.

---

## 3. Indexer support

- **electrs (JK, `codex/alpha-explorer-20260911`)**:
  - `GET /drivechain/pegs?start_height=&count=&include_l1=` proxies the node's `getdrivechainpegevents`. Defaults: `start_height` 0, `count` 10000 (also the maximum), `include_l1` false. It returns **502** if the L1 lifecycle is unavailable (`src/rest.rs:1183-1186, 1410-1470`; constant at `src/rest.rs:58`).
  - Response shape (fixture `tests/fixtures/drivechain-pegs-v1.json`):

    ```json
    { "schema_version":1, "sidechain_id":24,
      "sidechain_tip":{"hash","height"}, "range":{"start_height","end_height"},
      "events":[ { "event_id","source":"sidechain|l1","kind":"deposit|withdrawal|bundle_commitment|withdrawal_bundle",
                   "status","sidechain_txid","vin|vout","mainchain_txid","mainchain_vout","m6id","value_sats",
                   "asset","claim_script","address_hex","sequence_number","acknowledgement",
                   "mainchain_transaction","mainchain_genesis_hash","mainchain_script",
                   "sidechain":{"block_hash","height"}, "l1":{"block_hash","height","timestamp"} } ] }
    ```

  - Transaction JSON: `vin[].is_pegin`, plus `vin[].drivechain_pegin {mainchain_txid, mainchain_vout, value, asset, genesis_hash, claim_script}` (`src/rest.rs:241-292`, `src/elements/peg.rs:42-66`), and `vout[].pegout {genesis_hash, scriptpubkey, scriptpubkey_asm, scriptpubkey_address}` (`src/elements/peg.rs:80-108`, `src/rest.rs:335-396`).
  - `/asset/:policy_asset` has `chain_stats`/`mempool_stats` `peg_in_*`/`peg_out_*` (`esplora-ui API.md:282-360`).
  - Pegin inputs skip prevout lookup, so a credited deposit shows up as a normal address UTXO (`src/util/transaction.rs:82`).
  - **Gaps:**
    1. `drivechain_pegin` only parses the legacy **6-item** witness (`vendor/elements/src/transaction.rs:454-458`). Native 8-item claims show `is_pegin:true` but no `drivechain_pegin`.
    2. The node's own `getdrivechainpegevents` sidechain-deposit extraction relies on `GetDrivechainDepositPeginData`, which only accepts the 6-item legacy and 11-item witnesses (`node src/pegins.cpp:773-777`). **Native 8-item deposits probably never appear as `sidechain:deposit` events.** Only the L1 `deposit` event (`include_l1`) would show. This is likely a bug; confirm with JK.
    3. Whether `pegout` parsing tolerates the third push (the 8-byte fee) depends on rust-elements `pegout_data()`. I believe it treats the extra push as extra data, but this is unverified.
- **esplora-ui (`esplora-liquid-drivechain`)**: The UI consumes `/drivechain/pegs` (`client/src/views/pegs.js`, `API.md:385-403`). The alpha flavor pins `NATIVE_ASSET_ID=62dce3…`, `BLIND_PREFIX=6`, `MAX_BLOCK_WEIGHT=6000000` (`flavors/alpha/config.env`). The public gateway allows only `POST /api/tx` plus GETs (`tools/serve.py`). `RUNNING_WITH_ELEMENTS.md` describes the older `elements-ea98f481` LayerTwo-signet release, so it is stale.
- **L1 Esplora (beta)**: Stock Esplora with no BIP300 endpoints. Use the scripthash/outspend method from §1.8.

---

## 4. Risks and unknowns needing JK's input

1. **A betanet node build.** Master is frozen to alpha:
   - checkpoint height 995347 (above the betanet tip of about 970,848)
   - `OP_NOP5` treasury parsing (`node src/mainchainrpc.cpp:818-823`, `:1264`), but betanet uses `OP_NOP8`
   - ALPHANET thresholds
   - enforcer pin `86543d13` (`identity.h:70-71`)

   Changing identity values "requires a new genesis" (`identity.h:17-25`). **Will the betanet and mainnet genesis, pegged asset id, and address prefixes change?** The wallet pins alpha values. Where is the betanet sidechain explorer/Esplora, and who runs BMM? At the last check there were no slot-24 BMM commitments.
2. **Mainnet (~2026-10-31).** Is it a new fork with a new slot-24 proposal and activation? A fresh slot needs >1815 ACKs within 2016 blocks on mainnet (1008 on betanet), per `enforcer lib/types.rs:48-60`.
3. **Confirmation depth.** Is 1 L1 confirmation (code) or 100 (doc) the intended betanet value?
4. **Deposit claiming.** Who runs the claim relayer, or is it acceptable for the wallet to self-build and broadcast the fee-free 8-item claim? Will the betanet sidechain Esplora accept `POST /tx` for it?
5. **Deposit address policy.** Confirm that canonical `elements1…` is the right OP_RETURN payload, and that `el1`/`ert1`/confidential forms are consensus-accepted on every node version going forward. A rejected address means permanently locked L1 funds.
6. **Authenticated CTIP source for browsers.** Can JK or LayerTwo expose a read-only `GetCtip`/`GetSidechains`/`GetWithdrawalBundleProposals` proxy, or should the wallet trust Esplora scripthash plus heuristics?
7. **Withdrawal submission operator.** Who calls `submitdrivechainwithdrawal`, against which block-producing enforcer? It still uses the deprecated `BroadcastWithdrawalBundle`.
8. **Withdrawal throughput.** One burn equals one M6, each at about 91 days minimum with mainnet thresholds and serial competition. Is batching planned, for example with the "withdrawal accumulator v1" / `USDD` codec in `identity.h:277-301`? Is a fast-withdraw or swap operator for Elements planned?
9. **Indexer gaps.** Native deposits are missing from `getdrivechainpegevents` sidechain events and from electrs `drivechain_pegin` (§3).
10. **Replay protection.** Confirm the magic-locktime rule (nLockTime 499999999) is consensus on betanet and mainnet ECX, and agree an L1 derivation path for the wallet.
11. **`drivechainl1blocksync`.** The docs say keep it at 0 (`doc/drivechain-rpc-security.md:15-16, 106-108`) but it defaults on. Which setting does the production replay need so that deposits are seen promptly?
12. **Confidential payments.** Master merged "confidential payments enabled" on 2026-09-16, but peg outputs (claim and burn) are explicit-only by consensus. The wallet's explicit-only model is fine for pegs.

---

## 5. Suggested wallet flows (once §4.1 is resolved)

**Deposit**
1. Derive the L1 BIP84 account and scan it through L1 Esplora.
2. The user enters an amount. The wallet takes its own canonical `elements1…` address.
3. Find the CTIP with `/scripthash/<sha256(b7011851)>/utxo` and the outspend walk, cross-checked against a trusted source.
4. Build the inputs: CTIP (empty scriptSig) plus the user's UTXOs. Build the outputs: `[b7011851 : ctip + amt]`, `[OP_RETURN <addr>]`, change.
5. Set nLockTime 499999999 and nSequence 0xfffffffe, sign P2WPKH, and `POST /tx`.
6. Wait for the L1 confirmations (`pegin_confirmation_depth`).
7. Build the 8-item fee-free claim and broadcast it to the sidechain Esplora, or rely on a relayer. Show the minted UTXO.
8. On a CTIP race, rebuild on the new tip.

**Withdraw**
1. Build and sign the burn transaction (§2.1) with the user's sidechain UTXOs, then broadcast it.
2. After 6 confirmations, call the operator's submit endpoint, which wraps `submitdrivechainwithdrawal`.
3. Poll `/drivechain/pegs?include_l1=true` and the vote-count proxy. Show "pending ACKs N/13,150, expires at L1 height H" and the final L1 payout txid.
4. Offer fast-withdraw or swap as the default path, with clear irreversibility warnings on the native path.
