# Network profiles

The wallet (extension and `epw`) never guesses a chain. Every extension
artifact is built for exactly one **network profile**, and its pins are
compiled in and never user-editable. `epw` selects a profile by id in
`config.toml`. The registry exists twice and the two copies must stay in step:

- `src/network/profiles.ts` (extension, build scripts, artifact checks)
- `rust/wallet-core/src/network.rs` (signing core, WASM, `epw`)

## Profiles

| id | display name | status | notes |
|---|---|---|---|
| `ecx-beta` | eCash Beta · Elements | `pending` | Slot 24 on eCash betanet (BIP300 active from parent height 967680; the sidechain activated at 970715). It already pins the v11 identity that the slot-24 proposal commits to. The **only missing pin is the sidechain Esplora URL**. |
| `ecx-mainnet` | eCash · Elements | `pending` | Mainnet is planned for ~2026-10-31. No pins are published. |
| `elementsplus-regtest` | Elements+ local regtest | `live` | A disposable local chain. Genesis, asset and explorer come from `.regtest/network.json` at build time, or from `epw config` / discovery. |
| `ecx-alpha` | ECX Alpha (archived) | `archived` | The retired chain. It is kept only so historical tests and vectors pass. Nothing can select it. |

Betanet slot 24 was activated (parent 970715) by the existing Elements v11
proposal, whose bytes equal Alpha's `PROPOSAL_DESCRIPTION_HEX`. On 2026-10-02 JK
merged a betanet test deployment (Elements+ master `feb99d8b`,
`doc/betanet-slot24-test.md`): a **new child identity** authenticated by that
existing proposal, using betanet replay-v5 / NOP8 rules. It is not the Alpha
chain:

- genesis `a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f`
- native (pegged) asset `5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8`
- P2P domain `ecash-elements-drivechain-betanet-slot24-p2p-v1` (magic `3b5ff18b`)
- data dir `elements-betanet-slot24-v1`
- parent checkpoint height 967679; address encoding unchanged (`elements` / `elementsl`)

Slot 24 has been BMM-mined since about parent height 970890; no deposits yet
as of 2026-10-03. The only missing pin is a public sidechain Esplora.

## Schema

| Field (TS / Rust) | Meaning |
|---|---|
| `id` | Stable id. It is also the `network` field of every swap offer (V2-SPEC §2) and the `epw` `network` value. |
| `displayName` / `display_name` | Shown to users: the manifest name, the network pill and the review "Network" row. |
| `status` | `live` (buildable), `pending` (refused) or `archived` (refused, historical only). |
| `kind` | `public` (pins from the registry) or `local-regtest` (pins from the local node). |
| `sidechainSlot` / `sidechain_slot` | BIP300 sidechain slot on the L1 (24). |
| `genesisHash` / `genesis_hash` | The sidechain genesis block hash. |
| `policyAssetId` / `policy_asset` | The pegged (policy / fee) asset id. |
| `address` | Native address params (bech32/blech32 HRP, p2pkh/p2sh/blinded prefixes) plus the LWK alias HRPs. |
| `esploraUrl` / `esplora_url` | The sidechain Esplora API base (`…/api`). |
| `l1.networkId`, `l1.genesisHash`, `l1.esploraUrl`, `l1.explorerUrl` | The eCash L1. Its genesis is the Elements parent-genesis parameter. Betanet: `https://esplora.beta.ecash.ninja` and `https://explorer.beta.ecash.ninja`. |
| `dexUrl` / `dex_url` | The DEX / asset-registry origin. It is optional, and users can set it in Settings or `epw config`. |

**Invariant:** a profile is `pending` if and only if at least one pin is
missing (`missingPins()` / `missing_pins()`). Unit tests in both languages
enforce this, so filling the last pin without flipping the status fails CI, and
so does the reverse.

## What refuses a pending profile

- `node scripts/build-wasm.mjs | build.mjs | check-artifact.mjs --profile ecx-beta`
  exits with code 3: `Refusing to build: network profile "ecx-beta" … is
  pending: esploraUrl not yet published …`.
- `npm run build` skips pending profiles and prints a `PENDING` line for each.
  It still builds and checks the regtest artifact, so CI stays green.
- In the WASM core, `new WasmWalletCore()` takes pins only from the profile
  compiled in via `ELEMENTSPLUS_NETWORK_PROFILE`, and it throws for a pending
  profile, a regtest build or a build with no profile.
- `WalletCore::for_profile` and `decode_offer_for_profile` return
  `WalletError::Network(Pending)`.
- `epw` (default `network = "ecx-beta"`) fails every chain command with the
  same message. An old `network = "ecx-alpha"` config still parses, but it is
  refused as archived.
- `ECX_LIVE_TEST=1 npm run test:live` exits with code 3.

## Filling in a pending profile once JK publishes the parameters

Do this in one commit that changes **both** registries.

1. **Sidechain genesis hash** (`genesisHash` / `genesis_hash`). Take it from
   the identity refreeze output (`elements_identity_refreeze.py`, the frozen
   genesis it prints) or from the generated `src/elements_drivechain_identity.h`.
   Cross-check it with `getblockhash 0` on a sidechain node and with the
   sidechain Esplora's `/block-height/0`.
2. **Pegged asset** (`policyAssetId` / `policy_asset`). Take it from the same
   identity output or header. Cross-check it with `getsidechaininfo` →
   `pegged_asset` on a node and with Esplora `/asset/<id>`.
3. **Slot and proposal** (`sidechainSlot`). Read the slot from the enforcer's
   slot data (betanet: slot 24). Confirm that the slot's proposal bytes equal
   `PROPOSAL_DESCRIPTION_HEX` in the identity header. If they differ, the
   identity differs, so stop and re-derive the genesis and asset from that
   header.
4. **Address params** (`address`). Take these from Elements+ chainparams for
   that chain: the bech32/blech32 HRP and the base58 prefixes. The v11 identity
   uses `elements` / `elementsl` and 68 / 13 / 6, with the LWK alias `ert` /
   `el`. For the Rust profile, point `native` at a matching
   `elements::AddressParams` (for v11 that is
   `elementsplus_lwk_adapter::NATIVE_ADDRESS_PARAMS`).
5. **L1** (`l1.*`). Set the L1 network id, its Esplora and explorer URLs, and
   the L1 genesis from L1 Esplora `/block-height/0`. This value becomes the
   Elements parent-genesis parameter.
6. **Sidechain Esplora** (`esploraUrl` / `esplora_url`). Use the public API base
   that JK publishes (`https://…/api`). Its origin becomes the extension's only
   host permission and its CSP `connect-src` entry.
7. Optionally set **DEX** (`dexUrl` / `dex_url`).
8. Flip `status` to `live` (`ProfileStatus::Live`) in both files.
9. Verify:

   ```sh
   npm run typecheck && npm test && npm run test:build
   (cd rust/wallet-core && cargo test --all-features && cargo clippy --all-targets -- -D warnings)
   (cd rust/wallet-cli && cargo test)
   ELEMENTSPLUS_NETWORK_PROFILE=ecx-beta npm run build:profile   # builds dist/ and runs check-artifact
   ECX_LIVE_TEST=1 ECX_LIVE_PROFILE=ecx-beta npm run test:live   # read-only, against the real Esplora
   ```

   `check-artifact.mjs` checks several things against the registry pins: the
   compiled `build-profile.js`, the WASM's `network_profile_id()`, the manifest
   name, the host permission and CSP, and an address derivation in the native
   HRP.
10. Deploy the DEX server with matching settings. It is configured separately,
    in the `elementsplus-dex` repo:
    `NETWORK_NAME=<profile id>`, `GENESIS_HASH`, `POLICY_ASSET`,
    `ADDRESS_HRP=<native bech32 HRP>`, `ESPLORA_URL`. The server's
    `NETWORK_NAME` defaults to `ecx-alpha`, and it rejects offers whose
    `network` differs. Today's wallet emits the profile id, so a server left on
    the default rejects every offer.
