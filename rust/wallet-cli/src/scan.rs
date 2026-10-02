//! Gap-limit HD discovery over Esplora, mirroring the extension's scanner
//! (`src/network/explorer-hd-scan.ts`): external and change branches are
//! scanned until `gap_limit` consecutive unused addresses, address stats are
//! cross-checked against the UTXO list, and every funding transaction is
//! fetched raw and verified locally with `WalletCore::verify_raw_transaction`
//! before its outputs become spendable `VerifiedUtxo`s. Confidential outputs
//! that unblind with this wallet's SLIP-77 key are spendable too (they carry
//! their blinding); anything else is skipped.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use elementsplus_wallet_core::{
    Branch, ExpectedWalletOutput, RawTransactionVerificationRequest, VerifiedUtxo, WalletCore,
};
use serde::Serialize;

use crate::esplora::{Esplora, Utxo};

const MAX_INDEX: u32 = 100_000;

#[derive(Clone, Debug, Serialize)]
pub struct WalletUtxo {
    #[serde(flatten)]
    pub utxo: VerifiedUtxo,
    pub address: String,
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

impl WalletUtxo {
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.utxo.txid, self.utxo.vout)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ScannedAddress {
    pub branch: Branch,
    pub index: u32,
    pub address: String,
    pub used: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub utxos: Vec<WalletUtxo>,
    /// First index after the highest used one, per branch.
    pub next_external: u32,
    pub next_change: u32,
    pub addresses: Vec<ScannedAddress>,
    /// Verified raw funding transactions by txid.
    #[serde(skip)]
    pub raw_txs: BTreeMap<String, String>,
    /// Outputs the explorer reported but that failed local verification
    /// (e.g. non-explicit outputs); never spendable.
    pub skipped: Vec<String>,
    pub tip_height: u64,
}

impl Snapshot {
    pub fn used_addresses(&self) -> impl Iterator<Item = &ScannedAddress> {
        self.addresses.iter().filter(|a| a.used)
    }
}

struct AddressResult {
    address: ScannedAddress,
    script_hex: String,
    utxos: Vec<Utxo>,
}

fn scan_address(
    core: &WalletCore,
    esplora: &Esplora,
    branch: Branch,
    index: u32,
) -> Result<AddressResult> {
    let derived = core.derive_address(branch, index)?;
    let address = derived.native_address.clone();
    let info = esplora
        .address_info(&address)
        .with_context(|| format!("address stats for {address}"))?;
    let used = info.chain_stats.tx_count > 0
        || info.mempool_stats.tx_count > 0
        || info.chain_stats.funded_txo_count > 0
        || info.mempool_stats.funded_txo_count > 0;
    let funded = info.chain_stats.funded_txo_count + info.mempool_stats.funded_txo_count;
    let spent = info.chain_stats.spent_txo_count + info.mempool_stats.spent_txo_count;
    let expected = funded
        .checked_sub(spent)
        .with_context(|| format!("{address}: explorer reports more spends than funds"))?;
    let utxos = if used {
        esplora.address_utxos(&address)?
    } else {
        Vec::new()
    };
    if utxos.len() as u64 != expected {
        bail!("{address}: explorer statistics and UTXO list disagree");
    }
    Ok(AddressResult {
        address: ScannedAddress {
            branch,
            index,
            address,
            used,
        },
        script_hex: derived.script_pubkey_hex,
        utxos,
    })
}

fn scan_branch(
    core: &WalletCore,
    esplora: &Esplora,
    branch: Branch,
    gap_limit: u32,
    min_index: u32,
) -> Result<(Vec<AddressResult>, u32)> {
    let mut results = Vec::new();
    let mut index = 0u32;
    let mut trailing_unused = 0u32;
    let mut next_unused = 0u32;
    while trailing_unused < gap_limit || index < min_index {
        if index > MAX_INDEX {
            bail!("address scan exceeded index {MAX_INDEX}");
        }
        let page: Vec<u32> = (index..index + gap_limit.min(20)).collect();
        let page_results: Vec<Result<AddressResult>> = std::thread::scope(|scope| {
            let handles: Vec<_> = page
                .iter()
                .map(|i| scope.spawn(move || scan_address(core, esplora, branch, *i)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("scan thread panicked"))
                .collect()
        });
        for result in page_results {
            let result = result?;
            index = result.address.index + 1;
            if result.address.used {
                trailing_unused = 0;
                next_unused = result.address.index + 1;
            } else {
                trailing_unused += 1;
            }
            results.push(result);
            if trailing_unused >= gap_limit && index >= min_index {
                break;
            }
        }
    }
    Ok((results, next_unused))
}

/// Scan the wallet. `expected_genesis` pins the explorer to our chain;
/// external addresses below `min_external` (reserved for open offers) are
/// always scanned even if they exceed the gap.
pub fn scan(
    core: &WalletCore,
    esplora: &Esplora,
    gap_limit: u32,
    expected_genesis: &str,
    min_external: u32,
) -> Result<Snapshot> {
    let genesis = esplora.genesis_hash()?;
    if genesis != expected_genesis {
        bail!(
            "explorer {} serves genesis {genesis}, but this wallet is pinned to {expected_genesis}",
            esplora.base()
        );
    }
    let tip_height = esplora.tip_height()?;
    let (external, next_external) =
        scan_branch(core, esplora, Branch::External, gap_limit, min_external)?;
    let (change, next_change) = scan_branch(core, esplora, Branch::Change, gap_limit, 0)?;

    // Group explorer UTXOs by funding txid.
    struct Ref {
        branch: Branch,
        index: u32,
        address: String,
        script_hex: String,
        utxo: Utxo,
    }
    let mut by_txid: BTreeMap<String, Vec<Ref>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut addresses = Vec::new();
    for result in external.into_iter().chain(change) {
        for utxo in result.utxos {
            if !seen.insert((utxo.txid.clone(), utxo.vout)) {
                bail!("explorer returned one outpoint for multiple wallet addresses");
            }
            by_txid.entry(utxo.txid.clone()).or_default().push(Ref {
                branch: result.address.branch,
                index: result.address.index,
                address: result.address.address.clone(),
                script_hex: result.script_hex.clone(),
                utxo,
            });
        }
        addresses.push(result.address);
    }

    let mut snapshot = Snapshot {
        next_external,
        next_change,
        addresses,
        tip_height,
        ..Snapshot::default()
    };
    for (txid, refs) in by_txid {
        let raw = esplora.tx_hex(&txid)?;
        for reference in refs {
            let request = RawTransactionVerificationRequest {
                expected_txid: txid.clone(),
                raw_transaction_hex: raw.clone(),
                expected_wallet_outputs: vec![ExpectedWalletOutput {
                    vout: reference.utxo.vout,
                    script_pub_key_hex: reference.script_hex.clone(),
                }],
            };
            let label = format!("{txid}:{}", reference.utxo.vout);
            let verified = match core.verify_raw_transaction(&request) {
                Ok(verified) => verified,
                Err(error) => {
                    // Foreign-blinded or mismatching outputs are never spendable.
                    snapshot.skipped.push(format!("{label}: {error}"));
                    continue;
                }
            };
            let output = &verified.outputs[0];
            if reference
                .utxo
                .asset
                .as_deref()
                .is_some_and(|a| a != output.asset_id)
                || reference
                    .utxo
                    .value
                    .is_some_and(|v| v != output.value_atomic)
            {
                bail!("{label}: explorer asset/value disagree with the verified transaction");
            }
            snapshot.utxos.push(WalletUtxo {
                utxo: VerifiedUtxo {
                    txid: txid.clone(),
                    vout: reference.utxo.vout,
                    value: output.value_atomic,
                    asset_id: output.asset_id.clone(),
                    script_pubkey_hex: reference.script_hex.clone(),
                    branch: reference.branch,
                    index: reference.index,
                    blinding: output.blinding.clone(),
                },
                address: reference.address.clone(),
                confirmed: reference.utxo.status.confirmed,
                block_height: reference.utxo.status.block_height,
            });
        }
        snapshot.raw_txs.insert(txid, raw);
    }
    snapshot
        .utxos
        .sort_by(|a, b| (&a.utxo.txid, a.utxo.vout).cmp(&(&b.utxo.txid, b.utxo.vout)));
    Ok(snapshot)
}
