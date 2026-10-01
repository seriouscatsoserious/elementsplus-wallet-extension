//! Per-chain local state: verified asset metadata cache, offers this wallet
//! made, and receive-address reservations (offer payment addresses stay
//! unused on chain until the offer is taken).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use elementsplus_wallet_core::{
    verify_asset_issuance, AssetContract, AssetIssuanceVerificationRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::dex::RegistryEntry;
use crate::esplora::Esplora;

pub const POLICY_TICKER: &str = "ECX";
pub const POLICY_NAME: &str = "ECX";
pub const POLICY_PRECISION: u8 = 8;

/// Locally verified asset metadata.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerifiedAsset {
    pub asset_id: String,
    pub name: String,
    /// `None` for reissuance tokens (never resolvable by ticker).
    pub ticker: Option<String>,
    pub precision: u8,
    pub is_token: bool,
    pub issuance_txid: String,
    pub issuance_vin: u32,
    pub contract: AssetContract,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalOffer {
    pub outpoint: String,
    pub give_asset: String,
    pub give_amount: String,
    pub want_asset: String,
    pub want_amount: String,
    pub maker_address: String,
    pub receive_index: u32,
    pub offer: Value,
    pub created_at: u64,
    pub posted: bool,
    /// open | cancelled
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_txid: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LocalState {
    /// Lowest external index not reserved by an offer.
    #[serde(default)]
    pub reserved_external: u32,
    #[serde(default)]
    pub offers: Vec<LocalOffer>,
    #[serde(default)]
    pub assets: BTreeMap<String, VerifiedAsset>,
}

impl LocalState {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                serde_json::from_str(&text).with_context(|| format!("corrupt {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::config::write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }

    /// Outpoints locked in open offers (excluded from ordinary coin selection).
    pub fn open_offer_outpoints(&self) -> Vec<String> {
        self.offers
            .iter()
            .filter(|o| o.status == "open")
            .map(|o| o.outpoint.clone())
            .collect()
    }
}

/// Display metadata for any asset id.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AssetLabel {
    pub asset_id: String,
    pub ticker: Option<String>,
    pub name: Option<String>,
    pub precision: u8,
    pub verified: bool,
}

impl AssetLabel {
    pub fn short(&self) -> String {
        match &self.ticker {
            Some(t) => t.clone(),
            None if self.verified => self
                .name
                .clone()
                .unwrap_or_else(|| self.asset_id[..8].to_owned()),
            None => format!(
                "{}…(unverified)",
                &self.asset_id[..12.min(self.asset_id.len())]
            ),
        }
    }
}

pub fn label(state: &LocalState, policy_asset: &str, asset_id: &str) -> AssetLabel {
    if asset_id == policy_asset {
        return AssetLabel {
            asset_id: asset_id.into(),
            ticker: Some(POLICY_TICKER.into()),
            name: Some(POLICY_NAME.into()),
            precision: POLICY_PRECISION,
            verified: true,
        };
    }
    match state.assets.get(asset_id) {
        Some(asset) => AssetLabel {
            asset_id: asset_id.into(),
            ticker: asset.ticker.clone(),
            name: Some(asset.name.clone()),
            precision: asset.precision,
            verified: true,
        },
        None => AssetLabel {
            asset_id: asset_id.into(),
            ticker: None,
            name: None,
            precision: 0,
            verified: false,
        },
    }
}

/// Verify one issuance locally and produce cache entries for the asset (and
/// its reissuance token, if any).
pub fn verify_issuance(
    raw_tx_hex: &str,
    txid: &str,
    vin: u32,
    contract: &AssetContract,
) -> Result<Vec<VerifiedAsset>> {
    let verified = verify_asset_issuance(&AssetIssuanceVerificationRequest {
        raw_tx_hex: raw_tx_hex.into(),
        expected_txid: txid.into(),
        vin,
        contract: contract.clone(),
    })?;
    let mut out = vec![VerifiedAsset {
        asset_id: verified.asset_id.clone(),
        name: contract.name.clone(),
        ticker: Some(contract.ticker.clone()),
        precision: contract.precision,
        is_token: false,
        issuance_txid: txid.into(),
        issuance_vin: vin,
        contract: contract.clone(),
    }];
    if let Some(token) = verified.token_id {
        out.push(VerifiedAsset {
            asset_id: token,
            name: format!("{} reissuance token", contract.name),
            ticker: None,
            precision: 0,
            is_token: true,
            issuance_txid: txid.into(),
            issuance_vin: vin,
            contract: contract.clone(),
        });
    }
    Ok(out)
}

/// Verify registry entries that are not cached yet. Entries that fail
/// verification are ignored (the registry is untrusted).
pub fn refresh_from_registry(
    state: &mut LocalState,
    entries: &[RegistryEntry],
    esplora: &Esplora,
    policy_asset: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    for entry in entries {
        if entry.asset_id == policy_asset || state.assets.contains_key(&entry.asset_id) {
            continue;
        }
        let result = (|| -> Result<Vec<VerifiedAsset>> {
            let contract: AssetContract = serde_json::from_value(entry.contract.clone())
                .context("registry contract has an unexpected shape")?;
            let raw = esplora.tx_hex(&entry.issuance_txid)?;
            let verified =
                verify_issuance(&raw, &entry.issuance_txid, entry.issuance_vin, &contract)?;
            if verified[0].asset_id != entry.asset_id {
                bail!("registry asset id does not match the verified issuance");
            }
            if entry.token_id.is_some()
                && verified.get(1).map(|t| &t.asset_id) != entry.token_id.as_ref()
            {
                bail!("registry token id does not match the verified issuance");
            }
            Ok(verified)
        })();
        match result {
            Ok(verified) => {
                for asset in verified {
                    state.assets.insert(asset.asset_id.clone(), asset);
                }
            }
            Err(error) => problems.push(format!("{}: {error}", entry.asset_id)),
        }
    }
    problems
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Resolve a user asset argument: a 64-hex id, or a ticker that belongs to
/// exactly one verified asset (the policy asset's ticker included).
pub fn resolve_asset(state: &LocalState, policy_asset: &str, arg: &str) -> Result<Option<String>> {
    let lower = arg.trim().to_ascii_lowercase();
    if is_hex64(&lower) {
        return Ok(Some(lower));
    }
    let wanted = arg.trim().to_ascii_uppercase();
    let mut matches: Vec<String> = state
        .assets
        .values()
        .filter(|a| {
            a.ticker.as_deref().map(str::to_ascii_uppercase).as_deref() == Some(wanted.as_str())
        })
        .map(|a| a.asset_id.clone())
        .collect();
    if wanted == POLICY_TICKER {
        matches.push(policy_asset.to_owned());
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        _ => bail!(
            "ticker {arg:?} is ambiguous ({} verified assets claim it); use the 64-hex asset id",
            matches.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: &str, ticker: &str) -> VerifiedAsset {
        VerifiedAsset {
            asset_id: id.into(),
            name: ticker.into(),
            ticker: Some(ticker.into()),
            precision: 2,
            is_token: false,
            issuance_txid: "00".repeat(32),
            issuance_vin: 0,
            contract: AssetContract {
                name: ticker.into(),
                ticker: ticker.into(),
                precision: 2,
                version: 0,
                issuer_pubkey: None,
            },
        }
    }

    #[test]
    fn ticker_resolution_requires_uniqueness() {
        let policy = "aa".repeat(32);
        let a = "bb".repeat(32);
        let b = "cc".repeat(32);
        let mut state = LocalState::default();
        state.assets.insert(a.clone(), asset(&a, "TOK"));
        assert_eq!(
            resolve_asset(&state, &policy, "tok").unwrap(),
            Some(a.clone())
        );
        assert_eq!(
            resolve_asset(&state, &policy, "ECX").unwrap(),
            Some(policy.clone())
        );
        assert_eq!(
            resolve_asset(&state, &policy, &b.to_uppercase()).unwrap(),
            Some(b.clone())
        );
        assert_eq!(resolve_asset(&state, &policy, "NOPE").unwrap(), None);
        state.assets.insert(b.clone(), asset(&b, "TOK"));
        assert!(resolve_asset(&state, &policy, "TOK").is_err());
        // A registry asset impersonating the policy ticker makes it ambiguous.
        state.assets.insert(a.clone(), asset(&a, "ECX"));
        assert!(resolve_asset(&state, &policy, "ECX").is_err());
        assert_eq!(label(&state, &policy, &policy).precision, 8);
        assert_eq!(label(&state, &policy, &"dd".repeat(32)).precision, 0);
        assert!(!label(&state, &policy, &"dd".repeat(32)).verified);
    }
}
