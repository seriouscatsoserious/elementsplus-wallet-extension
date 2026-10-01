//! Asset contracts and issuance verification.

use std::collections::BTreeMap;
use std::str::FromStr;

use elements::confidential::Value;
use elements::encode::deserialize;
use elements::hashes::Hash;
use elements::secp256k1_zkp::{self, ZERO_TWEAK};
use elements::{AssetId, ContractHash, OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};

use crate::{WalletError, MAX_RAW_TRANSACTION_BYTES};

/// Maximum issuance amount accepted by Elements' `MoneyRange`.
pub const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// The asset contract committed to by an issuance.
///
/// Unknown fields are rejected so that every consumer hashes exactly the
/// same canonical object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetContract {
    pub name: String,
    pub ticker: String,
    pub precision: u8,
    pub version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_pubkey: Option<String>,
}

impl AssetContract {
    /// Enforce the registry rules this wallet relies on for display.
    pub fn validate(&self) -> Result<(), WalletError> {
        let invalid = |reason: &str| WalletError::Issuance(format!("invalid contract: {reason}"));
        let name_len = self.name.chars().count();
        if name_len == 0 || name_len > 255 {
            return Err(invalid("name must be 1 to 255 characters"));
        }
        if self.name.chars().any(char::is_control) || self.name.trim() != self.name {
            return Err(invalid(
                "name must not contain control characters or outer whitespace",
            ));
        }
        if !(3..=24).contains(&self.ticker.len())
            || !self
                .ticker
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(invalid(
                "ticker must be 3 to 24 characters of [A-Za-z0-9.-]",
            ));
        }
        if self.precision > 8 {
            return Err(invalid("precision must be 0 to 8"));
        }
        if self.version != 0 {
            return Err(invalid("version must be 0"));
        }
        if let Some(pubkey) = &self.issuer_pubkey {
            let bytes = hex::decode(pubkey).map_err(|_| invalid("issuer_pubkey is not hex"))?;
            if bytes.len() != 33
                || pubkey != &pubkey.to_ascii_lowercase()
                || secp256k1_zkp::PublicKey::from_slice(&bytes).is_err()
            {
                return Err(invalid(
                    "issuer_pubkey must be a lowercase compressed secp256k1 public key",
                ));
            }
        }
        Ok(())
    }

    /// Canonical JSON: sorted keys, no whitespace.
    pub fn canonical_json(&self) -> String {
        let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        map.insert("name", self.name.clone().into());
        map.insert("ticker", self.ticker.clone().into());
        map.insert("precision", self.precision.into());
        map.insert("version", self.version.into());
        if let Some(pubkey) = &self.issuer_pubkey {
            map.insert("issuer_pubkey", pubkey.clone().into());
        }
        serde_json::to_string(&map).expect("string map serializes")
    }

    /// Validate and hash the canonical contract.
    pub fn contract_hash(&self) -> Result<ContractHash, WalletError> {
        self.validate()?;
        ContractHash::from_json_contract(&self.canonical_json())
            .map_err(|e| WalletError::Issuance(format!("contract hashing failed: {e}")))
    }
}

/// Asset and reissuance-token ids of a new explicit issuance.
pub fn issuance_ids(
    prevout: OutPoint,
    contract_hash: ContractHash,
    confidential_amount: bool,
) -> (AssetId, AssetId) {
    let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
    (
        AssetId::from_entropy(entropy),
        AssetId::reissuance_token_from_entropy(entropy, confidential_amount),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetIssuanceVerificationRequest {
    pub raw_tx_hex: String,
    pub expected_txid: String,
    pub vin: u32,
    pub contract: AssetContract,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedAssetIssuance {
    pub asset_id: String,
    pub token_id: Option<String>,
    pub contract_hash: String,
}

/// Recompute contract hash → entropy → asset/token ids from an issuance input.
pub fn verify_asset_issuance(
    request: &AssetIssuanceVerificationRequest,
) -> Result<VerifiedAssetIssuance, WalletError> {
    let fail = |reason: String| WalletError::Issuance(reason);
    let expected_txid = Txid::from_str(&request.expected_txid)
        .map_err(|_| fail("expected txid is invalid".into()))?;
    let raw = hex::decode(&request.raw_tx_hex)
        .map_err(|_| fail("raw transaction is not valid hex".into()))?;
    if raw.is_empty() || raw.len() > MAX_RAW_TRANSACTION_BYTES {
        return Err(fail(
            "raw transaction length is outside the accepted range".into(),
        ));
    }
    let tx: Transaction =
        deserialize(&raw).map_err(|e| fail(format!("consensus decode failed: {e}")))?;
    if tx.txid() != expected_txid {
        return Err(fail(format!(
            "txid mismatch: expected {expected_txid}, decoded {}",
            tx.txid()
        )));
    }
    let input = tx
        .input
        .get(request.vin as usize)
        .ok_or_else(|| fail(format!("vin {} is out of range", request.vin)))?;
    if input.is_pegin || !input.has_issuance() {
        return Err(fail(format!(
            "vin {} carries no asset issuance",
            request.vin
        )));
    }
    let issuance = &input.asset_issuance;
    if issuance.asset_blinding_nonce != ZERO_TWEAK {
        return Err(fail("input is a reissuance, not a new issuance".into()));
    }
    let contract_hash = request.contract.contract_hash()?;
    if issuance.asset_entropy != contract_hash.to_byte_array() {
        return Err(fail(
            "issuance does not commit to the supplied contract".into(),
        ));
    }
    let confidential_amount = matches!(issuance.amount, Value::Confidential(_));
    let (asset_id, token_id) =
        issuance_ids(input.previous_output, contract_hash, confidential_amount);
    let has_token = match issuance.inflation_keys {
        Value::Null => false,
        Value::Explicit(n) => n > 0,
        Value::Confidential(_) => true,
    };
    Ok(VerifiedAssetIssuance {
        asset_id: asset_id.to_string(),
        token_id: has_token.then(|| token_id.to_string()),
        contract_hash: contract_hash.to_string(),
    })
}
