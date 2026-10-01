//! The single review model (spec §1.1), recomputed from the PSET alone.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::encode::serialize;
use elements::hashes::{sha256, Hash, HashEngine};
use elements::pset::{Input, PartiallySignedTransaction};
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{Address, AssetId, ContractHash, EcdsaSighashType, OutPoint, Sequence};
use elementsplus_lwk_adapter::preview_explicit_pset;
use lwk_common::get_genesis_hash;
use serde::{Deserialize, Serialize};

use crate::issuance::{issuance_ids, MAX_MONEY};
use crate::offer::{explicit_parts, verify_p2wpkh_witness};
use crate::{is_wallet_path, p2wpkh_script, WalletCore, WalletError, REVIEW_DOMAIN};

pub const SIGHASH_ALL: &str = "ALL";
pub const SIGHASH_SINGLE_ACP: &str = "SINGLE|ANYONECANPAY";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TxKind {
    Transfer,
    Issuance,
    SwapOffer,
    SwapTake,
    OfferSplit,
    Cancel,
}

impl TxKind {
    pub(crate) fn sighash(self) -> EcdsaSighashType {
        match self {
            Self::SwapOffer => EcdsaSighashType::SinglePlusAnyoneCanPay,
            _ => EcdsaSighashType::All,
        }
    }

    fn sighash_label(self) -> &'static str {
        match self {
            Self::SwapOffer => SIGHASH_SINGLE_ACP,
            _ => SIGHASH_ALL,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetDelta {
    pub asset_id: String,
    /// Signed decimal string of atomic units.
    pub amount: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOutput {
    pub address: String,
    pub asset_id: String,
    #[serde(with = "crate::amount::string")]
    pub amount: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceReview {
    pub asset_id: String,
    pub token_id: Option<String>,
    #[serde(with = "crate::amount::string")]
    pub amount: u64,
    #[serde(with = "crate::amount::string")]
    pub token_amount: u64,
    pub contract_hash: String,
}

/// Human-reviewable facts recomputed from the PSET before signing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TxReview {
    pub kind: TxKind,
    pub network: String,
    pub genesis_hash: String,
    /// Net effect on this wallet, per asset, excluding the fee.
    pub balance_changes: Vec<AssetDelta>,
    /// Policy-asset fee, atomic units.
    pub fee: u64,
    /// Outputs paying scripts that are NOT this wallet's.
    pub external_outputs: Vec<ExternalOutput>,
    /// `txid:vout` inputs this wallet will sign.
    pub inputs_signed: Vec<String>,
    /// Inputs owned by others (swap makers).
    pub foreign_inputs: Vec<String>,
    pub issuance: Option<IssuanceReview>,
    pub sighash: String,
}

/// Exact unsigned PSET plus its independently reviewable commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedTx {
    pub pset_base64: String,
    pub review: TxReview,
    pub review_hash: String,
}

/// Result of `sign_prepared`: a broadcastable transaction, or for swap
/// offers the signed offer (spec §2), which is not broadcastable on its own.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedResult {
    pub txid: String,
    pub review_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_tx_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer: Option<crate::Offer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputOwner {
    Wallet,
    Foreign,
}

/// Structural facts the signer needs beyond the human review.
pub(crate) struct Analysis {
    pub review: TxReview,
    pub owners: Vec<InputOwner>,
}

fn bad(reason: impl Into<String>) -> WalletError {
    WalletError::InvalidPset(reason.into())
}

fn add(map: &mut BTreeMap<AssetId, u64>, asset: AssetId, amount: u64) -> Result<(), WalletError> {
    let entry = map.entry(asset).or_default();
    *entry = entry
        .checked_add(amount)
        .ok_or(WalletError::AmountOverflow)?;
    Ok(())
}

impl WalletCore {
    /// Independently recompute the review and review hash of an existing
    /// unsigned PSET under the structural rules of `kind`. Signing still
    /// requires an explicit approval of the returned hash.
    pub fn review_pset(&self, pset_base64: &str, kind: TxKind) -> Result<PreparedTx, WalletError> {
        if pset_base64.len() > crate::MAX_RAW_TRANSACTION_BYTES {
            return Err(bad("PSET is too large"));
        }
        let pset =
            PartiallySignedTransaction::from_str(pset_base64).map_err(|e| bad(e.to_string()))?;
        let review = self.analyze(&pset, kind)?.review;
        let review_hash = self.review_commitment(&pset, &review)?;
        Ok(PreparedTx {
            pset_base64: pset_base64.to_owned(),
            review,
            review_hash,
        })
    }

    pub(crate) fn review_commitment(
        &self,
        pset: &PartiallySignedTransaction,
        review: &TxReview,
    ) -> Result<String, WalletError> {
        let review_json =
            serde_json::to_vec(review).map_err(|e| WalletError::Json(e.to_string()))?;
        let mut engine = sha256::Hash::engine();
        engine.input(REVIEW_DOMAIN);
        engine.input(&serialize(pset));
        engine.input(&review_json);
        Ok(sha256::Hash::from_engine(engine).to_string())
    }

    fn input_is_wallet(&self, input: &Input) -> Result<bool, WalletError> {
        let ours: Vec<_> = input
            .bip32_derivation
            .iter()
            .filter(|(_, (fingerprint, _))| *fingerprint == self.signer.fingerprint())
            .collect();
        if input.bip32_derivation.is_empty() {
            return Ok(false);
        }
        // Anything claiming a derivation must be exactly one valid path of
        // ours. Foreign or malformed derivations are refused outright so the
        // signer never sees a key it might act on.
        if input.bip32_derivation.len() != 1 || ours.len() != 1 {
            return Err(bad("input carries a foreign or ambiguous ownership path"));
        }
        let (public_key, (_, path)) = ours[0];
        let witness = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| bad("input lacks witness UTXO"))?;
        if !is_wallet_path(path)
            || self.derived_pubkey(path)? != *public_key
            || p2wpkh_script(public_key) != witness.script_pubkey
        {
            return Err(bad("input ownership proof does not match this wallet"));
        }
        Ok(true)
    }

    fn output_is_wallet(&self, output: &elements::pset::Output) -> bool {
        if output.bip32_derivation.len() != 1 {
            return false;
        }
        let (public_key, (fingerprint, path)) = output
            .bip32_derivation
            .iter()
            .next()
            .expect("length checked");
        *fingerprint == self.signer.fingerprint()
            && is_wallet_path(path)
            && self.derived_pubkey(path).ok().as_ref() == Some(public_key)
            && p2wpkh_script(public_key) == output.script_pubkey
    }

    /// Recompute every review fact from the PSET and enforce the structural
    /// rules of `kind`. Nothing here trusts caller-supplied summaries.
    pub(crate) fn analyze(
        &self,
        pset: &PartiallySignedTransaction,
        kind: TxKind,
    ) -> Result<Analysis, WalletError> {
        validate_globals(pset)?;
        if get_genesis_hash(pset) != Some(self.genesis_hash) {
            return Err(bad("PSET genesis does not match the configured network"));
        }
        preview_explicit_pset(pset, self.policy_asset).map_err(|e| bad(e.to_string()))?;
        let unsigned = pset.extract_tx().map_err(|e| bad(e.to_string()))?;
        if unsigned.version != 2 || unsigned.lock_time != elements::LockTime::ZERO {
            return Err(bad("transaction version or locktime is unsupported"));
        }
        if pset.inputs().is_empty() || pset.outputs().is_empty() {
            return Err(bad("PSET has no inputs or no outputs"));
        }
        if pset.inputs().len() > 256 || pset.outputs().len() > 256 {
            return Err(bad("PSET has too many inputs or outputs"));
        }

        let sighash = kind.sighash();
        let mut owners = Vec::with_capacity(pset.inputs().len());
        let mut seen = BTreeSet::new();
        let mut inputs_signed = Vec::new();
        let mut foreign_inputs = Vec::new();
        let mut total_in: BTreeMap<AssetId, u64> = BTreeMap::new();
        let mut wallet_in: BTreeMap<AssetId, u64> = BTreeMap::new();
        let mut issuance_review = None;

        for (index, input) in pset.inputs().iter().enumerate() {
            let outpoint = OutPoint::new(input.previous_txid, input.previous_output_index);
            let label = crate::outpoint_label(&outpoint);
            if !seen.insert(label.clone()) {
                return Err(WalletError::DuplicateUtxo(label));
            }
            validate_input_fields(input)?;
            let witness = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| bad("input lacks witness UTXO"))?;
            let (asset, value) =
                explicit_parts(witness).ok_or_else(|| bad("input UTXO is not fully explicit"))?;
            if input.asset != Some(asset)
                || input.amount != Some(value)
                || value == 0
                || value > MAX_MONEY
                || !witness.script_pubkey.is_v0_p2wpkh()
                || witness.witness != Default::default()
            {
                return Err(bad("input asset, amount, or script is inconsistent"));
            }
            add(&mut total_in, asset, value)?;

            let owner = if self.input_is_wallet(input)? {
                if input.final_script_witness.is_some() {
                    return Err(bad("wallet input is already finalized"));
                }
                if input.sighash_type.map(|s| s.ecdsa_hash_ty()) != Some(Some(sighash)) {
                    return Err(bad(format!(
                        "wallet input {index} does not declare the expected sighash {}",
                        kind.sighash_label()
                    )));
                }
                add(&mut wallet_in, asset, value)?;
                inputs_signed.push(label);
                InputOwner::Wallet
            } else {
                if kind != TxKind::SwapTake {
                    return Err(bad("foreign inputs are only allowed when taking offers"));
                }
                if input.sighash_type.is_some() || input.final_script_witness.is_none() {
                    return Err(bad("foreign input must carry a final witness"));
                }
                foreign_inputs.push(label);
                InputOwner::Foreign
            };

            if input.has_issuance() {
                if kind != TxKind::Issuance || index != 0 || owner != InputOwner::Wallet {
                    return Err(bad("issuance is only allowed on the first wallet input"));
                }
                let (asset_id, token_id, amount, token_amount, contract_hash) =
                    explicit_issuance(input)?;
                add(&mut total_in, asset_id, amount)?;
                if token_amount > 0 {
                    add(&mut total_in, token_id, token_amount)?;
                }
                issuance_review = Some(IssuanceReview {
                    asset_id: asset_id.to_string(),
                    token_id: (token_amount > 0).then(|| token_id.to_string()),
                    amount,
                    token_amount,
                    contract_hash: contract_hash.to_string(),
                });
            }
            owners.push(owner);
        }

        let mut total_out: BTreeMap<AssetId, u64> = BTreeMap::new();
        let mut wallet_out: BTreeMap<AssetId, u64> = BTreeMap::new();
        let mut external_outputs = Vec::new();
        let mut external_flags = Vec::with_capacity(pset.outputs().len());
        let mut fee = 0u64;
        let mut fee_outputs = 0usize;
        let output_count = pset.outputs().len();
        for (vout, output) in pset.outputs().iter().enumerate() {
            validate_output_fields(output)?;
            let (Some(asset), Some(amount)) = (output.asset, output.amount) else {
                return Err(bad("output is missing its explicit asset or amount"));
            };
            if amount == 0 || amount > MAX_MONEY {
                return Err(bad(format!(
                    "output {vout} amount is outside the money range"
                )));
            }
            add(&mut total_out, asset, amount)?;
            if output.script_pubkey.is_empty() {
                if asset != self.policy_asset || vout + 1 != output_count {
                    return Err(bad(
                        "fee must be a single policy-asset output in last position",
                    ));
                }
                fee = amount;
                fee_outputs += 1;
                external_flags.push(false);
                continue;
            }
            if self.output_is_wallet(output) {
                add(&mut wallet_out, asset, amount)?;
                external_flags.push(false);
            } else {
                let address =
                    Address::from_script(&output.script_pubkey, None, self.native_address_params)
                        .ok_or_else(|| bad(format!("output {vout} script has no address")))?;
                external_outputs.push(ExternalOutput {
                    address: address.to_string(),
                    asset_id: asset.to_string(),
                    amount,
                });
                external_flags.push(true);
            }
        }

        // Conservation: every asset balances, except the maker's half of a
        // swap offer, which is intentionally completed by the taker.
        if kind != TxKind::SwapOffer {
            if fee_outputs != 1 {
                return Err(bad("transaction must have exactly one fee output"));
            }
            let assets: BTreeSet<_> = total_in.keys().chain(total_out.keys()).collect();
            for asset in assets {
                let inputs = total_in.get(asset).copied().unwrap_or(0);
                let outputs = total_out.get(asset).copied().unwrap_or(0);
                if inputs != outputs {
                    return Err(bad(format!(
                        "asset {asset} is not conserved: inputs {inputs}, outputs {outputs}"
                    )));
                }
            }
        }

        let wallet_inputs = owners.iter().filter(|o| **o == InputOwner::Wallet).count();
        let foreign_count = owners.len() - wallet_inputs;
        match kind {
            TxKind::Transfer => {
                if external_outputs.is_empty() || issuance_review.is_some() {
                    return Err(bad("transfer must pay an external recipient"));
                }
            }
            TxKind::OfferSplit | TxKind::Cancel => {
                if !external_outputs.is_empty() || issuance_review.is_some() {
                    return Err(bad("self-send must not pay any external output"));
                }
            }
            TxKind::Issuance => {
                if issuance_review.is_none() {
                    return Err(bad("issuance transaction carries no issuance"));
                }
            }
            TxKind::SwapOffer => {
                if pset.inputs().len() != 1
                    || output_count != 1
                    || wallet_inputs != 1
                    || fee_outputs != 0
                    || external_flags[0]
                {
                    return Err(bad(
                        "swap offer must spend one wallet input to one wallet output",
                    ));
                }
                let input_asset = pset.inputs()[0].asset;
                if input_asset == pset.outputs()[0].asset {
                    return Err(bad("swap offer must exchange different assets"));
                }
            }
            TxKind::SwapTake => {
                if foreign_count == 0 || wallet_inputs == 0 || issuance_review.is_some() {
                    return Err(bad("swap take needs maker inputs and taker inputs"));
                }
                if owners[..foreign_count]
                    .iter()
                    .any(|o| *o != InputOwner::Foreign)
                {
                    return Err(bad("maker inputs must come first"));
                }
                if output_count <= foreign_count
                    || pset.outputs()[..foreign_count]
                        .iter()
                        .any(|o| !o.bip32_derivation.is_empty() || o.script_pubkey.is_empty())
                {
                    return Err(bad("maker outputs must be paired with maker inputs"));
                }
                for index in 0..foreign_count {
                    let prevout = pset.inputs()[index]
                        .witness_utxo
                        .as_ref()
                        .expect("checked above");
                    let flag = verify_p2wpkh_witness(&unsigned, index, prevout)
                        .map_err(|e| bad(format!("maker input {index}: {e}")))?;
                    if flag != EcdsaSighashType::SinglePlusAnyoneCanPay {
                        return Err(bad(format!(
                            "maker input {index} is not signed SIGHASH_SINGLE|ANYONECANPAY"
                        )));
                    }
                }
            }
        }
        if wallet_inputs == 0 {
            return Err(bad("PSET contains no wallet input to sign"));
        }

        // Net effect on this wallet per asset, excluding the fee (which the
        // wallet pays in every fee-bearing transaction this core builds).
        let mut deltas: BTreeMap<AssetId, i128> = BTreeMap::new();
        for (asset, amount) in &wallet_out {
            *deltas.entry(*asset).or_default() += i128::from(*amount);
        }
        for (asset, amount) in &wallet_in {
            *deltas.entry(*asset).or_default() -= i128::from(*amount);
        }
        if fee > 0 {
            *deltas.entry(self.policy_asset).or_default() += i128::from(fee);
        }
        let mut balance_changes: Vec<AssetDelta> = deltas
            .into_iter()
            .filter(|(_, amount)| *amount != 0)
            .map(|(asset, amount)| AssetDelta {
                asset_id: asset.to_string(),
                amount: amount.to_string(),
            })
            .collect();
        balance_changes.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));

        Ok(Analysis {
            review: TxReview {
                kind,
                network: self.network_name.clone(),
                genesis_hash: self.genesis_hash.to_string(),
                balance_changes,
                fee,
                external_outputs,
                inputs_signed,
                foreign_inputs,
                issuance: issuance_review,
                sighash: kind.sighash_label().into(),
            },
            owners,
        })
    }
}

fn explicit_issuance(
    input: &Input,
) -> Result<(AssetId, AssetId, u64, u64, ContractHash), WalletError> {
    if input.issuance_value_comm.is_some()
        || input.issuance_inflation_keys_comm.is_some()
        || input.issuance_value_rangeproof.is_some()
        || input.issuance_keys_rangeproof.is_some()
        || input.in_issuance_blind_value_proof.is_some()
        || input.in_issuance_blind_inflation_keys_proof.is_some()
        || input.blinded_issuance.is_some()
        || input
            .issuance_blinding_nonce
            .is_some_and(|n| n != ZERO_TWEAK)
    {
        return Err(bad("only explicit new issuances are supported"));
    }
    let amount = input
        .issuance_value_amount
        .filter(|a| *a > 0 && *a <= MAX_MONEY)
        .ok_or_else(|| bad("issuance amount must be within the money range"))?;
    let token_amount = input.issuance_inflation_keys.unwrap_or(0);
    if token_amount > MAX_MONEY || input.issuance_inflation_keys == Some(0) {
        return Err(bad("issuance token amount is invalid"));
    }
    let entropy = input
        .issuance_asset_entropy
        .ok_or_else(|| bad("issuance lacks a contract hash"))?;
    let contract_hash = ContractHash::from_byte_array(entropy);
    let prevout = OutPoint::new(input.previous_txid, input.previous_output_index);
    let (asset_id, token_id) = issuance_ids(prevout, contract_hash, false);
    Ok((asset_id, token_id, amount, token_amount, contract_hash))
}

fn validate_globals(pset: &PartiallySignedTransaction) -> Result<(), WalletError> {
    let global = &pset.global;
    if global.version != 2
        || global.tx_data.version != 2
        || global.tx_data.fallback_locktime.is_some()
        || global.tx_data.tx_modifiable.is_some()
        || !global.xpub.is_empty()
        || !global.scalars.is_empty()
        || global.elements_tx_modifiable_flag.is_some()
        || global.proprietary.len() != 1
        || !global.unknown.is_empty()
    {
        return Err(bad("unsupported or mutable global PSET fields"));
    }
    Ok(())
}

fn validate_input_fields(input: &Input) -> Result<(), WalletError> {
    if input.sequence != Some(Sequence::MAX)
        || input.non_witness_utxo.is_some()
        || !input.partial_sigs.is_empty()
        || input.redeem_script.is_some()
        || input.witness_script.is_some()
        || input.final_script_sig.is_some()
        || input.required_time_locktime.is_some()
        || input.required_height_locktime.is_some()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || !input.tap_scripts.is_empty()
        || !input.tap_key_origins.is_empty()
        || input.tap_internal_key.is_some()
        || input.tap_merkle_root.is_some()
        || !input.ripemd160_preimages.is_empty()
        || !input.sha256_preimages.is_empty()
        || !input.hash160_preimages.is_empty()
        || !input.hash256_preimages.is_empty()
        || input.pegin_tx.is_some()
        || input.pegin_txout_proof.is_some()
        || input.pegin_genesis_hash.is_some()
        || input.pegin_claim_script.is_some()
        || input.pegin_value.is_some()
        || input.pegin_witness.is_some()
        || input.is_pegin()
        || input.in_utxo_rangeproof.is_some()
        || input.blind_value_proof.is_some()
        || input.blind_asset_proof.is_some()
        || !input.proprietary.is_empty()
        || !input.unknown.is_empty()
    {
        return Err(bad(
            "input contains unsupported signing, peg-in, proof, or script fields",
        ));
    }
    if !input.has_issuance()
        && (input.issuance_value_amount.is_some()
            || input.issuance_value_comm.is_some()
            || input.issuance_value_rangeproof.is_some()
            || input.issuance_keys_rangeproof.is_some()
            || input.issuance_inflation_keys.is_some()
            || input.issuance_inflation_keys_comm.is_some()
            || input.issuance_blinding_nonce.is_some()
            || input.issuance_asset_entropy.is_some()
            || input.in_issuance_blind_value_proof.is_some()
            || input.in_issuance_blind_inflation_keys_proof.is_some()
            || input.blinded_issuance.is_some())
    {
        return Err(bad("input carries partial issuance fields"));
    }
    if let Some(witness) = &input.final_script_witness {
        if witness.len() != 2 || !input.bip32_derivation.is_empty() {
            return Err(bad("finalized input must carry a plain P2WPKH witness"));
        }
    }
    Ok(())
}

fn validate_output_fields(output: &elements::pset::Output) -> Result<(), WalletError> {
    if output.redeem_script.is_some()
        || output.witness_script.is_some()
        || output.tap_internal_key.is_some()
        || output.tap_tree.is_some()
        || !output.tap_key_origins.is_empty()
        || output.value_rangeproof.is_some()
        || output.asset_surjection_proof.is_some()
        || output.blind_value_proof.is_some()
        || output.blind_asset_proof.is_some()
        || !output.proprietary.is_empty()
        || !output.unknown.is_empty()
    {
        return Err(bad(
            "output contains unsupported scripts, proofs, or metadata",
        ));
    }
    Ok(())
}
