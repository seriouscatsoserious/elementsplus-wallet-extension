//! A deliberately narrow signing core for an ECX Alpha browser wallet.
//!
//! The crate owns no network client and trusts no explorer response by itself.
//! A caller supplies UTXOs that it has independently verified; this core then
//! verifies that they are explicit policy-asset P2WPKH outputs owned by the
//! mnemonic, constructs a deterministic PSET, binds the exact PSET to a review
//! hash, signs only after that hash is approved, finalizes, and validates the
//! resulting wire transaction. Scanning and broadcasting stay outside this
//! security boundary.

use std::collections::BTreeSet;
use std::str::FromStr;

use bech32::segwit;
use elements::bitcoin::bip32::DerivationPath;
use elements::bitcoin::PublicKey;
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::{sha256, Hash, HashEngine};
use elements::pset::{Input, Output, PartiallySignedTransaction};
use elements::secp256k1_zkp::Secp256k1;
use elements::{
    Address, AddressParams, AssetId, BlockHash, OutPoint, Script, Sequence, Transaction,
    TxInWitness, TxOut, TxOutWitness, Txid, WPubkeyHash,
};
use elements_miniscript::psbt::finalize;
use elementsplus_lwk_adapter::{
    lwk_network, preview_explicit_pset, validate_explicit_transaction, NATIVE_ADDRESS_PARAMS,
};
pub use elementsplus_lwk_adapter::{GENESIS_HASH, NETWORK_NAME, POLICY_ASSET};
use lwk_common::{get_genesis_hash, set_genesis_hash, Network, Signer};
use lwk_signer::bip39::{Language, Mnemonic};
use lwk_signer::SwSigner;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The sole derivation scheme supported by this core.
pub const DERIVATION_ACCOUNT: &str = "m/84'/1'/0'";
/// Domain separator for review commitments. Changing review semantics requires
/// a new version rather than silently reusing an approval.
pub const REVIEW_DOMAIN: &[u8] = b"ECX_ALPHA_EXPLICIT_SEND_REVIEW_V1\0";
/// Hard ceiling for untrusted raw transaction responses passed into WASM.
pub const MAX_RAW_TRANSACTION_BYTES: usize = 4_000_000;

/// Errors are intentionally descriptive but never contain mnemonic material.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid BIP39 mnemonic")]
    InvalidMnemonic,
    #[error("mnemonic generation failed")]
    MnemonicGeneration,
    #[error("invalid derivation index or branch")]
    InvalidDerivation,
    #[error("invalid recipient: {0}")]
    InvalidRecipient(&'static str),
    #[error("invalid UTXO {outpoint}: {reason}")]
    InvalidUtxo { outpoint: String, reason: String },
    #[error("duplicate UTXO {0}")]
    DuplicateUtxo(String),
    #[error("amount and fee must both be non-zero")]
    ZeroAmount,
    #[error("amount overflow")]
    AmountOverflow,
    #[error("insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },
    #[error("PSET is malformed: {0}")]
    InvalidPset(String),
    #[error("review summary does not match the PSET")]
    ReviewMismatch,
    #[error("approved review hash does not match the PSET")]
    ApprovalMismatch,
    #[error("signer produced {0} signature(s), expected one per input")]
    SignatureCount(u32),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("finalization failed: {0}")]
    Finalization(String),
    #[error("final transaction violates wallet policy: {0}")]
    FinalTransaction(String),
    #[error("raw transaction verification failed: {0}")]
    RawTransaction(String),
    #[error("JSON request is invalid: {0}")]
    Json(String),
}

/// External addresses are branch 0 and change addresses are branch 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Branch {
    External,
    Change,
}

impl Branch {
    fn number(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Change => 1,
        }
    }
}

/// A derived P2WPKH address. Both strings encode exactly the same script.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivedAddress {
    pub branch: Branch,
    pub index: u32,
    pub derivation_path: String,
    pub native_address: String,
    pub lwk_alias: String,
    pub script_pubkey_hex: String,
}

/// A UTXO supplied by a chain source outside this crate.
///
/// "Verified" means the caller has verified existence, confirmation status,
/// and non-spent status. This core still verifies the asset, amount, script,
/// ownership path, duplicates, and all transaction conservation rules.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub asset_id: String,
    pub script_pubkey_hex: String,
    pub branch: Branch,
    pub index: u32,
}

/// A single-policy-asset payment request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SendRequest {
    pub recipient: String,
    pub amount: u64,
    pub fee: u64,
    pub change_index: u32,
    pub utxos: Vec<VerifiedUtxo>,
}

/// Human-reviewable facts recomputed from the PSET before signing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewSummary {
    pub network: String,
    pub genesis_hash: String,
    pub policy_asset: String,
    pub recipient_native_address: String,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub change_native_address: Option<String>,
    pub total_input: u64,
    pub input_count: usize,
    pub selected_outpoints: Vec<String>,
}

/// Exact unsigned PSET plus its independently reviewable commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedSend {
    pub pset_base64: String,
    pub review: ReviewSummary,
    pub review_hash: String,
}

/// Final result ready for a separate broadcaster.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedTransaction {
    pub raw_tx_hex: String,
    pub txid: String,
    pub review_hash: String,
}

/// One wallet output the scanner expects to find in an untrusted raw
/// transaction response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedWalletOutput {
    pub vout: u32,
    pub script_pub_key_hex: String,
}

/// Input to the local raw-transaction verification boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawTransactionVerificationRequest {
    pub expected_txid: String,
    pub raw_transaction_hex: String,
    pub expected_wallet_outputs: Vec<ExpectedWalletOutput>,
}

/// A locally decoded, fully explicit output. Atomic amounts stay as `u64` in
/// Rust; the WASM JSON wrapper serializes the same type without floating-point
/// arithmetic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedExplicitOutput {
    pub vout: u32,
    pub script_pub_key_hex: String,
    pub asset_id: String,
    pub value_atomic: u64,
}

/// Result of consensus-decoding and matching requested wallet outputs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedRawTransaction {
    pub txid: String,
    pub outputs: Vec<VerifiedExplicitOutput>,
}

/// Verify an explorer-supplied transaction locally before its outputs can be
/// represented as [`VerifiedUtxo`] values.
///
/// This proves internal txid/output consistency, not chain inclusion or
/// unspent status. Those remain scanner responsibilities.
pub fn verify_raw_transaction(
    request: &RawTransactionVerificationRequest,
) -> Result<VerifiedRawTransaction, WalletError> {
    if request.expected_wallet_outputs.is_empty() {
        return Err(WalletError::RawTransaction(
            "at least one expected wallet output is required".into(),
        ));
    }
    let expected_txid = Txid::from_str(&request.expected_txid)
        .map_err(|_| WalletError::RawTransaction("expected txid is invalid".into()))?;
    let raw = hex::decode(&request.raw_transaction_hex)
        .map_err(|_| WalletError::RawTransaction("raw transaction is not valid hex".into()))?;
    if raw.is_empty() || raw.len() > MAX_RAW_TRANSACTION_BYTES {
        return Err(WalletError::RawTransaction(format!(
            "raw transaction length {} is outside the accepted range",
            raw.len()
        )));
    }
    let tx: Transaction = deserialize(&raw)
        .map_err(|e| WalletError::RawTransaction(format!("consensus decode failed: {e}")))?;
    let actual_txid = tx.txid();
    if actual_txid != expected_txid {
        return Err(WalletError::RawTransaction(format!(
            "txid mismatch: expected {expected_txid}, decoded {actual_txid}"
        )));
    }

    let mut seen = BTreeSet::new();
    let mut outputs = Vec::with_capacity(request.expected_wallet_outputs.len());
    for expected in &request.expected_wallet_outputs {
        if !seen.insert(expected.vout) {
            return Err(WalletError::RawTransaction(format!(
                "duplicate expected vout {}",
                expected.vout
            )));
        }
        let output = tx.output.get(expected.vout as usize).ok_or_else(|| {
            WalletError::RawTransaction(format!("vout {} is out of range", expected.vout))
        })?;
        let expected_script = hex::decode(&expected.script_pub_key_hex)
            .map_err(|_| WalletError::RawTransaction("expected script is invalid hex".into()))?;
        if output.script_pubkey.as_bytes() != expected_script {
            return Err(WalletError::RawTransaction(format!(
                "vout {} script does not match the expected wallet script",
                expected.vout
            )));
        }
        if !output.script_pubkey.is_v0_p2wpkh() {
            return Err(WalletError::RawTransaction(format!(
                "vout {} is not the wallet's P2WPKH script type",
                expected.vout
            )));
        }
        let (Asset::Explicit(asset), Value::Explicit(value), Nonce::Null) =
            (output.asset, output.value, output.nonce)
        else {
            return Err(WalletError::RawTransaction(format!(
                "vout {} has a confidential or missing asset/value/nonce",
                expected.vout
            )));
        };
        outputs.push(VerifiedExplicitOutput {
            vout: expected.vout,
            script_pub_key_hex: hex::encode(output.script_pubkey.as_bytes()),
            asset_id: asset.to_string(),
            value_atomic: value,
        });
    }

    Ok(VerifiedRawTransaction {
        txid: actual_txid.to_string(),
        outputs,
    })
}

#[derive(Clone)]
struct ParsedUtxo {
    outpoint: OutPoint,
    value: u64,
    script: Script,
    public_key: PublicKey,
    path: DerivationPath,
}

/// An in-memory software wallet. Debug output is deliberately not implemented.
pub struct WalletCore {
    signer: SwSigner,
    network: Network,
    network_name: String,
    policy_asset: AssetId,
    genesis_hash: BlockHash,
    native_address_params: &'static AddressParams,
    alias_address_params: &'static AddressParams,
}

impl WalletCore {
    /// Validate an English BIP39 mnemonic including its checksum.
    pub fn validate_mnemonic(mnemonic: &str) -> Result<(), WalletError> {
        Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map(|_| ())
            .map_err(|_| WalletError::InvalidMnemonic)
    }

    /// Generate a 12-word English BIP39 mnemonic from the platform CSPRNG.
    /// Browser builds require the crate's `wasm` feature and Web Crypto support.
    pub fn generate_mnemonic() -> Result<String, WalletError> {
        Mnemonic::generate_in(Language::English, 12)
            .map(|mnemonic| mnemonic.to_string())
            .map_err(|_| WalletError::MnemonicGeneration)
    }

    /// Open an in-memory signer. The mnemonic is never exposed again by this API.
    pub fn new(mnemonic: &str) -> Result<Self, WalletError> {
        Self::new_for_network(
            mnemonic,
            lwk_network(),
            NETWORK_NAME,
            &NATIVE_ADDRESS_PARAMS,
            &AddressParams::ELEMENTS,
        )
    }

    /// Construct the same signing engine for an explicitly supplied Elements
    /// network. This native-only seam exists for funded regtest integration
    /// tests; the browser/WASM API intentionally exposes ECX Alpha only.
    pub fn new_for_network(
        mnemonic: &str,
        network: Network,
        network_name: impl Into<String>,
        native_address_params: &'static AddressParams,
        alias_address_params: &'static AddressParams,
    ) -> Result<Self, WalletError> {
        Self::validate_mnemonic(mnemonic)?;
        let signer = SwSigner::new_with_network(mnemonic, network)
            .map_err(|_| WalletError::InvalidMnemonic)?;
        Ok(Self {
            signer,
            network,
            network_name: network_name.into(),
            policy_asset: *network.policy_asset(),
            genesis_hash: network.genesis_hash(),
            native_address_params,
            alias_address_params,
        })
    }

    /// Derive a native ECX address and the equivalent generic-Elements alias.
    pub fn derive_address(
        &self,
        branch: Branch,
        index: u32,
    ) -> Result<DerivedAddress, WalletError> {
        let path = derivation_path(branch, index)?;
        let public_key = self.derived_pubkey(&path)?;
        let script = p2wpkh_script(&public_key);
        let native = Address::from_script(&script, None, self.native_address_params)
            .ok_or(WalletError::InvalidDerivation)?
            .to_string();
        let alias = Address::from_script(&script, None, self.alias_address_params)
            .ok_or(WalletError::InvalidDerivation)?
            .to_string();

        Ok(DerivedAddress {
            branch,
            index,
            derivation_path: path.to_string(),
            native_address: native,
            lwk_alias: alias,
            script_pubkey_hex: hex::encode(script.as_bytes()),
        })
    }

    /// Deterministically select owned UTXOs and construct an explicit PSET.
    pub fn prepare_send(&self, request: SendRequest) -> Result<PreparedSend, WalletError> {
        if request.amount == 0 || request.fee == 0 {
            return Err(WalletError::ZeroAmount);
        }
        let target = request
            .amount
            .checked_add(request.fee)
            .ok_or(WalletError::AmountOverflow)?;
        let recipient_script = self.parse_recipient(&request.recipient)?;

        let mut candidates = request
            .utxos
            .iter()
            .map(|utxo| self.parse_and_verify_utxo(utxo))
            .collect::<Result<Vec<_>, _>>()?;
        candidates.sort_by_key(|utxo| (utxo.outpoint.txid.to_string(), utxo.outpoint.vout));

        let mut dedupe = BTreeSet::new();
        for utxo in &candidates {
            let key = utxo.outpoint.to_string();
            if !dedupe.insert(key.clone()) {
                return Err(WalletError::DuplicateUtxo(key));
            }
        }

        let mut selected = Vec::new();
        let mut total_input = 0u64;
        for candidate in candidates {
            if total_input >= target {
                break;
            }
            total_input = total_input
                .checked_add(candidate.value)
                .ok_or(WalletError::AmountOverflow)?;
            selected.push(candidate);
        }
        if total_input < target {
            return Err(WalletError::InsufficientFunds {
                needed: target,
                available: total_input,
            });
        }

        let change = total_input - target;
        let mut pset = PartiallySignedTransaction::new_v2();
        for utxo in &selected {
            let mut input = Input::from_prevout(utxo.outpoint);
            input.sequence = Some(Sequence::MAX);
            input.witness_utxo = Some(explicit_output(
                self.policy_asset,
                utxo.value,
                utxo.script.clone(),
            ));
            input.asset = Some(self.policy_asset);
            input.amount = Some(utxo.value);
            input.bip32_derivation.insert(
                utxo.public_key,
                (self.signer.fingerprint(), utxo.path.clone()),
            );
            pset.add_input(input);
        }

        pset.add_output(Output::from_txout(explicit_output(
            self.policy_asset,
            request.amount,
            recipient_script,
        )));

        if change > 0 {
            let change_path = derivation_path(Branch::Change, request.change_index)?;
            let change_key = self.derived_pubkey(&change_path)?;
            let change_script = p2wpkh_script(&change_key);
            let mut output =
                Output::from_txout(explicit_output(self.policy_asset, change, change_script));
            output
                .bip32_derivation
                .insert(change_key, (self.signer.fingerprint(), change_path));
            pset.add_output(output);
        }

        pset.add_output(Output::from_txout(explicit_output(
            self.policy_asset,
            request.fee,
            Script::new(),
        )));
        set_genesis_hash(&mut pset, &self.network);

        let review = self.review_pset(&pset)?;
        let review_hash = self.review_commitment(&pset);
        Ok(PreparedSend {
            pset_base64: pset.to_string(),
            review,
            review_hash,
        })
    }

    /// Recompute all review facts, require explicit approval of the exact PSET,
    /// sign/finalize it, and return raw transaction bytes without broadcasting.
    pub fn sign_prepared(
        &self,
        prepared: &PreparedSend,
        approved_review_hash: &str,
    ) -> Result<SignedTransaction, WalletError> {
        let mut pset = PartiallySignedTransaction::from_str(&prepared.pset_base64)
            .map_err(|e| WalletError::InvalidPset(e.to_string()))?;
        let actual_review = self.review_pset(&pset)?;
        if actual_review != prepared.review {
            return Err(WalletError::ReviewMismatch);
        }
        let actual_hash = self.review_commitment(&pset);
        if actual_hash != prepared.review_hash || actual_hash != approved_review_hash {
            return Err(WalletError::ApprovalMismatch);
        }

        let unsigned_tx = pset
            .extract_tx()
            .map_err(|e| WalletError::InvalidPset(e.to_string()))?;
        let signatures = self
            .signer
            .sign(&mut pset)
            .map_err(|e| WalletError::Signing(e.to_string()))?;
        if signatures as usize != pset.inputs().len() {
            return Err(WalletError::SignatureCount(signatures));
        }

        let secp = Secp256k1::verification_only();
        finalize(&mut pset, &secp, self.genesis_hash)
            .map_err(|e| WalletError::Finalization(e.to_string()))?;
        let tx = pset
            .extract_tx()
            .map_err(|e| WalletError::Finalization(e.to_string()))?;
        self.validate_final_transaction(&unsigned_tx, &tx)?;

        let raw = serialize(&tx);
        let roundtrip: Transaction =
            deserialize(&raw).map_err(|e| WalletError::FinalTransaction(e.to_string()))?;
        if roundtrip != tx {
            return Err(WalletError::FinalTransaction(
                "wire roundtrip changed the transaction".into(),
            ));
        }

        Ok(SignedTransaction {
            raw_tx_hex: hex::encode(raw),
            txid: tx.txid().to_string(),
            review_hash: actual_hash,
        })
    }

    fn parse_and_verify_utxo(&self, utxo: &VerifiedUtxo) -> Result<ParsedUtxo, WalletError> {
        let label = format!("{}:{}", utxo.txid, utxo.vout);
        let invalid = |reason: &str| WalletError::InvalidUtxo {
            outpoint: label.clone(),
            reason: reason.into(),
        };
        let txid = Txid::from_str(&utxo.txid).map_err(|_| invalid("invalid txid"))?;
        if utxo.value == 0 {
            return Err(invalid("zero value"));
        }
        let asset = AssetId::from_str(&utxo.asset_id).map_err(|_| invalid("invalid asset id"))?;
        if asset != self.policy_asset {
            return Err(invalid("not the pinned policy asset"));
        }
        let path = derivation_path(utxo.branch, utxo.index)
            .map_err(|_| invalid("invalid ownership path"))?;
        let public_key = self
            .derived_pubkey(&path)
            .map_err(|_| invalid("key derivation failed"))?;
        let expected_script = p2wpkh_script(&public_key);
        let supplied_script = hex::decode(&utxo.script_pubkey_hex)
            .map(Script::from)
            .map_err(|_| invalid("invalid script hex"))?;
        if supplied_script != expected_script {
            return Err(invalid("script does not match the declared wallet path"));
        }
        Ok(ParsedUtxo {
            outpoint: OutPoint::new(txid, utxo.vout),
            value: utxo.value,
            script: supplied_script,
            public_key,
            path,
        })
    }

    fn review_pset(&self, pset: &PartiallySignedTransaction) -> Result<ReviewSummary, WalletError> {
        validate_minimal_unsigned_pset(pset)?;
        if get_genesis_hash(pset) != Some(self.genesis_hash) {
            return Err(WalletError::InvalidPset(
                "PSET genesis does not match the configured network".into(),
            ));
        }
        preview_explicit_pset(pset, self.policy_asset)
            .map_err(|e| WalletError::InvalidPset(e.to_string()))?;
        if pset.inputs().is_empty() {
            return Err(WalletError::InvalidPset("no inputs".into()));
        }
        if pset.outputs().len() != 2 && pset.outputs().len() != 3 {
            return Err(WalletError::InvalidPset(
                "send must contain recipient, optional change, and fee".into(),
            ));
        }

        let mut total_input = 0u64;
        let mut selected_outpoints = Vec::with_capacity(pset.inputs().len());
        let mut seen = BTreeSet::new();
        for input in pset.inputs() {
            let outpoint = OutPoint::new(input.previous_txid, input.previous_output_index);
            let outpoint_label = outpoint.to_string();
            if !seen.insert(outpoint_label.clone()) {
                return Err(WalletError::DuplicateUtxo(outpoint_label));
            }
            let witness = input
                .witness_utxo
                .as_ref()
                .ok_or_else(|| WalletError::InvalidPset("input lacks witness UTXO".into()))?;
            let (Asset::Explicit(asset), Value::Explicit(value), Nonce::Null) =
                (witness.asset, witness.value, witness.nonce)
            else {
                return Err(WalletError::InvalidPset(
                    "input UTXO is not fully explicit".into(),
                ));
            };
            if asset != self.policy_asset
                || input.asset != Some(asset)
                || input.amount != Some(value)
                || !witness.script_pubkey.is_v0_p2wpkh()
            {
                return Err(WalletError::InvalidPset(
                    "input asset, amount, or script is inconsistent".into(),
                ));
            }
            if input.bip32_derivation.len() != 1 {
                return Err(WalletError::InvalidPset(
                    "input must have exactly one ownership path".into(),
                ));
            }
            let (public_key, (fingerprint, path)) = input
                .bip32_derivation
                .iter()
                .next()
                .expect("length checked");
            if *fingerprint != self.signer.fingerprint()
                || self.derived_pubkey(path)? != *public_key
                || p2wpkh_script(public_key) != witness.script_pubkey
                || !is_wallet_path(path)
            {
                return Err(WalletError::InvalidPset(
                    "input ownership proof does not match this wallet".into(),
                ));
            }
            total_input = total_input
                .checked_add(value)
                .ok_or(WalletError::AmountOverflow)?;
            selected_outpoints.push(outpoint_label);
        }

        let recipient = &pset.outputs()[0];
        let recipient_amount = recipient
            .amount
            .ok_or_else(|| WalletError::InvalidPset("recipient amount missing".into()))?;
        if recipient_amount == 0
            || recipient.script_pubkey.is_empty()
            || recipient.asset != Some(self.policy_asset)
        {
            return Err(WalletError::InvalidPset("invalid recipient output".into()));
        }
        let recipient_native_address =
            native_address(&recipient.script_pubkey, self.native_address_params)?;

        let fee_output = pset
            .outputs()
            .last()
            .ok_or_else(|| WalletError::InvalidPset("fee output missing".into()))?;
        if !fee_output.script_pubkey.is_empty()
            || fee_output.asset != Some(self.policy_asset)
            || fee_output.amount.unwrap_or(0) == 0
        {
            return Err(WalletError::InvalidPset("invalid fee output".into()));
        }
        let fee = fee_output.amount.expect("checked");

        let (change, change_native_address) = if pset.outputs().len() == 3 {
            let output = &pset.outputs()[1];
            let amount = output
                .amount
                .ok_or_else(|| WalletError::InvalidPset("change amount missing".into()))?;
            if amount == 0
                || output.asset != Some(self.policy_asset)
                || output.bip32_derivation.len() != 1
            {
                return Err(WalletError::InvalidPset("invalid change output".into()));
            }
            let (public_key, (fingerprint, path)) = output
                .bip32_derivation
                .iter()
                .next()
                .expect("length checked");
            if *fingerprint != self.signer.fingerprint()
                || self.derived_pubkey(path)? != *public_key
                || p2wpkh_script(public_key) != output.script_pubkey
                || !is_change_path(path)
            {
                return Err(WalletError::InvalidPset(
                    "change does not belong to the wallet change branch".into(),
                ));
            }
            (
                amount,
                Some(native_address(
                    &output.script_pubkey,
                    self.native_address_params,
                )?),
            )
        } else {
            (0, None)
        };

        let total_output = recipient_amount
            .checked_add(change)
            .and_then(|v| v.checked_add(fee))
            .ok_or(WalletError::AmountOverflow)?;
        if total_input != total_output {
            return Err(WalletError::InvalidPset(format!(
                "policy asset is not conserved: inputs {total_input}, outputs {total_output}"
            )));
        }

        Ok(ReviewSummary {
            network: self.network_name.clone(),
            genesis_hash: self.genesis_hash.to_string(),
            policy_asset: self.policy_asset.to_string(),
            recipient_native_address,
            amount: recipient_amount,
            fee,
            change,
            change_native_address,
            total_input,
            input_count: pset.inputs().len(),
            selected_outpoints,
        })
    }

    fn derived_pubkey(&self, path: &DerivationPath) -> Result<PublicKey, WalletError> {
        self.signer
            .derive_xpub(path)
            .map(|xpub| PublicKey::new(xpub.public_key))
            .map_err(|_| WalletError::InvalidDerivation)
    }

    fn validate_final_transaction(
        &self,
        unsigned: &Transaction,
        signed: &Transaction,
    ) -> Result<(), WalletError> {
        validate_explicit_transaction(signed)
            .map_err(|e| WalletError::FinalTransaction(e.to_string()))?;
        if unsigned.version != signed.version
            || unsigned.lock_time != signed.lock_time
            || unsigned.output != signed.output
            || unsigned.input.len() != signed.input.len()
        {
            return Err(WalletError::FinalTransaction(
                "signing changed non-witness transaction data".into(),
            ));
        }
        for (before, after) in unsigned.input.iter().zip(&signed.input) {
            if before.previous_output != after.previous_output
                || before.sequence != after.sequence
                || before.is_pegin != after.is_pegin
                || before.asset_issuance != after.asset_issuance
                || !after.script_sig.is_empty()
                || after.witness.script_witness.len() != 2
            {
                return Err(WalletError::FinalTransaction(
                    "final input structure is not the expected P2WPKH spend".into(),
                ));
            }
        }
        Ok(())
    }

    fn parse_recipient(&self, recipient: &str) -> Result<Script, WalletError> {
        if recipient != recipient.to_ascii_lowercase() {
            return Err(WalletError::InvalidRecipient(
                "address must use canonical lowercase encoding",
            ));
        }
        let (hrp, version, program) = segwit::decode(recipient)
            .map_err(|_| WalletError::InvalidRecipient("invalid bech32 address"))?;
        if (hrp != self.native_address_params.bech_hrp && hrp != self.alias_address_params.bech_hrp)
            || version != segwit::VERSION_0
            || program.len() != 20
        {
            return Err(WalletError::InvalidRecipient(
                "only configured unconfidential P2WPKH addresses are supported",
            ));
        }
        let mut bytes = Vec::with_capacity(22);
        bytes.push(0);
        bytes.push(20);
        bytes.extend(program);
        Ok(Script::from(bytes))
    }

    fn review_commitment(&self, pset: &PartiallySignedTransaction) -> String {
        let mut engine = sha256::Hash::engine();
        engine.input(REVIEW_DOMAIN);
        engine.input(self.genesis_hash.as_ref());
        engine.input(&self.policy_asset.into_inner().to_byte_array());
        engine.input(&serialize(pset));
        sha256::Hash::from_engine(engine).to_string()
    }
}

fn derivation_path(branch: Branch, index: u32) -> Result<DerivationPath, WalletError> {
    // BIP32 forbids indices with the hardened bit set in a normal child.
    if index >= (1 << 31) {
        return Err(WalletError::InvalidDerivation);
    }
    DerivationPath::from_str(&format!(
        "{DERIVATION_ACCOUNT}/{}/{}",
        branch.number(),
        index
    ))
    .map_err(|_| WalletError::InvalidDerivation)
}

fn is_wallet_path(path: &DerivationPath) -> bool {
    derivation_path_from_existing(path)
        .map(|(branch, _)| branch == Branch::External || branch == Branch::Change)
        .unwrap_or(false)
}

fn is_change_path(path: &DerivationPath) -> bool {
    derivation_path_from_existing(path)
        .map(|(branch, _)| branch == Branch::Change)
        .unwrap_or(false)
}

fn derivation_path_from_existing(path: &DerivationPath) -> Option<(Branch, u32)> {
    let children = path.as_ref();
    if children.len() != 5 {
        return None;
    }
    let branch = match children[3] {
        elements::bitcoin::bip32::ChildNumber::Normal { index: 0 } => Branch::External,
        elements::bitcoin::bip32::ChildNumber::Normal { index: 1 } => Branch::Change,
        _ => return None,
    };
    let index = match children[4] {
        elements::bitcoin::bip32::ChildNumber::Normal { index } => index,
        _ => return None,
    };
    if derivation_path(branch, index).ok().as_ref() == Some(path) {
        Some((branch, index))
    } else {
        None
    }
}

fn p2wpkh_script(public_key: &PublicKey) -> Script {
    Script::new_v0_wpkh(&WPubkeyHash::hash(&public_key.to_bytes()))
}

fn explicit_output(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn validate_minimal_unsigned_pset(pset: &PartiallySignedTransaction) -> Result<(), WalletError> {
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
        return Err(WalletError::InvalidPset(
            "unsupported or mutable global PSET fields".into(),
        ));
    }

    let unsigned = pset
        .extract_tx()
        .map_err(|e| WalletError::InvalidPset(e.to_string()))?;
    if unsigned.version != 2 || unsigned.lock_time != elements::LockTime::ZERO {
        return Err(WalletError::InvalidPset(
            "transaction version or locktime is unsupported".into(),
        ));
    }
    for (map, input) in pset.inputs().iter().zip(&unsigned.input) {
        if map.sequence != Some(Sequence::MAX)
            || map.non_witness_utxo.is_some()
            || !map.partial_sigs.is_empty()
            || map.sighash_type.is_some()
            || map.redeem_script.is_some()
            || map.witness_script.is_some()
            || map.final_script_sig.is_some()
            || map.final_script_witness.is_some()
            || map.required_time_locktime.is_some()
            || map.required_height_locktime.is_some()
            || map.tap_key_sig.is_some()
            || !map.tap_script_sigs.is_empty()
            || !map.tap_scripts.is_empty()
            || !map.tap_key_origins.is_empty()
            || map.tap_internal_key.is_some()
            || map.tap_merkle_root.is_some()
            || map.issuance_value_amount.is_some()
            || map.issuance_value_comm.is_some()
            || map.issuance_value_rangeproof.is_some()
            || map.issuance_keys_rangeproof.is_some()
            || map.pegin_tx.is_some()
            || map.pegin_txout_proof.is_some()
            || map.pegin_genesis_hash.is_some()
            || map.pegin_claim_script.is_some()
            || map.pegin_value.is_some()
            || map.pegin_witness.is_some()
            || map.issuance_inflation_keys.is_some()
            || map.issuance_inflation_keys_comm.is_some()
            || map.issuance_blinding_nonce.is_some()
            || map.issuance_asset_entropy.is_some()
            || map.in_utxo_rangeproof.is_some()
            || map.in_issuance_blind_value_proof.is_some()
            || map.in_issuance_blind_inflation_keys_proof.is_some()
            || map.blind_value_proof.is_some()
            || map.blind_asset_proof.is_some()
            || map.blinded_issuance.is_some()
            || !map.proprietary.is_empty()
            || !map.unknown.is_empty()
            || input.is_pegin
            || !input.asset_issuance.is_null()
            || !input.script_sig.is_empty()
            || input.witness != TxInWitness::default()
        {
            return Err(WalletError::InvalidPset(
                "input contains unsupported signing, issuance, peg-in, proof, or script fields"
                    .into(),
            ));
        }
    }
    for output in pset.outputs() {
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
            return Err(WalletError::InvalidPset(
                "output contains unsupported scripts, proofs, or metadata".into(),
            ));
        }
    }
    Ok(())
}

fn native_address(
    script: &Script,
    address_params: &'static AddressParams,
) -> Result<String, WalletError> {
    Address::from_script(script, None, address_params)
        .filter(|address| !address.is_blinded() && script.is_v0_p2wpkh())
        .map(|address| address.to_string())
        .ok_or(WalletError::InvalidPset(
            "only unconfidential P2WPKH outputs are supported".into(),
        ))
}

#[cfg(feature = "wasm")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Thin JSON boundary for MV3 offscreen-document integration. Amounts in
    /// production callers should stay below JavaScript's safe integer ceiling;
    /// the native Rust API remains the authoritative typed boundary.
    #[wasm_bindgen]
    pub struct WasmWalletCore {
        inner: WalletCore,
    }

    #[wasm_bindgen]
    impl WasmWalletCore {
        #[wasm_bindgen(constructor)]
        pub fn new(mnemonic: &str) -> Result<WasmWalletCore, JsValue> {
            WalletCore::new(mnemonic)
                .map(|inner| Self { inner })
                .map_err(js_error)
        }

        pub fn derive_address_json(&self, branch: &str, index: u32) -> Result<String, JsValue> {
            let branch = match branch {
                "external" => Branch::External,
                "change" => Branch::Change,
                _ => return Err(JsValue::from_str("invalid branch")),
            };
            let value = self.inner.derive_address(branch, index).map_err(js_error)?;
            serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
        }

        pub fn prepare_send_json(&self, request_json: &str) -> Result<String, JsValue> {
            let request = serde_json::from_str(request_json)
                .map_err(|e| JsValue::from_str(&format!("invalid request JSON: {e}")))?;
            let value = self.inner.prepare_send(request).map_err(js_error)?;
            serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
        }

        pub fn sign_prepared_json(
            &self,
            prepared_json: &str,
            approved_review_hash: &str,
        ) -> Result<String, JsValue> {
            let prepared = serde_json::from_str(prepared_json)
                .map_err(|e| JsValue::from_str(&format!("invalid prepared JSON: {e}")))?;
            let value = self
                .inner
                .sign_prepared(&prepared, approved_review_hash)
                .map_err(js_error)?;
            serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
        }

        pub fn verify_raw_transaction_json(&self, request_json: &str) -> Result<String, JsValue> {
            let request = serde_json::from_str(request_json)
                .map_err(|e| JsValue::from_str(&format!("invalid verification JSON: {e}")))?;
            let value = verify_raw_transaction(&request).map_err(js_error)?;
            serde_json::to_string(&value).map_err(|e| JsValue::from_str(&e.to_string()))
        }
    }

    #[wasm_bindgen]
    pub fn validate_mnemonic(mnemonic: &str) -> bool {
        WalletCore::validate_mnemonic(mnemonic).is_ok()
    }

    #[wasm_bindgen]
    pub fn generate_mnemonic() -> Result<String, JsValue> {
        WalletCore::generate_mnemonic().map_err(js_error)
    }

    fn js_error(error: WalletError) -> JsValue {
        JsValue::from_str(&error.to_string())
    }
}
