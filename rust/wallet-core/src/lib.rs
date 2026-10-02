//! A deliberately narrow signing core for an ECX Alpha browser wallet.
//!
//! The crate owns no network client and trusts no explorer response by itself.
//! A caller supplies UTXOs that it has independently verified; this core then
//! verifies that they are explicit P2WPKH outputs owned by the mnemonic,
//! constructs a deterministic PSET, recomputes a single [`TxReview`] from the
//! PSET, binds the exact PSET and review to a review hash, signs only after
//! that hash is approved, finalizes, and validates the resulting transaction.
//! Scanning and broadcasting stay outside this security boundary.
//!
//! Supported operations (spec §1.2): multi-asset transfers, explicit asset
//! issuance, offer splits, LiquiDEX-style explicit swap offers (maker) and
//! takes (taker), and offer cancellation.
//!
//! Confidential transactions (see [`confidential`]): the wallet derives a
//! SLIP-77 master blinding key, can hand out confidential receive addresses
//! (off by default, [`WalletCore::set_confidential_receive`]), unblinds its own
//! confidential outputs, and spends them in transfers, issuances, offer splits,
//! and cancels. Swap offers and takes remain explicit-only.

use std::collections::BTreeSet;
use std::str::FromStr;

use bech32::segwit;
use elements::bitcoin::bip32::{ChildNumber, DerivationPath};
use elements::bitcoin::PublicKey;
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::deserialize;
use elements::hashes::Hash;
use elements::secp256k1_zkp::{All, PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use elements::{
    Address, AddressParams, AssetId, BlockHash, OutPoint, Script, Transaction, TxOut, TxOutWitness,
    Txid, WPubkeyHash,
};
use elements_miniscript::slip77::MasterBlindingKey;
use elementsplus_lwk_adapter::{lwk_network, NATIVE_ADDRESS_PARAMS};
pub use elementsplus_lwk_adapter::{GENESIS_HASH, NETWORK_NAME, POLICY_ASSET};
#[cfg(feature = "regtest")]
use lwk_common::ElementsParamsBuilder;
use lwk_common::{Network, Signer};
use lwk_signer::bip39::{Language, Mnemonic};
use lwk_signer::SwSigner;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod amount;
mod build;
pub mod confidential;
pub mod issuance;
pub mod offer;
mod review;
mod sign;
#[cfg(feature = "wasm")]
mod wasm;

pub use build::{
    CancelRequest, IssuanceRequest, OfferInput, OfferSplitRequest, SwapOfferRequest,
    TakeOfferInput, TakeSwapOffersRequest, TransferRequest, MAX_FEE_RATE, POLICY_DUST_LIMIT,
};
pub use confidential::UtxoBlinding;
pub use issuance::{
    verify_asset_issuance, AssetContract, AssetIssuanceVerificationRequest, VerifiedAssetIssuance,
    MAX_MONEY,
};
pub use offer::{DecodedOffer, Offer, OfferLeg, OFFER_NETWORK, OFFER_VERSION};
pub use review::{
    AssetDelta, ExternalOutput, IssuanceReview, PreparedTx, SignedResult, TxKind, TxReview,
    SIGHASH_ALL, SIGHASH_SINGLE_ACP,
};

/// The sole derivation scheme supported by this core.
pub const DERIVATION_ACCOUNT: &str = "m/84'/1'/0'";
/// Domain separator for review commitments. Changing review semantics requires
/// a new version rather than silently reusing an approval.
pub const REVIEW_DOMAIN: &[u8] = b"ECX_ALPHA_TX_REVIEW_V2\0";
/// Hard ceiling for untrusted raw transaction responses passed into WASM.
pub const MAX_RAW_TRANSACTION_BYTES: usize = 4_000_000;
/// Hard ceiling for request JSON accepted by the WASM boundary.
pub const MAX_REQUEST_JSON_BYTES: usize = 8_000_000;

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
    #[error("amount must be non-zero")]
    ZeroAmount,
    #[error("amount overflow")]
    AmountOverflow,
    #[error("invalid fee rate: {0}")]
    InvalidFeeRate(String),
    #[error("insufficient funds for asset {asset}: need {needed}, have {available}")]
    InsufficientFunds {
        asset: String,
        needed: u64,
        available: u64,
    },
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("PSET is malformed: {0}")]
    InvalidPset(String),
    #[error("review summary does not match the PSET")]
    ReviewMismatch,
    #[error("approved review hash does not match the PSET")]
    ApprovalMismatch,
    #[error("signer produced {actual} signature(s), expected {expected}")]
    SignatureCount { actual: u32, expected: usize },
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("finalization failed: {0}")]
    Finalization(String),
    #[error("final transaction violates wallet policy: {0}")]
    FinalTransaction(String),
    #[error("raw transaction verification failed: {0}")]
    RawTransaction(String),
    #[error("swap offer rejected: {0}")]
    Offer(String),
    #[error("asset issuance rejected: {0}")]
    Issuance(String),
    #[error("JSON request is invalid: {0}")]
    Json(String),
    #[error("confidential funds rejected: {0}")]
    Confidential(String),
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

/// A derived P2WPKH address. Both unconfidential strings encode exactly the
/// same script; the confidential fields (present only when a confidential
/// address was requested) add this script's SLIP-77 blinding public key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivedAddress {
    pub branch: Branch,
    pub index: u32,
    pub derivation_path: String,
    pub native_address: String,
    pub lwk_alias: String,
    pub script_pubkey_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidential_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidential_lwk_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinding_pubkey_hex: Option<String>,
}

/// A UTXO supplied by a chain source outside this crate.
///
/// "Verified" means the caller has verified existence, confirmation status,
/// and non-spent status. This core still verifies the asset id syntax,
/// amount, script, ownership path, duplicates, and all transaction
/// conservation rules. Any explicit asset is accepted.
///
/// A confidential UTXO additionally carries `blinding` exactly as returned by
/// [`WalletCore::verify_raw_transaction`]; `value` and `asset_id` are then the
/// unblinded values, and the core re-opens the commitments before spending.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedUtxo {
    pub txid: String,
    pub vout: u32,
    #[serde(with = "amount::string")]
    pub value: u64,
    pub asset_id: String,
    pub script_pubkey_hex: String,
    pub branch: Branch,
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinding: Option<UtxoBlinding>,
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

/// A locally decoded wallet output: fully explicit, or (only through
/// [`WalletCore::verify_raw_transaction`]) confidential and unblinded with
/// this wallet's key, in which case `blinding` holds its commitments and
/// blinders.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedExplicitOutput {
    pub vout: u32,
    pub script_pub_key_hex: String,
    pub asset_id: String,
    pub value_atomic: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinding: Option<UtxoBlinding>,
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
    verify_raw_transaction_with(request, None)
}

fn verify_raw_transaction_with(
    request: &RawTransactionVerificationRequest,
    unblinder: Option<&WalletCore>,
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
        let (asset, value, blinding) = match (output.asset, output.value, output.nonce) {
            (Asset::Explicit(asset), Value::Explicit(value), Nonce::Null) => (asset, value, None),
            (Asset::Confidential(_), Value::Confidential(_), Nonce::Confidential(_))
                if unblinder.is_some() =>
            {
                let core = unblinder.expect("checked by the guard");
                let (asset, value, blinding) =
                    core.unblind_wallet_output(output).map_err(|reason| {
                        WalletError::RawTransaction(format!("vout {}: {reason}", expected.vout))
                    })?;
                if value == 0 || value > MAX_MONEY {
                    return Err(WalletError::RawTransaction(format!(
                        "vout {} value is outside the money range",
                        expected.vout
                    )));
                }
                (asset, value, Some(blinding))
            }
            _ => {
                return Err(WalletError::RawTransaction(format!(
                    "vout {} has a confidential or missing asset/value/nonce",
                    expected.vout
                )));
            }
        };
        outputs.push(VerifiedExplicitOutput {
            vout: expected.vout,
            script_pub_key_hex: hex::encode(output.script_pubkey.as_bytes()),
            asset_id: asset.to_string(),
            value_atomic: value,
            blinding,
        });
    }

    Ok(VerifiedRawTransaction {
        txid: actual_txid.to_string(),
        outputs,
    })
}

/// Decode and verify a swap offer for the pinned ECX Alpha network.
///
/// The funding transaction is supplied separately and must hash to the
/// offered input's txid; the maker's `SIGHASH_SINGLE|ANYONECANPAY` signature
/// is verified against the recomputed segwit v0 sighash.
pub fn decode_offer(
    offer_json: &str,
    prevout_raw_tx_hex: &str,
) -> Result<DecodedOffer, WalletError> {
    let offer = offer::parse_offer_json(offer_json)?;
    let genesis = BlockHash::from_str(GENESIS_HASH).expect("frozen genesis hash");
    offer::verify_offer(&offer, prevout_raw_tx_hex, genesis, &NATIVE_ADDRESS_PARAMS)
        .map(|verified| verified.decoded)
}

#[derive(Clone)]
pub(crate) struct ParsedUtxo {
    pub outpoint: OutPoint,
    pub asset: AssetId,
    pub value: u64,
    pub script: Script,
    pub public_key: PublicKey,
    pub path: DerivationPath,
    /// Present for a confidential UTXO whose blinders open its commitments.
    pub blinding: Option<confidential::OpenedBlinding>,
}

/// A parsed recipient: its script and, for a confidential address, the
/// receiver's blinding public key.
pub(crate) struct Recipient {
    pub script: Script,
    pub blinding_key: Option<SecpPublicKey>,
}

/// An in-memory software wallet. Debug output is deliberately not implemented.
pub struct WalletCore {
    pub(crate) signer: SwSigner,
    pub(crate) secp: Secp256k1<All>,
    pub(crate) master_blinding_key: MasterBlindingKey,
    /// Whether default receive addresses are confidential. Off by default.
    pub(crate) confidential_receive: bool,
    pub(crate) network: Network,
    pub(crate) network_name: String,
    pub(crate) policy_asset: AssetId,
    pub(crate) genesis_hash: BlockHash,
    pub(crate) native_address_params: &'static AddressParams,
    pub(crate) alias_address_params: &'static AddressParams,
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
    /// tests; the production browser/WASM API exposes ECX Alpha only.
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
        let master_blinding_key = signer
            .slip77_master_blinding_key()
            .map_err(|_| WalletError::InvalidMnemonic)?;
        Ok(Self {
            signer,
            secp: Secp256k1::new(),
            master_blinding_key,
            confidential_receive: false,
            network,
            network_name: network_name.into(),
            policy_asset: *network.policy_asset(),
            genesis_hash: network.genesis_hash(),
            native_address_params,
            alias_address_params,
        })
    }

    /// Construct a wallet for a disposable regtest chain (feature `regtest`).
    #[cfg(feature = "regtest")]
    pub fn new_for_regtest(
        mnemonic: &str,
        genesis_hash: &str,
        policy_asset: &str,
        display_name: &str,
    ) -> Result<Self, WalletError> {
        let genesis_hash = BlockHash::from_str(genesis_hash)
            .map_err(|_| WalletError::InvalidRequest("invalid regtest genesis hash".into()))?;
        let policy_asset = AssetId::from_str(policy_asset)
            .map_err(|_| WalletError::InvalidRequest("invalid regtest policy asset".into()))?;
        let parent_genesis = Network::default_regtest().parent_genesis_hash();
        let network = Network::CustomElements(
            ElementsParamsBuilder::new()
                .with_genesis_hash(genesis_hash)
                .with_policy_asset(policy_asset)
                .with_parent_genesis_hash(parent_genesis)
                .build()
                .map_err(|_| {
                    WalletError::InvalidRequest("invalid regtest network parameters".into())
                })?,
        );
        Self::new_for_network(
            mnemonic,
            network,
            display_name,
            &AddressParams::ELEMENTS,
            &AddressParams::ELEMENTS,
        )
    }

    /// The configured policy (fee) asset.
    pub fn policy_asset(&self) -> AssetId {
        self.policy_asset
    }

    /// The configured genesis hash.
    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis_hash
    }

    /// Whether default receive addresses are confidential.
    pub fn confidential_receive(&self) -> bool {
        self.confidential_receive
    }

    /// Enable or disable confidential default receive addresses. This only
    /// changes address derivation; confidential outputs that unblind with
    /// this wallet's key are always recognised and spendable.
    pub fn set_confidential_receive(&mut self, enabled: bool) {
        self.confidential_receive = enabled;
    }

    /// Derive a native address and the equivalent generic-Elements alias,
    /// confidential only when confidential receive is enabled.
    pub fn derive_address(
        &self,
        branch: Branch,
        index: u32,
    ) -> Result<DerivedAddress, WalletError> {
        self.derive_address_with(branch, index, None)
    }

    /// Derive an address; `confidential` overrides the wallet default.
    pub fn derive_address_with(
        &self,
        branch: Branch,
        index: u32,
        confidential: Option<bool>,
    ) -> Result<DerivedAddress, WalletError> {
        let path = derivation_path(branch, index)?;
        let public_key = self.derived_pubkey(&path)?;
        let script = p2wpkh_script(&public_key);
        let encode = |blinder: Option<SecpPublicKey>, params: &'static AddressParams| {
            Address::from_script(&script, blinder, params)
                .map(|address| address.to_string())
                .ok_or(WalletError::InvalidDerivation)
        };
        let native = encode(None, self.native_address_params)?;
        let alias = encode(None, self.alias_address_params)?;
        let (confidential_address, confidential_lwk_alias, blinding_pubkey_hex) =
            if confidential.unwrap_or(self.confidential_receive) {
                let blinder = self.blinding_public_key(&script);
                (
                    Some(encode(Some(blinder), self.native_address_params)?),
                    Some(encode(Some(blinder), self.alias_address_params)?),
                    Some(hex::encode(blinder.serialize())),
                )
            } else {
                (None, None, None)
            };

        Ok(DerivedAddress {
            branch,
            index,
            derivation_path: path.to_string(),
            native_address: native,
            lwk_alias: alias,
            script_pubkey_hex: hex::encode(script.as_bytes()),
            confidential_address,
            confidential_lwk_alias,
            blinding_pubkey_hex,
        })
    }

    /// SLIP-77 blinding public key of a wallet script.
    pub(crate) fn blinding_public_key(&self, script: &Script) -> SecpPublicKey {
        self.master_blinding_key.blinding_key(&self.secp, script)
    }

    pub(crate) fn blinding_private_key(&self, script: &Script) -> SecretKey {
        self.master_blinding_key.blinding_private_key(script)
    }

    /// Verify an explorer-supplied transaction like [`verify_raw_transaction`],
    /// additionally accepting confidential wallet outputs that unblind with
    /// this wallet's SLIP-77 key. A confidential output that does not unblind
    /// (blinded to another key, bad rangeproof, inconsistent asset
    /// commitment) is refused, so the whole verification fails closed.
    pub fn verify_raw_transaction(
        &self,
        request: &RawTransactionVerificationRequest,
    ) -> Result<VerifiedRawTransaction, WalletError> {
        verify_raw_transaction_with(request, Some(self))
    }

    /// Unblind one confidential wallet output with the script's blinding key.
    pub(crate) fn unblind_wallet_output(
        &self,
        output: &TxOut,
    ) -> Result<(AssetId, u64, UtxoBlinding), String> {
        let (Asset::Confidential(generator), Value::Confidential(commitment)) =
            (output.asset, output.value)
        else {
            return Err("output is not fully confidential".into());
        };
        if output.witness.surjection_proof.is_none() || output.witness.rangeproof.is_none() {
            return Err("confidential output lacks its rangeproof or surjection proof".into());
        }
        let secrets = output
            .unblind(&self.secp, self.blinding_private_key(&output.script_pubkey))
            .map_err(|e| format!("does not unblind with this wallet's blinding key: {e}"))?;
        let blinding = UtxoBlinding::from_parts(generator, commitment, &secrets);
        // Defence in depth: the recovered secrets must re-open both commitments.
        blinding
            .open(&self.secp, secrets.asset, secrets.value)
            .map_err(str::to_owned)?;
        Ok((secrets.asset, secrets.value, blinding))
    }

    /// Decode and verify an offer for this wallet's configured network.
    pub fn decode_offer(
        &self,
        offer_json: &str,
        prevout_raw_tx_hex: &str,
    ) -> Result<DecodedOffer, WalletError> {
        let offer = offer::parse_offer_json(offer_json)?;
        offer::verify_offer(
            &offer,
            prevout_raw_tx_hex,
            self.genesis_hash,
            self.native_address_params,
        )
        .map(|verified| verified.decoded)
    }

    pub(crate) fn parse_and_verify_utxo(
        &self,
        utxo: &VerifiedUtxo,
    ) -> Result<ParsedUtxo, WalletError> {
        let label = format!("{}:{}", utxo.txid, utxo.vout);
        let invalid = |reason: &str| WalletError::InvalidUtxo {
            outpoint: label.clone(),
            reason: reason.into(),
        };
        let txid = Txid::from_str(&utxo.txid).map_err(|_| invalid("invalid txid"))?;
        if utxo.value == 0 {
            return Err(invalid("zero value"));
        }
        if utxo.value > MAX_MONEY {
            return Err(invalid("value exceeds the money range"));
        }
        let asset = AssetId::from_str(&utxo.asset_id).map_err(|_| invalid("invalid asset id"))?;
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
        let blinding = utxo
            .blinding
            .as_ref()
            .map(|blinding| blinding.open(&self.secp, asset, utxo.value))
            .transpose()
            .map_err(invalid)?;
        Ok(ParsedUtxo {
            outpoint: OutPoint::new(txid, utxo.vout),
            asset,
            value: utxo.value,
            script: supplied_script,
            public_key,
            path,
            blinding,
        })
    }

    pub(crate) fn derived_pubkey(&self, path: &DerivationPath) -> Result<PublicKey, WalletError> {
        self.signer
            .derive_xpub(path)
            .map(|xpub| PublicKey::new(xpub.public_key))
            .map_err(|_| WalletError::InvalidDerivation)
    }

    /// Script, pubkey, and path of a wallet address.
    pub(crate) fn wallet_key(
        &self,
        branch: Branch,
        index: u32,
    ) -> Result<(Script, PublicKey, DerivationPath), WalletError> {
        let path = derivation_path(branch, index)?;
        let key = self.derived_pubkey(&path)?;
        Ok((p2wpkh_script(&key), key, path))
    }

    /// Parse an unconfidential P2WPKH address or, for the configured
    /// networks, a confidential (blech32) P2WPKH address.
    pub(crate) fn parse_recipient(&self, recipient: &str) -> Result<Recipient, WalletError> {
        if recipient != recipient.to_ascii_lowercase() {
            return Err(WalletError::InvalidRecipient(
                "address must use canonical lowercase encoding",
            ));
        }
        for params in [self.native_address_params, self.alias_address_params] {
            let prefix = format!("{}1", params.blech_hrp);
            if !recipient.starts_with(&prefix) {
                continue;
            }
            let address = Address::parse_with_params(recipient, params)
                .map_err(|_| WalletError::InvalidRecipient("invalid confidential address"))?;
            let script = address.script_pubkey();
            let Some(blinding_key) = address.blinding_pubkey else {
                return Err(WalletError::InvalidRecipient(
                    "invalid confidential address",
                ));
            };
            if !script.is_v0_p2wpkh() {
                return Err(WalletError::InvalidRecipient(
                    "only confidential P2WPKH addresses are supported",
                ));
            }
            return Ok(Recipient {
                script,
                blinding_key: Some(blinding_key),
            });
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
        Ok(Recipient {
            script: Script::from(bytes),
            blinding_key: None,
        })
    }
}

pub(crate) fn derivation_path(branch: Branch, index: u32) -> Result<DerivationPath, WalletError> {
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

/// Accept only paths of the exact form `m/84'/1'/0'/{0,1}/i`.
pub(crate) fn is_wallet_path(path: &DerivationPath) -> bool {
    let children = path.as_ref();
    if children.len() != 5 {
        return false;
    }
    let branch = match children[3] {
        ChildNumber::Normal { index: 0 } => Branch::External,
        ChildNumber::Normal { index: 1 } => Branch::Change,
        _ => return false,
    };
    let ChildNumber::Normal { index } = children[4] else {
        return false;
    };
    derivation_path(branch, index).ok().as_ref() == Some(path)
}

pub(crate) fn p2wpkh_script(public_key: &PublicKey) -> Script {
    Script::new_v0_wpkh(&WPubkeyHash::hash(&public_key.to_bytes()))
}

pub(crate) fn explicit_output(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

/// `txid:vout`. `OutPoint`'s `Display` adds an `[elements]` prefix.
pub(crate) fn outpoint_label(outpoint: &OutPoint) -> String {
    format!("{}:{}", outpoint.txid, outpoint.vout)
}
