//! Explicit LiquiDEX-style swap offers (spec §2).

use std::str::FromStr;

use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::{hash160, Hash};
use elements::secp256k1_zkp::{ecdsa, Message, PublicKey as SecpPublicKey, Secp256k1};
use elements::sighash::SighashCache;
use elements::{
    Address, AddressParams, AssetId, BlockHash, EcdsaSighashType, OutPoint, PubkeyHash, Script,
    Sequence, Transaction, TxOut,
};
use serde::{Deserialize, Serialize};

use crate::{WalletError, MAX_RAW_TRANSACTION_BYTES};

// The `network` field of every offer is the maker's network profile id
// (`crate::network::NetworkProfile::id`, e.g. `ecx-beta`); consumers match it
// together with `genesis_hash`.
pub const OFFER_VERSION: u32 = 1;
/// Offers are tiny; anything larger is refused before decoding.
pub const MAX_OFFER_JSON_BYTES: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfferLeg {
    pub asset_id: String,
    #[serde(with = "crate::amount::string")]
    pub amount: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub version: u32,
    pub network: String,
    pub genesis_hash: String,
    pub tx: String,
    pub give: OfferLeg,
    pub want: OfferLeg,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecodedOffer {
    pub give_asset: String,
    #[serde(with = "crate::amount::string")]
    pub give_amount: u64,
    pub want_asset: String,
    #[serde(with = "crate::amount::string")]
    pub want_amount: u64,
    pub outpoint: String,
    pub maker_address: String,
}

/// A fully verified offer, ready to be placed into a taker PSET.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedOffer {
    pub tx: Transaction,
    pub prevout: TxOut,
    pub give_asset: AssetId,
    pub give_amount: u64,
    pub want_asset: AssetId,
    pub want_amount: u64,
    pub decoded: DecodedOffer,
}

fn offer_error(reason: impl Into<String>) -> WalletError {
    WalletError::Offer(reason.into())
}

pub(crate) fn parse_offer_json(offer_json: &str) -> Result<Offer, WalletError> {
    if offer_json.len() > MAX_OFFER_JSON_BYTES {
        return Err(offer_error("offer JSON is too large"));
    }
    serde_json::from_str(offer_json).map_err(|e| offer_error(format!("invalid offer JSON: {e}")))
}

pub(crate) fn explicit_parts(output: &TxOut) -> Option<(AssetId, u64)> {
    match (output.asset, output.value, output.nonce) {
        (Asset::Explicit(asset), Value::Explicit(value), Nonce::Null) => Some((asset, value)),
        _ => None,
    }
}

/// P2WPKH script code used by segwit v0 sighashes.
pub(crate) fn p2wpkh_script_code(pubkey_bytes: &[u8]) -> Script {
    Script::new_p2pkh(&PubkeyHash::from_raw_hash(hash160::Hash::hash(
        pubkey_bytes,
    )))
}

/// Verify the P2WPKH witness on `tx.input[index]` spending `prevout`, and
/// return the sighash flag it was signed with. Only low-S DER signatures with
/// a compressed key matching the prevout script are accepted.
pub(crate) fn verify_p2wpkh_witness(
    tx: &Transaction,
    index: usize,
    prevout: &TxOut,
) -> Result<EcdsaSighashType, String> {
    let input = tx.input.get(index).ok_or("input index out of range")?;
    if !input.script_sig.is_empty() {
        return Err("input has a non-empty scriptSig".into());
    }
    let stack = &input.witness.script_witness;
    if stack.len() != 2 {
        return Err("witness is not a two-element P2WPKH stack".into());
    }
    let (sig_bytes, pubkey_bytes) = (&stack[0], &stack[1]);
    if pubkey_bytes.len() != 33 {
        return Err("witness public key is not compressed".into());
    }
    let pubkey = SecpPublicKey::from_slice(pubkey_bytes).map_err(|_| "invalid public key")?;
    let expected_script = Script::new_v0_wpkh(&elements::WPubkeyHash::from_raw_hash(
        hash160::Hash::hash(pubkey_bytes),
    ));
    if prevout.script_pubkey != expected_script {
        return Err("witness public key does not match the spent P2WPKH script".into());
    }
    let (&flag, der) = sig_bytes.split_last().ok_or("empty signature")?;
    let sighash_type =
        EcdsaSighashType::from_standard(u32::from(flag)).map_err(|_| "non-standard sighash")?;
    let mut signature =
        ecdsa::Signature::from_der(der).map_err(|_| "signature is not strict DER")?;
    let original = signature;
    signature.normalize_s();
    if signature != original {
        return Err("signature is not low-S".into());
    }
    let script_code = p2wpkh_script_code(pubkey_bytes);
    let sighash =
        SighashCache::new(tx).segwitv0_sighash(index, &script_code, prevout.value, sighash_type);
    let message = Message::from_digest(sighash.to_byte_array());
    Secp256k1::verification_only()
        .verify_ecdsa(&message, &signature, &pubkey)
        .map_err(|_| "signature does not verify against the computed sighash")?;
    Ok(sighash_type)
}

/// Decode and fully verify an offer against its independently fetched funding
/// transaction.
pub(crate) fn verify_offer(
    offer: &Offer,
    prevout_raw_tx_hex: &str,
    expected_network: &str,
    expected_genesis: BlockHash,
    address_params: &'static AddressParams,
) -> Result<VerifiedOffer, WalletError> {
    if offer.version != OFFER_VERSION {
        return Err(offer_error(format!(
            "unsupported offer version {}",
            offer.version
        )));
    }
    if offer.network != expected_network {
        return Err(offer_error(format!(
            "offer network {:?} is not this wallet's network {expected_network:?}",
            offer.network
        )));
    }
    let genesis = BlockHash::from_str(&offer.genesis_hash)
        .map_err(|_| offer_error("offer genesis hash is invalid"))?;
    if genesis != expected_genesis {
        return Err(offer_error(
            "offer genesis hash does not match this network",
        ));
    }

    let tx_bytes = hex::decode(&offer.tx).map_err(|_| offer_error("offer tx is not hex"))?;
    if tx_bytes.is_empty() || tx_bytes.len() > MAX_OFFER_JSON_BYTES {
        return Err(offer_error("offer tx length is outside the accepted range"));
    }
    let tx: Transaction =
        deserialize(&tx_bytes).map_err(|e| offer_error(format!("offer tx decode failed: {e}")))?;
    if serialize(&tx) != tx_bytes {
        return Err(offer_error("offer tx encoding is not canonical"));
    }
    if tx.version != 2 || tx.lock_time != elements::LockTime::ZERO {
        return Err(offer_error("offer tx version or locktime is unsupported"));
    }
    let ([input], [output]) = (tx.input.as_slice(), tx.output.as_slice()) else {
        return Err(offer_error(
            "offer tx must have exactly one input and one output",
        ));
    };
    if input.is_pegin
        || input.has_issuance()
        || input.sequence != Sequence::MAX
        || !input.witness.pegin_witness.is_empty()
        || input.witness.amount_rangeproof.is_some()
        || input.witness.inflation_keys_rangeproof.is_some()
    {
        return Err(offer_error(
            "offer input must be a plain final-sequence spend without issuance or peg-in",
        ));
    }
    let (want_asset, want_amount) =
        explicit_parts(output).ok_or_else(|| offer_error("offer output is not fully explicit"))?;
    if want_amount == 0
        || output.is_fee()
        || output.witness.surjection_proof.is_some()
        || output.witness.rangeproof.is_some()
    {
        return Err(offer_error(
            "offer output must be a non-zero explicit payment",
        ));
    }
    let maker_address = Address::from_script(&output.script_pubkey, None, address_params)
        .ok_or_else(|| offer_error("offer output script has no address encoding"))?
        .to_string();

    let prev_bytes = hex::decode(prevout_raw_tx_hex)
        .map_err(|_| offer_error("prevout transaction is not hex"))?;
    if prev_bytes.is_empty() || prev_bytes.len() > MAX_RAW_TRANSACTION_BYTES {
        return Err(offer_error(
            "prevout transaction length is outside the accepted range",
        ));
    }
    let prev_tx: Transaction = deserialize(&prev_bytes)
        .map_err(|e| offer_error(format!("prevout transaction decode failed: {e}")))?;
    let outpoint: OutPoint = input.previous_output;
    if prev_tx.txid() != outpoint.txid {
        return Err(offer_error(
            "prevout transaction does not hash to the offered input's txid",
        ));
    }
    let prevout = prev_tx
        .output
        .get(outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| offer_error("offered vout does not exist in the prevout transaction"))?;
    let (give_asset, give_amount) = explicit_parts(&prevout)
        .ok_or_else(|| offer_error("offered UTXO is not fully explicit"))?;
    if give_amount == 0 || !prevout.script_pubkey.is_v0_p2wpkh() {
        return Err(offer_error("offered UTXO must be a non-zero P2WPKH output"));
    }
    if give_asset == want_asset {
        return Err(offer_error("offer gives and wants the same asset"));
    }

    let flag = verify_p2wpkh_witness(&tx, 0, &prevout)
        .map_err(|e| offer_error(format!("maker signature invalid: {e}")))?;
    if flag != EcdsaSighashType::SinglePlusAnyoneCanPay {
        return Err(offer_error(
            "maker signature is not SIGHASH_SINGLE|ANYONECANPAY",
        ));
    }

    let declared_give = AssetId::from_str(&offer.give.asset_id)
        .map_err(|_| offer_error("give asset id is invalid"))?;
    let declared_want = AssetId::from_str(&offer.want.asset_id)
        .map_err(|_| offer_error("want asset id is invalid"))?;
    if declared_give != give_asset
        || offer.give.amount != give_amount
        || declared_want != want_asset
        || offer.want.amount != want_amount
    {
        return Err(offer_error(
            "declared give/want do not match the signed transaction and prevout",
        ));
    }

    let decoded = DecodedOffer {
        give_asset: give_asset.to_string(),
        give_amount,
        want_asset: want_asset.to_string(),
        want_amount,
        outpoint: crate::outpoint_label(&outpoint),
        maker_address,
    };
    Ok(VerifiedOffer {
        tx,
        prevout,
        give_asset,
        give_amount,
        want_asset,
        want_amount,
        decoded,
    })
}
