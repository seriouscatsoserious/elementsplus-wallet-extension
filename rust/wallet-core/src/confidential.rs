//! Confidential-transaction (CT) support.
//!
//! * SLIP-77: one master blinding key is derived from the BIP39 seed exactly
//!   as LWK and Green do; each script's blinding key is derived from it.
//! * Receiving: [`crate::WalletCore::verify_raw_transaction`] unblinds wallet
//!   outputs with the script's blinding key. `TxOut::unblind` rewinds (and so
//!   verifies) the rangeproof against the value commitment and recomputes the
//!   asset generator; an output that does not open with our key is refused.
//! * Spending: a confidential UTXO carries its commitments and blinders
//!   ([`UtxoBlinding`]). The core re-opens the commitments before use, puts
//!   the exact asset/value into the PSET together with PSET v2 explicit
//!   value/asset proofs, and blinds outputs with rust-elements' `blind_last`
//!   before the review is computed, so the review hash covers the blinded
//!   PSET bytes.

use std::collections::HashMap;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::pset::{Input, Output, PartiallySignedTransaction};
use elements::secp256k1_zkp::{
    All, Generator, PedersenCommitment, PublicKey as SecpPublicKey, RangeProof, Secp256k1,
    SurjectionProof,
};
use elements::{AssetId, BlindAssetProofs, BlindValueProofs, Script, TxOut, TxOutSecrets};
use serde::{Deserialize, Serialize};

use crate::WalletError;

/// Commitments and blinding factors of one confidential wallet output.
///
/// Produced by `verify_raw_transaction` after the output unblinds with this
/// wallet's SLIP-77 key, and passed back unchanged inside a
/// [`crate::VerifiedUtxo`] to spend it. Blinders use the Elements RPC
/// (byte-reversed) hex convention, commitments their 33-byte serialization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoBlinding {
    pub asset_commitment_hex: String,
    pub value_commitment_hex: String,
    pub asset_blinder_hex: String,
    pub value_blinder_hex: String,
}

/// A confidential UTXO whose blinders were checked against its commitments.
#[derive(Clone, Debug)]
pub(crate) struct OpenedBlinding {
    pub generator: Generator,
    pub commitment: PedersenCommitment,
    pub asset_bf: AssetBlindingFactor,
    pub value_bf: ValueBlindingFactor,
}

impl UtxoBlinding {
    pub(crate) fn from_parts(
        generator: Generator,
        commitment: PedersenCommitment,
        secrets: &TxOutSecrets,
    ) -> Self {
        Self {
            asset_commitment_hex: hex::encode(generator.serialize()),
            value_commitment_hex: hex::encode(commitment.serialize()),
            asset_blinder_hex: secrets.asset_bf.to_string(),
            value_blinder_hex: secrets.value_bf.to_string(),
        }
    }

    /// Recompute both commitments from `(asset, value)` and the blinders and
    /// require them to equal the supplied commitments.
    pub(crate) fn open(
        &self,
        secp: &Secp256k1<All>,
        asset: AssetId,
        value: u64,
    ) -> Result<OpenedBlinding, &'static str> {
        let generator = hex::decode(&self.asset_commitment_hex)
            .ok()
            .and_then(|bytes| Generator::from_slice(&bytes).ok())
            .ok_or("invalid asset commitment")?;
        let commitment = hex::decode(&self.value_commitment_hex)
            .ok()
            .and_then(|bytes| PedersenCommitment::from_slice(&bytes).ok())
            .ok_or("invalid value commitment")?;
        let asset_bf: AssetBlindingFactor = self
            .asset_blinder_hex
            .parse()
            .map_err(|_| "invalid asset blinder")?;
        let value_bf: ValueBlindingFactor = self
            .value_blinder_hex
            .parse()
            .map_err(|_| "invalid value blinder")?;
        let expected_generator =
            Generator::new_blinded(secp, asset.into_tag(), asset_bf.into_inner());
        let expected_commitment =
            PedersenCommitment::new(secp, value, value_bf.into_inner(), expected_generator);
        if expected_generator != generator || expected_commitment != commitment {
            return Err("blinding factors do not open the commitments");
        }
        Ok(OpenedBlinding {
            generator,
            commitment,
            asset_bf,
            value_bf,
        })
    }
}

/// The confidential prevout a PSET input spends. Nonce and proofs are not
/// part of the segwit v0 sighash and are not needed to spend.
pub(crate) fn confidential_prevout(opened: &OpenedBlinding, script: Script) -> TxOut {
    TxOut {
        asset: Asset::Confidential(opened.generator),
        value: Value::Confidential(opened.commitment),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    }
}

/// Attach PSET v2 explicit asset/value proofs so the PSET alone proves the
/// confidential input's exact asset and value to the reviewer.
pub(crate) fn add_input_proofs(
    secp: &Secp256k1<All>,
    input: &mut Input,
    asset: AssetId,
    value: u64,
    opened: &OpenedBlinding,
) -> Result<(), WalletError> {
    let mut rng = rand::thread_rng();
    let asset_proof = SurjectionProof::blind_asset_proof(&mut rng, secp, asset, opened.asset_bf)
        .map_err(|e| WalletError::InvalidPset(format!("asset proof: {e}")))?;
    let value_proof = RangeProof::blind_value_proof(
        &mut rng,
        secp,
        value,
        opened.commitment,
        opened.generator,
        opened.value_bf,
    )
    .map_err(|e| WalletError::InvalidPset(format!("value proof: {e}")))?;
    input.blind_asset_proof = Some(Box::new(asset_proof));
    input.blind_value_proof = Some(Box::new(value_proof));
    Ok(())
}

/// Verify a confidential input's explicit asset/value against its prevout
/// commitments using the PSET v2 explicit proofs.
pub(crate) fn verify_input_proofs(
    secp: &Secp256k1<All>,
    input: &Input,
    prevout: &TxOut,
) -> Result<(AssetId, u64), &'static str> {
    let (Asset::Confidential(generator), Value::Confidential(commitment)) =
        (prevout.asset, prevout.value)
    else {
        return Err("input prevout must be fully explicit or fully confidential");
    };
    let (Some(asset), Some(value)) = (input.asset, input.amount) else {
        return Err("confidential input lacks its explicit asset or value");
    };
    let (Some(asset_proof), Some(value_proof)) =
        (&input.blind_asset_proof, &input.blind_value_proof)
    else {
        return Err("confidential input lacks explicit asset/value proofs");
    };
    if !asset_proof.blind_asset_proof_verify(secp, asset, generator)
        || !value_proof.blind_value_proof_verify(secp, value, generator, commitment)
    {
        return Err("confidential input proofs do not match its commitments");
    }
    Ok((asset, value))
}

/// Verify a blinded PSET output's explicit asset/value proofs.
pub(crate) fn verify_output_proofs(
    secp: &Secp256k1<All>,
    output: &Output,
) -> Result<(AssetId, u64), &'static str> {
    let (Some(asset), Some(value)) = (output.asset, output.amount) else {
        return Err("blinded output lacks its explicit asset or value");
    };
    let (Some(generator), Some(commitment)) = (output.asset_comm, output.amount_comm) else {
        return Err("blinded output lacks its commitments");
    };
    if output.blinding_key.is_none()
        || output.ecdh_pubkey.is_none()
        || output.value_rangeproof.is_none()
        || output.asset_surjection_proof.is_none()
    {
        return Err("blinded output lacks its blinding key, nonce, or proofs");
    }
    let (Some(asset_proof), Some(value_proof)) =
        (&output.blind_asset_proof, &output.blind_value_proof)
    else {
        return Err("blinded output lacks explicit asset/value proofs");
    };
    if !asset_proof.blind_asset_proof_verify(secp, asset, generator)
        || !value_proof.blind_value_proof_verify(secp, value, generator, commitment)
    {
        return Err("blinded output proofs do not match its commitments");
    }
    Ok((asset, value))
}

/// Whether an output carries any blinding intent or blinded data.
pub(crate) fn output_has_ct_fields(output: &Output) -> bool {
    output.amount_comm.is_some()
        || output.asset_comm.is_some()
        || output.blinding_key.is_some()
        || output.ecdh_pubkey.is_some()
        || output.blinder_index.is_some()
        || output.value_rangeproof.is_some()
        || output.asset_surjection_proof.is_some()
        || output.blind_value_proof.is_some()
        || output.blind_asset_proof.is_some()
}

/// Whether an input spends a confidential prevout or carries CT proofs.
pub(crate) fn input_has_ct_fields(input: &Input) -> bool {
    input.blind_value_proof.is_some()
        || input.blind_asset_proof.is_some()
        || input.witness_utxo.as_ref().is_some_and(|utxo| {
            !matches!(utxo.asset, Asset::Explicit(_)) || !matches!(utxo.value, Value::Explicit(_))
        })
}

/// Mark `output` for blinding to `blinding_key`.
pub(crate) fn request_blinding(output: &mut Output, blinding_key: SecpPublicKey) {
    output.blinding_key = Some(elements::bitcoin::PublicKey::new(blinding_key));
    output.blinder_index = Some(0);
}

/// Blind every output that requests it, balancing with all input secrets
/// (explicit inputs contribute zero blinders). Issuances stay explicit.
pub(crate) fn blind_pset(
    secp: &Secp256k1<All>,
    pset: &mut PartiallySignedTransaction,
    input_secrets: &[TxOutSecrets],
) -> Result<(), WalletError> {
    if input_secrets.len() != pset.inputs().len() {
        return Err(WalletError::InvalidPset(
            "blinding needs secrets for every input".into(),
        ));
    }
    let secrets: HashMap<usize, TxOutSecrets> = input_secrets.iter().copied().enumerate().collect();
    // rust-elements refuses to blind next to an issuance unless the issuance
    // is explicitly marked unblinded; the marker is not kept in the PSET.
    let issuance_inputs: Vec<usize> = pset
        .inputs()
        .iter()
        .enumerate()
        .filter(|(_, input)| input.has_issuance())
        .map(|(index, _)| index)
        .collect();
    for index in &issuance_inputs {
        pset.inputs_mut()[*index].blinded_issuance = Some(0);
    }
    let result = pset.blind_last(&mut rand::thread_rng(), secp, &secrets);
    for index in &issuance_inputs {
        pset.inputs_mut()[*index].blinded_issuance = None;
    }
    result.map_err(|e| WalletError::InvalidPset(format!("blinding failed: {e}")))
}
