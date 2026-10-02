//! Approval-gated signing and finalization.

use std::str::FromStr;

use elements::encode::{deserialize, serialize};
use elements::pset::PartiallySignedTransaction;
use elements::{EcdsaSighashType, Transaction};
use elementsplus_lwk_adapter::validate_explicit_transaction;
use lwk_common::Signer;

use crate::offer::{explicit_parts, verify_p2wpkh_witness, Offer, OfferLeg};
use crate::review::{InputOwner, PreparedTx, SignedResult, TxKind};
use crate::{WalletCore, WalletError, MAX_RAW_TRANSACTION_BYTES, OFFER_VERSION};

impl WalletCore {
    /// Recompute all review facts, require explicit approval of the exact PSET
    /// and review, sign only this wallet's inputs with the declared sighash,
    /// finalize them, and verify every witness. Nothing is broadcast.
    ///
    /// For swap offers the result carries the signed offer instead of a
    /// broadcastable transaction.
    pub fn sign_prepared(
        &self,
        prepared: &PreparedTx,
        approved_review_hash: &str,
    ) -> Result<SignedResult, WalletError> {
        if prepared.pset_base64.len() > MAX_RAW_TRANSACTION_BYTES {
            return Err(WalletError::InvalidPset("PSET is too large".into()));
        }
        let mut pset = PartiallySignedTransaction::from_str(&prepared.pset_base64)
            .map_err(|e| WalletError::InvalidPset(e.to_string()))?;
        let kind = prepared.review.kind;
        let analysis = self.analyze(&pset, kind)?;
        if analysis.review != prepared.review {
            return Err(WalletError::ReviewMismatch);
        }
        let review_hash = self.review_commitment(&pset, &analysis.review)?;
        if review_hash != prepared.review_hash || review_hash != approved_review_hash {
            return Err(WalletError::ApprovalMismatch);
        }

        let unsigned = pset
            .extract_tx()
            .map_err(|e| WalletError::InvalidPset(e.to_string()))?;
        let expected = analysis
            .owners
            .iter()
            .filter(|owner| **owner == InputOwner::Wallet)
            .count();
        let signatures = self
            .signer
            .sign(&mut pset)
            .map_err(|e| WalletError::Signing(e.to_string()))?;
        if signatures as usize != expected {
            return Err(WalletError::SignatureCount {
                actual: signatures,
                expected,
            });
        }

        // Finalize wallet inputs only. Maker inputs keep their final witness
        // byte-for-byte; a generic finalizer could otherwise rebuild them.
        for (index, owner) in analysis.owners.iter().enumerate() {
            if *owner != InputOwner::Wallet {
                continue;
            }
            let input = &mut pset.inputs_mut()[index];
            let (key, _) = input
                .bip32_derivation
                .iter()
                .next()
                .ok_or_else(|| WalletError::Finalization("missing ownership path".into()))?;
            let key = *key;
            if input.partial_sigs.len() != 1 {
                return Err(WalletError::Finalization(format!(
                    "input {index} has {} partial signatures",
                    input.partial_sigs.len()
                )));
            }
            let signature = input
                .partial_sigs
                .get(&key)
                .cloned()
                .ok_or_else(|| WalletError::Finalization("signature key mismatch".into()))?;
            input.final_script_witness = Some(vec![signature, key.to_bytes()]);
            input.partial_sigs.clear();
            input.bip32_derivation.clear();
            input.sighash_type = None;
        }

        let tx = pset
            .extract_tx()
            .map_err(|e| WalletError::Finalization(e.to_string()))?;
        self.validate_final_transaction(&pset, &unsigned, &tx, &analysis.owners, kind)?;

        let raw = serialize(&tx);
        let roundtrip: Transaction =
            deserialize(&raw).map_err(|e| WalletError::FinalTransaction(e.to_string()))?;
        if roundtrip != tx {
            return Err(WalletError::FinalTransaction(
                "wire roundtrip changed the transaction".into(),
            ));
        }
        let txid = tx.txid().to_string();

        if kind == TxKind::SwapOffer {
            let prevout = pset.inputs()[0]
                .witness_utxo
                .as_ref()
                .ok_or_else(|| WalletError::FinalTransaction("missing prevout".into()))?;
            let (give_asset, give_amount) = explicit_parts(prevout)
                .ok_or_else(|| WalletError::FinalTransaction("prevout not explicit".into()))?;
            let (want_asset, want_amount) = explicit_parts(&tx.output[0])
                .ok_or_else(|| WalletError::FinalTransaction("output not explicit".into()))?;
            return Ok(SignedResult {
                txid,
                review_hash,
                raw_tx_hex: None,
                offer: Some(Offer {
                    version: OFFER_VERSION,
                    network: self.network_id.clone(),
                    genesis_hash: self.genesis_hash.to_string(),
                    tx: hex::encode(raw),
                    give: OfferLeg {
                        asset_id: give_asset.to_string(),
                        amount: give_amount,
                    },
                    want: OfferLeg {
                        asset_id: want_asset.to_string(),
                        amount: want_amount,
                    },
                }),
            });
        }

        Ok(SignedResult {
            txid,
            review_hash,
            raw_tx_hex: Some(hex::encode(raw)),
            offer: None,
        })
    }

    fn validate_final_transaction(
        &self,
        pset: &PartiallySignedTransaction,
        unsigned: &Transaction,
        signed: &Transaction,
        owners: &[InputOwner],
        kind: TxKind,
    ) -> Result<(), WalletError> {
        let fail = |reason: String| WalletError::FinalTransaction(reason);
        validate_explicit_transaction(signed).map_err(|e| fail(e.to_string()))?;
        if unsigned.version != signed.version
            || unsigned.lock_time != signed.lock_time
            || unsigned.output != signed.output
            || unsigned.input.len() != signed.input.len()
            || owners.len() != signed.input.len()
        {
            return Err(fail("signing changed non-witness transaction data".into()));
        }
        for (index, ((before, after), owner)) in unsigned
            .input
            .iter()
            .zip(&signed.input)
            .zip(owners)
            .enumerate()
        {
            if before.previous_output != after.previous_output
                || before.sequence != after.sequence
                || before.is_pegin != after.is_pegin
                || before.asset_issuance != after.asset_issuance
                || !after.script_sig.is_empty()
            {
                return Err(fail(format!("input {index} structure changed")));
            }
            let prevout = pset.inputs()[index]
                .witness_utxo
                .as_ref()
                .ok_or_else(|| fail(format!("input {index} lacks its prevout")))?;
            let flag = verify_p2wpkh_witness(signed, index, prevout)
                .map_err(|e| fail(format!("input {index}: {e}")))?;
            let expected = match owner {
                InputOwner::Wallet => kind.sighash(),
                InputOwner::Foreign => {
                    if before.witness != after.witness {
                        return Err(fail(format!("maker input {index} witness was modified")));
                    }
                    EcdsaSighashType::SinglePlusAnyoneCanPay
                }
            };
            if flag != expected {
                return Err(fail(format!(
                    "input {index} signed with an unexpected sighash"
                )));
            }
        }
        Ok(())
    }
}
