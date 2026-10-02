//! Offline confidential-transaction tests: SLIP-77 addresses, unblinding of
//! received outputs, spending confidential UTXOs, exact reviews, and
//! adversarial blinding data. Synthetic funding transactions only.

use std::collections::HashMap;
use std::str::FromStr;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::pset::{Input, Output, PartiallySignedTransaction};
use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use elements::{
    Address, AddressParams, AssetId, OutPoint, Script, Transaction, TxOut, TxOutSecrets, Txid,
};
use elementsplus_wallet_core::{
    verify_raw_transaction, Branch, CancelRequest, ExpectedWalletOutput, IssuanceRequest,
    OfferSplitRequest, PreparedTx, RawTransactionVerificationRequest, SwapOfferRequest,
    TakeOfferInput, TakeSwapOffersRequest, TransferRequest, TxKind, VerifiedUtxo, WalletCore,
    WalletError, POLICY_ASSET,
};

const ALICE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn policy() -> AssetId {
    AssetId::from_str(POLICY_ASSET).unwrap()
}

fn token() -> AssetId {
    AssetId::from_slice(&[0x77; 32]).unwrap()
}

fn script_of(core: &WalletCore, branch: Branch, index: u32) -> Script {
    Script::from(
        hex::decode(
            core.derive_address(branch, index)
                .unwrap()
                .script_pubkey_hex,
        )
        .unwrap(),
    )
}

fn blinding_key_of(core: &WalletCore, branch: Branch, index: u32) -> PublicKey {
    let derived = core.derive_address_with(branch, index, Some(true)).unwrap();
    PublicKey::from_slice(&hex::decode(derived.blinding_pubkey_hex.unwrap()).unwrap()).unwrap()
}

/// A synthetic transaction with one output blinded to `blinding_key` and
/// paying `script` (both normally belonging to the same wallet).
fn blinded_funding_tx(
    salt: u8,
    asset: AssetId,
    value: u64,
    script: Script,
    blinding_key: PublicKey,
) -> Transaction {
    let secp = Secp256k1::new();
    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = Input::from_prevout(OutPoint::new(Txid::from_byte_array([salt; 32]), 0));
    input.witness_utxo = Some(TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: Script::new_op_return(&[salt]),
        witness: Default::default(),
    });
    pset.add_input(input);
    let mut output = Output::from_txout(TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    });
    output.blinding_key = Some(elements::bitcoin::PublicKey::new(blinding_key));
    output.blinder_index = Some(0);
    pset.add_output(output);
    let secrets = HashMap::from([(
        0,
        TxOutSecrets::new(
            asset,
            AssetBlindingFactor::zero(),
            value,
            ValueBlindingFactor::zero(),
        ),
    )]);
    pset.blind_last(&mut rand::thread_rng(), &secp, &secrets)
        .unwrap();
    pset.extract_tx().unwrap()
}

/// Fund `core` at (branch, index) with a confidential output and return the
/// UTXO exactly as the scanner would build it from `verify_raw_transaction`.
fn ct_fund(
    core: &WalletCore,
    salt: u8,
    asset: AssetId,
    value: u64,
    branch: Branch,
    index: u32,
) -> (VerifiedUtxo, String) {
    let script = script_of(core, branch, index);
    let tx = blinded_funding_tx(
        salt,
        asset,
        value,
        script.clone(),
        blinding_key_of(core, branch, index),
    );
    let raw = hex::encode(serialize(&tx));
    let verified = core
        .verify_raw_transaction(&RawTransactionVerificationRequest {
            expected_txid: tx.txid().to_string(),
            raw_transaction_hex: raw.clone(),
            expected_wallet_outputs: vec![ExpectedWalletOutput {
                vout: 0,
                script_pub_key_hex: hex::encode(script.as_bytes()),
            }],
        })
        .unwrap();
    let output = &verified.outputs[0];
    assert_eq!(output.asset_id, asset.to_string());
    assert_eq!(output.value_atomic, value);
    (
        VerifiedUtxo {
            txid: verified.txid.clone(),
            vout: 0,
            value: output.value_atomic,
            asset_id: output.asset_id.clone(),
            script_pubkey_hex: output.script_pub_key_hex.clone(),
            branch,
            index,
            blinding: Some(output.blinding.clone().expect("confidential output")),
        },
        raw,
    )
}

/// Explicit synthetic funding, as in `headless.rs`.
fn fund(
    core: &WalletCore,
    salt: u8,
    asset: AssetId,
    value: u64,
    branch: Branch,
    index: u32,
) -> (VerifiedUtxo, String) {
    let script = script_of(core, branch, index);
    let tx = Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([salt; 32]), 0),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: script.clone(),
            witness: Default::default(),
        }],
    };
    (
        VerifiedUtxo {
            txid: tx.txid().to_string(),
            vout: 0,
            value,
            asset_id: asset.to_string(),
            script_pubkey_hex: hex::encode(script.as_bytes()),
            branch,
            index,
            blinding: None,
        },
        hex::encode(serialize(&tx)),
    )
}

fn decode_tx(raw_hex: &str) -> Transaction {
    deserialize(&hex::decode(raw_hex).unwrap()).unwrap()
}

fn pset_of(prepared: &PreparedTx) -> PartiallySignedTransaction {
    PartiallySignedTransaction::from_str(&prepared.pset_base64).unwrap()
}

fn with_pset(prepared: &PreparedTx, pset: &PartiallySignedTransaction) -> PreparedTx {
    PreparedTx {
        pset_base64: pset.to_string(),
        ..prepared.clone()
    }
}

fn delta(prepared: &PreparedTx, asset: AssetId) -> Option<String> {
    prepared
        .review
        .balance_changes
        .iter()
        .find(|d| d.asset_id == asset.to_string())
        .map(|d| d.amount.clone())
}

fn is_blinded(output: &TxOut) -> bool {
    output.asset.is_confidential() && output.value.is_confidential()
}

/// Locally verify (and for confidential outputs unblind) `vout` of `raw`.
fn verify_output(core: &WalletCore, raw: &str, vout: u32) -> (AssetId, u64, bool) {
    let tx = decode_tx(raw);
    let verified = core
        .verify_raw_transaction(&RawTransactionVerificationRequest {
            expected_txid: tx.txid().to_string(),
            raw_transaction_hex: raw.into(),
            expected_wallet_outputs: vec![ExpectedWalletOutput {
                vout,
                script_pub_key_hex: hex::encode(tx.output[vout as usize].script_pubkey.as_bytes()),
            }],
        })
        .unwrap();
    let output = &verified.outputs[0];
    (
        AssetId::from_str(&output.asset_id).unwrap(),
        output.value_atomic,
        output.blinding.is_some(),
    )
}

/// The fee must cover at least `fee_rate` sat/vB of the real transaction.
fn assert_fee_covers(prepared: &PreparedTx, raw: &str, fee_rate: u64) {
    let vsize = decode_tx(raw).weight().div_ceil(4) as u64;
    assert!(
        prepared.review.fee >= vsize * fee_rate,
        "fee {} below {fee_rate} sat/vB of {vsize} vB",
        prepared.review.fee
    );
}

#[test]
fn slip77_addresses_are_opt_in() {
    let mut alice = WalletCore::new(ALICE).unwrap();
    assert!(!alice.confidential_receive());
    let plain = alice.derive_address(Branch::External, 0).unwrap();
    assert!(plain.confidential_address.is_none());
    // Unchanged JSON shape while confidential receive is off.
    let json = serde_json::to_value(&plain).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 6);

    alice.set_confidential_receive(true);
    let ct = alice.derive_address(Branch::External, 0).unwrap();
    assert_eq!(ct.native_address, plain.native_address);
    assert_eq!(ct.script_pubkey_hex, plain.script_pubkey_hex);
    let native = ct.confidential_address.clone().unwrap();
    let alias = ct.confidential_lwk_alias.clone().unwrap();
    assert!(native.starts_with("elementsl1"), "{native}");
    assert!(alias.starts_with("el1"), "{alias}");
    let parsed = Address::parse_with_params(&alias, &AddressParams::ELEMENTS).unwrap();
    assert_eq!(
        hex::encode(parsed.script_pubkey().as_bytes()),
        ct.script_pubkey_hex
    );
    assert_eq!(
        hex::encode(parsed.blinding_pubkey.unwrap().serialize()),
        ct.blinding_pubkey_hex.clone().unwrap()
    );
    // The explicit override wins over the default in both directions.
    assert!(alice
        .derive_address_with(Branch::External, 0, Some(false))
        .unwrap()
        .confidential_address
        .is_none());
    // Deterministic: the same mnemonic always derives the same blinding key,
    // a different one never does.
    let again = WalletCore::new(ALICE).unwrap();
    assert_eq!(
        again
            .derive_address_with(Branch::External, 0, Some(true))
            .unwrap(),
        ct
    );
    let bob = WalletCore::new(BOB).unwrap();
    assert_ne!(
        bob.derive_address_with(Branch::External, 0, Some(true))
            .unwrap()
            .blinding_pubkey_hex,
        ct.blinding_pubkey_hex
    );
}

#[test]
fn unblinds_own_output_and_refuses_foreign_blinding() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let (utxo, raw) = ct_fund(&alice, 1, token(), 12_345, Branch::External, 3);
    let blinding = utxo.blinding.clone().unwrap();
    assert_eq!(blinding.asset_commitment_hex.len(), 66);
    assert_eq!(blinding.value_commitment_hex.len(), 66);
    assert_eq!(verify_output(&alice, &raw, 0), (token(), 12_345, true));

    let tx = decode_tx(&raw);
    let request = RawTransactionVerificationRequest {
        expected_txid: tx.txid().to_string(),
        raw_transaction_hex: raw.clone(),
        expected_wallet_outputs: vec![ExpectedWalletOutput {
            vout: 0,
            script_pub_key_hex: utxo.script_pubkey_hex.clone(),
        }],
    };
    // The keyless boundary stays explicit-only.
    assert!(verify_raw_transaction(&request).is_err());
    // Output paying Alice's script but blinded to Bob's key: refused.
    let foreign = blinded_funding_tx(
        2,
        token(),
        500,
        script_of(&alice, Branch::External, 3),
        blinding_key_of(&bob, Branch::External, 3),
    );
    let foreign_raw = hex::encode(serialize(&foreign));
    let err = alice
        .verify_raw_transaction(&RawTransactionVerificationRequest {
            expected_txid: foreign.txid().to_string(),
            raw_transaction_hex: foreign_raw,
            expected_wallet_outputs: request.expected_wallet_outputs.clone(),
        })
        .unwrap_err();
    assert!(err.to_string().contains("does not unblind"), "{err}");

    // A corrupted rangeproof does not unblind either.
    let mut corrupt = tx.clone();
    let mut proof = corrupt.output[0]
        .witness
        .rangeproof
        .as_ref()
        .unwrap()
        .serialize();
    let middle = proof.len() / 2;
    proof[middle] ^= 1;
    corrupt.output[0].witness.rangeproof = elements::secp256k1_zkp::RangeProof::from_slice(&proof)
        .ok()
        .map(Box::new);
    let corrupt_raw = hex::encode(serialize(&corrupt));
    assert!(alice
        .verify_raw_transaction(&RawTransactionVerificationRequest {
            expected_txid: corrupt.txid().to_string(),
            raw_transaction_hex: corrupt_raw,
            expected_wallet_outputs: request.expected_wallet_outputs.clone(),
        })
        .is_err());

    // A missing surjection proof is refused.
    let mut no_surjection = tx;
    no_surjection.output[0].witness.surjection_proof = None;
    assert!(alice
        .verify_raw_transaction(&RawTransactionVerificationRequest {
            expected_txid: no_surjection.txid().to_string(),
            raw_transaction_hex: hex::encode(serialize(&no_surjection)),
            expected_wallet_outputs: request.expected_wallet_outputs,
        })
        .is_err());
}

#[test]
fn spend_confidential_to_explicit_recipient() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let (utxo, _) = ct_fund(&alice, 3, policy(), 200_000, Branch::External, 0);
    let recipient = bob.derive_address(Branch::External, 1).unwrap();
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: recipient.native_address.clone(),
            asset_id: POLICY_ASSET.into(),
            amount: 50_000,
            fee_rate: 1,
            utxos: vec![utxo],
            change_index: 4,
        })
        .unwrap();
    let review = &prepared.review;
    assert!(review.confidential);
    assert_eq!(review.external_outputs.len(), 1);
    assert_eq!(review.external_outputs[0].address, recipient.native_address);
    assert!(!review.external_outputs[0].confidential);
    assert_eq!(review.external_outputs[0].amount, 50_000);
    // Exact deltas: the wallet loses exactly the amount sent (fee separate).
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("-50000"));
    let pset = pset_of(&prepared);
    assert!(pset.outputs()[0].asset_comm.is_none(), "recipient explicit");
    assert!(pset.outputs()[1].asset_comm.is_some(), "change blinded");
    assert!(pset.outputs()[2].script_pubkey.is_empty());
    assert!(pset.outputs()[2].asset_comm.is_none(), "fee explicit");
    let change = pset.outputs()[1].amount.unwrap();
    assert_eq!(50_000 + change + review.fee, 200_000);
    // Recomputing the review from the PSET alone gives the same review/hash.
    let recomputed = alice
        .review_pset(&prepared.pset_base64, TxKind::Transfer)
        .unwrap();
    assert_eq!(recomputed, prepared);

    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let raw = signed.raw_tx_hex.unwrap();
    let tx = decode_tx(&raw);
    assert!(!is_blinded(&tx.output[0]));
    assert!(is_blinded(&tx.output[1]));
    assert!(tx.output[2].is_fee());
    assert_fee_covers(&prepared, &raw, 1);
    assert_eq!(verify_output(&bob, &raw, 0), (policy(), 50_000, false));
    assert_eq!(verify_output(&alice, &raw, 1), (policy(), change, true));
}

#[test]
fn spend_confidential_to_confidential_recipient() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let (utxo, _) = ct_fund(&alice, 4, policy(), 200_000, Branch::Change, 7);
    let recipient = bob
        .derive_address_with(Branch::External, 2, Some(true))
        .unwrap();
    let address = recipient.confidential_address.clone().unwrap();
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: address.clone(),
            asset_id: POLICY_ASSET.into(),
            amount: 70_000,
            fee_rate: 2,
            utxos: vec![utxo],
            change_index: 0,
        })
        .unwrap();
    let review = &prepared.review;
    assert!(review.confidential);
    assert_eq!(review.external_outputs[0].address, address);
    assert!(review.external_outputs[0].confidential);
    assert_eq!(review.external_outputs[0].amount, 70_000);
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("-70000"));
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let raw = signed.raw_tx_hex.unwrap();
    let tx = decode_tx(&raw);
    assert!(is_blinded(&tx.output[0]) && is_blinded(&tx.output[1]));
    assert_fee_covers(&prepared, &raw, 2);
    // Bob unblinds his payment, Alice her change; neither unblinds the other.
    assert_eq!(verify_output(&bob, &raw, 0), (policy(), 70_000, true));
    let change = 200_000 - 70_000 - review.fee;
    assert_eq!(verify_output(&alice, &raw, 1), (policy(), change, true));
    let cross = alice.verify_raw_transaction(&RawTransactionVerificationRequest {
        expected_txid: tx.txid().to_string(),
        raw_transaction_hex: raw.clone(),
        expected_wallet_outputs: vec![ExpectedWalletOutput {
            vout: 0,
            script_pub_key_hex: hex::encode(tx.output[0].script_pubkey.as_bytes()),
        }],
    });
    assert!(cross.is_err());
}

#[test]
fn explicit_inputs_to_confidential_recipient_keep_explicit_change() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let address = bob
        .derive_address_with(Branch::External, 0, Some(true))
        .unwrap()
        .confidential_lwk_alias
        .unwrap();
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: address,
            asset_id: POLICY_ASSET.into(),
            amount: 10_000,
            fee_rate: 1,
            utxos: vec![fund(&alice, 5, policy(), 100_000, Branch::External, 0).0],
            change_index: 1,
        })
        .unwrap();
    let pset = pset_of(&prepared);
    assert!(pset.outputs()[0].asset_comm.is_some());
    assert!(
        pset.outputs()[1].asset_comm.is_none(),
        "change stays explicit"
    );
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("-10000"));
    let raw = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap()
        .raw_tx_hex
        .unwrap();
    assert_fee_covers(&prepared, &raw, 1);
    assert_eq!(verify_output(&bob, &raw, 0), (policy(), 10_000, true));
}

#[test]
fn mixed_inputs_and_asset_change_are_blinded_with_exact_deltas() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let utxos = vec![
        ct_fund(&alice, 6, token(), 1_000, Branch::External, 1).0,
        fund(&alice, 7, token(), 400, Branch::External, 2).0,
        fund(&alice, 8, policy(), 30_000, Branch::External, 3).0,
        ct_fund(&alice, 9, policy(), 9_000, Branch::Change, 0).0,
    ];
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob.derive_address(Branch::External, 0).unwrap().lwk_alias,
            asset_id: token().to_string(),
            amount: 1_200,
            fee_rate: 1,
            utxos,
            change_index: 5,
        })
        .unwrap();
    let review = &prepared.review;
    assert!(review.confidential);
    assert_eq!(delta(&prepared, token()).as_deref(), Some("-1200"));
    // Policy: only the fee left the wallet, which is not a balance change.
    assert_eq!(delta(&prepared, policy()), None);
    let pset = pset_of(&prepared);
    assert_eq!(pset.inputs().len(), 3, "both token inputs + one policy");
    // Token change and policy change are both blinded.
    let blinded: Vec<_> = pset
        .outputs()
        .iter()
        .filter(|o| o.asset_comm.is_some())
        .map(|o| (o.asset.unwrap(), o.amount.unwrap()))
        .collect();
    assert_eq!(blinded.len(), 2);
    assert!(blinded.contains(&(token(), 200)));
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let raw = signed.raw_tx_hex.unwrap();
    assert_fee_covers(&prepared, &raw, 1);
    assert_eq!(verify_output(&bob, &raw, 0), (token(), 1_200, false));
}

#[test]
fn confidential_spend_always_has_a_blinded_output() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let recipient = bob
        .derive_address(Branch::External, 0)
        .unwrap()
        .native_address;
    // Sending the whole confidential balance minus less than fee + dust
    // cannot balance blinders, and there is nothing else to spend.
    let (ct, _) = ct_fund(&alice, 10, policy(), 100_000, Branch::External, 0);
    let mut request = TransferRequest {
        recipient,
        asset_id: POLICY_ASSET.into(),
        amount: 99_000,
        fee_rate: 1,
        utxos: vec![ct],
        change_index: 0,
    };
    assert!(matches!(
        alice.prepare_transfer(&request),
        Err(WalletError::InsufficientFunds { .. })
    ));
    // With an extra explicit coin the wallet keeps a blinded change output.
    request
        .utxos
        .push(fund(&alice, 11, policy(), 3_000, Branch::External, 1).0);
    let prepared = alice.prepare_transfer(&request).unwrap();
    let pset = pset_of(&prepared);
    let change = pset
        .outputs()
        .iter()
        .find(|o| o.asset_comm.is_some())
        .expect("blinded change");
    assert!(change.amount.unwrap() >= 546);
    alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
}

#[test]
fn tampered_blinders_and_values_are_rejected() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let (utxo, _) = ct_fund(&alice, 12, policy(), 80_000, Branch::External, 0);
    let request = |utxo: VerifiedUtxo| TransferRequest {
        recipient: bob
            .derive_address(Branch::External, 0)
            .unwrap()
            .native_address,
        asset_id: POLICY_ASSET.into(),
        amount: 1_000,
        fee_rate: 1,
        utxos: vec![utxo],
        change_index: 0,
    };
    let invalid = |result: Result<PreparedTx, WalletError>| {
        assert!(
            matches!(result, Err(WalletError::InvalidUtxo { .. })),
            "{result:?}"
        )
    };

    let mut tampered = utxo.clone();
    let blinding = tampered.blinding.as_mut().unwrap();
    blinding.value_blinder_hex = AssetBlindingFactor::new(&mut rand::thread_rng()).to_string();
    invalid(alice.prepare_transfer(&request(tampered)));

    let mut tampered = utxo.clone();
    tampered.blinding.as_mut().unwrap().asset_blinder_hex =
        AssetBlindingFactor::new(&mut rand::thread_rng()).to_string();
    invalid(alice.prepare_transfer(&request(tampered)));

    // Claiming a larger value or another asset for the same commitments.
    let mut tampered = utxo.clone();
    tampered.value = 90_000;
    invalid(alice.prepare_transfer(&request(tampered)));
    let mut tampered = utxo.clone();
    tampered.asset_id = token().to_string();
    invalid(alice.prepare_transfer(&request(tampered)));

    let mut tampered = utxo.clone();
    tampered.blinding.as_mut().unwrap().value_commitment_hex = "02".repeat(33);
    invalid(alice.prepare_transfer(&request(tampered)));

    // Unknown fields in the blinding object are refused at the JSON boundary.
    let mut json = serde_json::to_value(&utxo).unwrap();
    json["blinding"]["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<VerifiedUtxo>(json).is_err());

    // The untampered UTXO still works.
    assert!(alice.prepare_transfer(&request(utxo)).is_ok());
}

#[test]
fn tampered_confidential_psets_are_rejected() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let (utxo, _) = ct_fund(&alice, 13, policy(), 80_000, Branch::External, 0);
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob
                .derive_address_with(Branch::External, 0, Some(true))
                .unwrap()
                .confidential_address
                .unwrap(),
            asset_id: POLICY_ASSET.into(),
            amount: 1_000,
            fee_rate: 1,
            utxos: vec![utxo],
            change_index: 0,
        })
        .unwrap();
    let rejects = |pset: &PartiallySignedTransaction| {
        let tampered = with_pset(&prepared, pset);
        assert!(alice
            .review_pset(&tampered.pset_base64, TxKind::Transfer)
            .is_err());
        assert!(alice
            .sign_prepared(&tampered, &prepared.review_hash)
            .is_err());
    };

    // Overstating the confidential input value.
    let mut pset = pset_of(&prepared);
    pset.inputs_mut()[0].amount = Some(90_000);
    rejects(&pset);
    // Dropping the input proofs.
    let mut pset = pset_of(&prepared);
    pset.inputs_mut()[0].blind_value_proof = None;
    rejects(&pset);
    // Understating the external blinded payment.
    let mut pset = pset_of(&prepared);
    pset.outputs_mut()[0].amount = Some(10);
    rejects(&pset);
    // Swapping the explicit-value proofs of two outputs.
    let mut pset = pset_of(&prepared);
    let proof = pset.outputs()[0].blind_value_proof.clone();
    pset.outputs_mut()[0].blind_value_proof = pset.outputs()[1].blind_value_proof.clone();
    pset.outputs_mut()[1].blind_value_proof = proof;
    rejects(&pset);
    // Change claimed by the wallet but blinded to someone else's key.
    let mut pset = pset_of(&prepared);
    let foreign_nonce =
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
    pset.outputs_mut()[1].ecdh_pubkey = Some(elements::bitcoin::PublicKey::new(foreign_nonce));
    rejects(&pset);
    // A blinded fee output.
    let mut pset = pset_of(&prepared);
    let fee = pset.outputs().len() - 1;
    pset.outputs_mut()[fee].blinding_key = pset.outputs()[1].blinding_key;
    rejects(&pset);
    // Corrupted rangeproof on the change.
    let mut pset = pset_of(&prepared);
    let mut proof = pset.outputs()[1]
        .value_rangeproof
        .as_ref()
        .unwrap()
        .serialize();
    let middle = proof.len() / 2;
    proof[middle] ^= 0x40;
    pset.outputs_mut()[1].value_rangeproof =
        elements::secp256k1_zkp::RangeProof::from_slice(&proof)
            .ok()
            .map(Box::new);
    rejects(&pset);

    // Re-blinding yields different PSET bytes and therefore a new review
    // hash: an approval never carries over to a different blinding.
    let (utxo, _) = ct_fund(&alice, 13, policy(), 80_000, Branch::External, 0);
    let again = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob
                .derive_address(Branch::External, 0)
                .unwrap()
                .native_address,
            asset_id: POLICY_ASSET.into(),
            amount: 1_000,
            fee_rate: 1,
            utxos: vec![utxo.clone()],
            change_index: 0,
        })
        .unwrap();
    let twice = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob
                .derive_address(Branch::External, 0)
                .unwrap()
                .native_address,
            asset_id: POLICY_ASSET.into(),
            amount: 1_000,
            fee_rate: 1,
            utxos: vec![utxo],
            change_index: 0,
        })
        .unwrap();
    assert_eq!(again.review, twice.review);
    assert_ne!(again.review_hash, twice.review_hash);
    assert!(matches!(
        alice.sign_prepared(&again, &twice.review_hash),
        Err(WalletError::ApprovalMismatch)
    ));
}

#[test]
fn swaps_stay_explicit_and_split_unlocks_confidential_funds() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let (ct_token, _) = ct_fund(&alice, 14, token(), 1_000, Branch::External, 0);
    let (ct_policy, _) = ct_fund(&alice, 15, policy(), 50_000, Branch::External, 1);

    // Offering a confidential UTXO directly is refused with a clear error.
    let err = alice
        .prepare_swap_offer(&SwapOfferRequest {
            utxo: ct_token.clone(),
            want_asset: POLICY_ASSET.into(),
            want_amount: 10_000,
            receive_index: 2,
        })
        .unwrap_err();
    assert!(matches!(err, WalletError::Confidential(_)), "{err}");
    assert!(err.to_string().contains("offer split"), "{err}");

    // An offer split turns confidential funds into an explicit offerable
    // output, with confidential change.
    let prepared = alice
        .prepare_offer_split(&OfferSplitRequest {
            asset_id: token().to_string(),
            amount: 600,
            fee_rate: 1,
            utxos: vec![ct_token, ct_policy],
            change_index: 3,
            receive_index: 4,
        })
        .unwrap();
    assert_eq!(prepared.review.kind, TxKind::OfferSplit);
    assert!(prepared.review.balance_changes.is_empty());
    let pset = pset_of(&prepared);
    assert!(pset.outputs()[0].asset_comm.is_none());
    assert_eq!(pset.outputs()[0].amount, Some(600));
    assert!(pset
        .outputs()
        .iter()
        .filter(|o| !o.script_pubkey.is_empty())
        .skip(1)
        .all(|o| o.asset_comm.is_some()));
    let raw = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap()
        .raw_tx_hex
        .unwrap();
    assert_fee_covers(&prepared, &raw, 1);
    let tx = decode_tx(&raw);
    let (asset, value, confidential) = verify_output(&alice, &raw, 0);
    assert_eq!((asset, value, confidential), (token(), 600, false));
    let split = VerifiedUtxo {
        txid: tx.txid().to_string(),
        vout: 0,
        value: 600,
        asset_id: token().to_string(),
        script_pubkey_hex: hex::encode(tx.output[0].script_pubkey.as_bytes()),
        branch: Branch::External,
        index: 4,
        blinding: None,
    };
    let offer = alice
        .prepare_swap_offer(&SwapOfferRequest {
            utxo: split,
            want_asset: POLICY_ASSET.into(),
            want_amount: 10_000,
            receive_index: 5,
        })
        .unwrap();
    let signed_offer = alice
        .sign_prepared(&offer, &offer.review_hash)
        .unwrap()
        .offer
        .unwrap();

    // A taker holding only confidential funds is told why it cannot take.
    let (bob_ct, _) = ct_fund(&bob, 16, policy(), 100_000, Branch::External, 0);
    let take = TakeSwapOffersRequest {
        offers: vec![TakeOfferInput {
            offer: elementsplus_wallet_core::OfferInput::Object(signed_offer.clone()),
            prevout_raw_tx_hex: raw.clone(),
        }],
        fee_rate: 1,
        utxos: vec![bob_ct.clone()],
        change_index: 0,
        receive_index: 1,
    };
    let err = bob.take_swap_offers(&take).unwrap_err();
    assert!(matches!(err, WalletError::Confidential(_)), "{err}");
    // With explicit funds the take ignores the confidential UTXO entirely.
    let mut take = take;
    take.utxos
        .push(fund(&bob, 17, policy(), 40_000, Branch::External, 2).0);
    let prepared = bob.take_swap_offers(&take).unwrap();
    assert!(!prepared.review.confidential);
    assert!(!prepared
        .review
        .inputs_signed
        .contains(&format!("{}:{}", bob_ct.txid, bob_ct.vout)));
    bob.sign_prepared(&prepared, &prepared.review_hash).unwrap();
}

#[test]
fn issuance_and_cancel_can_be_funded_confidentially() {
    let alice = WalletCore::new(ALICE).unwrap();
    let (ct, _) = ct_fund(&alice, 18, policy(), 300_000, Branch::External, 0);
    let prepared = alice
        .prepare_issuance(&IssuanceRequest {
            contract: elementsplus_wallet_core::AssetContract {
                name: "Hidden Funding".into(),
                ticker: "HIDE".into(),
                precision: 0,
                version: 0,
                issuer_pubkey: None,
            },
            amount: 5_000,
            token_amount: 1,
            fee_rate: 1,
            utxos: vec![ct],
            change_index: 1,
            receive_index: 2,
        })
        .unwrap();
    assert!(prepared.review.confidential);
    let issuance = prepared.review.issuance.clone().unwrap();
    let asset = AssetId::from_str(&issuance.asset_id).unwrap();
    assert_eq!(delta(&prepared, asset).as_deref(), Some("5000"));
    assert_eq!(delta(&prepared, policy()), None);
    let pset = pset_of(&prepared);
    // Issued asset and token are explicit; change is blinded.
    assert!(pset.outputs()[0].asset_comm.is_none() && pset.outputs()[1].asset_comm.is_none());
    assert!(pset.outputs()[2].asset_comm.is_some());
    assert!(pset.inputs()[0].blinded_issuance.is_none());
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let raw = signed.raw_tx_hex.unwrap();
    assert_fee_covers(&prepared, &raw, 1);
    assert_eq!(verify_output(&alice, &raw, 0), (asset, 5_000, false));

    // Cancel an explicit offered UTXO, paying the fee from confidential funds.
    let (offered, _) = fund(&alice, 19, token(), 500, Branch::External, 3);
    let (ct_fee, _) = ct_fund(&alice, 20, policy(), 20_000, Branch::External, 4);
    let prepared = alice
        .prepare_cancel(&CancelRequest {
            utxo: offered,
            change_index: 5,
            fee_rate: 1,
            other_utxos: vec![ct_fee],
        })
        .unwrap();
    assert!(prepared.review.confidential);
    assert!(prepared.review.balance_changes.is_empty());
    let raw = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap()
        .raw_tx_hex
        .unwrap();
    assert_fee_covers(&prepared, &raw, 1);
    let tx = decode_tx(&raw);
    assert!(tx.output[..tx.output.len() - 1].iter().all(is_blinded));
}

#[test]
fn explicit_reviews_are_unchanged_by_ct_support() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob
                .derive_address(Branch::External, 0)
                .unwrap()
                .native_address,
            asset_id: POLICY_ASSET.into(),
            amount: 1_000,
            fee_rate: 1,
            utxos: vec![fund(&alice, 21, policy(), 50_000, Branch::External, 0).0],
            change_index: 0,
        })
        .unwrap();
    assert!(!prepared.review.confidential);
    let json = serde_json::to_value(&prepared.review).unwrap();
    assert!(json.get("confidential").is_none());
    assert!(json["external_outputs"][0].get("confidential").is_none());
    // Explicit PSETs are deterministic (no blinding randomness).
    let again = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob
                .derive_address(Branch::External, 0)
                .unwrap()
                .native_address,
            asset_id: POLICY_ASSET.into(),
            amount: 1_000,
            fee_rate: 1,
            utxos: vec![fund(&alice, 21, policy(), 50_000, Branch::External, 0).0],
            change_index: 0,
        })
        .unwrap();
    assert_eq!(prepared, again);
}

#[test]
fn rangeproof_size_bound_holds() {
    let alice = WalletCore::new(ALICE).unwrap();
    // The largest value has the largest 52-bit rangeproof.
    let tx = blinded_funding_tx(
        22,
        policy(),
        elementsplus_wallet_core::MAX_MONEY,
        script_of(&alice, Branch::External, 0),
        blinding_key_of(&alice, Branch::External, 0),
    );
    let witness = &tx.output[0].witness;
    let rangeproof = witness.rangeproof.as_ref().unwrap().serialize().len();
    let surjection = witness.surjection_proof.as_ref().unwrap().serialize().len();
    assert!(rangeproof <= 4_174, "{rangeproof}");
    assert!(surjection <= 2 + 32 + 32 * 4, "{surjection}");
}
