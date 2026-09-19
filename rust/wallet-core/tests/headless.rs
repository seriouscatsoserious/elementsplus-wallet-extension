use std::str::FromStr;

use elements::pset::PartiallySignedTransaction;
use elementsplus_wallet_core::{
    verify_raw_transaction, Branch, ExpectedWalletOutput, PreparedSend,
    RawTransactionVerificationRequest, SendRequest, VerifiedUtxo, WalletCore, WalletError,
    POLICY_ASSET,
};

// Public BIP39 test vectors only. Never use either mnemonic for real funds.
const ALICE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn utxo(core: &WalletCore, byte: u8, vout: u32, value: u64, index: u32) -> VerifiedUtxo {
    let address = core.derive_address(Branch::External, index).unwrap();
    VerifiedUtxo {
        txid: hex::encode([byte; 32]),
        vout,
        value,
        asset_id: POLICY_ASSET.into(),
        script_pubkey_hex: address.script_pubkey_hex,
        branch: Branch::External,
        index,
    }
}

fn prepared_fixture() -> (WalletCore, PreparedSend) {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let recipient = bob.derive_address(Branch::External, 7).unwrap();
    let request = SendRequest {
        recipient: recipient.lwk_alias,
        amount: 100_000,
        fee: 700,
        change_index: 3,
        // Deliberately reverse lexical order. Selection must be deterministic.
        utxos: vec![
            utxo(&alice, 0x22, 1, 70_000, 1),
            utxo(&alice, 0x11, 0, 60_000, 0),
            utxo(&alice, 0x33, 2, 999_999, 2),
        ],
    };
    let prepared = alice.prepare_send(request).unwrap();
    (alice, prepared)
}

#[test]
fn mnemonic_address_prepare_review_sign_finalize_verify() {
    WalletCore::validate_mnemonic(ALICE).unwrap();
    assert!(WalletCore::validate_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    )
    .is_err());

    let generated = WalletCore::generate_mnemonic().unwrap();
    WalletCore::validate_mnemonic(&generated).unwrap();
    assert_eq!(generated.split_whitespace().count(), 12);

    let (alice, prepared) = prepared_fixture();
    assert_eq!(prepared.review.input_count, 2);
    assert_eq!(prepared.review.total_input, 130_000);
    assert_eq!(prepared.review.amount, 100_000);
    assert_eq!(prepared.review.fee, 700);
    assert_eq!(prepared.review.change, 29_300);
    assert!(prepared
        .review
        .recipient_native_address
        .starts_with("elements1"));
    assert!(prepared
        .review
        .change_native_address
        .as_deref()
        .unwrap()
        .starts_with("elements1"));
    assert_eq!(prepared.review.selected_outpoints.len(), 2);

    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    assert_eq!(signed.review_hash, prepared.review_hash);
    assert_eq!(signed.txid.len(), 64);
    assert!(signed.raw_tx_hex.len() > 200);

    let tx: elements::Transaction =
        elements::encode::deserialize(&hex::decode(&signed.raw_tx_hex).unwrap()).unwrap();
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 3);
    assert!(tx
        .input
        .iter()
        .all(|input| { input.script_sig.is_empty() && input.witness.script_witness.len() == 2 }));
    assert!(tx.output.iter().all(|output| {
        matches!(output.asset, elements::confidential::Asset::Explicit(_))
            && matches!(output.value, elements::confidential::Value::Explicit(_))
            && matches!(output.nonce, elements::confidential::Nonce::Null)
    }));
    assert!(tx.output.last().unwrap().is_fee());
}

#[test]
fn exact_review_hash_is_required() {
    let (alice, prepared) = prepared_fixture();
    let error = alice
        .sign_prepared(&prepared, &["00"; 32].join(""))
        .unwrap_err();
    assert!(matches!(error, WalletError::ApprovalMismatch));
}

#[test]
fn pset_mutation_is_rejected_even_when_displayed_summary_is_unchanged() {
    let (alice, mut prepared) = prepared_fixture();
    let mut pset = PartiallySignedTransaction::from_str(&prepared.pset_base64).unwrap();
    pset.outputs_mut()[0].amount = Some(prepared.review.amount - 1);
    pset.outputs_mut()[1].amount = Some(prepared.review.change + 1);
    prepared.pset_base64 = pset.to_string();

    let error = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap_err();
    assert!(matches!(error, WalletError::ReviewMismatch));
}

#[test]
fn changed_pset_and_changed_summary_still_need_a_new_explicit_approval() {
    let (alice, mut prepared) = prepared_fixture();
    let mut pset = PartiallySignedTransaction::from_str(&prepared.pset_base64).unwrap();
    pset.outputs_mut()[0].amount = Some(prepared.review.amount - 1);
    pset.outputs_mut()[1].amount = Some(prepared.review.change + 1);
    prepared.pset_base64 = pset.to_string();
    prepared.review.amount -= 1;
    prepared.review.change += 1;

    let error = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap_err();
    assert!(matches!(error, WalletError::ApprovalMismatch));
}

#[test]
fn foreign_script_and_duplicate_outpoints_are_rejected() {
    let alice = WalletCore::new(ALICE).unwrap();
    let bob = WalletCore::new(BOB).unwrap();
    let recipient = bob.derive_address(Branch::External, 0).unwrap();

    let mut foreign = utxo(&alice, 0x44, 0, 2_000, 0);
    foreign.script_pubkey_hex = recipient.script_pubkey_hex.clone();
    let error = alice
        .prepare_send(SendRequest {
            recipient: recipient.native_address.clone(),
            amount: 1_000,
            fee: 100,
            change_index: 0,
            utxos: vec![foreign],
        })
        .unwrap_err();
    assert!(matches!(error, WalletError::InvalidUtxo { .. }));

    let same = utxo(&alice, 0x55, 0, 1_000, 0);
    let error = alice
        .prepare_send(SendRequest {
            recipient: recipient.native_address,
            amount: 1_500,
            fee: 100,
            change_index: 0,
            utxos: vec![same.clone(), same],
        })
        .unwrap_err();
    assert!(matches!(error, WalletError::DuplicateUtxo(_)));
}

#[test]
fn raw_transaction_verifier_matches_txid_script_and_explicit_values() {
    let (alice, prepared) = prepared_fixture();
    let recipient_script = PartiallySignedTransaction::from_str(&prepared.pset_base64)
        .unwrap()
        .outputs()[0]
        .script_pubkey
        .clone();
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let request = RawTransactionVerificationRequest {
        expected_txid: signed.txid.clone(),
        raw_transaction_hex: signed.raw_tx_hex,
        expected_wallet_outputs: vec![ExpectedWalletOutput {
            vout: 0,
            script_pub_key_hex: hex::encode(recipient_script.as_bytes()),
        }],
    };
    let verified = verify_raw_transaction(&request).unwrap();
    assert_eq!(verified.txid, signed.txid);
    assert_eq!(verified.outputs.len(), 1);
    assert_eq!(verified.outputs[0].vout, 0);
    assert_eq!(verified.outputs[0].asset_id, POLICY_ASSET);
    assert_eq!(verified.outputs[0].value_atomic, 100_000);
}

#[test]
fn raw_transaction_verifier_rejects_txid_script_and_non_explicit_mutations() {
    let (alice, prepared) = prepared_fixture();
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let tx: elements::Transaction =
        elements::encode::deserialize(&hex::decode(&signed.raw_tx_hex).unwrap()).unwrap();
    let script = hex::encode(tx.output[0].script_pubkey.as_bytes());
    let mut request = RawTransactionVerificationRequest {
        expected_txid: ["00"; 32].join(""),
        raw_transaction_hex: signed.raw_tx_hex.clone(),
        expected_wallet_outputs: vec![ExpectedWalletOutput {
            vout: 0,
            script_pub_key_hex: script.clone(),
        }],
    };
    assert!(matches!(
        verify_raw_transaction(&request),
        Err(WalletError::RawTransaction(_))
    ));

    request.expected_txid = signed.txid;
    request.expected_wallet_outputs[0].script_pub_key_hex =
        "00140000000000000000000000000000000000000000".into();
    assert!(matches!(
        verify_raw_transaction(&request),
        Err(WalletError::RawTransaction(_))
    ));

    let mut non_explicit = tx;
    non_explicit.output[0].value = elements::confidential::Value::Null;
    request.raw_transaction_hex = hex::encode(elements::encode::serialize(&non_explicit));
    request.expected_txid = non_explicit.txid().to_string();
    request.expected_wallet_outputs[0].script_pub_key_hex = script;
    assert!(matches!(
        verify_raw_transaction(&request),
        Err(WalletError::RawTransaction(_))
    ));
}
