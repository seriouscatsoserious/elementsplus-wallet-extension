//! Offline tests for every operation of the signing core, including
//! adversarial mutations. Only public BIP39 test vectors and synthetic funding
//! transactions are used; nothing is broadcast.

use std::str::FromStr;

use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::pset::{PartiallySignedTransaction, PsbtSighashType};
use elements::{
    AssetId, EcdsaSighashType, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid,
};
use elementsplus_wallet_core::issuance::issuance_ids;
use elementsplus_wallet_core::network::{self, ECX_ALPHA, ECX_BETA, ECX_MAINNET};
use elementsplus_wallet_core::{
    decode_offer_for_profile, verify_asset_issuance, verify_raw_transaction, AssetContract,
    AssetIssuanceVerificationRequest, Branch, CancelRequest, ExpectedWalletOutput, IssuanceRequest,
    Offer, OfferSplitRequest, PreparedTx, RawTransactionVerificationRequest, SwapOfferRequest,
    TakeOfferInput, TakeSwapOffersRequest, TransferRequest, TxKind, VerifiedUtxo, WalletCore,
    WalletError, MAX_MONEY,
};

// Public BIP39 test vectors only. Never use either mnemonic for real funds.
const ALICE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const BOB: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

// These offline vectors were recorded against the retired ECX Alpha chain and
// run on its archived profile; live builds never select it.
const POLICY_ASSET: &str = match ECX_ALPHA.policy_asset {
    Some(asset) => asset,
    None => panic!("archived ECX Alpha profile lost its policy asset"),
};

fn core(mnemonic: &str) -> WalletCore {
    WalletCore::for_archived_profile(mnemonic, &ECX_ALPHA).unwrap()
}

fn decode_offer(
    offer_json: &str,
    prevout_raw_tx_hex: &str,
) -> Result<elementsplus_wallet_core::DecodedOffer, WalletError> {
    decode_offer_for_profile(&ECX_ALPHA, offer_json, prevout_raw_tx_hex)
}

fn policy() -> AssetId {
    AssetId::from_str(POLICY_ASSET).unwrap()
}

fn token() -> AssetId {
    AssetId::from_slice(&[0x77; 32]).unwrap()
}

fn txout(asset: AssetId, value: u64, script: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    }
}

/// A synthetic, consensus-encodable funding transaction.
fn funding_tx(salt: u8, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([salt; 32]), 0),
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }],
        output: outputs,
    }
}

/// Fund a wallet address and return (UTXO, funding tx hex).
fn fund(
    core: &WalletCore,
    salt: u8,
    asset: AssetId,
    value: u64,
    branch: Branch,
    index: u32,
) -> (VerifiedUtxo, String) {
    let address = core.derive_address(branch, index).unwrap();
    let script = Script::from(hex::decode(&address.script_pubkey_hex).unwrap());
    let tx = funding_tx(salt, vec![txout(asset, value, script)]);
    (
        VerifiedUtxo {
            txid: tx.txid().to_string(),
            vout: 0,
            value,
            asset_id: asset.to_string(),
            script_pubkey_hex: address.script_pubkey_hex,
            branch,
            index,
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

fn contract() -> AssetContract {
    AssetContract {
        name: "Test Token".into(),
        ticker: "TEST".into(),
        precision: 2,
        version: 0,
        issuer_pubkey: None,
    }
}

fn transfer_fixture() -> (WalletCore, PreparedTx) {
    let alice = core(ALICE);
    let bob = core(BOB);
    let recipient = bob.derive_address(Branch::External, 7).unwrap();
    let request = TransferRequest {
        recipient: recipient.lwk_alias,
        asset_id: POLICY_ASSET.into(),
        amount: 100_000,
        fee_rate: 1,
        change_index: 3,
        utxos: vec![
            fund(&alice, 0x22, policy(), 70_000, Branch::External, 1).0,
            fund(&alice, 0x11, policy(), 60_000, Branch::External, 0).0,
            fund(&alice, 0x33, policy(), 5_000, Branch::Change, 2).0,
        ],
    };
    let prepared = alice.prepare_transfer(&request).unwrap();
    (alice, prepared)
}

#[test]
fn mnemonic_generation_and_validation() {
    WalletCore::validate_mnemonic(ALICE).unwrap();
    assert!(WalletCore::validate_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    )
    .is_err());
    let generated = WalletCore::generate_mnemonic().unwrap();
    WalletCore::validate_mnemonic(&generated).unwrap();
    assert_eq!(generated.split_whitespace().count(), 12);
}

#[test]
fn policy_transfer_prepare_review_sign_verify() {
    let (alice, prepared) = transfer_fixture();
    let review = &prepared.review;
    assert_eq!(review.kind, TxKind::Transfer);
    assert_eq!(review.sighash, "ALL");
    assert_eq!(review.inputs_signed.len(), 2);
    assert!(review.foreign_inputs.is_empty());
    assert_eq!(review.external_outputs.len(), 1);
    assert_eq!(review.external_outputs[0].amount, 100_000);
    assert!(review.external_outputs[0].address.starts_with("elements1"));
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("-100000"));
    assert!(review.fee > 0 && review.fee < 1_000, "fee {}", review.fee);

    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    assert_eq!(signed.review_hash, prepared.review_hash);
    assert!(signed.offer.is_none());
    let tx = decode_tx(signed.raw_tx_hex.as_deref().unwrap());
    assert_eq!(tx.txid().to_string(), signed.txid);
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 3);
    assert!(tx.output.last().unwrap().is_fee());
    assert!(tx
        .input
        .iter()
        .all(|i| i.script_sig.is_empty() && i.witness.script_witness.len() == 2));
    // Every wallet signature uses SIGHASH_ALL.
    assert!(tx
        .input
        .iter()
        .all(|i| *i.witness.script_witness[0].last().unwrap() == 0x01));
    // The fee covers at least 1 sat/vB of the real transaction.
    let vsize = tx.weight().div_ceil(4) as u64;
    assert!(
        review.fee >= vsize,
        "fee {} below vsize {vsize}",
        review.fee
    );
}

#[test]
fn fee_rate_scales_the_fee() {
    let alice = core(ALICE);
    let bob = core(BOB);
    let recipient = bob
        .derive_address(Branch::External, 0)
        .unwrap()
        .native_address;
    let utxos = vec![fund(&alice, 1, policy(), 1_000_000, Branch::External, 0).0];
    let mut request = TransferRequest {
        recipient,
        asset_id: POLICY_ASSET.into(),
        amount: 10_000,
        fee_rate: 1,
        change_index: 0,
        utxos,
    };
    let slow = alice.prepare_transfer(&request).unwrap().review.fee;
    request.fee_rate = 10;
    let fast = alice.prepare_transfer(&request).unwrap().review.fee;
    assert_eq!(fast, slow * 10);
    request.fee_rate = 0;
    assert!(matches!(
        alice.prepare_transfer(&request),
        Err(WalletError::InvalidFeeRate(_))
    ));
    request.fee_rate = 1_000_000;
    assert!(matches!(
        alice.prepare_transfer(&request),
        Err(WalletError::InvalidFeeRate(_))
    ));
}

#[test]
fn asset_transfer_uses_asset_and_policy_inputs() {
    let alice = core(ALICE);
    let bob = core(BOB);
    let request = TransferRequest {
        recipient: bob
            .derive_address(Branch::External, 1)
            .unwrap()
            .native_address,
        asset_id: token().to_string(),
        amount: 400,
        fee_rate: 2,
        change_index: 1,
        utxos: vec![
            fund(&alice, 1, token(), 1_000, Branch::External, 0).0,
            fund(&alice, 2, policy(), 50_000, Branch::External, 1).0,
        ],
    };
    let prepared = alice.prepare_transfer(&request).unwrap();
    assert_eq!(delta(&prepared, token()).as_deref(), Some("-400"));
    assert_eq!(delta(&prepared, policy()), None, "fee is excluded");
    let pset = pset_of(&prepared);
    // recipient, token change, policy change, fee
    assert_eq!(pset.outputs().len(), 4);
    assert_eq!(pset.outputs()[1].asset, Some(token()));
    assert_eq!(pset.outputs()[1].amount, Some(600));
    assert_eq!(pset.outputs()[2].asset, Some(policy()));
    assert!(pset.outputs()[3].script_pubkey.is_empty());
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    assert_eq!(
        decode_tx(signed.raw_tx_hex.as_deref().unwrap()).input.len(),
        2
    );

    // Not enough of the asset.
    let mut short = request.clone();
    short.amount = 1_001;
    assert!(matches!(
        alice.prepare_transfer(&short),
        Err(WalletError::InsufficientFunds { .. })
    ));
    // No policy coins for the fee.
    let mut no_fee = request;
    no_fee.utxos.truncate(1);
    assert!(matches!(
        alice.prepare_transfer(&no_fee),
        Err(WalletError::InsufficientFunds { .. })
    ));
}

#[test]
fn approval_must_match_exact_hash() {
    let (alice, prepared) = transfer_fixture();
    let error = alice
        .sign_prepared(&prepared, &["00"; 32].join(""))
        .unwrap_err();
    assert!(matches!(error, WalletError::ApprovalMismatch));
}

#[test]
fn review_mismatch_is_rejected() {
    let (alice, prepared) = transfer_fixture();
    // Displayed summary edited, PSET unchanged.
    let mut edited = prepared.clone();
    edited.review.fee += 1;
    assert!(matches!(
        alice.sign_prepared(&edited, &prepared.review_hash),
        Err(WalletError::ReviewMismatch)
    ));
    // PSET edited, summary unchanged.
    let mut pset = pset_of(&prepared);
    pset.outputs_mut()[0].amount = Some(99_999);
    pset.outputs_mut()[1].amount = Some(pset.outputs()[1].amount.unwrap() + 1);
    assert!(matches!(
        alice.sign_prepared(&with_pset(&prepared, &pset), &prepared.review_hash),
        Err(WalletError::ReviewMismatch)
    ));
    // Kind relabelled.
    let mut relabelled = prepared.clone();
    relabelled.review.kind = TxKind::Cancel;
    assert!(alice
        .sign_prepared(&relabelled, &prepared.review_hash)
        .is_err());
}

#[test]
fn changed_pset_and_summary_still_need_new_approval() {
    let (alice, prepared) = transfer_fixture();
    let mut pset = pset_of(&prepared);
    pset.outputs_mut()[0].amount = Some(99_999);
    pset.outputs_mut()[1].amount = Some(pset.outputs()[1].amount.unwrap() + 1);
    let recomputed = alice
        .review_pset(&pset.to_string(), TxKind::Transfer)
        .unwrap();
    assert_ne!(recomputed.review_hash, prepared.review_hash);
    assert!(matches!(
        alice.sign_prepared(&recomputed, &prepared.review_hash),
        Err(WalletError::ApprovalMismatch)
    ));
    alice
        .sign_prepared(&recomputed, &recomputed.review_hash)
        .unwrap();
}

#[test]
fn foreign_output_disguised_as_change_is_external() {
    let (alice, prepared) = transfer_fixture();
    let bob = core(BOB);
    let thief = bob.derive_address(Branch::Change, 3).unwrap();
    let mut pset = pset_of(&prepared);
    // Keep Alice's bip32 derivation on the change output but redirect it.
    pset.outputs_mut()[1].script_pubkey =
        Script::from(hex::decode(&thief.script_pubkey_hex).unwrap());
    assert!(matches!(
        alice.sign_prepared(&with_pset(&prepared, &pset), &prepared.review_hash),
        Err(WalletError::ReviewMismatch)
    ));
    let review = alice
        .review_pset(&pset.to_string(), TxKind::Transfer)
        .unwrap()
        .review;
    assert_eq!(review.external_outputs.len(), 2);
    assert!(review
        .external_outputs
        .iter()
        .any(|o| o.address == thief.native_address));
    let change = pset.outputs()[1].amount.unwrap();
    assert_eq!(
        review.balance_changes[0].amount,
        format!("-{}", 100_000 + change)
    );
}

#[test]
fn wrong_sighash_is_rejected() {
    let (alice, prepared) = transfer_fixture();
    let mut pset = pset_of(&prepared);
    pset.inputs_mut()[0].sighash_type = Some(PsbtSighashType::from(
        EcdsaSighashType::SinglePlusAnyoneCanPay,
    ));
    assert!(matches!(
        alice.sign_prepared(&with_pset(&prepared, &pset), &prepared.review_hash),
        Err(WalletError::InvalidPset(_))
    ));
    pset.inputs_mut()[0].sighash_type = None;
    assert!(matches!(
        alice.review_pset(&pset.to_string(), TxKind::Transfer),
        Err(WalletError::InvalidPset(_))
    ));

    // A swap offer downgraded to SIGHASH_ALL (or relabelled) is refused too.
    let (maker, offer_prepared, _) = offer_fixture();
    let mut pset = pset_of(&offer_prepared);
    pset.inputs_mut()[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    assert!(matches!(
        maker.sign_prepared(
            &with_pset(&offer_prepared, &pset),
            &offer_prepared.review_hash
        ),
        Err(WalletError::InvalidPset(_))
    ));
}

#[test]
fn foreign_inputs_outside_swap_take_are_rejected() {
    let (alice, prepared) = transfer_fixture();
    let mut pset = pset_of(&prepared);
    pset.inputs_mut()[0].bip32_derivation.clear();
    assert!(matches!(
        alice.review_pset(&pset.to_string(), TxKind::Transfer),
        Err(WalletError::InvalidPset(_))
    ));
    // A derivation from another wallet is refused outright.
    let bob = core(BOB);
    assert!(matches!(
        bob.review_pset(&prepared.pset_base64, TxKind::Transfer),
        Err(WalletError::InvalidPset(_))
    ));
}

#[test]
fn foreign_script_duplicates_and_overflow_are_rejected() {
    let alice = core(ALICE);
    let bob = core(BOB);
    let recipient = bob.derive_address(Branch::External, 0).unwrap();

    let mut foreign = fund(&alice, 0x44, policy(), 2_000, Branch::External, 0).0;
    foreign.script_pubkey_hex = recipient.script_pubkey_hex.clone();
    let base = TransferRequest {
        recipient: recipient.native_address.clone(),
        asset_id: POLICY_ASSET.into(),
        amount: 1_000,
        fee_rate: 1,
        change_index: 0,
        utxos: vec![foreign],
    };
    assert!(matches!(
        alice.prepare_transfer(&base),
        Err(WalletError::InvalidUtxo { .. })
    ));

    let same = fund(&alice, 0x55, policy(), 1_000, Branch::External, 0).0;
    let mut dup = base.clone();
    dup.utxos = vec![same.clone(), same];
    assert!(matches!(
        alice.prepare_transfer(&dup),
        Err(WalletError::DuplicateUtxo(_))
    ));

    let mut huge = base.clone();
    huge.utxos = vec![fund(&alice, 0x66, policy(), u64::MAX, Branch::External, 0).0];
    assert!(matches!(
        alice.prepare_transfer(&huge),
        Err(WalletError::InvalidUtxo { .. })
    ));
    let mut huge_amount = base.clone();
    huge_amount.utxos = vec![fund(&alice, 0x67, policy(), MAX_MONEY, Branch::External, 0).0];
    huge_amount.amount = u64::MAX;
    assert!(matches!(
        alice.prepare_transfer(&huge_amount),
        Err(WalletError::AmountOverflow)
    ));

    // JSON boundary: amounts beyond u64 and floats are refused.
    let json = serde_json::to_value(&base).unwrap();
    let mut over = json.clone();
    over["amount"] = "18446744073709551616".into();
    assert!(serde_json::from_value::<TransferRequest>(over).is_err());
    let mut float = json.clone();
    float["amount"] = serde_json::json!(1.5);
    assert!(serde_json::from_value::<TransferRequest>(float).is_err());
    let mut unknown = json;
    unknown["fee"] = 5.into();
    assert!(serde_json::from_value::<TransferRequest>(unknown).is_err());
}

#[test]
fn recipient_must_be_unconfidential_p2wpkh() {
    let alice = core(ALICE);
    let mut request = TransferRequest {
        recipient: alice
            .derive_address(Branch::External, 0)
            .unwrap()
            .native_address
            .to_uppercase(),
        asset_id: POLICY_ASSET.into(),
        amount: 1_000,
        fee_rate: 1,
        change_index: 0,
        utxos: vec![fund(&alice, 9, policy(), 100_000, Branch::External, 0).0],
    };
    assert!(matches!(
        alice.prepare_transfer(&request),
        Err(WalletError::InvalidRecipient(_))
    ));
    request.recipient = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into();
    assert!(matches!(
        alice.prepare_transfer(&request),
        Err(WalletError::InvalidRecipient(_))
    ));
}

#[test]
fn issuance_prepare_sign_and_verify_contract() {
    let alice = core(ALICE);
    let (utxo, _) = fund(&alice, 0x10, policy(), 200_000, Branch::External, 0);
    let request = IssuanceRequest {
        contract: contract(),
        amount: 1_000_000,
        token_amount: 1,
        fee_rate: 1,
        utxos: vec![utxo.clone()],
        change_index: 0,
        receive_index: 4,
    };
    let prepared = alice.prepare_issuance(&request).unwrap();
    let issuance = prepared.review.issuance.clone().unwrap();
    let outpoint = OutPoint::new(Txid::from_str(&utxo.txid).unwrap(), 0);
    let contract_hash = contract().contract_hash().unwrap();
    let (asset_id, token_id) = issuance_ids(outpoint, contract_hash, false);
    assert_eq!(issuance.asset_id, asset_id.to_string());
    assert_eq!(issuance.token_id, Some(token_id.to_string()));
    assert_eq!(issuance.amount, 1_000_000);
    assert_eq!(issuance.token_amount, 1);
    assert_eq!(issuance.contract_hash, contract_hash.to_string());
    assert_eq!(delta(&prepared, asset_id).as_deref(), Some("1000000"));
    assert_eq!(delta(&prepared, token_id).as_deref(), Some("1"));
    assert!(prepared.review.external_outputs.is_empty());
    // Canonical contract JSON is sorted and compact.
    assert_eq!(
        contract().canonical_json(),
        r#"{"name":"Test Token","precision":2,"ticker":"TEST","version":0}"#
    );

    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let raw = signed.raw_tx_hex.unwrap();
    let tx = decode_tx(&raw);
    assert!(tx.input[0].has_issuance());
    assert_eq!(
        tx.input[0].asset_issuance.amount,
        Value::Explicit(1_000_000)
    );
    // The node-side computation agrees with ours.
    let (node_asset, node_token) = tx.input[0].issuance_ids();
    assert_eq!(node_asset, asset_id);
    assert_eq!(node_token, token_id);

    let verify = AssetIssuanceVerificationRequest {
        raw_tx_hex: raw.clone(),
        expected_txid: signed.txid.clone(),
        vin: 0,
        contract: contract(),
    };
    let verified = verify_asset_issuance(&verify).unwrap();
    assert_eq!(verified.asset_id, asset_id.to_string());
    assert_eq!(verified.token_id, Some(token_id.to_string()));
    assert_eq!(verified.contract_hash, contract_hash.to_string());

    // Contract mismatch.
    let mut wrong = verify.clone();
    wrong.contract.ticker = "TESX".into();
    assert!(matches!(
        verify_asset_issuance(&wrong),
        Err(WalletError::Issuance(_))
    ));
    // Txid mismatch and missing issuance input.
    let mut bad_txid = verify.clone();
    bad_txid.expected_txid = ["11"; 32].join("");
    assert!(verify_asset_issuance(&bad_txid).is_err());
    let mut bad_vin = verify;
    bad_vin.vin = 5;
    assert!(verify_asset_issuance(&bad_vin).is_err());
}

#[test]
fn issuance_without_token_and_contract_validation() {
    let alice = core(ALICE);
    let mut request = IssuanceRequest {
        contract: contract(),
        amount: 5,
        token_amount: 0,
        fee_rate: 1,
        utxos: vec![fund(&alice, 0x12, policy(), 200_000, Branch::External, 0).0],
        change_index: 0,
        receive_index: 0,
    };
    let prepared = alice.prepare_issuance(&request).unwrap();
    assert!(prepared
        .review
        .issuance
        .as_ref()
        .unwrap()
        .token_id
        .is_none());
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let verified = verify_asset_issuance(&AssetIssuanceVerificationRequest {
        raw_tx_hex: signed.raw_tx_hex.unwrap(),
        expected_txid: signed.txid,
        vin: 0,
        contract: contract(),
    })
    .unwrap();
    assert!(verified.token_id.is_none());

    for bad in [
        AssetContract {
            ticker: "T".into(),
            ..contract()
        },
        AssetContract {
            precision: 9,
            ..contract()
        },
        AssetContract {
            version: 1,
            ..contract()
        },
        AssetContract {
            name: String::new(),
            ..contract()
        },
        AssetContract {
            issuer_pubkey: Some("02".into()),
            ..contract()
        },
    ] {
        request.contract = bad;
        assert!(matches!(
            alice.prepare_issuance(&request),
            Err(WalletError::Issuance(_))
        ));
    }
    request.contract = contract();
    request.amount = MAX_MONEY + 1;
    assert!(alice.prepare_issuance(&request).is_err());
    // Unknown contract fields are refused at the JSON boundary.
    assert!(serde_json::from_str::<AssetContract>(
        r#"{"name":"A","ticker":"AAA","precision":0,"version":0,"entity":{}}"#
    )
    .is_err());
}

#[test]
fn issuance_tampering_is_rejected() {
    let alice = core(ALICE);
    let request = IssuanceRequest {
        contract: contract(),
        amount: 1_000,
        token_amount: 0,
        fee_rate: 1,
        utxos: vec![fund(&alice, 0x13, policy(), 200_000, Branch::External, 0).0],
        change_index: 0,
        receive_index: 0,
    };
    let prepared = alice.prepare_issuance(&request).unwrap();
    let mut pset = pset_of(&prepared);
    pset.inputs_mut()[0].issuance_value_amount = Some(2_000);
    assert!(alice
        .sign_prepared(&with_pset(&prepared, &pset), &prepared.review_hash)
        .is_err());
    // Issuance smuggled into a transfer.
    assert!(matches!(
        alice.review_pset(&prepared.pset_base64, TxKind::Transfer),
        Err(WalletError::InvalidPset(_))
    ));
}

#[test]
fn offer_split_is_a_self_send() {
    let alice = core(ALICE);
    let request = OfferSplitRequest {
        asset_id: token().to_string(),
        amount: 250,
        fee_rate: 1,
        utxos: vec![
            fund(&alice, 1, token(), 1_000, Branch::External, 0).0,
            fund(&alice, 2, policy(), 10_000, Branch::External, 1).0,
        ],
        change_index: 2,
        receive_index: 9,
    };
    let prepared = alice.prepare_offer_split(&request).unwrap();
    assert_eq!(prepared.review.kind, TxKind::OfferSplit);
    assert!(prepared.review.external_outputs.is_empty());
    assert!(prepared.review.balance_changes.is_empty());
    let pset = pset_of(&prepared);
    assert_eq!(pset.outputs()[0].amount, Some(250));
    assert_eq!(pset.outputs()[0].asset, Some(token()));
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    assert!(signed.raw_tx_hex.is_some());
}

/// Alice offers 500 tokens for 30 000 policy units.
fn offer_fixture() -> (WalletCore, PreparedTx, String) {
    let alice = core(ALICE);
    let (utxo, prevout_hex) = fund(&alice, 0x70, token(), 500, Branch::External, 2);
    let prepared = alice
        .prepare_swap_offer(&SwapOfferRequest {
            utxo,
            want_asset: POLICY_ASSET.into(),
            want_amount: 30_000,
            receive_index: 3,
        })
        .unwrap();
    (alice, prepared, prevout_hex)
}

fn signed_offer() -> (Offer, String) {
    let (alice, prepared, prevout_hex) = offer_fixture();
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    assert!(signed.raw_tx_hex.is_none());
    (signed.offer.unwrap(), prevout_hex)
}

#[test]
fn swap_offer_is_signed_single_anyonecanpay() {
    let (alice, prepared, prevout_hex) = offer_fixture();
    let review = &prepared.review;
    assert_eq!(review.kind, TxKind::SwapOffer);
    assert_eq!(review.sighash, "SINGLE|ANYONECANPAY");
    assert_eq!(review.fee, 0);
    assert!(review.external_outputs.is_empty());
    assert_eq!(delta(&prepared, token()).as_deref(), Some("-500"));
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("30000"));

    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let offer = signed.offer.unwrap();
    assert_eq!(offer.version, 1);
    assert_eq!(offer.network, "ecx-alpha");
    assert_eq!(offer.give.amount, 500);
    assert_eq!(offer.want.amount, 30_000);
    let tx = decode_tx(&offer.tx);
    assert_eq!(tx.txid().to_string(), signed.txid);
    assert_eq!(*tx.input[0].witness.script_witness[0].last().unwrap(), 0x83);
    // Amounts in the offer JSON are decimal strings.
    let json = serde_json::to_value(&offer).unwrap();
    assert_eq!(json["give"]["amount"], "500");

    let offer_json = serde_json::to_string(&offer).unwrap();
    let decoded = decode_offer(&offer_json, &prevout_hex).unwrap();
    assert_eq!(decoded.give_asset, token().to_string());
    assert_eq!(decoded.give_amount, 500);
    assert_eq!(decoded.want_asset, POLICY_ASSET);
    assert_eq!(decoded.want_amount, 30_000);
    assert_eq!(
        decoded.maker_address,
        alice
            .derive_address(Branch::External, 3)
            .unwrap()
            .native_address
    );
    assert_eq!(
        decoded,
        alice.decode_offer(&offer_json, &prevout_hex).unwrap()
    );
}

#[test]
fn swap_offer_request_validation() {
    let alice = core(ALICE);
    let (utxo, _) = fund(&alice, 0x71, token(), 500, Branch::External, 2);
    let mut request = SwapOfferRequest {
        utxo,
        want_asset: token().to_string(),
        want_amount: 1,
        receive_index: 0,
    };
    assert!(matches!(
        alice.prepare_swap_offer(&request),
        Err(WalletError::InvalidRequest(_))
    ));
    request.want_asset = POLICY_ASSET.into();
    request.want_amount = 0;
    assert!(matches!(
        alice.prepare_swap_offer(&request),
        Err(WalletError::ZeroAmount)
    ));
}

#[test]
fn tampered_offers_are_rejected() {
    let (offer, prevout_hex) = signed_offer();
    let check = |offer: &Offer, prevout: &str| {
        decode_offer(&serde_json::to_string(offer).unwrap(), prevout)
    };
    check(&offer, &prevout_hex).unwrap();

    // Convenience copies disagree with the signed transaction.
    let mut want = offer.clone();
    want.want.amount = 29_999;
    assert!(matches!(
        check(&want, &prevout_hex),
        Err(WalletError::Offer(_))
    ));
    let mut give = offer.clone();
    give.give.amount = 501;
    assert!(matches!(
        check(&give, &prevout_hex),
        Err(WalletError::Offer(_))
    ));

    // Signed output changed (and convenience copy updated to match).
    let mut tx = decode_tx(&offer.tx);
    tx.output[0].value = Value::Explicit(1);
    let mut repriced = offer.clone();
    repriced.tx = hex::encode(serialize(&tx));
    repriced.want.amount = 1;
    assert!(matches!(
        check(&repriced, &prevout_hex),
        Err(WalletError::Offer(_))
    ));

    // Signature re-flagged as SIGHASH_ALL.
    let mut tx = decode_tx(&offer.tx);
    *tx.input[0].witness.script_witness[0].last_mut().unwrap() = 0x01;
    let mut reflagged = offer.clone();
    reflagged.tx = hex::encode(serialize(&tx));
    assert!(matches!(
        check(&reflagged, &prevout_hex),
        Err(WalletError::Offer(_))
    ));

    // Prevout transaction that does not hash to the offered txid.
    let alice = core(ALICE);
    let (_, other_prevout) = fund(&alice, 0x99, token(), 500, Branch::External, 2);
    assert!(matches!(
        check(&offer, &other_prevout),
        Err(WalletError::Offer(_))
    ));
    // Prevout with a different value but the same txid is impossible; a
    // forged value in a re-encoded tx changes the txid.
    let mut prev = decode_tx(&prevout_hex);
    prev.output[0].value = Value::Explicit(5_000);
    assert!(check(&offer, &hex::encode(serialize(&prev))).is_err());

    // Wrong network or genesis.
    let mut network = offer.clone();
    network.network = "liquidv1".into();
    assert!(check(&network, &prevout_hex).is_err());
    let mut genesis = offer.clone();
    genesis.genesis_hash = ["00"; 32].join("");
    assert!(check(&genesis, &prevout_hex).is_err());
    // Garbage.
    assert!(decode_offer("{}", &prevout_hex).is_err());
    assert!(decode_offer(&"x".repeat(100_000), &prevout_hex).is_err());
}

fn take_fixture() -> (WalletCore, PreparedTx, Offer) {
    let (offer, prevout_hex) = signed_offer();
    let bob = core(BOB);
    let request = TakeSwapOffersRequest {
        offers: vec![TakeOfferInput {
            offer: elementsplus_wallet_core::OfferInput::Object(offer.clone()),
            prevout_raw_tx_hex: prevout_hex,
        }],
        fee_rate: 1,
        utxos: vec![fund(&bob, 0x80, policy(), 100_000, Branch::External, 0).0],
        change_index: 0,
        receive_index: 5,
    };
    let prepared = bob.take_swap_offers(&request).unwrap();
    (bob, prepared, offer)
}

#[test]
fn take_swap_offer_preserves_maker_witness() {
    let (bob, prepared, offer) = take_fixture();
    let review = &prepared.review;
    assert_eq!(review.kind, TxKind::SwapTake);
    assert_eq!(review.sighash, "ALL");
    assert_eq!(review.foreign_inputs.len(), 1);
    assert_eq!(review.inputs_signed.len(), 1);
    assert_eq!(delta(&prepared, token()).as_deref(), Some("500"));
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("-30000"));
    assert_eq!(review.external_outputs.len(), 1);
    assert_eq!(review.external_outputs[0].amount, 30_000);

    let signed = bob.sign_prepared(&prepared, &prepared.review_hash).unwrap();
    let tx = decode_tx(signed.raw_tx_hex.as_deref().unwrap());
    let maker_tx = decode_tx(&offer.tx);
    assert_eq!(
        tx.input[0].previous_output,
        maker_tx.input[0].previous_output
    );
    assert_eq!(tx.input[0].witness, maker_tx.input[0].witness);
    assert_eq!(tx.output[0], maker_tx.output[0]);
    assert_eq!(*tx.input[1].witness.script_witness[0].last().unwrap(), 0x01);
    assert!(tx.output.last().unwrap().is_fee());
}

#[test]
fn take_with_tampered_maker_witness_is_rejected() {
    let (bob, prepared, _) = take_fixture();
    let mut pset = pset_of(&prepared);
    let witness = pset.inputs_mut()[0].final_script_witness.as_mut().unwrap();
    let sig = &mut witness[0];
    let pos = sig.len() - 2;
    sig[pos] ^= 0x01;
    assert!(matches!(
        bob.review_pset(&pset.to_string(), TxKind::SwapTake),
        Err(WalletError::InvalidPset(_))
    ));
    assert!(bob
        .sign_prepared(&with_pset(&prepared, &pset), &prepared.review_hash)
        .is_err());

    // Maker output repointed to the taker: maker signature no longer covers it.
    let mut pset = pset_of(&prepared);
    let own = bob.derive_address(Branch::External, 0).unwrap();
    pset.outputs_mut()[0].script_pubkey = Script::from(hex::decode(own.script_pubkey_hex).unwrap());
    assert!(bob
        .review_pset(&pset.to_string(), TxKind::SwapTake)
        .is_err());
}

#[test]
fn take_rejects_duplicates_and_wrong_prevout() {
    let (offer, prevout_hex) = signed_offer();
    let bob = core(BOB);
    let entry = TakeOfferInput {
        offer: elementsplus_wallet_core::OfferInput::Object(offer.clone()),
        prevout_raw_tx_hex: prevout_hex.clone(),
    };
    let mut request = TakeSwapOffersRequest {
        offers: vec![entry.clone(), entry.clone()],
        fee_rate: 1,
        utxos: vec![fund(&bob, 0x81, policy(), 100_000, Branch::External, 0).0],
        change_index: 0,
        receive_index: 0,
    };
    assert!(matches!(
        bob.take_swap_offers(&request),
        Err(WalletError::Offer(_))
    ));
    let alice = core(ALICE);
    let (_, wrong_prevout) = fund(&alice, 0x98, token(), 500, Branch::External, 2);
    request.offers = vec![TakeOfferInput {
        prevout_raw_tx_hex: wrong_prevout,
        ..entry.clone()
    }];
    assert!(matches!(
        bob.take_swap_offers(&request),
        Err(WalletError::Offer(_))
    ));
    // Not enough funds to pay the maker.
    request.offers = vec![entry];
    request.utxos = vec![fund(&bob, 0x82, policy(), 20_000, Branch::External, 0).0];
    assert!(matches!(
        bob.take_swap_offers(&request),
        Err(WalletError::InsufficientFunds { .. })
    ));
    // The offer may also be passed as a JSON string.
    let as_string: TakeOfferInput = serde_json::from_value(serde_json::json!({
        "offer": serde_json::to_string(&offer).unwrap(),
        "prevout_raw_tx_hex": prevout_hex,
    }))
    .unwrap();
    request.offers = vec![as_string];
    request.utxos = vec![fund(&bob, 0x83, policy(), 100_000, Branch::External, 0).0];
    bob.take_swap_offers(&request).unwrap();
}

#[test]
fn take_multiple_offers_pairs_indices() {
    let alice = core(ALICE);
    let mut entries = Vec::new();
    for (salt, give, want) in [(0x90u8, 100u64, 7_000u64), (0x91, 200, 11_000)] {
        let (utxo, prevout_hex) = fund(&alice, salt, token(), give, Branch::External, 1);
        let prepared = alice
            .prepare_swap_offer(&SwapOfferRequest {
                utxo,
                want_asset: POLICY_ASSET.into(),
                want_amount: want,
                receive_index: u32::from(salt),
            })
            .unwrap();
        let offer = alice
            .sign_prepared(&prepared, &prepared.review_hash)
            .unwrap()
            .offer
            .unwrap();
        entries.push(TakeOfferInput {
            offer: elementsplus_wallet_core::OfferInput::Object(offer),
            prevout_raw_tx_hex: prevout_hex,
        });
    }
    let bob = core(BOB);
    let prepared = bob
        .take_swap_offers(&TakeSwapOffersRequest {
            offers: entries,
            fee_rate: 2,
            utxos: vec![
                fund(&bob, 0xA0, policy(), 10_000, Branch::External, 0).0,
                fund(&bob, 0xA1, policy(), 15_000, Branch::External, 1).0,
            ],
            change_index: 0,
            receive_index: 0,
        })
        .unwrap();
    assert_eq!(prepared.review.foreign_inputs.len(), 2);
    assert_eq!(delta(&prepared, token()).as_deref(), Some("300"));
    assert_eq!(delta(&prepared, policy()).as_deref(), Some("-18000"));
    let signed = bob.sign_prepared(&prepared, &prepared.review_hash).unwrap();
    let tx = decode_tx(signed.raw_tx_hex.as_deref().unwrap());
    assert_eq!(tx.output[0].value, Value::Explicit(7_000));
    assert_eq!(tx.output[1].value, Value::Explicit(11_000));
}

#[test]
fn cancel_returns_offered_utxo_to_wallet() {
    let alice = core(ALICE);
    let (offered, _) = fund(&alice, 0x70, token(), 500, Branch::External, 2);
    let request = CancelRequest {
        utxo: offered.clone(),
        change_index: 6,
        fee_rate: 1,
        other_utxos: vec![fund(&alice, 0x72, policy(), 5_000, Branch::External, 0).0],
    };
    let prepared = alice.prepare_cancel(&request).unwrap();
    assert_eq!(prepared.review.kind, TxKind::Cancel);
    assert!(prepared.review.external_outputs.is_empty());
    assert!(prepared.review.balance_changes.is_empty());
    assert_eq!(
        prepared.review.inputs_signed[0],
        format!("{}:{}", offered.txid, offered.vout)
    );
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let tx = decode_tx(signed.raw_tx_hex.as_deref().unwrap());
    let first = tx.input[0].previous_output;
    assert_eq!(
        format!("{}:{}", first.txid, first.vout),
        prepared.review.inputs_signed[0]
    );

    // A policy-asset offer can pay its own fee.
    let (policy_offer, _) = fund(&alice, 0x73, policy(), 50_000, Branch::External, 0);
    let prepared = alice
        .prepare_cancel(&CancelRequest {
            utxo: policy_offer,
            change_index: 0,
            fee_rate: 1,
            other_utxos: Vec::new(),
        })
        .unwrap();
    assert_eq!(pset_of(&prepared).inputs().len(), 1);
    // Without policy funds a token offer cannot be cancelled.
    let mut no_fee = request;
    no_fee.other_utxos.clear();
    assert!(matches!(
        alice.prepare_cancel(&no_fee),
        Err(WalletError::InsufficientFunds { .. })
    ));
}

#[test]
fn prepared_json_shape() {
    let (_, prepared) = transfer_fixture();
    let json = serde_json::to_value(&prepared).unwrap();
    assert_eq!(json["review"]["kind"], "transfer");
    assert!(json["review"]["fee"].is_u64());
    assert!(json["review"]["external_outputs"][0]["amount"].is_string());
    assert!(json["review"]["balance_changes"][0]["amount"].is_string());
    let roundtrip: PreparedTx = serde_json::from_value(json).unwrap();
    assert_eq!(roundtrip, prepared);
    // Utxo values may arrive as strings or integers.
    let txid = ["11"; 32].join("");
    let utxo: VerifiedUtxo = serde_json::from_value(serde_json::json!({
        "txid": txid, "vout": 0, "value": "123", "asset_id": POLICY_ASSET,
        "script_pubkey_hex": "00", "branch": "external", "index": 0
    }))
    .unwrap();
    assert_eq!(utxo.value, 123);
}

#[test]
fn raw_transaction_verifier_matches_txid_script_and_explicit_values() {
    let (alice, prepared) = transfer_fixture();
    let recipient_script = pset_of(&prepared).outputs()[0].script_pubkey.clone();
    let signed = alice
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let raw = signed.raw_tx_hex.unwrap();
    let mut request = RawTransactionVerificationRequest {
        expected_txid: signed.txid.clone(),
        raw_transaction_hex: raw.clone(),
        expected_wallet_outputs: vec![ExpectedWalletOutput {
            vout: 0,
            script_pub_key_hex: hex::encode(recipient_script.as_bytes()),
        }],
    };
    let verified = verify_raw_transaction(&request).unwrap();
    assert_eq!(verified.outputs[0].asset_id, POLICY_ASSET);
    assert_eq!(verified.outputs[0].value_atomic, 100_000);

    request.expected_txid = ["00"; 32].join("");
    assert!(verify_raw_transaction(&request).is_err());
    request.expected_txid = signed.txid;
    request.expected_wallet_outputs[0].script_pub_key_hex =
        "00140000000000000000000000000000000000000000".into();
    assert!(verify_raw_transaction(&request).is_err());

    let mut non_explicit = decode_tx(&raw);
    non_explicit.output[0].value = Value::Null;
    request.raw_transaction_hex = hex::encode(serialize(&non_explicit));
    request.expected_txid = non_explicit.txid().to_string();
    request.expected_wallet_outputs[0].script_pub_key_hex =
        hex::encode(recipient_script.as_bytes());
    assert!(verify_raw_transaction(&request).is_err());
}

#[test]
fn pending_and_archived_profiles_are_refused_by_constructors() {
    for profile in [&ECX_BETA, &ECX_MAINNET] {
        let error = WalletCore::for_profile(ALICE, profile).err().unwrap();
        assert!(
            matches!(
                error,
                WalletError::Network(network::NetworkProfileError::Pending(_))
            ),
            "{error}"
        );
        assert!(error.to_string().contains("pending"));
        assert!(decode_offer_for_profile(profile, "{}", "00").is_err());
    }
    assert!(matches!(
        WalletCore::for_profile(ALICE, &ECX_ALPHA),
        Err(WalletError::Network(
            network::NetworkProfileError::Archived(_)
        ))
    ));
    assert!(WalletCore::for_archived_profile(ALICE, &ECX_BETA).is_err());
}

#[test]
fn offers_carry_the_profile_id() {
    let (offer, prevout_hex) = signed_offer();
    assert_eq!(offer.network, ECX_ALPHA.id);
    // Same genesis, different profile id: rejected.
    let mut renamed = offer.clone();
    renamed.network = "ecx-beta".into();
    assert!(decode_offer(&serde_json::to_string(&renamed).unwrap(), &prevout_hex).is_err());
}
