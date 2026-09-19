//! Deterministic, offline proof that the pinned LWK signer can spend an
//! explicit ECX-style P2WPKH UTXO end to end.
//!
//! The outpoint is synthetic and the mnemonic is a public BIP39 test vector.
//! Nothing in this test is suitable for real funds.

use std::str::FromStr;

use elements::bitcoin::{bip32::DerivationPath, PublicKey};
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash;
use elements::pset::{Input, Output, PartiallySignedTransaction};
use elements::secp256k1_zkp::Secp256k1;
use elements::{
    Address, AddressParams, AssetId, BlockHash, OutPoint, Script, Sequence, Transaction, TxOut,
    TxOutWitness, Txid, WPubkeyHash,
};
use elements_miniscript::psbt::finalize;
use elementsplus_lwk_adapter::{
    lwk_network, native_unconfidential_address, preview_explicit_pset,
    validate_explicit_transaction, GENESIS_HASH, POLICY_ASSET,
};
use lwk_common::{set_genesis_hash, Signer};
use lwk_signer::SwSigner;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const INPUT_VALUE: u64 = 100_000;
const RECIPIENT_VALUE: u64 = 40_000;
const CHANGE_VALUE: u64 = 59_500;
const FEE_VALUE: u64 = 500;

fn derived_pubkey(signer: &SwSigner, path: &DerivationPath) -> PublicKey {
    let child = signer.derive_xpub(path).expect("derive test child key");
    PublicKey::new(child.public_key)
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

#[test]
fn mnemonic_to_signed_explicit_ecx_transaction() {
    let network = lwk_network();
    let policy_asset = AssetId::from_str(POLICY_ASSET).expect("frozen policy asset");
    let genesis = BlockHash::from_str(GENESIS_HASH).expect("frozen genesis hash");
    let signer = SwSigner::new_with_network(TEST_MNEMONIC, network)
        .expect("the public BIP39 test mnemonic is valid");

    assert_eq!(
        signer
            .mnemonic()
            .expect("mnemonic-backed signer")
            .word_count(),
        12
    );
    assert_eq!(network.genesis_hash(), genesis);
    assert_eq!(*network.policy_asset(), policy_asset);

    let spend_path = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
    let recipient_path = DerivationPath::from_str("m/84'/1'/0'/0/1").unwrap();
    let change_path = DerivationPath::from_str("m/84'/1'/0'/1/0").unwrap();

    let spend_key = derived_pubkey(&signer, &spend_path);
    let spend_script = p2wpkh_script(&spend_key);
    let spend_address =
        native_unconfidential_address(&spend_script).expect("native address for a witness script");
    assert!(spend_address.to_string().starts_with("elements1"));
    let lwk_alias = Address::from_script(&spend_script, None, &AddressParams::ELEMENTS)
        .expect("LWK-compatible witness alias");
    assert!(lwk_alias.to_string().starts_with("ert1"));
    assert_eq!(lwk_alias.script_pubkey(), spend_script);

    let recipient_script = p2wpkh_script(&derived_pubkey(&signer, &recipient_path));
    let change_script = p2wpkh_script(&derived_pubkey(&signer, &change_path));
    let synthetic_utxo = explicit_output(policy_asset, INPUT_VALUE, spend_script.clone());
    let synthetic_outpoint = OutPoint::new(Txid::from_byte_array([0x42; 32]), 0);

    let mut pset = PartiallySignedTransaction::new_v2();
    let mut input = Input::from_prevout(synthetic_outpoint);
    input.sequence = Some(Sequence::MAX);
    input.witness_utxo = Some(synthetic_utxo.clone());
    input.asset = Some(policy_asset);
    input.amount = Some(INPUT_VALUE);
    input
        .bip32_derivation
        .insert(spend_key, (signer.fingerprint(), spend_path));
    pset.add_input(input);

    pset.add_output(Output::from_txout(explicit_output(
        policy_asset,
        RECIPIENT_VALUE,
        recipient_script.clone(),
    )));
    pset.add_output(Output::from_txout(explicit_output(
        policy_asset,
        CHANGE_VALUE,
        change_script.clone(),
    )));
    pset.add_output(Output::from_txout(explicit_output(
        policy_asset,
        FEE_VALUE,
        Script::new(),
    )));
    set_genesis_hash(&mut pset, &network);

    let preview = preview_explicit_pset(&pset, policy_asset).expect("explicit-only preview");
    assert_eq!(preview.fees[&policy_asset], FEE_VALUE);
    assert_eq!(preview.outputs.len(), 3);
    assert_eq!(
        RECIPIENT_VALUE + CHANGE_VALUE + FEE_VALUE,
        INPUT_VALUE,
        "the synthetic spend must conserve the policy asset"
    );

    let signatures = signer.sign(&mut pset).expect("pinned LWK signer");
    assert_eq!(signatures, 1);
    assert_eq!(pset.inputs()[0].partial_sigs.len(), 1);

    let secp = Secp256k1::verification_only();
    finalize(&mut pset, &secp, genesis).expect("finalize and verify P2WPKH witness");
    assert!(pset.inputs()[0].partial_sigs.is_empty());

    let tx = pset.extract_tx().expect("extract finalized transaction");
    validate_explicit_transaction(&tx).expect("final transaction stays explicit");
    assert_eq!(tx.input.len(), 1);
    assert!(tx.input[0].script_sig.is_empty());
    assert_eq!(tx.input[0].witness.script_witness.len(), 2);
    assert_eq!(tx.input[0].witness.script_witness[1], spend_key.to_bytes());
    assert_eq!(tx.output.len(), 3);
    assert_eq!(tx.output[0].script_pubkey, recipient_script);
    assert_eq!(tx.output[1].script_pubkey, change_script);
    assert!(tx.output[2].is_fee());

    let wire = serialize(&tx);
    let decoded: Transaction = deserialize(&wire).expect("decode serialized transaction");
    assert_eq!(decoded, tx);
    assert_eq!(decoded.txid(), tx.txid());
    assert!(
        wire.len() > 100,
        "serialized transaction includes a witness"
    );
}
