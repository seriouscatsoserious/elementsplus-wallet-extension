use std::str::FromStr;

use elements::confidential::{Asset, Nonce, Value};
use elements::encode::Decodable;
use elements::hashes::Hash;
use elements::hex::FromHex;
use elements::pset::{Output, PartiallySignedTransaction};
use elements::{Address, AddressParams, AssetId, Script, TxOut, TxOutWitness, WPubkeyHash};
use elementsplus_lwk_adapter::{
    explicit_balance, lwk_network, native_unconfidential_address, preview_explicit_pset,
    AdapterError, EcxBlockHeader, EXPLICIT_ONLY_HEIGHT, GENESIS_HASH, NATIVE_ADDRESS_PARAMS,
    PARENT_GENESIS_HASH, POLICY_ASSET,
};

const GENESIS_HEADER: &str = "010000000000000000000000000000000000000000000000000000000000000000000000442a8cedddedf9d942fb1ba52dcd70d8f032288e5320ef3fc7a1bd987c1dc00f08c95a6a00000000015100";
const HEIGHT_84_HEADER: &str = "00000020df1edb47cf709af01ec1cba3a003ba994d43ce6c442af1c687b8f1c5396e26b2d06e56e9247c1e2e64ee3718183dcc4690eabf3a3e26d25200a05666941b3831ecdca16a54000000015100";
const HEIGHT_85_HEADER: &str = "00000f208d3e9df5e30c5064752b70a9600e2e14edc4cec1d6244234d002de64a29d0ef7940732877e2e3aa39fe1dfa83c224f0b6233f762c767db57717ba68bca4606441c23a36a5500000001510022680fdcc3aeb9090ae48ef95b4ff404a2eadc29cf7df9945318acd65bd8c06bf30b2ba89086fc69a55033d3cdb2238b8503924355504d6f60a1f5f89c23bbf97daab7836d0e8d6b88af5722bbdb9833a9bc79c51c3083ae149c89139b0e1157c1360f00000000000000000000000000000000000000000000000000";
const HEIGHT_223_HEADER: &str = "00000f204871760f8c42b7f787f9eb1e4d0a607d808223eecd80cad378b88b4092c93caee0e278c238acd9bad05d6c0be0045cdf75892f1b40245d667e789f2caa6b31e571e1ad6adf00000001510075859df6b7c4d3877e4490c379071976efcf356391ea3227627e0ffebbe50168f30b2ba89086fc69a55033d3cdb2238b8503924355504d6f60a1f5f89c23bbf97daab7836d0e8d6b88af5722bbdb9833a9bc79c51c3083ae149c89139b0e115772370f00000000000000000000000000000000000000000000000000";

fn decode(hex: &str) -> EcxBlockHeader {
    EcxBlockHeader::decode(&Vec::<u8>::from_hex(hex).unwrap()).unwrap()
}

#[test]
fn frozen_lwk_network_identity_matches_release() {
    let network = lwk_network();
    assert_eq!(network.genesis_hash().to_string(), GENESIS_HASH);
    assert_eq!(
        network.parent_genesis_hash().to_string(),
        PARENT_GENESIS_HASH
    );
    assert_eq!(network.policy_asset().to_string(), POLICY_ASSET);
    assert_eq!(EXPLICIT_ONLY_HEIGHT, 84);

    // Upstream's custom-network type still selects its generic Elements aliases.
    assert_eq!(network.address_params(), &AddressParams::ELEMENTS);
}

#[test]
fn native_and_lwk_alias_addresses_resolve_to_the_same_script() {
    let hash = WPubkeyHash::from_byte_array([7; 20]);
    let script = Script::new_v0_wpkh(&hash);
    let native = native_unconfidential_address(&script).unwrap();
    let alias = Address::from_script(&script, None, &AddressParams::ELEMENTS).unwrap();

    assert!(native.to_string().starts_with("elements1"));
    assert!(alias.to_string().starts_with("ert1"));
    assert_eq!(native.script_pubkey(), alias.script_pubkey());
    assert_eq!(native.params, &NATIVE_ADDRESS_PARAMS);
}

#[test]
fn live_headers_parse_and_hash_across_activation() {
    let vectors = [
        (GENESIS_HEADER, 0, GENESIS_HASH, 79),
        (
            HEIGHT_84_HEADER,
            84,
            "f70e9da264de02d0344224d6c1cec4ed142e0e60a9702b7564500ce3f59d3e8d",
            79,
        ),
        (
            HEIGHT_85_HEADER,
            85,
            "20d149b745f6d48ef3851ec282d0d4a4f65512f8ba21a32ec81b643374ac66aa",
            203,
        ),
        (
            HEIGHT_223_HEADER,
            223,
            "c34d7de42dc2aa0e92271b927146cf1f641ec7ec8dd8175233dbccb9a4a99d98",
            203,
        ),
    ];

    for (raw, height, expected_hash, expected_len) in vectors {
        assert_eq!(raw.len() / 2, expected_len);
        let header = decode(raw);
        assert_eq!(header.height, height);
        assert_eq!(header.block_hash().to_string(), expected_hash);
    }

    assert!(decode(HEIGHT_84_HEADER).ecx.exchange_state_root.is_none());
    let activated = decode(HEIGHT_85_HEADER);
    assert!(activated.ecx.exchange_state_root.is_some());
    assert!(activated.ecx.forced_inbox_root.is_some());
    assert!(activated.ecx.deposit_inbox_root.is_some());
    assert!(activated.ecx.forced_processed_cursor.is_some());
}

#[test]
fn stock_header_type_cannot_authenticate_post_activation_blocks() {
    let raw = Vec::<u8>::from_hex(HEIGHT_85_HEADER).unwrap();
    let stock = elements::BlockHeader::consensus_decode(&raw[..]).unwrap();

    // Stock parsing stops after the ordinary 79-byte prefix. Because its type
    // cannot retain the remaining 124 consensus bytes, it hashes a different
    // block. This is why using stock LWK here is unsafe rather than merely
    // cosmetically incomplete.
    assert_ne!(
        stock.block_hash().to_string(),
        "20d149b745f6d48ef3851ec282d0d4a4f65512f8ba21a32ec81b643374ac66aa"
    );
}

#[test]
fn explicit_balance_accepts_explicit_outputs_and_rejects_commitments() {
    let asset = AssetId::from_str(POLICY_ASSET).unwrap();
    let explicit = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(42),
        nonce: Nonce::Null,
        script_pubkey: Script::from(vec![0x51]),
        witness: TxOutWitness::default(),
    };
    let balance = explicit_balance([&explicit]).unwrap();
    assert_eq!(balance[&asset], 42);

    let mut confidential = explicit.clone();
    confidential.nonce = Nonce::Confidential(
        elements::secp256k1_zkp::PublicKey::from_slice(&[
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .unwrap(),
    );
    assert!(matches!(
        explicit_balance([&confidential]),
        Err(AdapterError::ConfidentialOutput { vout: 0 })
    ));
}

#[test]
fn pset_preview_is_explicit_only_and_counts_policy_fees() {
    let asset = AssetId::from_str(POLICY_ASSET).unwrap();
    let mut pset = PartiallySignedTransaction::new_v2();
    let recipient = Output {
        asset: Some(asset),
        amount: Some(50_000),
        script_pubkey: Script::from(vec![0x51]),
        ..Default::default()
    };
    pset.add_output(recipient);

    let fee = Output {
        asset: Some(asset),
        amount: Some(125),
        ..Default::default()
    };
    pset.add_output(fee);

    let preview = preview_explicit_pset(&pset, asset).unwrap();
    assert_eq!(preview.outputs.len(), 2);
    assert_eq!(preview.fees[&asset], 125);

    pset.outputs_mut()[0].blinder_index = Some(0);
    assert!(matches!(
        preview_explicit_pset(&pset, asset),
        Err(AdapterError::BlindingRequested { vout: 0 })
    ));
}

#[test]
fn trailing_header_bytes_are_rejected() {
    let mut raw = Vec::<u8>::from_hex(HEIGHT_223_HEADER).unwrap();
    raw.push(0);
    assert!(matches!(
        EcxBlockHeader::decode(&raw),
        Err(AdapterError::TrailingHeaderBytes(1))
    ));
}
