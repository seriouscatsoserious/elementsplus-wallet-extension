//! Opt-in live Elements+ regtest tests through the exact wallet core.
//!
//! These tests are ignored by default and refuse to run without an explicit
//! `ELEMENTS_DATADIR`, so an ordinary test run can never spend node funds.
//! They expect a node started like `scripts/regtest-stack.mjs` does, with a
//! funded descriptor wallet (default name `miner`):
//!
//! ```sh
//! ELEMENTS_CLI=.../elements-functional-test-cli ELEMENTS_DATADIR=... \
//! ELEMENTS_RPCPORT=19901 cargo test --locked --test funded_elements -- \
//!   --ignored --test-threads=1
//! ```
//!
//! Every run uses freshly generated mnemonics, so repeated runs are isolated.

use std::collections::BTreeSet;
use std::env;
use std::process::Command;

use elements::encode::deserialize;
use elements::{AddressParams, AssetId, BlockHash, Transaction};
use elementsplus_wallet_core::{
    verify_asset_issuance, AssetContract, AssetIssuanceVerificationRequest, Branch, CancelRequest,
    ExpectedWalletOutput, IssuanceRequest, OfferInput, OfferSplitRequest, PreparedTx,
    RawTransactionVerificationRequest, SwapOfferRequest, TakeOfferInput, TakeSwapOffersRequest,
    TransferRequest, TxKind, VerifiedUtxo, WalletCore,
};
use lwk_common::{ElementsParamsBuilder, Network};
use serde_json::Value;

struct ElementsCli {
    executable: String,
    datadir: String,
    chain: String,
    rpc_port: String,
    wallet: String,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
}

impl ElementsCli {
    fn from_env() -> Self {
        Self {
            executable: env::var("ELEMENTS_CLI").unwrap_or_else(|_| "elements-cli".into()),
            datadir: env::var("ELEMENTS_DATADIR")
                .expect("set ELEMENTS_DATADIR to opt into spending disposable regtest funds"),
            chain: env::var("ELEMENTS_CHAIN").unwrap_or_else(|_| "elementsregtest".into()),
            rpc_port: env::var("ELEMENTS_RPCPORT").unwrap_or_else(|_| "19843".into()),
            wallet: env::var("ELEMENTS_RPCWALLET").unwrap_or_else(|_| "miner".into()),
            rpc_user: env::var("ELEMENTS_RPCUSER").ok(),
            rpc_password: env::var("ELEMENTS_RPCPASSWORD").ok(),
        }
    }

    fn try_json(&self, method: &str, args: &[&str]) -> Result<Value, String> {
        let mut command = Command::new(&self.executable);
        command
            .arg(format!("-chain={}", self.chain))
            .arg(format!("-datadir={}", self.datadir))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcwallet={}", self.wallet));
        if let Some(user) = &self.rpc_user {
            command.arg(format!("-rpcuser={user}"));
        }
        if let Some(password) = &self.rpc_password {
            command.arg(format!("-rpcpassword={password}"));
        }
        let output = command
            .arg(method)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("failed to execute {}: {error}", self.executable));
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if stdout.is_empty() {
            return Ok(Value::Null);
        }
        // bitcoin-cli style clients print top-level JSON strings without
        // quotes while retaining JSON for arrays and objects.
        Ok(serde_json::from_str(&stdout).unwrap_or(Value::String(stdout)))
    }

    fn json(&self, method: &str, args: &[&str]) -> Value {
        self.try_json(method, args)
            .unwrap_or_else(|error| panic!("{method} failed: {error}"))
    }

    fn string(&self, method: &str, args: &[&str]) -> String {
        self.json(method, args)
            .as_str()
            .unwrap_or_else(|| panic!("{method} did not return a string"))
            .to_owned()
    }

    fn mine(&self) {
        let address = self.string("getnewaddress", &[]);
        self.json("generatetoaddress", &["1", &address]);
    }

    fn raw_tx(&self, txid: &str) -> String {
        self.string("getrawtransaction", &[txid])
    }

    fn broadcast_and_mine(&self, raw_tx_hex: &str, expected_txid: &str) {
        let accepted = self.string("sendrawtransaction", &[raw_tx_hex]);
        assert_eq!(accepted, expected_txid);
        self.mine();
        let verbose = self.json("getrawtransaction", &[expected_txid, "true"]);
        assert!(
            verbose["confirmations"].as_u64().unwrap_or(0) >= 1,
            "{expected_txid} was not mined"
        );
    }

    fn is_unspent(&self, txid: &str, vout: u32) -> bool {
        self.json("gettxout", &[txid, &vout.to_string()])
            .is_object()
    }
}

fn regtest_core(cli: &ElementsCli, mnemonic: &str) -> WalletCore {
    let genesis: BlockHash = cli
        .string("getblockhash", &["0"])
        .parse()
        .expect("valid genesis hash");
    let policy_asset: AssetId = cli.json("getsidechaininfo", &[])["pegged_asset"]
        .as_str()
        .expect("getsidechaininfo exposes pegged_asset")
        .parse()
        .expect("valid policy asset");
    let network = Network::CustomElements(
        ElementsParamsBuilder::new()
            .with_genesis_hash(genesis)
            .with_policy_asset(policy_asset)
            .build()
            .expect("complete regtest network identity"),
    );
    // The pinned functional-test node uses the generic Elements regtest
    // encoding (`ert1`), exactly like the `forRegtest` WASM constructor.
    WalletCore::new_for_network(
        mnemonic,
        network,
        "funded Elements+ regtest",
        &AddressParams::ELEMENTS,
        &AddressParams::ELEMENTS,
    )
    .unwrap()
}

fn decode(raw_hex: &str) -> Transaction {
    deserialize(&hex::decode(raw_hex).unwrap()).unwrap()
}

/// Locally scan a transaction for outputs paying the first few wallet slots.
fn wallet_utxos(core: &WalletCore, raw_hex: &str) -> Vec<VerifiedUtxo> {
    let tx = decode(raw_hex);
    let mut found = Vec::new();
    for branch in [Branch::External, Branch::Change] {
        for index in 0..12 {
            let address = core.derive_address(branch, index).unwrap();
            for (vout, output) in tx.output.iter().enumerate() {
                if hex::encode(output.script_pubkey.as_bytes()) != address.script_pubkey_hex {
                    continue;
                }
                let (asset, value) = match (output.asset, output.value) {
                    (
                        elements::confidential::Asset::Explicit(asset),
                        elements::confidential::Value::Explicit(value),
                    ) => (asset, value),
                    _ => panic!("wallet output is not explicit"),
                };
                found.push(VerifiedUtxo {
                    txid: tx.txid().to_string(),
                    vout: vout as u32,
                    value,
                    asset_id: asset.to_string(),
                    script_pubkey_hex: address.script_pubkey_hex.clone(),
                    branch,
                    index,
                    blinding: None,
                });
            }
        }
    }
    found
}

/// Remove spent inputs and add newly received outputs.
fn apply(set: &mut Vec<VerifiedUtxo>, core: &WalletCore, prepared: &PreparedTx, raw_hex: &str) {
    let spent: BTreeSet<_> = prepared.review.inputs_signed.iter().cloned().collect();
    set.retain(|u| !spent.contains(&format!("{}:{}", u.txid, u.vout)));
    set.extend(wallet_utxos(core, raw_hex));
}

fn fund_policy(cli: &ElementsCli, core: &WalletCore, index: u32, amount: &str) -> VerifiedUtxo {
    let address = core.derive_address(Branch::External, index).unwrap();
    let txid = cli.string("sendtoaddress", &[&address.native_address, amount]);
    wallet_utxos(core, &cli.raw_tx(&txid))
        .into_iter()
        .find(|u| u.index == index && u.branch == Branch::External)
        .expect("funding output")
}

fn sign(core: &WalletCore, prepared: &PreparedTx) -> (String, String) {
    let signed = core.sign_prepared(prepared, &prepared.review_hash).unwrap();
    (signed.txid, signed.raw_tx_hex.expect("broadcastable"))
}

#[test]
#[ignore = "spends disposable node funds; set ELEMENTS_DATADIR and run explicitly"]
fn funded_policy_transfer_is_mined() {
    let cli = ElementsCli::from_env();
    let alice = regtest_core(&cli, &WalletCore::generate_mnemonic().unwrap());
    let utxo = fund_policy(&cli, &alice, 0, "1.00000000");
    assert_eq!(utxo.value, 100_000_000);
    assert_eq!(utxo.asset_id, alice.policy_asset().to_string());
    cli.mine();

    let destination = cli.string("getnewaddress", &[]);
    let destination = cli.json("getaddressinfo", &[&destination])["unconfidential"]
        .as_str()
        .expect("node provides an unconfidential destination")
        .to_owned();
    let prepared = alice
        .prepare_transfer(&TransferRequest {
            recipient: destination,
            asset_id: alice.policy_asset().to_string(),
            amount: 90_000_000,
            fee_rate: 1,
            change_index: 0,
            utxos: vec![utxo],
        })
        .unwrap();
    let (txid, raw) = sign(&alice, &prepared);
    cli.broadcast_and_mine(&raw, &txid);
    let entry = cli.json("getrawtransaction", &[&txid, "true"]);
    let vsize = entry["vsize"].as_u64().unwrap();
    assert!(
        prepared.review.fee >= vsize,
        "fee {} < vsize {vsize}",
        prepared.review.fee
    );
}

#[test]
#[ignore = "spends disposable node funds; set ELEMENTS_DATADIR and run explicitly"]
fn funded_issue_transfer_swap_and_cancel_are_mined() {
    let cli = ElementsCli::from_env();
    let alice = regtest_core(&cli, &WalletCore::generate_mnemonic().unwrap());
    let bob = regtest_core(&cli, &WalletCore::generate_mnemonic().unwrap());
    let policy = alice.policy_asset();

    let mut alice_utxos = vec![
        fund_policy(&cli, &alice, 0, "1.00000000"),
        fund_policy(&cli, &alice, 1, "1.00000000"),
    ];
    let mut bob_utxos = vec![fund_policy(&cli, &bob, 0, "1.00000000")];
    cli.mine();

    // 1. Issue an explicit asset plus one reissuance token.
    let contract = AssetContract {
        name: "Regtest Token".into(),
        ticker: "RGT".into(),
        precision: 0,
        version: 0,
        issuer_pubkey: None,
    };
    let issuance = alice
        .prepare_issuance(&IssuanceRequest {
            contract: contract.clone(),
            amount: 1_000_000,
            token_amount: 1,
            fee_rate: 1,
            utxos: vec![alice_utxos[0].clone()],
            change_index: 0,
            receive_index: 2,
        })
        .unwrap();
    let (issuance_txid, raw) = sign(&alice, &issuance);
    cli.broadcast_and_mine(&raw, &issuance_txid);
    apply(&mut alice_utxos, &alice, &issuance, &raw);
    let issued = issuance.review.issuance.clone().unwrap();
    let verified = verify_asset_issuance(&AssetIssuanceVerificationRequest {
        raw_tx_hex: cli.raw_tx(&issuance_txid),
        expected_txid: issuance_txid.clone(),
        vin: 0,
        contract: contract.clone(),
    })
    .unwrap();
    assert_eq!(verified.asset_id, issued.asset_id);
    assert_eq!(verified.token_id, issued.token_id);
    let node_view = cli.json("getrawtransaction", &[&issuance_txid, "true"]);
    assert_eq!(
        node_view["vin"][0]["issuance"]["asset"].as_str(),
        Some(issued.asset_id.as_str()),
        "node computes the same asset id"
    );
    assert_eq!(
        node_view["vin"][0]["issuance"]["token"].as_str(),
        issued.token_id.as_deref(),
        "node computes the same token id"
    );
    let asset: AssetId = issued.asset_id.parse().unwrap();

    // 2. Transfer some of the asset to Bob.
    let bob_receive = bob.derive_address(Branch::External, 1).unwrap();
    let transfer = alice
        .prepare_transfer(&TransferRequest {
            recipient: bob_receive.native_address.clone(),
            asset_id: asset.to_string(),
            amount: 1_000,
            fee_rate: 1,
            change_index: 1,
            utxos: alice_utxos.clone(),
        })
        .unwrap();
    assert_eq!(transfer.review.balance_changes.len(), 1);
    let (transfer_txid, raw) = sign(&alice, &transfer);
    cli.broadcast_and_mine(&raw, &transfer_txid);
    apply(&mut alice_utxos, &alice, &transfer, &raw);
    let bob_asset = wallet_utxos(&bob, &raw);
    assert_eq!(bob_asset.len(), 1);
    assert_eq!(bob_asset[0].value, 1_000);
    assert_eq!(bob_asset[0].asset_id, asset.to_string());
    assert!(cli.is_unspent(&transfer_txid, bob_asset[0].vout));
    bob_utxos.extend(bob_asset);

    // 3. Split an exact 50 000-unit output for an offer.
    let split = alice
        .prepare_offer_split(&OfferSplitRequest {
            asset_id: asset.to_string(),
            amount: 50_000,
            fee_rate: 1,
            utxos: alice_utxos.clone(),
            change_index: 2,
            receive_index: 3,
        })
        .unwrap();
    let (split_txid, raw) = sign(&alice, &split);
    cli.broadcast_and_mine(&raw, &split_txid);
    apply(&mut alice_utxos, &alice, &split, &raw);
    let offered = alice_utxos
        .iter()
        .find(|u| u.txid == split_txid && u.value == 50_000)
        .cloned()
        .expect("split output");

    // 4. Maker offer: 50 000 RGT for 0.1 policy coin.
    let offer_prepared = alice
        .prepare_swap_offer(&SwapOfferRequest {
            utxo: offered.clone(),
            want_asset: policy.to_string(),
            want_amount: 10_000_000,
            receive_index: 4,
        })
        .unwrap();
    assert_eq!(offer_prepared.review.kind, TxKind::SwapOffer);
    let offer = alice
        .sign_prepared(&offer_prepared, &offer_prepared.review_hash)
        .unwrap()
        .offer
        .unwrap();
    let offer_json = serde_json::to_string(&offer).unwrap();
    let decoded = bob
        .decode_offer(&offer_json, &cli.raw_tx(&split_txid))
        .unwrap();
    assert_eq!(decoded.give_amount, 50_000);
    assert_eq!(decoded.want_amount, 10_000_000);
    // The lone maker half is not a valid transaction on its own.
    assert!(cli.try_json("sendrawtransaction", &[&offer.tx]).is_err());

    // 5. Taker (different mnemonic) fills the offer.
    let take = bob
        .take_swap_offers(&TakeSwapOffersRequest {
            offers: vec![TakeOfferInput {
                offer: OfferInput::Json(offer_json),
                prevout_raw_tx_hex: cli.raw_tx(&split_txid),
            }],
            fee_rate: 1,
            utxos: bob_utxos.clone(),
            change_index: 0,
            receive_index: 5,
        })
        .unwrap();
    assert_eq!(take.review.foreign_inputs, vec![decoded.outpoint.clone()]);
    let (take_txid, raw) = sign(&bob, &take);
    cli.broadcast_and_mine(&raw, &take_txid);
    apply(&mut bob_utxos, &bob, &take, &raw);
    assert!(!cli.is_unspent(&offered.txid, offered.vout));
    let take_tx = decode(&raw);
    assert_eq!(
        hex::encode(take_tx.output[0].script_pubkey.as_bytes()),
        alice
            .derive_address(Branch::External, 4)
            .unwrap()
            .script_pubkey_hex
    );
    assert!(cli.is_unspent(&take_txid, 0), "maker payment is unspent");
    let received = bob_utxos
        .iter()
        .find(|u| u.txid == take_txid && u.asset_id == asset.to_string())
        .expect("taker received the asset");
    assert_eq!(received.value, 50_000);
    // The maker's offered coin is gone; the payment arrived instead.
    alice_utxos.retain(|u| !(u.txid == offered.txid && u.vout == offered.vout));
    alice_utxos.extend(wallet_utxos(&alice, &raw));

    // 6. Make another offer, cancel it, and show it can no longer be taken.
    let remaining = alice_utxos
        .iter()
        .find(|u| u.asset_id == asset.to_string())
        .cloned()
        .expect("asset change");
    let offer2_prepared = alice
        .prepare_swap_offer(&SwapOfferRequest {
            utxo: remaining.clone(),
            want_asset: policy.to_string(),
            want_amount: 1_000_000,
            receive_index: 6,
        })
        .unwrap();
    let offer2 = alice
        .sign_prepared(&offer2_prepared, &offer2_prepared.review_hash)
        .unwrap()
        .offer
        .unwrap();
    let others: Vec<_> = alice_utxos
        .iter()
        .filter(|u| u.asset_id == policy.to_string())
        .cloned()
        .collect();
    let cancel = alice
        .prepare_cancel(&CancelRequest {
            utxo: remaining.clone(),
            change_index: 3,
            fee_rate: 1,
            other_utxos: others,
        })
        .unwrap();
    assert!(cancel.review.external_outputs.is_empty());
    let (cancel_txid, raw) = sign(&alice, &cancel);
    cli.broadcast_and_mine(&raw, &cancel_txid);
    apply(&mut alice_utxos, &alice, &cancel, &raw);
    assert!(!cli.is_unspent(&remaining.txid, remaining.vout));
    assert!(alice_utxos
        .iter()
        .any(|u| u.txid == cancel_txid && u.value == remaining.value));

    let stale = bob
        .take_swap_offers(&TakeSwapOffersRequest {
            offers: vec![TakeOfferInput {
                offer: OfferInput::Object(offer2),
                prevout_raw_tx_hex: cli.raw_tx(&remaining.txid),
            }],
            fee_rate: 1,
            utxos: bob_utxos.clone(),
            change_index: 1,
            receive_index: 7,
        })
        .unwrap();
    let (_, stale_raw) = sign(&bob, &stale);
    let verdict = cli.json("testmempoolaccept", &[&format!("[\"{stale_raw}\"]")]);
    assert_eq!(
        verdict[0]["allowed"],
        Value::Bool(false),
        "cancelled offer must not be takeable: {verdict}"
    );
    let reason = verdict[0]["reject-reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("missing") || reason.contains("spent"),
        "rejected for the spent maker input, not something else: {verdict}"
    );
}

/// Verify (and unblind) every output of `raw_hex` paying the first wallet
/// slots, exactly as the extension scanner does through the core.
fn verified_wallet_utxos(core: &WalletCore, raw_hex: &str) -> Vec<VerifiedUtxo> {
    let tx = decode(raw_hex);
    let mut found = Vec::new();
    for branch in [Branch::External, Branch::Change] {
        for index in 0..12 {
            let address = core.derive_address(branch, index).unwrap();
            let expected: Vec<_> = tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, o)| {
                    hex::encode(o.script_pubkey.as_bytes()) == address.script_pubkey_hex
                })
                .map(|(vout, _)| ExpectedWalletOutput {
                    vout: vout as u32,
                    script_pub_key_hex: address.script_pubkey_hex.clone(),
                })
                .collect();
            if expected.is_empty() {
                continue;
            }
            let verified = core
                .verify_raw_transaction(&RawTransactionVerificationRequest {
                    expected_txid: tx.txid().to_string(),
                    raw_transaction_hex: raw_hex.into(),
                    expected_wallet_outputs: expected,
                })
                .expect("wallet outputs verify and unblind");
            for output in verified.outputs {
                found.push(VerifiedUtxo {
                    txid: verified.txid.clone(),
                    vout: output.vout,
                    value: output.value_atomic,
                    asset_id: output.asset_id,
                    script_pubkey_hex: output.script_pub_key_hex,
                    branch,
                    index,
                    blinding: output.blinding,
                });
            }
        }
    }
    found
}

/// Amount (in BTC-style decimal) the node's wallet received in `txid`.
fn node_received(cli: &ElementsCli, txid: &str, asset: &str) -> f64 {
    let entry = cli.json("gettransaction", &[txid]);
    entry["details"]
        .as_array()
        .expect("details")
        .iter()
        .filter(|d| d["category"] == "receive" && d["asset"].as_str() == Some(asset))
        .map(|d| d["amount"].as_f64().unwrap())
        .sum()
}

#[test]
#[ignore = "spends disposable node funds; set ELEMENTS_DATADIR and run explicitly"]
fn funded_confidential_receive_and_spend_are_mined() {
    let cli = ElementsCli::from_env();
    let mut alice = regtest_core(&cli, &WalletCore::generate_mnemonic().unwrap());
    alice.set_confidential_receive(true);
    let policy = alice.policy_asset().to_string();
    let policy_hex = policy.clone();

    // 1. The node wallet pays Alice's confidential address; it blinds the
    //    output by default.
    let receive = alice.derive_address(Branch::External, 0).unwrap();
    let confidential_address = receive.confidential_address.clone().unwrap();
    assert!(confidential_address.starts_with("el1"));
    let funding_txid = cli.string("sendtoaddress", &[&confidential_address, "1.00000000"]);
    cli.mine();
    let funding_raw = cli.raw_tx(&funding_txid);
    let funding_tx = decode(&funding_raw);
    let wallet_vout = funding_tx
        .output
        .iter()
        .position(|o| hex::encode(o.script_pubkey.as_bytes()) == receive.script_pubkey_hex)
        .expect("payment to the wallet");
    assert!(
        funding_tx.output[wallet_vout].value.is_confidential()
            && funding_tx.output[wallet_vout].asset.is_confidential(),
        "the node blinded the payment"
    );
    let utxos = verified_wallet_utxos(&alice, &funding_raw);
    assert_eq!(utxos.len(), 1);
    let received = utxos[0].clone();
    assert_eq!(received.value, 100_000_000);
    assert_eq!(received.asset_id, policy);
    assert!(received.blinding.is_some());
    eprintln!("confidential funding {funding_txid}:{wallet_vout}");

    // 2. Spend it back to a confidential node address (CT -> CT).
    let node_address = cli.string("getnewaddress", &[]);
    assert!(node_address.starts_with("el1"));
    let to_node = alice
        .prepare_transfer(&TransferRequest {
            recipient: node_address,
            asset_id: policy.clone(),
            amount: 40_000_000,
            fee_rate: 1,
            change_index: 0,
            utxos: vec![received],
        })
        .unwrap();
    assert!(to_node.review.confidential);
    assert!(to_node.review.external_outputs[0].confidential);
    assert_eq!(
        to_node.review.balance_changes[0].amount, "-40000000",
        "exact delta"
    );
    let (txid, raw) = sign(&alice, &to_node);
    cli.broadcast_and_mine(&raw, &txid);
    eprintln!("confidential -> confidential spend {txid}");
    // The node unblinds its own output to exactly the reviewed amount.
    assert_eq!(node_received(&cli, &txid, &policy_hex), 0.4);
    let vsize = cli.json("getrawtransaction", &[&txid, "true"])["vsize"]
        .as_u64()
        .unwrap();
    assert!(
        to_node.review.fee >= vsize,
        "fee {} < {vsize}",
        to_node.review.fee
    );

    // 3. Alice's blinded change is found and unblinded by the scanner path.
    let change = verified_wallet_utxos(&alice, &raw);
    assert_eq!(change.len(), 1);
    assert!(change[0].blinding.is_some());
    assert_eq!(
        change[0].value,
        100_000_000 - 40_000_000 - to_node.review.fee
    );

    // 4. Offer split from confidential funds: explicit offerable output,
    //    confidential change.
    let split = alice
        .prepare_offer_split(&OfferSplitRequest {
            asset_id: policy.clone(),
            amount: 10_000_000,
            fee_rate: 1,
            utxos: change.clone(),
            change_index: 1,
            receive_index: 1,
        })
        .unwrap();
    let (split_txid, split_raw) = sign(&alice, &split);
    cli.broadcast_and_mine(&split_raw, &split_txid);
    eprintln!("confidential -> explicit offer split {split_txid}");
    let after_split = verified_wallet_utxos(&alice, &split_raw);
    let explicit = after_split
        .iter()
        .find(|u| u.blinding.is_none())
        .expect("explicit split output");
    assert_eq!(explicit.value, 10_000_000);
    let blinded = after_split
        .iter()
        .find(|u| u.blinding.is_some())
        .expect("confidential change")
        .clone();

    // 5. Spend the remaining confidential change to an unconfidential node
    //    address (CT -> explicit recipient).
    let destination = cli.string("getnewaddress", &[]);
    let destination = cli.json("getaddressinfo", &[&destination])["unconfidential"]
        .as_str()
        .unwrap()
        .to_owned();
    let to_explicit = alice
        .prepare_transfer(&TransferRequest {
            recipient: destination,
            asset_id: policy,
            amount: 20_000_000,
            fee_rate: 1,
            change_index: 2,
            utxos: vec![blinded],
        })
        .unwrap();
    assert!(!to_explicit.review.external_outputs[0].confidential);
    let (txid, raw) = sign(&alice, &to_explicit);
    cli.broadcast_and_mine(&raw, &txid);
    eprintln!("confidential -> explicit spend {txid}");
    assert_eq!(node_received(&cli, &txid, &policy_hex), 0.2);
    let tx = decode(&raw);
    assert!(tx.output[0].value.is_explicit());
    assert!(tx.output[1].value.is_confidential());
}
