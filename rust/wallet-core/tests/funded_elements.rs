//! Opt-in live Elements regtest roundtrip through the exact wallet core.
//!
//! This test is ignored by default and refuses to run without an explicit
//! `ELEMENTS_DATADIR`, so an ordinary test run can never spend node funds.

use std::env;
use std::process::Command;

use elements::{AddressParams, AssetId, BlockHash};
use elementsplus_lwk_adapter::NATIVE_ADDRESS_PARAMS;
use elementsplus_wallet_core::{Branch, SendRequest, VerifiedUtxo, WalletCore};
use lwk_common::{ElementsParamsBuilder, Network};
use serde_json::Value;

// Public BIP39 test vector. This wallet exists only on the disposable regtest.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

struct ElementsCli {
    executable: String,
    datadir: String,
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
            rpc_port: env::var("ELEMENTS_RPCPORT").unwrap_or_else(|_| "19843".into()),
            wallet: env::var("ELEMENTS_RPCWALLET").unwrap_or_else(|_| "funding".into()),
            rpc_user: env::var("ELEMENTS_RPCUSER").ok(),
            rpc_password: env::var("ELEMENTS_RPCPASSWORD").ok(),
        }
    }

    fn json(&self, method: &str, args: &[&str]) -> Value {
        let mut command = Command::new(&self.executable);
        command
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
        assert!(
            output.status.success(),
            "{method} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            // bitcoin-cli style clients print top-level JSON strings without
            // quotes while retaining JSON for arrays and objects.
            Value::String(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        })
    }
}

fn json_amount_to_sat(value: &Value) -> u64 {
    let decimal = value.to_string();
    assert!(
        !decimal.contains(['e', 'E', '-']),
        "unexpected amount {decimal}"
    );
    let (whole, fractional) = decimal.split_once('.').unwrap_or((&decimal, ""));
    assert!(fractional.len() <= 8, "amount has sub-satoshi precision");
    let mut padded = fractional.to_owned();
    padded.push_str(&"0".repeat(8 - padded.len()));
    whole.parse::<u64>().unwrap() * 100_000_000 + padded.parse::<u64>().unwrap_or(0)
}

#[test]
#[ignore = "spends disposable node funds; set ELEMENTS_DATADIR and run explicitly"]
fn funded_regtest_roundtrip_reaches_mempool() {
    let cli = ElementsCli::from_env();
    let genesis: BlockHash = cli
        .json("getblockhash", &["0"])
        .as_str()
        .expect("genesis hash string")
        .parse()
        .expect("valid genesis hash");
    let labels = cli.json("dumpassetlabels", &[]);
    let policy_asset: AssetId = labels
        .get("bitcoin")
        .and_then(Value::as_str)
        .expect("dumpassetlabels must expose the native asset as bitcoin")
        .parse()
        .expect("valid policy asset");
    let network = Network::CustomElements(
        ElementsParamsBuilder::new()
            .with_genesis_hash(genesis)
            .with_policy_asset(policy_asset)
            .build()
            .expect("complete regtest network identity"),
    );

    // This fork's regtest is configured with native `elements1` addresses. The
    // standard `ert1` alias is accepted by the core as well.
    let core = WalletCore::new_for_network(
        TEST_MNEMONIC,
        network,
        "funded Elements+ regtest",
        &NATIVE_ADDRESS_PARAMS,
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    let receive = core.derive_address(Branch::External, 0).unwrap();

    let funding_txid = cli
        .json("sendtoaddress", &[&receive.native_address, "1.00000000"])
        .as_str()
        .expect("funding txid")
        .to_owned();
    let funding_tx = cli.json("getrawtransaction", &[&funding_txid, "true"]);
    let output = funding_tx["vout"]
        .as_array()
        .expect("verbose transaction outputs")
        .iter()
        .find(|output| output["scriptPubKey"]["hex"] == receive.script_pubkey_hex)
        .expect("funding transaction contains the wallet output");
    assert_eq!(
        output["asset"].as_str(),
        Some(policy_asset.to_string().as_str()),
        "funding output must use the discovered policy asset"
    );
    let input_value = json_amount_to_sat(&output["value"]);
    assert_eq!(input_value, 100_000_000);
    let vout = output["n"].as_u64().expect("numeric vout") as u32;

    let confidential_destination = cli
        .json("getnewaddress", &[])
        .as_str()
        .expect("node destination")
        .to_owned();
    let address_info = cli.json("getaddressinfo", &[&confidential_destination]);
    let destination = address_info["unconfidential"]
        .as_str()
        .expect("node provides an unconfidential destination");
    let fee = 1_000;
    let amount = 90_000_000;
    let prepared = core
        .prepare_send(SendRequest {
            recipient: destination.into(),
            amount,
            fee,
            change_index: 0,
            utxos: vec![VerifiedUtxo {
                txid: funding_txid,
                vout,
                value: input_value,
                asset_id: policy_asset.to_string(),
                script_pubkey_hex: receive.script_pubkey_hex,
                branch: Branch::External,
                index: 0,
            }],
        })
        .unwrap();
    assert_eq!(prepared.review.change, input_value - amount - fee);
    let signed = core
        .sign_prepared(&prepared, &prepared.review_hash)
        .unwrap();
    let accepted_txid = cli
        .json("sendrawtransaction", &[&signed.raw_tx_hex])
        .as_str()
        .expect("broadcast txid")
        .to_owned();
    assert_eq!(accepted_txid, signed.txid);
    let mempool_entry = cli.json("getmempoolentry", &[&accepted_txid]);
    assert!(mempool_entry.is_object());
}
