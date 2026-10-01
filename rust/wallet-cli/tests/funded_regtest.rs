//! Opt-in end-to-end tests against a live Elements+ regtest node, the
//! regtest Esplora bridge and a DEX server. They spend disposable node funds
//! and therefore refuse to run unless `ELEMENTS_DATADIR` is set:
//!
//! ```sh
//! ELEMENTS_CLI=.../elements-functional-test-cli \
//! ELEMENTS_DATADIR=.../.regtest/node ELEMENTS_RPCPORT=18884 \
//! EPW_TEST_ESPLORA=http://127.0.0.1:43199/api EPW_TEST_DEX=http://127.0.0.1:8791 \
//! EPW_TEST_DIR=/some/scratch/dir \
//! cargo test --test funded_regtest -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! The DEX must accept offers with `network = "ecx-alpha"` (the wallet core
//! always emits that; run the server with the default `NETWORK_NAME`).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

const EPW: &str = env!("CARGO_BIN_EXE_epw");

struct Node {
    cli: String,
    datadir: String,
    rpc_port: String,
    wallet: String,
}

impl Node {
    fn from_env() -> Self {
        Self {
            cli: std::env::var("ELEMENTS_CLI").unwrap_or_else(|_| "elements-cli".into()),
            datadir: std::env::var("ELEMENTS_DATADIR")
                .expect("set ELEMENTS_DATADIR to opt into spending disposable regtest funds"),
            rpc_port: std::env::var("ELEMENTS_RPCPORT").unwrap_or_else(|_| "18884".into()),
            wallet: std::env::var("ELEMENTS_RPCWALLET").unwrap_or_else(|_| "miner".into()),
        }
    }

    fn run(&self, args: &[&str]) -> String {
        let out = Command::new(&self.cli)
            .arg("-chain=elementsregtest")
            .arg(format!("-datadir={}", self.datadir))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcwallet={}", self.wallet))
            .args(args)
            .output()
            .expect("run node cli");
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn mine(&self) {
        let address = self.run(&["getnewaddress"]);
        self.run(&["generatetoaddress", "1", &address]);
        // Let the bridge index and the DEX monitor catch up.
        std::thread::sleep(Duration::from_millis(1500));
    }
}

struct Wallet {
    home: PathBuf,
    password: String,
}

impl Wallet {
    fn new(root: &Path, name: &str, esplora: &str, dex: &str) -> Self {
        let wallet = Self {
            home: root.join(name),
            password: format!("pw-{name}-test"),
        };
        for (key, value) in [
            ("network", "regtest"),
            ("esplora_url", esplora),
            ("dex_url", dex),
        ] {
            let (_, code) = wallet.epw(&["config", "set", key, value]);
            assert_eq!(code, 0);
        }
        let (init, code) = wallet.epw(&["init"]);
        assert_eq!(code, 0, "{init}");
        assert_eq!(init["mnemonic"].as_str().unwrap().split(' ').count(), 12);
        wallet
    }

    fn command(&self) -> Command {
        let mut command = Command::new(EPW);
        command
            .env("EPW_HOME", &self.home)
            .env("EPW_PASSWORD", &self.password);
        command
    }

    fn epw(&self, args: &[&str]) -> (Value, i32) {
        let out = self
            .command()
            .arg("--json")
            .args(args)
            .output()
            .expect("run epw");
        let text = String::from_utf8_lossy(&out.stdout);
        let value = serde_json::from_str(&text).unwrap_or_else(|_| {
            panic!(
                "epw {args:?} printed non-JSON: {text} / {}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        let code = out.status.code().unwrap_or(-1);
        eprintln!("epw {} -> exit {code}", args.join(" "));
        (value, code)
    }

    fn ok(&self, args: &[&str]) -> Value {
        let (value, code) = self.epw(args);
        assert_eq!(code, 0, "epw {args:?}: {value:#}");
        value
    }

    fn set_policy(&self, toml: &str) {
        std::fs::write(self.home.join("policy.toml"), toml).unwrap();
    }

    fn balance(&self, asset: &str) -> u64 {
        let balances = self.ok(&["balances"]);
        balances["balances"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["asset_id"] == asset)
            .map(|b| b["amount"].as_str().unwrap().parse().unwrap())
            .unwrap_or(0)
    }
}

struct Setup {
    node: Node,
    root: PathBuf,
    esplora: String,
    dex: String,
    policy_asset: String,
    tag: String,
}

impl Setup {
    fn new(name: &str) -> Self {
        let node = Node::from_env();
        let base = std::env::var("EPW_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let root = base.join(format!("epw-{name}-{stamp}"));
        std::fs::create_dir_all(&root).unwrap();
        let esplora = std::env::var("EPW_TEST_ESPLORA")
            .unwrap_or_else(|_| "http://127.0.0.1:43199/api".into());
        let dex = std::env::var("EPW_TEST_DEX").unwrap_or_else(|_| "http://127.0.0.1:8791".into());
        let policy_asset = serde_json::from_str::<Value>(&node.run(&["getsidechaininfo"])).unwrap()
            ["pegged_asset"]
            .as_str()
            .unwrap()
            .to_owned();
        // Unique ticker per run: tickers must be unique among verified assets.
        let tag = format!("{:X}", stamp % 0xFFFFFF);
        Self {
            node,
            root,
            esplora,
            dex,
            policy_asset,
            tag,
        }
    }

    fn wallet(&self, name: &str) -> Wallet {
        Wallet::new(&self.root, name, &self.esplora, &self.dex)
    }

    fn fund(&self, wallet: &Wallet, amount: &str) {
        let address = wallet.ok(&["address"])["address"]
            .as_str()
            .unwrap()
            .to_owned();
        let txid = self.node.run(&["sendtoaddress", &address, amount]);
        eprintln!("funded {address} with {amount}: {txid}");
        self.node.mine();
    }

    fn auto_policy(&self, extra_asset: Option<&str>) -> String {
        let mut toml = format!(
            "mode = \"auto\"\nallowed_dex_urls = [\"{}\"]\n[limits.policy]\nper_tx = \"0.5\"\nper_24h = \"2\"\n",
            self.dex
        );
        if let Some(asset) = extra_asset {
            toml.push_str(&format!(
                "[limits.{asset}]\nper_tx = \"atomic:500000\"\nper_24h = \"atomic:600000\"\n"
            ));
        }
        toml
    }
}

fn txid_of(outcome: &Value, index: usize) -> String {
    outcome["results"][index]["txid"]
        .as_str()
        .unwrap_or_else(|| panic!("no txid in {outcome:#}"))
        .to_owned()
}

#[test]
#[ignore = "spends disposable node funds; set ELEMENTS_DATADIR and run explicitly"]
fn cli_issue_offer_swap_cancel_history() {
    let s = Setup::new("cli");
    let alice = s.wallet("alice");
    let bob = s.wallet("bob");
    s.fund(&alice, "1.5");
    s.fund(&bob, "1.5");
    alice.set_policy(&s.auto_policy(None));

    // Issue + register (auto mode, within the ECX limit).
    let ticker = format!("C{}", s.tag);
    let issued = alice.ok(&[
        "issue",
        "--name",
        "CLI Test Token",
        "--ticker",
        &ticker,
        "--precision",
        "2",
        "--amount",
        "10000",
        "--token-amount",
        "1",
        "--register",
    ]);
    assert_eq!(issued["status"], "completed");
    let asset = issued["results"][0]["asset_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(issued["results"][0]["registered"].is_object(), "{issued:#}");
    eprintln!("issuance txid {}", txid_of(&issued, 0));
    s.node.mine();
    alice.set_policy(&s.auto_policy(Some(&asset)));

    // Two offers (each with an exact-output split), both posted.
    let offer1 = alice.ok(&["offer", "make", &ticker, "1000", "ECX", "0.1", "--post"]);
    assert!(offer1["results"][1]["posted"].is_object(), "{offer1:#}");
    let offer1_outpoint = offer1["results"][1]["decoded"]["outpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    eprintln!(
        "offer1 split {} outpoint {offer1_outpoint}",
        txid_of(&offer1, 0)
    );
    s.node.mine();
    let offer2 = alice.ok(&["offer", "make", &ticker, "500", "ECX", "0.2", "--post"]);
    let offer2_outpoint = offer2["results"][1]["decoded"]["outpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    eprintln!(
        "offer2 split {} outpoint {offer2_outpoint}",
        txid_of(&offer2, 0)
    );
    s.node.mine();

    // Bob: default confirm policy -> parked, then approved by the human.
    let quote = bob.ok(&["quote", "ECX", &ticker, "0.1"]);
    assert_eq!(quote["buy_amount"], "100000");
    assert_eq!(quote["offers"][0]["outpoint"], offer1_outpoint.as_str());
    let (pending, code) = bob.epw(&["swap", "ECX", &ticker, "0.1"]);
    assert_eq!(code, 3, "{pending:#}");
    assert_eq!(pending["status"], "approval_required");
    let file = pending["pending_file"].as_str().unwrap();
    let hash = pending["approval_hash"].as_str().unwrap();
    let review = bob.ok(&["review", file]);
    assert_eq!(review["approval_hash"], hash);
    assert_eq!(review["steps"][0]["matches_file"], true);
    let (wrong, code) = bob.epw(&["sign", file, "--approve", &"0".repeat(64)]);
    assert_eq!(code, 1, "{wrong:#}");
    let swapped = bob.ok(&["sign", file, "--approve", hash]);
    let swap_txid = txid_of(&swapped, 0);
    eprintln!("swap txid {swap_txid}");
    s.node.mine();
    assert_eq!(bob.balance(&asset), 100_000);

    // Alice: list, cancel the second offer, history.
    let offers = alice.ok(&["offer", "list"]);
    let status = |outpoint: &str| {
        offers["offers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["outpoint"] == outpoint)
            .unwrap()["status"]
            .clone()
    };
    assert_eq!(status(&offer1_outpoint), "spent");
    assert_eq!(status(&offer2_outpoint), "open");
    let cancel = alice.ok(&["offer", "cancel", &offer2_outpoint]);
    eprintln!("cancel txid {}", txid_of(&cancel, 0));
    s.node.mine();
    let offers = alice.ok(&["offer", "list"]);
    let cancelled = offers["offers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["outpoint"] == offer2_outpoint.as_str())
        .unwrap();
    assert_eq!(cancelled["status"], "cancelled");
    let history = alice.ok(&["history"]);
    let txids: Vec<&str> = history["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["txid"].as_str().unwrap())
        .collect();
    assert!(txids.contains(&swap_txid.as_str()));
    assert!(txids.contains(&txid_of(&cancel, 0).as_str()));

    // Policy: per-tx ECX limit refuses in auto mode.
    let bob_address = bob.ok(&["address"])["address"].as_str().unwrap().to_owned();
    let (refused, code) = alice.epw(&["send", "ECX", "0.6", &bob_address]);
    assert_eq!(code, 4, "{refused:#}");
    assert_eq!(refused["status"], "refused");
    // 24h asset limit: 1000+500 already offered (150000) + 5000 (500000) > 600000.
    let (refused, code) = alice.epw(&["send", &ticker, "5000", &bob_address]);
    assert_eq!(code, 4, "{refused:#}");
    assert!(refused["decision"]["violations"][0]
        .as_str()
        .unwrap()
        .contains("24h"));
}

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn start(wallet: &Wallet) -> Self {
        let mut child = wallet
            .command()
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn epw mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut mcp = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        let init = mcp.request(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "epw-test", "version": "0"}}),
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        mcp.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        mcp
    }

    fn send(&mut self, message: &Value) {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], id);
        response
    }

    /// Returns (structuredContent, isError).
    fn tool(&mut self, name: &str, arguments: Value) -> (Value, bool) {
        let response = self.request("tools/call", json!({"name": name, "arguments": arguments}));
        let result = &response["result"];
        eprintln!(
            "mcp {name} -> isError={} status={}",
            result["isError"], result["structuredContent"]["status"]
        );
        (
            result["structuredContent"].clone(),
            result["isError"].as_bool().unwrap(),
        )
    }

    fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let (value, is_error) = self.tool(name, arguments);
        assert!(!is_error, "{name}: {value:#}");
        value
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "spends disposable node funds; set ELEMENTS_DATADIR and run explicitly"]
fn mcp_issue_offer_swap_cancel_history() {
    let s = Setup::new("mcp");
    let alice = s.wallet("alice");
    let bob = s.wallet("bob");
    s.fund(&alice, "1.5");
    s.fund(&bob, "1.5");
    alice.set_policy(&s.auto_policy(None));
    // Bob stays in confirm mode: MCP must park and never sign by itself.

    let mut a = Mcp::start(&alice);
    let tools = a.request("tools/list", json!({}));
    assert!(tools["result"]["tools"].as_array().unwrap().len() >= 11);

    let ticker = format!("M{}", s.tag);
    let issued = a.ok(
        "issue_asset",
        json!({"name": "MCP Test Token", "ticker": ticker, "precision": 2, "amount": "10000", "token_amount": "1", "register": true}),
    );
    assert_eq!(issued["status"], "completed");
    let asset = issued["results"][0]["asset_id"]
        .as_str()
        .unwrap()
        .to_owned();
    eprintln!("mcp issuance txid {}", txid_of(&issued, 0));
    s.node.mine();

    // Spending the new asset needs a limit in auto mode.
    let (refused, is_error) = a.tool(
        "make_offer",
        json!({"give_asset": ticker, "give_amount": "1000", "want_asset": "ECX", "want_amount": "0.1"}),
    );
    assert!(is_error);
    assert_eq!(refused["status"], "refused");
    assert!(refused["decision"]["violations"][0]
        .as_str()
        .unwrap()
        .contains("no limit configured"));
    drop(a);
    alice.set_policy(&s.auto_policy(Some(&asset)));
    let mut a = Mcp::start(&alice);

    let offer1 = a.ok(
        "make_offer",
        json!({"give_asset": ticker, "give_amount": "1000", "want_asset": "ECX", "want_amount": "0.1"}),
    );
    let offer1_outpoint = offer1["results"][1]["decoded"]["outpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(offer1["results"][1]["posted"].is_object(), "{offer1:#}");
    eprintln!(
        "mcp offer1 split {} outpoint {offer1_outpoint}",
        txid_of(&offer1, 0)
    );
    s.node.mine();
    let offer2 = a.ok(
        "make_offer",
        json!({"give_asset": asset, "give_amount": "atomic:50000", "want_asset": "ECX", "want_amount": "0.2"}),
    );
    let offer2_outpoint = offer2["results"][1]["decoded"]["outpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    eprintln!(
        "mcp offer2 split {} outpoint {offer2_outpoint}",
        txid_of(&offer2, 0)
    );
    s.node.mine();

    let mut b = Mcp::start(&bob);
    let markets = b.ok("get_markets", json!({}));
    assert!(markets["markets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["base"] == asset.as_str()));
    let book = b.ok("get_order_book", json!({"base": asset, "quote": "ECX"}));
    assert!(!book["asks"].as_array().unwrap().is_empty());
    let quote = b.ok(
        "get_quote",
        json!({"sell": "ECX", "buy": ticker, "amount": "0.1"}),
    );
    assert_eq!(quote["buy_amount"], "100000");
    let pending = b.ok(
        "swap",
        json!({"sell": "ECX", "buy": ticker, "amount": "0.1"}),
    );
    assert_eq!(pending["status"], "approval_required", "{pending:#}");
    assert_eq!(
        bob.balance(&asset),
        0,
        "nothing signed via MCP in confirm mode"
    );
    // The human approves out of band.
    let file = pending["pending_file"].as_str().unwrap();
    let swapped = bob.ok(&[
        "sign",
        file,
        "--approve",
        pending["approval_hash"].as_str().unwrap(),
    ]);
    eprintln!(
        "mcp swap txid (approved via epw sign) {}",
        txid_of(&swapped, 0)
    );
    s.node.mine();
    let balances = b.ok("get_balances", json!({}));
    assert!(balances["balances"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["asset_id"] == asset.as_str() && x["amount"] == "100000"));

    let offers = a.ok("list_offers", json!({}));
    let find = |offers: &Value, outpoint: &str| {
        offers["offers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["outpoint"] == outpoint)
            .unwrap()["status"]
            .clone()
    };
    assert_eq!(find(&offers, &offer1_outpoint), "spent");
    assert_eq!(find(&offers, &offer2_outpoint), "open");
    let cancel = a.ok("cancel_offer", json!({"outpoint": offer2_outpoint}));
    eprintln!("mcp cancel txid {}", txid_of(&cancel, 0));
    s.node.mine();
    assert_eq!(
        find(&a.ok("list_offers", json!({})), &offer2_outpoint),
        "cancelled"
    );

    let bob_address = b.ok("get_address", json!({}))["address"]
        .as_str()
        .unwrap()
        .to_owned();
    let sent = a.ok(
        "send",
        json!({"asset": "ECX", "amount": "0.01", "recipient": bob_address}),
    );
    eprintln!("mcp send txid {}", txid_of(&sent, 0));
    let (refused, is_error) = a.tool(
        "send",
        json!({"asset": "ECX", "amount": "0.6", "recipient": bob_address}),
    );
    assert!(is_error && refused["status"] == "refused");
    s.node.mine();
    let history = a.ok("get_history", json!({"limit": 20}));
    assert!(history["transactions"].as_array().unwrap().len() >= 6);
    let policy = a.ok("get_policy", json!({}));
    assert_eq!(policy["mode"], "auto");
    assert!(s.policy_asset.len() == 64);
}
