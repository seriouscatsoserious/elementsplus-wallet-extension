use elementsplus_preconf::{
    elements::{
        encode::{deserialize, serialize},
        secp256k1_zkp::{Keypair, Message as SecpMessage, Secp256k1, SecretKey},
        Transaction,
    },
    operator::Receipt,
    relay::{
        ClientMessage as RelayRequest, Profile, ServerMessage as RelayResponse, ValidatedProfile,
    },
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{
    accept_hdr_async_with_config, connect_async_with_config,
    tungstenite::{
        handshake::server::{Request as HandshakeRequest, Response as HandshakeResponse},
        protocol::WebSocketConfig,
        Message,
    },
};

const MAX_FRAME: usize = 8 * 1024 * 1024;
const MAX_JOURNAL: u64 = 2 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeCli {
    program: PathBuf,
    args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: SocketAddr,
    allowed_origins: Vec<String>,
    profile_path: PathBuf,
    secret_key_path: PathBuf,
    auth_token_path: PathBuf,
    decision_journal: PathBuf,
    node_cli: NodeCli,
    relay_urls: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientMessage {
    Authenticate {
        token: String,
        profile: String,
    },
    Preconfirm {
        request_id: String,
        bond: String,
        raw_tx: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Ready {
        profile: String,
    },
    Preconfirmed {
        request_id: String,
        receipt: Receipt,
        relay_acks: usize,
    },
    Error {
        request_id: Option<String>,
        code: &'static str,
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHeader {
    version: u32,
    profile: String,
}

struct DecisionJournal {
    profile: Arc<ValidatedProfile>,
    decisions: BTreeMap<elementsplus_preconf::elements::OutPoint, Receipt>,
    file: File,
    failed: bool,
}

impl DecisionJournal {
    fn open(path: &Path, profile: Arc<ValidatedProfile>) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| e.to_string())?;
        file.try_lock()
            .map_err(|_| "decision journal is already locked")?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("decision journal must be a regular file".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_JOURNAL + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_JOURNAL {
            return Err("decision journal is oversized".into());
        }
        let mut decisions = BTreeMap::new();
        if bytes.is_empty() {
            append(
                &mut file,
                &JournalHeader {
                    version: 1,
                    profile: profile.id.clone(),
                },
            )?;
        } else {
            if bytes.last() != Some(&b'\n') {
                return Err("torn decision journal; operator intervention required".into());
            }
            let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
            let header: JournalHeader =
                serde_json::from_slice(lines.next().ok_or("missing journal header")?)
                    .map_err(|_| "invalid journal header")?;
            if header.version != 1 || header.profile != profile.id {
                return Err("journal/profile mismatch".into());
            }
            for line in lines {
                let receipt: Receipt =
                    serde_json::from_slice(line).map_err(|_| "invalid journal receipt")?;
                profile.verify(&receipt)?;
                if decisions.insert(receipt.bond, receipt).is_some() {
                    return Err("journal contains more than one decision for a bond".into());
                }
            }
        }
        Ok(Self {
            profile,
            decisions,
            file,
            failed: false,
        })
    }

    fn commit(&mut self, receipt: Receipt) -> Result<Receipt, String> {
        if self.failed {
            return Err("decision journal unavailable".into());
        }
        self.profile.verify(&receipt)?;
        if let Some(existing) = self.decisions.get(&receipt.bond) {
            return if existing.txid == receipt.txid {
                Ok(existing.clone())
            } else {
                Err("bond already committed to a different transaction".into())
            };
        }
        if let Err(error) = append(&mut self.file, &receipt) {
            self.failed = true;
            return Err(error);
        }
        self.decisions.insert(receipt.bond, receipt.clone());
        Ok(receipt)
    }

    fn existing(
        &self,
        bond: elementsplus_preconf::elements::OutPoint,
        txid: elementsplus_preconf::elements::Txid,
    ) -> Result<Option<Receipt>, String> {
        match self.decisions.get(&bond) {
            Some(receipt) if receipt.txid == txid => Ok(Some(receipt.clone())),
            Some(_) => Err("bond already committed to a different transaction".into()),
            None => Ok(None),
        }
    }
}

fn append(file: &mut File, value: &impl Serialize) -> Result<(), String> {
    let mut line = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if line.len() > 4096 {
        return Err("oversized journal record".into());
    }
    line.push(b'\n');
    file.write_all(&line)
        .and_then(|_| file.sync_all())
        .map_err(|_| "durable journal write failed; signer disabled".into())
}

struct State {
    profile: Arc<ValidatedProfile>,
    keypair: Keypair,
    token: Vec<u8>,
    journal: Mutex<DecisionJournal>,
    node: NodeCli,
    relays: Vec<String>,
}

fn secure_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("cannot read {label}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!("{label} must not be accessible to group/other"));
        }
    }
    fs::read(path).map_err(|e| format!("cannot read {label}: {e}"))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}

fn command(node: &NodeCli) -> Command {
    let mut result = Command::new(&node.program);
    result.args(&node.args);
    result
}

fn rpc(node: &NodeCli, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = command(node)
        .args(args)
        .output()
        .map_err(|_| "node RPC unavailable")?;
    if !output.status.success() {
        return Err("node RPC rejected request".into());
    }
    Ok(output.stdout)
}

fn decimal_atoms(value: &serde_json::Value) -> Result<u64, String> {
    let text = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return Err("invalid node amount".into()),
    };
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    if fraction.len() > 8
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid node amount".into());
    }
    let padded = format!("{fraction:0<8}");
    whole
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(100_000_000))
        .and_then(|n| n.checked_add(padded.parse::<u64>().ok()?))
        .ok_or("node amount overflow".into())
}

fn validate_chain_and_bond(
    state: &State,
    bond_outpoint: elementsplus_preconf::elements::OutPoint,
) -> Result<(), String> {
    let bond = state
        .profile
        .bonds
        .get(&bond_outpoint)
        .ok_or("unknown bond/session")?;
    let genesis = String::from_utf8(rpc(&state.node, &["getblockhash", "0"])?)
        .map_err(|_| "invalid genesis response")?;
    if genesis.trim() != bond.config().genesis.to_string() {
        return Err("node genesis does not match profile".into());
    }
    let height_text = String::from_utf8(rpc(&state.node, &["getblockcount"])?)
        .map_err(|_| "invalid height response")?;
    let height: u32 = height_text
        .trim()
        .parse()
        .map_err(|_| "invalid node height")?;
    if height > bond.config().active_until {
        return Err("preconfirmation session is no longer active".into());
    }
    let outpoint = format!("{}", bond_outpoint.txid);
    let vout = bond_outpoint.vout.to_string();
    let output: serde_json::Value =
        serde_json::from_slice(&rpc(&state.node, &["gettxout", &outpoint, &vout, "true"])?)
            .map_err(|_| "invalid bond response")?;
    if output.is_null()
        || output.pointer("/scriptPubKey/hex").and_then(|v| v.as_str())
            != Some(&hex::encode(bond.script_pubkey().as_bytes()))
        || output.get("asset").and_then(|v| v.as_str())
            != Some(&bond.config().fee_asset.to_string())
        || decimal_atoms(output.get("value").ok_or("node omitted bond amount")?)?
            != bond.config().collateral
    {
        return Err("bond is absent, spent, or does not match the profile".into());
    }
    Ok(())
}

fn validate_transaction(
    state: &State,
    bond: elementsplus_preconf::elements::OutPoint,
    tx: &Transaction,
) -> Result<(), String> {
    validate_chain_and_bond(state, bond)?;
    let protected = state
        .profile
        .bonds
        .get(&bond)
        .ok_or("unknown bond/session")?
        .config()
        .protected_output;
    elementsplus_preconf::check_authorized_transaction(protected, tx, command(&state.node))
        .map(|_| ())
}

async fn publish(relay: &str, profile: &str, receipt: Receipt) -> Result<(), String> {
    let (mut socket, _) = timeout(
        IO_TIMEOUT,
        connect_async_with_config(relay, Some(ws_config()), false),
    )
    .await
    .map_err(|_| "relay connect timeout")?
    .map_err(|_| "relay connection failed")?;
    let subscribe = RelayRequest::Subscribe {
        profile: profile.into(),
        cursor: None,
    };
    socket
        .send(Message::text(serde_json::to_string(&subscribe).unwrap()))
        .await
        .map_err(|_| "relay write failed")?;
    loop {
        let frame = timeout(IO_TIMEOUT, socket.next())
            .await
            .map_err(|_| "relay synchronization timeout")?
            .ok_or("relay closed")?
            .map_err(|_| "relay read failed")?;
        if let Message::Text(text) = frame {
            let message: RelayResponse =
                serde_json::from_str(&text).map_err(|_| "invalid relay response")?;
            match message {
                RelayResponse::CaughtUp { .. } => break,
                RelayResponse::Error { .. } => return Err("relay rejected subscription".into()),
                _ => {}
            }
        }
    }
    socket
        .send(Message::text(
            serde_json::to_string(&RelayRequest::Publish { receipt }).unwrap(),
        ))
        .await
        .map_err(|_| "relay publish failed")?;
    loop {
        let frame = timeout(IO_TIMEOUT, socket.next())
            .await
            .map_err(|_| "relay acknowledgement timeout")?
            .ok_or("relay closed")?
            .map_err(|_| "relay read failed")?;
        if let Message::Text(text) = frame {
            match serde_json::from_str::<RelayResponse>(&text)
                .map_err(|_| "invalid relay response")?
            {
                RelayResponse::Published { status, .. }
                    if status == "stored" || status == "duplicate" =>
                {
                    return Ok(())
                }
                RelayResponse::Published { .. } | RelayResponse::Error { .. } => {
                    return Err("relay did not durably accept receipt".into())
                }
                _ => {}
            }
        }
    }
}

fn broadcast(state: &State, tx: &Transaction) -> Result<(), String> {
    let raw = hex::encode(serialize(tx));
    let expected = tx.txid().to_string();
    match rpc(&state.node, &["sendrawtransaction", &raw, "0"]) {
        Ok(stdout) if String::from_utf8_lossy(&stdout).trim() == expected => Ok(()),
        _ if rpc(&state.node, &["getmempoolentry", &expected]).is_ok() => Ok(()),
        _ => Err("receipt is durable but transaction broadcast is uncertain; retry the same transaction only".into()),
    }
}

async fn preconfirm(
    state: &State,
    bond_text: &str,
    raw_tx: &str,
) -> Result<(Receipt, usize), String> {
    if raw_tx.len() > MAX_FRAME * 2 || raw_tx.len() % 2 != 0 {
        return Err("raw transaction is oversized or malformed".into());
    }
    let bond = bond_text.parse().map_err(|_| "invalid bond outpoint")?;
    let bytes =
        hex::decode(raw_tx).map_err(|_| "raw transaction is not canonical lowercase hex")?;
    if hex::encode(&bytes) != raw_tx {
        return Err("raw transaction is not canonical lowercase hex".into());
    }
    let tx: Transaction = deserialize(&bytes).map_err(|_| "raw transaction decode failed")?;
    if serialize(&tx) != bytes {
        return Err("noncanonical transaction encoding".into());
    }
    let session = state
        .profile
        .bonds
        .get(&bond)
        .ok_or("unknown bond/session")?;
    let prior = state
        .journal
        .lock()
        .map_err(|_| "decision journal unavailable")?
        .existing(bond, tx.txid())?;
    if let Some(receipt) = prior {
        elementsplus_preconf::check_authorization_subject(session.config().protected_output, &tx)?;
        for relay in &state.relays {
            publish(relay, &state.profile.id, receipt.clone()).await?;
        }
        broadcast(state, &tx)?;
        return Ok((receipt, state.relays.len()));
    }
    validate_transaction(state, bond, &tx)?;
    let signature = Secp256k1::new().sign_schnorr_no_aux_rand(
        &SecpMessage::from_digest(session.digest(bond, tx.txid())),
        &state.keypair,
    );
    let proposed = Receipt {
        bond,
        txid: tx.txid(),
        signature: *signature.as_ref(),
    };
    let receipt = state
        .journal
        .lock()
        .map_err(|_| "decision journal unavailable")?
        .commit(proposed)?;
    for relay in &state.relays {
        publish(relay, &state.profile.id, receipt.clone()).await?;
    }
    broadcast(state, &tx)?;
    Ok((receipt, state.relays.len()))
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME))
}

async fn send(
    socket: &mut tokio_tungstenite::WebSocketStream<TcpStream>,
    message: &ServerMessage,
) -> Result<(), String> {
    timeout(
        IO_TIMEOUT,
        socket.send(Message::text(
            serde_json::to_string(message).map_err(|_| "serialization failed")?,
        )),
    )
    .await
    .map_err(|_| "client write timeout")?
    .map_err(|_| "client closed".into())
}

async fn connection(
    stream: TcpStream,
    state: Arc<State>,
    origins: Arc<Vec<String>>,
) -> Result<(), String> {
    let mut socket = accept_hdr_async_with_config(
        stream,
        |request: &HandshakeRequest, response: HandshakeResponse| {
            let origin = request
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok());
            if !origin.is_some_and(|value| origins.iter().any(|allowed| allowed == value)) {
                return Err(
                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(Some(
                        "origin denied".into(),
                    )),
                );
            }
            Ok(response)
        },
        Some(ws_config()),
    )
    .await
    .map_err(|_| "WebSocket handshake rejected")?;
    let first = timeout(IO_TIMEOUT, socket.next())
        .await
        .map_err(|_| "authentication timeout")?
        .ok_or("client closed")?
        .map_err(|_| "bad client frame")?;
    let Message::Text(text) = first else {
        return Err("authentication must be JSON text".into());
    };
    let ClientMessage::Authenticate { token, profile } =
        serde_json::from_str(&text).map_err(|_| "invalid authentication message")?
    else {
        return Err("authenticate first".into());
    };
    if profile != state.profile.id || !constant_time_equal(token.as_bytes(), &state.token) {
        return Err("authentication failed".into());
    }
    send(&mut socket, &ServerMessage::Ready { profile }).await?;
    while let Some(frame) = socket.next().await {
        let frame = frame.map_err(|_| "bad client frame")?;
        let Message::Text(text) = frame else {
            continue;
        };
        let request: ClientMessage = match serde_json::from_str(&text) {
            Ok(request) => request,
            Err(_) => {
                send(
                    &mut socket,
                    &ServerMessage::Error {
                        request_id: None,
                        code: "INVALID_REQUEST",
                        reason: "invalid request".into(),
                    },
                )
                .await?;
                continue;
            }
        };
        match request {
            ClientMessage::Preconfirm {
                request_id,
                bond,
                raw_tx,
            } if !request_id.is_empty() && request_id.len() <= 128 => {
                match preconfirm(&state, &bond, &raw_tx).await {
                    Ok((receipt, relay_acks)) => {
                        send(
                            &mut socket,
                            &ServerMessage::Preconfirmed {
                                request_id,
                                receipt,
                                relay_acks,
                            },
                        )
                        .await?
                    }
                    Err(reason) => {
                        send(
                            &mut socket,
                            &ServerMessage::Error {
                                request_id: Some(request_id),
                                code: "PRECONFIRMATION_REJECTED",
                                reason,
                            },
                        )
                        .await?
                    }
                }
            }
            _ => {
                send(
                    &mut socket,
                    &ServerMessage::Error {
                        request_id: None,
                        code: "INVALID_REQUEST",
                        reason: "unexpected request".into(),
                    },
                )
                .await?
            }
        }
    }
    Ok(())
}

fn load(config_path: &Path) -> Result<(Config, Arc<State>), String> {
    let config: Config = serde_json::from_slice(&fs::read(config_path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("invalid config: {e}"))?;
    if config.allowed_origins.is_empty() || config.relay_urls.len() < 2 {
        return Err("at least one origin and two relay endpoints are required".into());
    }
    let profile: Profile =
        serde_json::from_slice(&fs::read(&config.profile_path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid profile: {e}"))?;
    let profile = profile.validate()?;
    if profile.bonds.len() != 1 {
        return Err("this wallet milestone requires exactly one fixed session per profile".into());
    }
    let key_hex = String::from_utf8(secure_file(&config.secret_key_path, "preconfer secret")?)
        .map_err(|_| "preconfer secret is not UTF-8")?;
    let secret = SecretKey::from_slice(
        &hex::decode(key_hex.trim()).map_err(|_| "preconfer secret must be 32-byte hex")?,
    )
    .map_err(|_| "invalid preconfer secret")?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    if profile
        .bonds
        .values()
        .any(|bond| bond.config().preconfer != keypair.x_only_public_key().0)
    {
        return Err("secret key does not match every profile session".into());
    }
    let mut token = secure_file(&config.auth_token_path, "wallet authentication token")?;
    while matches!(token.last(), Some(b'\n' | b'\r')) {
        token.pop();
    }
    if token.len() < 32 || token.len() > 1024 {
        return Err("wallet authentication token must contain 32..1024 bytes".into());
    }
    let journal = DecisionJournal::open(&config.decision_journal, profile.clone())?;
    let state = Arc::new(State {
        profile,
        keypair,
        token,
        journal: Mutex::new(journal),
        node: config.node_cli.clone(),
        relays: config.relay_urls.clone(),
    });
    Ok((config, state))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: elementsplus-preconfer-signer CONFIG.json")?;
    let (config, state) = load(Path::new(&path))?;
    let listener = TcpListener::bind(config.listen).await?;
    eprintln!(
        "preconfer signer listening on {} for profile {}",
        config.listen, state.profile.id
    );
    let origins = Arc::new(config.allowed_origins);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone(); let origins = origins.clone();
                tokio::spawn(async move { if let Err(error) = connection(stream, state, origins).await { eprintln!("signer connection closed: {error}"); } });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elementsplus_preconf::{
        elements::{hashes::Hash, AssetId, BlockHash, OutPoint, Txid},
        operator::Config as OperatorConfig,
        relay::Session,
    };

    fn fixture() -> (Arc<ValidatedProfile>, Keypair, OutPoint) {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret);
        let bond = OutPoint {
            txid: Txid::from_byte_array([4; 32]),
            vout: 1,
        };
        let profile = Profile {
            version: 1,
            sessions: vec![Session {
                bond,
                config: OperatorConfig {
                    genesis: BlockHash::from_byte_array([1; 32]),
                    fee_asset: AssetId::from_byte_array([2; 32]),
                    preconfer: keypair.x_only_public_key().0,
                    protected_output: OutPoint {
                        txid: Txid::from_byte_array([3; 32]),
                        vout: 0,
                    },
                    epoch: 1,
                    collateral: 100_000,
                    active_until: 100,
                    refund_height: 110,
                },
            }],
        }
        .validate()
        .unwrap();
        (profile, keypair, bond)
    }

    fn receipt(profile: &ValidatedProfile, keypair: &Keypair, bond: OutPoint, byte: u8) -> Receipt {
        let txid = Txid::from_byte_array([byte; 32]);
        let digest = profile.bonds[&bond].digest(bond, txid);
        let signature =
            Secp256k1::new().sign_schnorr_no_aux_rand(&SecpMessage::from_digest(digest), keypair);
        Receipt {
            bond,
            txid,
            signature: *signature.as_ref(),
        }
    }

    #[test]
    fn token_comparison_checks_length_and_contents() {
        assert!(constant_time_equal(b"same", b"same"));
        assert!(!constant_time_equal(b"same", b"samf"));
        assert!(!constant_time_equal(b"same", b"same-more"));
    }
    #[test]
    fn amount_parser_is_exact() {
        assert_eq!(
            decimal_atoms(&serde_json::json!("1.00000001")).unwrap(),
            100_000_001
        );
        assert_eq!(decimal_atoms(&serde_json::json!(0.5)).unwrap(), 50_000_000);
        assert!(decimal_atoms(&serde_json::json!("0.000000001")).is_err());
    }

    #[test]
    fn journal_is_idempotent_but_refuses_a_second_txid() {
        let (profile, keypair, bond) = fixture();
        let path = env::temp_dir().join(format!(
            "elementsplus-signer-test-{}.journal",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let first = receipt(&profile, &keypair, bond, 5);
        let second = receipt(&profile, &keypair, bond, 6);
        {
            let mut journal = DecisionJournal::open(&path, profile.clone()).unwrap();
            assert_eq!(journal.commit(first.clone()).unwrap(), first);
            assert_eq!(journal.commit(first.clone()).unwrap(), first);
            assert!(journal
                .commit(second)
                .unwrap_err()
                .contains("different transaction"));
        }
        let journal = DecisionJournal::open(&path, profile).unwrap();
        assert_eq!(journal.decisions.get(&bond), Some(&first));
        drop(journal);
        fs::remove_file(path).unwrap();
    }
}
