//! Operator configuration and key file.
use elementsplus_instant::{
    elements::{
        secp256k1_zkp::{Keypair, Secp256k1, SecretKey},
        AssetId, BlockHash, OutPoint,
    },
    policy,
    wire::parse_outpoint,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRpc {
    /// e.g. `http://127.0.0.1:18884/` (loopback or TLS reverse proxy).
    pub url: String,
    /// Bitcoin-style `.cookie` file (preferred) ...
    #[serde(default)]
    pub cookie_file: Option<PathBuf>,
    /// ... or `user:password`.
    #[serde(default)]
    pub user_pass: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BondConfig {
    pub outpoint: String,
    pub refund_height: u32,
}

/// Policy constants. Defaults are SPEC.md §3; operators may only make them
/// stricter (loading refuses looser values).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// S: refuse promises when `tip + S >= expiry`.
    pub promise_margin: u32,
    /// W: a bond counts only if `refund_height >= max(expiry) + W`.
    pub challenge_window: u32,
    pub bond_min_confirmations: u32,
    /// Absolute fee-rate floor (sat/vB); the effective floor is
    /// `max(fee_multiplier x estimatesmartfee(2), fee_floor_sat_vb)`.
    pub fee_floor_sat_vb: f64,
    pub fee_multiplier: f64,
    /// A3: unconfirmed lockbox ancestors allowed.
    pub max_unconfirmed_ancestors: u32,
    /// Requests per second per client IP on `POST /v1/promise`.
    pub promise_rate_per_ip: u32,
    pub max_inputs: usize,
    pub max_outputs: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            promise_margin: policy::PROMISE_MARGIN,
            challenge_window: policy::CHALLENGE_WINDOW,
            bond_min_confirmations: policy::BOND_MIN_CONFIRMATIONS,
            fee_floor_sat_vb: 0.1,
            fee_multiplier: 2.0,
            max_unconfirmed_ancestors: 3,
            promise_rate_per_ip: 20,
            max_inputs: 16,
            max_outputs: 32,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Genesis block hash (RPC display hex). The node must report the same.
    pub genesis: String,
    /// Native fee asset (bond asset), RPC display hex.
    pub fee_asset: String,
    /// 32-byte hex secret, mode 0600 (`instant-operator keygen`).
    pub key_file: PathBuf,
    /// SQLite write-ahead promise log. Never restore an old copy.
    pub wal: PathBuf,
    /// Esplora REST base, e.g. `http://127.0.0.1:43199/api`.
    pub esplora_url: String,
    pub node_rpc: NodeRpc,
    #[serde(default)]
    pub bonds: Vec<BondConfig>,
    /// Public HTTPS promise API base URL put in the announcement.
    pub api_url: String,
    /// Loopback listen address; expose through a TLS reverse proxy.
    pub listen: String,
    /// Relay HTTP base URLs (receipts and announcements are POSTed).
    #[serde(default)]
    pub relays: Vec<String>,
    /// Optional DEX server base (`POST {dex_url}/v1/instant/operators`).
    #[serde(default)]
    pub dex_url: Option<String>,
    /// Extra browser origins (`chrome-extension://*` is always allowed).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Address HRP set for printing addresses: elements | liquid | liquidtestnet.
    #[serde(default = "default_address_params")]
    pub address_params: String,
    #[serde(default)]
    pub policy: Policy,
}

fn default_address_params() -> String {
    "elements".into()
}

pub struct Loaded {
    pub cfg: Config,
    pub genesis: BlockHash,
    pub fee_asset: AssetId,
    pub bonds: Vec<(OutPoint, u32)>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Loaded, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut cfg: Config =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        // Relative paths are relative to the config file.
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut cfg.key_file, &mut cfg.wal] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        if let Some(c) = cfg.node_rpc.cookie_file.as_mut() {
            if c.is_relative() {
                *c = base.join(&*c);
            }
        }
        cfg.validate()
    }

    pub fn validate(self) -> Result<Loaded, String> {
        let genesis = BlockHash::from_str(&self.genesis).map_err(|_| "invalid genesis")?;
        let fee_asset = AssetId::from_str(&self.fee_asset).map_err(|_| "invalid fee_asset")?;
        let p = &self.policy;
        let d = Policy::default();
        if p.promise_margin < d.promise_margin
            || p.challenge_window < d.challenge_window
            || p.bond_min_confirmations < d.bond_min_confirmations
            || p.max_unconfirmed_ancestors > d.max_unconfirmed_ancestors
            || !(p.fee_floor_sat_vb.is_finite() && p.fee_floor_sat_vb >= 0.0)
            || !(p.fee_multiplier.is_finite() && p.fee_multiplier >= 1.0)
            || p.max_inputs == 0
            || p.max_inputs > 64
            || p.max_outputs == 0
            || p.max_outputs > 256
            || p.promise_rate_per_ip == 0
        {
            return Err("policy may only be stricter than SPEC.md §3 defaults".into());
        }
        if self.node_rpc.cookie_file.is_none() == self.node_rpc.user_pass.is_none() {
            return Err("node_rpc needs exactly one of cookie_file / user_pass".into());
        }
        if self.bonds.len() > elementsplus_instant::announce::MAX_BONDS {
            return Err("at most 16 bonds".into());
        }
        let bonds = self
            .bonds
            .iter()
            .map(|b| Ok((parse_outpoint(&b.outpoint)?, b.refund_height)))
            .collect::<Result<Vec<_>, String>>()?;
        if self.relays.len() > 8 || self.allowed_origins.len() > 16 {
            return Err("at most 8 relays and 16 origins".into());
        }
        if self.allowed_origins.iter().any(|o| o == "*" || o == "null") {
            return Err("origins must be explicit".into());
        }
        Ok(Loaded {
            cfg: self,
            genesis,
            fee_asset,
            bonds,
        })
    }
}

pub fn address_params(
    name: &str,
) -> Result<&'static elementsplus_instant::elements::AddressParams, String> {
    use elementsplus_instant::elements::AddressParams;
    Ok(match name {
        "elements" => &AddressParams::ELEMENTS,
        "liquid" => &AddressParams::LIQUID,
        "liquidtestnet" => &AddressParams::LIQUID_TESTNET,
        _ => return Err("address_params: elements | liquid | liquidtestnet".into()),
    })
}

/// Create a fresh operator key file with mode 0600. Refuses to overwrite.
pub fn keygen(path: &Path) -> Result<Keypair, String> {
    let mut secret = [0u8; 32];
    let key = loop {
        getrandom::getrandom(&mut secret).map_err(|_| "no OS randomness")?;
        if let Ok(k) = SecretKey::from_slice(&secret) {
            break k;
        }
    };
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("{}: {e} (refusing to overwrite)", path.display()))?;
    f.write_all(format!("{}\n", hex::encode(secret)).as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    secret.fill(0);
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &key))
}

/// Load the key, refusing group/other-readable files.
pub fn load_key(path: &Path) -> Result<Keypair, String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: key file must be mode 0600 (chmod 600)",
                path.display()
            ));
        }
    }
    if !meta.is_file() {
        return Err("key file must be a regular file".into());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let bytes = hex::decode(text.trim()).map_err(|_| "key file must hold 64 hex chars")?;
    let key = SecretKey::from_slice(&bytes).map_err(|_| "invalid secret key")?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &key))
}
