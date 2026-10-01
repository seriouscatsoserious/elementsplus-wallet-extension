//! `EPW_HOME` layout and `config.toml`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_ESPLORA_URL: &str = "https://explorer.bitnames.info/api";
pub const DEFAULT_DEX_URL: &str = "http://127.0.0.1:8790";
pub const DEFAULT_FEE_RATE: u64 = 1;
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// The wallet home directory (`EPW_HOME`, else `$XDG_CONFIG_HOME/epw`, else
/// `~/.config/epw`).
#[derive(Clone, Debug)]
pub struct Home {
    pub root: PathBuf,
}

impl Home {
    pub fn resolve() -> Result<Self> {
        if let Some(home) = std::env::var_os("EPW_HOME").filter(|v| !v.is_empty()) {
            return Ok(Self { root: home.into() });
        }
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return Ok(Self {
                root: PathBuf::from(xdg).join("epw"),
            });
        }
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow!("cannot locate the home directory; set EPW_HOME"))?;
        Ok(Self {
            root: PathBuf::from(home).join(".config").join("epw"),
        })
    }

    pub fn keystore(&self) -> PathBuf {
        self.root.join("keystore.json")
    }
    pub fn config(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn policy(&self) -> PathBuf {
        self.root.join("policy.toml")
    }
    pub fn audit_log(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }
    pub fn pending_dir(&self) -> PathBuf {
        self.root.join("pending")
    }
    /// Per-chain local state (offers, address reservations, asset cache).
    pub fn state_file(&self, genesis_hash: &str) -> PathBuf {
        let short = genesis_hash.get(..16).unwrap_or(genesis_hash);
        self.root.join(format!("state-{short}.json"))
    }

    pub fn ensure(&self) -> Result<()> {
        create_private_dir(&self.root)
    }
}

pub fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Write a file atomically (temp file + rename) with private permissions.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NetworkKind {
    #[serde(rename = "ecx-alpha")]
    EcxAlpha,
    #[serde(rename = "regtest")]
    Regtest,
}

impl NetworkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcxAlpha => "ecx-alpha",
            Self::Regtest => "regtest",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network: NetworkKind,
    /// Regtest only (ECX Alpha is pinned by the core).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_hash: Option<String>,
    /// Regtest only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_asset: Option<String>,
    pub esplora_url: String,
    pub dex_url: String,
    /// Asset registry; defaults to `<dex_url>/api/assets`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_url: Option<String>,
    #[serde(default = "default_fee_rate")]
    pub fee_rate: u64,
    #[serde(default = "default_gap_limit")]
    pub gap_limit: u32,
}

fn default_fee_rate() -> u64 {
    DEFAULT_FEE_RATE
}
fn default_gap_limit() -> u32 {
    DEFAULT_GAP_LIMIT
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkKind::EcxAlpha,
            genesis_hash: None,
            policy_asset: None,
            esplora_url: DEFAULT_ESPLORA_URL.into(),
            dex_url: DEFAULT_DEX_URL.into(),
            registry_url: None,
            fee_rate: DEFAULT_FEE_RATE,
            gap_limit: DEFAULT_GAP_LIMIT,
        }
    }
}

pub const CONFIG_KEYS: &[&str] = &[
    "network",
    "genesis_hash",
    "policy_asset",
    "esplora_url",
    "dex_url",
    "registry_url",
    "fee_rate",
    "gap_limit",
];

fn is_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check_url(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        bail!("URL must start with http:// or https://");
    }
    Ok(value.to_owned())
}

impl Config {
    pub fn load(home: &Home) -> Result<Self> {
        let path = home.config();
        match fs::read_to_string(&path) {
            Ok(text) => {
                let config: Self =
                    toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?;
                config.validate()?;
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        self.validate()?;
        write_private(&home.config(), toml::to_string_pretty(self)?.as_bytes())
    }

    pub fn validate(&self) -> Result<()> {
        check_url(&self.esplora_url).context("esplora_url")?;
        check_url(&self.dex_url).context("dex_url")?;
        if let Some(url) = &self.registry_url {
            check_url(url).context("registry_url")?;
        }
        if self.fee_rate == 0 || self.fee_rate > elementsplus_wallet_core::MAX_FEE_RATE {
            bail!(
                "fee_rate must be 1..={}",
                elementsplus_wallet_core::MAX_FEE_RATE
            );
        }
        if !(1..=1000).contains(&self.gap_limit) {
            bail!("gap_limit must be 1..=1000");
        }
        for value in [&self.genesis_hash, &self.policy_asset]
            .into_iter()
            .flatten()
        {
            if !is_hex32(value) {
                bail!("genesis_hash/policy_asset must be 64 lowercase hex characters");
            }
        }
        if self.network == NetworkKind::EcxAlpha
            && (self.genesis_hash.is_some() || self.policy_asset.is_some())
        {
            bail!("genesis_hash/policy_asset are only configurable for network = \"regtest\"; ECX Alpha is pinned");
        }
        Ok(())
    }

    pub fn registry_url(&self) -> String {
        self.registry_url
            .clone()
            .unwrap_or_else(|| format!("{}/api/assets", self.dex_url))
    }

    pub fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(match key {
            "network" => Some(self.network.as_str().into()),
            "genesis_hash" => self.genesis_hash.clone(),
            "policy_asset" => self.policy_asset.clone(),
            "esplora_url" => Some(self.esplora_url.clone()),
            "dex_url" => Some(self.dex_url.clone()),
            "registry_url" => Some(self.registry_url()),
            "fee_rate" => Some(self.fee_rate.to_string()),
            "gap_limit" => Some(self.gap_limit.to_string()),
            _ => bail!(
                "unknown config key {key:?}; known: {}",
                CONFIG_KEYS.join(", ")
            ),
        })
    }

    /// Set a key; an empty value clears optional keys.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let optional = |value: &str| (!value.is_empty()).then(|| value.to_ascii_lowercase());
        match key {
            "network" => {
                self.network = match value {
                    "ecx-alpha" => {
                        self.genesis_hash = None;
                        self.policy_asset = None;
                        NetworkKind::EcxAlpha
                    }
                    "regtest" => NetworkKind::Regtest,
                    _ => bail!("network must be \"ecx-alpha\" or \"regtest\""),
                }
            }
            "genesis_hash" => self.genesis_hash = optional(value),
            "policy_asset" => self.policy_asset = optional(value),
            "esplora_url" => self.esplora_url = check_url(value)?,
            "dex_url" => self.dex_url = check_url(value)?,
            "registry_url" => {
                self.registry_url = if value.is_empty() {
                    None
                } else {
                    Some(check_url(value)?)
                }
            }
            "fee_rate" => self.fee_rate = value.parse().context("fee_rate must be an integer")?,
            "gap_limit" => {
                self.gap_limit = value.parse().context("gap_limit must be an integer")?
            }
            _ => bail!(
                "unknown config key {key:?}; known: {}",
                CONFIG_KEYS.join(", ")
            ),
        }
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_validate() {
        let mut config = Config::default();
        assert!(
            config.set("genesis_hash", &"a".repeat(64)).is_err(),
            "pinned on ecx-alpha"
        );
        config.set("network", "regtest").unwrap();
        config.set("genesis_hash", &"a".repeat(64)).unwrap();
        config.set("dex_url", "http://127.0.0.1:8790/").unwrap();
        assert_eq!(
            config.get("dex_url").unwrap().unwrap(),
            "http://127.0.0.1:8790"
        );
        assert_eq!(
            config.get("registry_url").unwrap().unwrap(),
            "http://127.0.0.1:8790/api/assets"
        );
        assert!(config.set("fee_rate", "0").is_err());
        assert!(config.set("esplora_url", "ftp://x").is_err());
        assert!(config.set("nope", "1").is_err());
        let text = toml::to_string_pretty(&config).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, config);
    }
}
