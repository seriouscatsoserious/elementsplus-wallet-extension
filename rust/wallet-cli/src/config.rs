//! `EPW_HOME` layout and `config.toml`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use elementsplus_wallet_core::network::{self, NetworkProfile};

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

/// Network profile ids accepted in `config.toml` (see `docs/NETWORKS.md`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NetworkKind {
    #[serde(rename = "ecx-beta")]
    EcxBeta,
    #[serde(rename = "ecx-mainnet")]
    EcxMainnet,
    /// `regtest` is accepted as a legacy spelling.
    #[serde(rename = "elementsplus-regtest", alias = "regtest")]
    Regtest,
    /// Retired chain. Still parsed so an old config yields a clear refusal
    /// instead of a TOML error; never selectable.
    #[serde(rename = "ecx-alpha")]
    ArchivedAlpha,
}

pub const NETWORK_IDS: &[&str] = &["ecx-beta", "ecx-mainnet", "elementsplus-regtest"];

impl NetworkKind {
    pub fn profile(self) -> &'static NetworkProfile {
        match self {
            Self::EcxBeta => &network::ECX_BETA,
            Self::EcxMainnet => &network::ECX_MAINNET,
            Self::Regtest => &network::ELEMENTSPLUS_REGTEST,
            Self::ArchivedAlpha => &network::ECX_ALPHA,
        }
    }

    pub fn as_str(self) -> &'static str {
        self.profile().id
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "ecx-beta" => Self::EcxBeta,
            "ecx-mainnet" => Self::EcxMainnet,
            "elementsplus-regtest" | "regtest" => Self::Regtest,
            "ecx-alpha" => bail!("{}", network::NetworkProfileError::Archived("ecx-alpha")),
            _ => bail!("network must be one of: {}", NETWORK_IDS.join(", ")),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Network profile id. Public profiles pin genesis and policy asset in
    /// the wallet core; pending profiles are refused until published.
    pub network: NetworkKind,
    /// Regtest only (public profiles are pinned by the core).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_hash: Option<String>,
    /// Regtest only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_asset: Option<String>,
    /// Overrides the profile's Esplora URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esplora_url: Option<String>,
    /// Overrides the profile's DEX URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dex_url: Option<String>,
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
            network: NetworkKind::EcxBeta,
            genesis_hash: None,
            policy_asset: None,
            esplora_url: None,
            dex_url: None,
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
        for (key, url) in [
            ("esplora_url", &self.esplora_url),
            ("dex_url", &self.dex_url),
            ("registry_url", &self.registry_url),
        ] {
            if let Some(url) = url {
                check_url(url).context(key)?;
            }
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
        if self.network != NetworkKind::Regtest
            && (self.genesis_hash.is_some() || self.policy_asset.is_some())
        {
            bail!(
                "genesis_hash/policy_asset are only configurable for network = \"elementsplus-regtest\"; {} is pinned by its profile",
                self.network.as_str()
            );
        }
        Ok(())
    }

    /// The selected profile, refusing pending (unpublished) and archived ones.
    pub fn profile(&self) -> Result<&'static NetworkProfile> {
        let profile = self.network.profile();
        profile.ensure_selectable().map_err(|e| anyhow!("{e}"))?;
        Ok(profile)
    }

    /// Configured Esplora URL, else the profile's.
    pub fn esplora_url(&self) -> Result<String> {
        let profile = self.profile()?;
        self.esplora_url
            .clone()
            .or_else(|| profile.esplora_url.map(str::to_owned))
            .ok_or_else(|| anyhow!("no Esplora URL for {}; set esplora_url", profile.id))
    }

    /// Configured DEX URL, else the profile's.
    pub fn dex_url(&self) -> Result<String> {
        let profile = self.profile()?;
        self.dex_url
            .clone()
            .or_else(|| profile.dex_url.map(str::to_owned))
            .ok_or_else(|| anyhow!("no DEX URL for {}; set dex_url", profile.id))
    }

    pub fn registry_url(&self) -> Result<String> {
        match &self.registry_url {
            Some(url) => Ok(url.clone()),
            None => Ok(format!("{}/api/assets", self.dex_url()?)),
        }
    }

    pub fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(match key {
            "network" => Some(self.network.as_str().into()),
            "genesis_hash" => self.genesis_hash.clone(),
            "policy_asset" => self.policy_asset.clone(),
            "esplora_url" => self.esplora_url()?.into(),
            "dex_url" => self.dex_url()?.into(),
            "registry_url" => self.registry_url()?.into(),
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
                self.network = NetworkKind::parse(value)?;
                if self.network != NetworkKind::Regtest {
                    self.genesis_hash = None;
                    self.policy_asset = None;
                }
            }
            "genesis_hash" => self.genesis_hash = optional(value),
            "policy_asset" => self.policy_asset = optional(value),
            "esplora_url" | "dex_url" | "registry_url" => {
                let url = if value.is_empty() {
                    None
                } else {
                    Some(check_url(value)?)
                };
                match key {
                    "esplora_url" => self.esplora_url = url,
                    "dex_url" => self.dex_url = url,
                    _ => self.registry_url = url,
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
        assert_eq!(config.network.as_str(), "ecx-beta");
        assert!(
            config.set("genesis_hash", &"a".repeat(64)).is_err(),
            "pinned on public profiles"
        );
        config.set("network", "regtest").unwrap();
        assert_eq!(
            config.get("network").unwrap().unwrap(),
            "elementsplus-regtest"
        );
        assert_eq!(
            config.get("esplora_url").unwrap().unwrap(),
            "http://127.0.0.1:43199/api",
            "profile default"
        );
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
        assert!(text.contains("network = \"elementsplus-regtest\""));
    }

    #[test]
    fn pending_and_archived_profiles_are_refused() {
        let mut config = Config::default();
        for id in ["ecx-beta", "ecx-mainnet"] {
            config.set("network", id).unwrap();
            let error = config.profile().unwrap_err().to_string();
            assert!(error.contains("pending"), "{error}");
            assert!(config.esplora_url().is_err());
        }
        let error = config.set("network", "ecx-alpha").unwrap_err().to_string();
        assert!(error.contains("archived"), "{error}");
        assert!(config.set("network", "liquidv1").is_err());
        // An old ecx-alpha config still parses, then refuses to run.
        let old: Config = toml::from_str(
            "network = \"ecx-alpha\"\nesplora_url = \"https://explorer.bitnames.info/api\"\ndex_url = \"http://127.0.0.1:8790\"\n",
        )
        .unwrap();
        assert!(old.profile().unwrap_err().to_string().contains("archived"));
        // Legacy `regtest` spelling still loads.
        let legacy: Config = toml::from_str(
            "network = \"regtest\"\nesplora_url = \"http://127.0.0.1:1/api\"\ndex_url = \"http://127.0.0.1:2\"\n",
        )
        .unwrap();
        assert_eq!(legacy.network, NetworkKind::Regtest);
    }
}
