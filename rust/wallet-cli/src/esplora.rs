//! Minimal blocking Esplora client. Every response is untrusted: callers
//! verify raw transactions locally before relying on them.

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;

const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;

pub fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("epw/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("cannot build HTTP client")
}

/// Read a bounded body as text.
pub fn read_body(response: reqwest::blocking::Response) -> Result<String> {
    let mut text = String::new();
    response
        .take(MAX_TEXT_BYTES + 1)
        .read_to_string(&mut text)
        .context("cannot read HTTP response body")?;
    if text.len() as u64 > MAX_TEXT_BYTES {
        bail!("HTTP response exceeds {MAX_TEXT_BYTES} bytes");
    }
    Ok(text)
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Stats {
    #[serde(default)]
    pub funded_txo_count: u64,
    #[serde(default)]
    pub spent_txo_count: u64,
    #[serde(default)]
    pub tx_count: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AddressInfo {
    #[serde(default)]
    pub chain_stats: Stats,
    #[serde(default)]
    pub mempool_stats: Stats,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TxStatus {
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub status: TxStatus,
    #[serde(default)]
    pub value: Option<u64>,
    #[serde(default)]
    pub asset: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Outspend {
    pub spent: bool,
    #[serde(default)]
    pub txid: Option<String>,
}

#[derive(Clone)]
pub struct Esplora {
    base: String,
    http: reqwest::blocking::Client,
}

fn check_hex_id(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("invalid txid {value:?}");
    }
    Ok(())
}

impl Esplora {
    pub fn new(base: &str) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: http_client()?,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn get(&self, path: &str) -> Result<Option<String>> {
        let url = format!("{}{path}", self.base);
        let response = self
            .http
            .get(&url)
            .send()
            .with_context(|| format!("explorer request failed: GET {url}"))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = read_body(response)?;
        if !status.is_success() {
            bail!("explorer GET {url} returned {status}: {}", body.trim());
        }
        Ok(Some(body))
    }

    fn get_text(&self, path: &str) -> Result<String> {
        self.get(path)?
            .ok_or_else(|| anyhow!("explorer: {path} not found"))
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.get_text(path)?;
        serde_json::from_str(&text)
            .with_context(|| format!("explorer returned malformed JSON for {path}"))
    }

    pub fn genesis_hash(&self) -> Result<String> {
        let hash = self.get_text("/block-height/0")?.trim().to_owned();
        check_hex_id(&hash).context("explorer genesis hash")?;
        Ok(hash)
    }

    pub fn tip_height(&self) -> Result<u64> {
        self.get_text("/blocks/tip/height")?
            .trim()
            .parse()
            .context("explorer tip height is not a number")
    }

    pub fn address_info(&self, address: &str) -> Result<AddressInfo> {
        self.get_json(&format!("/address/{address}"))
    }

    pub fn address_utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        self.get_json(&format!("/address/{address}/utxo"))
    }

    /// All transactions touching an address (mempool first, then confirmed,
    /// newest first), following Esplora's chain pagination.
    pub fn address_txs(&self, address: &str, max: usize) -> Result<Vec<serde_json::Value>> {
        let mut all: Vec<serde_json::Value> = self.get_json(&format!("/address/{address}/txs"))?;
        let mut confirmed = all
            .iter()
            .filter(|tx| tx["status"]["confirmed"].as_bool() == Some(true))
            .count();
        // Esplora returns up to 25 confirmed txs per page.
        while confirmed >= 25 && all.len() < max {
            let Some(last) = all
                .last()
                .and_then(|tx| tx["txid"].as_str())
                .map(str::to_owned)
            else {
                break;
            };
            let page: Vec<serde_json::Value> =
                self.get_json(&format!("/address/{address}/txs/chain/{last}"))?;
            if page.is_empty() {
                break;
            }
            confirmed = page.len();
            all.extend(page);
        }
        all.truncate(max);
        Ok(all)
    }

    pub fn tx_hex(&self, txid: &str) -> Result<String> {
        check_hex_id(txid)?;
        let hex = self
            .get_text(&format!("/tx/{txid}/hex"))?
            .trim()
            .to_ascii_lowercase();
        if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("explorer returned malformed raw transaction hex for {txid}");
        }
        Ok(hex)
    }

    pub fn outspend(&self, txid: &str, vout: u32) -> Result<Outspend> {
        check_hex_id(txid)?;
        self.get_json(&format!("/tx/{txid}/outspend/{vout}"))
    }

    /// POST /tx; returns the txid the explorer reports.
    pub fn broadcast(&self, raw_tx_hex: &str) -> Result<String> {
        let url = format!("{}/tx", self.base);
        let response = self
            .http
            .post(&url)
            .header("content-type", "text/plain")
            .body(raw_tx_hex.to_owned())
            .send()
            .with_context(|| format!("broadcast failed: POST {url}"))?;
        let status = response.status();
        let body = read_body(response)?;
        if !status.is_success() {
            bail!("broadcast rejected ({status}): {}", body.trim());
        }
        Ok(body.trim().to_owned())
    }
}
