//! DEX server client (spec §4.1, §6.1). The server is untrusted: offers are
//! re-verified locally and quote totals are recomputed by the caller.

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

use crate::esplora::{http_client, read_body};

const MAX_PAGES: usize = 50;

#[derive(Clone)]
pub struct Dex {
    base: String,
    http: reqwest::blocking::Client,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// A registry entry as served by `/api/assets` (only the fields we use).
#[derive(Clone, Debug, Deserialize)]
pub struct RegistryEntry {
    pub asset_id: String,
    #[serde(default)]
    pub token_id: Option<String>,
    pub contract: Value,
    pub issuance_txid: String,
    pub issuance_vin: u32,
}

/// An offer entry (book, quote, maker listing). `offer` is the spec §2 offer.
#[derive(Clone, Debug, Deserialize)]
pub struct OfferEntry {
    pub offer: Value,
    pub txid: String,
    pub vout: u32,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub maker_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Quote {
    pub offers: Vec<OfferEntry>,
    pub sell_amount: String,
    pub buy_amount: String,
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Dex {
    pub fn new(base: &str) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: http_client()?,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn handle(&self, what: &str, response: reqwest::blocking::Response) -> Result<Option<Value>> {
        let status = response.status();
        let body = read_body(response)?;
        let value: Option<Value> = serde_json::from_str(&body).ok();
        if status.is_success() {
            return value
                .map(Some)
                .ok_or_else(|| anyhow!("DEX returned non-JSON for {what}"));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            if let Some(code) = value.as_ref().and_then(|v| v["error"]["code"].as_str()) {
                if code != "route_not_found" {
                    return Ok(None);
                }
            }
        }
        match value.as_ref().map(|v| &v["error"]) {
            Some(error) if error.is_object() => bail!(
                "DEX error {} ({status}): {}",
                error["code"].as_str().unwrap_or("unknown"),
                error["message"].as_str().unwrap_or("")
            ),
            _ => bail!("DEX {what} failed ({status}): {}", body.trim()),
        }
    }

    fn get_opt(&self, path: &str) -> Result<Option<Value>> {
        let url = format!("{}{path}", self.base);
        let response = self
            .http
            .get(&url)
            .send()
            .with_context(|| format!("DEX request failed: GET {url}"))?;
        self.handle(path, response)
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let value = self
            .get_opt(path)?
            .ok_or_else(|| anyhow!("DEX: {path} not found"))?;
        serde_json::from_value(value)
            .with_context(|| format!("DEX returned an unexpected shape for {path}"))
    }

    fn get_all<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let separator = if path.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let url = match &cursor {
                Some(cursor) => format!("{path}{separator}limit=500&cursor={}", encode(cursor)),
                None => format!("{path}{separator}limit=500"),
            };
            let page: Page<T> = self.get(&url)?;
            items.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(items),
            }
        }
        Ok(items)
    }

    fn post(&self, path: &str, body: &Value, idempotency_key: &str) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        let response = self
            .http
            .post(&url)
            .header("idempotency-key", idempotency_key)
            .json(body)
            .send()
            .with_context(|| format!("DEX request failed: POST {url}"))?;
        self.handle(path, response)?
            .ok_or_else(|| anyhow!("DEX: {path} not found"))
    }

    pub fn health(&self) -> Result<Value> {
        self.get("/api/health")
    }

    pub fn markets(&self) -> Result<Vec<Value>> {
        self.get_all("/api/markets")
    }

    pub fn book(&self, base: &str, quote: &str) -> Result<Value> {
        self.get(&format!("/api/markets/{base}/{quote}/book"))
    }

    pub fn quote(&self, sell: &str, buy: &str, amount: u64, side: &str) -> Result<(Quote, Value)> {
        let raw: Value = self.get(&format!(
            "/api/quote?sell={sell}&buy={buy}&amount={amount}&side={side}"
        ))?;
        let quote =
            serde_json::from_value(raw.clone()).context("DEX quote has an unexpected shape")?;
        Ok((quote, raw))
    }

    pub fn post_offer(&self, offer: &Value, idempotency_key: &str) -> Result<Value> {
        self.post("/api/offers", offer, idempotency_key)
    }

    pub fn maker_offers(&self, maker_address: &str) -> Result<Vec<OfferEntry>> {
        self.get_all(&format!("/api/offers?maker={}", encode(maker_address)))
    }

    pub fn register_asset(&self, issuance_txid: &str, vin: u32, contract: &Value) -> Result<Value> {
        let body =
            serde_json::json!({ "issuance_txid": issuance_txid, "vin": vin, "contract": contract });
        self.post(
            "/api/assets",
            &body,
            &format!("register-{issuance_txid}-{vin}"),
        )
    }
}

/// Fetch every registry entry from a registry URL (`.../api/assets`).
pub fn fetch_registry(registry_url: &str) -> Result<Vec<RegistryEntry>> {
    let (base, path) = match registry_url.find("/api/") {
        Some(index) => (&registry_url[..index], &registry_url[index..]),
        None => (registry_url, ""),
    };
    let client = Dex::new(base)?;
    let values: Vec<Value> = client.get_all(path)?;
    // Skip malformed entries rather than failing the whole registry.
    Ok(values
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect())
}
