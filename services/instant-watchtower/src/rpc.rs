//! Minimal Elements JSON-RPC client (cookie or user:password auth).
//!
//! The node is REQUIRED for broadcasting: the penalty burns 7/8 of the bond to
//! `OP_RETURN`, and `sendrawtransaction` refuses that unless `maxburnamount`
//! is passed (its default is 0). A plain Esplora `POST /tx` therefore fails.
use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use elementsplus_instant::elements::{AssetId, BlockHash, Txid};
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub enum Auth {
    Cookie(PathBuf),
    UserPass(String, String),
}

#[derive(Clone, Debug)]
pub struct NodeRpc {
    url: String,
    auth: Auth,
    http: reqwest::Client,
}

/// Decimal coin string for exact atomic amounts (8 decimals).
pub fn coins(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Parse a JSON coin amount (number or string) into atomic units exactly.
pub fn sats_from_json(v: &Value) -> Option<u64> {
    let s = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return None,
    };
    let (whole, frac) = s.split_once('.').unwrap_or((&s, ""));
    if frac.len() > 8 || whole.starts_with('-') {
        return None;
    }
    let whole: u64 = whole.parse().ok()?;
    let frac: u64 = format!("{frac:0<8}").parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

impl NodeRpc {
    pub fn new(url: &str, auth: Auth) -> Result<Self> {
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            auth,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()?,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn credentials(&self) -> Result<(String, String)> {
        match &self.auth {
            Auth::UserPass(u, p) => Ok((u.clone(), p.clone())),
            Auth::Cookie(path) => {
                // Re-read every call: the cookie rotates when the node restarts.
                let s = std::fs::read_to_string(path)
                    .with_context(|| format!("read RPC cookie {}", path.display()))?;
                let (u, p) = s
                    .trim()
                    .split_once(':')
                    .ok_or_else(|| anyhow!("malformed cookie file"))?;
                Ok((u.into(), p.into()))
            }
        }
    }

    pub async fn call_at(&self, path: &str, method: &str, params: Value) -> Result<Value> {
        let (user, pass) = self.credentials()?;
        let resp = self
            .http
            .post(format!("{}{}", self.url, path))
            .basic_auth(user, Some(pass))
            .json(&json!({"jsonrpc": "1.0", "id": "watchtower", "method": method, "params": params}))
            .send()
            .await
            .with_context(|| format!("RPC {method}: connect"))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .with_context(|| format!("RPC {method}: HTTP {status}"))?;
        if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
            bail!(
                "RPC {method}: {}",
                err.get("message").and_then(Value::as_str).unwrap_or("error")
            );
        }
        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.call_at("", method, params).await
    }

    pub async fn genesis(&self) -> Result<BlockHash> {
        let v = self.call("getblockhash", json!([0])).await?;
        Ok(v.as_str().ok_or_else(|| anyhow!("getblockhash"))?.parse()?)
    }

    /// The native/pegged asset (the bond's `FEE_ASSET`).
    pub async fn policy_asset(&self) -> Result<AssetId> {
        let v = self.call("getsidechaininfo", json!([])).await?;
        Ok(v["pegged_asset"]
            .as_str()
            .ok_or_else(|| anyhow!("getsidechaininfo.pegged_asset"))?
            .parse()?)
    }

    pub async fn chain_name(&self) -> Result<String> {
        let v = self.call("getblockchaininfo", json!([])).await?;
        Ok(v["chain"].as_str().unwrap_or_default().to_string())
    }

    /// `estimatesmartfee 2` in sat/kvB, if the node has an estimate.
    pub async fn fee_rate_sat_per_kvb(&self) -> Option<u64> {
        let v = self.call("estimatesmartfee", json!([2])).await.ok()?;
        sats_from_json(v.get("feerate")?)
    }

    /// Address for a scriptPubKey as this node encodes it (network-agnostic).
    pub async fn address_for_script(&self, script_hex: &str) -> Result<Option<String>> {
        let v = self.call("decodescript", json!([script_hex])).await?;
        Ok(v.get("address")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                v.get("addresses")
                    .and_then(|a| a.get(0))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }))
    }

    /// Confirmed UTXOs paying `script_hex` (`scantxoutset`, slow on big chains).
    pub async fn scan_script(&self, script_hex: &str) -> Result<Vec<(Txid, u32)>> {
        let v = self
            .call(
                "scantxoutset",
                json!(["start", [format!("raw({script_hex})")]]),
            )
            .await?;
        v.get("unspents")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("scantxoutset.unspents"))?
            .iter()
            .map(|u| {
                Ok((
                    u["txid"].as_str().ok_or_else(|| anyhow!("txid"))?.parse()?,
                    u["vout"].as_u64().ok_or_else(|| anyhow!("vout"))? as u32,
                ))
            })
            .collect()
    }

    pub async fn send_raw(&self, hex: &str, max_burn: u64) -> Result<Txid> {
        let v = self
            .call("sendrawtransaction", json!([hex, 0, coins(max_burn)]))
            .await?;
        Ok(v.as_str()
            .ok_or_else(|| anyhow!("sendrawtransaction result"))?
            .parse()?)
    }
}

/// Anything that can submit a raw penalty transaction.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    fn name(&self) -> String;
    async fn broadcast(&self, hex: &str, max_burn: u64) -> Result<Txid>;
}

#[async_trait]
impl Broadcaster for NodeRpc {
    fn name(&self) -> String {
        format!("rpc:{}", self.url)
    }
    async fn broadcast(&self, hex: &str, max_burn: u64) -> Result<Txid> {
        self.send_raw(hex, max_burn).await
    }
}

/// Esplora `POST /tx`. Only useful for backends whose node accepts burns by
/// default; most will reject the penalty (see module docs). Best effort.
pub struct EsploraPost {
    pub url: String,
    pub http: reqwest::Client,
}

#[async_trait]
impl Broadcaster for EsploraPost {
    fn name(&self) -> String {
        format!("esplora:{}", self.url)
    }
    async fn broadcast(&self, hex: &str, _max_burn: u64) -> Result<Txid> {
        let r = self
            .http
            .post(format!("{}/tx", self.url.trim_end_matches('/')))
            .body(hex.to_string())
            .send()
            .await?;
        let status = r.status();
        let text = r.text().await?;
        if !status.is_success() {
            bail!("HTTP {status}: {}", text.trim());
        }
        Ok(text.trim().parse()?)
    }
}

/// The transaction is already known: treat as a successful (re)broadcast.
pub fn is_already_known(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("already in block chain")
        || e.contains("txn-already-in-mempool")
        || e.contains("txn-already-known")
        || e.contains("transaction already in block chain")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_conversions_are_exact() {
        assert_eq!(coins(7_000_000), "0.07000000");
        assert_eq!(coins(2_100_000_000_000_001), "21000000.00000001");
        assert_eq!(sats_from_json(&json!("0.07")), Some(7_000_000));
        assert_eq!(sats_from_json(&json!(0.00001)), Some(1_000));
        assert_eq!(sats_from_json(&json!("1.000000001")), None);
        assert_eq!(sats_from_json(&json!("-1")), None);
    }
}
