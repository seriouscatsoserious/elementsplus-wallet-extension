//! Wire formats the watchtower consumes, and their local verification.
//!
//! Nothing received from a relay, an operator API or a file is trusted. Every
//! promise is BIP340-verified against the claimed operator key over
//! `promise_digest(genesis, lockbox, commitment)` before it is stored, and
//! every announcement is signature-checked and bound to our genesis and fee
//! asset before its bonds are looked up on chain.
//!
//! Encoding conventions (SPEC §3, §5.2, §5.4):
//! * txids, block hashes and asset ids: RPC/display hex (as Esplora prints them);
//! * outpoints: `"<txid>:<vout>"` (an optional `[elements]` prefix is accepted);
//! * `commitment`: the 32 raw bytes of `tx_commitment` as hex, NOT reversed;
//! * `sig`: 128 hex chars (BIP340); `operator`: 64 hex chars (x-only key);
//! * sequence numbers: JSON number or decimal string.
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use elementsplus_instant::{
    announce::{AnnouncedBond, Announcement},
    bond::Promise,
    elements::{
        encode, secp256k1_zkp::XOnlyPublicKey, AssetId, BlockHash, OutPoint,
        Transaction, TxOut, Txid,
    },
    hash, verify_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub fn fmt_outpoint(o: &OutPoint) -> String {
    format!("{}:{}", o.txid, o.vout)
}

pub fn parse_outpoint(s: &str) -> Result<OutPoint> {
    let s = s.strip_prefix("[elements]").unwrap_or(s);
    let (txid, vout) = s.split_once(':').ok_or_else(|| anyhow!("outpoint {s:?}"))?;
    Ok(OutPoint::new(
        Txid::from_str(txid).context("outpoint txid")?,
        vout.parse().context("outpoint vout")?,
    ))
}

pub fn parse_xonly(s: &str) -> Result<XOnlyPublicKey> {
    XOnlyPublicKey::from_str(s.trim()).map_err(|e| anyhow!("x-only key {s:?}: {e}"))
}

fn parse_hex_array<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s.trim()).with_context(|| format!("{what} hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{what} must be {N} bytes"))
}

fn parse_seq(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// A promise as it travels on the wire, before verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromiseWire {
    pub operator: String,
    pub lockbox: String,
    pub commitment: String,
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// A promise whose signature has been checked locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPromise {
    pub operator: XOnlyPublicKey,
    pub lockbox: OutPoint,
    pub promise: Promise,
}

impl PromiseWire {
    pub fn verify(&self, genesis: BlockHash) -> Result<VerifiedPromise> {
        let operator = parse_xonly(&self.operator)?;
        let lockbox = parse_outpoint(&self.lockbox)?;
        let commitment: [u8; 32] = parse_hex_array(&self.commitment, "commitment")?;
        let signature: [u8; 64] = parse_hex_array(&self.sig, "sig")?;
        let digest = hash::promise_digest(genesis, lockbox, commitment);
        if !verify_digest(digest, &signature, &operator) {
            bail!(
                "promise signature for {} does not verify under operator {}",
                self.lockbox,
                self.operator
            );
        }
        Ok(VerifiedPromise {
            operator,
            lockbox,
            promise: Promise {
                commitment,
                signature,
            },
        })
    }
}

impl VerifiedPromise {
    pub fn to_wire(&self) -> PromiseWire {
        PromiseWire {
            operator: self.operator.to_string(),
            lockbox: fmt_outpoint(&self.lockbox),
            commitment: hex::encode(self.promise.commitment),
            sig: hex::encode(self.promise.signature),
            txid: None,
            seq: None,
        }
    }
}

/// Optional full transaction carried with a receipt (`tx` + `spent` as in the
/// `POST /v1/promise` request). When present, the commitment is recomputed
/// locally and must equal the one claimed.
fn check_tx_binding(obj: &Value, claimed: &str) -> Result<()> {
    let (Some(tx), Some(spent)) = (obj.get("tx"), obj.get("spent")) else {
        return Ok(());
    };
    let tx: Transaction = encode::deserialize(&hex::decode(
        tx.as_str().ok_or_else(|| anyhow!("tx must be hex"))?,
    )?)
    .context("tx")?;
    let spent: Vec<TxOut> = spent
        .as_array()
        .ok_or_else(|| anyhow!("spent must be an array"))?
        .iter()
        .map(|s| -> Result<TxOut> {
            Ok(encode::deserialize(&hex::decode(
                s.as_str().ok_or_else(|| anyhow!("spent[i] must be hex"))?,
            )?)?)
        })
        .collect::<Result<_>>()?;
    let c = hash::tx_commitment(&tx, &spent).map_err(|e| anyhow!(e))?;
    if hex::encode(c) != claimed.to_ascii_lowercase() {
        bail!("receipt commitment does not match its own transaction");
    }
    Ok(())
}

/// Extract every promise from a JSON value. Accepted shapes (arbitrarily
/// nested in arrays and in `{receipts|promises|items|data|event|receipt}`):
///
/// * flat: `{operator, lockbox, commitment, sig, txid?, seq?}`;
/// * SPEC §5.4 promise-API response / relay receipt:
///   `{operator, txid?, seq?, promises: [{index?, lockbox, commitment, sig}], tx?, spent?}`;
///   `operator` may also be supplied by the caller (`default_operator`, e.g.
///   when reading an operator's own `/v1/promises` log).
pub fn extract_promises(v: &Value, default_operator: Option<&str>) -> Vec<Result<PromiseWire>> {
    let mut out = vec![];
    walk(v, default_operator, None, &mut out, 0);
    out
}

fn walk(
    v: &Value,
    op: Option<&str>,
    seq: Option<u64>,
    out: &mut Vec<Result<PromiseWire>>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    match v {
        Value::Array(items) => {
            for i in items {
                walk(i, op, seq, out, depth + 1);
            }
        }
        Value::Object(map) => {
            let op_here = map.get("operator").and_then(Value::as_str).or(op);
            let seq_here = map.get("seq").and_then(parse_seq).or(seq);
            if map.contains_key("commitment") && map.contains_key("sig") {
                out.push(flat(v, op_here, seq_here));
                return;
            }
            for key in ["receipts", "promises", "items", "data", "event", "receipt"] {
                if let Some(inner) = map.get(key) {
                    if key == "promises" {
                        // Receipt envelope: the inner promises share operator/txid/tx.
                        if let Value::Array(ps) = inner {
                            for p in ps {
                                let r = flat(p, op_here, seq_here).and_then(|mut w| {
                                    if w.txid.is_none() {
                                        w.txid =
                                            map.get("txid").and_then(Value::as_str).map(Into::into);
                                    }
                                    check_tx_binding(v, &w.commitment)?;
                                    Ok(w)
                                });
                                out.push(r);
                            }
                            continue;
                        }
                    }
                    walk(inner, op_here, seq_here, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn flat(v: &Value, op: Option<&str>, seq: Option<u64>) -> Result<PromiseWire> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let commitment = s("commitment").ok_or_else(|| anyhow!("missing commitment"))?;
    check_tx_binding(v, &commitment)?;
    Ok(PromiseWire {
        operator: s("operator")
            .or(op.map(Into::into))
            .ok_or_else(|| anyhow!("missing operator"))?,
        lockbox: s("lockbox").ok_or_else(|| anyhow!("missing lockbox"))?,
        commitment,
        sig: s("sig")
            .or_else(|| s("signature"))
            .ok_or_else(|| anyhow!("missing sig"))?,
        txid: s("txid"),
        seq: v.get("seq").and_then(parse_seq).or(seq),
    })
}

/// Announcement JSON (SPEC §5.2): `{announcement: {...}, signature}` or the
/// announcement fields with a sibling `signature`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAnnouncement {
    pub announcement: Announcement,
    pub signature: [u8; 64],
}

impl SignedAnnouncement {
    pub fn parse(v: &Value) -> Result<Self> {
        let body = v.get("announcement").unwrap_or(v);
        let sig = v
            .get("signature")
            .or_else(|| body.get("signature"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("announcement without signature"))?;
        let s = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("announcement.{k}"))
        };
        let bonds = body
            .get("bonds")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("announcement.bonds"))?
            .iter()
            .map(|b| -> Result<AnnouncedBond> {
                Ok(AnnouncedBond {
                    outpoint: parse_outpoint(
                        b.get("outpoint")
                            .and_then(Value::as_str)
                            .ok_or_else(|| anyhow!("bond.outpoint"))?,
                    )?,
                    refund_height: b
                        .get("refund_height")
                        .and_then(parse_seq)
                        .and_then(|h| u32::try_from(h).ok())
                        .ok_or_else(|| anyhow!("bond.refund_height"))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            announcement: Announcement {
                genesis: BlockHash::from_str(s("genesis")?)?,
                fee_asset: AssetId::from_str(s("fee_asset")?)?,
                operator: parse_xonly(s("operator")?)?,
                sequence: body
                    .get("sequence")
                    .and_then(parse_seq)
                    .ok_or_else(|| anyhow!("announcement.sequence"))?,
                bonds,
                api_url: s("api_url")?.to_string(),
            },
            signature: parse_hex_array(sig, "announcement signature")?,
        })
    }

    /// Signature valid AND for our chain and fee asset.
    pub fn verify(&self, genesis: BlockHash, fee_asset: AssetId) -> Result<()> {
        let a = &self.announcement;
        if a.genesis != genesis {
            bail!("announcement is for another chain");
        }
        if a.fee_asset != fee_asset {
            bail!("announcement uses another fee asset");
        }
        a.verify(&self.signature).map_err(|e| anyhow!(e))
    }

    pub fn to_json(&self) -> Value {
        let a = &self.announcement;
        serde_json::json!({
            "announcement": {
                "genesis": a.genesis.to_string(),
                "fee_asset": a.fee_asset.to_string(),
                "operator": a.operator.to_string(),
                "sequence": a.sequence.to_string(),
                "bonds": a.bonds.iter().map(|b| serde_json::json!({
                    "outpoint": fmt_outpoint(&b.outpoint),
                    "refund_height": b.refund_height,
                })).collect::<Vec<_>>(),
                "api_url": a.api_url,
            },
            "signature": hex::encode(self.signature),
        })
    }
}

/// Extract announcements from `GET /v1/operators` (array, or `{operators: [...]}`).
pub fn extract_announcements(v: &Value) -> Vec<Result<SignedAnnouncement>> {
    let items = match v {
        Value::Array(a) => a.clone(),
        Value::Object(m) => match m.get("operators").or_else(|| m.get("announcements")) {
            Some(Value::Array(a)) => a.clone(),
            _ => vec![v.clone()],
        },
        _ => vec![],
    };
    items.iter().map(SignedAnnouncement::parse).collect()
}
