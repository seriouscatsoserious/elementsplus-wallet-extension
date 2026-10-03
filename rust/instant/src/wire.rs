//! Off-chain wire formats shared by operators, relays, wallets and
//! watchtowers (SPEC.md §5.2, §5.4): the JSON shapes of signed announcements
//! and signed promise receipts, and the receipt / status digests.
//!
//! Nothing here is consensus. The covenants only ever see the promise
//! signature (`hash::promise_digest`); receipts are the operator's signed,
//! publishable statement "I promised these lockboxes to this transaction",
//! which relays use to detect per-outpoint equivocation.
//!
//! JSON conventions (same as JK's relay): txids, block hashes and asset ids
//! in RPC/display hex; outpoints as `txid:vout`; x-only keys, signatures and
//! the 32-byte `tx_commitment` as plain lowercase hex of their bytes; u64
//! amounts and sequences as canonical decimal strings.
use crate::{
    announce::{AnnouncedBond, Announcement},
    elements::{
        hashes::{sha256, Hash, HashEngine},
        secp256k1_zkp::XOnlyPublicKey,
        AssetId, BlockHash, OutPoint, Txid,
    },
    hash, verify_digest,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, str::FromStr};

pub const RECEIPT_TAG: &[u8] = b"ECX/Instant/Receipt/v1";
pub const STATUS_TAG: &[u8] = b"ECX/Instant/Status/v1";
pub const MAX_RECEIPT_PROMISES: usize = 16;
pub const MAX_RECEIPT_BONDS: usize = 16;

// ---------- primitive parsers ----------

pub fn parse_outpoint(s: &str) -> Result<OutPoint, String> {
    let (txid, vout) = s.split_once(':').ok_or("outpoint must be txid:vout")?;
    if txid.len() != 64 || vout.is_empty() || (vout.len() > 1 && vout.starts_with('0')) {
        return Err("outpoint must be txid:vout".into());
    }
    Ok(OutPoint::new(
        Txid::from_str(txid).map_err(|_| "invalid txid")?,
        vout.parse().map_err(|_| "invalid vout")?,
    ))
}
pub fn fmt_outpoint(o: &OutPoint) -> String {
    format!("{}:{}", o.txid, o.vout)
}
pub fn parse_xonly(s: &str) -> Result<XOnlyPublicKey, String> {
    if s.len() != 64 {
        return Err("x-only key must be 64 hex chars".into());
    }
    XOnlyPublicKey::from_slice(&hex::decode(s).map_err(|_| "invalid key hex")?)
        .map_err(|_| "invalid x-only key".into())
}
pub fn parse_sig(s: &str) -> Result<[u8; 64], String> {
    let v = hex::decode(s).map_err(|_| "invalid signature hex")?;
    v.try_into()
        .map_err(|_| "signature must be 64 bytes".into())
}
pub fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|_| "invalid hex")?;
    v.try_into().map_err(|_| "expected 32 bytes".into())
}
/// Canonical decimal u64 (no sign, no leading zeros, no whitespace).
pub fn parse_amount(s: &str) -> Result<u64, String> {
    if s.is_empty()
        || s.len() > 20
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err("amount must be a canonical decimal string".into());
    }
    s.parse().map_err(|_| "amount out of range".into())
}

// ---------- announcement ----------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondJson {
    pub outpoint: String,
    pub refund_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnouncementJson {
    pub genesis: String,
    pub fee_asset: String,
    pub operator: String,
    pub sequence: String,
    pub bonds: Vec<BondJson>,
    pub api_url: String,
}

/// `{announcement, signature}` as posted to relays and the DEX server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAnnouncement {
    pub announcement: AnnouncementJson,
    pub signature: String,
}

impl SignedAnnouncement {
    pub fn new(a: &Announcement, signature: &[u8; 64]) -> Self {
        Self {
            announcement: AnnouncementJson {
                genesis: a.genesis.to_string(),
                fee_asset: a.fee_asset.to_string(),
                operator: hex::encode(a.operator.serialize()),
                sequence: a.sequence.to_string(),
                bonds: a
                    .bonds
                    .iter()
                    .map(|b| BondJson {
                        outpoint: fmt_outpoint(&b.outpoint),
                        refund_height: b.refund_height,
                    })
                    .collect(),
                api_url: a.api_url.clone(),
            },
            signature: hex::encode(signature),
        }
    }

    /// Parse and verify the signature (NOT the bonds: that needs chain data).
    pub fn verify(&self) -> Result<Announcement, String> {
        let j = &self.announcement;
        let a = Announcement {
            genesis: BlockHash::from_str(&j.genesis).map_err(|_| "invalid genesis")?,
            fee_asset: AssetId::from_str(&j.fee_asset).map_err(|_| "invalid fee asset")?,
            operator: parse_xonly(&j.operator)?,
            sequence: parse_amount(&j.sequence)?,
            bonds: j
                .bonds
                .iter()
                .map(|b| {
                    Ok(AnnouncedBond {
                        outpoint: parse_outpoint(&b.outpoint)?,
                        refund_height: b.refund_height,
                    })
                })
                .collect::<Result<_, String>>()?,
            api_url: j.api_url.clone(),
        };
        let unique: BTreeSet<_> = a.bonds.iter().map(|b| b.outpoint).collect();
        if unique.len() != a.bonds.len() {
            return Err("duplicate bond outpoint".into());
        }
        a.verify(&parse_sig(&self.signature)?)?;
        Ok(a)
    }
}

// ---------- receipt ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptPromise {
    /// Input index of the lockbox in the promised transaction.
    pub index: u32,
    pub lockbox: OutPoint,
    /// BIP340 by the operator over `hash::promise_digest(genesis, lockbox, commitment)`.
    pub signature: [u8; 64],
}

/// The operator's signed statement about one promised transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub genesis: BlockHash,
    pub operator: XOnlyPublicKey,
    /// Operator's append-only promise-log sequence (`GET /v1/promises?since=`).
    pub seq: u64,
    pub txid: Txid,
    pub commitment: [u8; 32],
    /// `false` for mixed transactions (a plain input): no instant guarantee.
    pub instant: bool,
    pub promises: Vec<ReceiptPromise>,
    /// Native-asset valuation counted against the operator's cover.
    pub value_at_risk: u64,
    /// Operator's unconfirmed promised value INCLUDING this transaction.
    pub in_flight: u64,
    /// Tip height the operator checked against.
    pub tip: u32,
    /// Bonds the operator counted as eligible cover.
    pub bonds: Vec<OutPoint>,
}

impl Receipt {
    /// `SHA256(SHA256(RECEIPT_TAG) || genesis[32] || operator[32] || seq[8] || txid[32]
    ///   || commitment[32] || instant[1] || n[1] || n x (index[4] || lockbox_txid[32]
    ///   || lockbox_vout[4] || sig[64]) || value_at_risk[8] || in_flight[8] || tip[4]
    ///   || n_bonds[1] || n_bonds x (txid[32] || vout[4]))`, integers big-endian,
    /// hashes in internal byte order.
    pub fn digest(&self) -> Result<[u8; 32], String> {
        if self.promises.is_empty() || self.promises.len() > MAX_RECEIPT_PROMISES {
            return Err("receipt needs 1..=16 promises".into());
        }
        if self.bonds.len() > MAX_RECEIPT_BONDS {
            return Err("receipt lists at most 16 bonds".into());
        }
        let unique: BTreeSet<_> = self.promises.iter().map(|p| p.lockbox).collect();
        if unique.len() != self.promises.len() {
            return Err("duplicate lockbox in receipt".into());
        }
        let mut e = sha256::Hash::engine();
        e.input(&hash::tag(RECEIPT_TAG));
        e.input(self.genesis.as_byte_array());
        e.input(&self.operator.serialize());
        e.input(&self.seq.to_be_bytes());
        e.input(self.txid.as_byte_array());
        e.input(&self.commitment);
        e.input(&[self.instant as u8]);
        e.input(&[self.promises.len() as u8]);
        for p in &self.promises {
            e.input(&p.index.to_be_bytes());
            e.input(p.lockbox.txid.as_byte_array());
            e.input(&p.lockbox.vout.to_be_bytes());
            e.input(&p.signature);
        }
        e.input(&self.value_at_risk.to_be_bytes());
        e.input(&self.in_flight.to_be_bytes());
        e.input(&self.tip.to_be_bytes());
        e.input(&[self.bonds.len() as u8]);
        for b in &self.bonds {
            e.input(b.txid.as_byte_array());
            e.input(&b.vout.to_be_bytes());
        }
        Ok(sha256::Hash::from_engine(e).to_byte_array())
    }

    /// Verify the receipt signature AND every embedded promise signature.
    pub fn verify(&self, signature: &[u8; 64]) -> Result<(), String> {
        if !verify_digest(self.digest()?, signature, &self.operator) {
            return Err("receipt signature invalid".into());
        }
        for p in &self.promises {
            let d = hash::promise_digest(self.genesis, p.lockbox, self.commitment);
            if !verify_digest(d, &p.signature, &self.operator) {
                return Err("promise signature invalid".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPromiseJson {
    pub index: u32,
    pub lockbox: String,
    pub sig: String,
}

/// Signed receipt as returned by `POST /v1/promise` and gossiped by relays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub genesis: String,
    pub operator: String,
    pub seq: String,
    pub txid: String,
    pub commitment: String,
    pub instant: bool,
    pub promises: Vec<ReceiptPromiseJson>,
    pub value_at_risk: String,
    pub in_flight: String,
    pub tip: u32,
    pub bonds: Vec<String>,
    pub signature: String,
}

impl SignedReceipt {
    pub fn new(r: &Receipt, signature: &[u8; 64]) -> Self {
        Self {
            genesis: r.genesis.to_string(),
            operator: hex::encode(r.operator.serialize()),
            seq: r.seq.to_string(),
            txid: r.txid.to_string(),
            commitment: hex::encode(r.commitment),
            instant: r.instant,
            promises: r
                .promises
                .iter()
                .map(|p| ReceiptPromiseJson {
                    index: p.index,
                    lockbox: fmt_outpoint(&p.lockbox),
                    sig: hex::encode(p.signature),
                })
                .collect(),
            value_at_risk: r.value_at_risk.to_string(),
            in_flight: r.in_flight.to_string(),
            tip: r.tip,
            bonds: r.bonds.iter().map(fmt_outpoint).collect(),
            signature: hex::encode(signature),
        }
    }

    pub fn parse(&self) -> Result<(Receipt, [u8; 64]), String> {
        let r = Receipt {
            genesis: BlockHash::from_str(&self.genesis).map_err(|_| "invalid genesis")?,
            operator: parse_xonly(&self.operator)?,
            seq: parse_amount(&self.seq)?,
            txid: Txid::from_str(&self.txid).map_err(|_| "invalid txid")?,
            commitment: parse_bytes32(&self.commitment)?,
            instant: self.instant,
            promises: self
                .promises
                .iter()
                .map(|p| {
                    Ok(ReceiptPromise {
                        index: p.index,
                        lockbox: parse_outpoint(&p.lockbox)?,
                        signature: parse_sig(&p.sig)?,
                    })
                })
                .collect::<Result<_, String>>()?,
            value_at_risk: parse_amount(&self.value_at_risk)?,
            in_flight: parse_amount(&self.in_flight)?,
            tip: self.tip,
            bonds: self
                .bonds
                .iter()
                .map(|b| parse_outpoint(b))
                .collect::<Result<_, String>>()?,
        };
        Ok((r, parse_sig(&self.signature)?))
    }

    /// Parse and fully verify (receipt + promise signatures). Callers must
    /// still check `genesis` and that `operator` is one they recognise.
    pub fn verify(&self) -> Result<Receipt, String> {
        let (r, sig) = self.parse()?;
        r.verify(&sig)?;
        Ok(r)
    }
}

/// Digest the operator signs for `GET /v1/status`:
/// `SHA256(SHA256(STATUS_TAG) || genesis[32] || operator[32] || tip[4] || tip_hash[32]
///   || in_flight[8] || cover[8] || unix_time[8])`.
pub fn status_digest(
    genesis: BlockHash,
    operator: &XOnlyPublicKey,
    tip: u32,
    tip_hash: BlockHash,
    in_flight: u64,
    cover: u64,
    unix_time: u64,
) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    e.input(&hash::tag(STATUS_TAG));
    e.input(genesis.as_byte_array());
    e.input(&operator.serialize());
    e.input(&tip.to_be_bytes());
    e.input(tip_hash.as_byte_array());
    e.input(&in_flight.to_be_bytes());
    e.input(&cover.to_be_bytes());
    e.input(&unix_time.to_be_bytes());
    sha256::Hash::from_engine(e).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey},
        sign_digest,
    };

    fn kp() -> Keypair {
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[9; 32]).unwrap())
    }

    fn receipt() -> Receipt {
        let genesis = BlockHash::from_byte_array([1; 32]);
        let lockbox = OutPoint::new(Txid::from_byte_array([3; 32]), 1);
        let commitment = [4; 32];
        Receipt {
            genesis,
            operator: kp().x_only_public_key().0,
            seq: 7,
            txid: Txid::from_byte_array([5; 32]),
            commitment,
            instant: true,
            promises: vec![ReceiptPromise {
                index: 0,
                lockbox,
                signature: sign_digest(hash::promise_digest(genesis, lockbox, commitment), &kp()),
            }],
            value_at_risk: 1_000,
            in_flight: 5_000,
            tip: 100,
            bonds: vec![OutPoint::new(Txid::from_byte_array([6; 32]), 0)],
        }
    }

    #[test]
    fn receipt_json_round_trip_and_tamper() {
        let r = receipt();
        let sig = sign_digest(r.digest().unwrap(), &kp());
        let j = SignedReceipt::new(&r, &sig);
        let text = serde_json::to_string(&j).unwrap();
        let back: SignedReceipt = serde_json::from_str(&text).unwrap();
        assert_eq!(back.verify().unwrap(), r);
        let mut bad = back.clone();
        bad.in_flight = "1".into();
        assert!(bad.verify().is_err());
        let mut bad = back.clone();
        bad.commitment = hex::encode([8u8; 32]);
        assert!(bad.verify().is_err(), "promise no longer matches");
        let mut bad = back;
        bad.seq = "07".into();
        assert!(bad.verify().is_err(), "non-canonical decimal");
    }

    #[test]
    fn announcement_json_round_trip() {
        let a = Announcement {
            genesis: BlockHash::from_byte_array([1; 32]),
            fee_asset: AssetId::from_byte_array([2; 32]),
            operator: kp().x_only_public_key().0,
            sequence: 3,
            bonds: vec![AnnouncedBond {
                outpoint: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
                refund_height: 5_000,
            }],
            api_url: "https://op.example".into(),
        };
        let sig = sign_digest(a.digest().unwrap(), &kp());
        let j = SignedAnnouncement::new(&a, &sig);
        assert_eq!(j.verify().unwrap(), a);
        let mut bad = j;
        bad.announcement.sequence = "4".into();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn outpoint_and_amount_parsing() {
        let o = OutPoint::new(Txid::from_byte_array([3; 32]), 12);
        assert_eq!(parse_outpoint(&fmt_outpoint(&o)).unwrap(), o);
        assert!(parse_outpoint("aa:1").is_err());
        assert!(parse_outpoint(&format!("{}:01", o.txid)).is_err());
        assert_eq!(parse_amount("0").unwrap(), 0);
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("18446744073709551616").is_err());
    }
}
