//! Operator announcement (SPEC.md §5.2): a self-certifying, signed record an
//! operator posts to any relay / DEX. Nothing in it is trusted until the
//! wallet re-derives each bond script from the announced parameters and finds
//! a matching confirmed, unspent, explicit output on chain (e.g. via Esplora).
use crate::{
    bond,
    elements::{
        hashes::{sha256, Hash, HashEngine},
        secp256k1_zkp::XOnlyPublicKey,
        AssetId, BlockHash, OutPoint, Script,
    },
    hash, verify_digest,
};

pub const MAX_URL: usize = 256;
pub const MAX_BONDS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnouncedBond {
    pub outpoint: OutPoint,
    pub refund_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub genesis: BlockHash,
    pub fee_asset: AssetId,
    pub operator: XOnlyPublicKey,
    /// Monotonic; wallets keep the highest valid sequence per operator.
    pub sequence: u64,
    pub bonds: Vec<AnnouncedBond>,
    /// HTTPS promise API base URL.
    pub api_url: String,
}

impl Announcement {
    /// `SHA256(SHA256(ANNOUNCE_TAG) || genesis[32] || fee_asset[32] || operator[32]
    ///   || sequence[8 BE] || n_bonds[1] || n x (txid[32] || vout[4 BE] || refund_height[4 BE])
    ///   || url_len[2 BE] || url[utf8])`
    pub fn digest(&self) -> Result<[u8; 32], String> {
        if self.bonds.is_empty() || self.bonds.len() > MAX_BONDS {
            return Err("1..=16 bonds".into());
        }
        if self.api_url.is_empty()
            || self.api_url.len() > MAX_URL
            || !self.api_url.starts_with("https://")
        {
            return Err("api_url must be https and at most 256 bytes".into());
        }
        let mut e = sha256::Hash::engine();
        e.input(&hash::tag(hash::ANNOUNCE_TAG));
        e.input(self.genesis.as_byte_array());
        e.input(&self.fee_asset.into_inner().to_byte_array());
        e.input(&self.operator.serialize());
        e.input(&self.sequence.to_be_bytes());
        e.input(&[self.bonds.len() as u8]);
        for b in &self.bonds {
            e.input(b.outpoint.txid.as_byte_array());
            e.input(&b.outpoint.vout.to_be_bytes());
            e.input(&b.refund_height.to_be_bytes());
        }
        e.input(&(self.api_url.len() as u16).to_be_bytes());
        e.input(self.api_url.as_bytes());
        Ok(sha256::Hash::from_engine(e).to_byte_array())
    }

    pub fn verify(&self, signature: &[u8; 64]) -> Result<(), String> {
        if !verify_digest(self.digest()?, signature, &self.operator) {
            return Err("announcement signature invalid".into());
        }
        Ok(())
    }

    /// The scriptPubKey each announced bond output MUST have on chain.
    pub fn expected_bond_script(&self, b: &AnnouncedBond) -> Result<Script, String> {
        Ok(bond::Params {
            genesis: self.genesis,
            fee_asset: self.fee_asset,
            operator: self.operator,
            refund_height: b.refund_height,
        }
        .compile()?
        .script_pubkey()
        .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        elements::{
            secp256k1_zkp::{Keypair, Secp256k1, SecretKey},
            Txid,
        },
        sign_digest,
    };

    #[test]
    fn signed_announcement_round_trip_and_bond_script() {
        let kp =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
        let mut a = Announcement {
            genesis: BlockHash::from_byte_array([1; 32]),
            fee_asset: AssetId::from_byte_array([2; 32]),
            operator: kp.x_only_public_key().0,
            sequence: 1,
            bonds: vec![AnnouncedBond {
                outpoint: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
                refund_height: 5_000,
            }],
            api_url: "https://op.example/instant".into(),
        };
        let sig = sign_digest(a.digest().unwrap(), &kp);
        a.verify(&sig).unwrap();
        let script = a.expected_bond_script(&a.bonds[0]).unwrap();
        assert!(script.is_v1_p2tr());
        a.api_url = "https://evil.example".into();
        assert!(a.verify(&sig).is_err());
        a.api_url = "http://op.example".into();
        assert!(a.digest().is_err());
    }
}
