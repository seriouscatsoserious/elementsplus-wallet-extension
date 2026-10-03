//! Lockbox covenant (`contracts/lockbox.simf`).
use crate::{
    compile,
    elements::{
        confidential, hashes::Hash, secp256k1_zkp::XOnlyPublicKey, AssetId, BlockHash, OutPoint,
        Transaction, TxOut,
    },
    hash, signature_type, word, Action, Compiled,
};
use simplicityhl::{
    types::{ResolvedType, TypeConstructible},
    value::{UIntValue, ValueConstructible},
};

pub const CONTRACT: &str = include_str!("../contracts/lockbox.simf");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub genesis: BlockHash,
    pub owner: XOnlyPublicKey,
    pub operator: XOnlyPublicKey,
    /// Absolute sidechain height from which the owner alone may spend.
    pub expiry: u32,
}

impl Params {
    pub fn validate(&self) -> Result<(), String> {
        if self.owner == self.operator {
            return Err("owner and operator must differ".into());
        }
        if self.expiry == 0 || self.expiry >= 500_000_000 {
            return Err("expiry must be a block height in 1..500000000".into());
        }
        Ok(())
    }

    pub fn compile(&self) -> Result<Lockbox, String> {
        self.validate()?;
        let compiled = compile(
            CONTRACT,
            vec![
                ("PROMISE_DOMAIN", word(&hash::tag(hash::PROMISE_TAG))),
                ("PAIRED_DOMAIN", word(&hash::tag(hash::PAIRED_TAG))),
                ("GENESIS", word(self.genesis.as_byte_array())),
                ("OWNER", word(&self.owner.serialize())),
                ("OPERATOR", word(&self.operator.serialize())),
                ("EXPIRY", UIntValue::from(self.expiry).into()),
            ],
        )?;
        Ok(Lockbox {
            params: self.clone(),
            compiled,
        })
    }
}

pub struct Lockbox {
    params: Params,
    compiled: Compiled,
}

impl std::ops::Deref for Lockbox {
    type Target = Compiled;
    fn deref(&self) -> &Compiled {
        &self.compiled
    }
}

impl Lockbox {
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Explicit funding output. Lockboxes are explicit-only.
    pub fn funding_output(&self, asset: AssetId, amount: u64) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(amount),
            nonce: confidential::Nonce::Null,
            script_pubkey: self.script_pubkey().clone(),
            witness: Default::default(),
        }
    }

    pub fn promise_digest(
        &self,
        lockbox: OutPoint,
        tx: &Transaction,
        spent: &[TxOut],
    ) -> Result<[u8; 32], String> {
        Ok(hash::promise_digest(
            self.params.genesis,
            lockbox,
            hash::tx_commitment(tx, spent)?,
        ))
    }

    pub fn paired_digest(&self, lockbox: OutPoint, paired: &TxOut) -> Result<[u8; 32], String> {
        hash::paired_digest(self.params.genesis, lockbox, paired)
    }
}

fn auth_type() -> ResolvedType {
    ResolvedType::either(signature_type(), signature_type())
}
fn cooperative_type() -> ResolvedType {
    ResolvedType::tuple([auth_type(), signature_type()])
}

/// Owner signs the whole transaction (`sig_all_hash`) + operator promise.
pub fn cooperative_all(owner_sig: &[u8; 64], promise: &[u8; 64]) -> Action {
    Action::left(
        Action::tuple([
            Action::left(Action::byte_array(*owner_sig), signature_type()),
            Action::byte_array(*promise),
        ]),
        signature_type(),
    )
}

/// Owner's pre-signed paired authorization (maker order) + operator promise.
pub fn cooperative_paired(owner_sig: &[u8; 64], promise: &[u8; 64]) -> Action {
    Action::left(
        Action::tuple([
            Action::right(signature_type(), Action::byte_array(*owner_sig)),
            Action::byte_array(*promise),
        ]),
        signature_type(),
    )
}

/// Owner-only exit; valid once the transaction's height lock >= EXPIRY.
pub fn timeout_exit(owner_sig: &[u8; 64]) -> Action {
    Action::right(cooperative_type(), Action::byte_array(*owner_sig))
}
