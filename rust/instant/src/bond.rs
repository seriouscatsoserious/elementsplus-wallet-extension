//! Pooled operator bond covenant (`contracts/pooled_bond.simf`).
use crate::{
    compile, elements,
    elements::{
        confidential, hashes::Hash, secp256k1_zkp::XOnlyPublicKey, AssetId, BlockHash, LockTime,
        OutPoint, Script, Sequence, Transaction, TxIn, TxOut,
    },
    hash, signature_type, verify_digest, word, Action, Compiled,
};
use simplicityhl::{
    types::{ResolvedType, TypeConstructible},
    value::{UIntValue, ValueConstructible},
};

pub const CONTRACT: &str = include_str!("../contracts/pooled_bond.simf");
/// Reporter share = floor(bond >> REWARD_SHIFT) = 12.5%. Fixed in the contract.
pub const REWARD_SHIFT: u32 = 3;
/// Smallest bond the reference policy accepts (so the reward is non-zero and
/// the penalty transaction is meaningful). 0.01 native units.
pub const MIN_BOND: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub genesis: BlockHash,
    /// Native fee asset (ECX). Must be independently authenticated.
    pub fee_asset: AssetId,
    pub operator: XOnlyPublicKey,
    pub refund_height: u32,
}

impl Params {
    pub fn compile(&self) -> Result<Bond, String> {
        if self.refund_height == 0 || self.refund_height >= 500_000_000 {
            return Err("refund height must be a block height in 1..500000000".into());
        }
        let compiled = compile(
            CONTRACT,
            vec![
                ("PROMISE_DOMAIN", word(&hash::tag(hash::PROMISE_TAG))),
                ("GENESIS", word(self.genesis.as_byte_array())),
                (
                    "FEE_ASSET",
                    word(&self.fee_asset.into_inner().to_byte_array()),
                ),
                ("OPERATOR", word(&self.operator.serialize())),
                ("REFUND_HEIGHT", UIntValue::from(self.refund_height).into()),
                ("BURN_SCRIPT_HASH", word(&burn_script_hash())),
            ],
        )?;
        Ok(Bond {
            params: self.clone(),
            compiled,
        })
    }
}

pub struct Bond {
    params: Params,
    compiled: Compiled,
}

impl std::ops::Deref for Bond {
    type Target = Compiled;
    fn deref(&self) -> &Compiled {
        &self.compiled
    }
}

/// One operator promise as carried in evidence: (tx commitment, signature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Promise {
    pub commitment: [u8; 32],
    pub signature: [u8; 64],
}

/// Equivocation evidence: two promises for the same lockbox outpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub lockbox: OutPoint,
    pub first: Promise,
    pub second: Promise,
}

pub fn reward(bond: u64) -> u64 {
    bond >> REWARD_SHIFT
}

/// The only accepted burn script: bare `OP_RETURN`.
pub fn burn_script() -> Script {
    Script::from(vec![0x6a])
}
pub fn burn_script_hash() -> [u8; 32] {
    elements::hashes::sha256::Hash::hash(burn_script().as_bytes()).to_byte_array()
}

impl Bond {
    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn funding_output(&self, amount: u64) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(self.params.fee_asset),
            value: confidential::Value::Explicit(amount),
            nonce: confidential::Nonce::Null,
            script_pubkey: self.script_pubkey().clone(),
            witness: Default::default(),
        }
    }

    /// Off-chain check of evidence (what the covenant enforces). Watchtowers
    /// run this before spending fees on a penalty transaction.
    pub fn check_evidence(&self, e: &Evidence) -> Result<(), String> {
        if e.first.commitment == e.second.commitment {
            return Err("same transaction commitment: not equivocation".into());
        }
        for p in [&e.first, &e.second] {
            let digest = hash::promise_digest(self.params.genesis, e.lockbox, p.commitment);
            if !verify_digest(digest, &p.signature, &self.params.operator) {
                return Err("promise signature invalid for this operator".into());
            }
        }
        Ok(())
    }

    /// Penalty: bond -> [reporter (bond>>3 - fee), OP_RETURN burn (rest), fee].
    pub fn penalty_transaction(
        &self,
        bond_outpoint: OutPoint,
        bond_amount: u64,
        reporter: Script,
        fee: u64,
    ) -> Result<Transaction, String> {
        let reward = reward(bond_amount);
        if fee > reward {
            return Err("fee exceeds the reporter reward".into());
        }
        Ok(Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bond_outpoint,
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            }],
            output: vec![
                self.explicit(reward - fee, reporter),
                self.explicit(bond_amount - reward, burn_script()),
                TxOut::new_fee(fee, self.params.fee_asset),
            ],
        })
    }

    fn explicit(&self, amount: u64, script_pubkey: Script) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(self.params.fee_asset),
            value: confidential::Value::Explicit(amount),
            nonce: confidential::Nonce::Null,
            script_pubkey,
            witness: Default::default(),
        }
    }
}

fn promise_value(p: &Promise) -> Action {
    Action::tuple([word(&p.commitment), Action::byte_array(p.signature)])
}

fn evidence_type() -> ResolvedType {
    let promise = ResolvedType::tuple([ResolvedType::u256(), signature_type()]);
    let outpoint = ResolvedType::tuple([ResolvedType::u256(), ResolvedType::u32()]);
    ResolvedType::tuple([outpoint, promise.clone(), promise])
}

pub fn penalty_action(e: &Evidence) -> Action {
    Action::left(
        Action::tuple([
            Action::tuple([
                word(e.lockbox.txid.as_byte_array()),
                UIntValue::from(e.lockbox.vout).into(),
            ]),
            promise_value(&e.first),
            promise_value(&e.second),
        ]),
        signature_type(),
    )
}

pub fn refund_action(operator_sig: &[u8; 64]) -> Action {
    Action::right(evidence_type(), Action::byte_array(*operator_sig))
}
