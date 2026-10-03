#![allow(dead_code)]
//! PUBLIC deterministic TEST KEYS ONLY. Never fund these on a real network.
use elementsplus_instant::{
    bond::{self, Bond, Promise},
    elements::{
        confidential,
        hashes::Hash,
        secp256k1_zkp::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
        AssetId, BlockHash, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxOut, Txid,
    },
    lockbox::{self, Lockbox},
    sign_digest,
    simplicity::jet::elements::{ElementsEnv, ElementsUtxo},
    Compiled,
};
use std::sync::{Arc, OnceLock};

pub const OWNER: u8 = 1;
pub const OPERATOR: u8 = 2;
pub const MAKER: u8 = 3;
pub const TAKER: u8 = 4;
pub const OTHER_OPERATOR: u8 = 5;
pub const EXPIRY: u32 = 1_000;
pub const REFUND: u32 = 1_200;
pub const BOND_AMOUNT: u64 = 100_000_000;

pub fn key(n: u8) -> Keypair {
    let mut secret = [0; 32];
    secret[31] = n;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap())
}
pub fn xonly(n: u8) -> XOnlyPublicKey {
    key(n).x_only_public_key().0
}
pub fn sign(digest: [u8; 32], n: u8) -> [u8; 64] {
    sign_digest(digest, &key(n))
}

pub fn genesis() -> BlockHash {
    BlockHash::from_byte_array([0x11; 32])
}
pub fn fee_asset() -> AssetId {
    AssetId::from_byte_array([0x22; 32])
}
pub fn token() -> AssetId {
    AssetId::from_byte_array([0x55; 32])
}

pub fn params(owner: u8, operator: u8) -> lockbox::Params {
    lockbox::Params {
        genesis: genesis(),
        owner: xonly(owner),
        operator: xonly(operator),
        expiry: EXPIRY,
    }
}

pub fn lockbox_of(owner: u8) -> &'static Lockbox {
    static L: [OnceLock<Lockbox>; 8] = [const { OnceLock::new() }; 8];
    L[owner as usize].get_or_init(|| params(owner, OPERATOR).compile().expect("lockbox compiles"))
}

pub fn bond_params() -> bond::Params {
    bond::Params {
        genesis: genesis(),
        fee_asset: fee_asset(),
        operator: xonly(OPERATOR),
        refund_height: REFUND,
    }
}
pub fn the_bond() -> &'static Bond {
    static B: OnceLock<Bond> = OnceLock::new();
    B.get_or_init(|| bond_params().compile().expect("bond compiles"))
}

pub fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([byte; 32]),
        vout,
    }
}
pub fn lockbox_outpoint() -> OutPoint {
    outpoint(0x44, 1)
}
pub fn bond_outpoint() -> OutPoint {
    outpoint(0x66, 0)
}

pub fn wpkh(tag: u8) -> Script {
    Script::from([vec![0x00, 0x14], vec![tag; 20]].concat())
}
pub fn pay(asset: AssetId, amount: u64, script: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(amount),
        nonce: confidential::Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    }
}
pub fn input(prev: OutPoint) -> TxIn {
    TxIn {
        previous_output: prev,
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        ..Default::default()
    }
}

/// Single-lockbox spend paying `recipient` (different recipients => conflicting txs).
pub fn spend(recipient: u8) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(lockbox_outpoint())],
        output: vec![
            pay(fee_asset(), 99_000, wpkh(recipient)),
            TxOut::new_fee(1_000, fee_asset()),
        ],
    }
}
pub fn lockbox_utxo() -> TxOut {
    lockbox_of(OWNER).funding_output(fee_asset(), 100_000)
}

pub fn env(
    c: &Compiled,
    tx: &Transaction,
    spent: &[TxOut],
    index: u32,
) -> ElementsEnv<Arc<Transaction>> {
    c.environment(
        tx.clone(),
        spent.iter().cloned().map(ElementsUtxo::from).collect(),
        index,
        genesis(),
    )
    .unwrap()
}

pub fn promise_for(
    lb: &Lockbox,
    at: OutPoint,
    tx: &Transaction,
    spent: &[TxOut],
    signer: u8,
) -> [u8; 64] {
    sign(lb.promise_digest(at, tx, spent).unwrap(), signer)
}

/// Operator promise as evidence material.
pub fn promise_record(tx: &Transaction, spent: &[TxOut]) -> Promise {
    let lb = lockbox_of(OWNER);
    Promise {
        commitment: elementsplus_instant::hash::tx_commitment(tx, spent).unwrap(),
        signature: promise_for(lb, lockbox_outpoint(), tx, spent, OPERATOR),
    }
}

/// Fully satisfied owner-ALL cooperative spend of the OWNER lockbox.
pub fn cooperative_witness(tx: &Transaction) -> Result<Vec<Vec<u8>>, String> {
    let lb = lockbox_of(OWNER);
    let spent = [lockbox_utxo()];
    let e = env(lb, tx, &spent, 0);
    let owner = sign(Compiled::sig_all_hash(&e), OWNER);
    let promise = promise_for(lb, lockbox_outpoint(), tx, &spent, OPERATOR);
    lb.satisfy(&e, &lockbox::cooperative_all(&owner, &promise))
}
