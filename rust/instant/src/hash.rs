//! Byte-exact host implementations of the digests the covenants compute with
//! Simplicity jets. Every value here is cross-checked by executing the real
//! compiled programs in `tests/` (a wrong byte makes a BIP340 check fail).
//!
//! Hash bytes are internal/consensus order (NOT reversed RPC display order).
//! Integers are big-endian, matching the `sha_256_ctx_8_add_4` jet.

use crate::elements::{
    confidential,
    encode::serialize,
    hashes::{sha256, Hash, HashEngine},
    BlockHash, OutPoint, Transaction, TxOut,
};

pub const PROMISE_TAG: &[u8] = b"ECX/Instant/Promise/v1";
pub const PAIRED_TAG: &[u8] = b"ECX/Instant/PairedAuth/v1";
pub const ANNOUNCE_TAG: &[u8] = b"ECX/Instant/Announce/v1";

pub fn tag(tag: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(tag).to_byte_array()
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(bytes).to_byte_array()
}

struct Engine(sha256::HashEngine);
impl Engine {
    fn new() -> Self {
        Self(sha256::Hash::engine())
    }
    fn add(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.input(bytes);
        self
    }
    fn finish(self) -> [u8; 32] {
        sha256::Hash::from_engine(self.0).to_byte_array()
    }
}

/// `simplicity_sha256_confAsset` / `confNonce`: the consensus serialization
/// (prefix byte + 32 bytes, or a single 0x00 for null) is exactly what the C
/// jets hash.
fn conf_asset(e: &mut Engine, asset: &confidential::Asset) {
    e.add(&serialize(asset));
}
fn conf_nonce(e: &mut Engine, nonce: &confidential::Nonce) {
    e.add(&serialize(nonce));
}
/// `simplicity_sha256_confAmt`: explicit = 0x01 || u64 BE (== serialization);
/// confidential = 0x08/0x09 || x (== serialization). Null is invalid.
fn conf_amount(e: &mut Engine, value: &confidential::Value) -> Result<(), String> {
    if matches!(value, confidential::Value::Null) {
        return Err("null amount".into());
    }
    e.add(&serialize(value));
    Ok(())
}

/// Explicit-only: confidential amounts/assets (and therefore range and
/// surjection proofs) are rejected, so their proof hashes are SHA256("").
fn explicit_only(asset: &confidential::Asset, value: &confidential::Value) -> Result<(), String> {
    if asset.is_confidential() || value.is_confidential() {
        return Err("confidential amounts/assets are outside the Instant protocol".into());
    }
    Ok(())
}

/// Equivalent of the `output_hash(i)` jet.
pub fn output_hash(out: &TxOut) -> Result<[u8; 32], String> {
    explicit_only(&out.asset, &out.value)?;
    let mut e = Engine::new();
    conf_asset(&mut e, &out.asset);
    conf_amount(&mut e, &out.value)?;
    conf_nonce(&mut e, &out.nonce);
    e.add(&sha(out.script_pubkey.as_bytes()));
    e.add(&sha(&[]));
    Ok(e.finish())
}

/// Equivalent of `SHA256(jet::tx_hash() || jet::input_script_sigs_hash())`
/// for the transaction shapes this protocol permits: no peg-ins, no
/// issuances, no Taproot annexes (all are rejected rather than modelled).
/// `spent` lists the UTXO spent by each input, in input order.
pub fn tx_commitment(tx: &Transaction, spent: &[TxOut]) -> Result<[u8; 32], String> {
    if tx.input.is_empty() || spent.len() != tx.input.len() {
        return Err("one spent UTXO per input is required".into());
    }
    let (mut outpoints, mut asset_amounts, mut scripts) =
        (Engine::new(), Engine::new(), Engine::new());
    let (mut sequences, mut annexes, mut script_sigs) =
        (Engine::new(), Engine::new(), Engine::new());
    let (mut iss_assets, mut iss_tokens, mut iss_proofs, mut iss_entropy) =
        (Engine::new(), Engine::new(), Engine::new(), Engine::new());
    for (input, utxo) in tx.input.iter().zip(spent) {
        if input.is_pegin || input.has_issuance() {
            return Err("peg-in and issuance inputs are outside the Instant protocol".into());
        }
        let stack = &input.witness.script_witness;
        if utxo.script_pubkey.is_v1_p2tr()
            && stack.len() >= 2
            && stack.last().and_then(|a| a.first()) == Some(&0x50)
        {
            return Err("Taproot annexes are outside the Instant protocol".into());
        }
        explicit_only(&utxo.asset, &utxo.value)?;
        outpoints
            .add(&[0])
            .add(input.previous_output.txid.as_byte_array())
            .add(&input.previous_output.vout.to_be_bytes());
        conf_asset(&mut asset_amounts, &utxo.asset);
        conf_amount(&mut asset_amounts, &utxo.value)?;
        scripts.add(&sha(utxo.script_pubkey.as_bytes()));
        sequences.add(&input.sequence.to_consensus_u32().to_be_bytes());
        annexes.add(&[0]);
        script_sigs.add(&sha(input.script_sig.as_bytes()));
        iss_assets.add(&[0, 0]);
        iss_tokens.add(&[0, 0]);
        iss_proofs.add(&sha(&[])).add(&sha(&[]));
        iss_entropy.add(&[0]);
    }
    let (outpoints, asset_amounts, scripts) =
        (outpoints.finish(), asset_amounts.finish(), scripts.finish());
    let (sequences, annexes, script_sigs) =
        (sequences.finish(), annexes.finish(), script_sigs.finish());
    let mut utxos = Engine::new();
    utxos.add(&asset_amounts).add(&scripts);
    let utxos = utxos.finish();
    let mut inputs = Engine::new();
    inputs.add(&outpoints).add(&sequences).add(&annexes);
    let inputs = inputs.finish();
    let mut issuances = Engine::new();
    issuances
        .add(&iss_assets.finish())
        .add(&iss_tokens.finish())
        .add(&iss_proofs.finish())
        .add(&iss_entropy.finish());
    let issuances = issuances.finish();

    let (mut o_amounts, mut o_nonces, mut o_scripts) =
        (Engine::new(), Engine::new(), Engine::new());
    let (mut o_ranges, mut o_surjections) = (Engine::new(), Engine::new());
    for out in &tx.output {
        explicit_only(&out.asset, &out.value)?;
        conf_asset(&mut o_amounts, &out.asset);
        conf_amount(&mut o_amounts, &out.value)?;
        conf_nonce(&mut o_nonces, &out.nonce);
        o_scripts.add(&sha(out.script_pubkey.as_bytes()));
        o_ranges.add(&sha(&[]));
        o_surjections.add(&sha(&[]));
    }
    let mut outputs = Engine::new();
    outputs
        .add(&o_amounts.finish())
        .add(&o_nonces.finish())
        .add(&o_scripts.finish())
        .add(&o_ranges.finish());
    let outputs = outputs.finish();

    let mut tx_hash = Engine::new();
    tx_hash
        .add(&tx.version.to_be_bytes())
        .add(&tx.lock_time.to_consensus_u32().to_be_bytes())
        .add(&inputs)
        .add(&outputs)
        .add(&issuances)
        .add(&o_surjections.finish())
        .add(&utxos);
    let tx_hash = tx_hash.finish();

    let mut commitment = Engine::new();
    commitment.add(&tx_hash).add(&script_sigs);
    Ok(commitment.finish())
}

/// Message the operator signs (BIP340) to promise that `lockbox` is spent by
/// the transaction with `commitment` = [`tx_commitment`]. Verified on-chain by
/// both the lockbox (cooperative spend) and the pooled bond (penalty).
///
/// `SHA256(SHA256(PROMISE_TAG) || genesis[32] || lockbox_txid[32] || lockbox_vout[4 BE] || commitment[32])`
pub fn promise_digest(genesis: BlockHash, lockbox: OutPoint, commitment: [u8; 32]) -> [u8; 32] {
    let mut e = Engine::new();
    e.add(&tag(PROMISE_TAG))
        .add(genesis.as_byte_array())
        .add(lockbox.txid.as_byte_array())
        .add(&lockbox.vout.to_be_bytes())
        .add(&commitment);
    e.finish()
}

/// Message an offline maker signs over its own lockbox input and the output
/// at the same index (SIGHASH_SINGLE|ANYONECANPAY analogue).
///
/// `SHA256(SHA256(PAIRED_TAG) || genesis[32] || lockbox_txid[32] || lockbox_vout[4 BE] || output_hash(paired)[32])`
pub fn paired_digest(
    genesis: BlockHash,
    lockbox: OutPoint,
    paired: &TxOut,
) -> Result<[u8; 32], String> {
    let mut e = Engine::new();
    e.add(&tag(PAIRED_TAG))
        .add(genesis.as_byte_array())
        .add(lockbox.txid.as_byte_array())
        .add(&lockbox.vout.to_be_bytes())
        .add(&output_hash(paired)?);
    Ok(e.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements::{AssetId, LockTime, Script, Sequence, TxIn, Txid};

    fn out(v: u64) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(AssetId::from_byte_array([2; 32])),
            value: confidential::Value::Explicit(v),
            nonce: confidential::Nonce::Null,
            script_pubkey: Script::from(vec![0x51]),
            witness: Default::default(),
        }
    }
    fn tx() -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            }],
            output: vec![out(5)],
        }
    }

    #[test]
    fn commitment_covers_script_sig_and_ignores_witness() {
        let base = tx_commitment(&tx(), &[out(6)]).unwrap();
        let mut sig = tx();
        sig.input[0].script_sig = Script::from(vec![0x00]);
        assert_ne!(tx_commitment(&sig, &[out(6)]).unwrap(), base);
        let mut wit = tx();
        wit.input[0].witness.script_witness = vec![vec![1, 2, 3]];
        assert_eq!(tx_commitment(&wit, &[out(6)]).unwrap(), base);
        // Spent UTXO data is committed too.
        assert_ne!(tx_commitment(&tx(), &[out(7)]).unwrap(), base);
    }

    #[test]
    fn out_of_scope_shapes_are_rejected() {
        let mut conf = out(6);
        conf.value = confidential::Value::from_commitment(&[8; 33]).unwrap();
        assert!(tx_commitment(&tx(), &[conf]).is_err());
        let mut pegin = tx();
        pegin.input[0].is_pegin = true;
        assert!(tx_commitment(&pegin, &[out(6)]).is_err());
        assert!(tx_commitment(&tx(), &[]).is_err());
    }

    #[test]
    fn domains_are_distinct() {
        assert_ne!(tag(PROMISE_TAG), tag(PAIRED_TAG));
        assert_ne!(tag(PROMISE_TAG), tag(ANNOUNCE_TAG));
    }
}
