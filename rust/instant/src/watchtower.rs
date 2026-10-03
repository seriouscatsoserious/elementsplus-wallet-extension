//! Watchtower helpers: turn an on-chain lockbox spend plus a held promise into
//! penalty evidence.
//!
//! Every cooperative lockbox spend carries the operator's promise inside its
//! Simplicity witness. Rather than depending on the witness-value layout, the
//! promise is located by scanning the witness bit string for a 512-bit window
//! that is a valid BIP340 signature by the operator over the promise digest
//! (which the watchtower recomputes from the confirmed transaction). This is
//! layout-independent and cannot produce a false positive (it is a signature
//! check), so evidence built this way always satisfies the bond covenant.
use crate::{
    bond::{Evidence, Promise},
    elements::{secp256k1_zkp::XOnlyPublicKey, BlockHash, OutPoint, Transaction, TxOut},
    hash, verify_digest,
};

fn bit_window(bytes: &[u8], bit: usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate() {
        let start = bit + i * 8;
        let (byte, shift) = (start / 8, start % 8);
        let hi = bytes[byte] << shift;
        let lo = if shift == 0 {
            0
        } else {
            bytes[byte + 1] >> (8 - shift)
        };
        *o = hi | lo;
    }
    out
}

/// Find a BIP340 signature by `key` over `digest` anywhere in `witness`
/// (Simplicity witness bytes, i.e. stack element 0).
pub fn find_signature(witness: &[u8], digest: [u8; 32], key: &XOnlyPublicKey) -> Option<[u8; 64]> {
    let bits = witness.len() * 8;
    if bits < 512 {
        return None;
    }
    // The last window must leave one spare byte for the shifted read.
    (0..=bits - 512)
        .filter(|bit| bit % 8 == 0 || bit / 8 + 64 < witness.len())
        .map(|bit| bit_window(witness, bit))
        .find(|candidate| verify_digest(digest, candidate, key))
}

/// Extract the operator's promise from the confirmed transaction `tx` that
/// spent `lockbox` (`spent` = UTXOs of every input of `tx`, in order).
pub fn promise_from_chain(
    genesis: BlockHash,
    operator: &XOnlyPublicKey,
    lockbox: OutPoint,
    tx: &Transaction,
    spent: &[TxOut],
) -> Result<Promise, String> {
    let input = tx
        .input
        .iter()
        .find(|i| i.previous_output == lockbox)
        .ok_or("transaction does not spend the lockbox")?;
    let commitment = hash::tx_commitment(tx, spent)?;
    let digest = hash::promise_digest(genesis, lockbox, commitment);
    let witness = input
        .witness
        .script_witness
        .first()
        .ok_or("lockbox input has no Simplicity witness")?;
    let signature = find_signature(witness, digest, operator)
        .ok_or("no operator promise in the witness (timeout exit or foreign script)")?;
    Ok(Promise {
        commitment,
        signature,
    })
}

/// Combine a held promise with the conflicting on-chain one.
pub fn evidence(lockbox: OutPoint, held: Promise, on_chain: Promise) -> Result<Evidence, String> {
    if held.commitment == on_chain.commitment {
        return Err("held promise is for the transaction that confirmed: no equivocation".into());
    }
    Ok(Evidence {
        lockbox,
        first: held,
        second: on_chain,
    })
}
