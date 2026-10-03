//! Fixtures for the pinned Elements+ C interpreter (scripts/check-fork.mjs).
//! PUBLIC TEST KEYS, synthetic genesis/assets. No RPC, no real funds.
//!
//! Negative fixtures are built so that ONLY the property under test is wrong:
//! the program is the pruned program of a valid spend of the same branch, and
//! signatures inside the witness bit string are re-signed for the mutated
//! transaction (bit-level replacement), so e.g. a premature exit carries a
//! correct owner signature and fails only on the height lock.
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use elementsplus_instant::{
    bond::{penalty_action, refund_action, Evidence},
    elements::{encode, hashes::Hash, LockTime, Sequence, Transaction, TxOut},
    lockbox, Compiled,
};
use serde_json::{json, Value};

fn get_bit(b: &[u8], i: usize) -> bool {
    b[i / 8] >> (7 - i % 8) & 1 == 1
}
fn set_bit(b: &mut [u8], i: usize, v: bool) {
    let mask = 1 << (7 - i % 8);
    if v {
        b[i / 8] |= mask
    } else {
        b[i / 8] &= !mask
    }
}
/// Replace the unique bit-level occurrence of `old` with `new` (same length).
fn replace_bits(witness: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    assert_eq!(old.len(), new.len());
    let n = old.len() * 8;
    let total = witness.len() * 8;
    let hits: Vec<usize> = (0..=total - n)
        .filter(|&s| (0..n).all(|i| get_bit(witness, s + i) == get_bit(old, i)))
        .collect();
    assert_eq!(hits.len(), 1, "pattern must occur exactly once");
    let mut out = witness.to_vec();
    for i in 0..n {
        set_bit(&mut out, hits[0] + i, get_bit(new, i));
    }
    out
}

fn fixture(
    name: &str,
    pass: bool,
    tx: &Transaction,
    spent: &[TxOut],
    index: u32,
    stack: &[Vec<u8>],
) -> Value {
    json!({
        "name": name, "pass": pass, "index": index,
        "genesis": hex::encode(genesis().as_byte_array()),
        "witness": hex::encode(&stack[0]), "program": hex::encode(&stack[1]),
        "cmr": hex::encode(&stack[2]), "control": hex::encode(&stack[3]),
        "txid": hex::encode(tx.txid().as_byte_array()),
        "version": tx.version, "lock_time": tx.lock_time.to_consensus_u32(),
        "inputs": tx.input.iter().zip(spent).map(|(i, u)| json!({
            "txid": hex::encode(i.previous_output.txid.as_byte_array()),
            "vout": i.previous_output.vout,
            "sequence": i.sequence.to_consensus_u32(),
            "asset": hex::encode(encode::serialize(&u.asset)),
            "value": hex::encode(encode::serialize(&u.value)),
            "script": hex::encode(u.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>(),
        "outputs": tx.output.iter().map(|o| json!({
            "asset": hex::encode(encode::serialize(&o.asset)),
            "value": hex::encode(encode::serialize(&o.value)),
            "script": hex::encode(o.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>(),
    })
}

fn with_witness(stack: &[Vec<u8>], witness: Vec<u8>) -> Vec<Vec<u8>> {
    let mut s = stack.to_vec();
    s[0] = witness;
    s
}

fn main() {
    let mut out = vec![];
    let lb = lockbox_of(OWNER);
    let spent = [lockbox_utxo()];

    // Cooperative spend.
    let tx = spend(8);
    let stack = cooperative_witness(&tx).unwrap();
    out.push(fixture(
        "lockbox cooperative (owner ALL + promise)",
        true,
        &tx,
        &spent,
        0,
        &stack,
    ));
    let good_promise = promise_for(lb, lockbox_outpoint(), &tx, &spent, OPERATOR);
    let other_promise = promise_for(lb, lockbox_outpoint(), &spend(9), &spent, OPERATOR);
    out.push(fixture(
        "lockbox: promise for a different tx",
        false,
        &tx,
        &spent,
        0,
        &with_witness(
            &stack,
            replace_bits(&stack[0], &good_promise, &other_promise),
        ),
    ));
    out.push(fixture(
        "lockbox: no promise (zero signature)",
        false,
        &tx,
        &spent,
        0,
        &with_witness(&stack, replace_bits(&stack[0], &good_promise, &[0; 64])),
    ));
    let owner_sig_on_promise = sign(
        lb.promise_digest(lockbox_outpoint(), &tx, &spent).unwrap(),
        OWNER,
    );
    out.push(fixture(
        "lockbox: promise signed by owner, not operator",
        false,
        &tx,
        &spent,
        0,
        &with_witness(
            &stack,
            replace_bits(&stack[0], &good_promise, &owner_sig_on_promise),
        ),
    ));
    let mut moved = tx.clone();
    moved.input[0].previous_output = outpoint(0x45, 1);
    out.push(fixture(
        "lockbox: witness replayed on another lockbox outpoint",
        false,
        &moved,
        &spent,
        0,
        &stack,
    ));

    // Timeout exit.
    let mut exit = spend(9);
    exit.lock_time = LockTime::from_height(EXPIRY).unwrap();
    let e = env(lb, &exit, &spent, 0);
    let sig = sign(Compiled::sig_all_hash(&e), OWNER);
    let exit_stack = lb.satisfy(&e, &lockbox::timeout_exit(&sig)).unwrap();
    out.push(fixture(
        "lockbox timeout exit at EXPIRY",
        true,
        &exit,
        &spent,
        0,
        &exit_stack,
    ));
    for (name, mutate) in [
        (
            "lockbox: premature exit (EXPIRY-1, correctly signed)",
            Box::new(|t: &mut Transaction| t.lock_time = LockTime::from_height(EXPIRY - 1).unwrap())
                as Box<dyn Fn(&mut Transaction)>,
        ),
        (
            "lockbox: exit with disabled lock time (correctly signed)",
            Box::new(|t: &mut Transaction| t.input[0].sequence = Sequence::MAX),
        ),
    ] {
        let mut t = exit.clone();
        mutate(&mut t);
        let resig = sign(Compiled::sig_all_hash(&env(lb, &t, &spent, 0)), OWNER);
        out.push(fixture(
            name,
            false,
            &t,
            &spent,
            0,
            &with_witness(&exit_stack, replace_bits(&exit_stack[0], &sig, &resig)),
        ));
    }

    // Two-lockbox DEX swap: maker PAIRED order at input 0, taker ALL at input 1.
    let maker_op = outpoint(0x71, 0);
    let taker_op = outpoint(0x72, 2);
    let swap = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(maker_op), input(taker_op)],
        output: vec![
            pay(fee_asset(), 40_000, wpkh(0x33)),
            pay(token(), 500, wpkh(0x44)),
            pay(fee_asset(), 59_000, wpkh(0x45)),
            TxOut::new_fee(1_000, fee_asset()),
        ],
    };
    let (maker, taker) = (lockbox_of(MAKER), lockbox_of(TAKER));
    let sspent = vec![
        maker.funding_output(token(), 500),
        taker.funding_output(fee_asset(), 100_000),
    ];
    let order = sign(
        maker.paired_digest(maker_op, &swap.output[0]).unwrap(),
        MAKER,
    );
    let p0 = promise_for(maker, maker_op, &swap, &sspent, OPERATOR);
    let s0 = maker
        .satisfy(
            &env(maker, &swap, &sspent, 0),
            &lockbox::cooperative_paired(&order, &p0),
        )
        .unwrap();
    out.push(fixture(
        "swap: maker lockbox, PAIRED order + promise (input 0)",
        true,
        &swap,
        &sspent,
        0,
        &s0,
    ));
    let e1 = env(taker, &swap, &sspent, 1);
    let p1 = promise_for(taker, taker_op, &swap, &sspent, OPERATOR);
    let s1 = taker
        .satisfy(
            &e1,
            &lockbox::cooperative_all(&sign(Compiled::sig_all_hash(&e1), TAKER), &p1),
        )
        .unwrap();
    out.push(fixture(
        "swap: taker lockbox, ALL + promise (input 1)",
        true,
        &swap,
        &sspent,
        1,
        &s1,
    ));
    let mut cheat = swap.clone();
    cheat.output[0] = pay(fee_asset(), 1, wpkh(0x33));
    let p0c = promise_for(maker, maker_op, &cheat, &sspent, OPERATOR);
    out.push(fixture(
        "swap: maker paid less than the signed order (operator re-promised)",
        false,
        &cheat,
        &sspent,
        0,
        &with_witness(&s0, replace_bits(&s0[0], &p0, &p0c)),
    ));

    // Pooled bond penalty.
    let b = the_bond();
    let bspent = [b.funding_output(BOND_AMOUNT)];
    let e = Evidence {
        lockbox: lockbox_outpoint(),
        first: promise_record(&spend(9), &spent),
        second: promise_record(&spend(8), &spent),
    };
    let ptx = b
        .penalty_transaction(bond_outpoint(), BOND_AMOUNT, wpkh(0xaa), 2_000)
        .unwrap();
    let pstack = b
        .satisfy(&env(b, &ptx, &bspent, 0), &penalty_action(&e))
        .unwrap();
    out.push(fixture(
        "bond penalty: 1/8 reporter (incl. fee), 7/8 OP_RETURN burn",
        true,
        &ptx,
        &bspent,
        0,
        &pstack,
    ));
    let reward = BOND_AMOUNT / 8;
    let burn = BOND_AMOUNT - reward;
    let burn_out = |v| pay(fee_asset(), v, elementsplus_instant::bond::burn_script());
    for (name, outputs) in [
        (
            "bond penalty: partial burn, reporter takes 1 more",
            vec![
                pay(fee_asset(), reward - 2_000 + 1, wpkh(0xaa)),
                burn_out(burn - 1),
                TxOut::new_fee(2_000, fee_asset()),
            ],
        ),
        (
            "bond penalty: burn paid as fee instead of OP_RETURN",
            vec![
                pay(fee_asset(), reward - 2_000, wpkh(0xaa)),
                TxOut::new_fee(burn, fee_asset()),
                TxOut::new_fee(2_000, fee_asset()),
            ],
        ),
        (
            "bond penalty: burn diverted to a script",
            vec![
                pay(fee_asset(), reward - 2_000, wpkh(0xaa)),
                pay(fee_asset(), burn, wpkh(0xbb)),
                TxOut::new_fee(2_000, fee_asset()),
            ],
        ),
        (
            "bond penalty: extra output",
            vec![
                pay(fee_asset(), reward - 2_000, wpkh(0xaa)),
                burn_out(burn),
                TxOut::new_fee(2_000, fee_asset()),
                TxOut::new_fee(0, fee_asset()),
            ],
        ),
    ] {
        let mut t = ptx.clone();
        t.output = outputs;
        out.push(fixture(name, false, &t, &bspent, 0, &pstack));
    }
    let dup = replace_bits(
        &replace_bits(&pstack[0], &e.second.signature, &e.first.signature),
        &e.second.commitment,
        &e.first.commitment,
    );
    out.push(fixture(
        "bond penalty: same commitment twice",
        false,
        &ptx,
        &bspent,
        0,
        &with_witness(&pstack, dup),
    ));

    // Pooled bond refund.
    let mut rtx = ptx.clone();
    rtx.lock_time = LockTime::from_height(REFUND).unwrap();
    rtx.output = vec![
        pay(fee_asset(), BOND_AMOUNT - 1_000, wpkh(0x22)),
        TxOut::new_fee(1_000, fee_asset()),
    ];
    let rsig = sign(Compiled::sig_all_hash(&env(b, &rtx, &bspent, 0)), OPERATOR);
    let rstack = b
        .satisfy(&env(b, &rtx, &bspent, 0), &refund_action(&rsig))
        .unwrap();
    out.push(fixture(
        "bond refund at REFUND_HEIGHT",
        true,
        &rtx,
        &bspent,
        0,
        &rstack,
    ));
    let mut early = rtx.clone();
    early.lock_time = LockTime::from_height(REFUND - 1).unwrap();
    let esig = sign(
        Compiled::sig_all_hash(&env(b, &early, &bspent, 0)),
        OPERATOR,
    );
    out.push(fixture(
        "bond: premature refund (correctly signed)",
        false,
        &early,
        &bspent,
        0,
        &with_witness(&rstack, replace_bits(&rstack[0], &rsig, &esig)),
    ));

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "warning": "PUBLIC TEST KEYS, SYNTHETIC GENESIS/ASSETS. DO NOT FUND.",
            "lockbox_cmr": lb.cmr().to_string(), "bond_cmr": b.cmr().to_string(),
            "vectors": out,
        }))
        .unwrap()
    );
}
