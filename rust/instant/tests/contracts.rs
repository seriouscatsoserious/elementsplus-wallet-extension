//! Executes the REAL compiled Simplicity programs (Rust BitMachine + the C
//! jets from simplicity-sys) against real BIP340 signatures. No mocked
//! covenant decisions. Pinned-node C interpreter runs: scripts/check-fork.mjs.
mod common;
use common::*;
use elementsplus_instant::{
    bond::{self, penalty_action, refund_action, Evidence, Promise},
    elements::{hashes::Hash, BlockHash, LockTime, Sequence, Transaction, TxOut},
    hash, lockbox, watchtower, Compiled,
};

// ---------- lockbox: cooperative path ----------

#[test]
fn cooperative_spend_with_owner_auth_and_promise_succeeds() {
    let stack = cooperative_witness(&spend(9)).expect("valid cooperative spend");
    assert_eq!(stack.len(), 4);
    assert_eq!(stack[2], lockbox_of(OWNER).cmr().as_ref().to_vec());
}

#[test]
fn spend_without_valid_promise_fails() {
    let lb = lockbox_of(OWNER);
    let tx = spend(9);
    let spent = [lockbox_utxo()];
    let e = env(lb, &tx, &spent, 0);
    let owner = sign(Compiled::sig_all_hash(&e), OWNER);
    let digest = lb.promise_digest(lockbox_outpoint(), &tx, &spent).unwrap();
    for (label, promise) in [
        ("zero promise", [0u8; 64]),
        ("owner signs the promise", sign(digest, OWNER)),
        ("other operator signs", sign(digest, OTHER_OPERATOR)),
        (
            "operator signs sig_all_hash",
            sign(Compiled::sig_all_hash(&e), OPERATOR),
        ),
    ] {
        assert!(
            lb.satisfy(&e, &lockbox::cooperative_all(&owner, &promise))
                .is_err(),
            "{label} must fail"
        );
    }
}

#[test]
fn promise_for_a_different_transaction_fails() {
    let lb = lockbox_of(OWNER);
    let spent = [lockbox_utxo()];
    let (signed_for, broadcast) = (spend(9), spend(8));
    let promise = promise_for(lb, lockbox_outpoint(), &signed_for, &spent, OPERATOR);
    let e = env(lb, &broadcast, &spent, 0);
    let owner = sign(Compiled::sig_all_hash(&e), OWNER);
    assert!(lb
        .satisfy(&e, &lockbox::cooperative_all(&owner, &promise))
        .is_err());

    // Same tx shape but changed fee / lock time / sequence => different commitment.
    for mutate in [
        |t: &mut Transaction| t.output[1] = TxOut::new_fee(1_001, fee_asset()),
        |t: &mut Transaction| t.lock_time = LockTime::from_height(5).unwrap(),
        |t: &mut Transaction| t.input[0].sequence = Sequence::ZERO,
    ] {
        let mut changed = signed_for.clone();
        mutate(&mut changed);
        let e = env(lb, &changed, &spent, 0);
        let owner = sign(Compiled::sig_all_hash(&e), OWNER);
        assert!(lb
            .satisfy(&e, &lockbox::cooperative_all(&owner, &promise))
            .is_err());
    }

    // A promise bound to another lockbox outpoint cannot be replayed here.
    let foreign = promise_for(lb, outpoint(0x45, 1), &signed_for, &spent, OPERATOR);
    let e = env(lb, &signed_for, &spent, 0);
    let owner = sign(Compiled::sig_all_hash(&e), OWNER);
    assert!(lb
        .satisfy(&e, &lockbox::cooperative_all(&owner, &foreign))
        .is_err());
}

#[test]
fn operator_alone_cannot_spend() {
    let lb = lockbox_of(OWNER);
    let tx = spend(9);
    let spent = [lockbox_utxo()];
    let e = env(lb, &tx, &spent, 0);
    let promise = promise_for(lb, lockbox_outpoint(), &tx, &spent, OPERATOR);
    let operator_as_owner = sign(Compiled::sig_all_hash(&e), OPERATOR);
    assert!(lb
        .satisfy(&e, &lockbox::cooperative_all(&operator_as_owner, &promise))
        .is_err());
    let paired = sign(
        lb.paired_digest(lockbox_outpoint(), &tx.output[0]).unwrap(),
        OPERATOR,
    );
    assert!(lb
        .satisfy(&e, &lockbox::cooperative_paired(&paired, &promise))
        .is_err());
    // Operator can't use the exit path either, even after expiry.
    let mut late = tx.clone();
    late.lock_time = LockTime::from_height(EXPIRY).unwrap();
    let e = env(lb, &late, &spent, 0);
    assert!(lb
        .satisfy(
            &e,
            &lockbox::timeout_exit(&sign(Compiled::sig_all_hash(&e), OPERATOR))
        )
        .is_err());
}

#[test]
fn owner_and_operator_must_differ() {
    assert!(params(OWNER, OWNER).compile().is_err());
}

// ---------- lockbox: maker paired authorization (DEX swap) ----------

struct Swap {
    tx: Transaction,
    spent: Vec<TxOut>,
}

fn maker_outpoint() -> elementsplus_instant::elements::OutPoint {
    outpoint(0x71, 0)
}
fn taker_outpoint() -> elementsplus_instant::elements::OutPoint {
    outpoint(0x72, 2)
}

/// Maker's lockbox (500 TOKEN) at input 0 paired with output 0 (40_000 ECX to
/// the maker); taker's lockbox (100_000 ECX) at input 1.
fn swap() -> Swap {
    Swap {
        tx: Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input(maker_outpoint()), input(taker_outpoint())],
            output: vec![
                pay(fee_asset(), 40_000, wpkh(0x33)),
                pay(token(), 500, wpkh(0x44)),
                pay(fee_asset(), 59_000, wpkh(0x45)),
                TxOut::new_fee(1_000, fee_asset()),
            ],
        },
        spent: vec![
            lockbox_of(MAKER).funding_output(token(), 500),
            lockbox_of(TAKER).funding_output(fee_asset(), 100_000),
        ],
    }
}

/// Maker's offline order: signed over its input + the output it wants.
fn maker_order(paired: &TxOut) -> [u8; 64] {
    sign(
        lockbox_of(MAKER)
            .paired_digest(maker_outpoint(), paired)
            .unwrap(),
        MAKER,
    )
}

fn satisfy_swap(s: &Swap, maker_sig: [u8; 64]) -> Result<(), String> {
    let (maker, taker) = (lockbox_of(MAKER), lockbox_of(TAKER));
    let e0 = env(maker, &s.tx, &s.spent, 0);
    let p0 = promise_for(maker, maker_outpoint(), &s.tx, &s.spent, OPERATOR);
    maker.satisfy(&e0, &lockbox::cooperative_paired(&maker_sig, &p0))?;
    let e1 = env(taker, &s.tx, &s.spent, 1);
    let taker_sig = sign(Compiled::sig_all_hash(&e1), TAKER);
    let p1 = promise_for(taker, taker_outpoint(), &s.tx, &s.spent, OPERATOR);
    taker.satisfy(&e1, &lockbox::cooperative_all(&taker_sig, &p1))?;
    Ok(())
}

#[test]
fn maker_paired_order_fills_in_a_two_lockbox_swap() {
    let s = swap();
    let order = maker_order(&s.tx.output[0]);
    satisfy_swap(&s, order).expect("instant swap of a lockbox offer");
}

#[test]
fn maker_order_survives_any_taker_completion_but_not_a_changed_paired_output() {
    let order = maker_order(&swap().tx.output[0]);
    // The taker may change everything that is not the maker's paired output.
    let mut s = swap();
    s.tx.output[2] = pay(fee_asset(), 58_000, wpkh(0x46));
    s.tx.output[3] = TxOut::new_fee(2_000, fee_asset());
    satisfy_swap(&s, order).expect("taker-side changes keep the maker order valid");

    // ...but not the maker's paid amount, asset or destination.
    for out in [
        pay(fee_asset(), 39_999, wpkh(0x33)),
        pay(token(), 40_000, wpkh(0x33)),
        pay(fee_asset(), 40_000, wpkh(0x34)),
    ] {
        let mut s = swap();
        s.tx.output[0] = out;
        assert!(satisfy_swap(&s, order).is_err());
    }
    // ...nor move the maker input away from its paired output index.
    let mut s = swap();
    s.tx.input.swap(0, 1);
    s.spent.swap(0, 1);
    let maker = lockbox_of(MAKER);
    let e = env(maker, &s.tx, &s.spent, 1);
    let p = promise_for(maker, maker_outpoint(), &s.tx, &s.spent, OPERATOR);
    assert!(maker
        .satisfy(&e, &lockbox::cooperative_paired(&order, &p))
        .is_err());
}

#[test]
fn maker_order_still_needs_the_operator_promise() {
    let s = swap();
    let order = maker_order(&s.tx.output[0]);
    let maker = lockbox_of(MAKER);
    let e = env(maker, &s.tx, &s.spent, 0);
    let wrong = promise_for(maker, taker_outpoint(), &s.tx, &s.spent, OPERATOR);
    assert!(maker
        .satisfy(&e, &lockbox::cooperative_paired(&order, &wrong))
        .is_err());
}

// ---------- lockbox: timeout exit ----------

fn exit_tx(height: u32) -> Transaction {
    let mut tx = spend(9);
    tx.lock_time = LockTime::from_height(height).unwrap();
    tx
}

fn try_exit(tx: &Transaction) -> Result<Vec<Vec<u8>>, String> {
    let lb = lockbox_of(OWNER);
    let spent = [lockbox_utxo()];
    let e = env(lb, tx, &spent, 0);
    lb.satisfy(
        &e,
        &lockbox::timeout_exit(&sign(Compiled::sig_all_hash(&e), OWNER)),
    )
}

#[test]
fn timeout_exit_only_from_expiry() {
    assert!(try_exit(&exit_tx(EXPIRY - 1)).is_err(), "before expiry");
    assert!(try_exit(&spend(9)).is_err(), "no lock time");
    try_exit(&exit_tx(EXPIRY)).expect("at expiry");
    try_exit(&exit_tx(EXPIRY + 500)).expect("after expiry");
    // Disabled lock time (all sequences final) does not count.
    let mut final_seq = exit_tx(EXPIRY);
    final_seq.input[0].sequence = Sequence::MAX;
    assert!(try_exit(&final_seq).is_err(), "disabled locktime");
    // A timestamp lock time is not a height lock.
    let mut timestamp = spend(9);
    timestamp.lock_time = LockTime::from_time(1_800_000_000).unwrap();
    assert!(try_exit(&timestamp).is_err(), "timestamp locktime");
}

#[test]
fn timeout_exit_requires_owner_signature_over_the_whole_tx() {
    let lb = lockbox_of(OWNER);
    let spent = [lockbox_utxo()];
    let signed = exit_tx(EXPIRY);
    let sig = sign(Compiled::sig_all_hash(&env(lb, &signed, &spent, 0)), OWNER);
    let mut changed = signed.clone();
    changed.output[0] = pay(fee_asset(), 99_000, wpkh(0x77));
    let e = env(lb, &changed, &spent, 0);
    assert!(lb.satisfy(&e, &lockbox::timeout_exit(&sig)).is_err());
}

// ---------- pooled bond: penalty ----------

fn bond_utxo() -> TxOut {
    the_bond().funding_output(BOND_AMOUNT)
}

fn evidence() -> Evidence {
    let spent = [lockbox_utxo()];
    Evidence {
        lockbox: lockbox_outpoint(),
        first: promise_record(&spend(9), &spent),
        second: promise_record(&spend(8), &spent),
    }
}

fn try_penalty(tx: &Transaction, e: &Evidence) -> Result<Vec<Vec<u8>>, String> {
    let b = the_bond();
    let env = env(b, tx, &[bond_utxo()], 0);
    b.satisfy(&env, &penalty_action(e))
}

const PENALTY_FEE: u64 = 2_000;

fn penalty_tx() -> Transaction {
    the_bond()
        .penalty_transaction(bond_outpoint(), BOND_AMOUNT, wpkh(0xaa), PENALTY_FEE)
        .unwrap()
}

#[test]
fn conflicting_promises_slash_the_pooled_bond_with_reporter_reward() {
    let e = evidence();
    the_bond().check_evidence(&e).unwrap();
    let tx = penalty_tx();
    let reward = BOND_AMOUNT / 8;
    assert_eq!(tx.output[0].value.explicit(), Some(reward - PENALTY_FEE));
    assert_eq!(tx.output[1].script_pubkey, bond::burn_script());
    assert_eq!(tx.output[1].value.explicit(), Some(BOND_AMOUNT - reward));
    assert!(tx.output[2].is_fee());
    try_penalty(&tx, &e).expect("valid penalty");
    // Either evidence order.
    let swapped = Evidence {
        lockbox: e.lockbox,
        first: e.second.clone(),
        second: e.first.clone(),
    };
    try_penalty(&tx, &swapped).expect("swapped order");
    // The reporter may spend its whole reward on the fee.
    let all_fee = the_bond()
        .penalty_transaction(bond_outpoint(), BOND_AMOUNT, wpkh(0xaa), reward)
        .unwrap();
    try_penalty(&all_fee, &e).expect("reward entirely as fee");
    assert!(the_bond()
        .penalty_transaction(bond_outpoint(), BOND_AMOUNT, wpkh(0xaa), reward + 1)
        .is_err());
}

#[test]
fn the_same_bond_secures_many_lockboxes() {
    // Equivocation on the maker's swap lockbox slashes the same pooled bond.
    let s = swap();
    let maker = lockbox_of(MAKER);
    let mut cancel = s.tx.clone();
    cancel.output[0] = pay(fee_asset(), 40_000, wpkh(0x99));
    let rec = |tx: &Transaction| Promise {
        commitment: hash::tx_commitment(tx, &s.spent).unwrap(),
        signature: promise_for(maker, maker_outpoint(), tx, &s.spent, OPERATOR),
    };
    let e = Evidence {
        lockbox: maker_outpoint(),
        first: rec(&s.tx),
        second: rec(&cancel),
    };
    try_penalty(&penalty_tx(), &e).expect("slash via a different lockbox");
}

#[test]
fn penalty_rejects_non_equivocation() {
    let e = evidence();
    let tx = penalty_tx();
    // Same commitment twice (even with a second signature) is not equivocation.
    let dup = Evidence {
        lockbox: e.lockbox,
        first: e.first.clone(),
        second: e.first.clone(),
    };
    assert!(try_penalty(&tx, &dup).is_err());
    // Promises for different lockboxes are not a conflict.
    let mut other = e.clone();
    other.second.signature = sign(
        hash::promise_digest(genesis(), outpoint(0x45, 1), other.second.commitment),
        OPERATOR,
    );
    assert!(try_penalty(&tx, &other).is_err());
    // Another key's promises cannot slash this operator.
    let mut framed = e.clone();
    framed.second.signature = sign(
        hash::promise_digest(genesis(), e.lockbox, e.second.commitment),
        OTHER_OPERATOR,
    );
    assert!(try_penalty(&tx, &framed).is_err());
    // Wrong network.
    let mut net = e.clone();
    for p in [&mut net.first, &mut net.second] {
        p.signature = sign(
            hash::promise_digest(
                BlockHash::from_byte_array([0x12; 32]),
                e.lockbox,
                p.commitment,
            ),
            OPERATOR,
        );
    }
    assert!(try_penalty(&tx, &net).is_err());
}

type Mutation = Box<dyn Fn(&mut Transaction)>;

#[test]
fn penalty_enforces_the_exact_split() {
    let e = evidence();
    let reward = bond::reward(BOND_AMOUNT);
    let burn = BOND_AMOUNT - reward;
    let fee = |v| TxOut::new_fee(v, fee_asset());
    let value = elementsplus_instant::elements::confidential::Value::Explicit;
    let mutations: Vec<(&str, Mutation)> = vec![
        (
            "burn paid as fee instead of OP_RETURN",
            Box::new(move |t| t.output[1] = fee(burn)),
        ),
        (
            "burn to a spendable script",
            Box::new(move |t| t.output[1] = pay(fee_asset(), burn, wpkh(0xbb))),
        ),
        (
            "burn with OP_RETURN data",
            Box::new(move |t| {
                t.output[1].script_pubkey =
                    elementsplus_instant::elements::Script::from(vec![0x6a, 0x01, 0x00])
            }),
        ),
        (
            "partial burn, reporter takes more",
            Box::new(move |t| {
                t.output[1].value = value(burn - 1);
                t.output[0].value = value(reward - PENALTY_FEE + 1);
            }),
        ),
        (
            "reporter + fee exceed the reward",
            Box::new(move |t| t.output[2] = fee(PENALTY_FEE + 1)),
        ),
        (
            "wrong reporter asset",
            Box::new(move |t| t.output[0] = pay(token(), reward - PENALTY_FEE, wpkh(0xaa))),
        ),
        (
            "reporter takes everything (old 2-output shape)",
            Box::new(move |t| {
                t.output = vec![
                    pay(fee_asset(), BOND_AMOUNT - PENALTY_FEE, wpkh(0xaa)),
                    fee(PENALTY_FEE),
                ]
            }),
        ),
        ("extra output", Box::new(move |t| t.output.push(fee(0)))),
        (
            "missing output",
            Box::new(|t| {
                t.output.pop();
            }),
        ),
        (
            "extra input",
            Box::new(|t| t.input.push(input(outpoint(0x67, 0)))),
        ),
    ];
    for (label, mutate) in mutations {
        let mut tx = penalty_tx();
        mutate(&mut tx);
        let b = the_bond();
        let spent = vec![bond_utxo(); tx.input.len()];
        let env = env(b, &tx, &spent, 0);
        assert!(
            b.satisfy(&env, &penalty_action(&e)).is_err(),
            "{label} must fail"
        );
    }
}

#[test]
fn bond_must_be_explicit_fee_asset() {
    let e = evidence();
    let tx = penalty_tx();
    let b = the_bond();
    let mut utxo = bond_utxo();
    utxo.asset = elementsplus_instant::elements::confidential::Asset::Explicit(token());
    let env = env(b, &tx, &[utxo], 0);
    assert!(b.satisfy(&env, &penalty_action(&e)).is_err());
}

#[test]
fn watchtower_extracts_the_on_chain_promise_and_slashes() {
    // Operator promised spend(9) to a victim; spend(8) (with its own promise)
    // confirms. The victim/watchtower recovers the on-chain promise from the
    // witness bits and builds penalty evidence.
    let spent = [lockbox_utxo()];
    let mut confirmed = spend(8);
    confirmed.input[0].witness.script_witness = cooperative_witness(&confirmed).unwrap();
    let on_chain = watchtower::promise_from_chain(
        genesis(),
        &xonly(OPERATOR),
        lockbox_outpoint(),
        &confirmed,
        &spent,
    )
    .expect("promise found in witness");
    let held = promise_record(&spend(9), &spent);
    let e = watchtower::evidence(lockbox_outpoint(), held.clone(), on_chain.clone()).unwrap();
    try_penalty(&penalty_tx(), &e).expect("penalty from chain evidence");
    // Holding the promise of the tx that actually confirmed is not evidence.
    assert!(watchtower::evidence(lockbox_outpoint(), on_chain.clone(), on_chain).is_err());
}

#[test]
fn watchtower_finds_nothing_in_a_timeout_exit() {
    let spent = [lockbox_utxo()];
    let mut exit = exit_tx(EXPIRY);
    exit.input[0].witness.script_witness = try_exit(&exit).unwrap();
    assert!(watchtower::promise_from_chain(
        genesis(),
        &xonly(OPERATOR),
        lockbox_outpoint(),
        &exit,
        &spent
    )
    .is_err());
}

// ---------- pooled bond: refund ----------

fn refund_tx(height: u32) -> Transaction {
    let mut tx = penalty_tx();
    tx.lock_time = LockTime::from_height(height).unwrap();
    tx.output = vec![
        pay(fee_asset(), BOND_AMOUNT - 1_000, wpkh(0x22)),
        TxOut::new_fee(1_000, fee_asset()),
    ];
    tx
}

fn try_refund(tx: &Transaction, signer: u8) -> Result<Vec<Vec<u8>>, String> {
    let b = the_bond();
    let e = env(b, tx, &[bond_utxo()], 0);
    b.satisfy(
        &e,
        &refund_action(&sign(Compiled::sig_all_hash(&e), signer)),
    )
}

#[test]
fn bond_refund_only_after_deadline_and_only_by_operator() {
    assert!(try_refund(&refund_tx(REFUND - 1), OPERATOR).is_err());
    try_refund(&refund_tx(REFUND), OPERATOR).expect("refund at deadline");
    assert!(try_refund(&refund_tx(REFUND), OWNER).is_err());
    let mut final_seq = refund_tx(REFUND);
    final_seq.input[0].sequence = Sequence::MAX;
    assert!(try_refund(&final_seq, OPERATOR).is_err());
}

#[test]
fn penalty_still_works_after_the_refund_deadline_while_unspent() {
    let mut tx = penalty_tx();
    tx.lock_time = LockTime::from_height(REFUND + 10).unwrap();
    try_penalty(&tx, &evidence()).expect("late penalty");
}
