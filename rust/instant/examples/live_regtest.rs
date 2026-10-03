//! Funded end-to-end run against a LOCAL, DISPOSABLE Elements+ regtest node
//! (Simplicity active). PUBLIC TEST KEYS. Refuses to run on any other chain.
//!
//!   cargo run --example live_regtest
//!
//! Environment (defaults match the local dev setup):
//!   INSTANT_CLI      elements CLI binary
//!   INSTANT_CLI_ARGS whitespace-separated args (chain, datadir, rpcport, wallet)
//!
//! Scenarios (all mined): A cooperative spend, B two-lockbox DEX swap with an
//! offline maker's paired order, C timeout exit, D equivocation -> watchtower
//! evidence from chain -> pooled-bond slash with reporter reward, E bond refund.
//! Node-level negative checks use `testmempoolaccept` (never broadcast).
use elementsplus_instant::{
    bond::{self, penalty_action, refund_action, Evidence, Promise},
    elements::{
        encode, secp256k1_zkp::Keypair, secp256k1_zkp::Secp256k1, secp256k1_zkp::SecretKey,
        Address, AddressParams, AssetId, BlockHash, LockTime, OutPoint, Script, Sequence,
        Transaction, TxIn, TxOut, Txid,
    },
    hash, lockbox, sign_digest,
    simplicity::jet::elements::ElementsUtxo,
    watchtower, Compiled,
};
use serde_json::{json, Value};
use std::{process::Command, str::FromStr, thread, time::Duration};

// Defaults match the repository's disposable regtest harness (paths relative to
// this crate); override with INSTANT_CLI / INSTANT_CLI_ARGS.
const DEFAULT_CLI: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../.local/elementsplus-node/build-regtest/bin/elements-functional-test-cli"
);

type R<T> = Result<T, String>;

fn cli(args: &[&str]) -> R<String> {
    let bin = std::env::var("INSTANT_CLI").unwrap_or_else(|_| DEFAULT_CLI.into());
    let base = std::env::var("INSTANT_CLI_ARGS").unwrap_or_else(|_| {
        format!(
            "-chain=elementsregtest -datadir={}/../../.regtest/node -rpcport=18884 -rpcwallet=miner",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let out = Command::new(bin)
        .args(base.split_whitespace())
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "{} {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
fn cli_json(args: &[&str]) -> R<Value> {
    serde_json::from_str(&cli(args)?).map_err(|e| e.to_string())
}

fn key(n: u8) -> Keypair {
    let mut s = [0; 32];
    s[31] = n;
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&s).unwrap())
}
fn xonly(n: u8) -> elementsplus_instant::elements::secp256k1_zkp::XOnlyPublicKey {
    key(n).x_only_public_key().0
}
fn sign(d: [u8; 32], n: u8) -> [u8; 64] {
    sign_digest(d, &key(n))
}

struct Chain {
    genesis: BlockHash,
    ecx: AssetId,
    token: AssetId,
    miner: String,
}

fn height() -> R<u32> {
    cli(&["getblockcount"])?
        .parse()
        .map_err(|_| "height".into())
}

fn wallet_script() -> R<Script> {
    let addr = cli(&["getnewaddress"])?;
    let info = cli_json(&["getaddressinfo", &addr])?;
    Ok(Script::from(
        hex::decode(info["scriptPubKey"].as_str().ok_or("spk")?).map_err(|e| e.to_string())?,
    ))
}

fn raw_tx(txid: &Txid) -> R<Transaction> {
    let hexs = cli(&["getrawtransaction", &txid.to_string()])?;
    encode::deserialize(&hex::decode(hexs).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn wait_confirmed(c: &Chain, txid: &Txid) -> R<u32> {
    for i in 0..60 {
        let v = cli_json(&["getrawtransaction", &txid.to_string(), "true"])?;
        if v["confirmations"].as_u64().unwrap_or(0) >= 1 {
            let block = v["blockhash"].as_str().unwrap_or_default().to_string();
            let h = cli_json(&["getblockheader", &block])?["height"]
                .as_u64()
                .unwrap_or(0);
            return Ok(h as u32);
        }
        if i == 15 {
            // Auto-miner normally mines ~4 s after a mempool tx; nudge if not.
            cli(&["generatetoaddress", "1", &c.miner])?;
        }
        thread::sleep(Duration::from_secs(1));
    }
    Err(format!("{txid} not confirmed"))
}

fn mine_to(c: &Chain, target: u32) -> R<()> {
    let h = height()?;
    if h < target {
        cli(&["generatetoaddress", &(target - h).to_string(), &c.miner])?;
    }
    Ok(())
}

fn btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Fund `script` with an explicit output; return (outpoint, txout).
fn fund(c: &Chain, script: &Script, asset: AssetId, sats: u64) -> R<(OutPoint, TxOut)> {
    let addr = Address::from_script(script, None, &AddressParams::ELEMENTS).ok_or("address")?;
    let asset_arg = if asset == c.ecx {
        "bitcoin".to_string()
    } else {
        asset.to_string()
    };
    let txid: Txid = cli(&[
        "-named",
        "sendtoaddress",
        &format!("address={addr}"),
        &format!("amount={}", btc(sats)),
        &format!("assetlabel={asset_arg}"),
    ])?
    .parse()
    .map_err(|_| "txid")?;
    wait_confirmed(c, &txid)?;
    let tx = raw_tx(&txid)?;
    let (vout, out) = tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| &o.script_pubkey == script)
        .ok_or("funding output not found")?;
    if out.value.explicit() != Some(sats) || out.asset.explicit() != Some(asset) {
        return Err("funding output is not the expected explicit amount".into());
    }
    Ok((
        OutPoint {
            txid,
            vout: vout as u32,
        },
        out.clone(),
    ))
}

fn hexs(tx: &Transaction) -> String {
    hex::encode(encode::serialize(tx))
}

/// testmempoolaccept: Ok(()) if allowed, Err(reason) otherwise.
fn mempool_check(tx: &Transaction) -> R<()> {
    let v = cli_json(&["testmempoolaccept", &json!([hexs(tx)]).to_string(), "0"])?;
    if v[0]["allowed"].as_bool() == Some(true) {
        Ok(())
    } else {
        Err(v[0]["reject-reason"]
            .as_str()
            .unwrap_or("rejected")
            .to_string())
    }
}

fn expect_rejected(label: &str, tx: &Transaction, log: &mut Vec<Value>) -> R<()> {
    match mempool_check(tx) {
        Ok(()) => Err(format!("NODE ACCEPTED A TX THAT MUST FAIL: {label}")),
        Err(reason) => {
            println!("  node rejects {label}: {reason}");
            log.push(json!({"check": label, "node_reject_reason": reason}));
            Ok(())
        }
    }
}

fn broadcast(c: &Chain, label: &str, tx: &Transaction, log: &mut Vec<Value>) -> R<Txid> {
    let txid: Txid = cli(&["sendrawtransaction", &hexs(tx), "0", "21000000"])?
        .parse()
        .map_err(|_| "txid")?;
    let h = wait_confirmed(c, &txid)?;
    println!("  MINED {label}: {txid} (height {h})");
    log.push(json!({"tx": label, "txid": txid.to_string(), "height": h}));
    Ok(txid)
}

fn utxos(spent: &[TxOut]) -> Vec<ElementsUtxo> {
    spent.iter().cloned().map(ElementsUtxo::from).collect()
}

fn single_spend(
    prev: OutPoint,
    asset: AssetId,
    amount: u64,
    to: Script,
    fee: u64,
    ecx: AssetId,
) -> Transaction {
    let mut outputs = vec![];
    if asset == ecx {
        outputs.push(explicit(asset, amount - fee, to));
    } else {
        unreachable!("single_spend is ECX-only")
    }
    outputs.push(TxOut::new_fee(fee, ecx));
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            ..Default::default()
        }],
        output: outputs,
    }
}

fn explicit(asset: AssetId, amount: u64, script: Script) -> TxOut {
    TxOut {
        asset: elementsplus_instant::elements::confidential::Asset::Explicit(asset),
        value: elementsplus_instant::elements::confidential::Value::Explicit(amount),
        nonce: elementsplus_instant::elements::confidential::Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    }
}

/// Owner-ALL + operator promise for input `index`.
fn coop_all(
    lb: &lockbox::Lockbox,
    at: OutPoint,
    tx: &Transaction,
    spent: &[TxOut],
    index: u32,
    owner: u8,
    c: &Chain,
) -> R<Vec<Vec<u8>>> {
    let env = lb.environment(tx.clone(), utxos(spent), index, c.genesis)?;
    let owner_sig = sign(Compiled::sig_all_hash(&env), owner);
    let promise = sign(lb.promise_digest(at, tx, spent)?, 2);
    lb.satisfy(&env, &lockbox::cooperative_all(&owner_sig, &promise))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn run() -> R<()> {
    let info = cli_json(&["getblockchaininfo"])?;
    if info["chain"] != "elementsregtest" {
        return Err("refusing: not elementsregtest".into());
    }
    let labels = cli_json(&["dumpassetlabels"])?;
    let ecx = AssetId::from_str(labels["bitcoin"].as_str().ok_or("policy asset")?)
        .map_err(|e| e.to_string())?;
    let balances = cli_json(&["getbalances"])?;
    let token = balances["mine"]["trusted"]
        .as_object()
        .and_then(|m| {
            m.iter()
                .filter(|(k, v)| *k != "bitcoin" && v.as_f64().unwrap_or(0.0) >= 2.0)
                .map(|(k, _)| k.clone())
                .next()
        })
        .ok_or("miner wallet holds no issued token with balance >= 2")?;
    let c = Chain {
        genesis: BlockHash::from_str(&cli(&["getblockhash", "0"])?).map_err(|e| e.to_string())?,
        ecx,
        token: AssetId::from_str(&token).map_err(|e| e.to_string())?,
        miner: cli(&["getnewaddress"])?,
    };
    let mut log: Vec<Value> = vec![];
    let tip = height()?;
    println!(
        "regtest tip {tip}, genesis {}, ECX {}, token {}",
        c.genesis, c.ecx, c.token
    );
    let lb_params = |owner: u8, expiry: u32| lockbox::Params {
        genesis: c.genesis,
        owner: xonly(owner),
        operator: xonly(2),
        expiry,
    };

    // ---------- A: cooperative spend ----------
    println!("A. lockbox fund -> cooperative spend (owner ALL + operator promise)");
    let la = lb_params(1, tip + 200).compile()?;
    let (a_op, a_out) = fund(&c, la.script_pubkey(), c.ecx, 1_000_000)?;
    log.push(json!({"tx": "A lockbox funding", "txid": a_op.txid.to_string(), "vout": a_op.vout}));
    let dest = wallet_script()?;
    let mut ta = single_spend(a_op, c.ecx, 1_000_000, dest.clone(), 1_000, c.ecx);
    let spent = [a_out.clone()];
    let good = coop_all(&la, a_op, &ta, &spent, 0, 1, &c)?;
    // Node-level negatives: same owner signature, promise for another tx / zero.
    let other = single_spend(a_op, c.ecx, 1_000_000, wallet_script()?, 1_000, c.ecx);
    let p_good = sign(la.promise_digest(a_op, &ta, &spent)?, 2);
    let p_other = sign(la.promise_digest(a_op, &other, &spent)?, 2);
    for (label, bad) in [
        ("A: promise for a different tx", p_other),
        ("A: no promise (zero sig)", [0u8; 64]),
    ] {
        let mut t = ta.clone();
        let mut stack = good.clone();
        stack[0] = replace_sig(&stack[0], &p_good, &bad)?;
        t.input[0].witness.script_witness = stack;
        expect_rejected(label, &t, &mut log)?;
    }
    ta.input[0].witness.script_witness = good;
    broadcast(&c, "A cooperative spend", &ta, &mut log)?;

    // ---------- B: DEX swap, maker offline paired order ----------
    println!("B. instant DEX swap: maker lockbox (token, PAIRED order) + taker lockbox (ECX)");
    let tip = height()?;
    let maker = lb_params(3, tip + 1_000).compile()?; // long-lived offer lockbox
    let taker = lb_params(4, tip + 72).compile()?;
    let (m_op, m_out) = fund(&c, maker.script_pubkey(), c.token, 100_000_000)?;
    let (t_op, t_out) = fund(&c, taker.script_pubkey(), c.ecx, 5_000_000)?;
    log.push(json!({"tx": "B maker lockbox funding (token)", "txid": m_op.txid.to_string()}));
    log.push(json!({"tx": "B taker lockbox funding (ECX)", "txid": t_op.txid.to_string()}));
    // Maker (offline later) signs: "my lockbox input pays 0.02 ECX to me".
    let maker_wants = explicit(c.ecx, 2_000_000, wallet_script()?);
    let order = sign(maker.paired_digest(m_op, &maker_wants)?, 3);
    // Taker completes the transaction.
    let mut swap = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: m_op,
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            },
            TxIn {
                previous_output: t_op,
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                ..Default::default()
            },
        ],
        output: vec![
            maker_wants.clone(),
            explicit(c.token, 100_000_000, wallet_script()?),
            explicit(c.ecx, 5_000_000 - 2_000_000 - 2_000, wallet_script()?),
            TxOut::new_fee(2_000, c.ecx),
        ],
    };
    let sspent = [m_out.clone(), t_out.clone()];
    let env0 = maker.environment(swap.clone(), utxos(&sspent), 0, c.genesis)?;
    let p0 = sign(maker.promise_digest(m_op, &swap, &sspent)?, 2);
    let w0 = maker.satisfy(&env0, &lockbox::cooperative_paired(&order, &p0))?;
    let w1 = coop_all(&taker, t_op, &swap, &sspent, 1, 4, &c)?;
    // Negative: taker shortchanges the maker (operator would even re-promise).
    let mut cheat = swap.clone();
    cheat.output[0].value =
        elementsplus_instant::elements::confidential::Value::Explicit(1_000_000);
    cheat.output[2].value = elementsplus_instant::elements::confidential::Value::Explicit(
        5_000_000 - 1_000_000 - 2_000,
    );
    let p0c = sign(maker.promise_digest(m_op, &cheat, &sspent)?, 2);
    let mut cw0 = w0.clone();
    cw0[0] = replace_sig(&w0[0], &p0, &p0c)?;
    cheat.input[0].witness.script_witness = cw0;
    cheat.input[1].witness.script_witness = coop_all(&taker, t_op, &cheat, &sspent, 1, 4, &c)?;
    expect_rejected(
        "B: taker pays maker less than its signed order",
        &cheat,
        &mut log,
    )?;
    swap.input[0].witness.script_witness = w0;
    swap.input[1].witness.script_witness = w1;
    broadcast(
        &c,
        "B instant swap (maker PAIRED + taker ALL, both promised)",
        &swap,
        &mut log,
    )?;

    // ---------- C: timeout exit ----------
    println!("C. lockbox timeout exit (operator absent)");
    let tip = height()?;
    let expiry = tip + 4;
    let lx = lb_params(1, expiry).compile()?;
    let (x_op, x_out) = fund(&c, lx.script_pubkey(), c.ecx, 1_000_000)?;
    log.push(json!({"tx": "C lockbox funding", "txid": x_op.txid.to_string(), "expiry": expiry}));
    let xspent = [x_out];
    let exit_tx = |lock: u32| -> R<Transaction> {
        let mut t = single_spend(x_op, c.ecx, 1_000_000, dest.clone(), 1_000, c.ecx);
        t.lock_time = LockTime::from_height(lock).map_err(|e| e.to_string())?;
        let env = lx.environment(t.clone(), utxos(&xspent), 0, c.genesis)?;
        let sig = sign(Compiled::sig_all_hash(&env), 1);
        // Rust-side execution rejects lock < EXPIRY, so for the premature
        // node check reuse the pruned program and swap in a correct signature.
        let w = match lx.satisfy(&env, &lockbox::timeout_exit(&sig)) {
            Ok(w) => w,
            Err(_) => {
                let mut ok = t.clone();
                ok.lock_time = LockTime::from_height(expiry).unwrap();
                let okenv = lx.environment(ok.clone(), utxos(&xspent), 0, c.genesis)?;
                let oksig = sign(Compiled::sig_all_hash(&okenv), 1);
                let mut w = lx.satisfy(&okenv, &lockbox::timeout_exit(&oksig))?;
                w[0] = replace_sig(&w[0], &oksig, &sig)?;
                w
            }
        };
        t.input[0].witness.script_witness = w;
        Ok(t)
    };
    let early = exit_tx(expiry)?;
    expect_rejected(
        &format!("C: exit at tip {} < EXPIRY {expiry} (non-final)", height()?),
        &early,
        &mut log,
    )?;
    mine_to(&c, expiry)?;
    expect_rejected(
        "C: exit with lock time EXPIRY-1 (script)",
        &exit_tx(expiry - 1)?,
        &mut log,
    )?;
    broadcast(&c, "C timeout exit", &early, &mut log)?;

    // ---------- D: equivocation -> slash ----------
    println!("D. operator equivocates; victim/watchtower slashes the pooled bond");
    let tip = height()?;
    let bond_d = bond::Params {
        genesis: c.genesis,
        fee_asset: c.ecx,
        operator: xonly(2),
        refund_height: tip + 500,
    }
    .compile()?;
    let (b_op, b_out) = fund(&c, bond_d.script_pubkey(), c.ecx, 8_000_000)?;
    log.push(
        json!({"tx": "D pooled bond funding", "txid": b_op.txid.to_string(), "amount": 8_000_000}),
    );
    let le = lb_params(1, tip + 200).compile()?;
    let (e_op, e_out) = fund(&c, le.script_pubkey(), c.ecx, 1_000_000)?;
    log.push(json!({"tx": "D lockbox funding", "txid": e_op.txid.to_string()}));
    let espent = [e_out];
    let mut victim_tx = single_spend(e_op, c.ecx, 1_000_000, wallet_script()?, 1_000, c.ecx);
    let held = Promise {
        commitment: hash::tx_commitment(&victim_tx, &espent)?,
        signature: sign(le.promise_digest(e_op, &victim_tx, &espent)?, 2),
    };
    let mut conflict = single_spend(e_op, c.ecx, 1_000_000, wallet_script()?, 1_000, c.ecx);
    conflict.input[0].witness.script_witness = coop_all(&le, e_op, &conflict, &espent, 0, 1, &c)?;
    let conflict_id = broadcast(&c, "D conflicting promised spend", &conflict, &mut log)?;
    // Watchtower: fetch from chain, recover the on-chain promise, build evidence.
    let on_chain_tx = raw_tx(&conflict_id)?;
    let on_chain =
        watchtower::promise_from_chain(c.genesis, &xonly(2), e_op, &on_chain_tx, &espent)?;
    let evidence: Evidence = watchtower::evidence(e_op, held, on_chain)?;
    bond_d.check_evidence(&evidence)?;
    victim_tx.input[0].witness.script_witness = coop_all(&le, e_op, &victim_tx, &espent, 0, 1, &c)?;
    expect_rejected(
        "D: victim's promised tx after the conflict confirmed",
        &victim_tx,
        &mut log,
    )?;
    let reporter = wallet_script()?;
    let mut penalty = bond_d.penalty_transaction(b_op, 8_000_000, reporter.clone(), 2_000)?;
    let bspent = [b_out];
    let penv = bond_d.environment(penalty.clone(), utxos(&bspent), 0, c.genesis)?;
    penalty.input[0].witness.script_witness = bond_d.satisfy(&penv, &penalty_action(&evidence))?;
    use elementsplus_instant::elements::confidential::Value as Amount;
    let mut greedy = penalty.clone();
    greedy.output[0].value = Amount::Explicit(4_000_000 - 2_000);
    greedy.output[1].value = Amount::Explicit(4_000_000);
    expect_rejected("D: penalty paying the reporter 50%", &greedy, &mut log)?;
    let mut to_fees = penalty.clone();
    to_fees.output[1] = TxOut::new_fee(7_000_000, c.ecx);
    expect_rejected(
        "D: penalty burning to miner fees instead of OP_RETURN",
        &to_fees,
        &mut log,
    )?;
    let pid = broadcast(
        &c,
        "D bond slash (1/8 reporter incl. fee, 7/8 OP_RETURN burn)",
        &penalty,
        &mut log,
    )?;
    let mined = raw_tx(&pid)?;
    println!(
        "  reporter got {:?} sats; burned (OP_RETURN) {:?} sats; fee {:?} sats",
        mined.output[0].value.explicit(),
        mined.output[1].value.explicit(),
        mined.output[2].value.explicit()
    );

    // ---------- E: bond refund ----------
    println!("E. pooled bond refund after REFUND_HEIGHT");
    let tip = height()?;
    let refund_h = tip + 4;
    let bond_e = bond::Params {
        genesis: c.genesis,
        fee_asset: c.ecx,
        operator: xonly(2),
        refund_height: refund_h,
    }
    .compile()?;
    let (r_op, r_out) = fund(&c, bond_e.script_pubkey(), c.ecx, 2_000_000)?;
    log.push(
        json!({"tx": "E bond funding", "txid": r_op.txid.to_string(), "refund_height": refund_h}),
    );
    let mut refund = single_spend(r_op, c.ecx, 2_000_000, wallet_script()?, 1_000, c.ecx);
    refund.lock_time = LockTime::from_height(refund_h).map_err(|e| e.to_string())?;
    let rspent = [r_out];
    let renv = bond_e.environment(refund.clone(), utxos(&rspent), 0, c.genesis)?;
    let rsig = sign(Compiled::sig_all_hash(&renv), 2);
    refund.input[0].witness.script_witness = bond_e.satisfy(&renv, &refund_action(&rsig))?;
    expect_rejected(
        &format!(
            "E: refund at tip {} < REFUND_HEIGHT {refund_h} (non-final)",
            height()?
        ),
        &refund,
        &mut log,
    )?;
    mine_to(&c, refund_h)?;
    broadcast(&c, "E bond refund", &refund, &mut log)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "lockbox_cmr_example": la.cmr().to_string(),
            "results": log,
        }))
        .map_err(|e| e.to_string())?
    );
    Ok(())
}

fn get_bit(b: &[u8], i: usize) -> bool {
    b[i / 8] >> (7 - i % 8) & 1 == 1
}
/// Replace the unique bit-level occurrence of signature `old` with `new`.
fn replace_sig(witness: &[u8], old: &[u8; 64], new: &[u8; 64]) -> R<Vec<u8>> {
    let total = witness.len() * 8;
    let hits: Vec<usize> = (0..=total - 512)
        .filter(|&s| (0..512).all(|i| get_bit(witness, s + i) == get_bit(old, i)))
        .collect();
    if hits.len() != 1 {
        return Err("signature not uniquely located in witness".into());
    }
    let mut out = witness.to_vec();
    for i in 0..512 {
        let (byte, mask) = ((hits[0] + i) / 8, 1u8 << (7 - (hits[0] + i) % 8));
        if get_bit(new, i) {
            out[byte] |= mask
        } else {
            out[byte] &= !mask
        }
    }
    Ok(out)
}
