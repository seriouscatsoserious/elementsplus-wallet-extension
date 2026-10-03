//! Penalty construction (SPEC §4.2, §7 step 3, §11).
//!
//! Outputs, fixed by the bond covenant (1 input, exactly 3 outputs):
//! `[reporter: ⌊b/8⌋ − fee, OP_RETURN: b − ⌊b/8⌋, fee]`.
//! The fee comes out of the reporter share; the burn is never touched.
use anyhow::{anyhow, bail, Result};
use elementsplus_instant::{
    bond::{self, penalty_action, Bond, Evidence},
    elements::{BlockHash, OutPoint, Script, Transaction, TxOut},
    simplicity::jet::elements::ElementsUtxo,
};

/// Fee policy. Rates are in satoshi per 1000 virtual bytes (sat/kvB) so the
/// arithmetic is exact integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    /// Target fee rate.
    pub rate_sat_per_kvb: u64,
    /// Lowest rate the network relays. Used only when the reporter share is
    /// too small to pay the target rate plus a non-dust reporter output.
    pub min_relay_sat_per_kvb: u64,
    /// Smallest reporter output we create; below it the whole reporter share
    /// becomes fee and output 0 is a zero-value `OP_RETURN`.
    pub dust: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        Self {
            rate_sat_per_kvb: 1_000,
            min_relay_sat_per_kvb: 100,
            dust: 1_000,
        }
    }
}

/// The exact split of one bond UTXO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split {
    pub bond: u64,
    /// ⌊bond/8⌋ = reporter + fee.
    pub reward: u64,
    /// bond − ⌊bond/8⌋, to bare `OP_RETURN`.
    pub burn: u64,
    pub fee: u64,
    /// What the reward address receives (0 in burn-only mode).
    pub reporter: u64,
    /// The share was too small for a reporter output: output 0 is a
    /// zero-value `OP_RETURN` and the whole share pays the fee. The operator
    /// still loses 7/8.
    pub burn_only: bool,
}

fn ceil_fee(vsize: u64, rate_sat_per_kvb: u64) -> u64 {
    (vsize.saturating_mul(rate_sat_per_kvb)).div_ceil(1000)
}

/// Compute the split for a bond of `bond` sats whose penalty is `vsize` vB.
pub fn split(bond: u64, vsize: u64, policy: &FeePolicy) -> Result<Split> {
    if bond == 0 {
        bail!("zero-value bond output");
    }
    let reward = bond::reward(bond);
    let burn = bond - reward;
    let target = ceil_fee(vsize, policy.rate_sat_per_kvb.max(policy.min_relay_sat_per_kvb));
    let floor = ceil_fee(vsize, policy.min_relay_sat_per_kvb);
    let s = if reward >= target.saturating_add(policy.dust) {
        Split {
            bond,
            reward,
            burn,
            fee: target,
            reporter: reward - target,
            burn_only: false,
        }
    } else if reward >= floor && reward > 0 {
        Split {
            bond,
            reward,
            burn,
            fee: reward,
            reporter: 0,
            burn_only: true,
        }
    } else {
        bail!(
            "uneconomic: reporter share {reward} sats cannot pay the minimum relay fee {floor} sats for {vsize} vB"
        );
    };
    debug_assert_eq!(s.reporter + s.fee, s.reward);
    debug_assert_eq!(s.reward + s.burn, s.bond);
    Ok(s)
}

pub struct BuiltPenalty {
    pub tx: Transaction,
    pub split: Split,
    pub vsize: u64,
}

fn satisfied(
    bond: &Bond,
    genesis: BlockHash,
    outpoint: OutPoint,
    utxo: &TxOut,
    evidence: &Evidence,
    reporter: Script,
    fee: u64,
    amount: u64,
) -> Result<Transaction> {
    let mut tx = bond
        .penalty_transaction(outpoint, amount, reporter, fee)
        .map_err(|e| anyhow!(e))?;
    let env = bond
        .environment(tx.clone(), vec![ElementsUtxo::from(utxo.clone())], 0, genesis)
        .map_err(|e| anyhow!(e))?;
    // `satisfy` EXECUTES the real covenant: an Err means the chain would reject it.
    tx.input[0].witness.script_witness = bond
        .satisfy(&env, &penalty_action(evidence))
        .map_err(|e| anyhow!("bond covenant rejects the penalty: {e}"))?;
    Ok(tx)
}

/// Build (and locally execute) the penalty spending `outpoint` (`utxo`).
pub fn build(
    bond: &Bond,
    genesis: BlockHash,
    outpoint: OutPoint,
    utxo: &TxOut,
    evidence: &Evidence,
    reporter: &Script,
    policy: &FeePolicy,
) -> Result<BuiltPenalty> {
    bond.check_evidence(evidence).map_err(|e| anyhow!(e))?;
    if utxo.script_pubkey != *bond.script_pubkey() {
        bail!("UTXO script is not this bond's script");
    }
    if utxo.asset.explicit() != Some(bond.params().fee_asset) {
        bail!("bond UTXO is not explicit fee asset");
    }
    let amount = utxo
        .value
        .explicit()
        .ok_or_else(|| anyhow!("bond UTXO amount is not explicit"))?;
    // Pass 1: measure. Explicit amounts are fixed-width, so the size only
    // depends on the reporter script.
    let probe = satisfied(
        bond,
        genesis,
        outpoint,
        utxo,
        evidence,
        reporter.clone(),
        0,
        amount,
    )?;
    let vsize = probe.vsize() as u64;
    let split = split(amount, vsize, policy)?;
    let script = if split.burn_only {
        bond::burn_script()
    } else {
        reporter.clone()
    };
    let tx = satisfied(
        bond, genesis, outpoint, utxo, evidence, script, split.fee, amount,
    )?;
    check_shape(&tx, &split, bond)?;
    Ok(BuiltPenalty { tx, split, vsize })
}

/// Belt and braces: the built transaction has exactly the planned split.
fn check_shape(tx: &Transaction, s: &Split, bond: &Bond) -> Result<()> {
    let asset = bond.params().fee_asset;
    let amt = |i: usize| tx.output.get(i).and_then(|o| o.value.explicit());
    if tx.input.len() != 1 || tx.output.len() != 3 {
        bail!("penalty must have 1 input and 3 outputs");
    }
    if tx.output.iter().any(|o| o.asset.explicit() != Some(asset)) {
        bail!("penalty output not in the fee asset");
    }
    if amt(0) != Some(s.reporter) || amt(1) != Some(s.burn) || amt(2) != Some(s.fee) {
        bail!("penalty amounts do not match the split");
    }
    if tx.output[1].script_pubkey != bond::burn_script() || !tx.output[2].is_fee() {
        bail!("penalty burn/fee outputs malformed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: FeePolicy = FeePolicy {
        rate_sat_per_kvb: 2_000,
        min_relay_sat_per_kvb: 100,
        dust: 1_000,
    };

    #[test]
    fn split_is_exact_for_many_sizes() {
        for bond in [
            1u64, 7, 8, 9, 15, 16, 1_000, 8_000, 9_999, 10_007, 80_000, 1_000_000, 8_000_000,
            123_456_789, 2_100_000_000_000_000,
        ] {
            match split(bond, 400, &P) {
                Ok(s) => {
                    assert_eq!(s.reward, bond >> 3, "{bond}");
                    assert_eq!(s.burn, bond - (bond >> 3), "{bond}");
                    assert_eq!(s.reporter + s.fee, s.reward, "{bond}");
                    assert_eq!(s.reporter + s.fee + s.burn, bond, "{bond}");
                    if !s.burn_only {
                        assert!(s.reporter >= P.dust);
                        assert_eq!(s.fee, 800);
                    }
                }
                Err(_) => assert!(bond >> 3 < 40, "only sub-relay-fee bonds fail: {bond}"),
            }
        }
    }

    #[test]
    fn tiny_bonds_near_dust() {
        // vsize 400 at 2 sat/vB = 800 fee; dust 1000 => need reward >= 1800.
        let ok = split(1_800 * 8, 400, &P).unwrap();
        assert!(!ok.burn_only);
        assert_eq!((ok.reporter, ok.fee), (1_000, 800));
        // One sat less of reward: burn-only, the whole share is fee.
        let b = split(1_799 * 8 + 7, 400, &P).unwrap();
        assert!(b.burn_only);
        assert_eq!((b.reporter, b.fee, b.reward), (0, 1_799, 1_799));
        assert_eq!(b.burn, 1_799 * 8 + 7 - 1_799);
        // Reward 40 = exactly min relay (400 vB * 0.1 sat/vB).
        let m = split(320, 400, &P).unwrap();
        assert!(m.burn_only);
        assert_eq!(m.fee, 40);
        // Reward 39: cannot relay.
        assert!(split(319, 400, &P).is_err());
        assert!(split(0, 400, &P).is_err());
        assert!(split(7, 400, &P).is_err());
    }

    #[test]
    fn target_rate_never_below_min_relay() {
        let p = FeePolicy {
            rate_sat_per_kvb: 10,
            ..P
        };
        assert_eq!(split(8_000_000, 400, &p).unwrap().fee, 40);
    }
}
