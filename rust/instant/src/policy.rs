//! Off-chain acceptance rules (SPEC.md §6, §8). These are NOT enforced by the
//! covenants; they are what honest operators and wallets check before issuing
//! or relying on a promise. Pure functions so wallets, operators and tests
//! share one implementation.
use crate::bond;

/// Blocks before a lockbox's EXPIRY at which promises stop (operator refuses,
/// wallet rejects). A promised tx must confirm within this many blocks or the
/// owner's exit path could race it. 6 blocks = ~1 hour at 10-minute blocks.
pub const PROMISE_MARGIN: u32 = 6;
/// Blocks a bond must outlive the latest lockbox expiry it backs, so a victim
/// who sees the conflicting spend by EXPIRY can still get a penalty mined.
pub const CHALLENGE_WINDOW: u32 = 144;
/// Confirmations before a bond counts.
pub const BOND_MIN_CONFIRMATIONS: u32 = 2;
/// Default lockbox lifetime for wallet balances (~12 hours).
pub const DEFAULT_LIFETIME: u32 = 72;
/// Wallet renews a lockbox (while online) once fewer blocks than this remain.
pub const RENEW_BELOW: u32 = 36;

#[derive(Clone, Debug)]
pub struct BondView {
    pub amount: u64,
    pub refund_height: u32,
    pub confirmations: u32,
    pub unspent: bool,
}

/// Slashable value of a bond net of what a self-reporting operator recovers.
pub fn effective_cover(amount: u64) -> u64 {
    amount - bond::reward(amount)
}

/// Total cover of the operator's bonds that are eligible for promises on
/// lockboxes expiring at `max_expiry`.
pub fn eligible_cover(bonds: &[BondView], max_expiry: u32) -> u64 {
    bonds
        .iter()
        .filter(|b| {
            b.unspent
                && b.confirmations >= BOND_MIN_CONFIRMATIONS
                && b.amount >= bond::MIN_BOND
                && b.refund_height >= max_expiry.saturating_add(CHALLENGE_WINDOW)
        })
        .map(|b| effective_cover(b.amount))
        .sum()
}

#[derive(Clone, Debug)]
pub struct PromiseCheck<'a> {
    pub tip: u32,
    /// EXPIRY of every input of the promised transaction that is a lockbox
    /// of THIS operator (other operators' inputs are checked against their
    /// own bonds separately).
    pub lockbox_expiries: &'a [u32],
    /// Every input of the transaction is a lockbox of some operator. A plain
    /// input can be double-spent without any promise (mixed => no instant).
    pub all_inputs_are_lockboxes: bool,
    pub bonds: &'a [BondView],
    /// Unconfirmed promised value the operator has published (and relays show).
    pub published_in_flight: u64,
    /// Native-asset valuation of what this promise newly puts at risk.
    pub value_at_risk: u64,
}

/// Returns Ok if an honest operator may sign / a wallet may show "Done".
pub fn check_promise(c: &PromiseCheck) -> Result<(), String> {
    if !c.all_inputs_are_lockboxes {
        return Err("a non-lockbox input can be double-spent: no instant guarantee".into());
    }
    let max_expiry = *c.lockbox_expiries.iter().max().ok_or("no lockbox inputs")?;
    for &expiry in c.lockbox_expiries {
        if c.tip.saturating_add(PROMISE_MARGIN) >= expiry {
            return Err(format!(
                "lockbox expires at {expiry}; promises stop {PROMISE_MARGIN} blocks before (tip {})",
                c.tip
            ));
        }
    }
    let cover = eligible_cover(c.bonds, max_expiry);
    let exposure = c
        .published_in_flight
        .checked_add(c.value_at_risk)
        .ok_or("exposure overflow")?;
    if exposure > cover {
        return Err(format!(
            "exposure {exposure} would exceed eligible bond cover {cover}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bond(amount: u64, refund_height: u32) -> BondView {
        BondView {
            amount,
            refund_height,
            confirmations: 6,
            unspent: true,
        }
    }

    fn check(
        tip: u32,
        expiries: &[u32],
        bonds: &[BondView],
        in_flight: u64,
        value: u64,
    ) -> Result<(), String> {
        check_promise(&PromiseCheck {
            tip,
            lockbox_expiries: expiries,
            all_inputs_are_lockboxes: true,
            bonds,
            published_in_flight: in_flight,
            value_at_risk: value,
        })
    }

    #[test]
    fn cover_is_net_of_reporter_share() {
        assert_eq!(effective_cover(800), 700);
        assert_eq!(
            eligible_cover(&[bond(800_000_000, 2_000)], 1_000),
            700_000_000
        );
    }

    #[test]
    fn rules() {
        let b = [bond(800_000_000, 1_000 + CHALLENGE_WINDOW)];
        check(900, &[1_000], &b, 0, 700_000_000).unwrap();
        assert!(
            check(900, &[1_000], &b, 1, 700_000_000).is_err(),
            "exposure cap"
        );
        assert!(
            check(994, &[1_000], &b, 0, 1).is_err(),
            "inside promise margin"
        );
        assert!(
            check(900, &[1_001], &b, 0, 1).is_err(),
            "bond expires too soon"
        );
        let unconfirmed = [BondView {
            confirmations: 1,
            ..bond(800_000_000, 5_000)
        }];
        assert!(check(900, &[1_000], &unconfirmed, 0, 1).is_err());
        let spent = [BondView {
            unspent: false,
            ..bond(800_000_000, 5_000)
        }];
        assert!(check(900, &[1_000], &spent, 0, 1).is_err());
        let mixed = PromiseCheck {
            tip: 900,
            lockbox_expiries: &[1_000],
            all_inputs_are_lockboxes: false,
            bonds: &b,
            published_in_flight: 0,
            value_at_risk: 1,
        };
        assert!(check_promise(&mixed).is_err());
    }
}
