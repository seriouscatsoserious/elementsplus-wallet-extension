//! Amount parsing and formatting.
//!
//! User-facing amounts are either decimals scaled by the asset precision
//! (`"1.5"` with precision 8 = 150 000 000 atomic units) or explicit atomic
//! units (`"atomic:150000000"`). Nothing ever goes through a float.

use anyhow::{bail, Result};
use elementsplus_wallet_core::amount::parse_decimal_u64;
use elementsplus_wallet_core::MAX_MONEY;

/// Parse a user amount for an asset with `precision` decimal places.
/// The result is non-zero and within the Elements money range.
pub fn parse_amount(text: &str, precision: u8) -> Result<u64> {
    let text = text.trim();
    let value = if let Some(atomic) = text.strip_prefix("atomic:") {
        match parse_decimal_u64(atomic) {
            Some(value) => value,
            None => {
                bail!("invalid atomic amount {atomic:?}: expected a canonical unsigned integer")
            }
        }
    } else {
        parse_decimal(text, precision)?
    };
    if value == 0 {
        bail!("amount must be greater than zero");
    }
    if value > MAX_MONEY {
        bail!("amount {value} exceeds the money range");
    }
    Ok(value)
}

fn parse_decimal(text: &str, precision: u8) -> Result<u64> {
    if text.is_empty() {
        bail!("amount is empty");
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || !digits(whole)
        || !digits(fraction)
        || (text.contains('.') && fraction.is_empty())
    {
        bail!("invalid amount {text:?}: use a plain decimal like 1.25 or atomic:<n>");
    }
    if fraction.len() > usize::from(precision) {
        bail!(
            "amount {text:?} has more than {precision} decimal place(s) for this asset; use atomic:<n> for raw units"
        );
    }
    let scale = 10u128.pow(u32::from(precision));
    let whole_value: u128 = whole
        .parse::<u128>()
        .map_err(|_| anyhow::anyhow!("amount {text:?} is too large"))?;
    let mut fraction_value: u128 = 0;
    if !fraction.is_empty() {
        fraction_value = fraction
            .parse::<u128>()
            .map_err(|_| anyhow::anyhow!("bad fraction"))?
            * 10u128.pow(u32::from(precision) - fraction.len() as u32);
    }
    let total = whole_value
        .checked_mul(scale)
        .and_then(|v| v.checked_add(fraction_value))
        .filter(|v| *v <= u128::from(u64::MAX))
        .ok_or_else(|| anyhow::anyhow!("amount {text:?} is too large"))?;
    Ok(total as u64)
}

/// Format atomic units with `precision` decimals, trimming trailing zeros.
pub fn format_amount(atomic: u64, precision: u8) -> String {
    format_u128(u128::from(atomic), precision)
}

fn format_u128(atomic: u128, precision: u8) -> String {
    if precision == 0 {
        return atomic.to_string();
    }
    let scale = 10u128.pow(u32::from(precision));
    let whole = atomic / scale;
    let fraction = atomic % scale;
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:0width$}", width = usize::from(precision));
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// Format a signed decimal string of atomic units (as found in reviews).
pub fn format_signed(atomic: &str, precision: u8) -> String {
    let (sign, digits) = match atomic.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("+", atomic.strip_prefix('+').unwrap_or(atomic)),
    };
    match digits.parse::<u128>() {
        Ok(value) => format!("{sign}{}", format_u128(value, precision)),
        Err(_) => atomic.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_scale_by_precision() {
        assert_eq!(parse_amount("1", 8).unwrap(), 100_000_000);
        assert_eq!(parse_amount("1.5", 8).unwrap(), 150_000_000);
        assert_eq!(parse_amount("0.00000001", 8).unwrap(), 1);
        assert_eq!(parse_amount("12", 0).unwrap(), 12);
        assert_eq!(parse_amount("0.25", 2).unwrap(), 25);
        assert_eq!(parse_amount("007", 0).unwrap(), 7);
    }

    #[test]
    fn atomic_prefix_bypasses_precision() {
        assert_eq!(parse_amount("atomic:150000000", 8).unwrap(), 150_000_000);
        assert_eq!(parse_amount("atomic:5", 0).unwrap(), 5);
        assert!(parse_amount("atomic:1.5", 8).is_err());
        assert!(parse_amount("atomic:-1", 8).is_err());
        assert!(parse_amount("atomic:01", 8).is_err());
        assert!(parse_amount("atomic:", 8).is_err());
    }

    #[test]
    fn rejects_malformed_and_out_of_range() {
        for bad in [
            "", "-1", "+1", "1e8", "1.", ".5", "1.2.3", "abc", " ", "1,5", "0", "0.0", "NaN",
        ] {
            assert!(parse_amount(bad, 8).is_err(), "{bad:?} accepted");
        }
        // Too many decimals for the asset precision.
        assert!(parse_amount("1.123456789", 8).is_err());
        assert!(parse_amount("1.5", 0).is_err());
        // Above MAX_MONEY.
        assert!(parse_amount("21000001", 8).is_err());
        assert!(parse_amount("99999999999999999999999999", 0).is_err());
        assert!(parse_amount("atomic:18446744073709551615", 0).is_err());
    }

    #[test]
    fn formatting_round_trips() {
        assert_eq!(format_amount(150_000_000, 8), "1.5");
        assert_eq!(format_amount(1, 8), "0.00000001");
        assert_eq!(format_amount(100_000_000, 8), "1");
        assert_eq!(format_amount(42, 0), "42");
        assert_eq!(format_signed("-150000000", 8), "-1.5");
        assert_eq!(format_signed("25", 2), "+0.25");
        for (value, precision) in [(1u64, 8u8), (123_456_789, 8), (5, 0), (1_000, 3)] {
            let text = format_amount(value, precision);
            assert_eq!(parse_amount(&text, precision).unwrap(), value);
        }
    }
}
