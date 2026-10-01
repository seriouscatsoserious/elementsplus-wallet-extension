//! Serde helpers for atomic amounts.
//!
//! Amounts cross JSON boundaries as decimal strings of atomic units so that
//! JavaScript never rounds them through an IEEE-754 double. For backwards
//! compatibility the deserializers also accept a non-negative JSON integer,
//! but never a float, sign, exponent, or leading zero.

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

/// Parse a canonical unsigned decimal string.
pub fn parse_decimal_u64(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > 20
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

struct U64Visitor;

impl Visitor<'_> for U64Visitor {
    type Value = u64;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("an unsigned integer or canonical decimal string")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<u64, E> {
        Ok(value)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<u64, E> {
        u64::try_from(value).map_err(|_| E::custom("amount must not be negative"))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<u64, E> {
        Err(E::custom("amount must be an integer, not a float"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<u64, E> {
        parse_decimal_u64(value).ok_or_else(|| E::custom("amount is not a canonical u64 decimal"))
    }
}

/// `u64` serialized as a decimal string, deserialized from string or integer.
pub mod string {
    use super::*;

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        deserializer.deserialize_any(U64Visitor)
    }
}

/// `u64` serialized as a JSON number, deserialized from string or integer.
pub mod number {
    use super::*;

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(*value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        deserializer.deserialize_any(U64Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct Wrapper {
        #[serde(with = "string")]
        v: u64,
    }

    #[test]
    fn decimal_parsing_is_canonical() {
        assert_eq!(parse_decimal_u64("0"), Some(0));
        assert_eq!(parse_decimal_u64("18446744073709551615"), Some(u64::MAX));
        for bad in [
            "",
            "01",
            "-1",
            "+1",
            "1.0",
            "1e3",
            " 1",
            "18446744073709551616",
        ] {
            assert_eq!(parse_decimal_u64(bad), None, "{bad}");
        }
    }

    #[test]
    fn serde_accepts_strings_and_integers_only() {
        let a: Wrapper = serde_json::from_str(r#"{"v":"2500000"}"#).unwrap();
        assert_eq!(a.v, 2_500_000);
        let b: Wrapper = serde_json::from_str(r#"{"v":7}"#).unwrap();
        assert_eq!(b.v, 7);
        assert!(serde_json::from_str::<Wrapper>(r#"{"v":1.5}"#).is_err());
        assert!(serde_json::from_str::<Wrapper>(r#"{"v":-1}"#).is_err());
        assert!(serde_json::from_str::<Wrapper>(r#"{"v":"-1"}"#).is_err());
        assert_eq!(
            serde_json::to_string(&Wrapper { v: u64::MAX }).unwrap(),
            r#"{"v":"18446744073709551615"}"#
        );
    }
}
