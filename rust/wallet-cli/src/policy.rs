//! Signing policy (`policy.toml`, spec §6.2).
//!
//! [`evaluate`] is the single decision function; `gate::authorize_and_sign`
//! is the single signing entry point and calls it for every signature, from
//! the CLI and from MCP alike. Spend is computed from the wallet's *own*
//! recomputed review, never from caller text:
//!
//! spend(asset) = Σ |negative balance_changes(asset)| (+ fee for the policy asset)
//!
//! summed over every transaction in the approval bundle.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use bech32::segwit;
use elementsplus_wallet_core::{TxKind, TxReview};
use serde::{Deserialize, Serialize};

use crate::amount::parse_amount;

pub const WINDOW_SECS: u64 = 24 * 60 * 60;
/// Key in `[limits]` that always means the network's policy (fee) asset.
pub const POLICY_ASSET_KEY: &str = "policy";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Every signature needs a human: tty y/N on the CLI; via MCP the
    /// request is refused and parked for `epw sign --approve`.
    #[default]
    #[serde(alias = "require_confirmation")]
    Confirm,
    /// Sign without asking when every rule passes. Requires limits.
    Auto,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitSpec {
    /// Max spend in one approval (decimal in asset precision or `atomic:<n>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_tx: Option<String>,
    /// Max spend over any rolling 24 h window, including this approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_24h: Option<String>,
}

/// The on-disk policy file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default)]
    pub mode: Mode,
    /// If set, transfers (and any non-swap transaction with external
    /// outputs) may only pay these addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_recipients: Option<Vec<String>>,
    /// If set, DEX-dependent operations require the configured DEX URL to be
    /// listed. Required (non-empty) for DEX operations in auto mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_dex_urls: Option<Vec<String>>,
    /// Keyed by 64-hex asset id or `"policy"`.
    #[serde(default)]
    pub limits: BTreeMap<String, LimitSpec>,
}

pub const DEFAULT_POLICY_TOML: &str = r#"# epw signing policy (see rust/wallet-cli/README.md)
#
# mode = "confirm": every signature needs a human (tty y/N; via MCP the request
#                   is parked and approved with `epw sign <file> --approve <hash>`).
# mode = "auto":    sign without asking when all rules pass. Every spent asset
#                   must have a limit below, and DEX operations need allowed_dex_urls.
mode = "confirm"

# allowed_recipients = ["ert1q..."]
# allowed_dex_urls = ["http://127.0.0.1:8790"]

# Limits are per asset ("policy" = the network fee asset, or a 64-hex asset id).
# Amounts are decimals in the asset's precision or "atomic:<n>".
# [limits.policy]
# per_tx = "0.1"
# per_24h = "1"
"#;

impl PolicyFile {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("invalid policy.toml")
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Limit {
    pub per_tx: Option<u64>,
    pub per_24h: Option<u64>,
}

/// A policy with amounts resolved to atomic units and addresses normalized.
#[derive(Clone, Debug)]
pub struct Policy {
    pub mode: Mode,
    recipients: Option<Vec<(u8, Vec<u8>)>>,
    dex_urls: Option<Vec<String>>,
    pub limits: BTreeMap<String, Limit>,
}

/// Script identity of a segwit address, independent of its HRP (so the
/// native `elements1…` and alias `ert1…` forms of one script match).
pub fn address_program(address: &str) -> Option<(u8, Vec<u8>)> {
    let (_, version, program) = segwit::decode(address.trim()).ok()?;
    Some((version.to_u8(), program))
}

fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

impl Policy {
    /// Resolve amounts with `precision_of(asset_id)`.
    pub fn resolve(
        file: &PolicyFile,
        policy_asset: &str,
        precision_of: impl Fn(&str) -> u8,
    ) -> Result<Self> {
        let recipients = match &file.allowed_recipients {
            None => None,
            Some(list) => Some(
                list.iter()
                    .map(|a| {
                        address_program(a)
                            .with_context(|| format!("allowed_recipients: invalid address {a:?}"))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let mut limits = BTreeMap::new();
        for (key, spec) in &file.limits {
            let asset = if key == POLICY_ASSET_KEY {
                policy_asset.to_owned()
            } else if key.len() == 64 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                key.clone()
            } else {
                bail!("limits: key {key:?} must be \"policy\" or a 64-hex asset id (tickers are not trusted here)");
            };
            let precision = precision_of(&asset);
            let parse = |field: &str, value: &Option<String>| -> Result<Option<u64>> {
                value
                    .as_deref()
                    .map(|v| {
                        parse_amount(v, precision).with_context(|| format!("limits.{key}.{field}"))
                    })
                    .transpose()
            };
            let limit = Limit {
                per_tx: parse("per_tx", &spec.per_tx)?,
                per_24h: parse("per_24h", &spec.per_24h)?,
            };
            if limits.insert(asset.clone(), limit).is_some() {
                bail!("limits: asset {asset} is listed twice");
            }
        }
        Ok(Self {
            mode: file.mode,
            recipients,
            dex_urls: file
                .allowed_dex_urls
                .as_ref()
                .map(|urls| urls.iter().map(|u| normalize_url(u)).collect()),
            limits,
        })
    }
}

/// One past signature's spend, reconstructed from the audit log.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpendRecord {
    pub time: u64,
    pub spend: BTreeMap<String, u64>,
}

/// What is being signed.
pub struct Request<'a> {
    /// Reviews recomputed by the wallet core from the exact PSETs.
    pub reviews: &'a [TxReview],
    pub policy_asset: &'a str,
    pub genesis_hash: &'a str,
    /// The DEX URL this operation relies on (quote/route/post), if any.
    pub dex_url: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Decision {
    /// No rule is violated. Signing may still require confirmation.
    pub allowed: bool,
    pub mode: Mode,
    pub requires_confirmation: bool,
    /// Atomic spend of this approval per asset.
    pub spend: BTreeMap<String, String>,
    /// Atomic spend already signed within the rolling 24 h window.
    pub spent_24h: BTreeMap<String, String>,
    pub violations: Vec<String>,
    pub notes: Vec<String>,
}

/// Per-asset spend of a set of reviews (negative deltas plus the fee).
pub fn spend_of(reviews: &[TxReview], policy_asset: &str) -> Result<BTreeMap<String, u64>> {
    let mut spend: BTreeMap<String, u64> = BTreeMap::new();
    let mut add = |asset: &str, amount: u64| -> Result<()> {
        let entry = spend.entry(asset.to_owned()).or_default();
        *entry = entry.checked_add(amount).context("spend overflow")?;
        Ok(())
    };
    for review in reviews {
        for delta in &review.balance_changes {
            let value: i128 = delta
                .amount
                .parse()
                .with_context(|| format!("malformed balance change {:?}", delta.amount))?;
            if value < 0 {
                add(
                    &delta.asset_id,
                    u64::try_from(-value).context("spend overflow")?,
                )?;
            }
        }
        if review.fee > 0 {
            add(policy_asset, review.fee)?;
        }
    }
    spend.retain(|_, v| *v > 0);
    Ok(spend)
}

/// Sum of recorded spend within `[now - 24h, now]`.
pub fn window_spend(history: &[SpendRecord], now: u64) -> BTreeMap<String, u64> {
    let mut total: BTreeMap<String, u64> = BTreeMap::new();
    for record in history {
        if record.time + WINDOW_SECS > now {
            for (asset, amount) in &record.spend {
                let entry = total.entry(asset.clone()).or_default();
                *entry = entry.saturating_add(*amount);
            }
        }
    }
    total
}

fn stringify(map: &BTreeMap<String, u64>) -> BTreeMap<String, String> {
    map.iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect()
}

/// THE policy decision. Pure: no I/O, so it is exhaustively unit-tested.
pub fn evaluate(
    policy: &Policy,
    history: &[SpendRecord],
    request: &Request<'_>,
    now: u64,
) -> Decision {
    let mut violations = Vec::new();
    let mut notes = Vec::new();
    let auto = policy.mode == Mode::Auto;

    if request.reviews.is_empty() {
        violations.push("nothing to sign".into());
    }
    for review in request.reviews {
        if review.genesis_hash != request.genesis_hash {
            violations.push(format!(
                "review is for genesis {}, wallet is pinned to {}",
                review.genesis_hash, request.genesis_hash
            ));
        }
    }

    let spend = match spend_of(request.reviews, request.policy_asset) {
        Ok(spend) => spend,
        Err(error) => {
            violations.push(format!("cannot compute spend: {error}"));
            BTreeMap::new()
        }
    };
    let spent_24h = window_spend(history, now);

    for (asset, amount) in &spend {
        let label = if asset == request.policy_asset {
            format!("{asset} (policy asset)")
        } else {
            asset.clone()
        };
        match policy.limits.get(asset) {
            None => {
                if auto {
                    violations.push(format!(
                        "auto mode: no limit configured for {label}; add [limits] to policy.toml"
                    ));
                }
            }
            Some(limit) => {
                if auto && limit.per_tx.is_none() && limit.per_24h.is_none() {
                    violations.push(format!(
                        "auto mode: limit for {label} sets neither per_tx nor per_24h"
                    ));
                }
                if let Some(max) = limit.per_tx {
                    if *amount > max {
                        violations.push(format!(
                            "per-transaction limit for {label}: spending {amount} > {max} (atomic)"
                        ));
                    }
                }
                if let Some(max) = limit.per_24h {
                    let before = spent_24h.get(asset).copied().unwrap_or(0);
                    let total = before.saturating_add(*amount);
                    if total > max {
                        violations.push(format!(
                            "24h limit for {label}: {before} already signed + {amount} = {total} > {max} (atomic)"
                        ));
                    }
                }
            }
        }
    }

    if let Some(allowed) = &policy.recipients {
        for review in request.reviews {
            // Maker outputs of a DEX-routed take are exempt; a take without
            // DEX context (e.g. a hand-made bundle) is treated like a transfer.
            if review.kind == TxKind::SwapTake && request.dex_url.is_some() {
                if !review.external_outputs.is_empty() {
                    notes.push(
                        "swap maker outputs are exempt from allowed_recipients (bounded by limits and allowed_dex_urls)"
                            .into(),
                    );
                }
                continue;
            }
            for output in &review.external_outputs {
                let ok = address_program(&output.address).is_some_and(|p| allowed.contains(&p));
                if !ok {
                    violations.push(format!(
                        "recipient {} is not in allowed_recipients",
                        output.address
                    ));
                }
            }
        }
    }

    if let Some(dex) = request.dex_url {
        let dex = normalize_url(dex);
        match &policy.dex_urls {
            Some(list) if !list.is_empty() => {
                if !list.contains(&dex) {
                    violations.push(format!("DEX {dex} is not in allowed_dex_urls"));
                }
            }
            _ => {
                if auto {
                    violations.push("auto mode: DEX operations require allowed_dex_urls".into());
                } else {
                    notes.push("allowed_dex_urls is not set; relying on confirmation".into());
                }
            }
        }
    }

    let allowed = violations.is_empty();
    Decision {
        allowed,
        mode: policy.mode,
        requires_confirmation: allowed && policy.mode == Mode::Confirm,
        spend: stringify(&spend),
        spent_24h: stringify(&spent_24h),
        violations,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elementsplus_wallet_core::{AssetDelta, ExternalOutput, SIGHASH_ALL};

    const POLICY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const GENESIS: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    fn addr(byte: u8) -> String {
        segwit::encode_v0(bech32::Hrp::parse("ert").unwrap(), &[byte; 20]).unwrap()
    }

    fn precision(asset: &str) -> u8 {
        if asset == POLICY {
            8
        } else {
            0
        }
    }

    fn review(
        kind: TxKind,
        deltas: &[(&str, i64)],
        fee: u64,
        external: &[(&str, &str, u64)],
    ) -> TxReview {
        TxReview {
            kind,
            network: "test".into(),
            genesis_hash: GENESIS.into(),
            balance_changes: deltas
                .iter()
                .map(|(a, v)| AssetDelta {
                    asset_id: (*a).into(),
                    amount: v.to_string(),
                })
                .collect(),
            fee,
            external_outputs: external
                .iter()
                .map(|(address, asset, amount)| ExternalOutput {
                    address: (*address).into(),
                    asset_id: (*asset).into(),
                    amount: *amount,
                    confidential: false,
                })
                .collect(),
            inputs_signed: vec![],
            foreign_inputs: vec![],
            issuance: None,
            sighash: SIGHASH_ALL.into(),
            confidential: false,
        }
    }

    fn policy(text: &str) -> Policy {
        Policy::resolve(&PolicyFile::parse(text).unwrap(), POLICY, precision).unwrap()
    }

    fn request<'a>(reviews: &'a [TxReview], dex: Option<&'a str>) -> Request<'a> {
        Request {
            reviews,
            policy_asset: POLICY,
            genesis_hash: GENESIS,
            dex_url: dex,
        }
    }

    fn send(amount: i64, fee: u64) -> TxReview {
        review(
            TxKind::Transfer,
            &[(POLICY, -amount)],
            fee,
            &[(&addr(1), POLICY, amount as u64)],
        )
    }

    #[test]
    fn default_policy_is_confirm_without_limits() {
        let p = policy("");
        assert_eq!(p.mode, Mode::Confirm);
        let reviews = [send(1_000, 200)];
        let d = evaluate(&p, &[], &request(&reviews, None), 0);
        assert!(d.allowed);
        assert!(d.requires_confirmation);
        assert_eq!(d.spend[POLICY], "1200");
    }

    #[test]
    fn auto_mode_refuses_until_limits_exist() {
        let reviews = [send(1_000, 200)];
        let d = evaluate(&policy("mode = \"auto\""), &[], &request(&reviews, None), 0);
        assert!(!d.allowed);
        assert!(
            d.violations[0].contains("no limit configured"),
            "{:?}",
            d.violations
        );

        let p = policy("mode = \"auto\"\n[limits.policy]\nper_tx = \"0.0001\"\n");
        let d = evaluate(&p, &[], &request(&reviews, None), 0);
        assert!(d.allowed, "{:?}", d.violations);
        assert!(!d.requires_confirmation);

        // An empty limit table does not count as a limit.
        let p = policy("mode = \"auto\"\n[limits.policy]\n");
        assert!(!evaluate(&p, &[], &request(&reviews, None), 0).allowed);
    }

    #[test]
    fn per_tx_limit_includes_fee_and_sums_bundle() {
        // 0.00001 ECX = 1000 atomic.
        let p = policy("mode = \"auto\"\n[limits.policy]\nper_tx = \"atomic:1200\"\n");
        let ok = [send(1_000, 200)];
        assert!(evaluate(&p, &[], &request(&ok, None), 0).allowed);
        let over = [send(1_000, 201)];
        let d = evaluate(&p, &[], &request(&over, None), 0);
        assert!(!d.allowed);
        assert!(d.violations[0].contains("per-transaction"));
        // A bundle (split + offer) is one approval: spends are summed.
        let bundle = [send(600, 100), send(400, 101)];
        assert!(!evaluate(&p, &[], &request(&bundle, None), 0).allowed);
    }

    #[test]
    fn rolling_window_counts_only_last_24h() {
        let p = policy("mode = \"auto\"\n[limits.policy]\nper_24h = \"atomic:5000\"\n");
        let now = 1_000_000;
        let history = vec![
            SpendRecord {
                time: now - WINDOW_SECS - 1, // expired
                spend: BTreeMap::from([(POLICY.to_string(), 4_000)]),
            },
            SpendRecord {
                time: now - 60,
                spend: BTreeMap::from([(POLICY.to_string(), 3_000)]),
            },
            SpendRecord {
                time: now - 30,
                spend: BTreeMap::from([(TOKEN.to_string(), 99)]),
            },
        ];
        let ok = [send(1_800, 200)]; // 3000 + 2000 = 5000
        let d = evaluate(&p, &history, &request(&ok, None), now);
        assert!(d.allowed, "{:?}", d.violations);
        assert_eq!(d.spent_24h[POLICY], "3000");
        let over = [send(1_801, 200)];
        let d = evaluate(&p, &history, &request(&over, None), now);
        assert!(!d.allowed);
        assert!(d.violations[0].contains("24h limit"));
    }

    #[test]
    fn limits_apply_in_confirm_mode_too() {
        let p = policy("[limits.policy]\nper_tx = \"atomic:10\"\n");
        let reviews = [send(1_000, 200)];
        let d = evaluate(&p, &[], &request(&reviews, None), 0);
        assert!(!d.allowed);
        assert!(!d.requires_confirmation);
    }

    #[test]
    fn every_spent_asset_needs_a_limit_in_auto_mode() {
        let p = policy("mode = \"auto\"\n[limits.policy]\nper_tx = \"1\"\n");
        // Swap take: pay token, receive policy asset.
        let take = [review(
            TxKind::SwapTake,
            &[(TOKEN, -50), (POLICY, 1_000)],
            300,
            &[],
        )];
        let d = evaluate(&p, &[], &request(&take, Some("http://dex")), 0);
        assert!(!d.allowed);
        assert!(d.violations.iter().any(|v| v.contains(TOKEN)));
        let p = policy(&format!(
            "mode = \"auto\"\nallowed_dex_urls = [\"http://dex/\"]\n[limits.policy]\nper_tx = \"1\"\n[limits.{TOKEN}]\nper_tx = \"50\"\n"
        ));
        let d = evaluate(&p, &[], &request(&take, Some("http://DEX")), 0);
        assert!(d.allowed, "{:?}", d.violations);
        assert_eq!(d.spend[TOKEN], "50");
        assert_eq!(
            d.spend[POLICY], "300",
            "received assets do not offset the fee"
        );
    }

    #[test]
    fn recipient_allowlist_matches_script_not_hrp() {
        let alice = addr(1);
        let bob = addr(2);
        let p = policy(&format!("allowed_recipients = [\"{alice}\"]"));
        let reviews = [send(1_000, 200)];
        assert!(evaluate(&p, &[], &request(&reviews, None), 0).allowed);
        let to_bob = [review(
            TxKind::Transfer,
            &[(POLICY, -1)],
            1,
            &[(&bob, POLICY, 1)],
        )];
        let d = evaluate(&p, &[], &request(&to_bob, None), 0);
        assert!(!d.allowed);
        assert!(d.violations[0].contains("allowed_recipients"));
        // Same witness program under another HRP is the same script.
        let (_, _, program) = segwit::decode(&alice).unwrap();
        let other = segwit::encode_v0(bech32::Hrp::parse("elements").unwrap(), &program).unwrap();
        let alias = [review(
            TxKind::Transfer,
            &[(POLICY, -1)],
            1,
            &[(&other, POLICY, 1)],
        )];
        assert!(evaluate(&p, &[], &request(&alias, None), 0).allowed);
        // DEX-routed swap takes pay makers; they are governed by the DEX
        // allowlist instead. Without DEX context the allowlist applies.
        let take = [review(
            TxKind::SwapTake,
            &[(POLICY, -5)],
            1,
            &[(&bob, POLICY, 5)],
        )];
        assert!(evaluate(&p, &[], &request(&take, Some("http://dex")), 0).allowed);
        assert!(!evaluate(&p, &[], &request(&take, None), 0).allowed);
        // Bad allowlist entries are rejected at load time.
        assert!(Policy::resolve(
            &PolicyFile::parse("allowed_recipients = [\"nope\"]").unwrap(),
            POLICY,
            precision
        )
        .is_err());
    }

    #[test]
    fn dex_allowlist() {
        let reviews = [send(1, 1)];
        let confirm = policy("");
        let d = evaluate(&confirm, &[], &request(&reviews, Some("http://evil")), 0);
        assert!(d.allowed && d.requires_confirmation);
        let listed = policy("allowed_dex_urls = [\"http://good\"]");
        assert!(!evaluate(&listed, &[], &request(&reviews, Some("http://evil")), 0).allowed);
        assert!(evaluate(&listed, &[], &request(&reviews, Some("http://good/")), 0).allowed);
        let auto = policy("mode = \"auto\"\n[limits.policy]\nper_tx = \"1\"\n");
        assert!(!evaluate(&auto, &[], &request(&reviews, Some("http://good")), 0).allowed);
        assert!(evaluate(&auto, &[], &request(&reviews, None), 0).allowed);
    }

    #[test]
    fn genesis_mismatch_and_empty_requests_are_refused() {
        let p = policy("");
        let mut other = send(1, 1);
        other.genesis_hash = TOKEN.into();
        assert!(!evaluate(&p, &[], &request(&[other], None), 0).allowed);
        assert!(!evaluate(&p, &[], &request(&[], None), 0).allowed);
    }

    #[test]
    fn policy_file_validation() {
        assert!(PolicyFile::parse("mode = \"yolo\"").is_err());
        assert!(PolicyFile::parse("unknown = 1").is_err());
        assert_eq!(
            PolicyFile::parse("mode = \"require_confirmation\"")
                .unwrap()
                .mode,
            Mode::Confirm
        );
        let ticker_key = PolicyFile::parse("[limits.ECX]\nper_tx = \"1\"").unwrap();
        assert!(Policy::resolve(&ticker_key, POLICY, precision).is_err());
        let too_precise =
            PolicyFile::parse(&format!("[limits.{TOKEN}]\nper_tx = \"1.5\"")).unwrap();
        assert!(Policy::resolve(&too_precise, POLICY, precision).is_err());
        let p = policy("[limits.policy]\nper_tx = \"1.5\"\nper_24h = \"atomic:7\"");
        assert_eq!(
            p.limits[POLICY],
            Limit {
                per_tx: Some(150_000_000),
                per_24h: Some(7)
            }
        );
        assert!(PolicyFile::parse(DEFAULT_POLICY_TOML).unwrap() == PolicyFile::default());
    }
}
