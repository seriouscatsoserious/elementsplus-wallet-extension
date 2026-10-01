//! Append-only JSONL audit log. Rolling-window spend for the policy is
//! reconstructed from `"signed"` entries, so the log is also policy state:
//! an unreadable log fails closed.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::policy::SpendRecord;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp (civil-from-days, no external crates).
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Append one entry; `time`/`time_iso` are added if absent.
pub fn append(path: &Path, mut entry: Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        crate::config::create_private_dir(parent)?;
    }
    if entry.get("time").is_none() {
        let t = now();
        entry["time"] = t.into();
        entry["time_iso"] = iso8601(t).into();
    }
    let mut options = fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open audit log {}", path.display()))?;
    let mut line = serde_json::to_vec(&entry)?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_data()?;
    Ok(())
}

pub fn read(path: &Path) -> Result<Vec<Value>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("cannot read audit log {}", path.display()))
        }
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(n, line)| {
            serde_json::from_str(line).with_context(|| {
                format!(
                    "audit log line {} is corrupt; refusing to compute limits",
                    n + 1
                )
            })
        })
        .collect()
}

/// Spend history from `"signed"` entries.
pub fn spend_history(path: &Path) -> Result<Vec<SpendRecord>> {
    let mut records = Vec::new();
    for entry in read(path)? {
        if entry["event"] != "signed" {
            continue;
        }
        let time = entry["time"].as_u64().context("audit entry without time")?;
        let mut spend = BTreeMap::new();
        if let Some(map) = entry["spend"].as_object() {
            for (asset, amount) in map {
                let amount = amount
                    .as_str()
                    .and_then(|a| a.parse::<u64>().ok())
                    .context("audit entry has a malformed spend amount")?;
                spend.insert(asset.clone(), amount);
            }
        }
        records.push(SpendRecord { time, spend });
    }
    Ok(records)
}

/// txid → kind, from signed entries (for labelling history).
pub fn kinds_by_txid(path: &Path) -> BTreeMap<String, String> {
    read(path)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e["event"] == "signed")
        .filter_map(|e| {
            Some((
                e["txid"].as_str()?.to_owned(),
                e["kind"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_790_000_000), "2026-09-21T14:13:20Z");
    }

    #[test]
    fn append_and_reconstruct_spend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        append(
            &path,
            serde_json::json!({"event": "refused", "spend": {"aa": "5"}}),
        )
        .unwrap();
        append(
            &path,
            serde_json::json!({"event": "signed", "time": 10, "kind": "transfer", "txid": "t1", "spend": {"aa": "7"}}),
        )
        .unwrap();
        let history = spend_history(&path).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].time, 10);
        assert_eq!(history[0].spend["aa"], 7);
        assert_eq!(kinds_by_txid(&path)["t1"], "transfer");
        // A corrupt line fails closed.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{oops\n")
            .unwrap();
        assert!(spend_history(&path).is_err());
    }
}
