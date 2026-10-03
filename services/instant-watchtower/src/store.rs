//! Durable state (SQLite, WAL, `synchronous=FULL`).
//!
//! Everything the watchtower decides is derivable from this file, so a crash
//! at any point resumes cleanly: verified promises, evidence, discovered bonds,
//! the exact penalty bytes per bond (written BEFORE the first broadcast, keyed
//! by the bond outpoint so a bond is never built twice), and source cursors.
use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use elementsplus_instant::{
    bond::{Evidence, Promise},
    elements::{secp256k1_zkp::XOnlyPublicKey, AssetId, BlockHash, OutPoint},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::model::{fmt_outpoint, parse_outpoint, parse_xonly, VerifiedPromise};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS promises(
  operator TEXT NOT NULL, lockbox TEXT NOT NULL, commitment TEXT NOT NULL,
  sig TEXT NOT NULL, txid TEXT, source TEXT NOT NULL, first_seen INTEGER NOT NULL,
  PRIMARY KEY(operator, lockbox, commitment));
CREATE TABLE IF NOT EXISTS watches(
  operator TEXT NOT NULL, lockbox TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  spender TEXT, note TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL,
  PRIMARY KEY(operator, lockbox));
CREATE TABLE IF NOT EXISTS evidence(
  operator TEXT NOT NULL, lockbox TEXT NOT NULL,
  c1 TEXT NOT NULL, s1 TEXT NOT NULL, c2 TEXT NOT NULL, s2 TEXT NOT NULL,
  source TEXT NOT NULL, found_at INTEGER NOT NULL,
  PRIMARY KEY(operator, lockbox));
CREATE TABLE IF NOT EXISTS announcements(
  operator TEXT PRIMARY KEY, sequence INTEGER NOT NULL, json TEXT NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS refund_hints(
  operator TEXT NOT NULL, refund_height INTEGER NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY(operator, refund_height));
CREATE TABLE IF NOT EXISTS bonds(
  outpoint TEXT PRIMARY KEY, operator TEXT NOT NULL, refund_height INTEGER NOT NULL,
  amount INTEGER NOT NULL, status TEXT NOT NULL, spender TEXT, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS penalties(
  bond TEXT PRIMARY KEY, operator TEXT NOT NULL, lockbox TEXT NOT NULL,
  txid TEXT NOT NULL, hex TEXT NOT NULL, amount INTEGER NOT NULL, reward INTEGER NOT NULL,
  burn INTEGER NOT NULL, fee INTEGER NOT NULL, reporter INTEGER NOT NULL, burn_only INTEGER NOT NULL,
  status TEXT NOT NULL, height INTEGER, block_hash TEXT, spender TEXT,
  attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cursors(source TEXT PRIMARY KEY, seq INTEGER NOT NULL);
"#;

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PenaltyRow {
    pub bond: OutPoint,
    pub operator: String,
    pub lockbox: String,
    pub txid: String,
    pub hex: String,
    pub amount: u64,
    pub reward: u64,
    pub burn: u64,
    pub fee: u64,
    pub reporter: u64,
    pub burn_only: bool,
    pub status: String,
    pub height: Option<u32>,
    pub block_hash: Option<String>,
    pub spender: Option<String>,
    pub attempts: u32,
    pub last_error: Option<String>,
}

/// Penalty lifecycle. `built` rows exist before any broadcast attempt.
pub mod status {
    pub const BUILT: &str = "built";
    pub const BROADCAST: &str = "broadcast";
    pub const CONFIRMED: &str = "confirmed";
    pub const FINAL: &str = "final";
    /// Bond spent by someone else (front-run, other watchtower, refund).
    pub const LOST: &str = "lost";
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondRow {
    pub outpoint: OutPoint,
    pub operator: XOnlyPublicKey,
    pub refund_height: u32,
    pub amount: u64,
    pub status: String,
}

fn ev_from_row(r: &rusqlite::Row) -> rusqlite::Result<(String, String, [String; 4])> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        [r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?],
    ))
}

fn h<const N: usize>(s: &str) -> Result<[u8; N]> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("bad stored hex length"))
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        Self::init(conn)
    }

    pub fn memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Bind the database to one chain. Refuses a mismatch forever after.
    pub fn pin_chain(&self, genesis: BlockHash, fee_asset: AssetId) -> Result<()> {
        let c = self.c();
        for (k, v) in [
            ("genesis", genesis.to_string()),
            ("fee_asset", fee_asset.to_string()),
        ] {
            let old: Option<String> = c
                .query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
                .optional()?;
            match old {
                Some(o) if o != v => bail!("database is pinned to {k} {o}, but the chain has {v}"),
                Some(_) => {}
                None => {
                    c.execute("INSERT INTO meta(key,value) VALUES(?1,?2)", params![k, v])?;
                }
            }
        }
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// Store a VERIFIED promise. Returns `(is_new, conflicting promise)`: the
    /// earliest stored promise by the same key for the same lockbox with a
    /// different commitment, if any. Also opens a chain watch for the lockbox.
    pub fn add_promise(
        &self,
        p: &VerifiedPromise,
        txid: Option<&str>,
        source: &str,
    ) -> Result<(bool, Option<Promise>)> {
        let c = self.c();
        let (op, lb) = (p.operator.to_string(), fmt_outpoint(&p.lockbox));
        let n = c.execute(
            "INSERT OR IGNORE INTO promises(operator,lockbox,commitment,sig,txid,source,first_seen)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                op,
                lb,
                hex::encode(p.promise.commitment),
                hex::encode(p.promise.signature),
                txid,
                source,
                now()
            ],
        )?;
        c.execute(
            "INSERT OR IGNORE INTO watches(operator,lockbox,created,updated) VALUES(?1,?2,?3,?3)",
            params![op, lb, now()],
        )?;
        let other: Option<(String, String)> = c
            .query_row(
                "SELECT commitment, sig FROM promises WHERE operator=?1 AND lockbox=?2 AND commitment<>?3
                 ORDER BY first_seen, rowid LIMIT 1",
                params![op, lb, hex::encode(p.promise.commitment)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let other = other
            .map(|(cm, s)| -> Result<Promise> {
                Ok(Promise {
                    commitment: h(&cm)?,
                    signature: h(&s)?,
                })
            })
            .transpose()?;
        Ok((n == 1, other))
    }

    pub fn commitments_for(&self, operator: &XOnlyPublicKey, lockbox: &OutPoint) -> Result<Vec<[u8; 32]>> {
        let c = self.c();
        let mut st =
            c.prepare("SELECT commitment FROM promises WHERE operator=?1 AND lockbox=?2")?;
        let rows = st
            .query_map(params![operator.to_string(), fmt_outpoint(lockbox)], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter().map(|s| h(s)).collect()
    }

    pub fn promise_count(&self) -> Result<u64> {
        Ok(self
            .c()
            .query_row("SELECT COUNT(*) FROM promises", [], |r| r.get::<_, i64>(0))? as u64)
    }

    /// Persist evidence (first one per (operator, lockbox) wins). Returns true if new.
    pub fn add_evidence(&self, operator: &XOnlyPublicKey, e: &Evidence, source: &str) -> Result<bool> {
        let n = self.c().execute(
            "INSERT OR IGNORE INTO evidence(operator,lockbox,c1,s1,c2,s2,source,found_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                operator.to_string(),
                fmt_outpoint(&e.lockbox),
                hex::encode(e.first.commitment),
                hex::encode(e.first.signature),
                hex::encode(e.second.commitment),
                hex::encode(e.second.signature),
                source,
                now()
            ],
        )?;
        Ok(n == 1)
    }

    /// All evidence, oldest first.
    pub fn evidence(&self) -> Result<Vec<(XOnlyPublicKey, Evidence)>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT operator,lockbox,c1,s1,c2,s2 FROM evidence ORDER BY found_at, rowid",
        )?;
        let rows = st
            .query_map([], ev_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(op, lb, [c1, s1, c2, s2])| {
                Ok((
                    parse_xonly(&op)?,
                    Evidence {
                        lockbox: parse_outpoint(&lb)?,
                        first: Promise {
                            commitment: h(&c1)?,
                            signature: h(&s1)?,
                        },
                        second: Promise {
                            commitment: h(&c2)?,
                            signature: h(&s2)?,
                        },
                    },
                ))
            })
            .collect()
    }

    pub fn open_watches(&self) -> Result<Vec<(XOnlyPublicKey, OutPoint, i64)>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT operator, lockbox, created FROM watches WHERE status='open' ORDER BY created",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(o, l, t)| Ok((parse_xonly(&o)?, parse_outpoint(&l)?, t)))
            .collect()
    }

    pub fn resolve_watch(
        &self,
        operator: &XOnlyPublicKey,
        lockbox: &OutPoint,
        status: &str,
        spender: Option<&str>,
        note: &str,
    ) -> Result<()> {
        self.c().execute(
            "UPDATE watches SET status=?3, spender=?4, note=?5, updated=?6 WHERE operator=?1 AND lockbox=?2",
            params![operator.to_string(), fmt_outpoint(lockbox), status, spender, note, now()],
        )?;
        Ok(())
    }

    pub fn watch_status(&self, operator: &XOnlyPublicKey, lockbox: &OutPoint) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row(
                "SELECT status FROM watches WHERE operator=?1 AND lockbox=?2",
                params![operator.to_string(), fmt_outpoint(lockbox)],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Keep the highest-sequence verified announcement per operator. Returns
    /// true if it replaced an older one (or was the first).
    pub fn upsert_announcement(&self, operator: &XOnlyPublicKey, sequence: u64, json: &Value) -> Result<bool> {
        let c = self.c();
        let old: Option<i64> = c
            .query_row(
                "SELECT sequence FROM announcements WHERE operator=?1",
                [operator.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let seq = i64::try_from(sequence).map_err(|_| anyhow!("sequence too large"))?;
        if old.is_some_and(|o| o >= seq) {
            return Ok(false);
        }
        c.execute(
            "INSERT INTO announcements(operator,sequence,json,updated) VALUES(?1,?2,?3,?4)
             ON CONFLICT(operator) DO UPDATE SET sequence=?2, json=?3, updated=?4",
            params![operator.to_string(), seq, json.to_string(), now()],
        )?;
        Ok(true)
    }

    pub fn announcements(&self) -> Result<Vec<Value>> {
        let c = self.c();
        let mut st = c.prepare("SELECT json FROM announcements ORDER BY operator")?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.iter()
            .map(|s| Ok(serde_json::from_str(s)?))
            .collect()
    }

    pub fn add_refund_hint(&self, operator: &XOnlyPublicKey, height: u32, source: &str) -> Result<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO refund_hints(operator,refund_height,source) VALUES(?1,?2,?3)",
            params![operator.to_string(), height, source],
        )?;
        Ok(())
    }

    pub fn refund_hints(&self, operator: &XOnlyPublicKey) -> Result<Vec<u32>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT refund_height FROM refund_hints WHERE operator=?1 ORDER BY refund_height",
        )?;
        let rows = st
            .query_map([operator.to_string()], |r| r.get::<_, u32>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_bond(&self, b: &BondRow, spender: Option<&str>) -> Result<()> {
        self.c().execute(
            "INSERT INTO bonds(outpoint,operator,refund_height,amount,status,spender,updated)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(outpoint) DO UPDATE SET status=?5, spender=?6, amount=?4, updated=?7",
            params![
                fmt_outpoint(&b.outpoint),
                b.operator.to_string(),
                b.refund_height,
                b.amount as i64,
                b.status,
                spender,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn bonds(&self, operator: Option<&XOnlyPublicKey>) -> Result<Vec<BondRow>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT outpoint,operator,refund_height,amount,status FROM bonds
             WHERE (?1 IS NULL OR operator=?1) ORDER BY outpoint",
        )?;
        let rows = st
            .query_map([operator.map(|o| o.to_string())], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(o, k, rh, a, s)| {
                Ok(BondRow {
                    outpoint: parse_outpoint(&o)?,
                    operator: parse_xonly(&k)?,
                    refund_height: rh,
                    amount: a as u64,
                    status: s,
                })
            })
            .collect()
    }

    /// Insert a freshly built penalty unless one already exists for this bond.
    /// Returns the row that is now authoritative (ours or the earlier one).
    pub fn insert_penalty(&self, row: &PenaltyRow) -> Result<PenaltyRow> {
        self.c().execute(
            "INSERT OR IGNORE INTO penalties(bond,operator,lockbox,txid,hex,amount,reward,burn,fee,reporter,burn_only,status,created,updated)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
            params![
                fmt_outpoint(&row.bond),
                row.operator,
                row.lockbox,
                row.txid,
                row.hex,
                row.amount as i64,
                row.reward as i64,
                row.burn as i64,
                row.fee as i64,
                row.reporter as i64,
                row.burn_only,
                row.status,
                now()
            ],
        )?;
        self.penalty(&row.bond)?
            .ok_or_else(|| anyhow!("penalty row vanished"))
    }

    pub fn penalty(&self, bond: &OutPoint) -> Result<Option<PenaltyRow>> {
        Ok(self
            .penalties_where("bond=?1", Some(fmt_outpoint(bond)))?
            .into_iter()
            .next())
    }

    pub fn penalties(&self) -> Result<Vec<PenaltyRow>> {
        self.penalties_where("1=1 OR ?1 IS NULL", None)
    }

    fn penalties_where(&self, clause: &str, arg: Option<String>) -> Result<Vec<PenaltyRow>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT bond,operator,lockbox,txid,hex,amount,reward,burn,fee,reporter,burn_only,
                    status,height,block_hash,spender,attempts,last_error
             FROM penalties WHERE {clause} ORDER BY created, rowid"
        ))?;
        let rows = st
            .query_map([arg], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    PenaltyRow {
                        bond: OutPoint::default(),
                        operator: r.get(1)?,
                        lockbox: r.get(2)?,
                        txid: r.get(3)?,
                        hex: r.get(4)?,
                        amount: r.get::<_, i64>(5)? as u64,
                        reward: r.get::<_, i64>(6)? as u64,
                        burn: r.get::<_, i64>(7)? as u64,
                        fee: r.get::<_, i64>(8)? as u64,
                        reporter: r.get::<_, i64>(9)? as u64,
                        burn_only: r.get(10)?,
                        status: r.get(11)?,
                        height: r.get(12)?,
                        block_hash: r.get(13)?,
                        spender: r.get(14)?,
                        attempts: r.get(15)?,
                        last_error: r.get(16)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(b, mut row)| {
                row.bond = parse_outpoint(&b)?;
                Ok(row)
            })
            .collect()
    }

    pub fn set_penalty_status(
        &self,
        bond: &OutPoint,
        status: &str,
        height: Option<u32>,
        block_hash: Option<&str>,
        spender: Option<&str>,
    ) -> Result<()> {
        self.c().execute(
            "UPDATE penalties SET status=?2, height=?3, block_hash=?4, spender=?5, updated=?6 WHERE bond=?1",
            params![fmt_outpoint(bond), status, height, block_hash, spender, now()],
        )?;
        Ok(())
    }

    pub fn record_attempt(&self, bond: &OutPoint, error: Option<&str>) -> Result<()> {
        self.c().execute(
            "UPDATE penalties SET attempts=attempts+1, last_error=?2, updated=?3 WHERE bond=?1",
            params![fmt_outpoint(bond), error, now()],
        )?;
        Ok(())
    }

    pub fn cursor(&self, source: &str) -> Result<Option<u64>> {
        Ok(self
            .c()
            .query_row("SELECT seq FROM cursors WHERE source=?1", [source], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .map(|v| v as u64))
    }

    pub fn set_cursor(&self, source: &str, seq: u64) -> Result<()> {
        self.c().execute(
            "INSERT INTO cursors(source,seq) VALUES(?1,?2)
             ON CONFLICT(source) DO UPDATE SET seq=MAX(seq, ?2)",
            params![source, seq as i64],
        )?;
        Ok(())
    }

    /// Human/JSON summary for `status`.
    pub fn summary(&self) -> Result<Value> {
        let c = self.c();
        let count = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
        let watches = {
            let mut st = c.prepare("SELECT status, COUNT(*) FROM watches GROUP BY status")?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter()
                .map(|(s, n)| (s, json!(n)))
                .collect::<serde_json::Map<_, _>>()
        };
        let evidence = {
            let mut st = c.prepare(
                "SELECT operator, lockbox, c1, c2, source, found_at FROM evidence ORDER BY found_at",
            )?;
            let rows = st
                .query_map([], |r| {
                    Ok(json!({
                        "operator": r.get::<_, String>(0)?, "lockbox": r.get::<_, String>(1)?,
                        "commitment_1": r.get::<_, String>(2)?, "commitment_2": r.get::<_, String>(3)?,
                        "source": r.get::<_, String>(4)?, "found_at": r.get::<_, i64>(5)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let bonds = {
            let mut st = c.prepare(
                "SELECT outpoint, operator, refund_height, amount, status, spender FROM bonds ORDER BY operator, outpoint",
            )?;
            let rows = st
                .query_map([], |r| {
                    Ok(json!({
                        "outpoint": r.get::<_, String>(0)?, "operator": r.get::<_, String>(1)?,
                        "refund_height": r.get::<_, u32>(2)?, "amount": r.get::<_, i64>(3)?,
                        "status": r.get::<_, String>(4)?, "spender": r.get::<_, Option<String>>(5)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        drop(c);
        let penalties: Vec<Value> = self
            .penalties()?
            .into_iter()
            .map(|p| {
                json!({
                    "bond": fmt_outpoint(&p.bond), "operator": p.operator, "lockbox": p.lockbox,
                    "txid": p.txid, "status": p.status, "height": p.height,
                    "amount": p.amount, "reward": p.reward, "burn": p.burn, "fee": p.fee,
                    "reporter": p.reporter, "burn_only": p.burn_only, "attempts": p.attempts,
                    "spender": p.spender, "last_error": p.last_error,
                })
            })
            .collect();
        let c = self.c();
        Ok(json!({
            "genesis": c.query_row("SELECT value FROM meta WHERE key='genesis'", [], |r| r.get::<_, String>(0)).optional()?,
            "fee_asset": c.query_row("SELECT value FROM meta WHERE key='fee_asset'", [], |r| r.get::<_, String>(0)).optional()?,
            "promises": count("SELECT COUNT(*) FROM promises")?,
            "operators_announced": count("SELECT COUNT(*) FROM announcements")?,
            "watches": watches,
            "evidence": evidence,
            "bonds": bonds,
            "penalties": penalties,
        }))
    }
}
