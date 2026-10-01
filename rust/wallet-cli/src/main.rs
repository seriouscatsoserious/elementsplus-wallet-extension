//! `epw`: headless, agent-friendly wallet for Elements+ (ECX Alpha).

mod amount;
mod audit;
mod config;
mod dex;
mod esplora;
mod gate;
mod keystore;
mod mcp;
mod policy;
mod scan;
mod state;
mod wallet;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use elementsplus_wallet_core::{Branch, WalletCore};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::config::{Config, Home};
use crate::gate::Bundle;
use crate::policy::Decision;
use crate::wallet::{error_json, Exec, Origin, PromptFn, Wallet};

#[derive(Parser)]
#[command(
    name = "epw",
    version,
    about = "Headless ECX Alpha (Elements+) wallet with a signing policy and an MCP server"
)]
struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args, Clone, Copy)]
struct SignOpts {
    /// Fee rate in sat/vB (default: config fee_rate).
    #[arg(long)]
    fee_rate: Option<u64>,
    /// Do not sign: write the bundle to pending/ and print its review and
    /// approval hash (complete with `epw sign <file> --approve <hash>`).
    #[arg(long)]
    prepare_only: bool,
}

impl SignOpts {
    fn exec(self) -> Exec {
        if self.prepare_only {
            Exec::PrepareOnly
        } else {
            Exec::Sign
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet (prints the mnemonic once).
    Init,
    /// Import a mnemonic (read from the terminal, or stdin when piped).
    Import,
    /// Show the next unused receive address.
    Address,
    /// Per-asset balances from locally verified UTXOs.
    Balances,
    /// Recent transactions with per-asset deltas.
    History {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Send an asset to an address.
    Send {
        asset: String,
        amount: String,
        address: String,
        #[command(flatten)]
        opts: SignOpts,
    },
    /// Issue a new explicit asset.
    Issue {
        #[arg(long)]
        name: String,
        #[arg(long)]
        ticker: String,
        #[arg(long)]
        precision: u8,
        /// Amount in the new asset's precision (or atomic:<n>).
        #[arg(long)]
        amount: String,
        /// Reissuance tokens (whole units).
        #[arg(long, default_value = "0")]
        token_amount: String,
        /// Register the contract with the asset registry after broadcast.
        #[arg(long)]
        register: bool,
        #[command(flatten)]
        opts: SignOpts,
    },
    /// Quote a swap via the DEX (offers re-verified locally).
    Quote {
        sell: String,
        buy: String,
        amount: String,
        /// `amount` is the amount to buy instead of to sell.
        #[arg(long)]
        exact_out: bool,
    },
    /// Quote and take DEX offers.
    Swap {
        sell: String,
        buy: String,
        amount: String,
        #[arg(long)]
        exact_out: bool,
        /// Max price impact vs the best offer, in basis points (default 100).
        #[arg(long)]
        max_slippage_bps: Option<u64>,
        #[command(flatten)]
        opts: SignOpts,
    },
    /// Maker offers.
    #[command(subcommand)]
    Offer(OfferCommand),
    /// DEX markets.
    Markets,
    /// DEX order book.
    Book { base: String, quote: String },
    /// Recompute and show the review of a prepared/pending file.
    Review { file: PathBuf },
    /// Sign (and broadcast/post) a prepared/pending file after approval.
    Sign {
        file: PathBuf,
        /// The approval hash shown by `epw review` / the pending result.
        #[arg(long)]
        approve: String,
    },
    /// Show the signing policy and rolling 24h spend.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Read or change config.toml.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Run an MCP server on stdio (requires EPW_PASSWORD).
    Mcp,
}

#[derive(Subcommand)]
enum OfferCommand {
    /// Offer <give_amount> of <give> for <want_amount> of <want>.
    Make {
        give: String,
        give_amount: String,
        want: String,
        want_amount: String,
        /// POST the signed offer to the DEX.
        #[arg(long)]
        post: bool,
        #[command(flatten)]
        opts: SignOpts,
    },
    /// List this wallet's offers.
    List,
    /// (Re-)post an already signed local offer to the DEX.
    Post { outpoint: String },
    /// Cancel an offer by spending its output back to self.
    Cancel {
        outpoint: String,
        #[command(flatten)]
        opts: SignOpts,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    Show,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print one key, or the whole config.
    Get { key: Option<String> },
    /// Set a key (empty value clears optional keys).
    Set { key: String, value: String },
    /// Discover regtest genesis/policy asset from the explorer and DEX.
    Discover,
}

fn tty_prompt() -> PromptFn {
    Box::new(|bundle: &Bundle, decision: &Decision, reviews: &[Value]| {
        let Ok(mut tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            return Ok(None);
        };
        let mut text = format!("\n== {} ==\n", bundle.description);
        for (i, review) in reviews.iter().enumerate() {
            text.push_str(&format!("-- transaction {} --\n", i + 1));
            for line in review["summary"].as_array().into_iter().flatten() {
                text.push_str(&format!("  {}\n", line.as_str().unwrap_or_default()));
            }
        }
        text.push_str(&format!("spend (atomic): {:?}\n", decision.spend));
        for note in &decision.notes {
            text.push_str(&format!("note: {note}\n"));
        }
        text.push_str(&format!(
            "approval hash: {}\nSign? [y/N] ",
            bundle.approval_hash
        ));
        tty.write_all(text.as_bytes())?;
        tty.flush()?;
        let mut answer = String::new();
        std::io::BufReader::new(&tty).read_line(&mut answer)?;
        Ok(Some(matches!(answer.trim(), "y" | "Y" | "yes")))
    })
}

fn read_mnemonic() -> Result<Zeroizing<String>> {
    let raw = if std::io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password("mnemonic (hidden): ")?)
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line)?;
        line
    };
    let normalized = Zeroizing::new(
        raw.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
    );
    WalletCore::validate_mnemonic(&normalized).map_err(|_| anyhow!("invalid BIP39 mnemonic"))?;
    Ok(normalized)
}

fn create_wallet(home: &Home, mnemonic: &str) -> Result<Value> {
    let path = home.keystore();
    if keystore::exists(&path) {
        bail!(
            "a keystore already exists at {}; refusing to overwrite",
            path.display()
        );
    }
    home.ensure()?;
    let password = keystore::password(true)?;
    let file = keystore::encrypt(mnemonic, &password, keystore::KdfParams::DEFAULT)?;
    keystore::write_new(&path, &file)?;
    if !home.config().exists() {
        Config::default().save(home)?;
    }
    if !home.policy().exists() {
        config::write_private(&home.policy(), policy::DEFAULT_POLICY_TOML.as_bytes())?;
    }
    let mut out =
        json!({ "keystore": path.display().to_string(), "home": home.root.display().to_string() });
    let mut cfg = Config::load(home)?;
    if wallet::discover_regtest(&mut cfg).unwrap_or(false) {
        cfg.save(home)?;
    }
    if let Ok(core) = wallet::open_core(&cfg, mnemonic) {
        if let Ok(addr) = core.derive_address(Branch::External, 0) {
            out["first_address"] = addr.native_address.into();
        }
    }
    Ok(out)
}

/// Exit codes: 0 ok, 1 error, 3 approval required, 4 refused by policy,
/// 5 signed/broadcast but posting to the DEX/registry failed.
fn exit_code(value: &Value) -> u8 {
    match value["status"].as_str() {
        Some("approval_required") => 3,
        Some("refused") => 4,
        Some("completed")
            if value["results"].as_array().into_iter().flatten().any(|r| {
                r.get("post_error").is_some() || r.get("registration_error").is_some()
            }) =>
        {
            5
        }
        _ => 0,
    }
}

fn human(value: &Value) -> String {
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    if let Some(status) = value["status"].as_str() {
        line(format!(
            "{status}: {}",
            value["description"]
                .as_str()
                .or(value["message"].as_str())
                .unwrap_or("")
        ));
        for review in value["reviews"].as_array().into_iter().flatten() {
            for l in review["summary"].as_array().into_iter().flatten() {
                line(format!("  {}", l.as_str().unwrap_or_default()));
            }
        }
        for v in value["decision"]["violations"]
            .as_array()
            .into_iter()
            .flatten()
        {
            line(format!("  violation: {}", v.as_str().unwrap_or_default()));
        }
        if let Some(cmd) = value["approve_command"].as_str() {
            line(format!(
                "approval hash: {}",
                value["approval_hash"].as_str().unwrap_or_default()
            ));
            line(format!("approve with: {cmd}"));
        }
        for r in value["results"].as_array().into_iter().flatten() {
            if let Some(txid) = r["txid"].as_str() {
                line(format!("txid: {txid}"));
            }
            if let Some(asset) = r["asset_id"].as_str() {
                line(format!("asset id: {asset}"));
            }
            if r.get("registered").is_some() {
                line("registered with the asset registry".into());
            }
            if let Some(e) = r["registration_error"].as_str() {
                line(format!("registration failed: {e}"));
            }
            if let Some(outpoint) = r["decoded"]["outpoint"].as_str() {
                line(format!("offer: {outpoint}"));
            }
            if r.get("posted").is_some() {
                line("offer posted to the DEX".into());
            }
            if let Some(e) = r["post_error"].as_str() {
                line(format!("posting failed: {e}"));
            }
        }
        return out;
    }
    if let Some(address) = value["address"].as_str() {
        line(address.to_owned());
    } else if let Some(balances) = value["balances"].as_array() {
        if balances.is_empty() {
            line("no funds".into());
        }
        for b in balances {
            let name = match (
                b["ticker"].as_str(),
                b["name"].as_str(),
                b["verified"].as_bool(),
            ) {
                (Some(ticker), _, _) => ticker.to_owned(),
                (None, Some(name), Some(true)) => {
                    format!("{name} ({})", b["asset_id"].as_str().unwrap_or_default())
                }
                _ => format!(
                    "{} [UNVERIFIED]",
                    b["asset_id"].as_str().unwrap_or_default()
                ),
            };
            line(format!(
                "{:>24} {name}  (unconfirmed {}, in offers {})",
                b["display"].as_str().unwrap_or_default(),
                b["unconfirmed_display"].as_str().unwrap_or("0"),
                b["in_open_offers_display"].as_str().unwrap_or("0"),
            ));
        }
    } else if let Some(txs) = value["transactions"].as_array() {
        for tx in txs {
            let changes: Vec<&str> = tx["balance_changes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["display"].as_str())
                .collect();
            line(format!(
                "{} {:>8} {:<12} {}",
                tx["txid"].as_str().unwrap_or_default(),
                tx["block_height"]
                    .as_u64()
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "mempool".into()),
                tx["kind"].as_str().unwrap_or("-"),
                changes.join(", ")
            ));
        }
    } else if let Some(offers) = value["offers"]
        .as_array()
        .filter(|_| value.get("verified").is_none())
    {
        for o in offers {
            line(format!(
                "{} {:<9} {}",
                o["outpoint"].as_str().unwrap_or_default(),
                o["status"].as_str().unwrap_or_default(),
                o["display"].as_str().unwrap_or_default()
            ));
        }
        if offers.is_empty() {
            line("no offers".into());
        }
    } else if value.get("verified").is_some() {
        line(format!(
            "sell {} -> buy {} via {} verified offer(s); price impact {} bps; unfilled {}",
            value["sell_display"].as_str().unwrap_or_default(),
            value["buy_display"].as_str().unwrap_or_default(),
            value["offers"].as_array().map(Vec::len).unwrap_or(0),
            value["price_impact_bps"],
            value["unfilled"].as_str().unwrap_or_default()
        ));
    } else {
        line(serde_json::to_string_pretty(value).unwrap_or_default());
    }
    out
}

fn run(cli: &Cli) -> Result<Value> {
    let home = Home::resolve()?;
    let open = |origin| Wallet::open(home.clone(), origin, tty_prompt());
    Ok(match &cli.command {
        Command::Init => {
            let mnemonic =
                Zeroizing::new(WalletCore::generate_mnemonic().map_err(|e| anyhow!("{e}"))?);
            let mut out = create_wallet(&home, &mnemonic)?;
            out["mnemonic"] = mnemonic.as_str().into();
            out["warning"] = "Write the mnemonic down now; epw never shows it again.".into();
            out
        }
        Command::Import => {
            let mnemonic = read_mnemonic()?;
            create_wallet(&home, &mnemonic)?
        }
        Command::Address => open(Origin::Cli)?.address()?,
        Command::Balances => open(Origin::Cli)?.balances()?,
        Command::History { limit } => open(Origin::Cli)?.history(*limit)?,
        Command::Send {
            asset,
            amount,
            address,
            opts,
        } => open(Origin::Cli)?.send(asset, amount, address, opts.fee_rate, opts.exec())?,
        Command::Issue {
            name,
            ticker,
            precision,
            amount,
            token_amount,
            register,
            opts,
        } => open(Origin::Cli)?.issue(
            name,
            ticker,
            *precision,
            amount,
            token_amount,
            *register,
            opts.fee_rate,
            opts.exec(),
        )?,
        Command::Quote {
            sell,
            buy,
            amount,
            exact_out,
        } => open(Origin::Cli)?.quote(sell, buy, amount, *exact_out)?,
        Command::Swap {
            sell,
            buy,
            amount,
            exact_out,
            max_slippage_bps,
            opts,
        } => open(Origin::Cli)?.swap(
            sell,
            buy,
            amount,
            *exact_out,
            *max_slippage_bps,
            opts.fee_rate,
            opts.exec(),
        )?,
        Command::Offer(OfferCommand::Make {
            give,
            give_amount,
            want,
            want_amount,
            post,
            opts,
        }) => open(Origin::Cli)?.offer_make(
            give,
            give_amount,
            want,
            want_amount,
            *post,
            opts.fee_rate,
            opts.exec(),
        )?,
        Command::Offer(OfferCommand::List) => open(Origin::Cli)?.offer_list()?,
        Command::Offer(OfferCommand::Post { outpoint }) => {
            open(Origin::Cli)?.offer_post(outpoint)?
        }
        Command::Offer(OfferCommand::Cancel { outpoint, opts }) => {
            open(Origin::Cli)?.offer_cancel(outpoint, opts.fee_rate, opts.exec())?
        }
        Command::Markets => open(Origin::Cli)?.markets()?,
        Command::Book { base, quote } => open(Origin::Cli)?.order_book(base, quote)?,
        Command::Review { file } => open(Origin::Cli)?.review_file(file)?,
        Command::Sign { file, approve } => open(Origin::Cli)?.sign_file(file, approve)?,
        Command::Policy(PolicyCommand::Show) => open(Origin::Cli)?.policy_status()?,
        Command::Config(command) => {
            let mut config = Config::load(&home)?;
            match command {
                ConfigCommand::Get { key: Some(key) } => json!({ key.clone(): config.get(key)? }),
                ConfigCommand::Get { key: None } => serde_json::to_value(&config)?,
                ConfigCommand::Set { key, value } => {
                    config.set(key, value)?;
                    config.save(&home)?;
                    json!({ key.clone(): config.get(key)? })
                }
                ConfigCommand::Discover => {
                    if config.network == config::NetworkKind::Regtest {
                        config.genesis_hash = None;
                        config.policy_asset = None;
                    }
                    wallet::discover_regtest(&mut config)?;
                    config.save(&home)?;
                    serde_json::to_value(&config)?
                }
            }
        }
        Command::Mcp => {
            if std::env::var_os("EPW_PASSWORD").is_none() {
                bail!(
                    "epw mcp needs EPW_PASSWORD (stdin carries the protocol, so it cannot prompt)"
                );
            }
            let wallet = Wallet::open(home, Origin::Mcp, Box::new(|_, _, _| Ok(None)))
                .context("cannot unlock the wallet for the MCP server")?;
            eprintln!(
                "epw mcp: wallet unlocked, serving MCP {} on stdio",
                mcp::PROTOCOL_VERSION
            );
            let server = mcp::Server::new(wallet);
            let stdin = std::io::stdin();
            server.serve(stdin.lock(), std::io::stdout())?;
            Value::Null
        }
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(Value::Null) => ExitCode::SUCCESS,
        Ok(value) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            } else {
                print!("{}", human(&value));
            }
            ExitCode::from(exit_code(&value))
        }
        Err(error) => {
            let body = error_json(&error);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
            } else {
                eprint!(
                    "{}",
                    human(&body).replace("refused: ", "error: refused by policy: ")
                );
                if body["status"] == "error" {
                    // human() already printed the message line.
                }
            }
            ExitCode::from(match exit_code(&body) {
                0 => 1,
                code => code,
            })
        }
    }
}
