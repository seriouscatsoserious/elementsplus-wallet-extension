//! Wallet operations shared by the CLI and the MCP server. Every operation
//! that signs builds a [`Bundle`] and hands it to
//! [`gate::authorize_and_sign`]; nothing here calls the signer directly.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use elements::confidential::{Asset, Value as ConfValue};
use elements::pset::PartiallySignedTransaction;
use elementsplus_wallet_core::{
    AssetContract, Branch, CancelRequest, DecodedOffer, IssuanceRequest, Offer, OfferInput,
    OfferSplitRequest, PreparedTx, SwapOfferRequest, TakeOfferInput, TakeSwapOffersRequest,
    TransferRequest, TxKind, TxReview, VerifiedUtxo, WalletCore,
};
use serde_json::{json, Value};

use crate::amount::{format_amount, format_signed, parse_amount};
use crate::audit;
use crate::config::{Config, Home, NetworkKind};
use crate::dex::{fetch_registry, Dex};
use crate::esplora::Esplora;
use crate::gate::{
    self, Approval, Bundle, GateContext, GateOutcome, PolicyRefused, Step, StepAction,
};
use crate::keystore;
use crate::policy::{self, Decision, Policy, PolicyFile};
use crate::scan::{self, Snapshot, WalletUtxo};
use crate::state::{self, AssetLabel, LocalOffer, LocalState};

pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 100;
const REGISTRY_REFRESH_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Cli,
    Mcp,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Mcp => "mcp",
        }
    }
}

/// Whether an operation signs (subject to policy) or only prepares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Exec {
    #[default]
    Sign,
    PrepareOnly,
}

pub type PromptFn = Box<dyn Fn(&Bundle, &Decision, &[Value]) -> Result<Option<bool>>>;

pub struct Wallet {
    pub home: Home,
    pub config: Config,
    pub core: WalletCore,
    pub esplora: Esplora,
    pub dex: Dex,
    pub policy_file: PolicyFile,
    pub origin: Origin,
    pub genesis_hash: String,
    pub policy_asset: String,
    state: RefCell<LocalState>,
    registry_refreshed_at: Cell<u64>,
    prompt: PromptFn,
}

/// Fill regtest chain parameters from the explorer (genesis) and the DEX
/// (policy asset), cross-checking the DEX genesis.
pub fn discover_regtest(config: &mut Config) -> Result<bool> {
    if config.network != NetworkKind::Regtest {
        return Ok(false);
    }
    if config.genesis_hash.is_some() && config.policy_asset.is_some() {
        return Ok(false);
    }
    let esplora = Esplora::new(&config.esplora_url)?;
    let genesis = esplora.genesis_hash()?;
    if let Some(configured) = &config.genesis_hash {
        if *configured != genesis {
            bail!("configured genesis_hash differs from the explorer's genesis {genesis}");
        }
    }
    if config.policy_asset.is_none() {
        let health = Dex::new(&config.dex_url)?
            .health()
            .context("regtest policy_asset is not configured and the DEX /api/health is unreachable; set it with `epw config set policy_asset <hex>`")?;
        if health["genesis_hash"].as_str() != Some(genesis.as_str()) {
            bail!(
                "DEX genesis {} differs from the explorer genesis {genesis}",
                health["genesis_hash"]
            );
        }
        let asset = health["policy_asset"]
            .as_str()
            .ok_or_else(|| anyhow!("DEX health has no policy_asset"))?;
        config.policy_asset = Some(asset.to_owned());
    }
    config.genesis_hash = Some(genesis);
    config.validate()?;
    Ok(true)
}

pub fn chain_identity(config: &Config) -> Result<(String, String)> {
    match config.network {
        NetworkKind::EcxAlpha => Ok((
            elementsplus_wallet_core::GENESIS_HASH.to_owned(),
            elementsplus_wallet_core::POLICY_ASSET.to_owned(),
        )),
        NetworkKind::Regtest => Ok((
            config
                .genesis_hash
                .clone()
                .ok_or_else(|| anyhow!("regtest genesis_hash is not configured"))?,
            config
                .policy_asset
                .clone()
                .ok_or_else(|| anyhow!("regtest policy_asset is not configured"))?,
        )),
    }
}

pub fn open_core(config: &Config, mnemonic: &str) -> Result<WalletCore> {
    match config.network {
        NetworkKind::EcxAlpha => WalletCore::new(mnemonic).map_err(|e| anyhow!("{e}")),
        NetworkKind::Regtest => {
            let (genesis, policy) = chain_identity(config)?;
            WalletCore::new_for_regtest(mnemonic, &genesis, &policy, "regtest")
                .map_err(|e| anyhow!("{e}"))
        }
    }
}

fn outpoint_parts(outpoint: &str) -> Result<(String, u32)> {
    let (txid, vout) = outpoint
        .split_once(':')
        .ok_or_else(|| anyhow!("expected <txid>:<vout>, got {outpoint:?}"))?;
    let txid = txid.to_ascii_lowercase();
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid txid in {outpoint:?}");
    }
    Ok((txid, vout.parse().context("invalid vout")?))
}

/// Locate an explicit wallet output inside a prepared PSET.
fn pset_output(
    prepared: &PreparedTx,
    script_hex: &str,
    asset: &str,
    amount: u64,
) -> Result<(String, u32, String)> {
    let pset =
        PartiallySignedTransaction::from_str(&prepared.pset_base64).map_err(|e| anyhow!("{e}"))?;
    let tx = pset.extract_tx().map_err(|e| anyhow!("{e}"))?;
    for (vout, output) in tx.output.iter().enumerate() {
        if hex::encode(output.script_pubkey.as_bytes()) != script_hex {
            continue;
        }
        if let (Asset::Explicit(a), ConfValue::Explicit(v)) = (output.asset, output.value) {
            if a.to_string() == asset && v == amount {
                return Ok((
                    tx.txid().to_string(),
                    vout as u32,
                    elements::encode::serialize_hex(&tx),
                ));
            }
        }
    }
    bail!("prepared split does not contain the expected output")
}

struct VerifiedQuote {
    offers: Vec<(Offer, String, DecodedOffer)>,
    sell_total: u64,
    buy_total: u64,
    price_impact_bps: u64,
    server: Value,
}

impl Wallet {
    /// Unlock the keystore and open the wallet.
    pub fn open(home: Home, origin: Origin, prompt: PromptFn) -> Result<Self> {
        let mut config = Config::load(&home)?;
        if discover_regtest(&mut config)? {
            config.save(&home)?;
        }
        let file = keystore::read(&home.keystore())?;
        let password = keystore::password(false)?;
        let mnemonic = keystore::decrypt(&file, &password)?;
        drop(password);
        let core = open_core(&config, &mnemonic)?;
        drop(mnemonic);
        Self::with_core(home, config, core, origin, prompt)
    }

    pub fn with_core(
        home: Home,
        config: Config,
        core: WalletCore,
        origin: Origin,
        prompt: PromptFn,
    ) -> Result<Self> {
        let (genesis_hash, policy_asset) = chain_identity(&config)?;
        if core.genesis_hash().to_string() != genesis_hash
            || core.policy_asset().to_string() != policy_asset
        {
            bail!("wallet core network does not match the configuration");
        }
        let policy_file = PolicyFile::load(&home.policy())?;
        let state = LocalState::load(&home.state_file(&genesis_hash))?;
        let wallet = Self {
            esplora: Esplora::new(&config.esplora_url)?,
            dex: Dex::new(&config.dex_url)?,
            home,
            config,
            core,
            policy_file,
            origin,
            genesis_hash,
            policy_asset,
            state: RefCell::new(state),
            registry_refreshed_at: Cell::new(0),
            prompt,
        };
        // Fail early on an invalid policy file.
        wallet.policy()?;
        Ok(wallet)
    }

    fn save_state(&self) -> Result<()> {
        self.state
            .borrow()
            .save(&self.home.state_file(&self.genesis_hash))
    }

    pub fn policy(&self) -> Result<Policy> {
        let state = self.state.borrow();
        Policy::resolve(&self.policy_file, &self.policy_asset, |asset| {
            state::label(&state, &self.policy_asset, asset).precision
        })
    }

    // ----------------------------------------------------------------- assets

    /// Refresh verified metadata from the registry (rate-limited; failures
    /// are non-fatal because cached entries were verified locally).
    pub fn refresh_registry(&self, force: bool) -> Vec<String> {
        let now = audit::now();
        if !force && now.saturating_sub(self.registry_refreshed_at.get()) < REGISTRY_REFRESH_SECS {
            return Vec::new();
        }
        self.registry_refreshed_at.set(now);
        let entries = match fetch_registry(&self.config.registry_url()) {
            Ok(entries) => entries,
            Err(error) => return vec![format!("registry unavailable: {error}")],
        };
        let problems = {
            let mut state = self.state.borrow_mut();
            state::refresh_from_registry(&mut state, &entries, &self.esplora, &self.policy_asset)
        };
        let _ = self.save_state();
        problems
    }

    pub fn label(&self, asset: &str) -> AssetLabel {
        state::label(&self.state.borrow(), &self.policy_asset, asset)
    }

    fn labels_for(&self, assets: impl IntoIterator<Item = String>) -> BTreeMap<String, AssetLabel> {
        let assets: BTreeSet<String> = assets.into_iter().collect();
        if assets.iter().any(|a| !self.label(a).verified) {
            self.refresh_registry(false);
        }
        assets
            .into_iter()
            .map(|a| (a.clone(), self.label(&a)))
            .collect()
    }

    /// Resolve a ticker or 64-hex id.
    pub fn resolve_asset(&self, arg: &str) -> Result<String> {
        if let Some(id) = state::resolve_asset(&self.state.borrow(), &self.policy_asset, arg)? {
            return Ok(id);
        }
        self.refresh_registry(true);
        state::resolve_asset(&self.state.borrow(), &self.policy_asset, arg)?.ok_or_else(|| {
            anyhow!(
                "unknown asset {arg:?}: not a 64-hex asset id or the ticker of a verified asset"
            )
        })
    }

    pub fn parse_amount_for(&self, asset: &str, amount: &str) -> Result<u64> {
        let precision = self.label(asset).precision;
        parse_amount(amount, precision).with_context(|| format!("amount {amount:?}"))
    }

    fn display(&self, asset: &str, atomic: u64) -> String {
        let label = self.label(asset);
        format!(
            "{} {}",
            format_amount(atomic, label.precision),
            label.short()
        )
    }

    // ------------------------------------------------------------------ chain

    pub fn snapshot(&self) -> Result<Snapshot> {
        let reserved = self.state.borrow().reserved_external;
        scan::scan(
            &self.core,
            &self.esplora,
            self.config.gap_limit,
            &self.genesis_hash,
            reserved,
        )
    }

    fn spendable(&self, snapshot: &Snapshot) -> Vec<VerifiedUtxo> {
        let locked: BTreeSet<String> = self
            .state
            .borrow()
            .open_offer_outpoints()
            .into_iter()
            .collect();
        snapshot
            .utxos
            .iter()
            .filter(|u| !locked.contains(&u.outpoint()))
            .map(|u| u.utxo.clone())
            .collect()
    }

    fn receive_index(&self, snapshot: &Snapshot) -> u32 {
        snapshot
            .next_external
            .max(self.state.borrow().reserved_external)
    }

    fn fee_rate(&self, override_rate: Option<u64>) -> u64 {
        override_rate.unwrap_or(self.config.fee_rate)
    }

    pub fn address(&self) -> Result<Value> {
        let snapshot = self.snapshot()?;
        let index = self.receive_index(&snapshot);
        let derived = self.core.derive_address(Branch::External, index)?;
        Ok(json!({
            "address": derived.native_address,
            "index": index,
            "derivation_path": derived.derivation_path,
            "script_pubkey_hex": derived.script_pubkey_hex,
            "network": self.config.network.as_str(),
        }))
    }

    pub fn balances(&self) -> Result<Value> {
        let snapshot = self.snapshot()?;
        let locked: BTreeSet<String> = self
            .state
            .borrow()
            .open_offer_outpoints()
            .into_iter()
            .collect();
        #[derive(Default)]
        struct Totals {
            confirmed: u64,
            unconfirmed: u64,
            in_offers: u64,
            utxos: usize,
        }
        let mut totals: BTreeMap<String, Totals> = BTreeMap::new();
        for utxo in &snapshot.utxos {
            let entry = totals.entry(utxo.utxo.asset_id.clone()).or_default();
            if utxo.confirmed {
                entry.confirmed += utxo.utxo.value;
            } else {
                entry.unconfirmed += utxo.utxo.value;
            }
            if locked.contains(&utxo.outpoint()) {
                entry.in_offers += utxo.utxo.value;
            }
            entry.utxos += 1;
        }
        let labels = self.labels_for(totals.keys().cloned());
        let balances: Vec<Value> = totals
            .iter()
            .map(|(asset, t)| {
                let label = &labels[asset];
                let total = t.confirmed + t.unconfirmed;
                json!({
                    "asset_id": asset,
                    "ticker": label.ticker,
                    "name": label.name,
                    "verified": label.verified,
                    "precision": label.precision,
                    "amount": total.to_string(),
                    "confirmed": t.confirmed.to_string(),
                    "unconfirmed": t.unconfirmed.to_string(),
                    "in_open_offers": t.in_offers.to_string(),
                    "display": format_amount(total, label.precision),
                    "utxos": t.utxos,
                })
            })
            .collect();
        Ok(json!({
            "balances": balances,
            "tip_height": snapshot.tip_height,
            "skipped_outputs": snapshot.skipped,
        }))
    }

    pub fn history(&self, limit: usize) -> Result<Value> {
        let snapshot = self.snapshot()?;
        let mut scripts = BTreeSet::new();
        for address in &snapshot.addresses {
            scripts.insert(
                self.core
                    .derive_address(address.branch, address.index)?
                    .script_pubkey_hex,
            );
        }
        let mut txs: BTreeMap<String, Value> = BTreeMap::new();
        for address in snapshot.used_addresses() {
            for tx in self.esplora.address_txs(&address.address, 1_000)? {
                if let Some(txid) = tx["txid"].as_str() {
                    txs.entry(txid.to_owned()).or_insert(tx);
                }
            }
        }
        let kinds = audit::kinds_by_txid(&self.home.audit_log());
        let mut rows = Vec::new();
        for (txid, tx) in &txs {
            let mut deltas: BTreeMap<String, i128> = BTreeMap::new();
            for input in tx["vin"].as_array().into_iter().flatten() {
                let prevout = &input["prevout"];
                if prevout["scriptpubkey"]
                    .as_str()
                    .is_some_and(|s| scripts.contains(s))
                {
                    if let (Some(asset), Some(value)) =
                        (prevout["asset"].as_str(), prevout["value"].as_u64())
                    {
                        *deltas.entry(asset.to_owned()).or_default() -= i128::from(value);
                    }
                }
            }
            for output in tx["vout"].as_array().into_iter().flatten() {
                if output["scriptpubkey"]
                    .as_str()
                    .is_some_and(|s| scripts.contains(s))
                {
                    if let (Some(asset), Some(value)) =
                        (output["asset"].as_str(), output["value"].as_u64())
                    {
                        *deltas.entry(asset.to_owned()).or_default() += i128::from(value);
                    }
                }
            }
            deltas.retain(|_, v| *v != 0);
            let changes: Vec<Value> = deltas
                .iter()
                .map(|(asset, v)| {
                    let label = self.label(asset);
                    json!({
                        "asset_id": asset,
                        "ticker": label.ticker,
                        "amount": v.to_string(),
                        "display": format!("{} {}", format_signed(&v.to_string(), label.precision), label.short()),
                    })
                })
                .collect();
            rows.push(json!({
                "txid": txid,
                "confirmed": tx["status"]["confirmed"].as_bool().unwrap_or(false),
                "block_height": tx["status"]["block_height"],
                "block_time": tx["status"]["block_time"],
                "fee": tx["fee"],
                "kind": kinds.get(txid),
                "balance_changes": changes,
            }));
        }
        rows.sort_by_key(|row| {
            let height = row["block_height"].as_u64().unwrap_or(u64::MAX);
            std::cmp::Reverse(height)
        });
        rows.truncate(limit);
        Ok(
            json!({ "transactions": rows, "tip_height": snapshot.tip_height, "source": "explorer (display only)" }),
        )
    }

    // ------------------------------------------------------------- reviews

    /// A review enriched with human-readable lines.
    pub fn describe_review(&self, review: &TxReview) -> Value {
        let mut lines = vec![format!("kind: {:?}", review.kind)];
        for delta in &review.balance_changes {
            let label = self.label(&delta.asset_id);
            lines.push(format!(
                "balance: {} {}{}",
                format_signed(&delta.amount, label.precision),
                label.short(),
                if label.verified { "" } else { " [UNVERIFIED]" }
            ));
        }
        lines.push(format!(
            "fee: {}",
            self.display(&self.policy_asset, review.fee)
        ));
        for output in &review.external_outputs {
            lines.push(format!(
                "pays: {} to {}",
                self.display(&output.asset_id, output.amount),
                output.address
            ));
        }
        if let Some(issuance) = &review.issuance {
            lines.push(format!(
                "issues asset {} (amount {}, tokens {})",
                issuance.asset_id, issuance.amount, issuance.token_amount
            ));
        }
        if !review.foreign_inputs.is_empty() {
            lines.push(format!(
                "foreign (maker) inputs: {}",
                review.foreign_inputs.len()
            ));
        }
        lines.push(format!("sighash: {}", review.sighash));
        json!({ "review": review, "summary": lines })
    }

    fn gate(&self, bundle: &Bundle, approval: Approval<'_>) -> Result<GateOutcome> {
        let policy = self.policy()?;
        let ctx = GateContext {
            core: &self.core,
            policy: &policy,
            home: &self.home,
            policy_asset: &self.policy_asset,
            genesis_hash: &self.genesis_hash,
            origin: self.origin.as_str(),
        };
        let described: Vec<Value> = bundle
            .steps
            .iter()
            .map(|s| self.describe_review(&s.prepared.review))
            .collect();
        let prompt =
            |bundle: &Bundle, decision: &Decision| (self.prompt)(bundle, decision, &described);
        gate::authorize_and_sign(&ctx, bundle, approval, &prompt)
    }

    /// Run a bundle through the gate and, if signed, execute its steps.
    pub fn run(&self, bundle: Bundle, exec: Exec) -> Result<Value> {
        let approval = match (exec, self.origin) {
            (Exec::PrepareOnly, _) => Approval::PrepareOnly,
            (Exec::Sign, Origin::Cli) => Approval::Interactive,
            (Exec::Sign, Origin::Mcp) => Approval::Deferred,
        };
        self.run_with(bundle, approval)
    }

    pub fn run_with(&self, bundle: Bundle, approval: Approval<'_>) -> Result<Value> {
        let reviews: Vec<Value> = bundle
            .steps
            .iter()
            .map(|s| self.describe_review(&s.prepared.review))
            .collect();
        match self.gate(&bundle, approval) {
            Err(error) => match error.downcast::<PolicyRefused>() {
                Ok(refused) => Err(anyhow!(StructuredError(json!({
                    "status": "refused",
                    "message": refused.to_string(),
                    "description": bundle.description,
                    "approval_hash": refused.approval_hash,
                    "decision": refused.decision,
                    "reviews": reviews,
                })))),
                Err(error) => Err(error),
            },
            Ok(GateOutcome::Pending {
                decision,
                pending_file,
            }) => {
                let file = pending_file.display().to_string();
                Ok(json!({
                    "status": "approval_required",
                    "description": bundle.description,
                    "approval_hash": bundle.approval_hash,
                    "decision": decision,
                    "reviews": reviews,
                    "pending_file": file,
                    "approve_command": format!("epw sign {file} --approve {}", bundle.approval_hash),
                }))
            }
            Ok(GateOutcome::Signed { decision, signed }) => {
                let results = self.execute(&bundle, &signed)?;
                Ok(json!({
                    "status": "completed",
                    "description": bundle.description,
                    "approval_hash": bundle.approval_hash,
                    "decision": decision,
                    "reviews": reviews,
                    "results": results,
                }))
            }
        }
    }

    fn execute(
        &self,
        bundle: &Bundle,
        signed: &[elementsplus_wallet_core::SignedResult],
    ) -> Result<Vec<Value>> {
        let mut results = Vec::new();
        let mut raw_by_txid: BTreeMap<String, String> = BTreeMap::new();
        for (step, result) in bundle.steps.iter().zip(signed) {
            let review = &step.prepared.review;
            match &step.action {
                StepAction::Broadcast {
                    issuance_contract,
                    register,
                } => {
                    let raw = result
                        .raw_tx_hex
                        .as_ref()
                        .ok_or_else(|| anyhow!("signed step has no transaction"))?;
                    let txid = self
                        .esplora
                        .broadcast(raw)
                        .with_context(|| format!("{} signed but broadcast failed", result.txid))?;
                    if txid != result.txid {
                        bail!("explorer reported txid {txid}, expected {}", result.txid);
                    }
                    audit::append(
                        &self.home.audit_log(),
                        json!({"event": "broadcast", "origin": self.origin.as_str(), "kind": review.kind, "txid": txid}),
                    )?;
                    raw_by_txid.insert(txid.clone(), raw.clone());
                    let mut out = json!({ "kind": review.kind, "txid": txid });
                    if review.kind == TxKind::Cancel {
                        let spent: BTreeSet<&String> = review.inputs_signed.iter().collect();
                        let mut state = self.state.borrow_mut();
                        for offer in state.offers.iter_mut() {
                            if spent.contains(&offer.outpoint) && offer.status == "open" {
                                offer.status = "cancelled".into();
                                offer.cancel_txid = Some(txid.clone());
                            }
                        }
                    }
                    if let Some(issuance) = &review.issuance {
                        out["asset_id"] = issuance.asset_id.clone().into();
                        out["token_id"] = issuance.token_id.clone().into();
                        out["vin"] = 0.into();
                        if let Some(contract) = issuance_contract {
                            let verified = state::verify_issuance(raw, &txid, 0, contract)?;
                            if verified[0].asset_id != issuance.asset_id {
                                bail!("issued asset id does not verify against the contract");
                            }
                            {
                                let mut state = self.state.borrow_mut();
                                for asset in verified {
                                    state.assets.insert(asset.asset_id.clone(), asset);
                                }
                            }
                            out["contract"] = serde_json::to_value(contract)?;
                            if *register {
                                match crate::dex::Dex::new(registry_base(
                                    &self.config.registry_url(),
                                ))
                                .and_then(|d| {
                                    d.register_asset(&txid, 0, &serde_json::to_value(contract)?)
                                }) {
                                    Ok(record) => out["registered"] = record,
                                    Err(error) => {
                                        out["registration_error"] = error.to_string().into()
                                    }
                                }
                            }
                        }
                    }
                    results.push(out);
                }
                StepAction::Offer { post } => {
                    let offer = result
                        .offer
                        .as_ref()
                        .ok_or_else(|| anyhow!("signed step has no offer"))?;
                    let offer_json = serde_json::to_string(offer)?;
                    let (prev_txid, _) = outpoint_parts(&review.inputs_signed[0])?;
                    let prevout = match raw_by_txid.get(&prev_txid) {
                        Some(raw) => raw.clone(),
                        None => self.esplora.tx_hex(&prev_txid)?,
                    };
                    let decoded = self
                        .core
                        .decode_offer(&offer_json, &prevout)
                        .map_err(|e| anyhow!("{e}"))?;
                    let receive_index = self.find_external_index(&decoded.maker_address)?;
                    let mut out = json!({
                        "kind": review.kind,
                        "offer": offer,
                        "decoded": decoded,
                    });
                    let mut posted = false;
                    if *post {
                        match self
                            .dex
                            .post_offer(&serde_json::to_value(offer)?, &decoded.outpoint)
                        {
                            Ok(record) => {
                                posted = true;
                                out["posted"] = json!({ "id": record["id"], "status": record["status"], "outpoint": record["outpoint"] });
                            }
                            Err(error) => out["post_error"] = error.to_string().into(),
                        }
                    }
                    let mut state = self.state.borrow_mut();
                    state.offers.retain(|o| o.outpoint != decoded.outpoint);
                    state.offers.push(LocalOffer {
                        outpoint: decoded.outpoint.clone(),
                        give_asset: decoded.give_asset.clone(),
                        give_amount: decoded.give_amount.to_string(),
                        want_asset: decoded.want_asset.clone(),
                        want_amount: decoded.want_amount.to_string(),
                        maker_address: decoded.maker_address.clone(),
                        receive_index,
                        offer: serde_json::to_value(offer)?,
                        created_at: audit::now(),
                        posted,
                        status: "open".into(),
                        cancel_txid: None,
                    });
                    state.reserved_external = state.reserved_external.max(receive_index + 1);
                    results.push(out);
                }
            }
        }
        self.save_state()?;
        Ok(results)
    }

    fn find_external_index(&self, address: &str) -> Result<u32> {
        let target = policy::address_program(address);
        let limit = self.state.borrow().reserved_external + self.config.gap_limit + 1_000;
        for index in 0..limit {
            let derived = self.core.derive_address(Branch::External, index)?;
            if policy::address_program(&derived.native_address) == target {
                return Ok(index);
            }
        }
        bail!("offer payment address is not a known wallet address")
    }

    fn bundle(&self, description: String, dex: bool, steps: Vec<Step>) -> Bundle {
        Bundle::new(
            description,
            &self.genesis_hash,
            self.origin.as_str(),
            dex.then(|| self.config.dex_url.clone()),
            steps,
        )
    }

    // ------------------------------------------------------------ operations

    pub fn send(
        &self,
        asset: &str,
        amount: &str,
        recipient: &str,
        fee_rate: Option<u64>,
        exec: Exec,
    ) -> Result<Value> {
        let asset = self.resolve_asset(asset)?;
        let amount = self.parse_amount_for(&asset, amount)?;
        let snapshot = self.snapshot()?;
        let prepared = self
            .core
            .prepare_transfer(&TransferRequest {
                recipient: recipient.trim().to_owned(),
                asset_id: asset.clone(),
                amount,
                fee_rate: self.fee_rate(fee_rate),
                utxos: self.spendable(&snapshot),
                change_index: snapshot.next_change,
            })
            .map_err(|e| anyhow!("{e}"))?;
        let bundle = self.bundle(
            format!("send {} to {recipient}", self.display(&asset, amount)),
            false,
            vec![Step {
                prepared,
                action: StepAction::Broadcast {
                    issuance_contract: None,
                    register: false,
                },
            }],
        );
        self.run(bundle, exec)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        name: &str,
        ticker: &str,
        precision: u8,
        amount: &str,
        token_amount: &str,
        register: bool,
        fee_rate: Option<u64>,
        exec: Exec,
    ) -> Result<Value> {
        let contract = AssetContract {
            name: name.to_owned(),
            ticker: ticker.to_owned(),
            precision,
            version: 0,
            issuer_pubkey: None,
        };
        contract.validate().map_err(|e| anyhow!("{e}"))?;
        let amount = parse_amount(amount, precision).context("--amount")?;
        let token_amount = match token_amount.trim() {
            "0" | "atomic:0" => 0,
            other => parse_amount(other, 0).context("--token-amount (whole tokens)")?,
        };
        let snapshot = self.snapshot()?;
        let policy_utxos: Vec<_> = self
            .spendable(&snapshot)
            .into_iter()
            .filter(|u| u.asset_id == self.policy_asset)
            .collect();
        let prepared = self
            .core
            .prepare_issuance(&IssuanceRequest {
                contract: contract.clone(),
                amount,
                token_amount,
                fee_rate: self.fee_rate(fee_rate),
                utxos: policy_utxos,
                change_index: snapshot.next_change,
                receive_index: self.receive_index(&snapshot),
            })
            .map_err(|e| anyhow!("{e}"))?;
        let bundle = self.bundle(
            format!(
                "issue {} {ticker} ({name})",
                format_amount(amount, precision)
            ),
            false,
            vec![Step {
                prepared,
                // Always verify + cache the contract; registration is optional.
                action: StepAction::Broadcast {
                    issuance_contract: Some(contract),
                    register,
                },
            }],
        );
        self.run(bundle, exec)
    }

    fn verified_quote(
        &self,
        sell: &str,
        buy: &str,
        amount: u64,
        side: &str,
    ) -> Result<VerifiedQuote> {
        let (quote, server) = self.dex.quote(sell, buy, amount, side)?;
        let mut offers = Vec::new();
        let mut seen = BTreeSet::new();
        let (mut sell_total, mut buy_total) = (0u64, 0u64);
        for entry in &quote.offers {
            let offer: Offer = serde_json::from_value(entry.offer.clone())
                .context("DEX returned a malformed offer")?;
            let offer_json = serde_json::to_string(&offer)?;
            let prevout = self.esplora.tx_hex(&entry.txid)?;
            let decoded = self.core.decode_offer(&offer_json, &prevout).map_err(|e| {
                anyhow!(
                    "DEX offer {}:{} failed verification: {e}",
                    entry.txid,
                    entry.vout
                )
            })?;
            if decoded.outpoint != format!("{}:{}", entry.txid, entry.vout) {
                bail!("DEX offer entry outpoint does not match the signed offer");
            }
            if decoded.give_asset != buy || decoded.want_asset != sell {
                bail!("DEX quote contains an offer for a different pair");
            }
            if !seen.insert(decoded.outpoint.clone()) {
                bail!("DEX quote lists the same offer twice");
            }
            sell_total = sell_total
                .checked_add(decoded.want_amount)
                .context("overflow")?;
            buy_total = buy_total
                .checked_add(decoded.give_amount)
                .context("overflow")?;
            offers.push((offer, prevout, decoded));
        }
        if quote.sell_amount != sell_total.to_string() || quote.buy_amount != buy_total.to_string()
        {
            bail!(
                "DEX quote totals (sell {}, buy {}) disagree with the verified offers (sell {sell_total}, buy {buy_total})",
                quote.sell_amount,
                quote.buy_amount
            );
        }
        let requested_side_total = if side == "exact_out" {
            buy_total
        } else {
            sell_total
        };
        if requested_side_total > amount {
            bail!("DEX quote overshoots the requested amount");
        }
        // Price impact: average sell-per-buy vs the best single offer.
        let mut impact = 0u64;
        if let Some((_, _, best)) = offers.iter().min_by(|(_, _, a), (_, _, b)| {
            (u128::from(a.want_amount) * u128::from(b.give_amount))
                .cmp(&(u128::from(b.want_amount) * u128::from(a.give_amount)))
        }) {
            let avg_num = u128::from(sell_total) * u128::from(best.give_amount);
            let best_num = u128::from(best.want_amount) * u128::from(buy_total);
            if best_num > 0 && avg_num > best_num {
                impact = ((avg_num - best_num) * 10_000 / best_num) as u64;
            }
        }
        Ok(VerifiedQuote {
            offers,
            sell_total,
            buy_total,
            price_impact_bps: impact,
            server,
        })
    }

    fn quote_json(
        &self,
        sell: &str,
        buy: &str,
        q: &VerifiedQuote,
        requested: u64,
        side: &str,
    ) -> Value {
        let requested_total = if side == "exact_out" {
            q.buy_total
        } else {
            q.sell_total
        };
        json!({
            "sell_asset": sell,
            "buy_asset": buy,
            "side": side,
            "requested": requested.to_string(),
            "sell_amount": q.sell_total.to_string(),
            "buy_amount": q.buy_total.to_string(),
            "sell_display": self.display(sell, q.sell_total),
            "buy_display": self.display(buy, q.buy_total),
            "unfilled": (requested - requested_total).to_string(),
            "price_impact_bps": q.price_impact_bps,
            "offers": q.offers.iter().map(|(_, _, d)| d).collect::<Vec<_>>(),
            "verified": true,
            "dex": self.dex.base(),
            "server_price": q.server["price"],
        })
    }

    pub fn quote(&self, sell: &str, buy: &str, amount: &str, exact_out: bool) -> Result<Value> {
        let sell = self.resolve_asset(sell)?;
        let buy = self.resolve_asset(buy)?;
        let side = if exact_out { "exact_out" } else { "exact_in" };
        let amount = self.parse_amount_for(if exact_out { &buy } else { &sell }, amount)?;
        let q = self.verified_quote(&sell, &buy, amount, side)?;
        Ok(self.quote_json(&sell, &buy, &q, amount, side))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn swap(
        &self,
        sell: &str,
        buy: &str,
        amount: &str,
        exact_out: bool,
        max_slippage_bps: Option<u64>,
        fee_rate: Option<u64>,
        exec: Exec,
    ) -> Result<Value> {
        let sell = self.resolve_asset(sell)?;
        let buy = self.resolve_asset(buy)?;
        let side = if exact_out { "exact_out" } else { "exact_in" };
        let amount = self.parse_amount_for(if exact_out { &buy } else { &sell }, amount)?;
        let q = self.verified_quote(&sell, &buy, amount, side)?;
        if q.offers.is_empty() {
            bail!("no offers can fill this swap");
        }
        let max = max_slippage_bps.unwrap_or(DEFAULT_MAX_SLIPPAGE_BPS);
        if q.price_impact_bps > max {
            bail!(
                "price impact {} bps exceeds --max-slippage-bps {max}",
                q.price_impact_bps
            );
        }
        for (_, _, decoded) in &q.offers {
            let (txid, vout) = outpoint_parts(&decoded.outpoint)?;
            if self.esplora.outspend(&txid, vout)?.spent {
                bail!("offer {} is already spent; quote again", decoded.outpoint);
            }
        }
        let snapshot = self.snapshot()?;
        let prepared = self
            .core
            .take_swap_offers(&TakeSwapOffersRequest {
                offers: q
                    .offers
                    .iter()
                    .map(|(offer, prevout, _)| TakeOfferInput {
                        offer: OfferInput::Object(offer.clone()),
                        prevout_raw_tx_hex: prevout.clone(),
                    })
                    .collect(),
                fee_rate: self.fee_rate(fee_rate),
                utxos: self.spendable(&snapshot),
                change_index: snapshot.next_change,
                receive_index: self.receive_index(&snapshot),
            })
            .map_err(|e| anyhow!("{e}"))?;
        let bundle = self.bundle(
            format!(
                "swap {} for {} via {} offer(s)",
                self.display(&sell, q.sell_total),
                self.display(&buy, q.buy_total),
                q.offers.len()
            ),
            true,
            vec![Step {
                prepared,
                action: StepAction::Broadcast {
                    issuance_contract: None,
                    register: false,
                },
            }],
        );
        let mut value = self.run(bundle, exec)?;
        value["quote"] = self.quote_json(&sell, &buy, &q, amount, side);
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn offer_make(
        &self,
        give: &str,
        give_amount: &str,
        want: &str,
        want_amount: &str,
        post: bool,
        fee_rate: Option<u64>,
        exec: Exec,
    ) -> Result<Value> {
        let give = self.resolve_asset(give)?;
        let want = self.resolve_asset(want)?;
        let give_amount = self.parse_amount_for(&give, give_amount)?;
        let want_amount = self.parse_amount_for(&want, want_amount)?;
        let snapshot = self.snapshot()?;
        let spendable = self.spendable(&snapshot);
        let mut receive = self.receive_index(&snapshot);
        let mut steps = Vec::new();
        let exact = spendable
            .iter()
            .filter(|u| u.asset_id == give && u.value == give_amount)
            .min_by_key(|u| {
                // Prefer confirmed outputs.
                let confirmed = snapshot
                    .utxos
                    .iter()
                    .any(|w: &WalletUtxo| w.utxo == **u && w.confirmed);
                !confirmed
            })
            .cloned();
        let utxo = match exact {
            Some(utxo) => utxo,
            None => {
                let split = self
                    .core
                    .prepare_offer_split(&OfferSplitRequest {
                        asset_id: give.clone(),
                        amount: give_amount,
                        fee_rate: self.fee_rate(fee_rate),
                        utxos: spendable.clone(),
                        change_index: snapshot.next_change,
                        receive_index: receive,
                    })
                    .map_err(|e| anyhow!("{e}"))?;
                let derived = self.core.derive_address(Branch::External, receive)?;
                let (txid, vout, _) =
                    pset_output(&split, &derived.script_pubkey_hex, &give, give_amount)?;
                steps.push(Step {
                    prepared: split,
                    action: StepAction::Broadcast {
                        issuance_contract: None,
                        register: false,
                    },
                });
                let utxo = VerifiedUtxo {
                    txid,
                    vout,
                    value: give_amount,
                    asset_id: give.clone(),
                    script_pubkey_hex: derived.script_pubkey_hex,
                    branch: Branch::External,
                    index: receive,
                };
                receive += 1;
                utxo
            }
        };
        let offer = self
            .core
            .prepare_swap_offer(&SwapOfferRequest {
                utxo,
                want_asset: want.clone(),
                want_amount,
                receive_index: receive,
            })
            .map_err(|e| anyhow!("{e}"))?;
        steps.push(Step {
            prepared: offer,
            action: StepAction::Offer { post },
        });
        // Reserve the payment address now so later operations never reuse it.
        {
            let mut state = self.state.borrow_mut();
            state.reserved_external = state.reserved_external.max(receive + 1);
        }
        self.save_state()?;
        let bundle = self.bundle(
            format!(
                "offer {} for {}{}{}",
                self.display(&give, give_amount),
                self.display(&want, want_amount),
                if steps.len() > 1 {
                    " (with exact-output split)"
                } else {
                    ""
                },
                if post { ", post to DEX" } else { "" }
            ),
            post,
            steps,
        );
        self.run(bundle, exec)
    }

    pub fn offer_list(&self) -> Result<Value> {
        let snapshot = self.snapshot()?;
        let mut makers: BTreeSet<String> = self
            .state
            .borrow()
            .offers
            .iter()
            .map(|o| o.maker_address.clone())
            .collect();
        makers.extend(
            snapshot
                .addresses
                .iter()
                .filter(|a| a.branch == Branch::External && a.used)
                .map(|a| a.address.clone()),
        );
        let mut dex_status: BTreeMap<String, Value> = BTreeMap::new();
        let mut dex_error = None;
        for maker in &makers {
            match self.dex.maker_offers(maker) {
                Ok(entries) => {
                    for entry in entries {
                        dex_status.insert(
                            format!("{}:{}", entry.txid, entry.vout),
                            json!({ "status": entry.status, "offer": entry.offer, "maker_address": entry.maker_address }),
                        );
                    }
                }
                Err(error) => {
                    dex_error = Some(error.to_string());
                    break;
                }
            }
        }
        let local = self.state.borrow().offers.clone();
        let mut outpoints: BTreeSet<String> = local.iter().map(|o| o.outpoint.clone()).collect();
        outpoints.extend(dex_status.keys().cloned());
        let mut rows = Vec::new();
        for outpoint in outpoints {
            let local = local.iter().find(|o| o.outpoint == outpoint);
            let dex = dex_status.get(&outpoint);
            let (txid, vout) = outpoint_parts(&outpoint)?;
            let outspend = self.esplora.outspend(&txid, vout)?;
            let (give, give_amount, want, want_amount) = match (local, dex) {
                (Some(o), _) => (
                    o.give_asset.clone(),
                    o.give_amount.clone(),
                    o.want_asset.clone(),
                    o.want_amount.clone(),
                ),
                (None, Some(d)) => (
                    d["offer"]["give"]["asset_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    d["offer"]["give"]["amount"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    d["offer"]["want"]["asset_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    d["offer"]["want"]["amount"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                ),
                (None, None) => continue,
            };
            let status = if !outspend.spent {
                "open".to_owned()
            } else if local.and_then(|o| o.cancel_txid.as_ref()) == outspend.txid.as_ref()
                && outspend.txid.is_some()
            {
                "cancelled".to_owned()
            } else {
                "spent".to_owned()
            };
            let fmt = |asset: &str, amount: &str| {
                amount
                    .parse::<u64>()
                    .map(|a| self.display(asset, a))
                    .unwrap_or_default()
            };
            rows.push(json!({
                "outpoint": outpoint,
                "status": status,
                "spent_by": outspend.txid,
                "give_asset": give,
                "give_amount": give_amount,
                "want_asset": want,
                "want_amount": want_amount,
                "display": format!("{} for {}", fmt(&give, &give_amount), fmt(&want, &want_amount)),
                "dex_status": dex.map(|d| d["status"].clone()),
                "local": local.is_some(),
            }));
        }
        // Local records whose outputs are gone are no longer open.
        {
            let mut state = self.state.borrow_mut();
            for row in &rows {
                if row["status"] != "open" {
                    if let Some(o) = state
                        .offers
                        .iter_mut()
                        .find(|o| o.outpoint == row["outpoint"].as_str().unwrap_or_default())
                    {
                        if o.status == "open" {
                            o.status = row["status"].as_str().unwrap_or("spent").to_owned();
                        }
                    }
                }
            }
        }
        self.save_state()?;
        Ok(json!({ "offers": rows, "dex": self.dex.base(), "dex_error": dex_error }))
    }

    pub fn offer_cancel(&self, outpoint: &str, fee_rate: Option<u64>, exec: Exec) -> Result<Value> {
        let (txid, vout) = outpoint_parts(outpoint)?;
        let snapshot = self.snapshot()?;
        let target = snapshot
            .utxos
            .iter()
            .find(|u| u.utxo.txid == txid && u.utxo.vout == vout)
            .ok_or_else(|| anyhow!("{outpoint} is not an unspent output of this wallet"))?
            .utxo
            .clone();
        let others: Vec<_> = self
            .spendable(&snapshot)
            .into_iter()
            .filter(|u| u.asset_id == self.policy_asset && !(u.txid == txid && u.vout == vout))
            .collect();
        let prepared = self
            .core
            .prepare_cancel(&CancelRequest {
                utxo: target.clone(),
                change_index: snapshot.next_change,
                fee_rate: self.fee_rate(fee_rate),
                other_utxos: others,
            })
            .map_err(|e| anyhow!("{e}"))?;
        let bundle = self.bundle(
            format!(
                "cancel offer {outpoint} ({})",
                self.display(&target.asset_id, target.value)
            ),
            false,
            vec![Step {
                prepared,
                action: StepAction::Broadcast {
                    issuance_contract: None,
                    register: false,
                },
            }],
        );
        self.run(bundle, exec)
    }

    pub fn review_file(&self, path: &std::path::Path) -> Result<Value> {
        let bundle = Bundle::load(path, &self.genesis_hash)?;
        let mut steps = Vec::new();
        let mut reviews = Vec::new();
        for step in &bundle.steps {
            let recomputed = self
                .core
                .review_pset(&step.prepared.pset_base64, step.prepared.review.kind)
                .map_err(|e| anyhow!("{e}"))?;
            let matches = recomputed.review == step.prepared.review
                && recomputed.review_hash == step.prepared.review_hash;
            steps.push(json!({
                "action": step.action,
                "review_hash": recomputed.review_hash,
                "matches_file": matches,
                "review": self.describe_review(&recomputed.review),
            }));
            reviews.push(recomputed.review);
        }
        let history = audit::spend_history(&self.home.audit_log())?;
        let decision = policy::evaluate(
            &self.policy()?,
            &history,
            &policy::Request {
                reviews: &reviews,
                policy_asset: &self.policy_asset,
                genesis_hash: &self.genesis_hash,
                dex_url: bundle.dex_url.as_deref(),
            },
            audit::now(),
        );
        Ok(json!({
            "description": bundle.description,
            "approval_hash": bundle.approval_hash,
            "dex_url": bundle.dex_url,
            "steps": steps,
            "decision": decision,
        }))
    }

    pub fn sign_file(&self, path: &std::path::Path, approve: &str) -> Result<Value> {
        let bundle = Bundle::load(path, &self.genesis_hash)?;
        self.run_with(bundle, Approval::Approved(approve))
    }

    pub fn markets(&self) -> Result<Value> {
        let markets = self.dex.markets()?;
        let assets = markets.iter().flat_map(|m| {
            [
                m["base"].as_str().unwrap_or_default().to_owned(),
                m["quote"].as_str().unwrap_or_default().to_owned(),
            ]
        });
        let labels = self.labels_for(assets.filter(|a| !a.is_empty()));
        let rows: Vec<Value> = markets
            .into_iter()
            .map(|mut m| {
                for side in ["base", "quote"] {
                    if let Some(label) = m[side].as_str().and_then(|a| labels.get(a)) {
                        m[format!("{side}_label")] =
                            serde_json::to_value(label).unwrap_or_default();
                    }
                }
                m
            })
            .collect();
        Ok(json!({ "markets": rows, "dex": self.dex.base() }))
    }

    pub fn order_book(&self, base: &str, quote: &str) -> Result<Value> {
        let base = self.resolve_asset(base)?;
        let quote = self.resolve_asset(quote)?;
        let book = self.dex.book(&base, &quote)?;
        let simplify = |side: &str| -> Vec<Value> {
            book[side]
                .as_array()
                .into_iter()
                .flatten()
                .map(|o| {
                    json!({
                        "outpoint": o["outpoint"],
                        "price": o["price"],
                        "base_amount": o["base_amount"],
                        "quote_amount": o["quote_amount"],
                        "maker_address": o["maker_address"],
                    })
                })
                .collect()
        };
        Ok(json!({
            "base": self.label(&base),
            "quote": self.label(&quote),
            "bids": simplify("bids"),
            "asks": simplify("asks"),
            "note": "unverified DEX data; swap/quote re-verify every offer locally",
        }))
    }

    pub fn policy_status(&self) -> Result<Value> {
        let policy = self.policy()?;
        let history = audit::spend_history(&self.home.audit_log())?;
        let spent = policy::window_spend(&history, audit::now());
        let limits: BTreeMap<String, Value> = policy
            .limits
            .iter()
            .map(|(asset, limit)| {
                let label = self.label(asset);
                (
                    asset.clone(),
                    json!({
                        "ticker": label.ticker,
                        "per_tx": limit.per_tx.map(|v| v.to_string()),
                        "per_24h": limit.per_24h.map(|v| v.to_string()),
                        "spent_24h": spent.get(asset).copied().unwrap_or(0).to_string(),
                    }),
                )
            })
            .collect();
        Ok(json!({
            "mode": policy.mode,
            "file": self.home.policy().display().to_string(),
            "policy": self.policy_file,
            "limits_atomic": limits,
            "spent_24h": spent.iter().map(|(k, v)| (k.clone(), v.to_string())).collect::<BTreeMap<_, _>>(),
        }))
    }
}

fn registry_base(url: &str) -> &str {
    match url.find("/api/") {
        Some(index) => &url[..index],
        None => url,
    }
}

/// An error carrying a JSON body (policy refusals).
#[derive(Debug)]
pub struct StructuredError(pub Value);

impl std::fmt::Display for StructuredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0["message"].as_str().unwrap_or("error"))
    }
}

impl std::error::Error for StructuredError {}

/// JSON body for any error.
pub fn error_json(error: &anyhow::Error) -> Value {
    if let Some(structured) = error.downcast_ref::<StructuredError>() {
        return structured.0.clone();
    }
    json!({ "status": "error", "message": format!("{error:#}") })
}
