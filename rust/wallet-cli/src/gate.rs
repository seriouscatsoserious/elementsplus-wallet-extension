//! The single signing gate. Every signature epw produces — CLI commands,
//! `epw sign --approve`, and every MCP tool — goes through
//! [`authorize_and_sign`]:
//!
//! 1. recompute each step's review from the exact PSET with the wallet core
//!    (`review_pset`) and refuse if the stored review or hash differ;
//! 2. evaluate the policy (`policy::evaluate`) on the recomputed reviews and
//!    the audit-log spend history;
//! 3. obtain confirmation if the policy mode requires it (tty, an explicit
//!    `--approve <hash>`, or park the bundle as a pending file);
//! 4. sign with `WalletCore::sign_prepared` and append an audit entry.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use elements::hashes::{sha256, Hash, HashEngine};
use elementsplus_wallet_core::{AssetContract, PreparedTx, SignedResult, WalletCore};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit;
use crate::config::Home;
use crate::policy::{self, Decision, Policy};

pub const BUNDLE_VERSION: u32 = 1;
const BUNDLE_DOMAIN: &[u8] = b"EPW_APPROVAL_BUNDLE_V1\0";

/// What to do with a signed step.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StepAction {
    /// Broadcast the transaction via Esplora. For issuances the contract is
    /// verified locally against the signed transaction and cached, and
    /// optionally registered with the registry.
    Broadcast {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuance_contract: Option<AssetContract>,
        #[serde(default)]
        register: bool,
    },
    /// A signed swap offer; optionally POST it to the DEX.
    Offer { post: bool },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub prepared: PreparedTx,
    pub action: StepAction,
}

/// A set of transactions approved together (e.g. split + offer). Stored as
/// `pending/<approval_hash>.json` when confirmation is deferred.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub version: u32,
    pub description: String,
    pub genesis_hash: String,
    pub created_at: u64,
    pub origin: String,
    /// DEX this operation relies on (policy `allowed_dex_urls`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dex_url: Option<String>,
    pub steps: Vec<Step>,
    pub approval_hash: String,
}

/// One step: its review hash. Several: SHA256(domain ‖ hash₁ ‖ … ‖ hashₙ).
pub fn approval_hash(steps: &[Step]) -> String {
    if let [single] = steps {
        return single.prepared.review_hash.clone();
    }
    let mut engine = sha256::Hash::engine();
    engine.input(BUNDLE_DOMAIN);
    for step in steps {
        engine.input(step.prepared.review_hash.as_bytes());
    }
    sha256::Hash::from_engine(engine).to_string()
}

impl Bundle {
    pub fn new(
        description: impl Into<String>,
        genesis_hash: &str,
        origin: &str,
        dex_url: Option<String>,
        steps: Vec<Step>,
    ) -> Self {
        let approval_hash = approval_hash(&steps);
        Self {
            version: BUNDLE_VERSION,
            description: description.into(),
            genesis_hash: genesis_hash.to_owned(),
            created_at: audit::now(),
            origin: origin.to_owned(),
            dex_url,
            steps,
            approval_hash,
        }
    }

    /// Load a pending bundle, or a bare `PreparedTx` (broadcast as-is).
    pub fn load(path: &Path, genesis_hash: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if let Ok(bundle) = serde_json::from_str::<Bundle>(&text) {
            if bundle.version != BUNDLE_VERSION {
                bail!("unsupported bundle version {}", bundle.version);
            }
            if bundle.approval_hash != approval_hash(&bundle.steps) {
                bail!("bundle approval_hash does not match its steps");
            }
            return Ok(bundle);
        }
        let prepared: PreparedTx = serde_json::from_str(&text)
            .context("file is neither an epw bundle nor a PreparedTx")?;
        let action = if prepared.review.kind == elementsplus_wallet_core::TxKind::SwapOffer {
            StepAction::Offer { post: false }
        } else {
            StepAction::Broadcast {
                issuance_contract: None,
                register: false,
            }
        };
        Ok(Self::new(
            "imported prepared transaction",
            genesis_hash,
            "file",
            None,
            vec![Step { prepared, action }],
        ))
    }
}

/// How confirmation is obtained when the policy requires it.
#[derive(Clone, Copy, Debug)]
pub enum Approval<'a> {
    /// Ask on the controlling terminal; park the bundle if there is none.
    Interactive,
    /// Never ask: park the bundle (MCP).
    Deferred,
    /// Only write the pending file; never sign.
    PrepareOnly,
    /// An explicit human approval of this approval hash (`epw sign --approve`).
    Approved(&'a str),
}

pub struct GateContext<'a> {
    pub core: &'a WalletCore,
    pub policy: &'a Policy,
    pub home: &'a Home,
    pub policy_asset: &'a str,
    pub genesis_hash: &'a str,
    pub origin: &'a str,
}

#[derive(Debug)]
pub enum GateOutcome {
    Signed {
        decision: Decision,
        signed: Vec<SignedResult>,
    },
    Pending {
        decision: Decision,
        pending_file: PathBuf,
    },
}

/// Policy refusal, carrying the full decision for structured output.
#[derive(Debug)]
pub struct PolicyRefused {
    pub decision: Decision,
    pub approval_hash: String,
}

impl std::fmt::Display for PolicyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refused by policy: {}",
            self.decision.violations.join("; ")
        )
    }
}

impl std::error::Error for PolicyRefused {}

/// Confirmation callback for [`Approval::Interactive`]: `Ok(None)` = no
/// terminal available.
pub type Prompter<'a> = &'a dyn Fn(&Bundle, &Decision) -> Result<Option<bool>>;

fn write_pending(home: &Home, bundle: &Bundle) -> Result<PathBuf> {
    let path = home
        .pending_dir()
        .join(format!("{}.json", bundle.approval_hash));
    crate::config::write_private(&path, serde_json::to_string_pretty(bundle)?.as_bytes())?;
    Ok(path)
}

/// THE signing entry point. See the module docs.
pub fn authorize_and_sign(
    ctx: &GateContext<'_>,
    bundle: &Bundle,
    approval: Approval<'_>,
    prompt: Prompter<'_>,
) -> Result<GateOutcome> {
    if bundle.genesis_hash != ctx.genesis_hash {
        bail!("bundle was prepared for another network");
    }
    if bundle.approval_hash != approval_hash(&bundle.steps) {
        bail!("bundle approval_hash does not match its steps");
    }
    // 1. Recompute every review from the PSET itself.
    let mut reviews = Vec::with_capacity(bundle.steps.len());
    for step in &bundle.steps {
        let recomputed = ctx
            .core
            .review_pset(&step.prepared.pset_base64, step.prepared.review.kind)
            .map_err(|e| anyhow!("PSET review failed: {e}"))?;
        if recomputed.review != step.prepared.review
            || recomputed.review_hash != step.prepared.review_hash
        {
            bail!("stored review does not match the PSET; refusing");
        }
        if matches!(step.action, StepAction::Offer { .. })
            != (recomputed.review.kind == elementsplus_wallet_core::TxKind::SwapOffer)
        {
            bail!("step action does not match the transaction kind");
        }
        reviews.push(recomputed.review);
    }

    // 2. Policy.
    let history = audit::spend_history(&ctx.home.audit_log())?;
    let now = audit::now();
    let decision = policy::evaluate(
        ctx.policy,
        &history,
        &policy::Request {
            reviews: &reviews,
            policy_asset: ctx.policy_asset,
            genesis_hash: ctx.genesis_hash,
            dex_url: bundle.dex_url.as_deref(),
        },
        now,
    );
    let audit_base = |event: &str| {
        json!({
            "event": event,
            "origin": ctx.origin,
            "description": bundle.description,
            "approval_hash": bundle.approval_hash,
            "kinds": reviews.iter().map(|r| r.kind).collect::<Vec<_>>(),
            "spend": decision.spend,
            "decision": decision,
        })
    };
    if !decision.allowed {
        audit::append(&ctx.home.audit_log(), audit_base("refused"))?;
        return Err(PolicyRefused {
            decision,
            approval_hash: bundle.approval_hash.clone(),
        }
        .into());
    }

    // 3. Confirmation.
    let park = |decision: &Decision| -> Result<GateOutcome> {
        let pending_file = write_pending(ctx.home, bundle)?;
        let mut entry = audit_base("pending");
        entry["pending_file"] = pending_file.display().to_string().into();
        audit::append(&ctx.home.audit_log(), entry)?;
        Ok(GateOutcome::Pending {
            decision: decision.clone(),
            pending_file,
        })
    };
    match approval {
        Approval::PrepareOnly => return park(&decision),
        Approval::Approved(hash) => {
            if hash != bundle.approval_hash {
                bail!(
                    "--approve {hash} does not match this bundle's approval hash {}",
                    bundle.approval_hash
                );
            }
        }
        Approval::Deferred if decision.requires_confirmation => return park(&decision),
        Approval::Interactive if decision.requires_confirmation => match prompt(bundle, &decision)?
        {
            Some(true) => {}
            Some(false) => {
                audit::append(&ctx.home.audit_log(), audit_base("rejected_by_user"))?;
                bail!("rejected by user");
            }
            None => return park(&decision),
        },
        Approval::Deferred | Approval::Interactive => {}
    }

    // 4. Sign and audit each step.
    let mut signed = Vec::with_capacity(bundle.steps.len());
    for (step, review) in bundle.steps.iter().zip(&reviews) {
        let result = ctx
            .core
            .sign_prepared(&step.prepared, &step.prepared.review_hash)
            .map_err(|e| anyhow!("signing failed: {e}"))?;
        let spend = policy::spend_of(std::slice::from_ref(review), ctx.policy_asset)?;
        let spend: std::collections::BTreeMap<_, _> =
            spend.into_iter().map(|(k, v)| (k, v.to_string())).collect();
        audit::append(
            &ctx.home.audit_log(),
            json!({
                "event": "signed",
                "origin": ctx.origin,
                "description": bundle.description,
                "approval_hash": bundle.approval_hash,
                "kind": review.kind,
                "review_hash": result.review_hash,
                "txid": result.txid,
                "spend": spend,
                "review": review,
            }),
        )?;
        signed.push(result);
    }
    // A parked copy of this bundle is now consumed.
    let _ = std::fs::remove_file(
        ctx.home
            .pending_dir()
            .join(format!("{}.json", bundle.approval_hash)),
    );
    Ok(GateOutcome::Signed { decision, signed })
}
