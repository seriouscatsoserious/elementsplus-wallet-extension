//! PSET construction for every supported operation (spec §1.2).

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::hashes::Hash;
use elements::pset::{Input, Output, PartiallySignedTransaction, PsbtSighashType};
use elements::{AssetId, EcdsaSighashType, Script, Sequence, TxOutSecrets};
use lwk_common::set_genesis_hash;
use serde::{Deserialize, Serialize};

use crate::confidential::{add_input_proofs, blind_pset, confidential_prevout, request_blinding};
use crate::issuance::{issuance_ids, AssetContract, MAX_MONEY};
use crate::offer::{parse_offer_json, verify_offer, Offer, VerifiedOffer};
use crate::review::{PreparedTx, TxKind};
use crate::{explicit_output, Branch, ParsedUtxo, VerifiedUtxo, WalletCore, WalletError};

/// Highest accepted fee rate in sat/vB; anything above is almost certainly a
/// unit mistake.
pub const MAX_FEE_RATE: u64 = 1_000;
/// Policy-asset change below this is added to the fee instead of creating a
/// dust output.
pub const POLICY_DUST_LIMIT: u64 = 546;
/// Hard cap on caller-supplied UTXO lists and offers per request.
const MAX_REQUEST_ITEMS: usize = 500;

// Size model for explicit P2WPKH Elements transactions. Every term is an
// upper bound so the computed fee rate never falls below the requested one.
const TX_OVERHEAD_BASE: u64 = 4 + 1 + 3 + 3 + 4; // version, flag, vin/vout counts, locktime
const INPUT_BASE: u64 = 32 + 4 + 1 + 4; // outpoint, empty scriptSig, sequence
const ISSUANCE_BASE: u64 = 32 + 32 + 9 + 9; // nonce, entropy, amount, inflation keys
const INPUT_WITNESS: u64 = 1 + 1 + 1 + (1 + 73) + (1 + 33) + 1;
const OUTPUT_BASE: u64 = 33 + 9 + 1 + 1; // asset, value, nonce, script length
const OUTPUT_WITNESS: u64 = 1 + 1;
const P2WPKH_SCRIPT_LEN: u64 = 22;
// A blinded output replaces the 9-byte explicit value and 1-byte null nonce
// with 33-byte commitments, and adds a surjection proof (at most 3 used
// inputs of a 256-input domain: 2 + 32 + 32 * 4 bytes) and a 52-bit
// rangeproof (rust-elements `TxOut::RANGEPROOF_MIN_PRIV_BITS`; values never
// exceed MAX_MONEY < 2^52), each behind a 3-byte length prefix.
const BLINDED_OUTPUT_EXTRA_BASE: u64 = (33 - 9) + (33 - 1);
const SURJECTION_PROOF_MAX: u64 = 2 + 32 + 32 * 4;
pub(crate) const RANGEPROOF_52_BIT_MAX: u64 = 4_174;
const BLINDED_OUTPUT_EXTRA_WITNESS: u64 = (3 + SURJECTION_PROOF_MAX) + (3 + RANGEPROOF_52_BIT_MAX);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    pub recipient: String,
    pub asset_id: String,
    #[serde(with = "crate::amount::string")]
    pub amount: u64,
    #[serde(alias = "fee_rate_sat_vb", with = "crate::amount::number")]
    pub fee_rate: u64,
    pub utxos: Vec<VerifiedUtxo>,
    pub change_index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceRequest {
    pub contract: AssetContract,
    #[serde(with = "crate::amount::string")]
    pub amount: u64,
    #[serde(with = "crate::amount::string")]
    pub token_amount: u64,
    #[serde(alias = "fee_rate_sat_vb", with = "crate::amount::number")]
    pub fee_rate: u64,
    pub utxos: Vec<VerifiedUtxo>,
    pub change_index: u32,
    pub receive_index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwapOfferRequest {
    pub utxo: VerifiedUtxo,
    pub want_asset: String,
    #[serde(with = "crate::amount::string")]
    pub want_amount: u64,
    pub receive_index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfferSplitRequest {
    pub asset_id: String,
    #[serde(with = "crate::amount::string")]
    pub amount: u64,
    #[serde(alias = "fee_rate_sat_vb", with = "crate::amount::number")]
    pub fee_rate: u64,
    pub utxos: Vec<VerifiedUtxo>,
    pub change_index: u32,
    pub receive_index: u32,
}

/// An offer is accepted either as a JSON object or as its JSON string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum OfferInput {
    Object(Offer),
    Json(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TakeOfferInput {
    pub offer: OfferInput,
    pub prevout_raw_tx_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TakeSwapOffersRequest {
    pub offers: Vec<TakeOfferInput>,
    #[serde(alias = "fee_rate_sat_vb", with = "crate::amount::number")]
    pub fee_rate: u64,
    pub utxos: Vec<VerifiedUtxo>,
    pub change_index: u32,
    pub receive_index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub utxo: VerifiedUtxo,
    pub change_index: u32,
    #[serde(alias = "fee_rate_sat_vb", with = "crate::amount::number")]
    pub fee_rate: u64,
    #[serde(default)]
    pub other_utxos: Vec<VerifiedUtxo>,
}

/// Shape of the transaction around the wallet-funded part, for fee estimation.
struct Shape {
    foreign_inputs: u64,
    has_issuance: bool,
    /// Script lengths of all outputs other than change and fee.
    fixed_output_scripts: Vec<u64>,
    /// How many of the fixed outputs are blinded (confidential recipient).
    blinded_fixed_outputs: u64,
}

struct Funding {
    inputs: Vec<ParsedUtxo>,
    /// (asset, amount) change outputs, non-policy first, policy last.
    changes: Vec<(AssetId, u64)>,
    fee: u64,
}

fn validate_fee_rate(fee_rate: u64) -> Result<(), WalletError> {
    if fee_rate == 0 || fee_rate > MAX_FEE_RATE {
        return Err(WalletError::InvalidFeeRate(format!(
            "fee rate must be between 1 and {MAX_FEE_RATE} sat/vB"
        )));
    }
    Ok(())
}

fn validate_amount(amount: u64) -> Result<(), WalletError> {
    if amount == 0 {
        return Err(WalletError::ZeroAmount);
    }
    if amount > MAX_MONEY {
        return Err(WalletError::AmountOverflow);
    }
    Ok(())
}

fn parse_asset(text: &str) -> Result<AssetId, WalletError> {
    AssetId::from_str(text).map_err(|_| WalletError::InvalidRequest("invalid asset id".into()))
}

/// Upper-bound virtual size of a transaction, `blinded_outputs` of whose
/// outputs are confidential.
fn estimate_vsize(
    inputs: u64,
    issuance: bool,
    output_scripts: &[u64],
    blinded_outputs: u64,
) -> Result<u64, WalletError> {
    let overflow = || WalletError::AmountOverflow;
    let mut base = TX_OVERHEAD_BASE
        .checked_add(inputs.checked_mul(INPUT_BASE).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;
    if issuance {
        base += ISSUANCE_BASE;
    }
    let mut witness = inputs.checked_mul(INPUT_WITNESS).ok_or_else(overflow)?;
    for script in output_scripts {
        base = base
            .checked_add(OUTPUT_BASE + script)
            .ok_or_else(overflow)?;
        witness = witness.checked_add(OUTPUT_WITNESS).ok_or_else(overflow)?;
    }
    if blinded_outputs > 0 {
        base = blinded_outputs
            .checked_mul(BLINDED_OUTPUT_EXTRA_BASE)
            .and_then(|extra| base.checked_add(extra))
            .ok_or_else(overflow)?;
        witness = blinded_outputs
            .checked_mul(BLINDED_OUTPUT_EXTRA_WITNESS - OUTPUT_WITNESS)
            .and_then(|extra| witness.checked_add(extra))
            .ok_or_else(overflow)?;
    }
    let weight = base
        .checked_mul(4)
        .and_then(|w| w.checked_add(witness))
        .ok_or_else(overflow)?;
    Ok(weight.div_ceil(4))
}

impl WalletCore {
    fn parse_utxos(&self, utxos: &[VerifiedUtxo]) -> Result<Vec<ParsedUtxo>, WalletError> {
        if utxos.len() > MAX_REQUEST_ITEMS {
            return Err(WalletError::InvalidRequest("too many UTXOs".into()));
        }
        utxos
            .iter()
            .map(|utxo| self.parse_and_verify_utxo(utxo))
            .collect()
    }

    /// Deterministic coin selection. `forced` inputs are always spent;
    /// `needs` lists how much of each asset the fixed outputs consume beyond
    /// what foreign inputs provide. Policy-asset selection iterates with the
    /// size estimate until the fee is covered.
    ///
    /// When any selected input is confidential every change output is
    /// blinded, and at least one blinded output must exist to balance the
    /// blinding factors; without a confidential recipient or other change,
    /// a policy change of at least the dust limit is therefore reserved.
    fn fund(
        &self,
        forced: Vec<ParsedUtxo>,
        candidates: Vec<ParsedUtxo>,
        needs: &BTreeMap<AssetId, u64>,
        shape: &Shape,
        fee_rate: u64,
        excluded: &BTreeSet<elements::OutPoint>,
    ) -> Result<Funding, WalletError> {
        validate_fee_rate(fee_rate)?;
        let mut seen = excluded.clone();
        for utxo in forced.iter().chain(&candidates) {
            if !seen.insert(utxo.outpoint) {
                return Err(WalletError::DuplicateUtxo(crate::outpoint_label(
                    &utxo.outpoint,
                )));
            }
        }

        let mut pools: BTreeMap<AssetId, Vec<ParsedUtxo>> = BTreeMap::new();
        for utxo in candidates {
            pools.entry(utxo.asset).or_default().push(utxo);
        }
        for pool in pools.values_mut() {
            // Largest first, then outpoint, so selection is deterministic and
            // uses few inputs. Reverse so `pop` yields the next candidate.
            pool.sort_by(|a, b| {
                b.value
                    .cmp(&a.value)
                    .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
                    .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
            });
            pool.reverse();
        }

        let mut selected: BTreeMap<AssetId, Vec<ParsedUtxo>> = BTreeMap::new();
        let mut sums: BTreeMap<AssetId, u64> = BTreeMap::new();
        let mut forced_order = Vec::new();
        for utxo in forced {
            let sum = sums.entry(utxo.asset).or_default();
            *sum = sum
                .checked_add(utxo.value)
                .ok_or(WalletError::AmountOverflow)?;
            forced_order.push(utxo);
        }

        let policy = self.policy_asset;
        let mut changes = Vec::new();
        let mut assets: BTreeSet<AssetId> = needs.keys().copied().collect();
        assets.extend(sums.keys().copied());
        for asset in assets.iter().copied().filter(|a| *a != policy) {
            let need = needs.get(&asset).copied().unwrap_or(0);
            let sum = sums.entry(asset).or_default();
            while *sum < need {
                let next = pools.get_mut(&asset).and_then(Vec::pop).ok_or_else(|| {
                    WalletError::InsufficientFunds {
                        asset: asset.to_string(),
                        needed: need,
                        available: *sum,
                    }
                })?;
                *sum = sum
                    .checked_add(next.value)
                    .ok_or(WalletError::AmountOverflow)?;
                selected.entry(asset).or_default().push(next);
            }
            if *sum > need {
                changes.push((asset, *sum - need));
            }
        }

        let need_policy = needs.get(&policy).copied().unwrap_or(0);
        let mut sum_policy = sums.get(&policy).copied().unwrap_or(0);
        let mut policy_selected = Vec::new();
        let fee = loop {
            let wallet_inputs = forced_order.len()
                + selected.values().map(Vec::len).sum::<usize>()
                + policy_selected.len();
            let any_confidential = forced_order
                .iter()
                .chain(selected.values().flatten())
                .chain(&policy_selected)
                .any(|utxo| utxo.blinding.is_some());
            let mut scripts = shape.fixed_output_scripts.clone();
            scripts.extend(std::iter::repeat_n(P2WPKH_SCRIPT_LEN, changes.len() + 1));
            scripts.push(0);
            let blinded_changes = if any_confidential {
                changes.len() as u64 + 1
            } else {
                0
            };
            let vsize = estimate_vsize(
                shape.foreign_inputs + wallet_inputs as u64,
                shape.has_issuance,
                &scripts,
                shape.blinded_fixed_outputs + blinded_changes,
            )?;
            let fee = vsize
                .checked_mul(fee_rate)
                .ok_or(WalletError::AmountOverflow)?;
            let reserve =
                if any_confidential && shape.blinded_fixed_outputs == 0 && changes.is_empty() {
                    POLICY_DUST_LIMIT
                } else {
                    0
                };
            let target = need_policy
                .checked_add(fee)
                .and_then(|total| total.checked_add(reserve))
                .ok_or(WalletError::AmountOverflow)?;
            if sum_policy >= target && (wallet_inputs > 0) {
                break fee;
            }
            let next = pools.get_mut(&policy).and_then(Vec::pop).ok_or_else(|| {
                WalletError::InsufficientFunds {
                    asset: policy.to_string(),
                    needed: target,
                    available: sum_policy,
                }
            })?;
            sum_policy = sum_policy
                .checked_add(next.value)
                .ok_or(WalletError::AmountOverflow)?;
            policy_selected.push(next);
        };
        let mut fee = fee;
        let policy_change = sum_policy - need_policy - fee;
        if policy_change >= POLICY_DUST_LIMIT {
            changes.push((policy, policy_change));
        } else {
            fee += policy_change;
        }

        let mut inputs = forced_order;
        for (_, utxos) in selected {
            inputs.extend(utxos);
        }
        inputs.extend(policy_selected);
        Ok(Funding {
            inputs,
            changes,
            fee,
        })
    }

    fn wallet_input(
        &self,
        utxo: &ParsedUtxo,
        sighash: EcdsaSighashType,
    ) -> Result<Input, WalletError> {
        let mut input = Input::from_prevout(utxo.outpoint);
        input.sequence = Some(Sequence::MAX);
        input.witness_utxo = Some(match &utxo.blinding {
            None => explicit_output(utxo.asset, utxo.value, utxo.script.clone()),
            Some(opened) => confidential_prevout(opened, utxo.script.clone()),
        });
        input.asset = Some(utxo.asset);
        input.amount = Some(utxo.value);
        if let Some(opened) = &utxo.blinding {
            add_input_proofs(&self.secp, &mut input, utxo.asset, utxo.value, opened)?;
        }
        input.sighash_type = Some(PsbtSighashType::from(sighash));
        input.bip32_derivation.insert(
            utxo.public_key,
            (self.signer.fingerprint(), utxo.path.clone()),
        );
        Ok(input)
    }

    fn add_wallet_inputs(
        &self,
        pset: &mut PartiallySignedTransaction,
        inputs: &[ParsedUtxo],
    ) -> Result<(), WalletError> {
        for utxo in inputs {
            pset.add_input(self.wallet_input(utxo, EcdsaSighashType::All)?);
        }
        Ok(())
    }

    /// A wallet-owned output; `blinded` blinds it to this wallet's key.
    fn wallet_output(
        &self,
        asset: AssetId,
        amount: u64,
        branch: Branch,
        index: u32,
        blinded: bool,
    ) -> Result<Output, WalletError> {
        let (script, key, path) = self.wallet_key(branch, index)?;
        let blinding_key = blinded.then(|| self.blinding_public_key(&script));
        let mut output = Output::from_txout(explicit_output(asset, amount, script));
        output
            .bip32_derivation
            .insert(key, (self.signer.fingerprint(), path));
        if let Some(blinding_key) = blinding_key {
            request_blinding(&mut output, blinding_key);
        }
        Ok(output)
    }

    /// Change is confidential whenever any wallet input was confidential, so
    /// spending confidential funds never reveals the remaining amount.
    fn add_changes_and_fee(
        &self,
        pset: &mut PartiallySignedTransaction,
        funding: &Funding,
        change_index: u32,
    ) -> Result<(), WalletError> {
        let blinded = funding.inputs.iter().any(|utxo| utxo.blinding.is_some());
        for (asset, amount) in &funding.changes {
            pset.add_output(self.wallet_output(
                *asset,
                *amount,
                Branch::Change,
                change_index,
                blinded,
            )?);
        }
        pset.add_output(Output::from_txout(explicit_output(
            self.policy_asset,
            funding.fee,
            Script::new(),
        )));
        Ok(())
    }

    /// Blind (when any output requests it) before the review is computed, so
    /// the review hash commits to the final blinded PSET bytes. `inputs` are
    /// the wallet UTXOs in PSET input order; only wallet-funded transactions
    /// may blind.
    fn finish(
        &self,
        mut pset: PartiallySignedTransaction,
        kind: TxKind,
        inputs: &[ParsedUtxo],
    ) -> Result<PreparedTx, WalletError> {
        if pset.outputs().iter().any(|o| o.blinding_key.is_some()) {
            if inputs.len() != pset.inputs().len() {
                return Err(WalletError::InvalidPset(
                    "only fully wallet-funded transactions can be blinded".into(),
                ));
            }
            let secrets: Vec<TxOutSecrets> = inputs
                .iter()
                .map(|utxo| match &utxo.blinding {
                    Some(opened) => {
                        TxOutSecrets::new(utxo.asset, opened.asset_bf, utxo.value, opened.value_bf)
                    }
                    None => TxOutSecrets::new(
                        utxo.asset,
                        AssetBlindingFactor::zero(),
                        utxo.value,
                        ValueBlindingFactor::zero(),
                    ),
                })
                .collect();
            blind_pset(&self.secp, &mut pset, &secrets)?;
        }
        set_genesis_hash(&mut pset, &self.network);
        let review = self.analyze(&pset, kind)?.review;
        let review_hash = self.review_commitment(&pset, &review)?;
        Ok(PreparedTx {
            pset_base64: pset.to_string(),
            review,
            review_hash,
        })
    }

    /// Send any asset to a P2WPKH recipient. A confidential address gets a
    /// blinded output; an unconfidential one an explicit output.
    pub fn prepare_transfer(&self, request: &TransferRequest) -> Result<PreparedTx, WalletError> {
        validate_amount(request.amount)?;
        let asset = parse_asset(&request.asset_id)?;
        let recipient = self.parse_recipient(&request.recipient)?;
        let candidates = self.parse_utxos(&request.utxos)?;
        let needs = BTreeMap::from([(asset, request.amount)]);
        let shape = Shape {
            foreign_inputs: 0,
            has_issuance: false,
            fixed_output_scripts: vec![recipient.script.len() as u64],
            blinded_fixed_outputs: u64::from(recipient.blinding_key.is_some()),
        };
        let funding = self.fund(
            Vec::new(),
            candidates,
            &needs,
            &shape,
            request.fee_rate,
            &BTreeSet::new(),
        )?;

        let mut pset = PartiallySignedTransaction::new_v2();
        self.add_wallet_inputs(&mut pset, &funding.inputs)?;
        let mut output =
            Output::from_txout(explicit_output(asset, request.amount, recipient.script));
        if let Some(blinding_key) = recipient.blinding_key {
            request_blinding(&mut output, blinding_key);
        }
        pset.add_output(output);
        self.add_changes_and_fee(&mut pset, &funding, request.change_index)?;
        self.finish(pset, TxKind::Transfer, &funding.inputs)
    }

    /// Issue a new explicit asset (and optional reissuance token) to this wallet.
    pub fn prepare_issuance(&self, request: &IssuanceRequest) -> Result<PreparedTx, WalletError> {
        validate_amount(request.amount)?;
        if request.token_amount > MAX_MONEY {
            return Err(WalletError::AmountOverflow);
        }
        let contract_hash = request.contract.contract_hash()?;
        let candidates = self.parse_utxos(&request.utxos)?;
        let mut fixed = vec![P2WPKH_SCRIPT_LEN];
        if request.token_amount > 0 {
            fixed.push(P2WPKH_SCRIPT_LEN);
        }
        let shape = Shape {
            foreign_inputs: 0,
            has_issuance: true,
            fixed_output_scripts: fixed,
            blinded_fixed_outputs: 0,
        };
        let funding = self.fund(
            Vec::new(),
            candidates,
            &BTreeMap::new(),
            &shape,
            request.fee_rate,
            &BTreeSet::new(),
        )?;
        let issuer = funding
            .inputs
            .first()
            .filter(|utxo| utxo.asset == self.policy_asset)
            .ok_or_else(|| WalletError::InvalidRequest("issuance needs a policy input".into()))?;
        let (asset_id, token_id) = issuance_ids(issuer.outpoint, contract_hash, false);

        let mut pset = PartiallySignedTransaction::new_v2();
        for (index, utxo) in funding.inputs.iter().enumerate() {
            let mut input = self.wallet_input(utxo, EcdsaSighashType::All)?;
            if index == 0 {
                input.issuance_value_amount = Some(request.amount);
                input.issuance_inflation_keys =
                    (request.token_amount > 0).then_some(request.token_amount);
                input.issuance_asset_entropy = Some(contract_hash.to_byte_array());
            }
            pset.add_input(input);
        }
        // Issued asset and token outputs stay explicit (registry-verifiable);
        // only change follows the confidential-input rule.
        pset.add_output(self.wallet_output(
            asset_id,
            request.amount,
            Branch::External,
            request.receive_index,
            false,
        )?);
        if request.token_amount > 0 {
            pset.add_output(self.wallet_output(
                token_id,
                request.token_amount,
                Branch::External,
                request.receive_index,
                false,
            )?);
        }
        self.add_changes_and_fee(&mut pset, &funding, request.change_index)?;
        self.finish(pset, TxKind::Issuance, &funding.inputs)
    }

    /// Self-send creating an output of exactly `amount` so it can be offered.
    pub fn prepare_offer_split(
        &self,
        request: &OfferSplitRequest,
    ) -> Result<PreparedTx, WalletError> {
        validate_amount(request.amount)?;
        let asset = parse_asset(&request.asset_id)?;
        let candidates = self.parse_utxos(&request.utxos)?;
        let needs = BTreeMap::from([(asset, request.amount)]);
        let shape = Shape {
            foreign_inputs: 0,
            has_issuance: false,
            fixed_output_scripts: vec![P2WPKH_SCRIPT_LEN],
            blinded_fixed_outputs: 0,
        };
        let funding = self.fund(
            Vec::new(),
            candidates,
            &needs,
            &shape,
            request.fee_rate,
            &BTreeSet::new(),
        )?;
        let mut pset = PartiallySignedTransaction::new_v2();
        self.add_wallet_inputs(&mut pset, &funding.inputs)?;
        // The offerable output is always explicit, even from confidential
        // inputs, because swap offers are explicit-only.
        pset.add_output(self.wallet_output(
            asset,
            request.amount,
            Branch::External,
            request.receive_index,
            false,
        )?);
        self.add_changes_and_fee(&mut pset, &funding, request.change_index)?;
        self.finish(pset, TxKind::OfferSplit, &funding.inputs)
    }

    /// Maker: offer one whole UTXO for `want_amount` of `want_asset`.
    pub fn prepare_swap_offer(
        &self,
        request: &SwapOfferRequest,
    ) -> Result<PreparedTx, WalletError> {
        validate_amount(request.want_amount)?;
        let want_asset = parse_asset(&request.want_asset)?;
        let utxo = self.parse_and_verify_utxo(&request.utxo)?;
        if utxo.blinding.is_some() {
            return Err(WalletError::Confidential(format!(
                "{} is confidential; swap offers are explicit-only, so split it to an \
                 explicit output with an offer split first",
                crate::outpoint_label(&utxo.outpoint)
            )));
        }
        if utxo.asset == want_asset {
            return Err(WalletError::InvalidRequest(
                "offer must want a different asset than it gives".into(),
            ));
        }
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(self.wallet_input(&utxo, EcdsaSighashType::SinglePlusAnyoneCanPay)?);
        pset.add_output(self.wallet_output(
            want_asset,
            request.want_amount,
            Branch::External,
            request.receive_index,
            false,
        )?);
        self.finish(pset, TxKind::SwapOffer, &[])
    }

    /// Taker: fill one or more whole offers.
    pub fn take_swap_offers(
        &self,
        request: &TakeSwapOffersRequest,
    ) -> Result<PreparedTx, WalletError> {
        if request.offers.is_empty() || request.offers.len() > MAX_REQUEST_ITEMS {
            return Err(WalletError::InvalidRequest(
                "between one and 500 offers are required".into(),
            ));
        }
        let mut verified: Vec<VerifiedOffer> = Vec::with_capacity(request.offers.len());
        let mut maker_outpoints = BTreeSet::new();
        for entry in &request.offers {
            let offer = match &entry.offer {
                OfferInput::Object(offer) => offer.clone(),
                OfferInput::Json(json) => parse_offer_json(json)?,
            };
            let offer = verify_offer(
                &offer,
                &entry.prevout_raw_tx_hex,
                self.genesis_hash,
                self.native_address_params,
            )?;
            if !maker_outpoints.insert(offer.tx.input[0].previous_output) {
                return Err(WalletError::Offer("the same offer appears twice".into()));
            }
            verified.push(offer);
        }

        let mut needs: BTreeMap<AssetId, u64> = BTreeMap::new();
        let mut receives: BTreeMap<AssetId, u64> = BTreeMap::new();
        for offer in &verified {
            let need = needs.entry(offer.want_asset).or_default();
            *need = need
                .checked_add(offer.want_amount)
                .ok_or(WalletError::AmountOverflow)?;
            let receive = receives.entry(offer.give_asset).or_default();
            *receive = receive
                .checked_add(offer.give_amount)
                .ok_or(WalletError::AmountOverflow)?;
        }
        if receives
            .values()
            .chain(needs.values())
            .any(|v| *v > MAX_MONEY)
        {
            return Err(WalletError::AmountOverflow);
        }

        // Swap takes are explicit-only: confidential wallet UTXOs are never
        // selected, and an underfunded take says why.
        let (confidential, candidates): (Vec<_>, Vec<_>) = self
            .parse_utxos(&request.utxos)?
            .into_iter()
            .filter(|utxo| !maker_outpoints.contains(&utxo.outpoint))
            .partition(|utxo| utxo.blinding.is_some());
        let mut fixed: Vec<u64> = verified
            .iter()
            .map(|offer| offer.tx.output[0].script_pubkey.len() as u64)
            .collect();
        fixed.extend(std::iter::repeat_n(P2WPKH_SCRIPT_LEN, receives.len()));
        let shape = Shape {
            foreign_inputs: verified.len() as u64,
            has_issuance: false,
            fixed_output_scripts: fixed,
            blinded_fixed_outputs: 0,
        };
        let funding = self
            .fund(
                Vec::new(),
                candidates,
                &needs,
                &shape,
                request.fee_rate,
                &maker_outpoints,
            )
            .map_err(|error| match error {
                WalletError::InsufficientFunds {
                    asset,
                    needed,
                    available,
                } if !confidential.is_empty() => WalletError::Confidential(format!(
                    "insufficient explicit funds for asset {asset} (need {needed}, have \
                     {available}); swap takes cannot spend the {} confidential UTXO(s) \
                     supplied — send them to yourself as explicit outputs first",
                    confidential.len()
                )),
                other => other,
            })?;

        let mut pset = PartiallySignedTransaction::new_v2();
        for offer in &verified {
            let txin = &offer.tx.input[0];
            let mut input = Input::from_prevout(txin.previous_output);
            input.sequence = Some(txin.sequence);
            input.witness_utxo = Some(offer.prevout.clone());
            input.asset = Some(offer.give_asset);
            input.amount = Some(offer.give_amount);
            input.final_script_witness = Some(txin.witness.script_witness.clone());
            pset.add_input(input);
        }
        self.add_wallet_inputs(&mut pset, &funding.inputs)?;
        for offer in &verified {
            pset.add_output(Output::from_txout(offer.tx.output[0].clone()));
        }
        for (asset, amount) in &receives {
            pset.add_output(self.wallet_output(
                *asset,
                *amount,
                Branch::External,
                request.receive_index,
                false,
            )?);
        }
        self.add_changes_and_fee(&mut pset, &funding, request.change_index)?;
        self.finish(pset, TxKind::SwapTake, &[])
    }

    /// Spend an offered UTXO back to this wallet, invalidating the offer.
    pub fn prepare_cancel(&self, request: &CancelRequest) -> Result<PreparedTx, WalletError> {
        let utxo = self.parse_and_verify_utxo(&request.utxo)?;
        let candidates = self.parse_utxos(&request.other_utxos)?;
        let shape = Shape {
            foreign_inputs: 0,
            has_issuance: false,
            fixed_output_scripts: Vec::new(),
            blinded_fixed_outputs: 0,
        };
        let funding = self.fund(
            vec![utxo],
            candidates,
            &BTreeMap::new(),
            &shape,
            request.fee_rate,
            &BTreeSet::new(),
        )?;
        if funding.changes.is_empty() {
            return Err(WalletError::InsufficientFunds {
                asset: self.policy_asset.to_string(),
                needed: funding.fee.saturating_add(POLICY_DUST_LIMIT),
                available: funding.fee,
            });
        }
        let mut pset = PartiallySignedTransaction::new_v2();
        self.add_wallet_inputs(&mut pset, &funding.inputs)?;
        self.add_changes_and_fee(&mut pset, &funding, request.change_index)?;
        self.finish(pset, TxKind::Cancel, &funding.inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsize_estimate_is_monotonic_and_bounded() {
        let one = estimate_vsize(1, false, &[22, 22, 0], 0).unwrap();
        let two = estimate_vsize(2, false, &[22, 22, 0], 0).unwrap();
        assert!(two > one);
        assert!(
            estimate_vsize(1, true, &[22, 0], 0).unwrap()
                > estimate_vsize(1, false, &[22, 0], 0).unwrap()
        );
        // 1-in/3-out explicit P2WPKH Elements tx is ~ 230 vB; keep the bound sane.
        assert!((200..400).contains(&one), "{one}");
        assert!(estimate_vsize(u64::MAX, false, &[], 0).is_err());
        let blinded = estimate_vsize(1, false, &[22, 22, 0], 2).unwrap();
        assert!(blinded > one + 2 * 1_000, "{blinded}");
    }

    #[test]
    fn fee_rate_bounds() {
        assert!(validate_fee_rate(0).is_err());
        assert!(validate_fee_rate(1).is_ok());
        assert!(validate_fee_rate(MAX_FEE_RATE + 1).is_err());
    }
}
