//! Thin JSON boundary for the MV3 extension (spec §1.3). All logic lives in
//! the native Rust API; these wrappers only parse, call, and serialize.

use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::*;

fn js_error(error: WalletError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

fn parse<T: DeserializeOwned>(json: &str, what: &str) -> Result<T, JsValue> {
    if json.len() > MAX_REQUEST_JSON_BYTES {
        return Err(JsValue::from_str(&format!("{what} JSON is too large")));
    }
    serde_json::from_str(json).map_err(|e| JsValue::from_str(&format!("invalid {what} JSON: {e}")))
}

fn to_json<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub struct WasmWalletCore {
    inner: WalletCore,
}

#[wasm_bindgen]
impl WasmWalletCore {
    #[wasm_bindgen(constructor)]
    pub fn new(mnemonic: &str) -> Result<WasmWalletCore, JsValue> {
        WalletCore::new(mnemonic)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Test-only constructor for the isolated Elements+ functional chain.
    /// It is absent from the reviewed production WASM artifact.
    #[cfg(feature = "regtest")]
    #[wasm_bindgen(js_name = forRegtest)]
    pub fn for_regtest(
        mnemonic: &str,
        genesis_hash: &str,
        policy_asset: &str,
        display_name: &str,
    ) -> Result<WasmWalletCore, JsValue> {
        WalletCore::new_for_regtest(mnemonic, genesis_hash, policy_asset, display_name)
            .map(|inner| Self { inner })
            .map_err(js_error)
    }

    /// Derive an address. `confidential` overrides the wallet default set by
    /// `set_confidential_receive` (omitted/undefined keeps the default).
    pub fn derive_address_json(
        &self,
        branch: &str,
        index: u32,
        confidential: Option<bool>,
    ) -> Result<String, JsValue> {
        let branch = match branch {
            "external" => Branch::External,
            "change" => Branch::Change,
            _ => return Err(JsValue::from_str("invalid branch")),
        };
        to_json(
            &self
                .inner
                .derive_address_with(branch, index, confidential)
                .map_err(js_error)?,
        )
    }

    /// Make default receive addresses confidential (off by default). Only
    /// address derivation changes; owned confidential outputs are always
    /// unblinded and spendable.
    pub fn set_confidential_receive(&mut self, enabled: bool) {
        self.inner.set_confidential_receive(enabled);
    }

    pub fn confidential_receive(&self) -> bool {
        self.inner.confidential_receive()
    }

    /// Verify raw transaction bytes and decode the requested wallet outputs;
    /// confidential outputs are unblinded with this wallet's SLIP-77 key.
    pub fn verify_raw_transaction_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "verification")?;
        to_json(
            &self
                .inner
                .verify_raw_transaction(&request)
                .map_err(js_error)?,
        )
    }

    pub fn prepare_transfer_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "transfer request")?;
        to_json(&self.inner.prepare_transfer(&request).map_err(js_error)?)
    }

    pub fn prepare_issuance_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "issuance request")?;
        to_json(&self.inner.prepare_issuance(&request).map_err(js_error)?)
    }

    pub fn prepare_offer_split_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "offer split request")?;
        to_json(&self.inner.prepare_offer_split(&request).map_err(js_error)?)
    }

    pub fn prepare_swap_offer_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "swap offer request")?;
        to_json(&self.inner.prepare_swap_offer(&request).map_err(js_error)?)
    }

    pub fn take_swap_offers_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "take offers request")?;
        to_json(&self.inner.take_swap_offers(&request).map_err(js_error)?)
    }

    pub fn prepare_cancel_json(&self, request_json: &str) -> Result<String, JsValue> {
        let request = parse(request_json, "cancel request")?;
        to_json(&self.inner.prepare_cancel(&request).map_err(js_error)?)
    }

    pub fn sign_prepared_json(
        &self,
        prepared_json: &str,
        approved_review_hash: &str,
    ) -> Result<String, JsValue> {
        let prepared = parse(prepared_json, "prepared transaction")?;
        to_json(
            &self
                .inner
                .sign_prepared(&prepared, approved_review_hash)
                .map_err(js_error)?,
        )
    }

    /// Decode an offer against this wallet's configured network (the free
    /// `decode_offer_json` is pinned to ECX Alpha).
    pub fn decode_offer_json(
        &self,
        offer_json: &str,
        prevout_raw_tx_hex: &str,
    ) -> Result<String, JsValue> {
        to_json(
            &self
                .inner
                .decode_offer(offer_json, prevout_raw_tx_hex)
                .map_err(js_error)?,
        )
    }
}

#[wasm_bindgen]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    WalletCore::validate_mnemonic(mnemonic).is_ok()
}

#[wasm_bindgen]
pub fn generate_mnemonic() -> Result<String, JsValue> {
    WalletCore::generate_mnemonic().map_err(js_error)
}

/// `{raw_tx_hex, expected_txid, vin, contract}` → `{asset_id, token_id|null, contract_hash}`.
#[wasm_bindgen]
pub fn verify_asset_issuance_json(request_json: &str) -> Result<String, JsValue> {
    let request = parse(request_json, "issuance verification")?;
    to_json(&verify_asset_issuance(&request).map_err(js_error)?)
}

/// Verify an offer for the pinned ECX Alpha network.
#[wasm_bindgen]
pub fn decode_offer_json(offer_json: &str, prevout_raw_tx_hex: &str) -> Result<String, JsValue> {
    to_json(&decode_offer(offer_json, prevout_raw_tx_hex).map_err(js_error)?)
}
