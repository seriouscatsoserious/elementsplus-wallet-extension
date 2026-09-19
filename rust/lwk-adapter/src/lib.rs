//! ECX Alpha compatibility helpers for the exact LWK revision pinned in
//! `UPSTREAM_PINS.toml`.
//!
//! This crate is deliberately small. It proves the frozen network identity,
//! parses and hashes the fork's extended block headers, and enforces the
//! explicit-output policy at the wallet boundary. It does not claim to make
//! stock LWK's Esplora scanner understand ECX headers; see `PATCH_PLAN.md`.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::str::FromStr;

use bech32::Hrp;
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::{Decodable, Encodable};
use elements::hashes::Hash;
use elements::pset::PartiallySignedTransaction;
use elements::{
    bitcoin, dynafed, Address, AddressParams, AssetId, BlockExtData, BlockHash, Script,
    Transaction, TxMerkleNode, TxOut,
};
use lwk_common::{ElementsParamsBuilder, Network};
use thiserror::Error;

/// LWK commit audited by this adapter.
pub const LWK_REVISION: &str = "55671e82c0cc713ece341f74704ff39255c633ec";

/// Exact commit behind the last published ECX Alpha desktop-r2 binary.
///
/// That release enforces explicit outputs from height 84. Current repository
/// `master` accepts confidential payments without changing the chain identity,
/// so explicit-only handling in this crate is a wallet policy, not a claim
/// about every validator on the live network.
pub const ELEMENTS_PLUS_REVISION: &str = "b2b928fd65e02901d8a98ee38adfe35dfb0f379f";
pub const ELEMENTS_PLUS_RELEASE_TAG: &str = "elements-alpha-cad1fc1fb-desktop-r2";
pub const ELEMENTS_PLUS_CURRENT_MASTER_REVISION: &str =
    "4041a8ba5d9c0870dbe22c188bce28410c10348a";

pub const NETWORK_NAME: &str = "ECX Alpha";
pub const SIDECHAIN_SLOT: u8 = 24;
pub const EXPLICIT_ONLY_HEIGHT: u32 = 84;
pub const EXPLORER_API: &str = "https://explorer.bitnames.info/api";
pub const SEED_PEER: &str = "163.192.123.236:39444";

pub const GENESIS_HASH: &str = "672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd";
pub const PARENT_GENESIS_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
pub const POLICY_ASSET: &str = "62dce3bd80dc4b0503e7ccbb3fcfa4d7adfd64b4e0cc78fa5e1754b88f1d2da4";

/// Native address encoding frozen by the ECX Alpha node.
///
/// The node also accepts `ert`/`el` witness-address aliases for LWK, but those
/// aliases do not identify this chain. Base58 aliases were not added.
pub static NATIVE_ADDRESS_PARAMS: AddressParams = AddressParams {
    p2pkh_prefix: 68,
    p2sh_prefix: 13,
    blinded_prefix: 6,
    bech_hrp: Hrp::parse_unchecked("elements"),
    blech_hrp: Hrp::parse_unchecked("elementsl"),
};

const DYNAFED_HF_MASK: u32 = 1 << 31;
const WITHDRAWAL_BUNDLE_HF_MASK: u32 = 1 << 30;
const BMM_PROOF_HF_MASK: u32 = 1 << 20;
const EXCHANGE_STATE_HF_MASK: u32 = 1 << 19;
const FORCED_INBOX_HF_MASK: u32 = 1 << 18;
const DEPOSIT_INBOX_HF_MASK: u32 = 1 << 17;
const INBOX_CURSOR_HF_MASK: u32 = 1 << 16;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("header decode failed: {0}")]
    Decode(#[from] elements::encode::Error),
    #[error("ECX header has {0} trailing byte(s)")]
    TrailingHeaderBytes(usize),
    #[error("output {vout} is confidential; this wallet build permits explicit outputs only")]
    ConfidentialOutput { vout: usize },
    #[error("output {vout} is missing its explicit asset or amount")]
    IncompletePsetOutput { vout: usize },
    #[error("output {vout} requests blinding; ECX Alpha desktop-r2 requires explicit outputs")]
    BlindingRequested { vout: usize },
    #[error("fee output {vout} uses {actual}, expected policy asset {expected}")]
    WrongFeeAsset {
        vout: usize,
        actual: AssetId,
        expected: AssetId,
    },
    #[error("amount overflow for asset {0}")]
    AmountOverflow(AssetId),
}

/// Build LWK's custom-network value with all identity fields that upstream LWK
/// currently permits callers to set.
///
/// LWK still returns `AddressParams::ELEMENTS` for this network. That is safe
/// only for witness addresses because the ECX node explicitly accepts `ert`
/// and `el` as aliases. Call [`native_unconfidential_address`] for native
/// `elements1...` display strings.
pub fn lwk_network() -> Network {
    let policy_asset = AssetId::from_str(POLICY_ASSET).expect("frozen policy asset");
    let genesis = BlockHash::from_str(GENESIS_HASH).expect("frozen genesis hash");
    let parent_genesis =
        bitcoin::BlockHash::from_str(PARENT_GENESIS_HASH).expect("frozen parent genesis hash");

    Network::CustomElements(
        ElementsParamsBuilder::new()
            .with_policy_asset(policy_asset)
            .with_genesis_hash(genesis)
            .with_parent_genesis_hash(parent_genesis)
            .build()
            .expect("frozen ECX Alpha parameters"),
    )
}

/// Render a known witness script with the chain's native unconfidential HRP.
pub fn native_unconfidential_address(script_pubkey: &Script) -> Option<Address> {
    Address::from_script(script_pubkey, None, &NATIVE_ADDRESS_PARAMS)
}

/// ECX-only data appended around the ordinary Elements header fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcxHeaderExtension {
    pub withdrawal_bundle_hash: Option<BlockHash>,
    pub bmm_proof_hash: Option<BlockHash>,
    pub exchange_state_root: Option<BlockHash>,
    pub forced_inbox_root: Option<BlockHash>,
    pub deposit_inbox_root: Option<BlockHash>,
    pub parent_height: Option<u32>,
    pub forced_processed_cursor: Option<u64>,
    pub deposit_processed_cursor: Option<u64>,
    pub source_backlog_oldest_parent_height: Option<u64>,
}

/// Parsed ECX Alpha block header.
///
/// Stock `elements::BlockHeader` cannot represent these fields, which is why
/// the LWK scanner patch cannot be reduced to network constants alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcxBlockHeader {
    pub raw_version: u32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: TxMerkleNode,
    pub time: u32,
    pub height: u32,
    pub ext: BlockExtData,
    pub ecx: EcxHeaderExtension,
}

impl EcxBlockHeader {
    pub fn decode(bytes: &[u8]) -> Result<Self, AdapterError> {
        let mut cursor = Cursor::new(bytes);
        let raw_version = u32::consensus_decode(&mut cursor)?;
        let is_dynafed = raw_version & DYNAFED_HF_MASK != 0;

        let prev_blockhash = BlockHash::consensus_decode(&mut cursor)?;
        let merkle_root = TxMerkleNode::consensus_decode(&mut cursor)?;
        let withdrawal_bundle_hash =
            decode_if(raw_version & WITHDRAWAL_BUNDLE_HF_MASK != 0, &mut cursor)?;
        let bmm_proof_hash = decode_if(raw_version & BMM_PROOF_HF_MASK != 0, &mut cursor)?;
        let time = u32::consensus_decode(&mut cursor)?;
        let height = u32::consensus_decode(&mut cursor)?;

        let ext = if is_dynafed {
            BlockExtData::Dynafed {
                current: dynafed::Params::consensus_decode(&mut cursor)?,
                proposed: dynafed::Params::consensus_decode(&mut cursor)?,
                signblock_witness: Vec::<Vec<u8>>::consensus_decode(&mut cursor)?,
            }
        } else {
            BlockExtData::Proof {
                challenge: Script::consensus_decode(&mut cursor)?,
                solution: Script::consensus_decode(&mut cursor)?,
            }
        };

        let exchange_state_root =
            decode_if(raw_version & EXCHANGE_STATE_HF_MASK != 0, &mut cursor)?;
        let forced_inbox_root = decode_if(raw_version & FORCED_INBOX_HF_MASK != 0, &mut cursor)?;
        let deposit_inbox_root = decode_if(raw_version & DEPOSIT_INBOX_HF_MASK != 0, &mut cursor)?;
        let parent_height = decode_if(
            raw_version & FORCED_INBOX_HF_MASK != 0 && raw_version & DEPOSIT_INBOX_HF_MASK != 0,
            &mut cursor,
        )?;
        let forced_processed_cursor =
            decode_if(raw_version & INBOX_CURSOR_HF_MASK != 0, &mut cursor)?;
        let deposit_processed_cursor =
            decode_if(raw_version & INBOX_CURSOR_HF_MASK != 0, &mut cursor)?;
        let source_backlog_oldest_parent_height =
            decode_if(raw_version & INBOX_CURSOR_HF_MASK != 0, &mut cursor)?;

        let consumed = cursor.position() as usize;
        if consumed != bytes.len() {
            return Err(AdapterError::TrailingHeaderBytes(bytes.len() - consumed));
        }

        Ok(Self {
            raw_version,
            prev_blockhash,
            merkle_root,
            time,
            height,
            ext,
            ecx: EcxHeaderExtension {
                withdrawal_bundle_hash,
                bmm_proof_hash,
                exchange_state_root,
                forced_inbox_root,
                deposit_inbox_root,
                parent_height,
                forced_processed_cursor,
                deposit_processed_cursor,
                source_backlog_oldest_parent_height,
            },
        })
    }

    /// Calculate the consensus block hash. Header witnesses (`solution` or
    /// dynafed signblock witness) are intentionally omitted, matching the ECX
    /// node's `CBlockHeader::GetHash()` implementation.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.raw_version.consensus_encode(&mut engine).unwrap();
        self.prev_blockhash.consensus_encode(&mut engine).unwrap();
        self.merkle_root.consensus_encode(&mut engine).unwrap();
        encode_optional(&self.ecx.withdrawal_bundle_hash, &mut engine);
        encode_optional(&self.ecx.bmm_proof_hash, &mut engine);
        self.time.consensus_encode(&mut engine).unwrap();
        self.height.consensus_encode(&mut engine).unwrap();
        match &self.ext {
            BlockExtData::Proof { challenge, .. } => {
                challenge.consensus_encode(&mut engine).unwrap();
            }
            BlockExtData::Dynafed {
                current, proposed, ..
            } => {
                current.consensus_encode(&mut engine).unwrap();
                proposed.consensus_encode(&mut engine).unwrap();
            }
        }
        encode_optional(&self.ecx.exchange_state_root, &mut engine);
        encode_optional(&self.ecx.forced_inbox_root, &mut engine);
        encode_optional(&self.ecx.deposit_inbox_root, &mut engine);
        encode_optional(&self.ecx.parent_height, &mut engine);
        encode_optional(&self.ecx.forced_processed_cursor, &mut engine);
        encode_optional(&self.ecx.deposit_processed_cursor, &mut engine);
        encode_optional(&self.ecx.source_backlog_oldest_parent_height, &mut engine);
        BlockHash::from_engine(engine)
    }
}

fn decode_if<T: Decodable>(
    present: bool,
    cursor: &mut Cursor<&[u8]>,
) -> Result<Option<T>, elements::encode::Error> {
    if present {
        T::consensus_decode(cursor).map(Some)
    } else {
        Ok(None)
    }
}

fn encode_optional<T: Encodable, W: std::io::Write>(value: &Option<T>, writer: &mut W) {
    if let Some(value) = value {
        value.consensus_encode(writer).unwrap();
    }
}

/// Sum only fully explicit, non-fee transaction outputs by asset.
pub fn explicit_balance<'a>(
    outputs: impl IntoIterator<Item = &'a TxOut>,
) -> Result<BTreeMap<AssetId, u64>, AdapterError> {
    let mut balance = BTreeMap::new();
    for (vout, output) in outputs.into_iter().enumerate() {
        if output.is_fee() {
            continue;
        }
        let (Asset::Explicit(asset), Value::Explicit(value), Nonce::Null) =
            (output.asset, output.value, output.nonce)
        else {
            return Err(AdapterError::ConfidentialOutput { vout });
        };
        checked_add(&mut balance, asset, value)?;
    }
    Ok(balance)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitOutputPreview {
    pub vout: usize,
    pub asset: AssetId,
    pub amount: u64,
    pub is_fee: bool,
    pub script_pubkey: Script,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitPsetPreview {
    pub outputs: Vec<ExplicitOutputPreview>,
    pub fees: BTreeMap<AssetId, u64>,
}

/// Inspect an unsigned PSET before signing and reject every confidential or
/// blinding-intent output. This is intentionally independent of UI rendering.
pub fn preview_explicit_pset(
    pset: &PartiallySignedTransaction,
    expected_fee_asset: AssetId,
) -> Result<ExplicitPsetPreview, AdapterError> {
    let mut outputs = Vec::with_capacity(pset.outputs().len());
    let mut fees = BTreeMap::new();

    for (vout, output) in pset.outputs().iter().enumerate() {
        if output.amount_comm.is_some() || output.asset_comm.is_some() {
            return Err(AdapterError::ConfidentialOutput { vout });
        }
        if output.blinding_key.is_some()
            || output.ecdh_pubkey.is_some()
            || output.blinder_index.is_some()
        {
            return Err(AdapterError::BlindingRequested { vout });
        }
        let (Some(asset), Some(amount)) = (output.asset, output.amount) else {
            return Err(AdapterError::IncompletePsetOutput { vout });
        };
        let is_fee = output.script_pubkey.is_empty();
        if is_fee {
            if asset != expected_fee_asset {
                return Err(AdapterError::WrongFeeAsset {
                    vout,
                    actual: asset,
                    expected: expected_fee_asset,
                });
            }
            checked_add(&mut fees, asset, amount)?;
        }
        outputs.push(ExplicitOutputPreview {
            vout,
            asset,
            amount,
            is_fee,
            script_pubkey: output.script_pubkey.clone(),
        });
    }

    Ok(ExplicitPsetPreview { outputs, fees })
}

/// Reject a finalized transaction if any output would violate this wallet's
/// explicit-only policy. This should run immediately before broadcast as a
/// defense in depth check.
pub fn validate_explicit_transaction(tx: &Transaction) -> Result<(), AdapterError> {
    for (vout, output) in tx.output.iter().enumerate() {
        if !matches!(output.asset, Asset::Explicit(_))
            || !matches!(output.value, Value::Explicit(_))
            || !matches!(output.nonce, Nonce::Null)
        {
            return Err(AdapterError::ConfidentialOutput { vout });
        }
    }
    Ok(())
}

fn checked_add(
    totals: &mut BTreeMap<AssetId, u64>,
    asset: AssetId,
    amount: u64,
) -> Result<(), AdapterError> {
    let current = totals.entry(asset).or_default();
    *current = current
        .checked_add(amount)
        .ok_or(AdapterError::AmountOverflow(asset))?;
    Ok(())
}
