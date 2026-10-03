//! Instant: feasibility prototype of the lockbox + pooled operator bond
//! covenants described in `SPEC.md`. Experimental; not audited; no wallet key
//! storage, no networking, no broadcasting (the `live_regtest` example does
//! that against a disposable regtest node only).
//!
//! The Taproot/satisfaction machinery is adapted from JK's
//! `elementsplus-preconf` (`preconf/vendor/elementsplus-preconf/src/lib.rs`:
//! `bond_taproot`, `bond_environment`, `satisfy_bond`), generalised to
//! multi-input transactions (the input index is a parameter).

pub mod announce;
pub mod bond;
pub mod hash;
pub mod lockbox;
pub mod policy;
pub mod watchtower;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use elements::{
    secp256k1_zkp::{Secp256k1, XOnlyPublicKey},
    taproot::{ControlBlock, TaprootBuilder},
    BlockHash, Script, Transaction,
};
use simplicity::{
    jet::elements::{ElementsEnv, ElementsUtxo},
    BitMachine, Cmr,
};
use simplicityhl::str::WitnessName;
use simplicityhl::types::{ResolvedType, TypeConstructible};
use simplicityhl::value::UIntValue;
pub use simplicityhl::value::Value as Action;
pub use simplicityhl::{elements, simplicity};
use simplicityhl::{Arguments, CompiledProgram, WitnessValues};

/// BIP341 NUMS point. No known private key: the Simplicity leaf is the only
/// spending path. Receivers MUST reject any other internal key or tree.
pub const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub(crate) fn word(bytes: &[u8; 32]) -> Action {
    UIntValue::try_from(bytes.as_slice())
        .expect("32-byte word")
        .into()
}

pub(crate) fn signature_type() -> ResolvedType {
    ResolvedType::array(ResolvedType::u8(), 64)
}

pub(crate) fn compile(source: &str, args: Vec<(&str, Action)>) -> Result<Compiled, String> {
    let args = Arguments::from(
        args.into_iter()
            .map(|(name, value)| (WitnessName::from_str_unchecked(name), value))
            .collect::<HashMap<_, _>>(),
    );
    let program = CompiledProgram::new(
        source,
        args,
        false,
        Box::new(simplicityhl::ast::ElementsJetHinter),
    )?;
    let cmr = program.commit().cmr();
    let leaf = Script::from(cmr.as_ref().to_vec());
    let info = TaprootBuilder::new()
        .add_leaf_with_ver(0, leaf.clone(), simplicity::leaf_version())
        .map_err(|e| e.to_string())?
        .finalize(
            &Secp256k1::verification_only(),
            XOnlyPublicKey::from_str(NUMS).map_err(|e| e.to_string())?,
        )
        .map_err(|_| "cannot finalize single-leaf Taproot tree")?;
    let control = info
        .control_block(&(leaf, simplicity::leaf_version()))
        .ok_or("missing single-leaf control block")?;
    Ok(Compiled {
        program,
        cmr,
        script_pubkey: Script::new_v1_p2tr_tweaked(info.output_key()),
        control,
    })
}

/// A compiled single-leaf Simplicity covenant and its Taproot output.
pub struct Compiled {
    program: CompiledProgram,
    cmr: Cmr,
    script_pubkey: Script,
    control: ControlBlock,
}

impl Compiled {
    pub fn cmr(&self) -> Cmr {
        self.cmr
    }
    pub fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }
    pub fn control_block(&self) -> &ControlBlock {
        &self.control
    }

    /// Execution environment for input `index` of `tx`. `utxos` is the
    /// caller-supplied spent output of every input (NOT a chain lookup).
    pub fn environment(
        &self,
        tx: Transaction,
        utxos: Vec<ElementsUtxo>,
        index: u32,
        genesis: BlockHash,
    ) -> Result<ElementsEnv<Arc<Transaction>>, String> {
        if tx.input.is_empty() || utxos.len() != tx.input.len() {
            return Err("one UTXO description per input is required".into());
        }
        if index as usize >= tx.input.len() {
            return Err("input index out of range".into());
        }
        Ok(ElementsEnv::new(
            Arc::new(tx),
            utxos,
            index,
            self.cmr,
            self.control.clone(),
            None,
            genesis,
        ))
    }

    /// `jet::sig_all_hash()` for this environment.
    pub fn sig_all_hash(env: &ElementsEnv<Arc<Transaction>>) -> [u8; 32] {
        use elements::hashes::Hash;
        env.c_tx_env().sighash_all().to_byte_array()
    }

    /// Prune and EXECUTE the real Simplicity program with the given witness;
    /// return the consensus witness stack `[witness, program, cmr, control]`.
    /// An `Err` means the covenant rejected the spend.
    pub fn satisfy(
        &self,
        env: &ElementsEnv<Arc<Transaction>>,
        action: &Action,
    ) -> Result<Vec<Vec<u8>>, String> {
        let witness = WitnessValues::from(
            [(WitnessName::from_str_unchecked("ACTION"), action.clone())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        );
        let satisfied = self.program.satisfy_with_env(witness, Some(env))?;
        let redeem = satisfied.redeem();
        let mut machine = BitMachine::for_program(redeem).map_err(|e| e.to_string())?;
        machine.exec(redeem, env).map_err(|e| e.to_string())?;
        let (encoded, witness) = redeem.to_vec_with_witness();
        Ok(vec![
            witness,
            encoded,
            self.cmr.as_ref().to_vec(),
            self.control.serialize(),
        ])
    }
}

/// BIP340-sign a 32-byte digest (deterministic nonce; tests/regtest only).
pub fn sign_digest(digest: [u8; 32], key: &elements::secp256k1_zkp::Keypair) -> [u8; 64] {
    *Secp256k1::new()
        .sign_schnorr_no_aux_rand(&elements::secp256k1_zkp::Message::from_digest(digest), key)
        .as_ref()
}

/// Verify a BIP340 signature over a 32-byte digest.
pub fn verify_digest(digest: [u8; 32], sig: &[u8; 64], key: &XOnlyPublicKey) -> bool {
    let Ok(sig) = elements::secp256k1_zkp::schnorr::Signature::from_slice(sig) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(
            &sig,
            &elements::secp256k1_zkp::Message::from_digest(digest),
            key,
        )
        .is_ok()
}
