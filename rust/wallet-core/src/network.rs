//! Typed network profile registry.
//!
//! Mirrors `src/network/profiles.ts` in the extension (keep both in step; see
//! `docs/NETWORKS.md`). A profile is the complete chain identity a wallet build
//! is pinned to. Profiles whose sidechain parameters have not been published
//! are [`ProfileStatus::Pending`]: their pins are `None` and every constructor
//! refuses them rather than guessing. The retired ECX Alpha chain is kept as an
//! [`ProfileStatus::Archived`] entry so historical vectors keep verifying; it
//! is not selectable by builds or the CLI.

use std::str::FromStr;

use elements::bitcoin;
use elements::{AddressParams, AssetId, BlockHash};
use elementsplus_lwk_adapter as alpha;
use lwk_common::{ElementsParamsBuilder, Network};
use serde::Serialize;
use thiserror::Error;

/// Lifecycle of a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileStatus {
    /// All pins are known; builds and the CLI may target it.
    Live,
    /// The chain exists (or is planned) but its sidechain pins are unknown.
    Pending,
    /// Retired chain kept only for historical test vectors.
    Archived,
}

/// Where the sidechain pins come from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileKind {
    /// Public network; pins are compiled from this registry.
    Public,
    /// Disposable local chain; pins are read from the local node at build or
    /// configuration time (`.regtest/network.json`, `epw config`).
    LocalRegtest,
}

/// The eCash L1 (parent chain) a sidechain profile hangs off.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct L1Profile {
    pub network_id: &'static str,
    /// Parent-chain genesis hash used in the Elements network parameters.
    pub genesis_hash: Option<&'static str>,
    pub esplora_url: Option<&'static str>,
    pub explorer_url: Option<&'static str>,
}

/// Address encoding of a profile: the chain's native spelling plus the
/// generic-Elements alias LWK renders.
#[derive(Clone, Copy, Debug)]
pub struct AddressProfile {
    pub native: &'static AddressParams,
    pub alias: &'static AddressParams,
}

#[derive(Clone, Copy, Debug)]
pub struct NetworkProfile {
    /// Stable identifier; also the `network` field of every swap offer.
    pub id: &'static str,
    pub display_name: &'static str,
    pub status: ProfileStatus,
    pub kind: ProfileKind,
    pub sidechain_slot: u8,
    pub genesis_hash: Option<&'static str>,
    /// Pegged (policy / fee) asset id.
    pub policy_asset: Option<&'static str>,
    pub address: Option<AddressProfile>,
    /// Sidechain Esplora API base URL.
    pub esplora_url: Option<&'static str>,
    pub l1: L1Profile,
    /// DEX / asset-registry origin.
    pub dex_url: Option<&'static str>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NetworkProfileError {
    #[error("unknown network profile {0:?}; known profiles: ecx-beta, ecx-mainnet, elementsplus-regtest")]
    Unknown(String),
    #[error("network profile {0:?} is pending: not all of its pins (sidechain genesis, pegged asset, address encoding, sidechain Esplora URL) are published yet, so this wallet refuses to run on it (see docs/NETWORKS.md)")]
    Pending(&'static str),
    #[error("network profile {0:?} is archived (retired chain) and cannot be selected")]
    Archived(&'static str),
    #[error("network profile {0:?} takes its pins from a local node; use the regtest constructor")]
    LocalRegtest(&'static str),
    #[error("this wallet core was built without a network profile")]
    NotCompiled,
    #[error("network profile {0:?} has an invalid pin: {1}")]
    InvalidPin(&'static str, &'static str),
}

/// Retired ECX Alpha Elements sidechain (archived; historical vectors only).
pub const ECX_ALPHA: NetworkProfile = NetworkProfile {
    id: "ecx-alpha",
    display_name: "ECX Alpha (archived)",
    status: ProfileStatus::Archived,
    kind: ProfileKind::Public,
    sidechain_slot: alpha::SIDECHAIN_SLOT,
    genesis_hash: Some(alpha::GENESIS_HASH),
    policy_asset: Some(alpha::POLICY_ASSET),
    address: Some(AddressProfile {
        native: &alpha::NATIVE_ADDRESS_PARAMS,
        alias: &AddressParams::ELEMENTS,
    }),
    esplora_url: Some(alpha::EXPLORER_API),
    l1: L1Profile {
        network_id: "ecash-alpha",
        genesis_hash: Some(alpha::PARENT_GENESIS_HASH),
        esplora_url: None,
        explorer_url: None,
    },
    dex_url: None,
};

/// Elements sidechain in slot 24 on eCash betanet (activated at parent height
/// 970715). Pins come from Elements+ `doc/betanet-slot24-test.md` and
/// `src/elements_drivechain_identity.h` (master feb99d8b, 2026-10-02): a child
/// identity authenticated by the existing slot-24 proposal, with its own
/// genesis and native asset (not the Alpha chain's). Address encoding is
/// unchanged. Sidechain Esplora announced by JK on 2026-10-03.
pub const ECX_BETA: NetworkProfile = NetworkProfile {
    id: "ecx-beta",
    display_name: "eCash Beta · Elements",
    status: ProfileStatus::Live,
    kind: ProfileKind::Public,
    sidechain_slot: 24,
    genesis_hash: Some("a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f"),
    policy_asset: Some("5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8"),
    address: Some(AddressProfile {
        native: &alpha::NATIVE_ADDRESS_PARAMS,
        alias: &AddressParams::ELEMENTS,
    }),
    esplora_url: Some("https://explorer.bitnames.info/api"),
    l1: L1Profile {
        network_id: "ecash-beta",
        // Observed from the beta L1 Esplora `/block-height/0` (2026-10-02).
        genesis_hash: Some("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        esplora_url: Some("https://esplora.beta.ecash.ninja"),
        explorer_url: Some("https://explorer.beta.ecash.ninja"),
    },
    dex_url: None,
};

/// eCash mainnet Elements sidechain (planned ~2026-10-31).
pub const ECX_MAINNET: NetworkProfile = NetworkProfile {
    id: "ecx-mainnet",
    display_name: "eCash · Elements",
    status: ProfileStatus::Pending,
    kind: ProfileKind::Public,
    sidechain_slot: 24,
    genesis_hash: None,
    policy_asset: None,
    address: None,
    esplora_url: None,
    l1: L1Profile {
        network_id: "ecash-mainnet",
        genesis_hash: None,
        esplora_url: None,
        explorer_url: None,
    },
    dex_url: None,
};

/// Disposable local Elements+ functional-test chain. Genesis and policy asset
/// come from the local node.
pub const ELEMENTSPLUS_REGTEST: NetworkProfile = NetworkProfile {
    id: "elementsplus-regtest",
    display_name: "Elements+ local regtest",
    status: ProfileStatus::Live,
    kind: ProfileKind::LocalRegtest,
    sidechain_slot: 24,
    genesis_hash: None,
    policy_asset: None,
    address: Some(AddressProfile {
        native: &AddressParams::ELEMENTS,
        alias: &AddressParams::ELEMENTS,
    }),
    esplora_url: Some("http://127.0.0.1:43199/api"),
    l1: L1Profile {
        network_id: "regtest",
        genesis_hash: Some("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
        esplora_url: None,
        explorer_url: None,
    },
    dex_url: Some("http://127.0.0.1:8790"),
};

/// Every known profile, selectable or not.
pub const PROFILES: &[&NetworkProfile] =
    &[&ECX_BETA, &ECX_MAINNET, &ELEMENTSPLUS_REGTEST, &ECX_ALPHA];

/// Profile id baked into this build (`ELEMENTSPLUS_NETWORK_PROFILE` at compile
/// time; set by `scripts/build-wasm.mjs`).
pub const COMPILED_PROFILE_ID: Option<&str> = option_env!("ELEMENTSPLUS_NETWORK_PROFILE");

/// Look up any profile, including archived ones.
pub fn profile(id: &str) -> Option<&'static NetworkProfile> {
    PROFILES.iter().copied().find(|profile| profile.id == id)
}

/// Look up a profile a build or the CLI may select. Pending and archived
/// profiles are refused here with an explanatory error.
pub fn selectable_profile(id: &str) -> Result<&'static NetworkProfile, NetworkProfileError> {
    let profile = profile(id).ok_or_else(|| NetworkProfileError::Unknown(id.into()))?;
    profile.ensure_selectable()?;
    Ok(profile)
}

/// The profile compiled into this build.
pub fn compiled_profile() -> Result<&'static NetworkProfile, NetworkProfileError> {
    selectable_profile(COMPILED_PROFILE_ID.ok_or(NetworkProfileError::NotCompiled)?)
}

/// Fully resolved, parsed pins of a profile.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedPins {
    pub network: Network,
    pub genesis_hash: BlockHash,
    pub policy_asset: AssetId,
    pub address: AddressProfile,
}

impl NetworkProfile {
    /// Pins a public profile still lacks. A profile is buildable only when
    /// this is empty *and* its status is live.
    pub fn missing_pins(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.kind == ProfileKind::Public {
            if self.genesis_hash.is_none() {
                missing.push("genesis_hash");
            }
            if self.policy_asset.is_none() {
                missing.push("policy_asset");
            }
            if self.esplora_url.is_none() {
                missing.push("esplora_url");
            }
            if self.l1.genesis_hash.is_none() {
                missing.push("l1.genesis_hash");
            }
        }
        if self.address.is_none() {
            missing.push("address");
        }
        missing
    }

    pub fn ensure_selectable(&self) -> Result<(), NetworkProfileError> {
        match self.status {
            ProfileStatus::Live => Ok(()),
            ProfileStatus::Pending => Err(NetworkProfileError::Pending(self.id)),
            ProfileStatus::Archived => Err(NetworkProfileError::Archived(self.id)),
        }
    }

    /// Parse the compiled pins of a public profile. Pending profiles are
    /// refused; archived ones resolve (for historical verification only).
    pub fn resolve_pins(&self) -> Result<ResolvedPins, NetworkProfileError> {
        if self.status == ProfileStatus::Pending {
            return Err(NetworkProfileError::Pending(self.id));
        }
        if self.kind == ProfileKind::LocalRegtest {
            return Err(NetworkProfileError::LocalRegtest(self.id));
        }
        let missing = NetworkProfileError::Pending(self.id);
        let genesis_hash = BlockHash::from_str(self.genesis_hash.ok_or(missing.clone())?)
            .map_err(|_| NetworkProfileError::InvalidPin(self.id, "genesis_hash"))?;
        let policy_asset = AssetId::from_str(self.policy_asset.ok_or(missing.clone())?)
            .map_err(|_| NetworkProfileError::InvalidPin(self.id, "policy_asset"))?;
        let parent = bitcoin::BlockHash::from_str(self.l1.genesis_hash.ok_or(missing.clone())?)
            .map_err(|_| NetworkProfileError::InvalidPin(self.id, "l1.genesis_hash"))?;
        let address = self.address.ok_or(missing)?;
        let network = Network::CustomElements(
            ElementsParamsBuilder::new()
                .with_policy_asset(policy_asset)
                .with_genesis_hash(genesis_hash)
                .with_parent_genesis_hash(parent)
                .build()
                .map_err(|_| NetworkProfileError::InvalidPin(self.id, "network parameters"))?,
        );
        Ok(ResolvedPins {
            network,
            genesis_hash,
            policy_asset,
            address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_are_unique_and_known() {
        let ids: Vec<_> = PROFILES.iter().map(|p| p.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
        assert_eq!(
            ids,
            [
                "ecx-beta",
                "ecx-mainnet",
                "elementsplus-regtest",
                "ecx-alpha"
            ]
        );
    }

    #[test]
    fn pending_and_archived_profiles_are_refused() {
        assert_eq!(selectable_profile("ecx-beta").unwrap().id, "ecx-beta");
        assert_eq!(
            selectable_profile("ecx-mainnet").unwrap_err(),
            NetworkProfileError::Pending("ecx-mainnet")
        );
        assert_eq!(
            selectable_profile("ecx-alpha").unwrap_err(),
            NetworkProfileError::Archived("ecx-alpha")
        );
        assert!(matches!(
            selectable_profile("liquidv1"),
            Err(NetworkProfileError::Unknown(_))
        ));
        assert!(ECX_BETA.resolve_pins().is_ok());
        assert!(ECX_MAINNET.resolve_pins().is_err());
        assert_eq!(
            selectable_profile("elementsplus-regtest").unwrap().id,
            "elementsplus-regtest"
        );
        assert!(ELEMENTSPLUS_REGTEST.resolve_pins().is_err());
    }

    #[test]
    fn status_matches_missing_pins() {
        // Invariant: pending <=> something unpublished. Filling the last pin
        // without flipping the status (or vice versa) fails here.
        for profile in PROFILES {
            if profile.status == ProfileStatus::Pending {
                assert!(!profile.missing_pins().is_empty(), "{}", profile.id);
            } else {
                assert!(profile.missing_pins().is_empty(), "{}", profile.id);
            }
        }
        // Betanet slot 24: JK's child identity plus his public Esplora.
        assert!(ECX_BETA.missing_pins().is_empty());
        assert_eq!(
            ECX_BETA.esplora_url,
            Some("https://explorer.bitnames.info/api")
        );
        assert_eq!(
            ECX_BETA.genesis_hash,
            Some("a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f")
        );
        assert_eq!(
            ECX_BETA.policy_asset,
            Some("5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8")
        );
        assert_ne!(ECX_BETA.genesis_hash, ECX_ALPHA.genesis_hash);
        assert_eq!(ECX_BETA.sidechain_slot, 24);
        assert_eq!(
            ECX_MAINNET.missing_pins(),
            [
                "genesis_hash",
                "policy_asset",
                "esplora_url",
                "l1.genesis_hash",
                "address"
            ]
        );
    }

    #[test]
    fn beta_resolves_to_the_slot24_child_identity() {
        ECX_BETA.ensure_selectable().unwrap();
        let pins = ECX_BETA.resolve_pins().unwrap();
        assert_eq!(
            pins.genesis_hash.to_string(),
            "a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f"
        );
        assert_eq!(
            pins.policy_asset.to_string(),
            "5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8"
        );
    }

    #[test]
    fn archived_alpha_pins_still_resolve() {
        let pins = ECX_ALPHA.resolve_pins().unwrap();
        assert_eq!(pins.genesis_hash.to_string(), alpha::GENESIS_HASH);
        assert_eq!(pins.policy_asset.to_string(), alpha::POLICY_ASSET);
        assert_eq!(pins.network, alpha::lwk_network());
    }
}
