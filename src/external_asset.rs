use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const EXTERNAL_ASSET_ID_DOMAIN: &str = "unchained-external-asset-id-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExternalAsset {
    ZcashShieldedZec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAssetPolicy {
    pub asset: ExternalAsset,
    pub asset_id: [u8; 32],
    pub ticker: &'static str,
    pub name: &'static str,
    pub minimum_lock_epochs: u64,
    pub minimum_external_confirmations: u32,
}

impl ExternalAsset {
    pub fn policy(self) -> ExternalAssetPolicy {
        match self {
            Self::ZcashShieldedZec => ExternalAssetPolicy {
                asset: self,
                asset_id: external_asset_id(b"zcash-shielded-zec"),
                ticker: "ZEC",
                name: "Zcash shielded ZEC",
                minimum_lock_epochs: 32,
                minimum_external_confirmations: 24,
            },
        }
    }

    pub fn asset_id(self) -> [u8; 32] {
        self.policy().asset_id
    }
}

pub fn external_asset_id(label: &[u8]) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(EXTERNAL_ASSET_ID_DOMAIN, &[label])
}

pub fn validate_external_stake_shape(
    asset: ExternalAsset,
    current_epoch: u64,
    activation_epoch: u64,
    external_nullifier: &[u8; 32],
    stake_position_commitment: &[u8; 32],
) -> Result<()> {
    let policy = asset.policy();
    if external_nullifier == &[0u8; 32] {
        bail!("external stake nullifier cannot be zero");
    }
    if stake_position_commitment == &[0u8; 32] {
        bail!("external stake position commitment cannot be zero");
    }
    if activation_epoch < current_epoch {
        bail!("external stake activation epoch cannot be in the past");
    }
    let minimum_activation_epoch = current_epoch.saturating_add(policy.minimum_lock_epochs);
    if activation_epoch < minimum_activation_epoch {
        bail!(
            "external stake activation epoch must be at least {} epochs after the current epoch",
            policy.minimum_lock_epochs
        );
    }
    Ok(())
}
