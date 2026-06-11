use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::external_asset::{ExternalAsset, ExternalAssetPolicy};

const ZCASH_STAKE_ANCHOR_DOMAIN: &str = "unchained-zcash-stake-anchor-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ZcashShieldedProtocol {
    OrchardV1,
    TachyonV1,
}

impl ZcashShieldedProtocol {
    pub fn code(self) -> u8 {
        match self {
            Self::OrchardV1 => 1,
            Self::TachyonV1 => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZcashStakeAnchor {
    pub protocol: ZcashShieldedProtocol,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub note_commitment_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub confirmation_depth: u32,
}

impl ZcashStakeAnchor {
    pub fn anchor_hash(&self) -> [u8; 32] {
        proof_core::proof_hash_domain_parts(
            ZCASH_STAKE_ANCHOR_DOMAIN,
            &[
                &[self.protocol.code()],
                &self.height.to_le_bytes(),
                &self.block_hash,
                &self.note_commitment_root,
                &self.nullifier_root,
            ],
        )
    }

    pub fn validate_for_asset(&self, asset: ExternalAsset) -> Result<()> {
        let policy = asset.policy();
        validate_zcash_asset_policy(policy)?;
        if self.height == 0 {
            bail!("Zcash stake anchor height cannot be zero");
        }
        if self.block_hash == [0u8; 32] {
            bail!("Zcash stake anchor block hash cannot be zero");
        }
        if self.note_commitment_root == [0u8; 32] {
            bail!("Zcash stake anchor note commitment root cannot be zero");
        }
        if self.nullifier_root == [0u8; 32] {
            bail!("Zcash stake anchor nullifier root cannot be zero");
        }
        if self.confirmation_depth < policy.minimum_external_confirmations {
            bail!(
                "Zcash stake anchor has {} confirmations but requires at least {}",
                self.confirmation_depth,
                policy.minimum_external_confirmations
            );
        }
        Ok(())
    }
}

fn validate_zcash_asset_policy(policy: ExternalAssetPolicy) -> Result<()> {
    match policy.asset {
        ExternalAsset::ZcashShieldedZec => Ok(()),
    }
}

pub fn external_anchor_storage_key(asset: ExternalAsset, anchor_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&asset.asset_id());
    key.extend_from_slice(anchor_hash);
    key
}
