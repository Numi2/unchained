use crate::{
    consensus::{Validator, ValidatorId, ValidatorSet, MAX_ACTIVE_VALIDATORS},
    node_identity::{validator_from_record, NodeRecordV2},
    storage::Store,
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

const MAX_DISPLAY_NAME_BYTES: usize = 96;
const MAX_WEBSITE_BYTES: usize = 160;
const MAX_DESCRIPTION_BYTES: usize = 280;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ValidatorMetadata {
    pub display_name: String,
    pub website: Option<String>,
    pub description: Option<String>,
}

impl ValidatorMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.display_name.len() > MAX_DISPLAY_NAME_BYTES {
            bail!(
                "validator display name exceeds {} bytes",
                MAX_DISPLAY_NAME_BYTES
            );
        }
        if let Some(website) = &self.website {
            if website.len() > MAX_WEBSITE_BYTES {
                bail!("validator website exceeds {} bytes", MAX_WEBSITE_BYTES);
            }
        }
        if let Some(description) = &self.description {
            if description.len() > MAX_DESCRIPTION_BYTES {
                bail!(
                    "validator description exceeds {} bytes",
                    MAX_DESCRIPTION_BYTES
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    PendingActivation,
    Active,
    Jailed,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPool {
    pub validator: Validator,
    pub node_id: [u8; 32],
    pub commission_bps: u16,
    pub total_bonded_stake: u64,
    pub total_delegation_shares: u128,
    pub activation_epoch: u64,
    pub status: ValidatorStatus,
    pub metadata: ValidatorMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationPreview {
    pub delegated_amount: u64,
    pub minted_shares: u64,
    pub updated_pool: ValidatorPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndelegationPreview {
    pub burned_shares: u64,
    pub claim_amount: u64,
    pub release_epoch: u64,
    pub updated_pool: ValidatorPool,
}

impl ValidatorPool {
    pub fn new(
        validator: Validator,
        node_id: [u8; 32],
        commission_bps: u16,
        total_bonded_stake: u64,
        activation_epoch: u64,
        status: ValidatorStatus,
        metadata: ValidatorMetadata,
    ) -> Result<Self> {
        if commission_bps > 10_000 {
            bail!("validator commission exceeds 100%");
        }
        if total_bonded_stake == 0 {
            bail!("validator pool bonded stake must be non-zero");
        }
        if validator.voting_power != total_bonded_stake {
            bail!("validator voting power must match total bonded stake");
        }
        metadata.validate()?;
        Ok(Self {
            validator,
            node_id,
            commission_bps,
            total_bonded_stake,
            total_delegation_shares: total_bonded_stake as u128,
            activation_epoch,
            status,
            metadata,
        })
    }

    pub fn from_node_record(
        record: &NodeRecordV2,
        commission_bps: u16,
        total_bonded_stake: u64,
        activation_epoch: u64,
        status: ValidatorStatus,
        metadata: ValidatorMetadata,
    ) -> Result<Self> {
        let validator = validator_from_record(record, total_bonded_stake)?;
        Self::new(
            validator,
            record.node_id,
            commission_bps,
            total_bonded_stake,
            activation_epoch,
            status,
            metadata,
        )
    }

    pub fn validator_id(&self) -> ValidatorId {
        self.validator.id
    }

    pub fn validate(&self) -> Result<()> {
        let validated = Validator::new(self.total_bonded_stake, self.validator.keys.clone())?;
        if validated.id != self.validator.id {
            bail!("validator id does not match validator hot key");
        }
        if self.commission_bps > 10_000 {
            bail!("validator commission exceeds 100%");
        }
        if self.total_delegation_shares == 0 {
            bail!("validator pool delegation share supply must be non-zero");
        }
        self.metadata.validate()?;
        Ok(())
    }

    pub fn is_eligible_for_epoch(&self, epoch: u64) -> bool {
        matches!(
            self.status,
            ValidatorStatus::PendingActivation | ValidatorStatus::Active
        ) && epoch >= self.activation_epoch
    }

    pub fn committee_member(&self) -> Result<Validator> {
        Validator::new(self.total_bonded_stake, self.validator.keys.clone())
    }

    pub fn with_profile(&self, commission_bps: u16, metadata: ValidatorMetadata) -> Result<Self> {
        if commission_bps > 10_000 {
            bail!("validator commission exceeds 100%");
        }
        metadata.validate()?;
        let updated = Self {
            validator: Validator::new(self.total_bonded_stake, self.validator.keys.clone())?,
            node_id: self.node_id,
            commission_bps,
            total_bonded_stake: self.total_bonded_stake,
            total_delegation_shares: self.total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            metadata,
        };
        updated.validate()?;
        Ok(updated)
    }

    pub fn preview_delegation(&self, delegated_amount: u64) -> Result<DelegationPreview> {
        self.validate()?;
        if delegated_amount == 0 {
            bail!("delegated amount must be non-zero");
        }
        if matches!(
            self.status,
            ValidatorStatus::Jailed | ValidatorStatus::Retired
        ) {
            bail!("delegation into jailed or retired validator pools is not allowed");
        }

        let minted_shares_u128 =
            if self.total_bonded_stake == 0 || self.total_delegation_shares == 0 {
                delegated_amount as u128
            } else {
                (delegated_amount as u128)
                    .checked_mul(self.total_delegation_shares)
                    .ok_or_else(|| anyhow::anyhow!("delegation share supply overflow"))?
                    / (self.total_bonded_stake as u128)
            };
        if minted_shares_u128 == 0 {
            bail!("delegation amount is too small to mint any pool shares");
        }
        let minted_shares = u64::try_from(minted_shares_u128)
            .map_err(|_| anyhow::anyhow!("delegation share value exceeds u64 note capacity"))?;

        let updated_total_bonded_stake = self
            .total_bonded_stake
            .checked_add(delegated_amount)
            .ok_or_else(|| anyhow::anyhow!("validator bonded stake overflow"))?;
        let updated_total_delegation_shares = self
            .total_delegation_shares
            .checked_add(minted_shares as u128)
            .ok_or_else(|| anyhow::anyhow!("validator delegation share supply overflow"))?;

        let updated_pool = Self {
            validator: Validator::new(updated_total_bonded_stake, self.validator.keys.clone())?,
            node_id: self.node_id,
            commission_bps: self.commission_bps,
            total_bonded_stake: updated_total_bonded_stake,
            total_delegation_shares: updated_total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            metadata: self.metadata.clone(),
        };
        updated_pool.validate()?;
        Ok(DelegationPreview {
            delegated_amount,
            minted_shares,
            updated_pool,
        })
    }

    pub fn apply_delegation(&self, delegated_amount: u64, minted_shares: u64) -> Result<Self> {
        let preview = self.preview_delegation(delegated_amount)?;
        if preview.minted_shares != minted_shares {
            bail!("delegation share value does not match the canonical pool mint result");
        }
        Ok(preview.updated_pool)
    }

    pub fn preview_undelegation(
        &self,
        burned_shares: u64,
        requested_epoch: u64,
        unbonding_epochs: u64,
    ) -> Result<UndelegationPreview> {
        self.validate()?;
        if burned_shares == 0 {
            bail!("undelegated share amount must be non-zero");
        }
        if (burned_shares as u128) >= self.total_delegation_shares {
            bail!("undelegation cannot consume the validator's full share supply");
        }

        let claim_amount_u128 = (burned_shares as u128)
            .checked_mul(self.total_bonded_stake as u128)
            .ok_or_else(|| anyhow::anyhow!("undelegation claim amount overflow"))?
            / self.total_delegation_shares;
        if claim_amount_u128 == 0 {
            bail!("undelegated share amount is too small to realize any bonded stake");
        }
        let claim_amount = u64::try_from(claim_amount_u128)
            .map_err(|_| anyhow::anyhow!("undelegation claim amount exceeds u64"))?;

        let updated_total_bonded_stake = self
            .total_bonded_stake
            .checked_sub(claim_amount)
            .ok_or_else(|| anyhow::anyhow!("undelegation exceeds bonded stake"))?;
        if updated_total_bonded_stake == 0 {
            bail!("undelegation cannot drain the validator's full bonded stake");
        }
        let updated_total_delegation_shares = self
            .total_delegation_shares
            .checked_sub(burned_shares as u128)
            .ok_or_else(|| anyhow::anyhow!("undelegation exceeds share supply"))?;
        if updated_total_delegation_shares == 0 {
            bail!("undelegation cannot drain the validator's full share supply");
        }

        let release_epoch = requested_epoch
            .checked_add(unbonding_epochs.max(1))
            .ok_or_else(|| anyhow::anyhow!("unbonding release epoch overflow"))?;
        let updated_pool = Self {
            validator: Validator::new(updated_total_bonded_stake, self.validator.keys.clone())?,
            node_id: self.node_id,
            commission_bps: self.commission_bps,
            total_bonded_stake: updated_total_bonded_stake,
            total_delegation_shares: updated_total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            metadata: self.metadata.clone(),
        };
        updated_pool.validate()?;
        Ok(UndelegationPreview {
            burned_shares,
            claim_amount,
            release_epoch,
            updated_pool,
        })
    }

    pub fn apply_undelegation(
        &self,
        burned_shares: u64,
        claim_amount: u64,
        requested_epoch: u64,
        release_epoch: u64,
        unbonding_epochs: u64,
    ) -> Result<Self> {
        let preview =
            self.preview_undelegation(burned_shares, requested_epoch, unbonding_epochs)?;
        if preview.claim_amount != claim_amount {
            bail!("unbonding claim amount does not match the canonical pool redeem result");
        }
        if preview.release_epoch != release_epoch {
            bail!("unbonding release epoch does not match the canonical pool unbonding schedule");
        }
        Ok(preview.updated_pool)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRegistration {
    pub pool: ValidatorPool,
}

impl ValidatorRegistration {
    pub fn validate(&self) -> Result<()> {
        self.pool.validate()?;
        if !matches!(self.pool.status, ValidatorStatus::PendingActivation) {
            bail!("validator registrations must begin in pending activation status");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorProfileUpdate {
    pub validator_id: ValidatorId,
    pub commission_bps: u16,
    pub metadata: ValidatorMetadata,
}

impl ValidatorProfileUpdate {
    pub fn validate(&self) -> Result<()> {
        if self.commission_bps > 10_000 {
            bail!("validator commission exceeds 100%");
        }
        self.metadata.validate()
    }

    pub fn apply_to(&self, existing: &ValidatorPool) -> Result<ValidatorPool> {
        if existing.validator.id != self.validator_id {
            bail!("validator profile update targets the wrong validator pool");
        }
        existing.with_profile(self.commission_bps, self.metadata.clone())
    }
}

pub fn select_active_validator_set(epoch: u64, pools: &[ValidatorPool]) -> Result<ValidatorSet> {
    let mut eligible = pools
        .iter()
        .filter(|pool| pool.is_eligible_for_epoch(epoch))
        .cloned()
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        bail!("no eligible validator pools for epoch {}", epoch);
    }
    eligible.sort_by(|left, right| {
        right
            .total_bonded_stake
            .cmp(&left.total_bonded_stake)
            .then_with(|| left.validator.id.cmp(&right.validator.id))
    });
    if eligible.len() > MAX_ACTIVE_VALIDATORS {
        eligible.truncate(MAX_ACTIVE_VALIDATORS);
    }
    let validators = eligible
        .into_iter()
        .map(|pool| pool.committee_member())
        .collect::<Result<Vec<_>>>()?;
    ValidatorSet::new(epoch, validators)
}

pub fn register_genesis_local_validator_pool(
    db: &Store,
    record: &NodeRecordV2,
) -> Result<ValidatorPool> {
    let validator_id = ValidatorId::from_hot_key(&record.auth_spki);
    if let Some(existing) = db.load_validator_pool(&validator_id)? {
        return Ok(existing);
    }
    let pool = ValidatorPool::from_node_record(
        record,
        0,
        1,
        0,
        ValidatorStatus::Active,
        ValidatorMetadata::default(),
    )?;
    db.store_validator_pool(&pool)?;
    Ok(pool)
}

pub fn load_or_compute_active_validator_set(db: &Store, epoch: u64) -> Result<ValidatorSet> {
    if let Some(existing) = db.load_validator_committee(epoch)? {
        return Ok(existing);
    }
    let pools = db.load_validator_pools()?;
    if pools.is_empty() {
        bail!(
            "missing validator pool state for epoch {}; committee activation is undefined",
            epoch
        );
    }
    let selected = select_active_validator_set(epoch, &pools)?;
    db.store_validator_committee(&selected)?;
    Ok(selected)
}

pub fn expected_validator_set_for_epoch(db: &Store, epoch: u64) -> Result<Option<ValidatorSet>> {
    if let Some(existing) = db.load_validator_committee(epoch)? {
        return Ok(Some(existing));
    }
    let pools = db.load_validator_pools()?;
    if pools.is_empty() {
        return Ok(None);
    }
    Ok(Some(select_active_validator_set(epoch, &pools)?))
}

pub fn ensure_validator_set_matches_epoch_state(
    db: &Store,
    validator_set: &ValidatorSet,
) -> Result<()> {
    let expected = expected_validator_set_for_epoch(db, validator_set.epoch)?;
    let Some(expected) = expected else {
        bail!(
            "missing validator pool state for epoch {}; cannot validate committee activation",
            validator_set.epoch
        );
    };
    if expected != *validator_set {
        bail!(
            "validator set for epoch {} does not match the canonical active committee snapshot",
            validator_set.epoch
        );
    }
    Ok(())
}

pub fn local_validator_pool_from_record(
    record: &NodeRecordV2,
    commission_bps: u16,
    total_bonded_stake: u64,
    activation_epoch: u64,
    status: ValidatorStatus,
    metadata: ValidatorMetadata,
) -> Result<ValidatorPool> {
    ValidatorPool::from_node_record(
        record,
        commission_bps,
        total_bonded_stake,
        activation_epoch,
        status,
        metadata,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki};
    use tempfile::TempDir;

    fn pool(voting_power: u64, activation_epoch: u64, status: ValidatorStatus) -> ValidatorPool {
        let hot_key = ml_dsa_65_generate().unwrap();
        let cold_key = ml_dsa_65_generate().unwrap();
        ValidatorPool::new(
            Validator::new(
                voting_power,
                crate::consensus::ValidatorKeys {
                    hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key).unwrap(),
                    cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                },
            )
            .unwrap(),
            ValidatorId::from_hot_key(&ml_dsa_65_public_key_spki(&cold_key).unwrap()).0,
            250,
            voting_power,
            activation_epoch,
            status,
            ValidatorMetadata {
                display_name: "validator".to_string(),
                website: None,
                description: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn committee_selection_prefers_highest_bonded_stake() {
        let low = pool(3, 0, ValidatorStatus::Active);
        let mid = pool(7, 0, ValidatorStatus::Active);
        let high = pool(11, 0, ValidatorStatus::Active);

        let set =
            select_active_validator_set(0, &[low.clone(), high.clone(), mid.clone()]).unwrap();
        assert_eq!(set.total_voting_power, 21);
        assert!(set.validator(&high.validator_id()).is_some());
        assert!(set.validator(&mid.validator_id()).is_some());
        assert!(set.validator(&low.validator_id()).is_some());
    }

    #[test]
    fn committee_selection_filters_future_and_jailed_pools() {
        let active = pool(9, 0, ValidatorStatus::Active);
        let future = pool(10, 5, ValidatorStatus::PendingActivation);
        let jailed = pool(20, 0, ValidatorStatus::Jailed);

        let set =
            select_active_validator_set(0, &[future.clone(), jailed, active.clone()]).unwrap();
        assert_eq!(set.validators.len(), 1);
        assert_eq!(set.validators[0].id, active.validator_id());
    }

    #[test]
    fn committee_snapshot_round_trip_uses_storage() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let first = pool(5, 0, ValidatorStatus::Active);
        let second = pool(8, 0, ValidatorStatus::Active);
        db.store_validator_pool(&first).unwrap();
        db.store_validator_pool(&second).unwrap();

        let epoch7 = load_or_compute_active_validator_set(&db, 7).unwrap();
        let stored = db.load_validator_committee(7).unwrap().unwrap();
        assert_eq!(epoch7, stored);
        ensure_validator_set_matches_epoch_state(&db, &stored).unwrap();
    }

    #[test]
    fn validator_pool_rejects_mismatched_power_and_bonded_stake() {
        let hot_key = ml_dsa_65_generate().unwrap();
        let cold_key = ml_dsa_65_generate().unwrap();
        let validator = Validator::new(
            5,
            crate::consensus::ValidatorKeys {
                hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key).unwrap(),
                cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
            },
        )
        .unwrap();
        let err = ValidatorPool::new(
            validator,
            [1u8; 32],
            0,
            6,
            0,
            ValidatorStatus::Active,
            ValidatorMetadata::default(),
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("validator voting power must match total bonded stake"));
    }
}
