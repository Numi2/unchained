use crate::{
    consensus::{ConsensusPosition, Validator, ValidatorId, ValidatorSet, MAX_ACTIVE_VALIDATORS},
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ValidatorAccountability {
    pub liveness_faults: u32,
    pub safety_faults: u32,
    pub jailed_until_epoch: Option<u64>,
}

impl ValidatorAccountability {
    pub fn validate(&self, status: ValidatorStatus) -> Result<()> {
        match status {
            ValidatorStatus::Jailed => {
                if self.jailed_until_epoch.is_none() {
                    bail!("jailed validator pools must declare a jail release epoch");
                }
            }
            ValidatorStatus::PendingActivation
            | ValidatorStatus::Active
            | ValidatorStatus::Retired => {
                if self.jailed_until_epoch.is_some() {
                    bail!("non-jailed validator pools must not retain a jail release epoch");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPool {
    pub validator: Validator,
    pub node_id: [u8; 32],
    pub commission_bps: u16,
    pub total_bonded_stake: u64,
    pub pending_commission_stake: u64,
    pub total_delegation_shares: u128,
    pub activation_epoch: u64,
    pub status: ValidatorStatus,
    pub accountability: ValidatorAccountability,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyFaultClass {
    Safety,
    Liveness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PenaltyPolicy {
    pub slash_bps: u16,
    pub jail_after_faults: u32,
    pub jail_epochs: u64,
    pub retire_after_faults: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PenaltyApplication {
    pub updated_pool: ValidatorPool,
    pub slashed_amount: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RewardSuppressionReason {
    MissedVote,
    Jailed,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardAccrual {
    pub updated_pool: ValidatorPool,
    pub gross_reward: u64,
    pub commission_reward: u64,
    pub share_backed_reward: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PenaltyCause {
    ProposalEquivocation {
        position: ConsensusPosition,
    },
    VoteEquivocation {
        position: ConsensusPosition,
    },
    DagBatchEquivocation {
        epoch: u64,
        round: u64,
    },
    MissedConsensusVote {
        position: ConsensusPosition,
        anchor_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPenaltyEvent {
    pub evidence_id: [u8; 32],
    pub validator_id: ValidatorId,
    pub cause: PenaltyCause,
    pub slash_bps: u16,
    pub slashed_amount: u64,
    pub bonded_stake_before: u64,
    pub bonded_stake_after: u64,
    pub applied_in_epoch: u64,
    pub resulting_status: ValidatorStatus,
    pub resulting_activation_epoch: u64,
    pub resulting_accountability: ValidatorAccountability,
}

impl ValidatorPenaltyEvent {
    pub fn validate(&self) -> Result<()> {
        if self.slash_bps > 10_000 {
            bail!("validator penalty exceeds 100%");
        }
        if self.bonded_stake_before == 0 || self.bonded_stake_after == 0 {
            bail!("validator penalty cannot reference an empty bonded stake");
        }
        if self.bonded_stake_after >= self.bonded_stake_before {
            bail!("validator penalty must reduce bonded stake");
        }
        if self
            .bonded_stake_before
            .checked_sub(self.bonded_stake_after)
            .ok_or_else(|| anyhow::anyhow!("validator penalty underflow"))?
            != self.slashed_amount
        {
            bail!("validator penalty slashed amount mismatch");
        }
        self.resulting_accountability
            .validate(self.resulting_status)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRewardEvent {
    pub anchor_hash: [u8; 32],
    pub anchor_num: u64,
    pub validator_id: ValidatorId,
    pub validator_voting_power: u64,
    pub total_rewarded_voting_power: u64,
    pub protocol_reward: u64,
    pub fee_reward: u64,
    pub gross_reward: u64,
    pub commission_reward: u64,
    pub share_backed_reward: u64,
    pub bonded_stake_before: u64,
    pub bonded_stake_after: u64,
    pub pending_commission_before: u64,
    pub pending_commission_after: u64,
    pub resulting_status: ValidatorStatus,
    pub suppression_reason: Option<RewardSuppressionReason>,
}

impl ValidatorRewardEvent {
    pub fn validate(&self) -> Result<()> {
        if self.validator_voting_power == 0 {
            bail!("validator reward event requires non-zero validator voting power");
        }
        if self.suppression_reason.is_some() {
            if self.protocol_reward != 0
                || self.fee_reward != 0
                || self.gross_reward != 0
                || self.commission_reward != 0
                || self.share_backed_reward != 0
                || self.bonded_stake_before != self.bonded_stake_after
                || self.pending_commission_before != self.pending_commission_after
            {
                bail!("suppressed validator reward events must not mutate pool rewards");
            }
        } else {
            if self.total_rewarded_voting_power == 0 {
                bail!("rewarded validator event requires non-zero rewarded voting power");
            }
            if self.gross_reward == 0 {
                bail!("rewarded validator event must carry a non-zero reward");
            }
            if self
                .protocol_reward
                .checked_add(self.fee_reward)
                .ok_or_else(|| anyhow::anyhow!("validator reward source overflow"))?
                != self.gross_reward
            {
                bail!("validator reward sources do not sum to the gross reward");
            }
            if self
                .commission_reward
                .checked_add(self.share_backed_reward)
                .ok_or_else(|| anyhow::anyhow!("validator reward overflow"))?
                != self.gross_reward
            {
                bail!("validator reward split does not sum to the gross reward");
            }
            if self.bonded_stake_after <= self.bonded_stake_before {
                bail!("rewarded validator event must increase bonded stake");
            }
            if self.pending_commission_after < self.pending_commission_before {
                bail!("validator commission reserve cannot decrease during reward accrual");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorReactivation {
    pub validator_id: ValidatorId,
}

impl ValidatorReactivation {
    pub fn validate(&self) -> Result<()> {
        if self.validator_id.0 == [0u8; 32] {
            bail!("validator reactivation references the zero validator id");
        }
        Ok(())
    }
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
            pending_commission_stake: 0,
            total_delegation_shares: total_bonded_stake as u128,
            activation_epoch,
            status,
            accountability: ValidatorAccountability::default(),
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
        if self.pending_commission_stake >= self.total_bonded_stake {
            bail!("validator pending commission must remain below total bonded stake");
        }
        self.accountability.validate(self.status)?;
        self.metadata.validate()?;
        Ok(())
    }

    pub fn claimable_bonded_stake(&self) -> Result<u64> {
        self.total_bonded_stake
            .checked_sub(self.pending_commission_stake)
            .ok_or_else(|| anyhow::anyhow!("validator commission reserve exceeds bonded stake"))
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
            pending_commission_stake: self.pending_commission_stake,
            total_delegation_shares: self.total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            accountability: self.accountability.clone(),
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

        let claimable_bonded_stake = self.claimable_bonded_stake()?;
        let minted_shares_u128 = if claimable_bonded_stake == 0 || self.total_delegation_shares == 0
        {
            delegated_amount as u128
        } else {
            (delegated_amount as u128)
                .checked_mul(self.total_delegation_shares)
                .ok_or_else(|| anyhow::anyhow!("delegation share supply overflow"))?
                / (claimable_bonded_stake as u128)
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
            pending_commission_stake: self.pending_commission_stake,
            total_delegation_shares: updated_total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            accountability: self.accountability.clone(),
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

        let claimable_bonded_stake = self.claimable_bonded_stake()?;
        let claim_amount_u128 = (burned_shares as u128)
            .checked_mul(claimable_bonded_stake as u128)
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
            pending_commission_stake: self.pending_commission_stake,
            total_delegation_shares: updated_total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            accountability: self.accountability.clone(),
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

    pub fn apply_penalty(
        &self,
        fault_class: PenaltyFaultClass,
        applied_in_epoch: u64,
        policy: PenaltyPolicy,
    ) -> Result<PenaltyApplication> {
        self.validate()?;
        if policy.slash_bps > 10_000 {
            bail!("validator penalty exceeds 100%");
        }
        if policy.jail_after_faults == 0 {
            bail!("validator penalty jail threshold must be non-zero");
        }
        if policy.retire_after_faults < policy.jail_after_faults {
            bail!("validator retirement threshold must not be below the jail threshold");
        }
        let max_slash = self
            .total_bonded_stake
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("validator pool cannot be fully slashed"))?;
        if max_slash == 0 {
            bail!("validator pool cannot be fully slashed");
        }
        let proportional =
            ((self.total_bonded_stake as u128) * (policy.slash_bps as u128)) / 10_000u128;
        let slashed_amount = if policy.slash_bps == 0 {
            0
        } else {
            let proportional = u64::try_from(proportional)
                .map_err(|_| anyhow::anyhow!("validator penalty exceeds u64"))?;
            proportional.max(1).min(max_slash)
        };
        let mut accountability = self.accountability.clone();
        let next_fault_count = match fault_class {
            PenaltyFaultClass::Safety => {
                accountability.safety_faults = accountability
                    .safety_faults
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("validator safety fault count overflow"))?;
                accountability.safety_faults
            }
            PenaltyFaultClass::Liveness => {
                accountability.liveness_faults = accountability
                    .liveness_faults
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("validator liveness fault count overflow"))?;
                accountability.liveness_faults
            }
        };
        let mut resulting_status = self.status;
        if self.status == ValidatorStatus::Retired || next_fault_count >= policy.retire_after_faults
        {
            resulting_status = ValidatorStatus::Retired;
            accountability.jailed_until_epoch = None;
        } else if next_fault_count % policy.jail_after_faults == 0 {
            resulting_status = ValidatorStatus::Jailed;
            let release_epoch = applied_in_epoch
                .checked_add(policy.jail_epochs.max(1))
                .ok_or_else(|| anyhow::anyhow!("validator jail release epoch overflow"))?;
            accountability.jailed_until_epoch = Some(
                accountability
                    .jailed_until_epoch
                    .map_or(release_epoch, |current| current.max(release_epoch)),
            );
        } else if self.status == ValidatorStatus::Jailed {
            resulting_status = ValidatorStatus::Jailed;
        } else {
            accountability.jailed_until_epoch = None;
        }
        let updated_total_bonded_stake = self
            .total_bonded_stake
            .checked_sub(slashed_amount)
            .ok_or_else(|| anyhow::anyhow!("validator penalty exceeds bonded stake"))?;
        let updated_pending_commission_stake = if self.pending_commission_stake == 0 {
            0
        } else {
            u64::try_from(
                ((self.pending_commission_stake as u128) * (updated_total_bonded_stake as u128))
                    / (self.total_bonded_stake as u128),
            )
            .map_err(|_| anyhow::anyhow!("validator commission reserve exceeds u64"))?
        };
        let updated_pool = Self {
            validator: Validator::new(updated_total_bonded_stake, self.validator.keys.clone())?,
            node_id: self.node_id,
            commission_bps: self.commission_bps,
            total_bonded_stake: updated_total_bonded_stake,
            pending_commission_stake: updated_pending_commission_stake,
            total_delegation_shares: self.total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: resulting_status,
            accountability,
            metadata: self.metadata.clone(),
        };
        updated_pool.validate()?;
        Ok(PenaltyApplication {
            updated_pool,
            slashed_amount,
        })
    }

    pub fn accrue_reward(&self, gross_reward: u64) -> Result<RewardAccrual> {
        self.validate()?;
        if gross_reward == 0 {
            bail!("validator rewards must be non-zero");
        }
        let commission_reward =
            u64::try_from(((gross_reward as u128) * (self.commission_bps as u128)) / 10_000u128)
                .map_err(|_| anyhow::anyhow!("validator commission reward exceeds u64"))?;
        let share_backed_reward = gross_reward
            .checked_sub(commission_reward)
            .ok_or_else(|| anyhow::anyhow!("validator reward split underflow"))?;
        let updated_total_bonded_stake = self
            .total_bonded_stake
            .checked_add(gross_reward)
            .ok_or_else(|| anyhow::anyhow!("validator reward bonded stake overflow"))?;
        let updated_pending_commission_stake = self
            .pending_commission_stake
            .checked_add(commission_reward)
            .ok_or_else(|| anyhow::anyhow!("validator commission reserve overflow"))?;
        let updated_pool = Self {
            validator: Validator::new(updated_total_bonded_stake, self.validator.keys.clone())?,
            node_id: self.node_id,
            commission_bps: self.commission_bps,
            total_bonded_stake: updated_total_bonded_stake,
            pending_commission_stake: updated_pending_commission_stake,
            total_delegation_shares: self.total_delegation_shares,
            activation_epoch: self.activation_epoch,
            status: self.status,
            accountability: self.accountability.clone(),
            metadata: self.metadata.clone(),
        };
        updated_pool.validate()?;
        Ok(RewardAccrual {
            updated_pool,
            gross_reward,
            commission_reward,
            share_backed_reward,
        })
    }

    pub fn request_reactivation(&self, current_epoch: u64) -> Result<Self> {
        self.validate()?;
        if self.status != ValidatorStatus::Jailed {
            bail!("validator reactivation requires a jailed validator pool");
        }
        let jailed_until_epoch = self
            .accountability
            .jailed_until_epoch
            .ok_or_else(|| anyhow::anyhow!("jailed validator is missing its release epoch"))?;
        if current_epoch < jailed_until_epoch {
            bail!(
                "validator remains jailed until epoch {}; current epoch is {}",
                jailed_until_epoch,
                current_epoch
            );
        }
        let activation_epoch = current_epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("validator reactivation epoch overflow"))?;
        let mut accountability = self.accountability.clone();
        accountability.jailed_until_epoch = None;
        let updated = Self {
            validator: Validator::new(self.total_bonded_stake, self.validator.keys.clone())?,
            node_id: self.node_id,
            commission_bps: self.commission_bps,
            total_bonded_stake: self.total_bonded_stake,
            pending_commission_stake: self.pending_commission_stake,
            total_delegation_shares: self.total_delegation_shares,
            activation_epoch,
            status: ValidatorStatus::PendingActivation,
            accountability,
            metadata: self.metadata.clone(),
        };
        updated.validate()?;
        Ok(updated)
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
        if self.pool.accountability != ValidatorAccountability::default() {
            bail!("validator registrations must begin with a clean accountability state");
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
    select_active_validator_set(epoch, &pools)
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
        assert!(db.load_validator_committee(7).unwrap().is_none());
        db.store_validator_committee(&epoch7).unwrap();
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

    #[test]
    fn reward_accrual_raises_share_exchange_rate_and_reserves_commission() {
        let mut pool = pool(50_000, 0, ValidatorStatus::Active);
        pool.commission_bps = 2_500;
        pool.validate().unwrap();

        let accrued = pool.accrue_reward(20).unwrap();
        assert_eq!(accrued.gross_reward, 20);
        assert_eq!(accrued.commission_reward, 5);
        assert_eq!(accrued.share_backed_reward, 15);
        assert_eq!(accrued.updated_pool.total_bonded_stake, 50_020);
        assert_eq!(accrued.updated_pool.pending_commission_stake, 5);
        assert_eq!(
            accrued.updated_pool.claimable_bonded_stake().unwrap(),
            50_015
        );
        assert_eq!(
            accrued.updated_pool.total_delegation_shares,
            pool.total_delegation_shares
        );

        let undelegation = accrued
            .updated_pool
            .preview_undelegation(10_000, 0, 1)
            .unwrap();
        assert_eq!(undelegation.claim_amount, 10_003);
    }
}
