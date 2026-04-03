use crate::protocol::CURRENT as PROTOCOL;
use anyhow::{anyhow, bail, Result as AnyResult};
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::ML_DSA_65;
use serde::{Deserialize, Serialize};

pub const MAX_ACTIVE_VALIDATORS: usize = PROTOCOL.max_active_validators as usize;
pub const DEFAULT_SLOTS_PER_EPOCH: u32 = PROTOCOL.slots_per_epoch;
pub const DEFAULT_SLOT_DURATION_MS: u64 = PROTOCOL.slot_duration_ms;
pub const FAST_PATH_TIMEOUT_MS: u64 = PROTOCOL.fast_path_timeout_ms;
pub const DAG_BFT_TIMEOUT_MS: u64 = PROTOCOL.dag_bft_timeout_ms;
pub const MAX_COINS_PER_CHECKPOINT: u32 = PROTOCOL.max_coins_per_epoch;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatorId(pub [u8; 32]);

impl ValidatorId {
    pub fn from_hot_key(hot_key: &[u8]) -> Self {
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.validator-id.hot-key.v1");
        hasher.update(hot_key);
        Self(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorKeys {
    pub hot_ml_dsa_65_spki: Vec<u8>,
    pub cold_governance_key: Vec<u8>,
}

impl ValidatorKeys {
    fn validate(&self) -> AnyResult<()> {
        if self.hot_ml_dsa_65_spki.is_empty() {
            bail!("validator hot ML-DSA SPKI cannot be empty");
        }
        if self.cold_governance_key.is_empty() {
            bail!("validator cold governance key cannot be empty");
        }
        let hot_digest = blake3::hash(&self.hot_ml_dsa_65_spki);
        let cold_digest = blake3::hash(&self.cold_governance_key);
        if hot_digest.as_bytes() == cold_digest.as_bytes() {
            bail!("validator hot and cold signing roles must remain separated");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    pub id: ValidatorId,
    pub voting_power: u64,
    pub keys: ValidatorKeys,
}

impl Validator {
    pub fn new(voting_power: u64, keys: ValidatorKeys) -> AnyResult<Self> {
        if voting_power == 0 {
            bail!("validator voting power must be non-zero");
        }
        keys.validate()?;
        Ok(Self {
            id: ValidatorId::from_hot_key(&keys.hot_ml_dsa_65_spki),
            voting_power,
            keys,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSet {
    pub epoch: u64,
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
    pub quorum_threshold: u64,
}

impl ValidatorSet {
    pub fn new(epoch: u64, mut validators: Vec<Validator>) -> AnyResult<Self> {
        if validators.is_empty() {
            bail!("validator set cannot be empty");
        }
        if validators.len() > MAX_ACTIVE_VALIDATORS {
            bail!(
                "validator set exceeds active committee limit: {} > {}",
                validators.len(),
                MAX_ACTIVE_VALIDATORS
            );
        }

        validators.sort_by_key(|validator| validator.id);
        let mut total_voting_power = 0u64;
        let mut last_id = None;
        let mut hot_key_digests = std::collections::BTreeSet::new();
        for validator in &validators {
            validator.keys.validate()?;
            if last_id == Some(validator.id) {
                bail!("validator set contains duplicate validator ids");
            }
            last_id = Some(validator.id);

            total_voting_power = total_voting_power
                .checked_add(validator.voting_power)
                .ok_or_else(|| anyhow!("validator set voting power overflow"))?;

            let hot_key_digest = blake3::hash(&validator.keys.hot_ml_dsa_65_spki);
            if !hot_key_digests.insert(*hot_key_digest.as_bytes()) {
                bail!("validator set contains duplicate hot validator keys");
            }
        }

        let quorum_threshold = Self::quorum_threshold_for(total_voting_power)?;
        Ok(Self {
            epoch,
            validators,
            total_voting_power,
            quorum_threshold,
        })
    }

    pub fn quorum_threshold_for(total_voting_power: u64) -> AnyResult<u64> {
        if total_voting_power == 0 {
            bail!("validator set voting power cannot be zero");
        }
        Ok(total_voting_power
            .checked_mul(2)
            .ok_or_else(|| anyhow!("validator set voting power overflow"))?
            / 3
            + 1)
    }

    pub fn validator(&self, id: &ValidatorId) -> Option<&Validator> {
        self.validators
            .binary_search_by_key(id, |validator| validator.id)
            .ok()
            .map(|index| &self.validators[index])
    }

    pub fn committee_hash(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.validator-set.hash.v1");
        for validator in &self.validators {
            hasher.update(&validator.id.0);
            hasher.update(&validator.voting_power.to_le_bytes());
            hasher.update(&(validator.keys.hot_ml_dsa_65_spki.len() as u64).to_le_bytes());
            hasher.update(&validator.keys.hot_ml_dsa_65_spki);
            hasher.update(&(validator.keys.cold_governance_key.len() as u64).to_le_bytes());
            hasher.update(&validator.keys.cold_governance_key);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn leader_for(&self, position: ConsensusPosition) -> ValidatorId {
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.slot-leader-selection.v1");
        hasher.update(&self.committee_hash());
        hasher.update(&position.epoch.to_le_bytes());
        hasher.update(&position.slot.to_le_bytes());
        let digest = hasher.finalize();
        let selection_point = u64::from_le_bytes(digest.as_bytes()[0..8].try_into().unwrap())
            % self.total_voting_power;

        let mut running = 0u64;
        for validator in &self.validators {
            running = running.saturating_add(validator.voting_power);
            if selection_point < running {
                return validator.id;
            }
        }
        self.validators
            .last()
            .map(|validator| validator.id)
            .expect("validated validator set is never empty")
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OrderingPath {
    FastPathPrivateTransfer,
    DagBftSharedState,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusPosition {
    pub epoch: u64,
    pub slot: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteTarget {
    pub position: ConsensusPosition,
    pub ordering_path: OrderingPath,
    pub block_digest: [u8; 32],
}

impl VoteTarget {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 4 + 32 + 32);
        out.extend_from_slice(b"unchained.consensus.vote-target.v1");
        out.extend_from_slice(&self.position.epoch.to_le_bytes());
        out.extend_from_slice(&self.position.slot.to_le_bytes());
        out.push(match self.ordering_path {
            OrderingPath::FastPathPrivateTransfer => 0,
            OrderingPath::DagBftSharedState => 1,
        });
        out.extend_from_slice(&self.block_digest);
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorVote {
    pub voter: ValidatorId,
    pub target: VoteTarget,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub target: VoteTarget,
    pub votes: Vec<ValidatorVote>,
    pub signed_voting_power: u64,
}

impl QuorumCertificate {
    pub fn from_votes(
        validator_set: &ValidatorSet,
        target: VoteTarget,
        mut votes: Vec<ValidatorVote>,
    ) -> AnyResult<Self> {
        if votes.is_empty() {
            bail!("quorum certificate requires at least one vote");
        }
        votes.sort_by_key(|vote| vote.voter);
        let mut signed_voting_power = 0u64;
        let mut previous_voter = None;
        for vote in &votes {
            if vote.target != target {
                bail!("quorum certificate vote target mismatch");
            }
            if vote.signature.is_empty() {
                bail!("quorum certificate votes must carry a validator signature");
            }
            if previous_voter == Some(vote.voter) {
                bail!("quorum certificate contains duplicate validator votes");
            }
            previous_voter = Some(vote.voter);
            let validator = validator_set
                .validator(&vote.voter)
                .ok_or_else(|| anyhow!("quorum certificate references unknown validator"))?;
            UnparsedPublicKey::new(&ML_DSA_65, validator.keys.hot_ml_dsa_65_spki.as_slice())
                .verify(&target.signing_bytes(), vote.signature.as_slice())
                .map_err(|_| anyhow!("quorum certificate vote signature verification failed"))?;
            signed_voting_power = signed_voting_power
                .checked_add(validator.voting_power)
                .ok_or_else(|| anyhow!("quorum certificate voting power overflow"))?;
        }
        if signed_voting_power < validator_set.quorum_threshold {
            bail!(
                "quorum certificate is under threshold: signed={} threshold={}",
                signed_voting_power,
                validator_set.quorum_threshold
            );
        }
        Ok(Self {
            target,
            votes,
            signed_voting_power,
        })
    }

    pub fn validate(&self, validator_set: &ValidatorSet) -> AnyResult<()> {
        let rebuilt = Self::from_votes(validator_set, self.target.clone(), self.votes.clone())?;
        if rebuilt.signed_voting_power != self.signed_voting_power {
            bail!("quorum certificate signed voting power does not match vote set");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeterministicEpochSchedule {
    pub epoch: u64,
    pub slots_per_epoch: u32,
    pub slot_duration_ms: u64,
    pub epoch_start_unix_ms: u64,
}

impl DeterministicEpochSchedule {
    pub fn new(
        epoch: u64,
        slots_per_epoch: u32,
        slot_duration_ms: u64,
        epoch_start_unix_ms: u64,
    ) -> AnyResult<Self> {
        if slots_per_epoch == 0 {
            bail!("epoch schedule must contain at least one slot");
        }
        if slot_duration_ms == 0 {
            bail!("slot duration must be non-zero");
        }
        Ok(Self {
            epoch,
            slots_per_epoch,
            slot_duration_ms,
            epoch_start_unix_ms,
        })
    }

    pub fn slot_start_unix_ms(&self, slot: u32) -> AnyResult<u64> {
        if slot >= self.slots_per_epoch {
            bail!("slot {} is outside epoch {}", slot, self.epoch);
        }
        self.epoch_start_unix_ms
            .checked_add(self.slot_duration_ms.saturating_mul(slot as u64))
            .ok_or_else(|| anyhow!("slot start timestamp overflow"))
    }

    pub fn position_for_unix_ms(&self, unix_ms: u64) -> Option<ConsensusPosition> {
        if unix_ms < self.epoch_start_unix_ms {
            return None;
        }
        let elapsed = unix_ms - self.epoch_start_unix_ms;
        let slot = elapsed / self.slot_duration_ms;
        if slot >= self.slots_per_epoch as u64 {
            return None;
        }
        Some(ConsensusPosition {
            epoch: self.epoch,
            slot: slot as u32,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochConsensusState {
    pub validator_set: ValidatorSet,
    pub schedule: DeterministicEpochSchedule,
    pub last_committed_slot: Option<u32>,
    pub highest_qc: Option<QuorumCertificate>,
}

impl EpochConsensusState {
    pub fn new(
        validator_set: ValidatorSet,
        schedule: DeterministicEpochSchedule,
        last_committed_slot: Option<u32>,
        highest_qc: Option<QuorumCertificate>,
    ) -> AnyResult<Self> {
        if validator_set.epoch != schedule.epoch {
            bail!("validator set epoch and slot schedule epoch must match");
        }
        if let Some(slot) = last_committed_slot {
            if slot >= schedule.slots_per_epoch {
                bail!("last committed slot is outside the epoch schedule");
            }
        }
        if let Some(qc) = &highest_qc {
            qc.validate(&validator_set)?;
            if qc.target.position.epoch != schedule.epoch {
                bail!("highest QC epoch does not match the local epoch schedule");
            }
        }
        Ok(Self {
            validator_set,
            schedule,
            last_committed_slot,
            highest_qc,
        })
    }

    pub fn leader_for_slot(&self, slot: u32) -> AnyResult<ValidatorId> {
        self.schedule.slot_start_unix_ms(slot)?;
        Ok(self.validator_set.leader_for(ConsensusPosition {
            epoch: self.schedule.epoch,
            slot,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign};
    use aws_lc_rs::unstable::signature::PqdsaKeyPair;

    fn validator(voting_power: u64) -> (Validator, PqdsaKeyPair) {
        let hot_key = ml_dsa_65_generate().unwrap();
        let cold_key = ml_dsa_65_generate().unwrap();
        (
            Validator::new(
                voting_power,
                ValidatorKeys {
                    hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key).unwrap(),
                    cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                },
            )
            .unwrap(),
            hot_key,
        )
    }

    #[test]
    fn protocol_constants_match_architecture_targets() {
        assert_eq!(MAX_ACTIVE_VALIDATORS, 32);
        assert_eq!(DEFAULT_SLOTS_PER_EPOCH, 256);
        assert_eq!(DEFAULT_SLOT_DURATION_MS, 250);
        assert_eq!(FAST_PATH_TIMEOUT_MS, 450);
        assert_eq!(DAG_BFT_TIMEOUT_MS, 1_200);
        assert_eq!(MAX_COINS_PER_CHECKPOINT, 111);
    }

    #[test]
    fn validator_set_requires_unique_validators_and_quorum() {
        let (v1, _) = validator(4);
        let (v2, _) = validator(3);
        let (v3, _) = validator(2);
        let set = ValidatorSet::new(7, vec![v1.clone(), v2, v3]).unwrap();
        assert_eq!(set.total_voting_power, 9);
        assert_eq!(set.quorum_threshold, 7);

        let duplicate = Validator {
            id: v1.id,
            voting_power: 5,
            keys: v1.keys.clone(),
        };
        let err = ValidatorSet::new(7, vec![v1, duplicate]).unwrap_err();
        assert!(err.to_string().contains("duplicate validator ids"));
    }

    #[test]
    fn quorum_certificate_enforces_explicit_vote_set_threshold() {
        let (v1, k1) = validator(5);
        let (v2, k2) = validator(3);
        let (v3, k3) = validator(2);
        let set = ValidatorSet::new(11, vec![v1.clone(), v2.clone(), v3.clone()]).unwrap();
        let target = VoteTarget {
            position: ConsensusPosition { epoch: 11, slot: 3 },
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: [42u8; 32],
        };
        let target_bytes = target.signing_bytes();
        let votes = vec![
            ValidatorVote {
                voter: v1.id,
                target: target.clone(),
                signature: ml_dsa_65_sign(&k1, &target_bytes).unwrap(),
            },
            ValidatorVote {
                voter: v2.id,
                target: target.clone(),
                signature: ml_dsa_65_sign(&k2, &target_bytes).unwrap(),
            },
        ];
        let qc = QuorumCertificate::from_votes(&set, target.clone(), votes).unwrap();
        assert_eq!(qc.signed_voting_power, 8);
        qc.validate(&set).unwrap();

        let insufficient_votes = vec![ValidatorVote {
            voter: v3.id,
            target,
            signature: ml_dsa_65_sign(
                &k3,
                &VoteTarget {
                    position: ConsensusPosition { epoch: 11, slot: 3 },
                    ordering_path: OrderingPath::FastPathPrivateTransfer,
                    block_digest: [42u8; 32],
                }
                .signing_bytes(),
            )
            .unwrap(),
        }];
        let err = QuorumCertificate::from_votes(
            &set,
            VoteTarget {
                position: ConsensusPosition { epoch: 11, slot: 3 },
                ordering_path: OrderingPath::FastPathPrivateTransfer,
                block_digest: [42u8; 32],
            },
            insufficient_votes,
        )
        .unwrap_err();
        assert!(err.to_string().contains("under threshold"));
    }

    #[test]
    fn epoch_schedule_and_leader_selection_are_deterministic() {
        let (v1, _) = validator(5);
        let (v2, _) = validator(3);
        let (v3, _) = validator(2);
        let set = ValidatorSet::new(3, vec![v1, v2, v3]).unwrap();
        let schedule = DeterministicEpochSchedule::new(3, 8, 250, 10_000).unwrap();
        let state = EpochConsensusState::new(set.clone(), schedule.clone(), None, None).unwrap();

        assert_eq!(
            schedule.position_for_unix_ms(10_000),
            Some(ConsensusPosition { epoch: 3, slot: 0 })
        );
        assert_eq!(
            schedule.position_for_unix_ms(10_749),
            Some(ConsensusPosition { epoch: 3, slot: 2 })
        );
        assert_eq!(schedule.position_for_unix_ms(12_001), None);

        let first = state.leader_for_slot(2).unwrap();
        let second = state.leader_for_slot(2).unwrap();
        assert_eq!(first, second);
        assert!(set.validator(&first).is_some());
    }

    #[test]
    fn committee_hash_is_stable_across_epoch_rollover_for_same_membership() {
        let (v1, _) = validator(5);
        let (v2, _) = validator(3);
        let current = ValidatorSet::new(9, vec![v1.clone(), v2.clone()]).unwrap();
        let rolled = ValidatorSet::new(10, vec![v1, v2]).unwrap();
        assert_eq!(current.committee_hash(), rolled.committee_hash());
    }
}
