use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    canonical,
    consensus::{ConsensusPosition, ValidatorId, ValidatorVote},
    epoch::AnchorProposal,
    node_identity::SignedEnvelope,
    storage::Store,
    transaction::SharedStateDagBatch,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAnchorProposalObservation {
    pub proposal: AnchorProposal,
    pub envelope: SignedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredValidatorVoteObservation {
    pub vote: ValidatorVote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSharedStateDagObservation {
    pub batch_id: [u8; 32],
    pub envelope: SignedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalEquivocationEvidence {
    pub proposer: ValidatorId,
    pub position: ConsensusPosition,
    pub first_proposal: AnchorProposal,
    pub first_envelope: SignedEnvelope,
    pub second_proposal: AnchorProposal,
    pub second_envelope: SignedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteEquivocationEvidence {
    pub voter: ValidatorId,
    pub position: ConsensusPosition,
    pub first_vote: ValidatorVote,
    pub second_vote: ValidatorVote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DagBatchEquivocationEvidence {
    pub author: ValidatorId,
    pub epoch: u64,
    pub round: u64,
    pub first_batch: SharedStateDagBatch,
    pub first_envelope: SignedEnvelope,
    pub second_batch: SharedStateDagBatch,
    pub second_envelope: SignedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsensusEvidence {
    ProposalEquivocation(ProposalEquivocationEvidence),
    VoteEquivocation(VoteEquivocationEvidence),
    DagBatchEquivocation(DagBatchEquivocationEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusEvidenceRecord {
    pub evidence_id: [u8; 32],
    pub recorded_unix_ms: u64,
    pub evidence: ConsensusEvidence,
}

impl ProposalEquivocationEvidence {
    pub fn new(
        proposer: ValidatorId,
        first_proposal: AnchorProposal,
        first_envelope: SignedEnvelope,
        second_proposal: AnchorProposal,
        second_envelope: SignedEnvelope,
    ) -> Result<Self> {
        if first_proposal.position != second_proposal.position {
            bail!("proposal equivocation requires matching consensus positions");
        }
        if first_proposal.hash == second_proposal.hash {
            bail!("proposal equivocation requires conflicting proposal hashes");
        }
        let mut pair = vec![
            (first_proposal.hash, first_proposal, first_envelope),
            (second_proposal.hash, second_proposal, second_envelope),
        ];
        pair.sort_by_key(|(proposal_hash, _, _)| *proposal_hash);
        let (_, first_proposal, first_envelope) = pair.remove(0);
        let (_, second_proposal, second_envelope) = pair.remove(0);
        Ok(Self {
            proposer,
            position: first_proposal.position,
            first_proposal,
            first_envelope,
            second_proposal,
            second_envelope,
        })
    }

    fn evidence_id(&self) -> Result<[u8; 32]> {
        let first_proposal = canonical::encode_anchor_proposal(&self.first_proposal)?;
        let first_envelope = canonical::encode_signed_envelope(&self.first_envelope)?;
        let second_proposal = canonical::encode_anchor_proposal(&self.second_proposal)?;
        let second_envelope = canonical::encode_signed_envelope(&self.second_envelope)?;
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.evidence.proposal-equivocation.v1");
        hasher.update(&self.proposer.0);
        hasher.update(&self.position.epoch.to_le_bytes());
        hasher.update(&self.position.slot.to_le_bytes());
        hasher.update(&(first_proposal.len() as u64).to_le_bytes());
        hasher.update(&first_proposal);
        hasher.update(&(first_envelope.len() as u64).to_le_bytes());
        hasher.update(&first_envelope);
        hasher.update(&(second_proposal.len() as u64).to_le_bytes());
        hasher.update(&second_proposal);
        hasher.update(&(second_envelope.len() as u64).to_le_bytes());
        hasher.update(&second_envelope);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl VoteEquivocationEvidence {
    pub fn new(first_vote: ValidatorVote, second_vote: ValidatorVote) -> Result<Self> {
        if first_vote.voter != second_vote.voter {
            bail!("vote equivocation requires matching voters");
        }
        if first_vote.target.position != second_vote.target.position {
            bail!("vote equivocation requires matching consensus positions");
        }
        if first_vote.target == second_vote.target {
            bail!("vote equivocation requires conflicting vote targets");
        }
        let mut pair = vec![first_vote, second_vote];
        pair.sort_by_key(|vote| vote.target.block_digest);
        let first_vote = pair.remove(0);
        let second_vote = pair.remove(0);
        Ok(Self {
            voter: first_vote.voter,
            position: first_vote.target.position,
            first_vote,
            second_vote,
        })
    }

    fn evidence_id(&self) -> Result<[u8; 32]> {
        let first_vote = canonical::encode_validator_vote(&self.first_vote)?;
        let second_vote = canonical::encode_validator_vote(&self.second_vote)?;
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.evidence.vote-equivocation.v1");
        hasher.update(&self.voter.0);
        hasher.update(&self.position.epoch.to_le_bytes());
        hasher.update(&self.position.slot.to_le_bytes());
        hasher.update(&(first_vote.len() as u64).to_le_bytes());
        hasher.update(&first_vote);
        hasher.update(&(second_vote.len() as u64).to_le_bytes());
        hasher.update(&second_vote);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl DagBatchEquivocationEvidence {
    pub fn new(
        author: ValidatorId,
        first_batch: SharedStateDagBatch,
        first_envelope: SignedEnvelope,
        second_batch: SharedStateDagBatch,
        second_envelope: SignedEnvelope,
    ) -> Result<Self> {
        if first_batch.author != author || second_batch.author != author {
            bail!("DAG batch equivocation author mismatch");
        }
        if first_batch.epoch != second_batch.epoch || first_batch.round != second_batch.round {
            bail!("DAG batch equivocation requires matching epoch and round");
        }
        if first_batch.batch_id == second_batch.batch_id {
            bail!("DAG batch equivocation requires conflicting batch ids");
        }
        let mut pair = vec![
            (first_batch.batch_id, first_batch, first_envelope),
            (second_batch.batch_id, second_batch, second_envelope),
        ];
        pair.sort_by_key(|(batch_id, _, _)| *batch_id);
        let (_, first_batch, first_envelope) = pair.remove(0);
        let (_, second_batch, second_envelope) = pair.remove(0);
        Ok(Self {
            author,
            epoch: first_batch.epoch,
            round: first_batch.round,
            first_batch,
            first_envelope,
            second_batch,
            second_envelope,
        })
    }

    fn evidence_id(&self) -> Result<[u8; 32]> {
        let first_batch = canonical::encode_shared_state_dag_batch(&self.first_batch)?;
        let first_envelope = canonical::encode_signed_envelope(&self.first_envelope)?;
        let second_batch = canonical::encode_shared_state_dag_batch(&self.second_batch)?;
        let second_envelope = canonical::encode_signed_envelope(&self.second_envelope)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "unchained.consensus.evidence.dag-batch-equivocation.v1",
        );
        hasher.update(&self.author.0);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.round.to_le_bytes());
        hasher.update(&(first_batch.len() as u64).to_le_bytes());
        hasher.update(&first_batch);
        hasher.update(&(first_envelope.len() as u64).to_le_bytes());
        hasher.update(&first_envelope);
        hasher.update(&(second_batch.len() as u64).to_le_bytes());
        hasher.update(&second_batch);
        hasher.update(&(second_envelope.len() as u64).to_le_bytes());
        hasher.update(&second_envelope);
        Ok(*hasher.finalize().as_bytes())
    }
}

impl ConsensusEvidenceRecord {
    pub fn new(evidence: ConsensusEvidence) -> Result<Self> {
        let evidence_id = match &evidence {
            ConsensusEvidence::ProposalEquivocation(evidence) => evidence.evidence_id()?,
            ConsensusEvidence::VoteEquivocation(evidence) => evidence.evidence_id()?,
            ConsensusEvidence::DagBatchEquivocation(evidence) => evidence.evidence_id()?,
        };
        Ok(Self {
            evidence_id,
            recorded_unix_ms: now_unix_ms(),
            evidence,
        })
    }

    pub fn validator_id(&self) -> ValidatorId {
        match &self.evidence {
            ConsensusEvidence::ProposalEquivocation(evidence) => evidence.proposer,
            ConsensusEvidence::VoteEquivocation(evidence) => evidence.voter,
            ConsensusEvidence::DagBatchEquivocation(evidence) => evidence.author,
        }
    }
}

pub fn observe_anchor_proposal(
    db: &Store,
    proposer: ValidatorId,
    proposal: &AnchorProposal,
    envelope: &SignedEnvelope,
) -> Result<Option<ConsensusEvidenceRecord>> {
    let key = Store::anchor_proposal_observation_key(proposer, proposal.position);
    let existing = db.load_anchor_proposal_observation(&key)?;
    let observation = StoredAnchorProposalObservation {
        proposal: proposal.clone(),
        envelope: envelope.clone(),
    };
    match existing {
        Some(existing) if existing.proposal.hash == proposal.hash => Ok(None),
        Some(existing) => {
            let evidence = ProposalEquivocationEvidence::new(
                proposer,
                existing.proposal,
                existing.envelope,
                proposal.clone(),
                envelope.clone(),
            )?;
            let record =
                ConsensusEvidenceRecord::new(ConsensusEvidence::ProposalEquivocation(evidence))?;
            db.store_consensus_evidence(&record)?;
            Ok(Some(record))
        }
        None => {
            db.store_anchor_proposal_observation(&key, &observation)?;
            Ok(None)
        }
    }
}

pub fn observe_validator_vote(
    db: &Store,
    vote: &ValidatorVote,
) -> Result<Option<ConsensusEvidenceRecord>> {
    let key = Store::validator_vote_observation_key(vote.voter, vote.target.position);
    let existing = db.load_validator_vote_observation(&key)?;
    let observation = StoredValidatorVoteObservation { vote: vote.clone() };
    match existing {
        Some(existing) if existing.vote.target == vote.target => Ok(None),
        Some(existing) => {
            let evidence = VoteEquivocationEvidence::new(existing.vote, vote.clone())?;
            let record =
                ConsensusEvidenceRecord::new(ConsensusEvidence::VoteEquivocation(evidence))?;
            db.store_consensus_evidence(&record)?;
            Ok(Some(record))
        }
        None => {
            db.store_validator_vote_observation(&key, &observation)?;
            Ok(None)
        }
    }
}

pub fn observe_shared_state_dag_batch(
    db: &Store,
    batch: &SharedStateDagBatch,
    envelope: &SignedEnvelope,
) -> Result<Option<ConsensusEvidenceRecord>> {
    let key = Store::shared_state_dag_observation_key(batch.epoch, batch.round, batch.author);
    let existing = db.load_shared_state_dag_observation(&key)?;
    match existing {
        Some(existing) if existing.batch_id == batch.batch_id => Ok(None),
        Some(existing) => {
            let existing_batch = db
                .load_shared_state_dag_batch(&existing.batch_id)?
                .ok_or_else(|| {
                    anyhow!("stored DAG batch observation references a missing batch")
                })?;
            let evidence = DagBatchEquivocationEvidence::new(
                batch.author,
                existing_batch,
                existing.envelope,
                batch.clone(),
                envelope.clone(),
            )?;
            let record =
                ConsensusEvidenceRecord::new(ConsensusEvidence::DagBatchEquivocation(evidence))?;
            db.store_consensus_evidence(&record)?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{OrderingPath, Validator, ValidatorKeys, ValidatorSet},
        crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
        epoch::AnchorProposal,
        node_identity::SignedEnvelope,
        transaction::SharedStateBatch,
    };
    use tempfile::TempDir;

    fn validator_set() -> ValidatorSet {
        let hot_key = ml_dsa_65_generate().unwrap();
        let cold_key = ml_dsa_65_generate().unwrap();
        ValidatorSet::new(
            0,
            vec![Validator::new(
                5,
                ValidatorKeys {
                    hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key).unwrap(),
                    cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                },
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn proposal(
        validator_set: &ValidatorSet,
        slot: u32,
        ordering_path: crate::consensus::OrderingPath,
        merkle_root: [u8; 32],
        ordered_tx_root: [u8; 32],
    ) -> AnchorProposal {
        AnchorProposal::new(
            slot as u64,
            if slot == 0 {
                None
            } else {
                Some([slot as u8; 32])
            },
            ordering_path,
            merkle_root,
            if ordering_path == crate::consensus::OrderingPath::FastPathPrivateTransfer {
                1
            } else {
                0
            },
            if ordering_path == crate::consensus::OrderingPath::DagBftSharedState {
                1
            } else {
                0
            },
            if ordering_path == crate::consensus::OrderingPath::DagBftSharedState {
                vec![[9u8; 32]]
            } else {
                Vec::new()
            },
            if ordering_path == crate::consensus::OrderingPath::DagBftSharedState {
                vec![[9u8; 32]]
            } else {
                Vec::new()
            },
            ordered_tx_root,
            if ordering_path == crate::consensus::OrderingPath::DagBftSharedState {
                1
            } else {
                0
            },
            validator_set.clone(),
        )
        .unwrap()
    }

    fn envelope(message_seed: u8) -> SignedEnvelope {
        SignedEnvelope {
            version: 1,
            protocol_version: 1,
            node_id: [message_seed; 32],
            chain_id: Some([7u8; 32]),
            issued_unix_ms: 1,
            expires_unix_ms: 2,
            response_to_message_id: None,
            nonce: [message_seed; 16],
            message_id: [message_seed.wrapping_add(1); 32],
            payload: vec![message_seed],
            sig: vec![message_seed.wrapping_add(2)],
        }
    }

    fn vote(validator_set: &ValidatorSet, block_digest_seed: u8) -> ValidatorVote {
        let hot_key = ml_dsa_65_generate().unwrap();
        let validator = validator_set.validators[0].clone();
        let target = crate::consensus::VoteTarget {
            position: ConsensusPosition { epoch: 0, slot: 1 },
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: [block_digest_seed; 32],
        };
        ValidatorVote {
            voter: validator.id,
            target: target.clone(),
            signature: ml_dsa_65_sign(&hot_key, &target.signing_bytes()).unwrap(),
        }
    }

    #[test]
    fn proposal_equivocation_is_persisted_once() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let validator_set = validator_set();
        let proposer = validator_set.validators[0].id;
        let first = proposal(
            &validator_set,
            1,
            OrderingPath::FastPathPrivateTransfer,
            [1u8; 32],
            [0u8; 32],
        );
        let second = proposal(
            &validator_set,
            1,
            OrderingPath::DagBftSharedState,
            [0u8; 32],
            [2u8; 32],
        );

        assert!(observe_anchor_proposal(&db, proposer, &first, &envelope(1))
            .unwrap()
            .is_none());
        let evidence = observe_anchor_proposal(&db, proposer, &second, &envelope(2))
            .unwrap()
            .expect("proposal equivocation evidence");
        assert!(matches!(
            evidence.evidence,
            ConsensusEvidence::ProposalEquivocation(_)
        ));
        assert_eq!(db.load_consensus_evidence().unwrap().len(), 1);
        let repeated = observe_anchor_proposal(&db, proposer, &second, &envelope(2))
            .unwrap()
            .expect("proposal equivocation remains detectable");
        assert_eq!(repeated.evidence_id, evidence.evidence_id);
        assert_eq!(db.load_consensus_evidence().unwrap().len(), 1);
    }

    #[test]
    fn vote_equivocation_is_persisted_once() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let validator_set = validator_set();
        let first = vote(&validator_set, 4);
        let second = ValidatorVote {
            voter: first.voter,
            target: crate::consensus::VoteTarget {
                position: first.target.position,
                ordering_path: first.target.ordering_path,
                block_digest: [5u8; 32],
            },
            signature: vec![8u8; 12],
        };

        assert!(observe_validator_vote(&db, &first).unwrap().is_none());
        let evidence = observe_validator_vote(&db, &second)
            .unwrap()
            .expect("vote equivocation evidence");
        assert!(matches!(
            evidence.evidence,
            ConsensusEvidence::VoteEquivocation(_)
        ));
        assert_eq!(db.load_consensus_evidence().unwrap().len(), 1);
    }

    #[test]
    fn dag_batch_equivocation_is_persisted_once() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let validator_set = validator_set();
        let author = validator_set.validators[0].id;
        let first = SharedStateDagBatch::new(
            0,
            1,
            author,
            Vec::new(),
            SharedStateBatch::new(vec![crate::Tx::new(
                vec![[1u8; 32]],
                vec![crate::transaction::ShieldedOutput {
                    note_commitment: [2u8; 32],
                    kem_ct: [3u8; crate::crypto::ML_KEM_768_CT_BYTES],
                    nonce: [4u8; 24],
                    view_tag: 5,
                    ciphertext: vec![6u8],
                }],
                vec![7u8],
            )])
            .unwrap(),
        )
        .unwrap();
        db.store_shared_state_dag_batch(&first).unwrap();
        db.store_shared_state_dag_observation(
            &Store::shared_state_dag_observation_key(first.epoch, first.round, first.author),
            &StoredSharedStateDagObservation {
                batch_id: first.batch_id,
                envelope: envelope(3),
            },
        )
        .unwrap();
        assert!(observe_shared_state_dag_batch(&db, &first, &envelope(3))
            .unwrap()
            .is_none());

        let second = SharedStateDagBatch::new(
            0,
            1,
            author,
            Vec::new(),
            SharedStateBatch::new(vec![crate::Tx::new(
                vec![[8u8; 32]],
                vec![crate::transaction::ShieldedOutput {
                    note_commitment: [9u8; 32],
                    kem_ct: [10u8; crate::crypto::ML_KEM_768_CT_BYTES],
                    nonce: [11u8; 24],
                    view_tag: 12,
                    ciphertext: vec![13u8],
                }],
                vec![14u8],
            )])
            .unwrap(),
        )
        .unwrap();
        db.store_shared_state_dag_batch(&second).unwrap();
        let evidence = observe_shared_state_dag_batch(&db, &second, &envelope(4))
            .unwrap()
            .expect("dag batch equivocation evidence");
        assert!(matches!(
            evidence.evidence,
            ConsensusEvidence::DagBatchEquivocation(_)
        ));
        assert_eq!(db.load_consensus_evidence().unwrap().len(), 1);
    }
}
