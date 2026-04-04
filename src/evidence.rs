use anyhow::{anyhow, bail, Result};
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::ML_DSA_65;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    canonical::{self, CanonicalReader},
    consensus::{ConsensusPosition, OrderingPath, ValidatorId, ValidatorSet, ValidatorVote},
    epoch::{Anchor, AnchorProposal},
    node_identity::{NodeRecordV2, SignedEnvelope},
    storage::Store,
    transaction::SharedStateDagBatch,
};

const TOPIC_ANCHOR_PROPOSAL: u8 = 2;
const TOPIC_SHARED_STATE_DAG_BATCH: u8 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeAuthor {
    pub node_id: [u8; 32],
    pub auth_spki: Vec<u8>,
}

impl EnvelopeAuthor {
    pub fn from_record(record: &NodeRecordV2) -> Self {
        Self {
            node_id: record.node_id,
            auth_spki: record.auth_spki.clone(),
        }
    }

    pub fn validator_id(&self) -> ValidatorId {
        ValidatorId::from_hot_key(&self.auth_spki)
    }

    pub fn verify_envelope(&self, envelope: &SignedEnvelope) -> Result<()> {
        let record = NodeRecordV2 {
            version: envelope.version,
            protocol_version: envelope.protocol_version,
            node_id: self.node_id,
            chain_id: envelope.chain_id,
            root_spki: Vec::new(),
            auth_spki: self.auth_spki.clone(),
            ingress_kem_pk: crate::crypto::TaggedKemPublicKey::zero_ml_kem_768(),
            ingress_x25519_pk: [0u8; 32],
            addresses: vec!["0.0.0.0:0".to_string()],
            issued_unix_ms: envelope.issued_unix_ms,
            expires_unix_ms: envelope.expires_unix_ms,
            sig: Vec::new(),
        };
        envelope.verify(&record, envelope.issued_unix_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAnchorProposalObservation {
    pub proposer_author: EnvelopeAuthor,
    pub proposal: AnchorProposal,
    pub envelope: SignedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredValidatorVoteObservation {
    pub vote: ValidatorVote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredSharedStateDagObservation {
    pub author: EnvelopeAuthor,
    pub batch_id: [u8; 32],
    pub envelope: SignedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalEquivocationEvidence {
    pub proposer: ValidatorId,
    pub position: ConsensusPosition,
    pub first_author: EnvelopeAuthor,
    pub first_proposal: AnchorProposal,
    pub first_envelope: SignedEnvelope,
    pub second_author: EnvelopeAuthor,
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
    pub first_author_info: EnvelopeAuthor,
    pub first_batch: SharedStateDagBatch,
    pub first_envelope: SignedEnvelope,
    pub second_author_info: EnvelopeAuthor,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LivenessFaultKind {
    MissedVote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LivenessFaultProof {
    pub validator: ValidatorId,
    pub position: ConsensusPosition,
    pub ordering_path: OrderingPath,
    pub anchor_hash: [u8; 32],
    pub kind: LivenessFaultKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LivenessFaultRecord {
    pub evidence_id: [u8; 32],
    pub recorded_unix_ms: u64,
    pub fault: LivenessFaultProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashableEvidence {
    Consensus(ConsensusEvidence),
    Liveness(LivenessFaultProof),
}

impl ProposalEquivocationEvidence {
    pub fn new(
        proposer: ValidatorId,
        first_author: EnvelopeAuthor,
        first_proposal: AnchorProposal,
        first_envelope: SignedEnvelope,
        second_author: EnvelopeAuthor,
        second_proposal: AnchorProposal,
        second_envelope: SignedEnvelope,
    ) -> Result<Self> {
        if first_author.validator_id() != proposer || second_author.validator_id() != proposer {
            bail!("proposal equivocation author does not match the accused validator");
        }
        if first_proposal.position != second_proposal.position {
            bail!("proposal equivocation requires matching consensus positions");
        }
        if first_proposal.hash == second_proposal.hash {
            bail!("proposal equivocation requires conflicting proposal hashes");
        }
        let mut pair = vec![
            (
                first_proposal.hash,
                first_author,
                first_proposal,
                first_envelope,
            ),
            (
                second_proposal.hash,
                second_author,
                second_proposal,
                second_envelope,
            ),
        ];
        pair.sort_by_key(|(proposal_hash, _, _, _)| *proposal_hash);
        let (_, first_author, first_proposal, first_envelope) = pair.remove(0);
        let (_, second_author, second_proposal, second_envelope) = pair.remove(0);
        Ok(Self {
            proposer,
            position: first_proposal.position,
            first_author,
            first_proposal,
            first_envelope,
            second_author,
            second_proposal,
            second_envelope,
        })
    }

    pub fn evidence_id(&self) -> Result<[u8; 32]> {
        let first_proposal = canonical::encode_anchor_proposal(&self.first_proposal)?;
        let first_envelope = canonical::encode_signed_envelope(&self.first_envelope)?;
        let second_proposal = canonical::encode_anchor_proposal(&self.second_proposal)?;
        let second_envelope = canonical::encode_signed_envelope(&self.second_envelope)?;
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.evidence.proposal-equivocation.v1");
        hasher.update(&self.proposer.0);
        hasher.update(&self.position.epoch.to_le_bytes());
        hasher.update(&self.position.slot.to_le_bytes());
        hash_envelope_author(&mut hasher, &self.first_author);
        hasher.update(&(first_proposal.len() as u64).to_le_bytes());
        hasher.update(&first_proposal);
        hasher.update(&(first_envelope.len() as u64).to_le_bytes());
        hasher.update(&first_envelope);
        hash_envelope_author(&mut hasher, &self.second_author);
        hasher.update(&(second_proposal.len() as u64).to_le_bytes());
        hasher.update(&second_proposal);
        hasher.update(&(second_envelope.len() as u64).to_le_bytes());
        hasher.update(&second_envelope);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate(&self, db: &Store) -> Result<()> {
        let expected = db
            .load_validator_committee(self.position.epoch)?
            .ok_or_else(|| anyhow!("missing validator committee for proposal evidence epoch"))?;
        if expected != self.first_proposal.validator_set
            || expected != self.second_proposal.validator_set
        {
            bail!("proposal equivocation references a non-canonical validator set");
        }
        if expected.validator(&self.proposer).is_none() {
            bail!("proposal equivocation references an unknown validator");
        }
        if expected.leader_for(self.position) != self.proposer {
            bail!("proposal equivocation proposer is not the deterministic leader");
        }
        validate_anchor_proposal_digest(&self.first_proposal)?;
        validate_anchor_proposal_digest(&self.second_proposal)?;
        validate_enveloped_anchor_proposal(
            &self.first_author,
            &self.first_proposal,
            &self.first_envelope,
            db.effective_chain_id(),
        )?;
        validate_enveloped_anchor_proposal(
            &self.second_author,
            &self.second_proposal,
            &self.second_envelope,
            db.effective_chain_id(),
        )?;
        Ok(())
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

    pub fn evidence_id(&self) -> Result<[u8; 32]> {
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

    fn validate(&self, db: &Store) -> Result<()> {
        let validator_set = db
            .load_validator_committee(self.position.epoch)?
            .ok_or_else(|| anyhow!("missing validator committee for vote evidence epoch"))?;
        verify_vote_against_validator_set(&validator_set, &self.first_vote)?;
        verify_vote_against_validator_set(&validator_set, &self.second_vote)?;
        Ok(())
    }
}

impl DagBatchEquivocationEvidence {
    pub fn new(
        author: ValidatorId,
        first_author_info: EnvelopeAuthor,
        first_batch: SharedStateDagBatch,
        first_envelope: SignedEnvelope,
        second_author_info: EnvelopeAuthor,
        second_batch: SharedStateDagBatch,
        second_envelope: SignedEnvelope,
    ) -> Result<Self> {
        if first_author_info.validator_id() != author || second_author_info.validator_id() != author
        {
            bail!("DAG batch equivocation author does not match the accused validator");
        }
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
            (
                first_batch.batch_id,
                first_author_info,
                first_batch,
                first_envelope,
            ),
            (
                second_batch.batch_id,
                second_author_info,
                second_batch,
                second_envelope,
            ),
        ];
        pair.sort_by_key(|(batch_id, _, _, _)| *batch_id);
        let (_, first_author_info, first_batch, first_envelope) = pair.remove(0);
        let (_, second_author_info, second_batch, second_envelope) = pair.remove(0);
        Ok(Self {
            author,
            epoch: first_batch.epoch,
            round: first_batch.round,
            first_author_info,
            first_batch,
            first_envelope,
            second_author_info,
            second_batch,
            second_envelope,
        })
    }

    pub fn evidence_id(&self) -> Result<[u8; 32]> {
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
        hash_envelope_author(&mut hasher, &self.first_author_info);
        hasher.update(&(first_batch.len() as u64).to_le_bytes());
        hasher.update(&first_batch);
        hasher.update(&(first_envelope.len() as u64).to_le_bytes());
        hasher.update(&first_envelope);
        hash_envelope_author(&mut hasher, &self.second_author_info);
        hasher.update(&(second_batch.len() as u64).to_le_bytes());
        hasher.update(&second_batch);
        hasher.update(&(second_envelope.len() as u64).to_le_bytes());
        hasher.update(&second_envelope);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate(&self, db: &Store) -> Result<()> {
        let validator_set = db
            .load_validator_committee(self.epoch)?
            .ok_or_else(|| anyhow!("missing validator committee for DAG evidence epoch"))?;
        if validator_set.validator(&self.author).is_none() {
            bail!("DAG batch equivocation references an unknown validator");
        }
        self.first_batch.validate()?;
        self.second_batch.validate()?;
        validate_enveloped_shared_state_dag_batch(
            &self.first_author_info,
            &self.first_batch,
            &self.first_envelope,
            db.effective_chain_id(),
        )?;
        validate_enveloped_shared_state_dag_batch(
            &self.second_author_info,
            &self.second_batch,
            &self.second_envelope,
            db.effective_chain_id(),
        )?;
        Ok(())
    }
}

impl ConsensusEvidence {
    pub fn evidence_id(&self) -> Result<[u8; 32]> {
        match self {
            Self::ProposalEquivocation(evidence) => evidence.evidence_id(),
            Self::VoteEquivocation(evidence) => evidence.evidence_id(),
            Self::DagBatchEquivocation(evidence) => evidence.evidence_id(),
        }
    }

    pub fn validator_id(&self) -> ValidatorId {
        match self {
            Self::ProposalEquivocation(evidence) => evidence.proposer,
            Self::VoteEquivocation(evidence) => evidence.voter,
            Self::DagBatchEquivocation(evidence) => evidence.author,
        }
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        match self {
            Self::ProposalEquivocation(evidence) => evidence.validate(db),
            Self::VoteEquivocation(evidence) => evidence.validate(db),
            Self::DagBatchEquivocation(evidence) => evidence.validate(db),
        }
    }
}

impl ConsensusEvidenceRecord {
    pub fn new(evidence: ConsensusEvidence) -> Result<Self> {
        Ok(Self {
            evidence_id: evidence.evidence_id()?,
            recorded_unix_ms: now_unix_ms(),
            evidence,
        })
    }

    pub fn validator_id(&self) -> ValidatorId {
        self.evidence.validator_id()
    }
}

impl LivenessFaultProof {
    pub fn new_missed_vote(anchor: &Anchor, validator: ValidatorId) -> Result<Self> {
        if anchor.validator_set.validator(&validator).is_none() {
            bail!("liveness fault references a validator outside the finalized committee");
        }
        if anchor.qc.votes.iter().any(|vote| vote.voter == validator) {
            bail!("liveness fault cannot accuse a validator that signed the finalized QC");
        }
        Ok(Self {
            validator,
            position: anchor.position,
            ordering_path: anchor.ordering_path,
            anchor_hash: anchor.hash,
            kind: LivenessFaultKind::MissedVote,
        })
    }

    pub fn evidence_id(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.consensus.evidence.liveness-fault.v1");
        hasher.update(&self.validator.0);
        hasher.update(&self.position.epoch.to_le_bytes());
        hasher.update(&self.position.slot.to_le_bytes());
        hasher.update(&[match self.ordering_path {
            OrderingPath::FastPathPrivateTransfer => 0,
            OrderingPath::DagBftSharedState => 1,
        }]);
        hasher.update(&self.anchor_hash);
        hasher.update(&[match self.kind {
            LivenessFaultKind::MissedVote => 0,
        }]);
        *hasher.finalize().as_bytes()
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        let anchor = db
            .get::<Anchor>("anchor", &self.anchor_hash)?
            .ok_or_else(|| anyhow!("missing finalized anchor referenced by liveness fault"))?;
        if anchor.position != self.position {
            bail!("liveness fault position does not match the finalized anchor");
        }
        if anchor.ordering_path != self.ordering_path {
            bail!("liveness fault ordering path does not match the finalized anchor");
        }
        match self.kind {
            LivenessFaultKind::MissedVote => {
                let expected = Self::new_missed_vote(&anchor, self.validator)?;
                if expected != *self {
                    bail!("liveness fault does not match the canonical finalized-QC omission");
                }
            }
        }
        Ok(())
    }
}

impl LivenessFaultRecord {
    pub fn new(fault: LivenessFaultProof) -> Self {
        Self {
            evidence_id: fault.evidence_id(),
            recorded_unix_ms: now_unix_ms(),
            fault,
        }
    }

    pub fn validator_id(&self) -> ValidatorId {
        self.fault.validator
    }
}

impl SlashableEvidence {
    pub fn evidence_id(&self) -> Result<[u8; 32]> {
        Ok(match self {
            Self::Consensus(evidence) => evidence.evidence_id()?,
            Self::Liveness(fault) => fault.evidence_id(),
        })
    }

    pub fn validator_id(&self) -> ValidatorId {
        match self {
            Self::Consensus(evidence) => evidence.validator_id(),
            Self::Liveness(fault) => fault.validator,
        }
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        match self {
            Self::Consensus(evidence) => evidence.validate(db),
            Self::Liveness(fault) => fault.validate(db),
        }
    }

    pub fn persist(&self, db: &Store) -> Result<[u8; 32]> {
        match self {
            Self::Consensus(evidence) => {
                let record = ConsensusEvidenceRecord::new(evidence.clone())?;
                db.store_consensus_evidence(&record)?;
                Ok(record.evidence_id)
            }
            Self::Liveness(fault) => {
                let record = LivenessFaultRecord::new(fault.clone());
                db.store_liveness_fault_record(&record)?;
                Ok(record.evidence_id)
            }
        }
    }
}

pub fn observe_anchor_proposal(
    db: &Store,
    proposer_author: &EnvelopeAuthor,
    proposal: &AnchorProposal,
    envelope: &SignedEnvelope,
) -> Result<Option<ConsensusEvidenceRecord>> {
    let proposer = proposer_author.validator_id();
    let key = Store::anchor_proposal_observation_key(proposer, proposal.position);
    let existing = db.load_anchor_proposal_observation(&key)?;
    let observation = StoredAnchorProposalObservation {
        proposer_author: proposer_author.clone(),
        proposal: proposal.clone(),
        envelope: envelope.clone(),
    };
    match existing {
        Some(existing) if existing.proposal.hash == proposal.hash => Ok(None),
        Some(existing) => {
            let evidence = ProposalEquivocationEvidence::new(
                proposer,
                existing.proposer_author,
                existing.proposal,
                existing.envelope,
                proposer_author.clone(),
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
    author: &EnvelopeAuthor,
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
                existing.author,
                existing_batch,
                existing.envelope,
                author.clone(),
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

pub fn record_anchor_liveness_faults(
    db: &Store,
    anchor: &Anchor,
) -> Result<Vec<LivenessFaultRecord>> {
    let voters = anchor
        .qc
        .votes
        .iter()
        .map(|vote| vote.voter)
        .collect::<HashSet<_>>();
    let mut recorded = Vec::new();
    for validator in &anchor.validator_set.validators {
        if voters.contains(&validator.id) {
            continue;
        }
        let proof = LivenessFaultProof::new_missed_vote(anchor, validator.id)?;
        let record = LivenessFaultRecord::new(proof);
        if db
            .load_liveness_fault_record(&record.evidence_id)?
            .is_none()
        {
            db.store_liveness_fault_record(&record)?;
            recorded.push(record);
        }
    }
    Ok(recorded)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hash_envelope_author(hasher: &mut blake3::Hasher, author: &EnvelopeAuthor) {
    hasher.update(&author.node_id);
    hasher.update(&(author.auth_spki.len() as u64).to_le_bytes());
    hasher.update(&author.auth_spki);
}

fn validate_anchor_proposal_digest(proposal: &AnchorProposal) -> Result<()> {
    let expected = AnchorProposal::compute_hash(
        proposal.num,
        proposal.parent_hash,
        proposal.position,
        proposal.ordering_path,
        proposal.merkle_root,
        proposal.coin_count,
        proposal.dag_round,
        &proposal.dag_frontier,
        &proposal.ordered_batch_ids,
        proposal.ordered_tx_root,
        proposal.ordered_tx_count,
        &proposal.validator_set,
    );
    if proposal.hash != expected {
        bail!("proposal equivocation carries an anchor proposal with a bad digest");
    }
    Ok(())
}

fn verify_vote_against_validator_set(
    validator_set: &ValidatorSet,
    vote: &ValidatorVote,
) -> Result<()> {
    let validator = validator_set
        .validator(&vote.voter)
        .ok_or_else(|| anyhow!("vote equivocation references an unknown validator"))?;
    UnparsedPublicKey::new(&ML_DSA_65, validator.keys.hot_ml_dsa_65_spki.as_slice())
        .verify(&vote.target.signing_bytes(), vote.signature.as_slice())
        .map_err(|_| anyhow!("vote equivocation signature verification failed"))
}

fn validate_enveloped_anchor_proposal(
    author: &EnvelopeAuthor,
    proposal: &AnchorProposal,
    envelope: &SignedEnvelope,
    chain_id: [u8; 32],
) -> Result<()> {
    if envelope.chain_id != Some(chain_id) {
        bail!("proposal equivocation envelope chain id mismatch");
    }
    author.verify_envelope(envelope)?;
    let (topic, body) = decode_topic_frame_like(&envelope.payload)?;
    if topic != TOPIC_ANCHOR_PROPOSAL {
        bail!("proposal equivocation envelope does not carry an anchor proposal");
    }
    let decoded = canonical::decode_anchor_proposal(&body)?;
    if decoded != *proposal {
        bail!("proposal equivocation envelope payload does not match the supplied proposal");
    }
    Ok(())
}

fn validate_enveloped_shared_state_dag_batch(
    author: &EnvelopeAuthor,
    batch: &SharedStateDagBatch,
    envelope: &SignedEnvelope,
    chain_id: [u8; 32],
) -> Result<()> {
    if envelope.chain_id != Some(chain_id) {
        bail!("DAG batch equivocation envelope chain id mismatch");
    }
    author.verify_envelope(envelope)?;
    let (topic, body) = decode_topic_frame_like(&envelope.payload)?;
    if topic != TOPIC_SHARED_STATE_DAG_BATCH {
        bail!("DAG batch equivocation envelope does not carry a DAG batch");
    }
    let decoded = canonical::decode_shared_state_dag_batch(&body)?;
    if decoded != *batch {
        bail!("DAG batch equivocation envelope payload does not match the supplied batch");
    }
    Ok(())
}

fn decode_topic_frame_like(bytes: &[u8]) -> Result<(u8, Vec<u8>)> {
    let mut reader = CanonicalReader::new(bytes);
    let topic = reader.read_u8()?;
    let body = reader.read_bytes()?;
    reader.finish()?;
    Ok((topic, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{OrderingPath, Validator, ValidatorKeys, ValidatorSet},
        crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
        proof::{TransparentProof, TransparentProofStatement},
        transaction::{SharedStateBatch, Tx},
    };
    use tempfile::TempDir;

    fn dummy_proof(statement: TransparentProofStatement, seed: u8) -> TransparentProof {
        TransparentProof::new(statement, vec![seed; 8])
    }

    fn validator_set() -> (ValidatorSet, Vec<Vec<u8>>) {
        let mut hot_spkis = Vec::new();
        let validators = (0..3)
            .map(|index| {
                let hot_key = ml_dsa_65_generate().unwrap();
                let cold_key = ml_dsa_65_generate().unwrap();
                let hot_spki = ml_dsa_65_public_key_spki(&hot_key).unwrap();
                hot_spkis.push(hot_spki.clone());
                Validator::new(
                    5 + index,
                    ValidatorKeys {
                        hot_ml_dsa_65_spki: hot_spki,
                        cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        (ValidatorSet::new(0, validators).unwrap(), hot_spkis)
    }

    fn author(node_seed: u8, auth_spki: Vec<u8>) -> EnvelopeAuthor {
        EnvelopeAuthor {
            node_id: [node_seed; 32],
            auth_spki,
        }
    }

    fn envelope(seed: u8) -> SignedEnvelope {
        SignedEnvelope {
            version: 2,
            protocol_version: crate::protocol::CURRENT.version,
            node_id: [seed; 32],
            chain_id: Some([9u8; 32]),
            issued_unix_ms: 1,
            expires_unix_ms: 2,
            response_to_message_id: None,
            nonce: [seed; 16],
            message_id: [seed.wrapping_add(1); 32],
            payload: vec![seed],
            sig: vec![seed.wrapping_add(2)],
        }
    }

    fn proposal(
        validator_set: &ValidatorSet,
        slot: u32,
        ordering_path: OrderingPath,
        merkle_root: [u8; 32],
        ordered_tx_root: [u8; 32],
    ) -> AnchorProposal {
        AnchorProposal::new(
            slot as u64,
            Some([7u8; 32]),
            ordering_path,
            merkle_root,
            0,
            if ordering_path == OrderingPath::DagBftSharedState {
                1
            } else {
                0
            },
            if ordering_path == OrderingPath::DagBftSharedState {
                vec![[8u8; 32]]
            } else {
                Vec::new()
            },
            if ordering_path == OrderingPath::DagBftSharedState {
                vec![[9u8; 32]]
            } else {
                Vec::new()
            },
            ordered_tx_root,
            if ordering_path == OrderingPath::DagBftSharedState {
                1
            } else {
                0
            },
            validator_set.clone(),
        )
        .unwrap()
    }

    #[test]
    fn proposal_equivocation_is_persisted_once() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let (validator_set, hot_spkis) = validator_set();
        let proposer_author = author(1, hot_spkis[0].clone());
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

        assert!(
            observe_anchor_proposal(&db, &proposer_author, &first, &envelope(1))
                .unwrap()
                .is_none()
        );
        let evidence = observe_anchor_proposal(&db, &proposer_author, &second, &envelope(2))
            .unwrap()
            .expect("proposal equivocation evidence");
        assert!(matches!(
            evidence.evidence,
            ConsensusEvidence::ProposalEquivocation(_)
        ));
        assert_eq!(db.load_consensus_evidence().unwrap().len(), 1);
    }

    #[test]
    fn vote_equivocation_is_persisted_once() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let (validator_set, _) = validator_set();
        let hot_key = ml_dsa_65_generate().unwrap();
        let target = crate::consensus::VoteTarget {
            position: ConsensusPosition { epoch: 0, slot: 1 },
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: [4u8; 32],
        };
        let first = ValidatorVote {
            voter: validator_set.validators[0].id,
            target: target.clone(),
            signature: ml_dsa_65_sign(&hot_key, &target.signing_bytes()).unwrap(),
        };
        let second = ValidatorVote {
            voter: first.voter,
            target: crate::consensus::VoteTarget {
                block_digest: [5u8; 32],
                ..target
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
        let (validator_set, _) = validator_set();
        let author_info = author(
            2,
            validator_set.validators[0].keys.hot_ml_dsa_65_spki.clone(),
        );
        let tx = Tx::new(
            vec![[1u8; 32]],
            Vec::new(),
            0,
            dummy_proof(TransparentProofStatement::ShieldedTransfer, 3),
        );
        let first = SharedStateDagBatch::new(
            0,
            1,
            validator_set.validators[0].id,
            Vec::new(),
            SharedStateBatch::new(vec![tx.clone()]).unwrap(),
        )
        .unwrap();
        let second = SharedStateDagBatch::new(
            0,
            1,
            validator_set.validators[0].id,
            Vec::new(),
            SharedStateBatch::new(vec![Tx::new(
                vec![[2u8; 32]],
                Vec::new(),
                0,
                dummy_proof(TransparentProofStatement::ShieldedTransfer, 4),
            )])
            .unwrap(),
        )
        .unwrap();

        db.store_shared_state_dag_batch(&first).unwrap();
        let key = Store::shared_state_dag_observation_key(first.epoch, first.round, first.author);
        db.store_shared_state_dag_observation(
            &key,
            &StoredSharedStateDagObservation {
                author: author_info.clone(),
                batch_id: first.batch_id,
                envelope: envelope(3),
            },
        )
        .unwrap();

        let evidence = observe_shared_state_dag_batch(&db, &author_info, &second, &envelope(4))
            .unwrap()
            .expect("dag batch equivocation evidence");
        assert!(matches!(
            evidence.evidence,
            ConsensusEvidence::DagBatchEquivocation(_)
        ));
        assert_eq!(db.load_consensus_evidence().unwrap().len(), 1);
    }

    #[test]
    fn liveness_fault_records_missing_qc_voters() {
        let dir = TempDir::new().unwrap();
        let db = Store::open(&dir.path().to_string_lossy()).unwrap();
        let hot_keys = (0..3)
            .map(|_| ml_dsa_65_generate().unwrap())
            .collect::<Vec<_>>();
        let validator_specs = hot_keys
            .iter()
            .zip([2u64, 2, 1])
            .map(|(hot_key, voting_power)| {
                let cold_key = ml_dsa_65_generate().unwrap();
                Validator::new(
                    voting_power,
                    ValidatorKeys {
                        hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(hot_key).unwrap(),
                        cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let validator_set = ValidatorSet::new(0, validator_specs.clone()).unwrap();
        db.store_validator_committee(&validator_set).unwrap();
        for validator in &validator_set.validators {
            db.store_validator_pool(
                &crate::staking::ValidatorPool::new(
                    validator.clone(),
                    validator.id.0,
                    0,
                    validator.voting_power,
                    0,
                    crate::staking::ValidatorStatus::Active,
                    crate::staking::ValidatorMetadata::default(),
                )
                .unwrap(),
            )
            .unwrap();
        }
        let position = ConsensusPosition { epoch: 0, slot: 0 };
        let target = crate::consensus::VoteTarget {
            position,
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: Anchor::compute_hash(
                0,
                None,
                position,
                OrderingPath::FastPathPrivateTransfer,
                [0u8; 32],
                0,
                0,
                &[],
                &[],
                [0u8; 32],
                0,
                &validator_set,
            ),
        };
        let votes = validator_specs[..2]
            .iter()
            .zip(hot_keys[..2].iter())
            .map(|(validator, hot_key)| ValidatorVote {
                voter: validator.id,
                target: target.clone(),
                signature: ml_dsa_65_sign(hot_key, &target.signing_bytes()).unwrap(),
            })
            .collect::<Vec<_>>();
        let qc =
            crate::consensus::QuorumCertificate::from_votes(&validator_set, target, votes).unwrap();
        let anchor = Anchor::new(
            0,
            None,
            OrderingPath::FastPathPrivateTransfer,
            [0u8; 32],
            0,
            0,
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            0,
            validator_set.clone(),
            qc,
        )
        .unwrap();
        db.put("anchor", &anchor.hash, &anchor).unwrap();

        let records = record_anchor_liveness_faults(&db, &anchor).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].validator_id(), validator_specs[2].id);
        assert_eq!(db.load_liveness_fault_records().unwrap().len(), 1);
    }
}
