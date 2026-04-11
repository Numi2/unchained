use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    coin::Coin,
    crypto::{Address, TaggedKemPublicKey, TaggedSigningPublicKey},
};

pub const SHIELDED_NOTE_VERSION: u8 = 1;
pub const SHIELDED_CHECKPOINT_VERSION: u8 = 1;
pub const SHIELDED_EXTENSION_VERSION: u8 = 1;
pub const SHIELDED_ACTIVE_NULLIFIER_VERSION: u8 = 1;

const NOTE_KEY_COMMIT_DOMAIN: &str = "unchained-shielded-note-key-v1";
const OWNER_SIGNING_KEY_COMMIT_DOMAIN: &str = "unchained-shielded-owner-signing-key-v1";
const OWNER_KEM_KEY_COMMIT_DOMAIN: &str = "unchained-shielded-owner-kem-key-v1";
const NOTE_COMMIT_DOMAIN: &str = "unchained-shielded-note-commit-v1";
const NOTE_LEAF_DOMAIN: &str = "unchained-shielded-note-leaf-v1";
const NULLIFIER_DOMAIN: &str = "unchained-shielded-evolving-nullifier-v1";
const NULLIFIER_LEAF_DOMAIN: &str = "unchained-shielded-nullifier-leaf-v1";
const CHECKPOINT_BASE_DOMAIN: &str = "unchained-shielded-checkpoint-base-v1";
const CHECKPOINT_SEGMENT_BASE_DOMAIN: &str = "unchained-shielded-checkpoint-segment-base-v1";
const CHECKPOINT_SERVICE_DOMAIN: &str = "unchained-shielded-checkpoint-service-v1";
const CHECKPOINT_RERANDOMIZE_DOMAIN: &str = "unchained-shielded-checkpoint-rerandomize-v1";
const CHECKPOINT_SEGMENT_COMMIT_DOMAIN: &str = "unchained-shielded-checkpoint-segment-commit-v1";
const CHECKPOINT_PACKET_COMMIT_DOMAIN: &str = "unchained-shielded-checkpoint-packet-commit-v1";
const CHECKPOINT_PACKET_ACCUMULATE_DOMAIN: &str =
    "unchained-shielded-checkpoint-packet-accumulate-v1";
const CHECKPOINT_STRATUM_COMMIT_DOMAIN: &str = "unchained-shielded-checkpoint-stratum-commit-v1";
const CHECKPOINT_STRATUM_ACCUMULATE_DOMAIN: &str =
    "unchained-shielded-checkpoint-stratum-accumulate-v1";
const CHECKPOINT_EXTENSION_ACCUMULATE_DOMAIN: &str = "unchained-shielded-checkpoint-accumulate-v1";
const PRESENTATION_DOMAIN: &str = "unchained-shielded-presentation-v1";
const FINALIZED_HISTORY_SHARD_DOMAIN: &str = "unchained-shielded-finalized-history-shard-v1";
const GENESIS_NOTE_KEY_DOMAIN: &str = "unchained-shielded-genesis-note-key-v1";
const GENESIS_NOTE_RHO_DOMAIN: &str = "unchained-shielded-genesis-note-rho-v1";
const GENESIS_NOTE_RANDOMIZER_DOMAIN: &str = "unchained-shielded-genesis-note-randomizer-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShieldedNoteKind {
    Payment,
    DelegationShare {
        validator_id: [u8; 32],
    },
    UnbondingClaim {
        validator_id: [u8; 32],
        release_epoch: u64,
    },
}

impl ShieldedNoteKind {
    pub fn payment() -> Self {
        Self::Payment
    }

    pub fn is_payment(&self) -> bool {
        matches!(self, Self::Payment)
    }

    pub fn is_delegation_share_for(&self, validator_id: &[u8; 32]) -> bool {
        matches!(
            self,
            Self::DelegationShare {
                validator_id: note_validator_id
            } if note_validator_id == validator_id
        )
    }

    pub fn is_unbonding_claim_for(&self, validator_id: &[u8; 32]) -> bool {
        matches!(
            self,
            Self::UnbondingClaim {
                validator_id: note_validator_id,
                ..
            } if note_validator_id == validator_id
        )
    }

    pub fn unbonding_release_epoch(&self) -> Option<u64> {
        match self {
            Self::UnbondingClaim { release_epoch, .. } => Some(*release_epoch),
            _ => None,
        }
    }

    fn commitment_bytes(&self) -> [u8; 41] {
        let mut out = [0u8; 41];
        match self {
            Self::Payment => {
                out[0] = 0;
            }
            Self::DelegationShare { validator_id } => {
                out[0] = 1;
                out[1..33].copy_from_slice(validator_id);
            }
            Self::UnbondingClaim {
                validator_id,
                release_epoch,
            } => {
                out[0] = 2;
                out[1..33].copy_from_slice(validator_id);
                out[33..41].copy_from_slice(&release_epoch.to_le_bytes());
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedNote {
    pub version: u8,
    pub kind: ShieldedNoteKind,
    pub value: u64,
    pub birth_epoch: u64,
    pub owner_address: Address,
    pub owner_signing_key_commitment: [u8; 32],
    pub owner_kem_key_commitment: [u8; 32],
    pub owner_signing_pk: TaggedSigningPublicKey,
    pub owner_kem_pk: TaggedKemPublicKey,
    pub rho: [u8; 32],
    pub note_randomizer: [u8; 32],
    pub note_key_commitment: [u8; 32],
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoteMembershipProof {
    pub note_commitment: [u8; 32],
    pub root: [u8; 32],
    pub proof: Vec<([u8; 32], bool)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierMembershipWitness {
    pub nullifier: [u8; 32],
    pub root: [u8; 32],
    pub proof: Vec<([u8; 32], bool)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierNonMembershipProof {
    pub epoch: u64,
    pub queried_nullifier: [u8; 32],
    pub root: [u8; 32],
    pub set_size: u32,
    pub predecessor: Option<NullifierMembershipWitness>,
    pub successor: Option<NullifierMembershipWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalNullifierWindow {
    pub epoch: u64,
    pub nullifiers: Vec<[u8; 32]>,
    pub levels: Vec<Vec<[u8; 32]>>,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NoteCommitmentTree {
    pub commitments: Vec<[u8; 32]>,
    pub levels: Vec<Vec<[u8; 32]>>,
    positions: BTreeMap<[u8; 32], u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NullifierRootLedger {
    pub roots: BTreeMap<u64, [u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvolvingNullifierQuery {
    pub epoch: u64,
    pub nullifier: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalAbsenceRecord {
    pub epoch: u64,
    pub nullifier: [u8; 32],
    pub proof: NullifierNonMembershipProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentCheckpoint {
    pub version: u8,
    pub note_commitment: [u8; 32],
    pub birth_epoch: u64,
    pub covered_through_epoch: u64,
    pub transcript_root: [u8; 32],
    pub verified_epoch_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentServiceResponse {
    pub version: u8,
    pub request_binding: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub segment_service_root: [u8; 32],
    pub segment_historical_root_digest: [u8; 32],
    pub records: Vec<HistoricalAbsenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentSegment {
    pub request_binding: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub segment_service_root: [u8; 32],
    pub segment_historical_root_digest: [u8; 32],
    pub rerandomization_blinding: [u8; 32],
    pub segment_transcript_root: [u8; 32],
    pub records: Vec<HistoricalAbsenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentPacket {
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub packet_historical_root_digest: [u8; 32],
    pub segment_commitment_root: [u8; 32],
    pub packet_rerandomization_blinding: [u8; 32],
    pub packet_transcript_root: [u8; 32],
    pub segments: Vec<HistoricalUnspentSegment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentStratum {
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub stratum_historical_root_digest: [u8; 32],
    pub packet_commitment_root: [u8; 32],
    pub stratum_rerandomization_blinding: [u8; 32],
    pub stratum_transcript_root: [u8; 32],
    pub packets: Vec<HistoricalUnspentPacket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentExtension {
    pub version: u8,
    pub note_commitment: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub prior_transcript_root: [u8; 32],
    pub historical_root_digest: [u8; 32],
    pub stratum_commitment_root: [u8; 32],
    pub aggregate_rerandomization_blinding: [u8; 32],
    pub new_transcript_root: [u8; 32],
    pub strata: Vec<HistoricalUnspentStratum>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPresentation {
    pub covered_through_epoch: u64,
    pub blinding: [u8; 32],
    pub presentation_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveNullifierEpoch {
    pub version: u8,
    pub epoch: u64,
    pub nullifiers: BTreeSet<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedHistoryShard {
    pub shard_id: u64,
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub root_digest: [u8; 32],
    pub epoch_roots: Vec<(u64, [u8; 32])>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FinalizedHistoryDirectory {
    pub shard_span: u64,
    pub shards: Vec<FinalizedHistoryShard>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedSpendContext {
    pub note_commitment: [u8; 32],
    pub current_epoch: u64,
    pub current_nullifier: [u8; 32],
    pub historical_checkpoint_root: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct ShieldedSyncServer {
    epochs: BTreeMap<u64, HistoricalNullifierWindow>,
    ledger: NullifierRootLedger,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointExtensionRequest {
    pub checkpoint: Option<HistoricalUnspentCheckpoint>,
    pub presentation: CheckpointPresentation,
    pub queries: Vec<EvolvingNullifierQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointBatchRequest {
    pub requests: Vec<CheckpointExtensionRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointBatchResponse {
    pub responses: Vec<HistoricalUnspentServiceResponse>,
}

impl ShieldedNote {
    pub fn new(
        value: u64,
        birth_epoch: u64,
        owner_signing_pk: TaggedSigningPublicKey,
        owner_kem_pk: TaggedKemPublicKey,
        note_key: [u8; 32],
        rho: [u8; 32],
        note_randomizer: [u8; 32],
    ) -> Self {
        Self::new_with_kind(
            ShieldedNoteKind::Payment,
            value,
            birth_epoch,
            owner_signing_pk,
            owner_kem_pk,
            note_key,
            rho,
            note_randomizer,
        )
    }

    pub fn new_with_kind(
        kind: ShieldedNoteKind,
        value: u64,
        birth_epoch: u64,
        owner_signing_pk: TaggedSigningPublicKey,
        owner_kem_pk: TaggedKemPublicKey,
        note_key: [u8; 32],
        rho: [u8; 32],
        note_randomizer: [u8; 32],
    ) -> Self {
        let owner_address = owner_signing_pk.address();
        let owner_signing_key_commitment = owner_signing_key_commitment(&owner_signing_pk);
        let owner_kem_key_commitment = owner_kem_key_commitment(&owner_kem_pk);
        let note_key_commitment = note_key_commitment(&note_key);
        let commitment = compute_note_commitment(
            SHIELDED_NOTE_VERSION,
            &kind,
            value,
            birth_epoch,
            &owner_address,
            &owner_signing_key_commitment,
            &owner_kem_key_commitment,
            &rho,
            &note_randomizer,
            &note_key_commitment,
        );
        Self {
            version: SHIELDED_NOTE_VERSION,
            kind,
            value,
            birth_epoch,
            owner_address,
            owner_signing_key_commitment,
            owner_kem_key_commitment,
            owner_signing_pk,
            owner_kem_pk,
            rho,
            note_randomizer,
            note_key_commitment,
            commitment,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != SHIELDED_NOTE_VERSION {
            bail!("unsupported shielded note version {}", self.version);
        }
        if self.owner_signing_pk.address() != self.owner_address {
            bail!("shielded note owner address does not match signing key");
        }
        if owner_signing_key_commitment(&self.owner_signing_pk) != self.owner_signing_key_commitment
        {
            bail!("shielded note owner signing key commitment mismatch");
        }
        if owner_kem_key_commitment(&self.owner_kem_pk) != self.owner_kem_key_commitment {
            bail!("shielded note owner KEM key commitment mismatch");
        }
        let expected = compute_note_commitment(
            self.version,
            &self.kind,
            self.value,
            self.birth_epoch,
            &self.owner_address,
            &self.owner_signing_key_commitment,
            &self.owner_kem_key_commitment,
            &self.rho,
            &self.note_randomizer,
            &self.note_key_commitment,
        );
        if expected != self.commitment {
            bail!("shielded note commitment mismatch");
        }
        Ok(())
    }

    pub fn derive_evolving_nullifier(
        &self,
        note_key: &[u8; 32],
        chain_id: &[u8; 32],
        epoch: u64,
    ) -> Result<[u8; 32]> {
        self.validate()?;
        if note_key_commitment(note_key) != self.note_key_commitment {
            bail!("note key does not match note key commitment");
        }
        if epoch < self.birth_epoch {
            bail!("cannot derive an evolving nullifier before the note birth epoch");
        }
        Ok(evolving_nullifier(note_key, &self.rho, chain_id, epoch))
    }

    pub fn spend_context(
        &self,
        note_key: &[u8; 32],
        chain_id: &[u8; 32],
        current_epoch: u64,
        checkpoint: &HistoricalUnspentCheckpoint,
    ) -> Result<ShieldedSpendContext> {
        if checkpoint.note_commitment != self.commitment {
            bail!("checkpoint note commitment does not match shielded note");
        }
        if checkpoint.covered_through_epoch.saturating_add(1) < current_epoch {
            bail!("historical checkpoint is stale for the requested spend epoch");
        }
        Ok(ShieldedSpendContext {
            note_commitment: self.commitment,
            current_epoch,
            current_nullifier: self.derive_evolving_nullifier(note_key, chain_id, current_epoch)?,
            historical_checkpoint_root: checkpoint.transcript_root,
        })
    }
}

impl NoteCommitmentTree {
    pub fn new() -> Self {
        Self {
            commitments: Vec::new(),
            levels: Vec::new(),
            positions: BTreeMap::new(),
        }
    }

    pub fn from_parts(commitments: Vec<[u8; 32]>, levels: Vec<Vec<[u8; 32]>>) -> Result<Self> {
        validate_leaf_levels(
            &commitments
                .iter()
                .map(note_leaf_hash)
                .collect::<Vec<[u8; 32]>>(),
            &levels,
        )?;
        let mut positions = BTreeMap::new();
        for (index, commitment) in commitments.iter().enumerate() {
            if positions
                .insert(*commitment, u32::try_from(index).unwrap_or(u32::MAX))
                .is_some()
            {
                bail!("duplicate note commitment inside note tree");
            }
        }
        Ok(Self {
            commitments,
            levels,
            positions,
        })
    }

    pub fn append(&mut self, commitment: [u8; 32]) -> Result<()> {
        if self.positions.contains_key(&commitment) {
            bail!("duplicate note commitment");
        }
        let index =
            u32::try_from(self.commitments.len()).map_err(|_| anyhow!("note tree too large"))?;
        self.commitments.push(commitment);
        self.positions.insert(commitment, index);
        push_merkle_leaf(&mut self.levels, note_leaf_hash(&commitment));
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        merkle_root_from_levels(&self.levels)
    }

    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    pub fn contains_commitment(&self, note_commitment: &[u8; 32]) -> bool {
        self.positions.contains_key(note_commitment)
    }

    pub fn prove_membership(&self, note_commitment: &[u8; 32]) -> Option<NoteMembershipProof> {
        let index = usize::try_from(*self.positions.get(note_commitment)?).ok()?;
        let proof = merkle_proof_from_levels(&self.levels, index)?;
        Some(NoteMembershipProof {
            note_commitment: *note_commitment,
            root: merkle_root_from_levels(&self.levels),
            proof,
        })
    }
}

impl NoteMembershipProof {
    pub fn verify(&self) -> bool {
        verify_merkle_proof(
            &note_leaf_hash(&self.note_commitment),
            &self.proof,
            &self.root,
        )
    }
}

impl HistoricalNullifierWindow {
    pub fn new(epoch: u64, nullifiers: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let nullifiers = nullifiers
            .into_iter()
            .collect::<BTreeSet<[u8; 32]>>()
            .into_iter()
            .collect::<Vec<_>>();
        let levels = build_merkle_levels(
            &nullifiers
                .iter()
                .map(nullifier_leaf_hash)
                .collect::<Vec<[u8; 32]>>(),
        );
        let root = merkle_root_from_levels(&levels);
        Self {
            epoch,
            nullifiers,
            levels,
            root,
        }
    }

    pub fn from_parts(
        epoch: u64,
        nullifiers: Vec<[u8; 32]>,
        levels: Vec<Vec<[u8; 32]>>,
        root: [u8; 32],
    ) -> Result<Self> {
        if nullifiers.windows(2).any(|pair| pair[0] >= pair[1]) {
            bail!("historical nullifier window must stay strictly sorted and deduplicated");
        }
        validate_leaf_levels(
            &nullifiers
                .iter()
                .map(nullifier_leaf_hash)
                .collect::<Vec<[u8; 32]>>(),
            &levels,
        )?;
        if merkle_root_from_levels(&levels) != root {
            bail!("historical nullifier window root mismatch");
        }
        Ok(Self {
            epoch,
            nullifiers,
            levels,
            root,
        })
    }

    pub fn contains(&self, queried_nullifier: &[u8; 32]) -> bool {
        self.nullifiers.binary_search(queried_nullifier).is_ok()
    }

    pub fn validate(&self) -> Result<()> {
        Self::from_parts(
            self.epoch,
            self.nullifiers.clone(),
            self.levels.clone(),
            self.root,
        )?;
        Ok(())
    }

    pub fn prove_absence(
        &self,
        queried_nullifier: [u8; 32],
    ) -> Result<NullifierNonMembershipProof> {
        if self.contains(&queried_nullifier) {
            bail!("queried nullifier is present in epoch {}", self.epoch);
        }
        let predecessor_index = self
            .nullifiers
            .partition_point(|value| value < &queried_nullifier);
        let predecessor = predecessor_index
            .checked_sub(1)
            .and_then(|index| self.membership_witness(index));
        let successor = self.membership_witness(predecessor_index);
        let proof = NullifierNonMembershipProof {
            epoch: self.epoch,
            queried_nullifier,
            root: self.root,
            set_size: self.nullifiers.len() as u32,
            predecessor,
            successor,
        };
        proof.verify()?;
        Ok(proof)
    }

    fn membership_witness(&self, index: usize) -> Option<NullifierMembershipWitness> {
        let nullifier = *self.nullifiers.get(index)?;
        let proof = merkle_proof_from_levels(&self.levels, index)?;
        Some(NullifierMembershipWitness {
            nullifier,
            root: self.root,
            proof,
        })
    }
}

impl NullifierMembershipWitness {
    pub fn verify(&self) -> bool {
        verify_merkle_proof(
            &nullifier_leaf_hash(&self.nullifier),
            &self.proof,
            &self.root,
        )
    }
}

impl NullifierNonMembershipProof {
    pub fn verify(&self) -> Result<()> {
        if self.set_size == 0 {
            if self.root != [0u8; 32] {
                bail!("empty nullifier set must use the zero root");
            }
            if self.predecessor.is_some() || self.successor.is_some() {
                bail!("empty nullifier set must not include predecessor or successor witnesses");
            }
            return Ok(());
        }

        let predecessor = self.predecessor.as_ref();
        let successor = self.successor.as_ref();
        if predecessor.is_none() && successor.is_none() {
            bail!("non-empty nullifier set must include at least one boundary witness");
        }

        if let Some(predecessor) = predecessor {
            if predecessor.root != self.root || !predecessor.verify() {
                bail!("invalid predecessor witness");
            }
            if predecessor.nullifier >= self.queried_nullifier {
                bail!("predecessor witness is not strictly below the queried nullifier");
            }
        }
        if let Some(successor) = successor {
            if successor.root != self.root || !successor.verify() {
                bail!("invalid successor witness");
            }
            if successor.nullifier <= self.queried_nullifier {
                bail!("successor witness is not strictly above the queried nullifier");
            }
        }
        if let (Some(predecessor), Some(successor)) = (predecessor, successor) {
            if predecessor.nullifier >= successor.nullifier {
                bail!("predecessor witness must sort before successor witness");
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> [u8; 32] {
        let predecessor_digest = self
            .predecessor
            .as_ref()
            .map(|witness| {
                proof_core::nullifier_membership_witness_digest(
                    &witness.nullifier,
                    &witness.root,
                    &witness.proof,
                )
            })
            .unwrap_or([0u8; 32]);
        let successor_digest = self
            .successor
            .as_ref()
            .map(|witness| {
                proof_core::nullifier_membership_witness_digest(
                    &witness.nullifier,
                    &witness.root,
                    &witness.proof,
                )
            })
            .unwrap_or([0u8; 32]);
        proof_core::proof_hash_domain_parts(
            "unchained-shielded-absence-proof-v1",
            &[
                &self.epoch.to_le_bytes(),
                self.queried_nullifier.as_slice(),
                self.root.as_slice(),
                &self.set_size.to_le_bytes(),
                &[u8::from(self.predecessor.is_some())],
                predecessor_digest.as_slice(),
                &[u8::from(self.successor.is_some())],
                successor_digest.as_slice(),
            ],
        )
    }
}

impl NullifierRootLedger {
    pub fn root_for_epoch(&self, epoch: u64) -> Result<[u8; 32]> {
        self.roots
            .get(&epoch)
            .copied()
            .ok_or_else(|| anyhow!("missing historical nullifier root for epoch {}", epoch))
    }

    pub fn remember_epoch(&mut self, window: &HistoricalNullifierWindow) {
        self.roots.insert(window.epoch, window.root);
    }
}

impl HistoricalUnspentCheckpoint {
    pub fn genesis(note_commitment: [u8; 32], birth_epoch: u64) -> Self {
        let covered_through_epoch = birth_epoch.saturating_sub(1);
        Self {
            version: SHIELDED_CHECKPOINT_VERSION,
            note_commitment,
            birth_epoch,
            covered_through_epoch,
            transcript_root: checkpoint_base_root(&note_commitment, birth_epoch),
            verified_epoch_count: 0,
        }
    }

    pub fn presentation(&self, blinding: [u8; 32]) -> CheckpointPresentation {
        CheckpointPresentation::for_checkpoint(self, blinding)
    }

    pub fn empty_extension(&self) -> HistoricalUnspentExtension {
        HistoricalUnspentExtension {
            version: SHIELDED_EXTENSION_VERSION,
            note_commitment: self.note_commitment,
            from_epoch: self.covered_through_epoch.saturating_add(1),
            through_epoch: self.covered_through_epoch,
            prior_transcript_root: self.transcript_root,
            historical_root_digest: proof_core::historical_root_digest_from_pairs(&[]),
            stratum_commitment_root: [0u8; 32],
            aggregate_rerandomization_blinding: [0u8; 32],
            new_transcript_root: self.transcript_root,
            strata: Vec::new(),
        }
    }

    pub fn apply_accumulator(
        &self,
        accumulator: &proof_core::CheckpointAccumulatorJournal,
        ledger: &NullifierRootLedger,
    ) -> Result<Self> {
        if self.version != SHIELDED_CHECKPOINT_VERSION {
            bail!("unsupported checkpoint version {}", self.version);
        }
        if accumulator.note_commitment != self.note_commitment {
            bail!("checkpoint accumulator note mismatch");
        }
        if accumulator.birth_epoch != self.birth_epoch {
            bail!("checkpoint accumulator birth epoch mismatch");
        }
        if accumulator.covered_through_epoch < self.covered_through_epoch {
            bail!("checkpoint accumulator regresses the covered epoch");
        }

        let expected_historical_root_digest =
            if accumulator.covered_through_epoch < self.birth_epoch {
                proof_core::checkpoint_accumulator_historical_digest_from_pairs(&[])
            } else {
                let mut pairs = Vec::new();
                for epoch in self.birth_epoch..=accumulator.covered_through_epoch {
                    pairs.push((epoch, ledger.root_for_epoch(epoch)?));
                }
                proof_core::checkpoint_accumulator_historical_digest_from_pairs(&pairs)
            };
        if accumulator.historical_root_digest != expected_historical_root_digest {
            bail!("checkpoint accumulator historical root digest mismatch");
        }
        let expected_root = proof_core::checkpoint_accumulator_root(
            &self.note_commitment,
            self.birth_epoch,
            accumulator.covered_through_epoch,
            &accumulator.historical_root_digest,
            &accumulator.stratum_commitment_root,
        );
        if accumulator.checkpoint_root != expected_root {
            bail!("checkpoint accumulator root mismatch");
        }

        Ok(Self {
            version: self.version,
            note_commitment: self.note_commitment,
            birth_epoch: self.birth_epoch,
            covered_through_epoch: accumulator.covered_through_epoch,
            transcript_root: accumulator.checkpoint_root,
            verified_epoch_count: accumulator.verified_epoch_count,
        })
    }

    pub fn apply_extension(
        &self,
        extension: &HistoricalUnspentExtension,
        ledger: &NullifierRootLedger,
    ) -> Result<Self> {
        if self.version != SHIELDED_CHECKPOINT_VERSION {
            bail!("unsupported checkpoint version {}", self.version);
        }
        if extension.version != SHIELDED_EXTENSION_VERSION {
            bail!("unsupported extension version {}", extension.version);
        }
        if self.note_commitment != extension.note_commitment {
            bail!("extension note commitment mismatch");
        }
        if self.transcript_root != extension.prior_transcript_root {
            bail!("extension prior transcript root mismatch");
        }

        let expected_from = self.covered_through_epoch.saturating_add(1);
        if extension.strata.is_empty() {
            if extension.from_epoch != expected_from {
                bail!("empty extension starts at the wrong epoch");
            }
            if extension.through_epoch != self.covered_through_epoch {
                bail!("empty extension cannot advance the checkpoint range");
            }
            if extension.new_transcript_root != self.transcript_root {
                bail!("empty extension must preserve the transcript root");
            }
            if extension.stratum_commitment_root != [0u8; 32] {
                bail!("empty extension must use the zero stratum commitment root");
            }
            return Ok(self.clone());
        }

        if extension.from_epoch != expected_from {
            bail!("extension does not continue from the prior checkpoint");
        }

        let mut expected_epoch = extension.from_epoch;
        let mut historical_roots = Vec::new();
        let mut stratum_digests = Vec::with_capacity(extension.strata.len());
        for stratum in &extension.strata {
            stratum.verify_against_note(&self.note_commitment)?;
            if stratum.packets.is_empty() {
                bail!("historical extension strata cannot be empty");
            }
            if stratum.from_epoch != expected_epoch {
                bail!("historical extension strata must be contiguous");
            }
            let mut stratum_pairs = Vec::new();
            for packet in &stratum.packets {
                for segment in &packet.segments {
                    if segment.from_epoch != expected_epoch {
                        bail!("historical extension segments must stay contiguous inside strata");
                    }
                    for record in &segment.records {
                        if record.epoch != expected_epoch {
                            bail!(
                                "extension epochs must stay contiguous across segment boundaries"
                            );
                        }
                        if record.nullifier != record.proof.queried_nullifier {
                            bail!("extension record nullifier does not match the proof");
                        }
                        let root = ledger.root_for_epoch(record.epoch)?;
                        if root != record.proof.root {
                            bail!("extension proof root does not match the historical root ledger");
                        }
                        record.proof.verify()?;
                        stratum_pairs.push((record.epoch, root));
                        historical_roots.push((record.epoch, root));
                        expected_epoch = expected_epoch.saturating_add(1);
                    }
                }
            }
            let expected_stratum_digest =
                proof_core::historical_root_digest_from_pairs(&stratum_pairs);
            if stratum.stratum_historical_root_digest != expected_stratum_digest {
                bail!("stratum historical root digest mismatch");
            }
            stratum_digests.push(stratum.commitment_digest());
        }

        if extension.through_epoch != expected_epoch.saturating_sub(1) {
            bail!("extension through_epoch does not match the proof payload");
        }
        let expected_historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_roots);
        if extension.historical_root_digest != expected_historical_root_digest {
            bail!("extension historical root digest mismatch");
        }
        let expected_stratum_commitment_root = checkpoint_stratum_commitment_root(&stratum_digests);
        if extension.stratum_commitment_root != expected_stratum_commitment_root {
            bail!("extension stratum commitment root mismatch");
        }
        let rerandomized_root = accumulated_checkpoint_root(
            &self.transcript_root,
            &self.note_commitment,
            extension.from_epoch,
            extension.through_epoch,
            &extension.historical_root_digest,
            &extension.stratum_commitment_root,
            &extension.aggregate_rerandomization_blinding,
        );
        if extension.new_transcript_root != rerandomized_root {
            bail!("extension transcript root mismatch");
        }

        let additional = u32::try_from(historical_roots.len())
            .map_err(|_| anyhow!("too many extension records"))?;
        Ok(Self {
            version: self.version,
            note_commitment: self.note_commitment,
            birth_epoch: self.birth_epoch,
            covered_through_epoch: extension.through_epoch,
            transcript_root: rerandomized_root,
            verified_epoch_count: self.verified_epoch_count.saturating_add(additional),
        })
    }
}

impl CheckpointExtensionRequest {
    pub fn new(
        checkpoint: HistoricalUnspentCheckpoint,
        queries: Vec<EvolvingNullifierQuery>,
        blinding: [u8; 32],
    ) -> Self {
        let presentation = checkpoint.presentation(blinding);
        Self {
            checkpoint: Some(checkpoint),
            presentation,
            queries,
        }
    }

    pub fn with_random_blinding(
        checkpoint: HistoricalUnspentCheckpoint,
        queries: Vec<EvolvingNullifierQuery>,
    ) -> Self {
        let mut blinding = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut blinding);
        Self::new(checkpoint, queries, blinding)
    }

    pub fn wire_only(
        presentation: CheckpointPresentation,
        queries: Vec<EvolvingNullifierQuery>,
    ) -> Self {
        Self {
            checkpoint: None,
            presentation,
            queries,
        }
    }

    pub fn local_checkpoint(&self) -> Result<&HistoricalUnspentCheckpoint> {
        self.checkpoint
            .as_ref()
            .ok_or_else(|| anyhow!("checkpoint request is missing local checkpoint context"))
    }

    pub fn from_epoch(&self) -> u64 {
        self.presentation.covered_through_epoch.saturating_add(1)
    }

    pub fn request_binding(&self) -> [u8; 32] {
        self.presentation.presentation_digest
    }

    pub fn derive_segment_request(
        &self,
        segment_queries: Vec<EvolvingNullifierQuery>,
        segment_index: u32,
    ) -> Result<Self> {
        let from_epoch = segment_queries
            .first()
            .map(|query| query.epoch)
            .ok_or_else(|| anyhow!("segment request cannot be empty"))?;
        let through_epoch = segment_queries
            .last()
            .map(|query| query.epoch)
            .ok_or_else(|| anyhow!("segment request cannot be empty"))?;
        Ok(Self::wire_only(
            self.presentation.derive_segment(
                from_epoch.saturating_sub(1),
                from_epoch,
                through_epoch,
                segment_index,
            ),
            segment_queries,
        ))
    }
}

impl HistoricalUnspentServiceResponse {
    pub fn rerandomize(&self, blinding: [u8; 32]) -> HistoricalUnspentSegment {
        HistoricalUnspentSegment {
            request_binding: self.request_binding,
            from_epoch: self.from_epoch,
            through_epoch: self.through_epoch,
            segment_service_root: self.segment_service_root,
            segment_historical_root_digest: self.segment_historical_root_digest,
            rerandomization_blinding: blinding,
            segment_transcript_root: rerandomized_segment_root(
                &self.segment_service_root,
                &self.segment_historical_root_digest,
                &blinding,
            ),
            records: self.records.clone(),
        }
    }

    pub fn verify_against_request_local(
        &self,
        request: &CheckpointExtensionRequest,
    ) -> Result<()> {
        if self.request_binding != request.request_binding() {
            bail!("service response request binding mismatch");
        }
        if self.from_epoch != request.from_epoch() {
            bail!("service response starts at the wrong epoch");
        }
        if self.records.len() != request.queries.len() {
            bail!("service response length does not match the request");
        }
        let expected_through_epoch = request
            .queries
            .last()
            .map(|query| query.epoch)
            .ok_or_else(|| anyhow!("checkpoint request is missing the terminal epoch"))?;
        if self.through_epoch != expected_through_epoch {
            bail!("service response ends at the wrong epoch");
        }
        let roots = self
            .records
            .iter()
            .map(|record| (record.epoch, record.proof.root))
            .collect::<Vec<_>>();
        if self.segment_historical_root_digest != proof_core::historical_root_digest_from_pairs(&roots)
        {
            bail!("service response historical root digest mismatch");
        }
        let expected_service_root =
            checkpoint_segment_service_root(&self.request_binding, self.from_epoch, &self.records)?;
        if self.segment_service_root != expected_service_root {
            bail!("service response segment transcript root mismatch");
        }
        Ok(())
    }
}

impl HistoricalUnspentSegment {
    pub fn verify(&self) -> Result<()> {
        if self.records.is_empty() {
            bail!("historical segment cannot be empty");
        }
        if self.records.last().map(|record| record.epoch) != Some(self.through_epoch) {
            bail!("historical segment through_epoch does not match the final record");
        }
        let expected_service_root =
            checkpoint_segment_service_root(&self.request_binding, self.from_epoch, &self.records)?;
        if self.segment_service_root != expected_service_root {
            bail!("historical segment service root mismatch");
        }
        let expected_segment_root = rerandomized_segment_root(
            &self.segment_service_root,
            &self.segment_historical_root_digest,
            &self.rerandomization_blinding,
        );
        if self.segment_transcript_root != expected_segment_root {
            bail!("historical segment transcript root mismatch");
        }
        Ok(())
    }

    pub fn commitment_digest(&self) -> [u8; 32] {
        checkpoint_segment_commitment_digest(
            self.from_epoch,
            self.through_epoch,
            &self.segment_historical_root_digest,
            &self.segment_transcript_root,
            self.records.len() as u32,
        )
    }
}

impl HistoricalUnspentPacket {
    pub fn aggregate(
        note_commitment: &[u8; 32],
        mut segments: Vec<HistoricalUnspentSegment>,
        blinding: [u8; 32],
    ) -> Result<Self> {
        if segments.is_empty() {
            bail!("historical packets cannot be empty");
        }
        segments.sort_by_key(|segment| (segment.from_epoch, segment.through_epoch));
        let from_epoch = segments[0].from_epoch;
        let mut expected_epoch = from_epoch;
        let mut historical_pairs = Vec::new();
        let mut segment_digests = Vec::with_capacity(segments.len());
        for segment in &segments {
            if segment.from_epoch != expected_epoch {
                bail!("historical packet segments must stay contiguous");
            }
            segment.verify()?;
            for record in &segment.records {
                if record.epoch != expected_epoch {
                    bail!("historical packet records must remain contiguous");
                }
                if record.nullifier != record.proof.queried_nullifier {
                    bail!("historical packet record nullifier mismatch");
                }
                historical_pairs.push((record.epoch, record.proof.root));
                expected_epoch = expected_epoch.saturating_add(1);
            }
            segment_digests.push(segment.commitment_digest());
        }
        let through_epoch = expected_epoch.saturating_sub(1);
        let packet_historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_pairs);
        let segment_commitment_root = checkpoint_segment_commitment_root(&segment_digests);
        let packet_transcript_root = accumulated_packet_root(
            note_commitment,
            from_epoch,
            through_epoch,
            &packet_historical_root_digest,
            &segment_commitment_root,
            &blinding,
        );
        Ok(Self {
            from_epoch,
            through_epoch,
            packet_historical_root_digest,
            segment_commitment_root,
            packet_rerandomization_blinding: blinding,
            packet_transcript_root,
            segments,
        })
    }

    pub fn verify_against_note(&self, note_commitment: &[u8; 32]) -> Result<()> {
        if self.segments.is_empty() {
            bail!("historical packet cannot be empty");
        }
        let mut expected_epoch = self.from_epoch;
        let mut historical_pairs = Vec::new();
        let mut segment_digests = Vec::with_capacity(self.segments.len());
        for segment in &self.segments {
            if segment.from_epoch != expected_epoch {
                bail!("historical packet segments must stay contiguous");
            }
            segment.verify()?;
            for record in &segment.records {
                if record.epoch != expected_epoch {
                    bail!("historical packet records must remain contiguous");
                }
                historical_pairs.push((record.epoch, record.proof.root));
                expected_epoch = expected_epoch.saturating_add(1);
            }
            segment_digests.push(segment.commitment_digest());
        }
        if self.through_epoch != expected_epoch.saturating_sub(1) {
            bail!("historical packet through_epoch does not match the final record");
        }
        let expected_historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_pairs);
        if self.packet_historical_root_digest != expected_historical_root_digest {
            bail!("historical packet root digest mismatch");
        }
        let expected_segment_commitment_root = checkpoint_segment_commitment_root(&segment_digests);
        if self.segment_commitment_root != expected_segment_commitment_root {
            bail!("historical packet segment commitment root mismatch");
        }
        let expected_packet_root = accumulated_packet_root(
            note_commitment,
            self.from_epoch,
            self.through_epoch,
            &self.packet_historical_root_digest,
            &self.segment_commitment_root,
            &self.packet_rerandomization_blinding,
        );
        if self.packet_transcript_root != expected_packet_root {
            bail!("historical packet transcript root mismatch");
        }
        Ok(())
    }

    pub fn commitment_digest(&self) -> [u8; 32] {
        checkpoint_packet_commitment_digest(
            self.from_epoch,
            self.through_epoch,
            &self.packet_historical_root_digest,
            &self.segment_commitment_root,
            &self.packet_transcript_root,
            self.segments.len() as u32,
        )
    }
}

impl HistoricalUnspentStratum {
    pub fn aggregate(
        note_commitment: &[u8; 32],
        mut packets: Vec<HistoricalUnspentPacket>,
        blinding: [u8; 32],
    ) -> Result<Self> {
        if packets.is_empty() {
            bail!("historical strata cannot be empty");
        }
        packets.sort_by_key(|packet| (packet.from_epoch, packet.through_epoch));
        let from_epoch = packets[0].from_epoch;
        let mut expected_epoch = from_epoch;
        let mut historical_pairs = Vec::new();
        let mut packet_digests = Vec::with_capacity(packets.len());
        for packet in &packets {
            if packet.from_epoch != expected_epoch {
                bail!("historical stratum packets must stay contiguous");
            }
            packet.verify_against_note(note_commitment)?;
            for segment in &packet.segments {
                for record in &segment.records {
                    if record.epoch != expected_epoch {
                        bail!("historical stratum records must remain contiguous");
                    }
                    historical_pairs.push((record.epoch, record.proof.root));
                    expected_epoch = expected_epoch.saturating_add(1);
                }
            }
            packet_digests.push(packet.commitment_digest());
        }
        let through_epoch = expected_epoch.saturating_sub(1);
        let stratum_historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_pairs);
        let packet_commitment_root = checkpoint_packet_commitment_root(&packet_digests);
        let stratum_transcript_root = accumulated_stratum_root(
            note_commitment,
            from_epoch,
            through_epoch,
            &stratum_historical_root_digest,
            &packet_commitment_root,
            &blinding,
        );
        Ok(Self {
            from_epoch,
            through_epoch,
            stratum_historical_root_digest,
            packet_commitment_root,
            stratum_rerandomization_blinding: blinding,
            stratum_transcript_root,
            packets,
        })
    }

    pub fn verify_against_note(&self, note_commitment: &[u8; 32]) -> Result<()> {
        if self.packets.is_empty() {
            bail!("historical stratum cannot be empty");
        }
        let mut expected_epoch = self.from_epoch;
        let mut historical_pairs = Vec::new();
        let mut packet_digests = Vec::with_capacity(self.packets.len());
        for packet in &self.packets {
            if packet.from_epoch != expected_epoch {
                bail!("historical stratum packets must stay contiguous");
            }
            packet.verify_against_note(note_commitment)?;
            for segment in &packet.segments {
                for record in &segment.records {
                    if record.epoch != expected_epoch {
                        bail!("historical stratum records must remain contiguous");
                    }
                    historical_pairs.push((record.epoch, record.proof.root));
                    expected_epoch = expected_epoch.saturating_add(1);
                }
            }
            packet_digests.push(packet.commitment_digest());
        }
        if self.through_epoch != expected_epoch.saturating_sub(1) {
            bail!("historical stratum through_epoch does not match the final record");
        }
        let expected_historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_pairs);
        if self.stratum_historical_root_digest != expected_historical_root_digest {
            bail!("historical stratum root digest mismatch");
        }
        let expected_packet_commitment_root = checkpoint_packet_commitment_root(&packet_digests);
        if self.packet_commitment_root != expected_packet_commitment_root {
            bail!("historical stratum packet commitment root mismatch");
        }
        let expected_stratum_root = accumulated_stratum_root(
            note_commitment,
            self.from_epoch,
            self.through_epoch,
            &self.stratum_historical_root_digest,
            &self.packet_commitment_root,
            &self.stratum_rerandomization_blinding,
        );
        if self.stratum_transcript_root != expected_stratum_root {
            bail!("historical stratum transcript root mismatch");
        }
        Ok(())
    }

    pub fn commitment_digest(&self) -> [u8; 32] {
        checkpoint_stratum_commitment_digest(
            self.from_epoch,
            self.through_epoch,
            &self.stratum_historical_root_digest,
            &self.packet_commitment_root,
            &self.stratum_transcript_root,
            self.packets.len() as u32,
        )
    }
}

impl HistoricalUnspentExtension {
    pub fn aggregate(
        checkpoint: &HistoricalUnspentCheckpoint,
        mut segments: Vec<HistoricalUnspentSegment>,
        aggregate_blinding: [u8; 32],
    ) -> Result<Self> {
        if segments.is_empty() {
            return Ok(checkpoint.empty_extension());
        }
        segments.sort_by_key(|segment| (segment.from_epoch, segment.through_epoch));
        let mut expected_epoch = checkpoint.covered_through_epoch.saturating_add(1);
        let mut historical_pairs = Vec::new();
        for segment in &segments {
            if segment.from_epoch != expected_epoch {
                bail!("historical segments must cover a contiguous range");
            }
            if segment.records.is_empty() {
                bail!("historical segments cannot be empty");
            }
            segment.verify()?;
            for record in &segment.records {
                if record.epoch != expected_epoch {
                    bail!("historical segment records must remain contiguous");
                }
                if record.nullifier != record.proof.queried_nullifier {
                    bail!("historical segment record nullifier mismatch");
                }
                record.proof.verify()?;
                historical_pairs.push((record.epoch, record.proof.root));
                expected_epoch = expected_epoch.saturating_add(1);
            }
        }

        let from_epoch = checkpoint.covered_through_epoch.saturating_add(1);
        let through_epoch = expected_epoch.saturating_sub(1);
        let historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_pairs);
        let packet_target = crate::protocol::CURRENT
            .finalized_history_checkpoint_packet_segments
            .max(1) as usize;
        let mut packets = Vec::new();
        let mut packet_start = 0usize;
        while packet_start < segments.len() {
            let packet_end = (packet_start + packet_target).min(segments.len());
            let mut packet_blinding = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut packet_blinding);
            packets.push(HistoricalUnspentPacket::aggregate(
                &checkpoint.note_commitment,
                segments[packet_start..packet_end].to_vec(),
                packet_blinding,
            )?);
            packet_start = packet_end;
        }
        let stratum_target = crate::protocol::CURRENT
            .finalized_history_checkpoint_stratum_packets
            .max(1) as usize;
        let mut strata = Vec::new();
        let mut stratum_start = 0usize;
        while stratum_start < packets.len() {
            let stratum_end = (stratum_start + stratum_target).min(packets.len());
            let mut stratum_blinding = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut stratum_blinding);
            strata.push(HistoricalUnspentStratum::aggregate(
                &checkpoint.note_commitment,
                packets[stratum_start..stratum_end].to_vec(),
                stratum_blinding,
            )?);
            stratum_start = stratum_end;
        }
        let stratum_commitment_root = checkpoint_stratum_commitment_root(
            &strata
                .iter()
                .map(HistoricalUnspentStratum::commitment_digest)
                .collect::<Vec<_>>(),
        );
        let new_transcript_root = accumulated_checkpoint_root(
            &checkpoint.transcript_root,
            &checkpoint.note_commitment,
            from_epoch,
            through_epoch,
            &historical_root_digest,
            &stratum_commitment_root,
            &aggregate_blinding,
        );
        Ok(Self {
            version: SHIELDED_EXTENSION_VERSION,
            note_commitment: checkpoint.note_commitment,
            from_epoch,
            through_epoch,
            prior_transcript_root: checkpoint.transcript_root,
            historical_root_digest,
            stratum_commitment_root,
            aggregate_rerandomization_blinding: aggregate_blinding,
            new_transcript_root,
            strata,
        })
    }
}

impl CheckpointPresentation {
    pub fn for_checkpoint(checkpoint: &HistoricalUnspentCheckpoint, blinding: [u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(PRESENTATION_DOMAIN);
        hasher.update(&[checkpoint.version]);
        hasher.update(&checkpoint.birth_epoch.to_le_bytes());
        hasher.update(&checkpoint.covered_through_epoch.to_le_bytes());
        hasher.update(&checkpoint.transcript_root);
        hasher.update(&checkpoint.verified_epoch_count.to_le_bytes());
        hasher.update(&blinding);
        Self {
            covered_through_epoch: checkpoint.covered_through_epoch,
            blinding,
            presentation_digest: *hasher.finalize().as_bytes(),
        }
    }

    pub fn derive_segment(
        &self,
        covered_through_epoch: u64,
        from_epoch: u64,
        through_epoch: u64,
        segment_index: u32,
    ) -> Self {
        let mut blinding_hasher = blake3::Hasher::new_derive_key(PRESENTATION_DOMAIN);
        blinding_hasher.update(b"segment-blinding");
        blinding_hasher.update(&self.presentation_digest);
        blinding_hasher.update(&covered_through_epoch.to_le_bytes());
        blinding_hasher.update(&from_epoch.to_le_bytes());
        blinding_hasher.update(&through_epoch.to_le_bytes());
        blinding_hasher.update(&segment_index.to_le_bytes());
        let blinding = *blinding_hasher.finalize().as_bytes();

        let mut digest_hasher = blake3::Hasher::new_derive_key(PRESENTATION_DOMAIN);
        digest_hasher.update(b"segment");
        digest_hasher.update(&self.presentation_digest);
        digest_hasher.update(&covered_through_epoch.to_le_bytes());
        digest_hasher.update(&from_epoch.to_le_bytes());
        digest_hasher.update(&through_epoch.to_le_bytes());
        digest_hasher.update(&segment_index.to_le_bytes());
        digest_hasher.update(&blinding);
        Self {
            covered_through_epoch,
            blinding,
            presentation_digest: *digest_hasher.finalize().as_bytes(),
        }
    }

    pub fn verify_against_checkpoint(&self, checkpoint: &HistoricalUnspentCheckpoint) -> bool {
        *self == Self::for_checkpoint(checkpoint, self.blinding)
    }
}

impl FinalizedHistoryShard {
    pub fn new(shard_id: u64, epoch_roots: Vec<(u64, [u8; 32])>) -> Result<Self> {
        if epoch_roots.is_empty() {
            bail!("finalized-history shard cannot be empty");
        }
        for pair in epoch_roots.windows(2) {
            if pair[1].0 != pair[0].0.saturating_add(1) {
                bail!("finalized-history shard epochs must be contiguous");
            }
        }
        let first_epoch = epoch_roots.first().map(|(epoch, _)| *epoch).unwrap_or(0);
        let last_epoch = epoch_roots.last().map(|(epoch, _)| *epoch).unwrap_or(0);
        let root_digest = finalized_history_shard_digest(shard_id, &epoch_roots);
        Ok(Self {
            shard_id,
            first_epoch,
            last_epoch,
            root_digest,
            epoch_roots,
        })
    }

    pub fn covers_range(&self, from_epoch: u64, through_epoch: u64) -> bool {
        if from_epoch > through_epoch {
            return true;
        }
        self.first_epoch <= from_epoch && self.last_epoch >= through_epoch
    }

    pub fn epoch_root(&self, epoch: u64) -> Option<[u8; 32]> {
        self.epoch_roots
            .iter()
            .find(|(candidate_epoch, _)| *candidate_epoch == epoch)
            .map(|(_, root)| *root)
    }
}

impl FinalizedHistoryDirectory {
    pub fn shards_from_root_ledger(
        ledger: &NullifierRootLedger,
        shard_span: u64,
    ) -> Result<Vec<FinalizedHistoryShard>> {
        let shard_span = shard_span.max(1);
        let entries = ledger
            .roots
            .iter()
            .map(|(epoch, root)| (*epoch, *root))
            .collect::<Vec<_>>();
        let mut shards = Vec::new();
        for (shard_index, chunk) in entries.chunks(shard_span as usize).enumerate() {
            shards.push(FinalizedHistoryShard::new(shard_index as u64, chunk.to_vec())?);
        }
        Ok(shards)
    }

    pub fn from_root_ledger(ledger: &NullifierRootLedger, shard_span: u64) -> Result<Self> {
        Ok(Self {
            shard_span: shard_span.max(1),
            shards: Self::shards_from_root_ledger(ledger, shard_span)?,
        })
    }

    pub fn shard(&self, shard_id: u64) -> Option<&FinalizedHistoryShard> {
        self.shards.iter().find(|shard| shard.shard_id == shard_id)
    }

    pub fn shard_for_epoch(&self, epoch: u64) -> Result<&FinalizedHistoryShard> {
        self.shards
            .iter()
            .find(|shard| epoch >= shard.first_epoch && epoch <= shard.last_epoch)
            .ok_or_else(|| anyhow!("missing finalized-history shard for epoch {}", epoch))
    }

    pub fn historical_root_digest_for_range(
        &self,
        from_epoch: u64,
        through_epoch: u64,
    ) -> Result<[u8; 32]> {
        if from_epoch > through_epoch {
            return Ok(proof_core::historical_root_digest_from_pairs(&[]));
        }
        let mut pairs = Vec::new();
        for epoch in from_epoch..=through_epoch {
            let root = self.shard_for_epoch(epoch)?.epoch_root(epoch).ok_or_else(|| {
                anyhow!("missing finalized nullifier-history root for epoch {}", epoch)
            })?;
            pairs.push((epoch, root));
        }
        Ok(proof_core::historical_root_digest_from_pairs(&pairs))
    }
}

impl ShieldedSyncServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_historical_nullifier_window(
        &mut self,
        window: HistoricalNullifierWindow,
    ) -> Result<()> {
        if self.epochs.contains_key(&window.epoch) {
            bail!("nullifier epoch {} already exists in finalized history", window.epoch);
        }
        if let Some((&last_epoch, _)) = self.epochs.last_key_value() {
            if window.epoch <= last_epoch {
                bail!("historical nullifier windows must be inserted in increasing order");
            }
        }
        self.ledger.remember_epoch(&window);
        self.epochs.insert(window.epoch, window);
        Ok(())
    }

    pub fn finalized_history_epoch(
        &mut self,
        epoch: u64,
        nullifiers: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<()> {
        self.insert_historical_nullifier_window(HistoricalNullifierWindow::new(epoch, nullifiers))
    }

    pub fn root_ledger(&self) -> &NullifierRootLedger {
        &self.ledger
    }

    pub fn historical_nullifier_window(&self, epoch: u64) -> Option<&HistoricalNullifierWindow> {
        self.epochs.get(&epoch)
    }

    pub fn epoch(&self, epoch: u64) -> Option<&HistoricalNullifierWindow> {
        self.historical_nullifier_window(epoch)
    }

    pub fn serve_local_checkpoints_batch(
        &self,
        requests: &[CheckpointExtensionRequest],
    ) -> Result<Vec<HistoricalUnspentServiceResponse>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        struct PendingResponse {
            request_binding: [u8; 32],
            from_epoch: u64,
            through_epoch: u64,
            historical_roots: Vec<(u64, [u8; 32])>,
            records: Vec<HistoricalAbsenceRecord>,
        }

        let mut pending = Vec::with_capacity(requests.len());
        let mut epoch_queries: BTreeMap<u64, Vec<(usize, [u8; 32])>> = BTreeMap::new();

        for (request_index, request) in requests.iter().enumerate() {
            let expected_from = request.from_epoch();
            let mut expected_epoch = expected_from;
            for query in &request.queries {
                if query.epoch != expected_epoch {
                    bail!("queries must form a contiguous epoch range");
                }
                epoch_queries
                    .entry(query.epoch)
                    .or_default()
                    .push((request_index, query.nullifier));
                expected_epoch = expected_epoch.saturating_add(1);
            }
            pending.push(PendingResponse {
                request_binding: request.request_binding(),
                from_epoch: expected_from,
                through_epoch: request.presentation.covered_through_epoch,
                historical_roots: Vec::with_capacity(request.queries.len()),
                records: Vec::with_capacity(request.queries.len()),
            });
        }

        for (epoch, entries) in epoch_queries {
            let window = self.epochs.get(&epoch).ok_or_else(|| {
                anyhow!("missing finalized nullifier history for epoch {}", epoch)
            })?;
            let mut ordered_entries = entries;
            ordered_entries.sort_by_key(|(_, nullifier)| *nullifier);
            for (request_index, nullifier) in ordered_entries {
                let proof = window.prove_absence(nullifier)?;
                let pending_response = &mut pending[request_index];
                pending_response.historical_roots.push((epoch, proof.root));
                pending_response.records.push(HistoricalAbsenceRecord {
                    epoch,
                    nullifier,
                    proof,
                });
                pending_response.through_epoch = epoch;
            }
        }

        pending
            .into_iter()
            .map(|pending_response| {
                Ok(HistoricalUnspentServiceResponse {
                    version: SHIELDED_EXTENSION_VERSION,
                    request_binding: pending_response.request_binding,
                    from_epoch: pending_response.from_epoch,
                    through_epoch: pending_response.through_epoch,
                    segment_service_root: checkpoint_segment_service_root(
                        &pending_response.request_binding,
                        pending_response.from_epoch,
                        &pending_response.records,
                    )?,
                    segment_historical_root_digest: proof_core::historical_root_digest_from_pairs(
                        &pending_response.historical_roots,
                    ),
                    records: pending_response.records,
                })
            })
            .collect()
    }
}

impl ActiveNullifierEpoch {
    pub fn new(epoch: u64) -> Self {
        Self {
            version: SHIELDED_ACTIVE_NULLIFIER_VERSION,
            epoch,
            nullifiers: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != SHIELDED_ACTIVE_NULLIFIER_VERSION {
            bail!(
                "unsupported active nullifier epoch version {}",
                self.version
            );
        }
        Ok(())
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub fn insert(&mut self, nullifier: [u8; 32]) -> Result<()> {
        self.validate()?;
        if !self.nullifiers.insert(nullifier) {
            bail!("duplicate current-epoch nullifier");
        }
        Ok(())
    }

    pub fn historical_nullifier_window(&self) -> Result<HistoricalNullifierWindow> {
        self.validate()?;
        Ok(HistoricalNullifierWindow::new(
            self.epoch,
            self.nullifiers.iter().copied(),
        ))
    }

}

pub fn note_key_commitment(note_key: &[u8; 32]) -> [u8; 32] {
    proof_core::proof_hash_bytes(NOTE_KEY_COMMIT_DOMAIN, note_key)
}

pub fn owner_signing_key_commitment(owner_signing_pk: &TaggedSigningPublicKey) -> [u8; 32] {
    proof_core::proof_hash_bytes(
        OWNER_SIGNING_KEY_COMMIT_DOMAIN,
        owner_signing_pk.bytes.as_slice(),
    )
}

pub fn owner_kem_key_commitment(owner_kem_pk: &TaggedKemPublicKey) -> [u8; 32] {
    proof_core::proof_hash_bytes(OWNER_KEM_KEY_COMMIT_DOMAIN, owner_kem_pk.bytes.as_slice())
}

pub fn evolving_nullifier(
    note_key: &[u8; 32],
    rho: &[u8; 32],
    chain_id: &[u8; 32],
    epoch: u64,
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        NULLIFIER_DOMAIN,
        &[
            note_key.as_slice(),
            rho.as_slice(),
            chain_id.as_slice(),
            &epoch.to_le_bytes(),
        ],
    )
}

pub fn note_leaf_hash(note_commitment: &[u8; 32]) -> [u8; 32] {
    proof_core::proof_hash_bytes(NOTE_LEAF_DOMAIN, note_commitment)
}

pub fn nullifier_leaf_hash(nullifier: &[u8; 32]) -> [u8; 32] {
    proof_core::proof_hash_bytes(NULLIFIER_LEAF_DOMAIN, nullifier)
}

fn compute_note_commitment(
    version: u8,
    kind: &ShieldedNoteKind,
    value: u64,
    birth_epoch: u64,
    owner_address: &Address,
    owner_signing_key_commitment: &[u8; 32],
    owner_kem_key_commitment: &[u8; 32],
    rho: &[u8; 32],
    note_randomizer: &[u8; 32],
    note_key_commitment: &[u8; 32],
) -> [u8; 32] {
    let kind_commitment = kind.commitment_bytes();
    proof_core::proof_hash_domain_parts(
        NOTE_COMMIT_DOMAIN,
        &[
            &[version],
            kind_commitment.as_slice(),
            &value.to_le_bytes(),
            &birth_epoch.to_le_bytes(),
            owner_address.as_slice(),
            owner_signing_key_commitment.as_slice(),
            owner_kem_key_commitment.as_slice(),
            rho.as_slice(),
            note_randomizer.as_slice(),
            note_key_commitment.as_slice(),
        ],
    )
}

fn checkpoint_base_root(note_commitment: &[u8; 32], birth_epoch: u64) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_BASE_DOMAIN,
        &[note_commitment.as_slice(), &birth_epoch.to_le_bytes()],
    )
}

fn checkpoint_segment_base_root(note_commitment: &[u8; 32], from_epoch: u64) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_SEGMENT_BASE_DOMAIN,
        &[note_commitment.as_slice(), &from_epoch.to_le_bytes()],
    )
}

fn checkpoint_service_root(
    prior_root: &[u8; 32],
    epoch: u64,
    nullifier: &[u8; 32],
    proof_digest: &[u8; 32],
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_SERVICE_DOMAIN,
        &[
            prior_root.as_slice(),
            &epoch.to_le_bytes(),
            nullifier.as_slice(),
            proof_digest.as_slice(),
        ],
    )
}

fn checkpoint_segment_service_root(
    note_commitment: &[u8; 32],
    from_epoch: u64,
    records: &[HistoricalAbsenceRecord],
) -> Result<[u8; 32]> {
    let mut expected_epoch = from_epoch;
    let mut root = checkpoint_segment_base_root(note_commitment, from_epoch);
    for record in records {
        if record.epoch != expected_epoch {
            bail!("checkpoint segment records must remain contiguous");
        }
        root = checkpoint_service_root(
            &root,
            record.epoch,
            &record.nullifier,
            &record.proof.digest(),
        );
        expected_epoch = expected_epoch.saturating_add(1);
    }
    Ok(root)
}

fn rerandomized_segment_root(
    service_root: &[u8; 32],
    historical_root_digest: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_RERANDOMIZE_DOMAIN,
        &[
            service_root.as_slice(),
            historical_root_digest.as_slice(),
            blinding.as_slice(),
        ],
    )
}

fn checkpoint_segment_commitment_digest(
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    segment_transcript_root: &[u8; 32],
    record_count: u32,
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_SEGMENT_COMMIT_DOMAIN,
        &[
            &from_epoch.to_le_bytes(),
            &through_epoch.to_le_bytes(),
            historical_root_digest.as_slice(),
            segment_transcript_root.as_slice(),
            &record_count.to_le_bytes(),
        ],
    )
}

fn checkpoint_segment_commitment_root(segment_digests: &[[u8; 32]]) -> [u8; 32] {
    let digest_count = (segment_digests.len() as u32).to_le_bytes();
    let mut parts = Vec::with_capacity(1 + segment_digests.len());
    parts.push(digest_count.as_slice());
    for digest in segment_digests {
        parts.push(digest.as_slice());
    }
    proof_core::proof_hash_domain_parts(CHECKPOINT_SEGMENT_COMMIT_DOMAIN, &parts)
}

fn checkpoint_packet_commitment_digest(
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    segment_commitment_root: &[u8; 32],
    packet_transcript_root: &[u8; 32],
    segment_count: u32,
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_PACKET_COMMIT_DOMAIN,
        &[
            &from_epoch.to_le_bytes(),
            &through_epoch.to_le_bytes(),
            historical_root_digest.as_slice(),
            segment_commitment_root.as_slice(),
            packet_transcript_root.as_slice(),
            &segment_count.to_le_bytes(),
        ],
    )
}

fn checkpoint_packet_commitment_root(packet_digests: &[[u8; 32]]) -> [u8; 32] {
    let digest_count = (packet_digests.len() as u32).to_le_bytes();
    let mut parts = Vec::with_capacity(1 + packet_digests.len());
    parts.push(digest_count.as_slice());
    for digest in packet_digests {
        parts.push(digest.as_slice());
    }
    proof_core::proof_hash_domain_parts(CHECKPOINT_PACKET_COMMIT_DOMAIN, &parts)
}

fn accumulated_packet_root(
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    segment_commitment_root: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_PACKET_ACCUMULATE_DOMAIN,
        &[
            note_commitment.as_slice(),
            &from_epoch.to_le_bytes(),
            &through_epoch.to_le_bytes(),
            historical_root_digest.as_slice(),
            segment_commitment_root.as_slice(),
            blinding.as_slice(),
        ],
    )
}

fn checkpoint_stratum_commitment_digest(
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    packet_commitment_root: &[u8; 32],
    stratum_transcript_root: &[u8; 32],
    packet_count: u32,
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_STRATUM_COMMIT_DOMAIN,
        &[
            &from_epoch.to_le_bytes(),
            &through_epoch.to_le_bytes(),
            historical_root_digest.as_slice(),
            packet_commitment_root.as_slice(),
            stratum_transcript_root.as_slice(),
            &packet_count.to_le_bytes(),
        ],
    )
}

fn checkpoint_stratum_commitment_root(stratum_digests: &[[u8; 32]]) -> [u8; 32] {
    let digest_count = (stratum_digests.len() as u32).to_le_bytes();
    let mut parts = Vec::with_capacity(1 + stratum_digests.len());
    parts.push(digest_count.as_slice());
    for digest in stratum_digests {
        parts.push(digest.as_slice());
    }
    proof_core::proof_hash_domain_parts(CHECKPOINT_STRATUM_COMMIT_DOMAIN, &parts)
}

fn accumulated_stratum_root(
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    packet_commitment_root: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_STRATUM_ACCUMULATE_DOMAIN,
        &[
            note_commitment.as_slice(),
            &from_epoch.to_le_bytes(),
            &through_epoch.to_le_bytes(),
            historical_root_digest.as_slice(),
            packet_commitment_root.as_slice(),
            blinding.as_slice(),
        ],
    )
}

fn accumulated_checkpoint_root(
    prior_transcript_root: &[u8; 32],
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    stratum_commitment_root: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        CHECKPOINT_EXTENSION_ACCUMULATE_DOMAIN,
        &[
            prior_transcript_root.as_slice(),
            note_commitment.as_slice(),
            &from_epoch.to_le_bytes(),
            &through_epoch.to_le_bytes(),
            historical_root_digest.as_slice(),
            stratum_commitment_root.as_slice(),
            blinding.as_slice(),
        ],
    )
}

fn finalized_history_shard_digest(shard_id: u64, epoch_roots: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(FINALIZED_HISTORY_SHARD_DOMAIN);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&(epoch_roots.len() as u32).to_le_bytes());
    for (epoch, root) in epoch_roots {
        hasher.update(&epoch.to_le_bytes());
        hasher.update(root);
    }
    *hasher.finalize().as_bytes()
}

fn verify_merkle_proof(leaf_hash: &[u8; 32], proof: &[([u8; 32], bool)], root: &[u8; 32]) -> bool {
    if proof.len() > 64 {
        return false;
    }
    let mut computed = *leaf_hash;
    for (sibling, sibling_is_left) in proof {
        computed = if *sibling_is_left {
            proof_core::merkle_parent_hash(sibling, &computed)
        } else {
            proof_core::merkle_parent_hash(&computed, sibling)
        };
    }
    &computed == root
}

fn build_merkle_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut levels = vec![leaves.to_vec()];
    while levels.last().map(|level| level.len()).unwrap_or(0) > 1 {
        let current = levels.last().cloned().unwrap_or_default();
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(proof_core::merkle_parent_hash(&pair[0], right));
        }
        levels.push(next);
    }
    levels
}

fn push_merkle_leaf(levels: &mut Vec<Vec<[u8; 32]>>, leaf: [u8; 32]) {
    if levels.is_empty() {
        levels.push(Vec::new());
    }
    levels[0].push(leaf);

    let mut level_index = 0usize;
    let mut node_index = levels[0].len() - 1;
    loop {
        if levels.len() <= level_index + 1 {
            levels.push(Vec::new());
        }
        let parent_index = node_index / 2;
        let left_index = node_index & !1;
        let left = levels[level_index][left_index];
        let right = levels[level_index]
            .get(left_index + 1)
            .copied()
            .unwrap_or(left);
        let parent = proof_core::merkle_parent_hash(&left, &right);
        if levels[level_index + 1].len() == parent_index {
            levels[level_index + 1].push(parent);
        } else {
            levels[level_index + 1][parent_index] = parent;
        }
        level_index += 1;
        node_index = parent_index;
        if node_index == 0 && levels[level_index].len() == 1 {
            break;
        }
    }
}

fn merkle_root_from_levels(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .unwrap_or([0u8; 32])
}

fn merkle_proof_from_levels(
    levels: &[Vec<[u8; 32]>],
    mut index: usize,
) -> Option<Vec<([u8; 32], bool)>> {
    let leaf_count = levels.first().map(|level| level.len()).unwrap_or(0);
    if leaf_count == 0 || index >= leaf_count {
        return None;
    }
    let mut proof = Vec::with_capacity(levels.len().saturating_sub(1));
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling_index = if index % 2 == 0 {
            (index + 1).min(level.len().saturating_sub(1))
        } else {
            index.saturating_sub(1)
        };
        let sibling_is_left = sibling_index < index;
        proof.push((level[sibling_index], sibling_is_left));
        index /= 2;
    }
    Some(proof)
}

fn validate_leaf_levels(leaves: &[[u8; 32]], levels: &[Vec<[u8; 32]>]) -> Result<()> {
    if leaves.is_empty() {
        if !levels.is_empty() {
            bail!("empty merkle state cannot contain levels");
        }
        return Ok(());
    }
    if levels.is_empty() {
        bail!("non-empty merkle state requires levels");
    }
    if levels[0] != leaves {
        bail!("leaf level does not match the expected leaves");
    }
    for level_index in 0..levels.len().saturating_sub(1) {
        let current = &levels[level_index];
        let next = &levels[level_index + 1];
        if next.len() != current.len().div_ceil(2) {
            bail!("invalid merkle level width");
        }
        for (parent_index, pair) in current.chunks(2).enumerate() {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let expected = proof_core::merkle_parent_hash(&pair[0], right);
            if next[parent_index] != expected {
                bail!("invalid merkle parent hash");
            }
        }
    }
    if levels.last().map(|level| level.len()).unwrap_or(0) != 1 {
        bail!("top merkle level must contain exactly one node");
    }
    Ok(())
}

pub fn deterministic_genesis_note_key(coin: &Coin, chain_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(GENESIS_NOTE_KEY_DOMAIN);
    hasher.update(chain_id);
    hasher.update(&coin.id);
    hasher.update(&coin.epoch_hash);
    hasher.update(&coin.creator_pk.bytes);
    *hasher.finalize().as_bytes()
}

fn deterministic_genesis_rho(coin: &Coin, birth_epoch: u64, chain_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(GENESIS_NOTE_RHO_DOMAIN);
    hasher.update(chain_id);
    hasher.update(&coin.id);
    hasher.update(&birth_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn deterministic_genesis_randomizer(
    coin: &Coin,
    birth_epoch: u64,
    chain_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(GENESIS_NOTE_RANDOMIZER_DOMAIN);
    hasher.update(chain_id);
    hasher.update(&coin.id);
    hasher.update(&coin.creator_pk.bytes);
    hasher.update(&birth_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn deterministic_genesis_note(
    coin: &Coin,
    birth_epoch: u64,
    chain_id: &[u8; 32],
) -> (ShieldedNote, [u8; 32], HistoricalUnspentCheckpoint) {
    let note_key = deterministic_genesis_note_key(coin, chain_id);
    let note = ShieldedNote::new(
        coin.value,
        birth_epoch,
        coin.creator_pk.clone(),
        TaggedKemPublicKey::zero_ml_kem_768(),
        note_key,
        deterministic_genesis_rho(coin, birth_epoch, chain_id),
        deterministic_genesis_randomizer(coin, birth_epoch, chain_id),
    );
    let checkpoint = HistoricalUnspentCheckpoint::genesis(note.commitment, birth_epoch);
    (note, note_key, checkpoint)
}
