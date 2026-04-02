use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    coin::Coin,
    crypto::{Address, TaggedKemPublicKey, TaggedSigningPublicKey},
    epoch::MerkleTree,
};

pub const SHIELDED_NOTE_VERSION: u8 = 1;
pub const SHIELDED_CHECKPOINT_VERSION: u8 = 1;
pub const SHIELDED_EXTENSION_VERSION: u8 = 1;
pub const SHIELDED_ACTIVE_NULLIFIER_VERSION: u8 = 1;

const NOTE_KEY_COMMIT_DOMAIN: &str = "unchained-shielded-note-key-v1";
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
const ARCHIVE_SHARD_DOMAIN: &str = "unchained-shielded-archive-shard-v1";
const ARCHIVE_PROVIDER_MANIFEST_DOMAIN: &str = "unchained-shielded-archive-provider-v1";
const ARCHIVE_PROVIDER_SELECT_DOMAIN: &str = "unchained-shielded-archive-select-v1";
const ARCHIVE_BATCH_ORDER_DOMAIN: &str = "unchained-shielded-archive-batch-order-v1";
const ARCHIVE_REPLICA_ATTEST_DOMAIN: &str = "unchained-shielded-archive-replica-v1";
const ARCHIVE_CUSTODY_ASSIGN_DOMAIN: &str = "unchained-shielded-archive-custody-v1";
const ARCHIVE_CUSTODY_COMMITMENT_DOMAIN: &str = "unchained-shielded-archive-custody-commit-v1";
const ARCHIVE_SERVICE_LEDGER_DOMAIN: &str = "unchained-shielded-archive-service-ledger-v1";
const ARCHIVE_AVAILABILITY_CERT_DOMAIN: &str = "unchained-shielded-archive-availability-v1";
const ARCHIVE_RETRIEVAL_RECEIPT_DOMAIN: &str = "unchained-shielded-archive-retrieval-receipt-v1";
const GENESIS_NOTE_KEY_DOMAIN: &str = "unchained-shielded-genesis-note-key-v1";
const GENESIS_NOTE_RHO_DOMAIN: &str = "unchained-shielded-genesis-note-rho-v1";
const GENESIS_NOTE_RANDOMIZER_DOMAIN: &str = "unchained-shielded-genesis-note-randomizer-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedNote {
    pub version: u8,
    pub value: u64,
    pub birth_epoch: u64,
    pub owner_address: Address,
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
pub struct ArchivedNullifierEpoch {
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
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub request_binding: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub segment_service_root: [u8; 32],
    pub segment_historical_root_digest: [u8; 32],
    pub records: Vec<HistoricalAbsenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentSegment {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
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
pub struct ArchiveReplicaAttestation {
    pub provider_id: [u8; 32],
    pub shard_id: u64,
    pub shard_digest: [u8; 32],
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub retention_through_epoch: u64,
    pub attestation_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveReplicaReport {
    pub shard_id: u64,
    pub shard_digest: [u8; 32],
    pub replica_count: u32,
    pub retention_through_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveCustodyAssignment {
    pub shard_id: u64,
    pub shard_digest: [u8; 32],
    pub custodians: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveOperatorScorecard {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub advertised_shard_count: u32,
    pub assigned_shard_count: u32,
    pub fulfilled_custody_count: u32,
    pub committed_custody_count: u32,
    pub missing_custody_commitment_count: u32,
    pub retention_surplus_epochs: u64,
    pub availability_bps: u16,
    pub service_success_bps: u16,
    pub successful_retrieval_receipts: u64,
    pub failed_retrieval_receipts: u64,
    pub served_checkpoint_batches: u64,
    pub served_checkpoint_segments: u64,
    pub served_archive_shards: u64,
    pub mean_checkpoint_latency_ms: u32,
    pub reward_weight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveServiceLedger {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub served_checkpoint_batches: u64,
    pub served_checkpoint_segments: u64,
    pub served_archive_shards: u64,
    pub failed_checkpoint_batches: u64,
    pub failed_archive_shards: u64,
    pub total_checkpoint_latency_ms: u64,
    pub last_success_unix_ms: u64,
    pub ledger_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveAvailabilityCertificate {
    pub shard_id: u64,
    pub shard_digest: [u8; 32],
    pub certified_providers: Vec<[u8; 32]>,
    pub certified_replica_count: u32,
    pub quorum_target: u32,
    pub quorum_met: bool,
    pub retention_through_epoch: u64,
    pub certificate_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArchiveRetrievalKind {
    CheckpointBatch,
    ArchiveShard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveCustodyCommitment {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub shard_id: u64,
    pub shard_digest: [u8; 32],
    pub retention_through_epoch: u64,
    pub commitment_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveRetrievalReceipt {
    pub requester_id: [u8; 32],
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub retrieval_kind: ArchiveRetrievalKind,
    pub request_message_id: [u8; 32],
    pub response_message_id: Option<[u8; 32]>,
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub shard_id: Option<u64>,
    pub served_units: u32,
    pub success: bool,
    pub latency_ms: u64,
    pub observed_unix_ms: u64,
    pub receipt_digest: [u8; 32],
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
pub struct ArchiveShard {
    pub shard_id: u64,
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub root_digest: [u8; 32],
    pub epoch_roots: Vec<(u64, [u8; 32])>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveProviderManifest {
    pub provider_id: [u8; 32],
    pub schedule_seed: [u8; 32],
    pub coverage_first_epoch: u64,
    pub coverage_last_epoch: u64,
    pub shard_ids: Vec<u64>,
    pub shard_digests: Vec<[u8; 32]>,
    pub manifest_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ArchiveDirectory {
    pub shard_span: u64,
    pub shards: Vec<ArchiveShard>,
    pub providers: Vec<ArchiveProviderManifest>,
    pub replicas: Vec<ArchiveReplicaAttestation>,
    pub accounting: Vec<ArchiveServiceLedger>,
    pub custody_commitments: Vec<ArchiveCustodyCommitment>,
    pub retrieval_receipts: Vec<ArchiveRetrievalReceipt>,
    pub availability_certificates: Vec<ArchiveAvailabilityCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveShardBundle {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub shard: ArchiveShard,
    pub epochs: Vec<ArchivedNullifierEpoch>,
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
    epochs: BTreeMap<u64, ArchivedNullifierEpoch>,
    ledger: NullifierRootLedger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointExtensionRequest {
    pub checkpoint: Option<HistoricalUnspentCheckpoint>,
    pub presentation: CheckpointPresentation,
    pub queries: Vec<EvolvingNullifierQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointBatchRequest {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub requests: Vec<CheckpointExtensionRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointBatchResponse {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub responses: Vec<HistoricalUnspentServiceResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedCheckpointRequest {
    pub provider_id: [u8; 32],
    pub request_index: Option<usize>,
    pub segment_index: u32,
    pub shard_id: u64,
    pub request: CheckpointExtensionRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoutedCheckpointBatch {
    pub provider_id: [u8; 32],
    pub requests: Vec<RoutedCheckpointRequest>,
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
        let owner_address = owner_signing_pk.address();
        let note_key_commitment = note_key_commitment(&note_key);
        let commitment = compute_note_commitment(
            SHIELDED_NOTE_VERSION,
            value,
            birth_epoch,
            &owner_address,
            &owner_signing_pk,
            &owner_kem_pk,
            &rho,
            &note_randomizer,
            &note_key_commitment,
        );
        Self {
            version: SHIELDED_NOTE_VERSION,
            value,
            birth_epoch,
            owner_address,
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
        let expected = compute_note_commitment(
            self.version,
            self.value,
            self.birth_epoch,
            &self.owner_address,
            &self.owner_signing_pk,
            &self.owner_kem_pk,
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
        MerkleTree::verify_proof(
            &note_leaf_hash(&self.note_commitment),
            &self.proof,
            &self.root,
        )
    }
}

impl ArchivedNullifierEpoch {
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
            bail!("archived nullifier epoch must stay strictly sorted and deduplicated");
        }
        validate_leaf_levels(
            &nullifiers
                .iter()
                .map(nullifier_leaf_hash)
                .collect::<Vec<[u8; 32]>>(),
            &levels,
        )?;
        if merkle_root_from_levels(&levels) != root {
            bail!("archived nullifier epoch root mismatch");
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
        MerkleTree::verify_proof(
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
        let mut hasher = blake3::Hasher::new_derive_key("unchained-shielded-absence-proof-v1");
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.queried_nullifier);
        hasher.update(&self.root);
        hasher.update(&self.set_size.to_le_bytes());
        hash_optional_membership(&mut hasher, &self.predecessor);
        hash_optional_membership(&mut hasher, &self.successor);
        *hasher.finalize().as_bytes()
    }
}

impl NullifierRootLedger {
    pub fn root_for_epoch(&self, epoch: u64) -> Result<[u8; 32]> {
        self.roots
            .get(&epoch)
            .copied()
            .ok_or_else(|| anyhow!("missing historical nullifier root for epoch {}", epoch))
    }

    pub fn remember_epoch(&mut self, archived: &ArchivedNullifierEpoch) {
        self.roots.insert(archived.epoch, archived.root);
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
            provider_id: self.provider_id,
            provider_manifest_digest: self.provider_manifest_digest,
            request_binding: self.request_binding,
            from_epoch: self.from_epoch,
            through_epoch: self.through_epoch,
            segment_service_root: self.segment_service_root,
            segment_historical_root_digest: self.segment_historical_root_digest,
            rerandomization_blinding: blinding,
            segment_transcript_root: rerandomized_segment_root(
                &self.segment_service_root,
                &self.provider_id,
                &self.provider_manifest_digest,
                &self.segment_historical_root_digest,
                &blinding,
            ),
            records: self.records.clone(),
        }
    }

    pub fn verify_against_manifest(
        &self,
        manifest: &ArchiveProviderManifest,
        directory: &ArchiveDirectory,
    ) -> Result<()> {
        if self.provider_id != manifest.provider_id {
            bail!("service response provider id mismatch");
        }
        if self.provider_manifest_digest != manifest.manifest_digest {
            bail!("service response manifest digest mismatch");
        }
        if self.provider_manifest_digest != manifest.digest() {
            bail!("archive provider manifest digest mismatch");
        }
        if self.records.is_empty() {
            bail!("service response must contain at least one absence record");
        }
        if self.records.last().map(|record| record.epoch) != Some(self.through_epoch) {
            bail!("service response through_epoch does not match the final record");
        }
        if !manifest.covers_range(directory, self.from_epoch, self.through_epoch)? {
            bail!("archive provider manifest does not cover the requested epoch range");
        }
        let expected_historical_root_digest =
            directory.historical_root_digest_for_range(self.from_epoch, self.through_epoch)?;
        if self.segment_historical_root_digest != expected_historical_root_digest {
            bail!("service response historical root digest mismatch");
        }
        let expected_service_root =
            checkpoint_segment_service_root(&self.request_binding, self.from_epoch, &self.records)?;
        if self.segment_service_root != expected_service_root {
            bail!("service response segment transcript root mismatch");
        }
        Ok(())
    }

    pub fn verify_against_request(
        &self,
        request: &CheckpointExtensionRequest,
        manifest: &ArchiveProviderManifest,
        directory: &ArchiveDirectory,
    ) -> Result<()> {
        self.verify_against_manifest(manifest, directory)?;
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
            &self.provider_id,
            &self.provider_manifest_digest,
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
            &self.provider_id,
            &self.provider_manifest_digest,
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
            .archive_checkpoint_packet_segments
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
            .archive_checkpoint_stratum_packets
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

impl CheckpointBatchRequest {
    pub fn validate_against_manifest(
        &self,
        manifest: &ArchiveProviderManifest,
        directory: &ArchiveDirectory,
    ) -> Result<()> {
        if self.provider_id != manifest.provider_id {
            bail!("checkpoint batch request provider id mismatch");
        }
        if self.provider_manifest_digest != manifest.manifest_digest {
            bail!("checkpoint batch request manifest digest mismatch");
        }
        if self.provider_manifest_digest != manifest.digest() {
            bail!("archive provider manifest digest mismatch");
        }
        for request in &self.requests {
            if request.queries.is_empty() {
                continue;
            }
            let expected_from = request.from_epoch();
            let through_epoch = request
                .queries
                .last()
                .map(|query| query.epoch)
                .ok_or_else(|| anyhow!("checkpoint batch request missing terminal epoch"))?;
            if request.queries.first().map(|query| query.epoch) != Some(expected_from) {
                bail!("checkpoint batch request does not continue from the prior checkpoint");
            }
            if !manifest.covers_range(directory, expected_from, through_epoch)? {
                bail!("archive provider manifest does not cover the requested checkpoint range");
            }
        }
        Ok(())
    }
}

impl CheckpointBatchResponse {
    pub fn verify_against_manifest(
        &self,
        manifest: &ArchiveProviderManifest,
        directory: &ArchiveDirectory,
    ) -> Result<()> {
        if self.provider_id != manifest.provider_id {
            bail!("checkpoint batch response provider id mismatch");
        }
        if self.provider_manifest_digest != manifest.manifest_digest {
            bail!("checkpoint batch response manifest digest mismatch");
        }
        if self.provider_manifest_digest != manifest.digest() {
            bail!("archive provider manifest digest mismatch");
        }
        for response in &self.responses {
            response.verify_against_manifest(manifest, directory)?;
        }
        Ok(())
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

impl ArchiveShard {
    pub fn new(shard_id: u64, epoch_roots: Vec<(u64, [u8; 32])>) -> Result<Self> {
        if epoch_roots.is_empty() {
            bail!("archive shard cannot be empty");
        }
        for pair in epoch_roots.windows(2) {
            if pair[1].0 != pair[0].0.saturating_add(1) {
                bail!("archive shard epochs must be contiguous");
            }
        }
        let first_epoch = epoch_roots.first().map(|(epoch, _)| *epoch).unwrap_or(0);
        let last_epoch = epoch_roots.last().map(|(epoch, _)| *epoch).unwrap_or(0);
        let root_digest = archive_shard_digest(shard_id, &epoch_roots);
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

impl ArchiveProviderManifest {
    pub fn new(provider_id: [u8; 32], shards: &[ArchiveShard]) -> Self {
        let coverage_first_epoch = shards.first().map(|shard| shard.first_epoch).unwrap_or(0);
        let coverage_last_epoch = shards.last().map(|shard| shard.last_epoch).unwrap_or(0);
        let shard_ids = shards
            .iter()
            .map(|shard| shard.shard_id)
            .collect::<Vec<_>>();
        let shard_digests = shards
            .iter()
            .map(|shard| shard.root_digest)
            .collect::<Vec<_>>();
        let schedule_seed =
            archive_provider_schedule_seed(&provider_id, &shard_ids, &shard_digests);
        let manifest_digest = archive_provider_manifest_digest(
            &provider_id,
            &schedule_seed,
            coverage_first_epoch,
            coverage_last_epoch,
            &shard_ids,
            &shard_digests,
        );
        Self {
            provider_id,
            schedule_seed,
            coverage_first_epoch,
            coverage_last_epoch,
            shard_ids,
            shard_digests,
            manifest_digest,
        }
    }

    pub fn digest(&self) -> [u8; 32] {
        archive_provider_manifest_digest(
            &self.provider_id,
            &self.schedule_seed,
            self.coverage_first_epoch,
            self.coverage_last_epoch,
            &self.shard_ids,
            &self.shard_digests,
        )
    }

    pub fn validate(&self, directory: &ArchiveDirectory) -> Result<()> {
        if self.schedule_seed
            != archive_provider_schedule_seed(
                &self.provider_id,
                &self.shard_ids,
                &self.shard_digests,
            )
        {
            bail!("archive provider manifest schedule seed mismatch");
        }
        if self.manifest_digest != self.digest() {
            bail!("archive provider manifest digest mismatch");
        }
        for (shard_id, shard_digest) in self.shard_ids.iter().zip(&self.shard_digests) {
            let shard = directory
                .shard(*shard_id)
                .ok_or_else(|| anyhow!("archive provider references unknown shard {}", shard_id))?;
            if shard.root_digest != *shard_digest {
                bail!("archive provider shard digest mismatch");
            }
        }
        Ok(())
    }

    pub fn serves_shard(&self, shard_id: u64, shard_digest: &[u8; 32]) -> bool {
        self.shard_ids
            .iter()
            .zip(&self.shard_digests)
            .any(|(candidate_id, candidate_digest)| {
                *candidate_id == shard_id && candidate_digest == shard_digest
            })
    }

    pub fn covers_range(
        &self,
        directory: &ArchiveDirectory,
        from_epoch: u64,
        through_epoch: u64,
    ) -> Result<bool> {
        if from_epoch > through_epoch {
            return Ok(true);
        }
        if from_epoch < self.coverage_first_epoch || through_epoch > self.coverage_last_epoch {
            return Ok(false);
        }
        Ok(directory
            .shards
            .iter()
            .filter(|shard| !(through_epoch < shard.first_epoch || from_epoch > shard.last_epoch))
            .all(|shard| {
                self.shard_ids
                    .iter()
                    .zip(&self.shard_digests)
                    .any(|(shard_id, shard_digest)| {
                        *shard_id == shard.shard_id && *shard_digest == shard.root_digest
                    })
            }))
    }
}

impl ArchiveDirectory {
    pub fn shards_from_root_ledger(
        ledger: &NullifierRootLedger,
        shard_span: u64,
    ) -> Result<Vec<ArchiveShard>> {
        let shard_span = shard_span.max(1);
        let entries = ledger
            .roots
            .iter()
            .map(|(epoch, root)| (*epoch, *root))
            .collect::<Vec<_>>();
        let mut shards = Vec::new();
        for (shard_index, chunk) in entries.chunks(shard_span as usize).enumerate() {
            shards.push(ArchiveShard::new(shard_index as u64, chunk.to_vec())?);
        }
        Ok(shards)
    }

    pub fn from_root_ledger_and_providers(
        ledger: &NullifierRootLedger,
        shard_span: u64,
        providers: Vec<ArchiveProviderManifest>,
    ) -> Result<Self> {
        Self::from_root_ledger_and_providers_and_replicas_and_accounting(
            ledger,
            shard_span,
            providers,
            Vec::new(),
            Vec::new(),
        )
    }

    pub fn from_root_ledger_and_providers_and_replicas(
        ledger: &NullifierRootLedger,
        shard_span: u64,
        providers: Vec<ArchiveProviderManifest>,
        replicas: Vec<ArchiveReplicaAttestation>,
    ) -> Result<Self> {
        Self::from_root_ledger_and_providers_and_replicas_and_accounting(
            ledger,
            shard_span,
            providers,
            replicas,
            Vec::new(),
        )
    }

    pub fn from_root_ledger_and_providers_and_replicas_and_accounting(
        ledger: &NullifierRootLedger,
        shard_span: u64,
        providers: Vec<ArchiveProviderManifest>,
        replicas: Vec<ArchiveReplicaAttestation>,
        accounting: Vec<ArchiveServiceLedger>,
    ) -> Result<Self> {
        Self::from_root_ledger_and_providers_and_replicas_and_evidence(
            ledger,
            shard_span,
            providers,
            replicas,
            accounting,
            Vec::new(),
            Vec::new(),
        )
    }

    pub fn from_root_ledger_and_providers_and_replicas_and_evidence(
        ledger: &NullifierRootLedger,
        shard_span: u64,
        providers: Vec<ArchiveProviderManifest>,
        replicas: Vec<ArchiveReplicaAttestation>,
        accounting: Vec<ArchiveServiceLedger>,
        custody_commitments: Vec<ArchiveCustodyCommitment>,
        retrieval_receipts: Vec<ArchiveRetrievalReceipt>,
    ) -> Result<Self> {
        let shards = Self::shards_from_root_ledger(ledger, shard_span)?;
        let validation_directory = Self {
            shard_span,
            shards: shards.clone(),
            providers: Vec::new(),
            replicas: Vec::new(),
            accounting: Vec::new(),
            custody_commitments: Vec::new(),
            retrieval_receipts: Vec::new(),
            availability_certificates: Vec::new(),
        };
        let providers: Vec<ArchiveProviderManifest> = providers
            .into_iter()
            .filter(|provider| provider.validate(&validation_directory).is_ok())
            .collect();
        let replica_validation_directory = Self {
            shard_span,
            shards: shards.clone(),
            providers: providers.clone(),
            replicas: Vec::new(),
            accounting: Vec::new(),
            custody_commitments: Vec::new(),
            retrieval_receipts: Vec::new(),
            availability_certificates: Vec::new(),
        };
        let replicas: Vec<ArchiveReplicaAttestation> = replicas
            .into_iter()
            .filter(|replica| replica.validate(&replica_validation_directory).is_ok())
            .collect();
        let accounting = accounting
            .into_iter()
            .filter(|ledger| {
                providers.iter().any(|provider| {
                    provider.provider_id == ledger.provider_id
                        && provider.manifest_digest == ledger.provider_manifest_digest
                }) && ledger.validate().is_ok()
            })
            .collect::<Vec<_>>();
        let commitment_validation_directory = Self {
            shard_span,
            shards: shards.clone(),
            providers: providers.clone(),
            replicas: replicas.clone(),
            accounting: accounting.clone(),
            custody_commitments: Vec::new(),
            retrieval_receipts: Vec::new(),
            availability_certificates: Vec::new(),
        };
        let custody_commitments = custody_commitments
            .into_iter()
            .filter(|commitment| {
                commitment
                    .validate(&commitment_validation_directory)
                    .is_ok()
            })
            .collect::<Vec<_>>();
        let receipt_validation_directory = Self {
            shard_span,
            shards: shards.clone(),
            providers: providers.clone(),
            replicas: replicas.clone(),
            accounting: accounting.clone(),
            custody_commitments: custody_commitments.clone(),
            retrieval_receipts: Vec::new(),
            availability_certificates: Vec::new(),
        };
        let retrieval_receipts = retrieval_receipts
            .into_iter()
            .filter(|receipt| receipt.validate(&receipt_validation_directory).is_ok())
            .collect::<Vec<_>>();
        let mut directory = Self {
            shard_span,
            shards,
            providers,
            replicas,
            accounting,
            custody_commitments,
            retrieval_receipts,
            availability_certificates: Vec::new(),
        };
        directory.availability_certificates = directory.derive_availability_certificates(
            crate::protocol::CURRENT.archive_provider_replica_count as usize,
            crate::protocol::CURRENT.archive_retention_horizon_epochs,
        );
        Ok(directory)
    }

    pub fn provider(&self, provider_id: &[u8; 32]) -> Result<&ArchiveProviderManifest> {
        self.providers
            .iter()
            .find(|provider| &provider.provider_id == provider_id)
            .ok_or_else(|| anyhow!("unknown archive provider"))
    }

    pub fn shard(&self, shard_id: u64) -> Option<&ArchiveShard> {
        self.shards.iter().find(|shard| shard.shard_id == shard_id)
    }

    pub fn shard_for_epoch(&self, epoch: u64) -> Result<&ArchiveShard> {
        self.shards
            .iter()
            .find(|shard| epoch >= shard.first_epoch && epoch <= shard.last_epoch)
            .ok_or_else(|| anyhow!("missing archive shard for epoch {}", epoch))
    }

    pub fn replicas_for_shard(&self, shard_id: u64) -> Vec<&ArchiveReplicaAttestation> {
        self.replicas
            .iter()
            .filter(|replica| replica.shard_id == shard_id)
            .collect()
    }

    pub fn replica_report(&self, shard_id: u64) -> Result<ArchiveReplicaReport> {
        let shard = self
            .shard(shard_id)
            .ok_or_else(|| anyhow!("unknown archive shard {}", shard_id))?;
        let replicas = self.replicas_for_shard(shard_id);
        let replica_count = if replicas.is_empty() {
            self.providers
                .iter()
                .filter(|provider| provider.serves_shard(shard_id, &shard.root_digest))
                .count() as u32
        } else {
            replicas.len() as u32
        };
        let retention_through_epoch = replicas
            .iter()
            .map(|replica| replica.retention_through_epoch)
            .max()
            .unwrap_or(shard.last_epoch);
        Ok(ArchiveReplicaReport {
            shard_id,
            shard_digest: shard.root_digest,
            replica_count,
            retention_through_epoch,
        })
    }

    pub fn accounting_for_provider(&self, provider_id: &[u8; 32]) -> Option<&ArchiveServiceLedger> {
        self.accounting
            .iter()
            .find(|ledger| &ledger.provider_id == provider_id)
    }

    pub fn custody_commitment(
        &self,
        provider_id: &[u8; 32],
        shard_id: u64,
    ) -> Option<&ArchiveCustodyCommitment> {
        self.custody_commitments.iter().find(|commitment| {
            &commitment.provider_id == provider_id && commitment.shard_id == shard_id
        })
    }

    pub fn has_custody_commitment(
        &self,
        provider_id: &[u8; 32],
        shard_id: u64,
        required_retention: u64,
    ) -> bool {
        self.custody_commitment(provider_id, shard_id)
            .map(|commitment| commitment.retention_through_epoch >= required_retention)
            .unwrap_or(false)
    }

    pub fn retrieval_receipts_for_provider(
        &self,
        provider_id: &[u8; 32],
    ) -> Vec<&ArchiveRetrievalReceipt> {
        self.retrieval_receipts
            .iter()
            .filter(|receipt| &receipt.provider_id == provider_id)
            .collect()
    }

    pub fn availability_certificate(
        &self,
        shard_id: u64,
    ) -> Option<&ArchiveAvailabilityCertificate> {
        self.availability_certificates
            .iter()
            .find(|certificate| certificate.shard_id == shard_id)
    }

    pub fn providers_covering_range(
        &self,
        from_epoch: u64,
        through_epoch: u64,
    ) -> Result<Vec<&ArchiveProviderManifest>> {
        if from_epoch > through_epoch {
            return Ok(Vec::new());
        }
        Ok(self
            .providers
            .iter()
            .filter(|provider| {
                provider
                    .covers_range(self, from_epoch, through_epoch)
                    .unwrap_or(false)
            })
            .collect())
    }

    pub fn pick_provider(
        &self,
        checkpoint: &HistoricalUnspentCheckpoint,
        through_epoch: u64,
        rotation_round: u64,
    ) -> Result<&ArchiveProviderManifest> {
        let from_epoch = checkpoint.covered_through_epoch.saturating_add(1);
        let mut eligible = self
            .providers
            .iter()
            .filter(|provider| {
                provider
                    .covers_range(self, from_epoch, through_epoch)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            bail!("no archive provider covers the requested epoch range");
        }
        let range_shards = self
            .shards
            .iter()
            .filter(|shard| !(through_epoch < shard.first_epoch || from_epoch > shard.last_epoch))
            .collect::<Vec<_>>();
        eligible.sort_by_key(|provider| {
            let commitment_penalty = range_shards.iter().any(|shard| {
                let required_retention = shard
                    .last_epoch
                    .saturating_add(crate::protocol::CURRENT.archive_retention_horizon_epochs);
                !self.has_custody_commitment(
                    &provider.provider_id,
                    shard.shard_id,
                    required_retention,
                )
            }) as u8;
            let certificate_penalty = range_shards
                .iter()
                .filter_map(|shard| self.availability_certificate(shard.shard_id))
                .filter(|certificate| certificate.quorum_met)
                .any(|certificate| {
                    !certificate
                        .certified_providers
                        .contains(&provider.provider_id)
                }) as u8;
            let scorecard = self
                .operator_scorecard(
                    &provider.provider_id,
                    crate::protocol::CURRENT.archive_provider_replica_count as usize,
                    crate::protocol::CURRENT.archive_retention_horizon_epochs,
                )
                .ok();
            (
                commitment_penalty,
                certificate_penalty,
                u64::MAX.saturating_sub(scorecard.as_ref().map_or(0, |score| score.reward_weight)),
                provider_selection_score(
                    &provider.provider_id,
                    &provider.schedule_seed,
                    &checkpoint.transcript_root,
                    from_epoch,
                    through_epoch,
                    rotation_round,
                ),
            )
        });
        Ok(eligible[0])
    }

    pub fn provider_retention_for_shard(&self, provider_id: &[u8; 32], shard_id: u64) -> u64 {
        self.replicas
            .iter()
            .filter(|replica| &replica.provider_id == provider_id && replica.shard_id == shard_id)
            .map(|replica| replica.retention_through_epoch)
            .max()
            .or_else(|| self.shard(shard_id).map(|shard| shard.last_epoch))
            .unwrap_or(0)
    }

    pub fn operator_scorecards(
        &self,
        replica_count: usize,
        retention_horizon_epochs: u64,
    ) -> Vec<ArchiveOperatorScorecard> {
        let mut candidate_nodes = self
            .providers
            .iter()
            .map(|provider| provider.provider_id)
            .collect::<Vec<_>>();
        candidate_nodes.sort();
        candidate_nodes.dedup();
        let assignments = self.custody_assignments(&candidate_nodes, replica_count);
        self.providers
            .iter()
            .map(|provider| {
                let advertised_shard_count = provider.shard_ids.len() as u32;
                let assigned = assignments
                    .iter()
                    .filter(|assignment| assignment.custodians.contains(&provider.provider_id))
                    .collect::<Vec<_>>();
                let assigned_shard_count = assigned.len() as u32;
                let mut fulfilled_custody_count = 0u32;
                let mut committed_custody_count = 0u32;
                let mut retention_surplus_epochs = 0u64;
                for shard_id in &provider.shard_ids {
                    let retention =
                        self.provider_retention_for_shard(&provider.provider_id, *shard_id);
                    let Some(shard) = self.shard(*shard_id) else {
                        continue;
                    };
                    retention_surplus_epochs = retention_surplus_epochs.saturating_add(
                        retention
                            .saturating_sub(shard.last_epoch)
                            .min(retention_horizon_epochs),
                    );
                }
                for assignment in assigned {
                    let Some(shard) = self.shard(assignment.shard_id) else {
                        continue;
                    };
                    let required_retention =
                        shard.last_epoch.saturating_add(retention_horizon_epochs);
                    if self.provider_retention_for_shard(&provider.provider_id, assignment.shard_id)
                        >= required_retention
                    {
                        fulfilled_custody_count = fulfilled_custody_count.saturating_add(1);
                    }
                    if self.has_custody_commitment(
                        &provider.provider_id,
                        assignment.shard_id,
                        required_retention,
                    ) {
                        committed_custody_count = committed_custody_count.saturating_add(1);
                    }
                }
                let missing_custody_commitment_count =
                    assigned_shard_count.saturating_sub(committed_custody_count);
                let effective_custody_count = fulfilled_custody_count.min(committed_custody_count);
                let availability_bps = if assigned_shard_count == 0 {
                    10_000
                } else {
                    ((effective_custody_count as u64 * 10_000) / assigned_shard_count as u64)
                        .min(10_000) as u16
                };
                let accounting = self.accounting_for_provider(&provider.provider_id);
                let receipts = self.retrieval_receipts_for_provider(&provider.provider_id);
                let successful_retrieval_receipts =
                    receipts.iter().filter(|receipt| receipt.success).count() as u64;
                let failed_retrieval_receipts =
                    receipts.iter().filter(|receipt| !receipt.success).count() as u64;
                let total_receipts =
                    successful_retrieval_receipts.saturating_add(failed_retrieval_receipts);
                let service_success_bps = if total_receipts == 0 {
                    accounting
                        .map(ArchiveServiceLedger::success_bps)
                        .unwrap_or(10_000)
                } else {
                    ((successful_retrieval_receipts.saturating_mul(10_000)) / total_receipts)
                        .min(10_000) as u16
                };
                let receipt_checkpoint_batches = receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.success
                            && receipt.retrieval_kind == ArchiveRetrievalKind::CheckpointBatch
                    })
                    .count() as u64;
                let receipt_checkpoint_segments = receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.success
                            && receipt.retrieval_kind == ArchiveRetrievalKind::CheckpointBatch
                    })
                    .map(|receipt| receipt.served_units as u64)
                    .sum::<u64>();
                let receipt_archive_shards = receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.success
                            && receipt.retrieval_kind == ArchiveRetrievalKind::ArchiveShard
                    })
                    .map(|receipt| receipt.served_units as u64)
                    .sum::<u64>();
                let receipt_checkpoint_latency_ms = receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.success
                            && receipt.retrieval_kind == ArchiveRetrievalKind::CheckpointBatch
                    })
                    .map(|receipt| receipt.latency_ms)
                    .sum::<u64>();
                let served_checkpoint_batches = if total_receipts == 0 {
                    accounting
                        .map(|ledger| ledger.served_checkpoint_batches)
                        .unwrap_or(0)
                } else {
                    receipt_checkpoint_batches
                };
                let served_checkpoint_segments = if total_receipts == 0 {
                    accounting
                        .map(|ledger| ledger.served_checkpoint_segments)
                        .unwrap_or(0)
                } else {
                    receipt_checkpoint_segments
                };
                let served_archive_shards = if total_receipts == 0 {
                    accounting
                        .map(|ledger| ledger.served_archive_shards)
                        .unwrap_or(0)
                } else {
                    receipt_archive_shards
                };
                let mean_checkpoint_latency_ms = if total_receipts == 0 {
                    accounting
                        .map(ArchiveServiceLedger::mean_checkpoint_latency_ms)
                        .unwrap_or(0)
                } else if served_checkpoint_batches == 0 {
                    0
                } else {
                    (receipt_checkpoint_latency_ms / served_checkpoint_batches).min(u32::MAX as u64)
                        as u32
                };
                let reward_weight = 1u64
                    .saturating_add((effective_custody_count as u64).saturating_mul(1_000_000))
                    .saturating_add((committed_custody_count as u64).saturating_mul(500_000))
                    .saturating_add((retention_surplus_epochs.min(u32::MAX as u64)) * 1_000)
                    .saturating_add((service_success_bps as u64).saturating_mul(100))
                    .saturating_add(successful_retrieval_receipts.saturating_mul(100))
                    .saturating_add(served_checkpoint_segments)
                    .saturating_add(served_archive_shards.saturating_mul(10))
                    .saturating_add(advertised_shard_count as u64)
                    .saturating_sub(
                        (missing_custody_commitment_count as u64).saturating_mul(750_000),
                    )
                    .saturating_sub(failed_retrieval_receipts.saturating_mul(500));
                ArchiveOperatorScorecard {
                    provider_id: provider.provider_id,
                    provider_manifest_digest: provider.manifest_digest,
                    advertised_shard_count,
                    assigned_shard_count,
                    fulfilled_custody_count,
                    committed_custody_count,
                    missing_custody_commitment_count,
                    retention_surplus_epochs,
                    availability_bps,
                    service_success_bps,
                    successful_retrieval_receipts,
                    failed_retrieval_receipts,
                    served_checkpoint_batches,
                    served_checkpoint_segments,
                    served_archive_shards,
                    mean_checkpoint_latency_ms,
                    reward_weight,
                }
            })
            .collect()
    }

    pub fn operator_scorecard(
        &self,
        provider_id: &[u8; 32],
        replica_count: usize,
        retention_horizon_epochs: u64,
    ) -> Result<ArchiveOperatorScorecard> {
        self.operator_scorecards(replica_count, retention_horizon_epochs)
            .into_iter()
            .find(|scorecard| &scorecard.provider_id == provider_id)
            .ok_or_else(|| anyhow!("missing archive operator scorecard"))
    }

    fn derive_availability_certificates(
        &self,
        replica_count: usize,
        retention_horizon_epochs: u64,
    ) -> Vec<ArchiveAvailabilityCertificate> {
        let scorecards = self
            .operator_scorecards(replica_count, retention_horizon_epochs)
            .into_iter()
            .map(|scorecard| (scorecard.provider_id, scorecard))
            .collect::<BTreeMap<_, _>>();
        self.shards
            .iter()
            .map(|shard| {
                let mut certified_providers = self
                    .providers
                    .iter()
                    .filter(|provider| provider.serves_shard(shard.shard_id, &shard.root_digest))
                    .filter(|provider| {
                        let retention = self
                            .provider_retention_for_shard(&provider.provider_id, shard.shard_id);
                        let Some(scorecard) = scorecards.get(&provider.provider_id) else {
                            return false;
                        };
                        let required_retention =
                            shard.last_epoch.saturating_add(retention_horizon_epochs);
                        retention >= shard.last_epoch.saturating_add(retention_horizon_epochs)
                            && self.has_custody_commitment(
                                &provider.provider_id,
                                shard.shard_id,
                                required_retention,
                            )
                            && scorecard.availability_bps >= 9_000
                            && scorecard.service_success_bps >= 9_000
                    })
                    .map(|provider| provider.provider_id)
                    .collect::<Vec<_>>();
                certified_providers.sort();
                let certified_replica_count = certified_providers.len() as u32;
                let retention_through_epoch = certified_providers
                    .iter()
                    .map(|provider_id| {
                        self.provider_retention_for_shard(provider_id, shard.shard_id)
                    })
                    .max()
                    .unwrap_or(shard.last_epoch);
                let quorum_target = replica_count as u32;
                ArchiveAvailabilityCertificate::new(
                    shard.shard_id,
                    shard.root_digest,
                    certified_providers,
                    certified_replica_count,
                    quorum_target,
                    retention_through_epoch,
                )
            })
            .collect()
    }

    pub fn pick_provider_for_segment(
        &self,
        request_binding: &[u8; 32],
        from_epoch: u64,
        through_epoch: u64,
        rotation_round: u64,
        segment_index: u32,
        used_providers: &BTreeSet<[u8; 32]>,
        provider_loads: &BTreeMap<[u8; 32], usize>,
    ) -> Result<&ArchiveProviderManifest> {
        let range_shards = self
            .shards
            .iter()
            .filter(|shard| !(through_epoch < shard.first_epoch || from_epoch > shard.last_epoch))
            .collect::<Vec<_>>();
        let mut eligible = self.providers_covering_range(from_epoch, through_epoch)?;
        if eligible.is_empty() {
            bail!("no archive provider covers requested segment range");
        }
        eligible.sort_by_key(|provider| {
            let used_penalty = used_providers.contains(&provider.provider_id) as u8;
            let provider_load = *provider_loads.get(&provider.provider_id).unwrap_or(&0) as u32;
            let scorecard = self
                .operator_scorecard(
                    &provider.provider_id,
                    crate::protocol::CURRENT.archive_provider_replica_count as usize,
                    crate::protocol::CURRENT.archive_retention_horizon_epochs,
                )
                .ok();
            let min_replica_count = range_shards
                .iter()
                .filter_map(|shard| self.replica_report(shard.shard_id).ok())
                .map(|report| report.replica_count)
                .min()
                .unwrap_or(0);
            let min_retention = range_shards
                .iter()
                .map(|shard| {
                    self.provider_retention_for_shard(&provider.provider_id, shard.shard_id)
                })
                .min()
                .unwrap_or(through_epoch);
            let commitment_penalty = range_shards.iter().any(|shard| {
                let required_retention = shard
                    .last_epoch
                    .saturating_add(crate::protocol::CURRENT.archive_retention_horizon_epochs);
                !self.has_custody_commitment(
                    &provider.provider_id,
                    shard.shard_id,
                    required_retention,
                )
            }) as u8;
            let certificate_penalty = range_shards
                .iter()
                .filter_map(|shard| self.availability_certificate(shard.shard_id))
                .filter(|certificate| certificate.quorum_met)
                .any(|certificate| {
                    !certificate
                        .certified_providers
                        .contains(&provider.provider_id)
                }) as u8;
            (
                used_penalty,
                provider_load,
                commitment_penalty,
                certificate_penalty,
                u64::MAX.saturating_sub(scorecard.as_ref().map_or(0, |score| score.reward_weight)),
                u64::MAX.saturating_sub(min_retention),
                u32::MAX.saturating_sub(min_replica_count),
                provider_selection_score(
                    &provider.provider_id,
                    &provider.schedule_seed,
                    request_binding,
                    from_epoch,
                    through_epoch,
                    rotation_round ^ (segment_index as u64),
                ),
            )
        });
        Ok(eligible[0])
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
            let root = self
                .shards
                .iter()
                .find_map(|shard| {
                    shard
                        .epoch_roots
                        .iter()
                        .find(|(candidate_epoch, _)| *candidate_epoch == epoch)
                        .map(|(_, root)| *root)
                })
                .ok_or_else(|| anyhow!("missing archive shard root for epoch {}", epoch))?;
            pairs.push((epoch, root));
        }
        Ok(proof_core::historical_root_digest_from_pairs(&pairs))
    }

    pub fn provider_for_shard(
        &self,
        shard_id: u64,
        rotation_round: u64,
    ) -> Result<&ArchiveProviderManifest> {
        let shard = self
            .shard(shard_id)
            .ok_or_else(|| anyhow!("unknown archive shard {}", shard_id))?;
        let mut eligible = self
            .providers
            .iter()
            .filter(|provider| provider.serves_shard(shard_id, &shard.root_digest))
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            bail!("no archive provider serves shard {}", shard_id);
        }
        eligible.sort_by_key(|provider| {
            let retention = self.provider_retention_for_shard(&provider.provider_id, shard_id);
            let scorecard = self
                .operator_scorecard(
                    &provider.provider_id,
                    crate::protocol::CURRENT.archive_provider_replica_count as usize,
                    crate::protocol::CURRENT.archive_retention_horizon_epochs,
                )
                .ok();
            let required_retention = shard
                .last_epoch
                .saturating_add(crate::protocol::CURRENT.archive_retention_horizon_epochs);
            let commitment_penalty =
                !self.has_custody_commitment(&provider.provider_id, shard_id, required_retention)
                    as u8;
            let certificate_penalty = self
                .availability_certificate(shard_id)
                .map(|certificate| {
                    (certificate.quorum_met
                        && !certificate
                            .certified_providers
                            .contains(&provider.provider_id)) as u8
                })
                .unwrap_or(0);
            (
                commitment_penalty,
                certificate_penalty,
                u64::MAX.saturating_sub(scorecard.as_ref().map_or(0, |score| score.reward_weight)),
                u64::MAX.saturating_sub(retention),
                provider_selection_score(
                    &provider.provider_id,
                    &provider.schedule_seed,
                    &shard.root_digest,
                    shard.first_epoch,
                    shard.last_epoch,
                    rotation_round,
                ),
            )
        });
        Ok(eligible[0])
    }

    pub fn under_replicated_shards(&self, target_replica_count: u32) -> Vec<ArchiveShard> {
        self.shards
            .iter()
            .filter(|shard| {
                self.availability_certificate(shard.shard_id)
                    .map(|certificate| certificate.certified_replica_count < target_replica_count)
                    .or_else(|| {
                        self.replica_report(shard.shard_id)
                            .map(|report| report.replica_count < target_replica_count)
                            .ok()
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    pub fn custody_assignments(
        &self,
        candidate_nodes: &[[u8; 32]],
        replica_count: usize,
    ) -> Vec<ArchiveCustodyAssignment> {
        self.shards
            .iter()
            .map(|shard| ArchiveCustodyAssignment {
                shard_id: shard.shard_id,
                shard_digest: shard.root_digest,
                custodians: assigned_archive_custodians(
                    shard.shard_id,
                    &shard.root_digest,
                    candidate_nodes,
                    replica_count,
                ),
            })
            .collect()
    }

    pub fn shard_ids_covering_epochs(
        &self,
        epochs: &BTreeSet<u64>,
        available_epochs: &BTreeSet<u64>,
    ) -> Vec<u64> {
        let mut shard_ids = BTreeSet::new();
        for epoch in epochs {
            if available_epochs.contains(epoch) {
                continue;
            }
            if let Some(shard) = self
                .shards
                .iter()
                .find(|shard| *epoch >= shard.first_epoch && *epoch <= shard.last_epoch)
            {
                shard_ids.insert(shard.shard_id);
            }
        }
        shard_ids.into_iter().collect()
    }
}

pub fn local_archive_provider_manifest(
    provider_id: [u8; 32],
    ledger: &NullifierRootLedger,
    shard_span: u64,
    available_epochs: &BTreeSet<u64>,
) -> Result<ArchiveProviderManifest> {
    let shards = ArchiveDirectory::shards_from_root_ledger(ledger, shard_span)?
        .into_iter()
        .filter(|shard| {
            (shard.first_epoch..=shard.last_epoch).all(|epoch| available_epochs.contains(&epoch))
        })
        .collect::<Vec<_>>();
    Ok(ArchiveProviderManifest::new(provider_id, &shards))
}

pub fn local_archive_custody_commitments(
    provider_id: [u8; 32],
    directory: &ArchiveDirectory,
    replica_count: usize,
    retention_horizon_epochs: u64,
) -> Result<Vec<ArchiveCustodyCommitment>> {
    let provider = directory.provider(&provider_id)?;
    let candidate_nodes = directory
        .providers
        .iter()
        .map(|provider| provider.provider_id)
        .collect::<Vec<_>>();
    let assignments = directory.custody_assignments(&candidate_nodes, replica_count);
    Ok(assignments
        .into_iter()
        .filter(|assignment| assignment.custodians.contains(&provider_id))
        .filter_map(|assignment| {
            let shard = directory.shard(assignment.shard_id)?;
            let retention =
                directory.provider_retention_for_shard(&provider_id, assignment.shard_id);
            let required_retention = shard.last_epoch.saturating_add(retention_horizon_epochs);
            if retention < required_retention {
                return None;
            }
            Some(ArchiveCustodyCommitment::new(
                provider.provider_id,
                provider.manifest_digest,
                shard.shard_id,
                shard.root_digest,
                retention,
            ))
        })
        .collect())
}

pub fn local_archive_replica_attestations(
    provider_id: [u8; 32],
    directory: &ArchiveDirectory,
    retention_horizon_epochs: u64,
) -> Result<Vec<ArchiveReplicaAttestation>> {
    directory
        .providers
        .iter()
        .find(|provider| provider.provider_id == provider_id)
        .ok_or_else(|| anyhow!("missing local archive provider manifest"))?;
    directory
        .shards
        .iter()
        .filter(|shard| {
            directory
                .provider(&provider_id)
                .map(|provider| provider.serves_shard(shard.shard_id, &shard.root_digest))
                .unwrap_or(false)
        })
        .map(|shard| {
            ArchiveReplicaAttestation::new(
                provider_id,
                shard,
                shard.last_epoch.saturating_add(retention_horizon_epochs),
            )
        })
        .collect()
}

impl ArchiveShardBundle {
    pub fn validate(
        &self,
        manifest: &ArchiveProviderManifest,
        directory: &ArchiveDirectory,
    ) -> Result<()> {
        manifest.validate(directory)?;
        if self.provider_id != manifest.provider_id {
            bail!("archive shard bundle provider id mismatch");
        }
        if self.provider_manifest_digest != manifest.manifest_digest {
            bail!("archive shard bundle manifest digest mismatch");
        }
        if !manifest.serves_shard(self.shard.shard_id, &self.shard.root_digest) {
            bail!("archive shard bundle references an unserved shard");
        }
        let canonical_shard = directory
            .shard(self.shard.shard_id)
            .ok_or_else(|| anyhow!("archive shard bundle references unknown shard"))?;
        if canonical_shard != &self.shard {
            bail!("archive shard bundle shard descriptor mismatch");
        }
        if self.epochs.len() != canonical_shard.epoch_roots.len() {
            bail!("archive shard bundle epoch count mismatch");
        }
        for (archived, (epoch, root)) in self.epochs.iter().zip(&canonical_shard.epoch_roots) {
            if archived.epoch != *epoch {
                bail!("archive shard bundle epoch ordering mismatch");
            }
            if archived.root != *root {
                bail!("archive shard bundle epoch root mismatch");
            }
            archived.validate()?;
        }
        Ok(())
    }
}

pub fn route_checkpoint_requests(
    directory: &ArchiveDirectory,
    requests: &[CheckpointExtensionRequest],
    rotation_round: u64,
    min_batch_size: usize,
    max_batch_size: usize,
) -> Result<Vec<RoutedCheckpointBatch>> {
    if requests.is_empty() {
        return Ok(Vec::new());
    }

    let max_batch_size = max_batch_size.max(1);
    let min_batch_size = min_batch_size.max(1).min(max_batch_size);
    let mut routed = Vec::new();
    let mut segment_lengths_by_provider_shard = BTreeMap::<([u8; 32], u64), Vec<usize>>::new();
    let mut provider_loads = BTreeMap::<[u8; 32], usize>::new();

    for (request_index, request) in requests.iter().enumerate() {
        if request.queries.is_empty() {
            continue;
        }
        let mut segment_start = 0usize;
        let mut segment_index = 0u32;
        let mut used_providers = BTreeSet::new();
        while segment_start < request.queries.len() {
            let first_query = &request.queries[segment_start];
            let shard = directory.shard_for_epoch(first_query.epoch)?;
            let segment_shard_id = shard.shard_id;
            let mut segment_end = segment_start + 1;
            while segment_end < request.queries.len()
                && segment_end - segment_start < max_batch_size
                && directory
                    .shard_for_epoch(request.queries[segment_end].epoch)?
                    .shard_id
                    == segment_shard_id
            {
                segment_end += 1;
            }
            let segment_queries = request.queries[segment_start..segment_end].to_vec();
            let through_epoch = segment_queries
                .last()
                .map(|query| query.epoch)
                .ok_or_else(|| anyhow!("checkpoint segment is missing terminal epoch"))?;
            let segment_request =
                request.derive_segment_request(segment_queries.clone(), segment_index)?;
            let provider = directory.pick_provider_for_segment(
                &segment_request.request_binding(),
                segment_queries[0].epoch,
                through_epoch,
                rotation_round,
                segment_index,
                &used_providers,
                &provider_loads,
            )?;
            used_providers.insert(provider.provider_id);
            segment_lengths_by_provider_shard
                .entry((provider.provider_id, segment_shard_id))
                .or_default()
                .push(segment_request.queries.len());
            *provider_loads.entry(provider.provider_id).or_default() += 1;
            routed.push(RoutedCheckpointRequest {
                provider_id: provider.provider_id,
                request_index: Some(request_index),
                segment_index,
                shard_id: segment_shard_id,
                request: segment_request,
            });
            segment_index = segment_index.saturating_add(1);
            segment_start = segment_end;
        }
    }

    for ((provider_id, shard_id), segment_lengths) in segment_lengths_by_provider_shard {
        let shard = directory
            .shard(shard_id)
            .ok_or_else(|| anyhow!("missing archive shard {}", shard_id))?;
        let real_count = segment_lengths.len();
        let mut target_count = real_count.max(min_batch_size).next_power_of_two();
        target_count = target_count.min(max_batch_size.max(real_count));
        for cover_index in real_count..target_count {
            let available_span = shard
                .last_epoch
                .saturating_sub(shard.first_epoch)
                .saturating_add(1);
            let template_len = segment_lengths[cover_index % segment_lengths.len()].max(1);
            let cover_len = template_len.min(available_span as usize).max(1);
            let start_slots = available_span
                .saturating_sub(cover_len as u64)
                .saturating_add(1);
            let start_seed = synthetic_cover_digest(
                b"start",
                &provider_id,
                rotation_round ^ shard_id,
                shard.first_epoch,
                cover_index as u64,
            );
            let mut start_bytes = [0u8; 8];
            start_bytes.copy_from_slice(&start_seed[..8]);
            let cover_epoch =
                shard.first_epoch + (u64::from_le_bytes(start_bytes) % start_slots.max(1));
            let cover_queries = (0..cover_len)
                .map(|offset| {
                    let epoch = cover_epoch.saturating_add(offset as u64);
                    EvolvingNullifierQuery {
                        epoch,
                        nullifier: synthetic_cover_digest(
                            b"nullifier",
                            &provider_id,
                            rotation_round ^ shard_id,
                            epoch,
                            ((cover_index as u64) << 32) | (offset as u64),
                        ),
                    }
                })
                .collect::<Vec<_>>();
            let fake_commitment = synthetic_cover_digest(
                b"commitment",
                &provider_id,
                rotation_round ^ shard_id,
                cover_epoch,
                cover_index as u64,
            );
            let presentation_blinding = synthetic_cover_digest(
                b"presentation",
                &provider_id,
                rotation_round ^ shard_id,
                cover_epoch,
                cover_index as u64,
            );
            routed.push(RoutedCheckpointRequest {
                provider_id,
                request_index: None,
                segment_index: u32::MAX,
                shard_id,
                request: CheckpointExtensionRequest::new(
                    HistoricalUnspentCheckpoint::genesis(fake_commitment, cover_epoch),
                    cover_queries,
                    presentation_blinding,
                ),
            });
        }
    }

    let mut batches_by_provider = BTreeMap::<[u8; 32], Vec<RoutedCheckpointRequest>>::new();
    for routed_request in routed {
        batches_by_provider
            .entry(routed_request.provider_id)
            .or_default()
            .push(routed_request);
    }

    Ok(batches_by_provider
        .into_iter()
        .map(|(provider_id, mut requests)| {
            requests.sort_by_key(|request| {
                checkpoint_batch_order_key(&provider_id, rotation_round, request)
            });
            RoutedCheckpointBatch {
                provider_id,
                requests,
            }
        })
        .collect())
}

impl ShieldedSyncServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_archived_epoch(&mut self, archived: ArchivedNullifierEpoch) -> Result<()> {
        if self.epochs.contains_key(&archived.epoch) {
            bail!("nullifier epoch {} already archived", archived.epoch);
        }
        if let Some((&last_epoch, _)) = self.epochs.last_key_value() {
            if archived.epoch <= last_epoch {
                bail!("nullifier epochs must be archived in increasing order");
            }
        }
        self.ledger.remember_epoch(&archived);
        self.epochs.insert(archived.epoch, archived);
        Ok(())
    }

    pub fn archive_epoch(
        &mut self,
        epoch: u64,
        nullifiers: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<()> {
        self.insert_archived_epoch(ArchivedNullifierEpoch::new(epoch, nullifiers))
    }

    pub fn root_ledger(&self) -> &NullifierRootLedger {
        &self.ledger
    }

    pub fn epoch(&self, epoch: u64) -> Option<&ArchivedNullifierEpoch> {
        self.epochs.get(&epoch)
    }

    pub fn serve_checkpoint(
        &self,
        manifest: &ArchiveProviderManifest,
        checkpoint: &HistoricalUnspentCheckpoint,
        queries: &[EvolvingNullifierQuery],
    ) -> Result<HistoricalUnspentServiceResponse> {
        let mut responses = self.serve_checkpoints_batch(
            manifest,
            &[CheckpointExtensionRequest::new(
                checkpoint.clone(),
                queries.to_vec(),
                [0u8; 32],
            )],
        )?;
        responses
            .pop()
            .ok_or_else(|| anyhow!("missing checkpoint service response"))
    }

    pub fn serve_checkpoints_batch(
        &self,
        manifest: &ArchiveProviderManifest,
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
            let archived = self
                .epochs
                .get(&epoch)
                .ok_or_else(|| anyhow!("missing nullifier archive for epoch {}", epoch))?;
            let mut ordered_entries = entries;
            ordered_entries.sort_by_key(|(_, nullifier)| *nullifier);
            for (request_index, nullifier) in ordered_entries {
                let proof = archived.prove_absence(nullifier)?;
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

        Ok(pending
            .into_iter()
            .map(|pending_response| {
                Ok(HistoricalUnspentServiceResponse {
                    version: SHIELDED_EXTENSION_VERSION,
                    provider_id: manifest.provider_id,
                    provider_manifest_digest: manifest.manifest_digest,
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
            .collect::<Result<Vec<_>>>()?)
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

    pub fn archive(&self) -> Result<ArchivedNullifierEpoch> {
        self.validate()?;
        Ok(ArchivedNullifierEpoch::new(
            self.epoch,
            self.nullifiers.iter().copied(),
        ))
    }
}

pub fn note_key_commitment(note_key: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key(NOTE_KEY_COMMIT_DOMAIN)
        .update(note_key)
        .finalize()
        .as_bytes()
}

pub fn evolving_nullifier(
    note_key: &[u8; 32],
    rho: &[u8; 32],
    chain_id: &[u8; 32],
    epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NULLIFIER_DOMAIN);
    hasher.update(note_key);
    hasher.update(rho);
    hasher.update(chain_id);
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn note_leaf_hash(note_commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NOTE_LEAF_DOMAIN);
    hasher.update(note_commitment);
    *hasher.finalize().as_bytes()
}

pub fn nullifier_leaf_hash(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NULLIFIER_LEAF_DOMAIN);
    hasher.update(nullifier);
    *hasher.finalize().as_bytes()
}

fn compute_note_commitment(
    version: u8,
    value: u64,
    birth_epoch: u64,
    owner_address: &Address,
    owner_signing_pk: &TaggedSigningPublicKey,
    owner_kem_pk: &TaggedKemPublicKey,
    rho: &[u8; 32],
    note_randomizer: &[u8; 32],
    note_key_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NOTE_COMMIT_DOMAIN);
    hasher.update(&[version]);
    hasher.update(&value.to_le_bytes());
    hasher.update(&birth_epoch.to_le_bytes());
    hasher.update(owner_address);
    hasher.update(&owner_signing_pk.bytes);
    hasher.update(&owner_kem_pk.bytes);
    hasher.update(rho);
    hasher.update(note_randomizer);
    hasher.update(note_key_commitment);
    *hasher.finalize().as_bytes()
}

fn checkpoint_base_root(note_commitment: &[u8; 32], birth_epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_BASE_DOMAIN);
    hasher.update(note_commitment);
    hasher.update(&birth_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn checkpoint_segment_base_root(note_commitment: &[u8; 32], from_epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_SEGMENT_BASE_DOMAIN);
    hasher.update(note_commitment);
    hasher.update(&from_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn checkpoint_service_root(
    prior_root: &[u8; 32],
    epoch: u64,
    nullifier: &[u8; 32],
    proof_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_SERVICE_DOMAIN);
    hasher.update(prior_root);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(nullifier);
    hasher.update(proof_digest);
    *hasher.finalize().as_bytes()
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
    provider_id: &[u8; 32],
    provider_manifest_digest: &[u8; 32],
    historical_root_digest: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_RERANDOMIZE_DOMAIN);
    hasher.update(service_root);
    hasher.update(provider_id);
    hasher.update(provider_manifest_digest);
    hasher.update(historical_root_digest);
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

fn checkpoint_segment_commitment_digest(
    provider_id: &[u8; 32],
    provider_manifest_digest: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    segment_transcript_root: &[u8; 32],
    record_count: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_SEGMENT_COMMIT_DOMAIN);
    hasher.update(provider_id);
    hasher.update(provider_manifest_digest);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(segment_transcript_root);
    hasher.update(&record_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn checkpoint_segment_commitment_root(segment_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_SEGMENT_COMMIT_DOMAIN);
    hasher.update(&(segment_digests.len() as u32).to_le_bytes());
    for digest in segment_digests {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn checkpoint_packet_commitment_digest(
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    segment_commitment_root: &[u8; 32],
    packet_transcript_root: &[u8; 32],
    segment_count: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_PACKET_COMMIT_DOMAIN);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(segment_commitment_root);
    hasher.update(packet_transcript_root);
    hasher.update(&segment_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn checkpoint_packet_commitment_root(packet_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_PACKET_COMMIT_DOMAIN);
    hasher.update(&(packet_digests.len() as u32).to_le_bytes());
    for digest in packet_digests {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn accumulated_packet_root(
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    segment_commitment_root: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_PACKET_ACCUMULATE_DOMAIN);
    hasher.update(note_commitment);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(segment_commitment_root);
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

fn checkpoint_stratum_commitment_digest(
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    packet_commitment_root: &[u8; 32],
    stratum_transcript_root: &[u8; 32],
    packet_count: u32,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_STRATUM_COMMIT_DOMAIN);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(packet_commitment_root);
    hasher.update(stratum_transcript_root);
    hasher.update(&packet_count.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn checkpoint_stratum_commitment_root(stratum_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_STRATUM_COMMIT_DOMAIN);
    hasher.update(&(stratum_digests.len() as u32).to_le_bytes());
    for digest in stratum_digests {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn accumulated_stratum_root(
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    packet_commitment_root: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_STRATUM_ACCUMULATE_DOMAIN);
    hasher.update(note_commitment);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(packet_commitment_root);
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
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
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_EXTENSION_ACCUMULATE_DOMAIN);
    hasher.update(prior_transcript_root);
    hasher.update(note_commitment);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(stratum_commitment_root);
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

fn archive_shard_digest(shard_id: u64, epoch_roots: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_SHARD_DOMAIN);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(&(epoch_roots.len() as u32).to_le_bytes());
    for (epoch, root) in epoch_roots {
        hasher.update(&epoch.to_le_bytes());
        hasher.update(root);
    }
    *hasher.finalize().as_bytes()
}

fn archive_replica_attestation_digest(
    provider_id: &[u8; 32],
    shard_id: u64,
    shard_digest: &[u8; 32],
    first_epoch: u64,
    last_epoch: u64,
    retention_through_epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_REPLICA_ATTEST_DOMAIN);
    hasher.update(provider_id);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(shard_digest);
    hasher.update(&first_epoch.to_le_bytes());
    hasher.update(&last_epoch.to_le_bytes());
    hasher.update(&retention_through_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn archive_service_ledger_digest(
    provider_id: &[u8; 32],
    provider_manifest_digest: &[u8; 32],
    served_checkpoint_batches: u64,
    served_checkpoint_segments: u64,
    served_archive_shards: u64,
    failed_checkpoint_batches: u64,
    failed_archive_shards: u64,
    total_checkpoint_latency_ms: u64,
    last_success_unix_ms: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_SERVICE_LEDGER_DOMAIN);
    hasher.update(provider_id);
    hasher.update(provider_manifest_digest);
    hasher.update(&served_checkpoint_batches.to_le_bytes());
    hasher.update(&served_checkpoint_segments.to_le_bytes());
    hasher.update(&served_archive_shards.to_le_bytes());
    hasher.update(&failed_checkpoint_batches.to_le_bytes());
    hasher.update(&failed_archive_shards.to_le_bytes());
    hasher.update(&total_checkpoint_latency_ms.to_le_bytes());
    hasher.update(&last_success_unix_ms.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn archive_custody_commitment_digest(
    provider_id: &[u8; 32],
    provider_manifest_digest: &[u8; 32],
    shard_id: u64,
    shard_digest: &[u8; 32],
    retention_through_epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_CUSTODY_COMMITMENT_DOMAIN);
    hasher.update(provider_id);
    hasher.update(provider_manifest_digest);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(shard_digest);
    hasher.update(&retention_through_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn archive_availability_certificate_digest(
    shard_id: u64,
    shard_digest: &[u8; 32],
    certified_providers: &[[u8; 32]],
    certified_replica_count: u32,
    quorum_target: u32,
    quorum_met: bool,
    retention_through_epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_AVAILABILITY_CERT_DOMAIN);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(shard_digest);
    hasher.update(&(certified_providers.len() as u32).to_le_bytes());
    for provider_id in certified_providers {
        hasher.update(provider_id);
    }
    hasher.update(&certified_replica_count.to_le_bytes());
    hasher.update(&quorum_target.to_le_bytes());
    hasher.update(&[quorum_met as u8]);
    hasher.update(&retention_through_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn archive_retrieval_receipt_digest(
    requester_id: &[u8; 32],
    provider_id: &[u8; 32],
    provider_manifest_digest: &[u8; 32],
    retrieval_kind: ArchiveRetrievalKind,
    request_message_id: &[u8; 32],
    response_message_id: &Option<[u8; 32]>,
    from_epoch: u64,
    through_epoch: u64,
    shard_id: &Option<u64>,
    served_units: u32,
    success: bool,
    latency_ms: u64,
    observed_unix_ms: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_RETRIEVAL_RECEIPT_DOMAIN);
    hasher.update(requester_id);
    hasher.update(provider_id);
    hasher.update(provider_manifest_digest);
    hasher.update(&[match retrieval_kind {
        ArchiveRetrievalKind::CheckpointBatch => 1,
        ArchiveRetrievalKind::ArchiveShard => 2,
    }]);
    hasher.update(request_message_id);
    match response_message_id {
        Some(message_id) => {
            hasher.update(&[1]);
            hasher.update(message_id);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    match shard_id {
        Some(shard_id) => {
            hasher.update(&[1]);
            hasher.update(&shard_id.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&served_units.to_le_bytes());
    hasher.update(&[success as u8]);
    hasher.update(&latency_ms.to_le_bytes());
    hasher.update(&observed_unix_ms.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn archive_provider_manifest_digest(
    provider_id: &[u8; 32],
    schedule_seed: &[u8; 32],
    coverage_first_epoch: u64,
    coverage_last_epoch: u64,
    shard_ids: &[u64],
    shard_digests: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_PROVIDER_MANIFEST_DOMAIN);
    hasher.update(provider_id);
    hasher.update(schedule_seed);
    hasher.update(&coverage_first_epoch.to_le_bytes());
    hasher.update(&coverage_last_epoch.to_le_bytes());
    hasher.update(&(shard_ids.len() as u32).to_le_bytes());
    for (shard_id, shard_digest) in shard_ids.iter().zip(shard_digests) {
        hasher.update(&shard_id.to_le_bytes());
        hasher.update(shard_digest);
    }
    *hasher.finalize().as_bytes()
}

fn checkpoint_batch_order_key(
    provider_id: &[u8; 32],
    rotation_round: u64,
    request: &RoutedCheckpointRequest,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_BATCH_ORDER_DOMAIN);
    hasher.update(provider_id);
    hasher.update(&rotation_round.to_le_bytes());
    match request.request_index {
        Some(index) => {
            hasher.update(&[1]);
            hasher.update(&(index as u64).to_le_bytes());
            hasher.update(&request.segment_index.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&request.shard_id.to_le_bytes());
    hasher.update(&request.request.request_binding());
    hasher.update(
        &request
            .request
            .presentation
            .covered_through_epoch
            .to_le_bytes(),
    );
    if let Some(first) = request.request.queries.first() {
        hasher.update(&first.epoch.to_le_bytes());
        hasher.update(&first.nullifier);
    }
    if let Some(last) = request.request.queries.last() {
        hasher.update(&last.epoch.to_le_bytes());
        hasher.update(&last.nullifier);
    }
    *hasher.finalize().as_bytes()
}

fn archive_provider_schedule_seed(
    provider_id: &[u8; 32],
    shard_ids: &[u64],
    shard_digests: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_PROVIDER_MANIFEST_DOMAIN);
    hasher.update(b"provider-seed");
    hasher.update(provider_id);
    hasher.update(&(shard_ids.len() as u32).to_le_bytes());
    for (shard_id, shard_digest) in shard_ids.iter().zip(shard_digests) {
        hasher.update(&shard_id.to_le_bytes());
        hasher.update(shard_digest);
    }
    *hasher.finalize().as_bytes()
}

fn provider_selection_score(
    provider_id: &[u8; 32],
    schedule_seed: &[u8; 32],
    request_binding: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    rotation_round: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_PROVIDER_SELECT_DOMAIN);
    hasher.update(provider_id);
    hasher.update(schedule_seed);
    hasher.update(request_binding);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(&rotation_round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn synthetic_cover_digest(
    label: &[u8],
    provider_id: &[u8; 32],
    rotation_round: u64,
    epoch: u64,
    slot: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_PROVIDER_SELECT_DOMAIN);
    hasher.update(label);
    hasher.update(provider_id);
    hasher.update(&rotation_round.to_le_bytes());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&slot.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn archive_custody_score(node_id: &[u8; 32], shard_id: u64, shard_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_CUSTODY_ASSIGN_DOMAIN);
    hasher.update(node_id);
    hasher.update(&shard_id.to_le_bytes());
    hasher.update(shard_digest);
    *hasher.finalize().as_bytes()
}

pub fn assigned_archive_custodians(
    shard_id: u64,
    shard_digest: &[u8; 32],
    candidate_nodes: &[[u8; 32]],
    replica_count: usize,
) -> Vec<[u8; 32]> {
    let mut candidates = candidate_nodes.to_vec();
    candidates.sort();
    candidates.dedup();
    candidates.sort_by_key(|node_id| archive_custody_score(node_id, shard_id, shard_digest));
    candidates.into_iter().take(replica_count.max(1)).collect()
}

impl ArchiveReplicaAttestation {
    pub fn new(
        provider_id: [u8; 32],
        shard: &ArchiveShard,
        retention_through_epoch: u64,
    ) -> Result<Self> {
        if retention_through_epoch < shard.last_epoch {
            bail!("archive replica retention horizon cannot precede the shard coverage");
        }
        Ok(Self {
            provider_id,
            shard_id: shard.shard_id,
            shard_digest: shard.root_digest,
            first_epoch: shard.first_epoch,
            last_epoch: shard.last_epoch,
            retention_through_epoch,
            attestation_digest: archive_replica_attestation_digest(
                &provider_id,
                shard.shard_id,
                &shard.root_digest,
                shard.first_epoch,
                shard.last_epoch,
                retention_through_epoch,
            ),
        })
    }

    pub fn validate(&self, directory: &ArchiveDirectory) -> Result<()> {
        let manifest = directory.provider(&self.provider_id)?;
        let shard = directory
            .shard(self.shard_id)
            .ok_or_else(|| anyhow!("unknown archive shard {}", self.shard_id))?;
        if !manifest.serves_shard(self.shard_id, &self.shard_digest) {
            bail!("archive replica attestation references an unserved shard");
        }
        if shard.root_digest != self.shard_digest {
            bail!("archive replica attestation shard digest mismatch");
        }
        if shard.first_epoch != self.first_epoch || shard.last_epoch != self.last_epoch {
            bail!("archive replica attestation shard coverage mismatch");
        }
        if self.attestation_digest
            != archive_replica_attestation_digest(
                &self.provider_id,
                self.shard_id,
                &self.shard_digest,
                self.first_epoch,
                self.last_epoch,
                self.retention_through_epoch,
            )
        {
            bail!("archive replica attestation digest mismatch");
        }
        Ok(())
    }
}

impl ArchiveServiceLedger {
    pub fn new(provider_id: [u8; 32], provider_manifest_digest: [u8; 32]) -> Self {
        let mut ledger = Self {
            provider_id,
            provider_manifest_digest,
            served_checkpoint_batches: 0,
            served_checkpoint_segments: 0,
            served_archive_shards: 0,
            failed_checkpoint_batches: 0,
            failed_archive_shards: 0,
            total_checkpoint_latency_ms: 0,
            last_success_unix_ms: 0,
            ledger_digest: [0u8; 32],
        };
        ledger.refresh_digest();
        ledger
    }

    pub fn validate(&self) -> Result<()> {
        if self.ledger_digest
            != archive_service_ledger_digest(
                &self.provider_id,
                &self.provider_manifest_digest,
                self.served_checkpoint_batches,
                self.served_checkpoint_segments,
                self.served_archive_shards,
                self.failed_checkpoint_batches,
                self.failed_archive_shards,
                self.total_checkpoint_latency_ms,
                self.last_success_unix_ms,
            )
        {
            bail!("archive service ledger digest mismatch");
        }
        Ok(())
    }

    pub fn record_checkpoint_success(
        &mut self,
        segment_count: u64,
        latency_ms: u64,
        observed_unix_ms: u64,
    ) {
        self.served_checkpoint_batches = self.served_checkpoint_batches.saturating_add(1);
        self.served_checkpoint_segments = self
            .served_checkpoint_segments
            .saturating_add(segment_count);
        self.total_checkpoint_latency_ms =
            self.total_checkpoint_latency_ms.saturating_add(latency_ms);
        self.last_success_unix_ms = observed_unix_ms.max(self.last_success_unix_ms);
        self.refresh_digest();
    }

    pub fn record_checkpoint_failure(&mut self) {
        self.failed_checkpoint_batches = self.failed_checkpoint_batches.saturating_add(1);
        self.refresh_digest();
    }

    pub fn record_archive_shard_success(&mut self, shard_count: u64, observed_unix_ms: u64) {
        self.served_archive_shards = self.served_archive_shards.saturating_add(shard_count);
        self.last_success_unix_ms = observed_unix_ms.max(self.last_success_unix_ms);
        self.refresh_digest();
    }

    pub fn record_archive_shard_failure(&mut self) {
        self.failed_archive_shards = self.failed_archive_shards.saturating_add(1);
        self.refresh_digest();
    }

    pub fn success_bps(&self) -> u16 {
        let successes = self
            .served_checkpoint_batches
            .saturating_add(self.served_archive_shards);
        let failures = self
            .failed_checkpoint_batches
            .saturating_add(self.failed_archive_shards);
        let total = successes.saturating_add(failures);
        if total == 0 {
            10_000
        } else {
            ((successes.saturating_mul(10_000)) / total).min(10_000) as u16
        }
    }

    pub fn mean_checkpoint_latency_ms(&self) -> u32 {
        if self.served_checkpoint_batches == 0 {
            0
        } else {
            (self.total_checkpoint_latency_ms / self.served_checkpoint_batches).min(u32::MAX as u64)
                as u32
        }
    }

    fn refresh_digest(&mut self) {
        self.ledger_digest = archive_service_ledger_digest(
            &self.provider_id,
            &self.provider_manifest_digest,
            self.served_checkpoint_batches,
            self.served_checkpoint_segments,
            self.served_archive_shards,
            self.failed_checkpoint_batches,
            self.failed_archive_shards,
            self.total_checkpoint_latency_ms,
            self.last_success_unix_ms,
        );
    }
}

impl ArchiveCustodyCommitment {
    pub fn new(
        provider_id: [u8; 32],
        provider_manifest_digest: [u8; 32],
        shard_id: u64,
        shard_digest: [u8; 32],
        retention_through_epoch: u64,
    ) -> Self {
        Self {
            provider_id,
            provider_manifest_digest,
            shard_id,
            shard_digest,
            retention_through_epoch,
            commitment_digest: archive_custody_commitment_digest(
                &provider_id,
                &provider_manifest_digest,
                shard_id,
                &shard_digest,
                retention_through_epoch,
            ),
        }
    }

    pub fn validate(&self, directory: &ArchiveDirectory) -> Result<()> {
        let provider = directory.provider(&self.provider_id)?;
        if provider.manifest_digest != self.provider_manifest_digest {
            bail!("archive custody commitment manifest digest mismatch");
        }
        let shard = directory
            .shard(self.shard_id)
            .ok_or_else(|| anyhow!("unknown archive shard {}", self.shard_id))?;
        if shard.root_digest != self.shard_digest {
            bail!("archive custody commitment shard digest mismatch");
        }
        if !provider.serves_shard(self.shard_id, &self.shard_digest) {
            bail!("archive custody commitment references an unserved shard");
        }
        if directory.provider_retention_for_shard(&self.provider_id, self.shard_id)
            < self.retention_through_epoch
        {
            bail!("archive custody commitment exceeds replica retention");
        }
        if self.commitment_digest
            != archive_custody_commitment_digest(
                &self.provider_id,
                &self.provider_manifest_digest,
                self.shard_id,
                &self.shard_digest,
                self.retention_through_epoch,
            )
        {
            bail!("archive custody commitment digest mismatch");
        }
        Ok(())
    }
}

impl ArchiveRetrievalReceipt {
    pub fn new(
        requester_id: [u8; 32],
        provider_id: [u8; 32],
        provider_manifest_digest: [u8; 32],
        retrieval_kind: ArchiveRetrievalKind,
        request_message_id: [u8; 32],
        response_message_id: Option<[u8; 32]>,
        from_epoch: u64,
        through_epoch: u64,
        shard_id: Option<u64>,
        served_units: u32,
        success: bool,
        latency_ms: u64,
        observed_unix_ms: u64,
    ) -> Self {
        Self {
            requester_id,
            provider_id,
            provider_manifest_digest,
            retrieval_kind,
            request_message_id,
            response_message_id,
            from_epoch,
            through_epoch,
            shard_id,
            served_units,
            success,
            latency_ms,
            observed_unix_ms,
            receipt_digest: archive_retrieval_receipt_digest(
                &requester_id,
                &provider_id,
                &provider_manifest_digest,
                retrieval_kind,
                &request_message_id,
                &response_message_id,
                from_epoch,
                through_epoch,
                &shard_id,
                served_units,
                success,
                latency_ms,
                observed_unix_ms,
            ),
        }
    }

    pub fn validate(&self, directory: &ArchiveDirectory) -> Result<()> {
        let provider = directory.provider(&self.provider_id)?;
        if provider.manifest_digest != self.provider_manifest_digest {
            bail!("archive retrieval receipt manifest digest mismatch");
        }
        if self.from_epoch > self.through_epoch {
            bail!("archive retrieval receipt range is inverted");
        }
        if self.success {
            if self.served_units == 0 {
                bail!("successful archive retrieval receipt must serve at least one unit");
            }
            if self.response_message_id.is_none() {
                bail!("successful archive retrieval receipt must bind a response message");
            }
        } else if self.response_message_id.is_some() {
            bail!("failed archive retrieval receipt cannot bind a response message");
        }
        match self.retrieval_kind {
            ArchiveRetrievalKind::CheckpointBatch => {
                if self.shard_id.is_some() {
                    bail!("checkpoint retrieval receipt must not name a shard");
                }
                if !provider.covers_range(directory, self.from_epoch, self.through_epoch)? {
                    bail!("checkpoint retrieval receipt references an uncovered range");
                }
            }
            ArchiveRetrievalKind::ArchiveShard => {
                let shard_id = self
                    .shard_id
                    .ok_or_else(|| anyhow!("archive-shard receipt is missing the shard id"))?;
                let shard = directory
                    .shard(shard_id)
                    .ok_or_else(|| anyhow!("unknown archive shard {}", shard_id))?;
                if shard.first_epoch != self.from_epoch || shard.last_epoch != self.through_epoch {
                    bail!("archive-shard receipt range does not match the shard");
                }
                if !provider.serves_shard(shard_id, &shard.root_digest) {
                    bail!("archive-shard receipt references an unserved shard");
                }
            }
        }
        if self.receipt_digest
            != archive_retrieval_receipt_digest(
                &self.requester_id,
                &self.provider_id,
                &self.provider_manifest_digest,
                self.retrieval_kind,
                &self.request_message_id,
                &self.response_message_id,
                self.from_epoch,
                self.through_epoch,
                &self.shard_id,
                self.served_units,
                self.success,
                self.latency_ms,
                self.observed_unix_ms,
            )
        {
            bail!("archive retrieval receipt digest mismatch");
        }
        Ok(())
    }
}

impl ArchiveAvailabilityCertificate {
    pub fn new(
        shard_id: u64,
        shard_digest: [u8; 32],
        mut certified_providers: Vec<[u8; 32]>,
        certified_replica_count: u32,
        quorum_target: u32,
        retention_through_epoch: u64,
    ) -> Self {
        certified_providers.sort();
        certified_providers.dedup();
        let quorum_met = certified_replica_count >= quorum_target.max(1);
        let certificate_digest = archive_availability_certificate_digest(
            shard_id,
            &shard_digest,
            &certified_providers,
            certified_replica_count,
            quorum_target,
            quorum_met,
            retention_through_epoch,
        );
        Self {
            shard_id,
            shard_digest,
            certified_providers,
            certified_replica_count,
            quorum_target,
            quorum_met,
            retention_through_epoch,
            certificate_digest,
        }
    }
}

fn hash_optional_membership(
    hasher: &mut blake3::Hasher,
    witness: &Option<NullifierMembershipWitness>,
) {
    match witness {
        Some(witness) => {
            hasher.update(&[1]);
            hasher.update(&witness.nullifier);
            hasher.update(&witness.root);
            hasher.update(&(witness.proof.len() as u32).to_le_bytes());
            for (hash, sibling_is_left) in &witness.proof {
                hasher.update(hash);
                hasher.update(&[*sibling_is_left as u8]);
            }
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
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
            next.push(hash_pair(&pair[0], right));
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
        let parent = hash_pair(&left, &right);
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
            let expected = hash_pair(&pair[0], right);
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
