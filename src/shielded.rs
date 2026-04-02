use anyhow::{anyhow, bail, Result};
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
const CHECKPOINT_SERVICE_DOMAIN: &str = "unchained-shielded-checkpoint-service-v1";
const CHECKPOINT_RERANDOMIZE_DOMAIN: &str = "unchained-shielded-checkpoint-rerandomize-v1";
const PRESENTATION_DOMAIN: &str = "unchained-shielded-presentation-v1";
const ARCHIVE_SHARD_DOMAIN: &str = "unchained-shielded-archive-shard-v1";
const ARCHIVE_PROVIDER_MANIFEST_DOMAIN: &str = "unchained-shielded-archive-provider-v1";
const ARCHIVE_PROVIDER_SELECT_DOMAIN: &str = "unchained-shielded-archive-select-v1";
const ARCHIVE_BATCH_ORDER_DOMAIN: &str = "unchained-shielded-archive-batch-order-v1";
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
    pub note_commitment: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub prior_transcript_root: [u8; 32],
    pub service_transcript_root: [u8; 32],
    pub historical_root_digest: [u8; 32],
    pub records: Vec<HistoricalAbsenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentExtension {
    pub version: u8,
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
    pub note_commitment: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub prior_transcript_root: [u8; 32],
    pub service_transcript_root: [u8; 32],
    pub historical_root_digest: [u8; 32],
    pub rerandomization_blinding: [u8; 32],
    pub new_transcript_root: [u8; 32],
    pub records: Vec<HistoricalAbsenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPresentation {
    pub checkpoint: HistoricalUnspentCheckpoint,
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
    pub checkpoint: HistoricalUnspentCheckpoint,
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
        let mut hasher = blake3::Hasher::new_derive_key(PRESENTATION_DOMAIN);
        hasher.update(&self.transcript_root);
        hasher.update(&blinding);
        CheckpointPresentation {
            checkpoint: self.clone(),
            blinding,
            presentation_digest: *hasher.finalize().as_bytes(),
        }
    }

    pub fn empty_extension(&self) -> HistoricalUnspentExtension {
        HistoricalUnspentExtension {
            version: SHIELDED_EXTENSION_VERSION,
            provider_id: [0u8; 32],
            provider_manifest_digest: [0u8; 32],
            note_commitment: self.note_commitment,
            from_epoch: self.covered_through_epoch.saturating_add(1),
            through_epoch: self.covered_through_epoch,
            prior_transcript_root: self.transcript_root,
            service_transcript_root: self.transcript_root,
            historical_root_digest: proof_core::historical_root_digest_from_pairs(&[]),
            rerandomization_blinding: [0u8; 32],
            new_transcript_root: self.transcript_root,
            records: Vec::new(),
        }
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
        if extension.records.is_empty() {
            if extension.from_epoch != expected_from {
                bail!("empty extension starts at the wrong epoch");
            }
            if extension.through_epoch != self.covered_through_epoch {
                bail!("empty extension cannot advance the checkpoint range");
            }
            if extension.service_transcript_root != self.transcript_root {
                bail!("empty extension must preserve the service transcript root");
            }
            if extension.new_transcript_root != self.transcript_root {
                bail!("empty extension must preserve the transcript root");
            }
            return Ok(self.clone());
        }

        if extension.from_epoch != expected_from {
            bail!("extension does not continue from the prior checkpoint");
        }

        let mut service_transcript_root = self.transcript_root;
        let mut expected_epoch = extension.from_epoch;
        let mut historical_roots = Vec::with_capacity(extension.records.len());
        for record in &extension.records {
            if record.epoch != expected_epoch {
                bail!("extension epochs must be contiguous");
            }
            if record.nullifier != record.proof.queried_nullifier {
                bail!("extension record nullifier does not match the proof");
            }
            let root = ledger.root_for_epoch(record.epoch)?;
            if root != record.proof.root {
                bail!("extension proof root does not match the historical root ledger");
            }
            record.proof.verify()?;
            historical_roots.push((record.epoch, root));
            service_transcript_root = checkpoint_service_root(
                &service_transcript_root,
                record.epoch,
                &record.nullifier,
                &record.proof.digest(),
            );
            expected_epoch = expected_epoch.saturating_add(1);
        }

        if extension.through_epoch != expected_epoch.saturating_sub(1) {
            bail!("extension through_epoch does not match the proof payload");
        }
        let expected_historical_root_digest =
            proof_core::historical_root_digest_from_pairs(&historical_roots);
        if extension.historical_root_digest != expected_historical_root_digest {
            bail!("extension historical root digest mismatch");
        }
        if extension.service_transcript_root != service_transcript_root {
            bail!("extension service transcript root mismatch");
        }
        let rerandomized_root = rerandomized_checkpoint_root(
            &extension.service_transcript_root,
            &extension.provider_id,
            &extension.provider_manifest_digest,
            &extension.historical_root_digest,
            &extension.rerandomization_blinding,
        );
        if extension.new_transcript_root != rerandomized_root {
            bail!("extension transcript root mismatch");
        }

        let additional = u32::try_from(extension.records.len())
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

impl HistoricalUnspentServiceResponse {
    pub fn rerandomize(&self, blinding: [u8; 32]) -> HistoricalUnspentExtension {
        HistoricalUnspentExtension {
            version: self.version,
            provider_id: self.provider_id,
            provider_manifest_digest: self.provider_manifest_digest,
            note_commitment: self.note_commitment,
            from_epoch: self.from_epoch,
            through_epoch: self.through_epoch,
            prior_transcript_root: self.prior_transcript_root,
            service_transcript_root: self.service_transcript_root,
            historical_root_digest: self.historical_root_digest,
            rerandomization_blinding: blinding,
            new_transcript_root: rerandomized_checkpoint_root(
                &self.service_transcript_root,
                &self.provider_id,
                &self.provider_manifest_digest,
                &self.historical_root_digest,
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
        if !manifest.covers_range(directory, self.from_epoch, self.through_epoch)? {
            bail!("archive provider manifest does not cover the requested epoch range");
        }
        let expected_historical_root_digest =
            directory.historical_root_digest_for_range(self.from_epoch, self.through_epoch)?;
        if self.historical_root_digest != expected_historical_root_digest {
            bail!("service response historical root digest mismatch");
        }
        Ok(())
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
            let expected_from = request.checkpoint.covered_through_epoch.saturating_add(1);
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
    pub fn verify(&self) -> bool {
        let mut hasher = blake3::Hasher::new_derive_key(PRESENTATION_DOMAIN);
        hasher.update(&self.checkpoint.transcript_root);
        hasher.update(&self.blinding);
        *hasher.finalize().as_bytes() == self.presentation_digest
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
        let shards = Self::shards_from_root_ledger(ledger, shard_span)?;
        let validation_directory = Self {
            shard_span,
            shards: shards.clone(),
            providers: Vec::new(),
        };
        let providers = providers
            .into_iter()
            .filter(|provider| provider.validate(&validation_directory).is_ok())
            .collect();
        Ok(Self {
            shard_span,
            shards,
            providers,
        })
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
        eligible.sort_by_key(|provider| {
            provider_selection_score(
                &provider.provider_id,
                &provider.schedule_seed,
                &checkpoint.note_commitment,
                from_epoch,
                through_epoch,
                rotation_round,
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
            provider_selection_score(
                &provider.provider_id,
                &provider.schedule_seed,
                &shard.root_digest,
                shard.first_epoch,
                shard.last_epoch,
                rotation_round,
            )
        });
        Ok(eligible[0])
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
    let mut counts_by_provider_epoch = BTreeMap::<([u8; 32], u64), usize>::new();

    for (request_index, request) in requests.iter().enumerate() {
        if request.queries.is_empty() {
            continue;
        }
        let through_epoch = request
            .queries
            .last()
            .map(|query| query.epoch)
            .ok_or_else(|| anyhow!("checkpoint request is missing a terminal epoch"))?;
        let provider =
            directory.pick_provider(&request.checkpoint, through_epoch, rotation_round)?;
        for query in &request.queries {
            *counts_by_provider_epoch
                .entry((provider.provider_id, query.epoch))
                .or_default() += 1;
        }
        routed.push(RoutedCheckpointRequest {
            provider_id: provider.provider_id,
            request_index: Some(request_index),
            request: request.clone(),
        });
    }

    for ((provider_id, epoch), real_count) in counts_by_provider_epoch {
        let mut target_count = real_count.max(min_batch_size).next_power_of_two();
        target_count = target_count.min(max_batch_size.max(real_count));
        for cover_index in real_count..target_count {
            let fake_commitment = synthetic_cover_digest(
                b"commitment",
                &provider_id,
                rotation_round,
                epoch,
                cover_index as u64,
            );
            let fake_nullifier = synthetic_cover_digest(
                b"nullifier",
                &provider_id,
                rotation_round,
                epoch,
                cover_index as u64,
            );
            routed.push(RoutedCheckpointRequest {
                provider_id,
                request_index: None,
                request: CheckpointExtensionRequest {
                    checkpoint: HistoricalUnspentCheckpoint::genesis(fake_commitment, epoch),
                    queries: vec![EvolvingNullifierQuery {
                        epoch,
                        nullifier: fake_nullifier,
                    }],
                },
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
            &[CheckpointExtensionRequest {
                checkpoint: checkpoint.clone(),
                queries: queries.to_vec(),
            }],
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
            note_commitment: [u8; 32],
            from_epoch: u64,
            through_epoch: u64,
            prior_transcript_root: [u8; 32],
            service_transcript_root: [u8; 32],
            historical_roots: Vec<(u64, [u8; 32])>,
            records: Vec<HistoricalAbsenceRecord>,
        }

        let mut pending = Vec::with_capacity(requests.len());
        let mut epoch_queries: BTreeMap<u64, Vec<(usize, [u8; 32])>> = BTreeMap::new();

        for (request_index, request) in requests.iter().enumerate() {
            let expected_from = request.checkpoint.covered_through_epoch.saturating_add(1);
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
                note_commitment: request.checkpoint.note_commitment,
                from_epoch: expected_from,
                through_epoch: request.checkpoint.covered_through_epoch,
                prior_transcript_root: request.checkpoint.transcript_root,
                service_transcript_root: request.checkpoint.transcript_root,
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
                pending_response.service_transcript_root = checkpoint_service_root(
                    &pending_response.service_transcript_root,
                    epoch,
                    &nullifier,
                    &proof.digest(),
                );
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
            .map(|pending_response| HistoricalUnspentServiceResponse {
                version: SHIELDED_EXTENSION_VERSION,
                provider_id: manifest.provider_id,
                provider_manifest_digest: manifest.manifest_digest,
                note_commitment: pending_response.note_commitment,
                from_epoch: pending_response.from_epoch,
                through_epoch: pending_response.through_epoch,
                prior_transcript_root: pending_response.prior_transcript_root,
                service_transcript_root: pending_response.service_transcript_root,
                historical_root_digest: proof_core::historical_root_digest_from_pairs(
                    &pending_response.historical_roots,
                ),
                records: pending_response.records,
            })
            .collect())
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

fn rerandomized_checkpoint_root(
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
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&request.request.checkpoint.note_commitment);
    hasher.update(&request.request.checkpoint.transcript_root);
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
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    rotation_round: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ARCHIVE_PROVIDER_SELECT_DOMAIN);
    hasher.update(provider_id);
    hasher.update(schedule_seed);
    hasher.update(note_commitment);
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
