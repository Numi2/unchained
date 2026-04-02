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
const CHECKPOINT_STEP_DOMAIN: &str = "unchained-shielded-checkpoint-step-v1";
const PRESENTATION_DOMAIN: &str = "unchained-shielded-presentation-v1";
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
pub struct HistoricalUnspentExtension {
    pub version: u8,
    pub note_commitment: [u8; 32],
    pub from_epoch: u64,
    pub through_epoch: u64,
    pub prior_transcript_root: [u8; 32],
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
            if extension.new_transcript_root != self.transcript_root {
                bail!("empty extension must preserve the transcript root");
            }
            return Ok(self.clone());
        }

        if extension.from_epoch != expected_from {
            bail!("extension does not continue from the prior checkpoint");
        }

        let mut transcript_root = self.transcript_root;
        let mut expected_epoch = extension.from_epoch;
        for record in &extension.records {
            if record.epoch != expected_epoch {
                bail!("extension epochs must be contiguous");
            }
            if record.nullifier != record.proof.queried_nullifier {
                bail!("extension record nullifier does not match the proof");
            }
            if ledger.root_for_epoch(record.epoch)? != record.proof.root {
                bail!("extension proof root does not match the historical root ledger");
            }
            record.proof.verify()?;
            transcript_root = checkpoint_step_root(
                &transcript_root,
                record.epoch,
                &record.nullifier,
                &record.proof.digest(),
            );
            expected_epoch = expected_epoch.saturating_add(1);
        }

        if extension.through_epoch != expected_epoch.saturating_sub(1) {
            bail!("extension through_epoch does not match the proof payload");
        }
        if extension.new_transcript_root != transcript_root {
            bail!("extension transcript root mismatch");
        }

        let additional = u32::try_from(extension.records.len())
            .map_err(|_| anyhow!("too many extension records"))?;
        Ok(Self {
            version: self.version,
            note_commitment: self.note_commitment,
            birth_epoch: self.birth_epoch,
            covered_through_epoch: extension.through_epoch,
            transcript_root,
            verified_epoch_count: self.verified_epoch_count.saturating_add(additional),
        })
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

    pub fn extend_checkpoint(
        &self,
        checkpoint: &HistoricalUnspentCheckpoint,
        queries: &[EvolvingNullifierQuery],
    ) -> Result<HistoricalUnspentExtension> {
        let mut extensions = self.extend_checkpoints_batch(&[CheckpointExtensionRequest {
            checkpoint: checkpoint.clone(),
            queries: queries.to_vec(),
        }])?;
        extensions
            .pop()
            .ok_or_else(|| anyhow!("missing checkpoint extension result"))
    }

    pub fn extend_checkpoints_batch(
        &self,
        requests: &[CheckpointExtensionRequest],
    ) -> Result<Vec<HistoricalUnspentExtension>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        struct PendingExtension {
            note_commitment: [u8; 32],
            from_epoch: u64,
            through_epoch: u64,
            prior_transcript_root: [u8; 32],
            transcript_root: [u8; 32],
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
            pending.push(PendingExtension {
                note_commitment: request.checkpoint.note_commitment,
                from_epoch: expected_from,
                through_epoch: request.checkpoint.covered_through_epoch,
                prior_transcript_root: request.checkpoint.transcript_root,
                transcript_root: request.checkpoint.transcript_root,
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
                let pending_extension = &mut pending[request_index];
                pending_extension.transcript_root = checkpoint_step_root(
                    &pending_extension.transcript_root,
                    epoch,
                    &nullifier,
                    &proof.digest(),
                );
                pending_extension.records.push(HistoricalAbsenceRecord {
                    epoch,
                    nullifier,
                    proof,
                });
                pending_extension.through_epoch = epoch;
            }
        }

        Ok(pending
            .into_iter()
            .map(|pending_extension| HistoricalUnspentExtension {
                version: SHIELDED_EXTENSION_VERSION,
                note_commitment: pending_extension.note_commitment,
                from_epoch: pending_extension.from_epoch,
                through_epoch: pending_extension.through_epoch,
                prior_transcript_root: pending_extension.prior_transcript_root,
                new_transcript_root: pending_extension.transcript_root,
                records: pending_extension.records,
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

fn checkpoint_step_root(
    prior_root: &[u8; 32],
    epoch: u64,
    nullifier: &[u8; 32],
    proof_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_STEP_DOMAIN);
    hasher.update(prior_root);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(nullifier);
    hasher.update(proof_digest);
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
