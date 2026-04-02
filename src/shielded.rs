use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    crypto::{Address, TaggedKemPublicKey, TaggedSigningPublicKey},
    epoch::MerkleTree,
};

pub const SHIELDED_NOTE_VERSION: u8 = 1;
pub const SHIELDED_CHECKPOINT_VERSION: u8 = 1;
pub const SHIELDED_EXTENSION_VERSION: u8 = 1;

const NOTE_KEY_COMMIT_DOMAIN: &str = "unchained-shielded-note-key-v1";
const NOTE_COMMIT_DOMAIN: &str = "unchained-shielded-note-commit-v1";
const NOTE_LEAF_DOMAIN: &str = "unchained-shielded-note-leaf-v1";
const NULLIFIER_DOMAIN: &str = "unchained-shielded-evolving-nullifier-v1";
const NULLIFIER_LEAF_DOMAIN: &str = "unchained-shielded-nullifier-leaf-v1";
const CHECKPOINT_BASE_DOMAIN: &str = "unchained-shielded-checkpoint-base-v1";
const CHECKPOINT_STEP_DOMAIN: &str = "unchained-shielded-checkpoint-step-v1";
const PRESENTATION_DOMAIN: &str = "unchained-shielded-presentation-v1";

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
    pub root: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NoteCommitmentTree {
    pub commitments: Vec<[u8; 32]>,
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
        }
    }

    pub fn append(&mut self, commitment: [u8; 32]) {
        self.commitments.push(commitment);
    }

    pub fn root(&self) -> [u8; 32] {
        let leaves = self.note_leaves();
        MerkleTree::compute_root_from_sorted_leaves(&leaves)
    }

    pub fn note_leaves(&self) -> Vec<[u8; 32]> {
        let mut leaves = self
            .commitments
            .iter()
            .map(note_leaf_hash)
            .collect::<Vec<[u8; 32]>>();
        leaves.sort();
        leaves
    }

    pub fn prove_membership(&self, note_commitment: &[u8; 32]) -> Option<NoteMembershipProof> {
        let leaves = self.note_leaves();
        let leaf = note_leaf_hash(note_commitment);
        let proof = MerkleTree::build_proof_from_leaves(&leaves, &leaf)?;
        Some(NoteMembershipProof {
            note_commitment: *note_commitment,
            root: self.root(),
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
        let mut unique = nullifiers.into_iter().collect::<BTreeSet<[u8; 32]>>();
        let nullifiers = unique.iter().copied().collect::<Vec<_>>();
        let root = compute_nullifier_root(&nullifiers);
        unique.clear();
        Self {
            epoch,
            nullifiers,
            root,
        }
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
        let leaves = self.nullifier_leaves();
        let leaf = nullifier_leaf_hash(&nullifier);
        let proof = MerkleTree::build_proof_from_leaves(&leaves, &leaf)?;
        Some(NullifierMembershipWitness {
            nullifier,
            root: self.root,
            proof,
        })
    }

    fn nullifier_leaves(&self) -> Vec<[u8; 32]> {
        self.nullifiers
            .iter()
            .map(nullifier_leaf_hash)
            .collect::<Vec<_>>()
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

    pub fn archive_epoch(
        &mut self,
        epoch: u64,
        nullifiers: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<()> {
        if self.epochs.contains_key(&epoch) {
            bail!("nullifier epoch {} already archived", epoch);
        }
        if let Some((&last_epoch, _)) = self.epochs.last_key_value() {
            if epoch <= last_epoch {
                bail!("nullifier epochs must be archived in increasing order");
            }
        }
        let archived = ArchivedNullifierEpoch::new(epoch, nullifiers);
        self.ledger.remember_epoch(&archived);
        self.epochs.insert(epoch, archived);
        Ok(())
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
        let expected_from = checkpoint.covered_through_epoch.saturating_add(1);
        if queries.is_empty() {
            return Ok(HistoricalUnspentExtension {
                version: SHIELDED_EXTENSION_VERSION,
                note_commitment: checkpoint.note_commitment,
                from_epoch: expected_from,
                through_epoch: checkpoint.covered_through_epoch,
                prior_transcript_root: checkpoint.transcript_root,
                new_transcript_root: checkpoint.transcript_root,
                records: Vec::new(),
            });
        }

        let mut records = Vec::with_capacity(queries.len());
        let mut transcript_root = checkpoint.transcript_root;
        let mut expected_epoch = expected_from;
        for query in queries {
            if query.epoch != expected_epoch {
                bail!("queries must form a contiguous epoch range");
            }
            let archived = self
                .epochs
                .get(&query.epoch)
                .ok_or_else(|| anyhow!("missing nullifier archive for epoch {}", query.epoch))?;
            let proof = archived.prove_absence(query.nullifier)?;
            transcript_root = checkpoint_step_root(
                &transcript_root,
                query.epoch,
                &query.nullifier,
                &proof.digest(),
            );
            records.push(HistoricalAbsenceRecord {
                epoch: query.epoch,
                nullifier: query.nullifier,
                proof,
            });
            expected_epoch = expected_epoch.saturating_add(1);
        }

        Ok(HistoricalUnspentExtension {
            version: SHIELDED_EXTENSION_VERSION,
            note_commitment: checkpoint.note_commitment,
            from_epoch: expected_from,
            through_epoch: expected_epoch.saturating_sub(1),
            prior_transcript_root: checkpoint.transcript_root,
            new_transcript_root: transcript_root,
            records,
        })
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

fn compute_nullifier_root(nullifiers: &[[u8; 32]]) -> [u8; 32] {
    let leaves = nullifiers
        .iter()
        .map(nullifier_leaf_hash)
        .collect::<Vec<[u8; 32]>>();
    MerkleTree::compute_root_from_sorted_leaves(&leaves)
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
