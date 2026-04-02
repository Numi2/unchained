use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const SHIELDED_NOTE_VERSION: u8 = 1;
pub const SHIELDED_CHECKPOINT_VERSION: u8 = 1;
pub const SHIELDED_EXTENSION_VERSION: u8 = 1;
pub const SHIELDED_OUTPUT_NONCE_LEN: usize = 24;

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
const CHECKPOINT_EXTENSION_ACCUMULATE_DOMAIN: &str = "unchained-shielded-checkpoint-accumulate-v1";
const OUTPUT_BINDING_DOMAIN: &str = "unchained-shielded-output-binding-v1";
const HISTORICAL_ROOT_DIGEST_DOMAIN: &str = "unchained-shielded-historical-ledger-digest-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedNote {
    pub version: u8,
    pub value: u64,
    pub birth_epoch: u64,
    pub owner_address: [u8; 32],
    pub owner_signing_pk: Vec<u8>,
    pub owner_kem_pk: Vec<u8>,
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
    pub historical_root_digest: [u8; 32],
    pub packet_commitment_root: [u8; 32],
    pub aggregate_rerandomization_blinding: [u8; 32],
    pub new_transcript_root: [u8; 32],
    pub packets: Vec<HistoricalUnspentPacket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoricalUnspentSegment {
    pub provider_id: [u8; 32],
    pub provider_manifest_digest: [u8; 32],
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
pub struct ProofShieldedOutputPlaintext {
    pub note: ProofShieldedNote,
    pub note_key: [u8; 32],
    pub checkpoint: HistoricalUnspentCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedOutput {
    pub note_commitment: [u8; 32],
    pub kem_ct: Vec<u8>,
    pub nonce: [u8; SHIELDED_OUTPUT_NONCE_LEN],
    pub view_tag: u8,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedInputWitness {
    pub note: ProofShieldedNote,
    pub note_key: [u8; 32],
    pub membership_proof: NoteMembershipProof,
    pub historical_checkpoint: HistoricalUnspentCheckpoint,
    pub historical_extension: HistoricalUnspentExtension,
    pub current_nullifier: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedOutputWitness {
    pub plaintext: ProofShieldedOutputPlaintext,
    pub public_output: ProofShieldedOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedTxWitness {
    pub chain_id: [u8; 32],
    pub current_epoch: u64,
    pub note_tree_root: [u8; 32],
    pub inputs: Vec<ProofShieldedInputWitness>,
    pub outputs: Vec<ProofShieldedOutputWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedInputBinding {
    pub current_nullifier: [u8; 32],
    pub historical_from_epoch: u64,
    pub historical_through_epoch: u64,
    pub historical_root_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedOutputBinding {
    pub note_commitment: [u8; 32],
    pub public_output_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofShieldedTxJournal {
    pub chain_id: [u8; 32],
    pub current_epoch: u64,
    pub note_tree_root: [u8; 32],
    pub inputs: Vec<ProofShieldedInputBinding>,
    pub outputs: Vec<ProofShieldedOutputBinding>,
}

pub fn validate_shielded_tx_witness(
    witness: &ProofShieldedTxWitness,
) -> Result<ProofShieldedTxJournal> {
    if witness.inputs.is_empty() {
        bail!("proof witness must contain at least one input");
    }
    if witness.outputs.is_empty() {
        bail!("proof witness must contain at least one output");
    }

    let mut total_in = 0u128;
    let mut total_out = 0u128;
    let mut seen_nullifiers = HashSet::new();
    let mut seen_input_commitments = HashSet::new();
    let mut seen_output_commitments = HashSet::new();
    let mut input_bindings = Vec::with_capacity(witness.inputs.len());
    let mut output_bindings = Vec::with_capacity(witness.outputs.len());

    for input in &witness.inputs {
        input.note.validate()?;
        if note_key_commitment(&input.note_key) != input.note.note_key_commitment {
            bail!("input note key commitment mismatch");
        }
        if !seen_input_commitments.insert(input.note.commitment) {
            bail!("duplicate input note commitment");
        }
        if !seen_nullifiers.insert(input.current_nullifier) {
            bail!("duplicate current nullifier");
        }
        if input.membership_proof.note_commitment != input.note.commitment {
            bail!("input membership proof commitment mismatch");
        }
        if input.membership_proof.root != witness.note_tree_root || !input.membership_proof.verify()
        {
            bail!("invalid note membership proof");
        }
        if input.historical_checkpoint.note_commitment != input.note.commitment {
            bail!("historical checkpoint note mismatch");
        }
        let updated_checkpoint = input
            .historical_checkpoint
            .apply_extension(&input.historical_extension)?;
        if witness.current_epoch == 0 {
            if !input.historical_extension.packets.is_empty() {
                bail!("epoch-zero spends must not include historical records");
            }
        } else if updated_checkpoint.covered_through_epoch != witness.current_epoch - 1 {
            bail!("historical checkpoint does not cover all prior epochs");
        }
        let expected_nullifier = input.note.derive_evolving_nullifier(
            &input.note_key,
            &witness.chain_id,
            witness.current_epoch,
        )?;
        if expected_nullifier != input.current_nullifier {
            bail!("current nullifier mismatch");
        }
        total_in = total_in.saturating_add(input.note.value as u128);
        input_bindings.push(ProofShieldedInputBinding {
            current_nullifier: input.current_nullifier,
            historical_from_epoch: input.historical_extension.from_epoch,
            historical_through_epoch: input.historical_extension.through_epoch,
            historical_root_digest: input.historical_extension.historical_root_digest,
        });
    }

    for output in &witness.outputs {
        output.plaintext.note.validate()?;
        if output.plaintext.note.birth_epoch != witness.current_epoch {
            bail!("output birth epoch must match current epoch");
        }
        if note_key_commitment(&output.plaintext.note_key)
            != output.plaintext.note.note_key_commitment
        {
            bail!("output note key commitment mismatch");
        }
        let expected_checkpoint = HistoricalUnspentCheckpoint::genesis(
            output.plaintext.note.commitment,
            witness.current_epoch,
        );
        if output.plaintext.checkpoint != expected_checkpoint {
            bail!("output checkpoint mismatch");
        }
        if output.public_output.note_commitment != output.plaintext.note.commitment {
            bail!("public output note commitment mismatch");
        }
        if !seen_output_commitments.insert(output.public_output.note_commitment) {
            bail!("duplicate output note commitment");
        }
        total_out = total_out.saturating_add(output.plaintext.note.value as u128);
        output_bindings.push(ProofShieldedOutputBinding {
            note_commitment: output.public_output.note_commitment,
            public_output_digest: public_output_digest(&output.public_output),
        });
    }

    if total_in != total_out {
        bail!("shielded value balance mismatch");
    }

    Ok(ProofShieldedTxJournal {
        chain_id: witness.chain_id,
        current_epoch: witness.current_epoch,
        note_tree_root: witness.note_tree_root,
        inputs: input_bindings,
        outputs: output_bindings,
    })
}

impl ProofShieldedNote {
    pub fn validate(&self) -> Result<()> {
        if self.version != SHIELDED_NOTE_VERSION {
            bail!("unsupported note version {}", self.version);
        }
        if address_from_bytes(&self.owner_signing_pk) != self.owner_address {
            bail!("owner address does not match the signing key");
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
            bail!("note commitment mismatch");
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
            bail!("nullifier epoch predates note birth");
        }
        Ok(evolving_nullifier(note_key, &self.rho, chain_id, epoch))
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
                bail!("empty nullifier set cannot include witnesses");
            }
            return Ok(());
        }

        let predecessor = self.predecessor.as_ref();
        let successor = self.successor.as_ref();
        if predecessor.is_none() && successor.is_none() {
            bail!("non-empty nullifier set requires a boundary witness");
        }

        if let Some(predecessor) = predecessor {
            if predecessor.root != self.root || !predecessor.verify() {
                bail!("invalid predecessor witness");
            }
            if predecessor.nullifier >= self.queried_nullifier {
                bail!("predecessor must sort before the queried nullifier");
            }
        }
        if let Some(successor) = successor {
            if successor.root != self.root || !successor.verify() {
                bail!("invalid successor witness");
            }
            if successor.nullifier <= self.queried_nullifier {
                bail!("successor must sort after the queried nullifier");
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

impl HistoricalUnspentCheckpoint {
    pub fn genesis(note_commitment: [u8; 32], birth_epoch: u64) -> Self {
        Self {
            version: SHIELDED_CHECKPOINT_VERSION,
            note_commitment,
            birth_epoch,
            covered_through_epoch: birth_epoch.saturating_sub(1),
            transcript_root: checkpoint_base_root(&note_commitment, birth_epoch),
            verified_epoch_count: 0,
        }
    }

    pub fn apply_extension(&self, extension: &HistoricalUnspentExtension) -> Result<Self> {
        if self.version != SHIELDED_CHECKPOINT_VERSION {
            bail!("unsupported checkpoint version {}", self.version);
        }
        if extension.version != SHIELDED_EXTENSION_VERSION {
            bail!("unsupported extension version {}", extension.version);
        }
        if self.note_commitment != extension.note_commitment {
            bail!("checkpoint extension note mismatch");
        }
        if self.transcript_root != extension.prior_transcript_root {
            bail!("checkpoint extension prior root mismatch");
        }

        let expected_from = self.covered_through_epoch.saturating_add(1);
        if extension.packets.is_empty() {
            if extension.from_epoch != expected_from {
                bail!("empty extension starts at the wrong epoch");
            }
            if extension.through_epoch != self.covered_through_epoch {
                bail!("empty extension cannot advance the checkpoint");
            }
            if extension.new_transcript_root != self.transcript_root {
                bail!("empty extension must preserve the transcript root");
            }
            if extension.packet_commitment_root != [0u8; 32] {
                bail!("empty extension must use the zero packet commitment root");
            }
            return Ok(self.clone());
        }

        if extension.from_epoch != expected_from {
            bail!("extension does not continue from the prior checkpoint");
        }

        let mut expected_epoch = extension.from_epoch;
        let mut historical_pairs = Vec::new();
        let mut packet_digests = Vec::with_capacity(extension.packets.len());
        for packet in &extension.packets {
            if packet.from_epoch != expected_epoch {
                bail!("extension packets must be contiguous");
            }
            packet.verify_against_note(&self.note_commitment)?;
            let mut packet_pairs = Vec::new();
            for segment in &packet.segments {
                if segment.from_epoch != expected_epoch {
                    bail!("extension segments must be contiguous inside packets");
                }
                for record in &segment.records {
                    if record.epoch != expected_epoch {
                        bail!("extension epochs must be contiguous");
                    }
                    if record.nullifier != record.proof.queried_nullifier {
                        bail!("record nullifier does not match its proof");
                    }
                    if record.proof.epoch != record.epoch {
                        bail!("record epoch does not match its proof");
                    }
                    if record.proof.root == [0u8; 32] && record.proof.set_size != 0 {
                        bail!("non-empty nullifier proof cannot use the zero root");
                    }
                    record.proof.verify()?;
                    historical_pairs.push((record.epoch, record.proof.root));
                    packet_pairs.push((record.epoch, record.proof.root));
                    expected_epoch = expected_epoch.saturating_add(1);
                }
            }
            let expected_packet_digest = historical_root_digest_from_pairs(&packet_pairs);
            if packet.packet_historical_root_digest != expected_packet_digest {
                bail!("packet historical root digest mismatch");
            }
            packet_digests.push(packet.commitment_digest());
        }

        if extension.through_epoch != expected_epoch.saturating_sub(1) {
            bail!("extension through_epoch does not match the payload");
        }
        let expected_historical_root_digest = historical_root_digest_from_pairs(&historical_pairs);
        if extension.historical_root_digest != expected_historical_root_digest {
            bail!("extension historical root digest mismatch");
        }
        let expected_packet_commitment_root = checkpoint_packet_commitment_root(&packet_digests);
        if extension.packet_commitment_root != expected_packet_commitment_root {
            bail!("extension packet commitment root mismatch");
        }
        let rerandomized_root = accumulated_checkpoint_root(
            &self.transcript_root,
            &self.note_commitment,
            extension.from_epoch,
            extension.through_epoch,
            &extension.historical_root_digest,
            &extension.packet_commitment_root,
            &extension.aggregate_rerandomization_blinding,
        );
        if extension.new_transcript_root != rerandomized_root {
            bail!("extension transcript root mismatch");
        }

        let additional = u32::try_from(historical_pairs.len()).unwrap_or(u32::MAX);
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

impl HistoricalUnspentSegment {
    pub fn verify_against_note(&self, note_commitment: &[u8; 32]) -> Result<()> {
        if self.records.is_empty() {
            bail!("historical segment cannot be empty");
        }
        if self.records.last().map(|record| record.epoch) != Some(self.through_epoch) {
            bail!("historical segment through_epoch does not match the final record");
        }
        let expected_service_root =
            checkpoint_segment_service_root(note_commitment, self.from_epoch, &self.records)?;
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
            segment.verify_against_note(note_commitment)?;
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
        let expected_historical_root_digest = historical_root_digest_from_pairs(&historical_pairs);
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

pub fn note_key_commitment(note_key: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key(NOTE_KEY_COMMIT_DOMAIN)
        .update(note_key)
        .finalize()
        .as_bytes()
}

pub fn public_output_digest(output: &ProofShieldedOutput) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(OUTPUT_BINDING_DOMAIN);
    hasher.update(&output.note_commitment);
    hasher.update(&(output.kem_ct.len() as u32).to_le_bytes());
    hasher.update(&output.kem_ct);
    hasher.update(&output.nonce);
    hasher.update(&[output.view_tag]);
    hasher.update(&(output.ciphertext.len() as u32).to_le_bytes());
    hasher.update(&output.ciphertext);
    *hasher.finalize().as_bytes()
}

pub fn historical_root_digest(records: &[HistoricalAbsenceRecord]) -> [u8; 32] {
    let pairs = records
        .iter()
        .map(|record| (record.epoch, record.proof.root))
        .collect::<Vec<_>>();
    historical_root_digest_from_pairs(&pairs)
}

pub fn historical_root_digest_from_pairs(pairs: &[(u64, [u8; 32])]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(HISTORICAL_ROOT_DIGEST_DOMAIN);
    hasher.update(&(pairs.len() as u32).to_le_bytes());
    for (epoch, root) in pairs {
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
        let mut hasher = blake3::Hasher::new();
        if *sibling_is_left {
            hasher.update(sibling);
            hasher.update(&computed);
        } else {
            hasher.update(&computed);
            hasher.update(sibling);
        }
        computed = *hasher.finalize().as_bytes();
    }
    &computed == root
}

fn compute_note_commitment(
    version: u8,
    value: u64,
    birth_epoch: u64,
    owner_address: &[u8; 32],
    owner_signing_pk: &[u8],
    owner_kem_pk: &[u8],
    rho: &[u8; 32],
    note_randomizer: &[u8; 32],
    note_key_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NOTE_COMMIT_DOMAIN);
    hasher.update(&[version]);
    hasher.update(&value.to_le_bytes());
    hasher.update(&birth_epoch.to_le_bytes());
    hasher.update(owner_address);
    hasher.update(owner_signing_pk);
    hasher.update(owner_kem_pk);
    hasher.update(rho);
    hasher.update(note_randomizer);
    hasher.update(note_key_commitment);
    *hasher.finalize().as_bytes()
}

fn address_from_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("unchained-address")
        .update(bytes)
        .finalize()
        .as_bytes()
}

fn evolving_nullifier(
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

fn note_leaf_hash(note_commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NOTE_LEAF_DOMAIN);
    hasher.update(note_commitment);
    *hasher.finalize().as_bytes()
}

fn nullifier_leaf_hash(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NULLIFIER_LEAF_DOMAIN);
    hasher.update(nullifier);
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

fn accumulated_checkpoint_root(
    prior_transcript_root: &[u8; 32],
    note_commitment: &[u8; 32],
    from_epoch: u64,
    through_epoch: u64,
    historical_root_digest: &[u8; 32],
    packet_commitment_root: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_EXTENSION_ACCUMULATE_DOMAIN);
    hasher.update(prior_transcript_root);
    hasher.update(note_commitment);
    hasher.update(&from_epoch.to_le_bytes());
    hasher.update(&through_epoch.to_le_bytes());
    hasher.update(historical_root_digest);
    hasher.update(packet_commitment_root);
    hasher.update(blinding);
    *hasher.finalize().as_bytes()
}

fn hash_optional_membership(
    hasher: &mut blake3::Hasher,
    witness: &Option<NullifierMembershipWitness>,
) {
    match witness {
        Some(witness) => {
            hasher.update(&[1u8]);
            hasher.update(&witness.nullifier);
            hasher.update(&witness.root);
            hasher.update(&(witness.proof.len() as u32).to_le_bytes());
            for (hash, sibling_is_left) in &witness.proof {
                hasher.update(hash);
                hasher.update(&[*sibling_is_left as u8]);
            }
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_note(seed: u8, value: u64, birth_epoch: u64) -> (ProofShieldedNote, [u8; 32]) {
        let owner_signing_pk = vec![seed; 32];
        let owner_kem_pk = vec![seed.wrapping_add(1); 32];
        let owner_address = address_from_bytes(&owner_signing_pk);
        let note_key = [seed.wrapping_add(2); 32];
        let rho = [seed.wrapping_add(3); 32];
        let note_randomizer = [seed.wrapping_add(4); 32];
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
        (
            ProofShieldedNote {
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
            },
            note_key,
        )
    }

    fn single_leaf_membership(note: &ProofShieldedNote) -> NoteMembershipProof {
        NoteMembershipProof {
            note_commitment: note.commitment,
            root: note_leaf_hash(&note.commitment),
            proof: Vec::new(),
        }
    }

    fn extend_checkpoint(
        note: &ProofShieldedNote,
        note_key: &[u8; 32],
        chain_id: &[u8; 32],
        checkpoint: &HistoricalUnspentCheckpoint,
        through_epoch: u64,
    ) -> HistoricalUnspentExtension {
        let provider_id = [1u8; 32];
        let provider_manifest_digest = [2u8; 32];
        let from_epoch = checkpoint.covered_through_epoch.saturating_add(1);
        if through_epoch < from_epoch {
            return HistoricalUnspentExtension {
                version: SHIELDED_EXTENSION_VERSION,
                note_commitment: checkpoint.note_commitment,
                from_epoch,
                through_epoch: checkpoint.covered_through_epoch,
                prior_transcript_root: checkpoint.transcript_root,
                historical_root_digest: historical_root_digest_from_pairs(&[]),
                packet_commitment_root: [0u8; 32],
                aggregate_rerandomization_blinding: [0u8; 32],
                new_transcript_root: checkpoint.transcript_root,
                packets: Vec::new(),
            };
        }

        let mut records = Vec::new();
        let mut historical_pairs = Vec::new();
        for epoch in from_epoch..=through_epoch {
            let nullifier = note
                .derive_evolving_nullifier(note_key, chain_id, epoch)
                .expect("derive evolving nullifier");
            let proof = NullifierNonMembershipProof {
                epoch,
                queried_nullifier: nullifier,
                root: [0u8; 32],
                set_size: 0,
                predecessor: None,
                successor: None,
            };
            historical_pairs.push((epoch, proof.root));
            records.push(HistoricalAbsenceRecord {
                epoch,
                nullifier,
                proof,
            });
        }

        let historical_root_digest = historical_root_digest_from_pairs(&historical_pairs);
        let segment_service_root =
            checkpoint_segment_service_root(&checkpoint.note_commitment, from_epoch, &records)
                .expect("segment service root");
        let rerandomization_blinding = [3u8; 32];
        let segment = HistoricalUnspentSegment {
            provider_id,
            provider_manifest_digest,
            from_epoch,
            through_epoch,
            segment_service_root,
            segment_historical_root_digest: historical_root_digest,
            rerandomization_blinding,
            segment_transcript_root: rerandomized_segment_root(
                &segment_service_root,
                &provider_id,
                &provider_manifest_digest,
                &historical_root_digest,
                &rerandomization_blinding,
            ),
            records,
        };
        let packet = HistoricalUnspentPacket {
            from_epoch,
            through_epoch,
            packet_historical_root_digest: historical_root_digest,
            segment_commitment_root: checkpoint_segment_commitment_root(&[
                segment.commitment_digest()
            ]),
            packet_rerandomization_blinding: [5u8; 32],
            packet_transcript_root: accumulated_packet_root(
                &checkpoint.note_commitment,
                from_epoch,
                through_epoch,
                &historical_root_digest,
                &checkpoint_segment_commitment_root(&[segment.commitment_digest()]),
                &[5u8; 32],
            ),
            segments: vec![segment],
        };
        let packet_commitment_root =
            checkpoint_packet_commitment_root(&[packet.commitment_digest()]);
        let aggregate_rerandomization_blinding = [4u8; 32];
        HistoricalUnspentExtension {
            version: SHIELDED_EXTENSION_VERSION,
            note_commitment: checkpoint.note_commitment,
            from_epoch,
            through_epoch,
            prior_transcript_root: checkpoint.transcript_root,
            historical_root_digest,
            packet_commitment_root,
            aggregate_rerandomization_blinding,
            new_transcript_root: accumulated_checkpoint_root(
                &checkpoint.transcript_root,
                &checkpoint.note_commitment,
                from_epoch,
                through_epoch,
                &historical_root_digest,
                &packet_commitment_root,
                &aggregate_rerandomization_blinding,
            ),
            packets: vec![packet],
        }
    }

    fn sample_output_witness(seed: u8, value: u64, birth_epoch: u64) -> ProofShieldedOutputWitness {
        let (note, note_key) = sample_note(seed, value, birth_epoch);
        ProofShieldedOutputWitness {
            plaintext: ProofShieldedOutputPlaintext {
                checkpoint: HistoricalUnspentCheckpoint::genesis(note.commitment, birth_epoch),
                note,
                note_key,
            },
            public_output: ProofShieldedOutput {
                note_commitment: note.commitment,
                kem_ct: vec![seed; 64],
                nonce: [seed; SHIELDED_OUTPUT_NONCE_LEN],
                view_tag: seed,
                ciphertext: vec![seed.wrapping_add(9); 48],
            },
        }
    }

    fn sample_witness(output_value: u64) -> (ProofShieldedTxWitness, HistoricalUnspentExtension) {
        let chain_id = [7u8; 32];
        let current_epoch = 2;
        let (input_note, input_note_key) = sample_note(11, 7, 1);
        let membership_proof = single_leaf_membership(&input_note);
        let checkpoint = HistoricalUnspentCheckpoint::genesis(input_note.commitment, 1);
        let extension = extend_checkpoint(
            &input_note,
            &input_note_key,
            &chain_id,
            &checkpoint,
            current_epoch - 1,
        );
        let current_nullifier = input_note
            .derive_evolving_nullifier(&input_note_key, &chain_id, current_epoch)
            .expect("derive current nullifier");
        let output = sample_output_witness(44, output_value, current_epoch);
        (
            ProofShieldedTxWitness {
                chain_id,
                current_epoch,
                note_tree_root: membership_proof.root,
                inputs: vec![ProofShieldedInputWitness {
                    note: input_note,
                    note_key: input_note_key,
                    membership_proof,
                    historical_checkpoint: checkpoint,
                    historical_extension: extension.clone(),
                    current_nullifier,
                }],
                outputs: vec![output],
            },
            extension,
        )
    }

    #[test]
    fn valid_witness_yields_public_journal_bindings() {
        let (witness, extension) = sample_witness(7);
        let journal = validate_shielded_tx_witness(&witness).expect("valid witness");
        assert_eq!(journal.chain_id, witness.chain_id);
        assert_eq!(journal.current_epoch, witness.current_epoch);
        assert_eq!(journal.note_tree_root, witness.note_tree_root);
        assert_eq!(journal.inputs.len(), 1);
        assert_eq!(journal.outputs.len(), 1);
        assert_eq!(
            journal.inputs[0].current_nullifier,
            witness.inputs[0].current_nullifier
        );
        assert_eq!(
            journal.inputs[0].historical_from_epoch,
            extension.from_epoch
        );
        assert_eq!(
            journal.inputs[0].historical_through_epoch,
            extension.through_epoch
        );
        assert_eq!(
            journal.inputs[0].historical_root_digest,
            extension.historical_root_digest
        );
        assert_eq!(
            journal.outputs[0].note_commitment,
            witness.outputs[0].public_output.note_commitment
        );
        assert_eq!(
            journal.outputs[0].public_output_digest,
            public_output_digest(&witness.outputs[0].public_output)
        );
    }

    #[test]
    fn invalid_historical_extension_is_rejected() {
        let (mut witness, _) = sample_witness(7);
        witness.inputs[0].historical_extension.new_transcript_root[0] ^= 0x80;
        let err = validate_shielded_tx_witness(&witness).expect_err("invalid extension");
        assert!(
            err.to_string()
                .contains("extension transcript root mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn value_imbalance_is_rejected() {
        let (witness, _) = sample_witness(6);
        let err = validate_shielded_tx_witness(&witness).expect_err("value imbalance");
        assert!(
            err.to_string().contains("shielded value balance mismatch"),
            "unexpected error: {err:?}"
        );
    }
}
