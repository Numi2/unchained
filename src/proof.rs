use anyhow::{bail, Context, Result};
use proof_core::{
    CheckpointAccumulatorJournal, HistoricalAbsenceRecord as ProofHistoricalAbsenceRecord,
    HistoricalUnspentCheckpoint as ProofHistoricalUnspentCheckpoint,
    HistoricalUnspentPacket as ProofHistoricalUnspentPacket,
    HistoricalUnspentSegment as ProofHistoricalUnspentSegment,
    HistoricalUnspentStratum as ProofHistoricalUnspentStratum,
    NoteMembershipProof as ProofNoteMembershipProof,
    NullifierMembershipWitness as ProofNullifierMembershipWitness,
    NullifierNonMembershipProof as ProofNullifierNonMembershipProof,
    ProofExternalAssetAnchorJournal, ProofExternalAssetAnchorWitness,
    ProofPrivateDelegationJournal, ProofPrivateDelegationWitness, ProofPrivateExternalStakeJournal,
    ProofPrivateExternalStakeWitness, ProofPrivateUndelegationJournal,
    ProofPrivateUndelegationWitness, ProofShieldedInputWitness, ProofShieldedNote,
    ProofShieldedNoteKind, ProofShieldedOutput, ProofShieldedOutputBinding,
    ProofShieldedOutputPlaintext, ProofShieldedOutputWitness, ProofShieldedTxJournal,
    ProofShieldedTxWitness,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{TaggedKemPublicKey, TaggedSigningPublicKey},
    shielded::{
        HistoricalAbsenceRecord, HistoricalUnspentCheckpoint, HistoricalUnspentExtension,
        HistoricalUnspentPacket, HistoricalUnspentSegment, HistoricalUnspentStratum,
        NoteMembershipProof, NullifierMembershipWitness, NullifierNonMembershipProof, ShieldedNote,
        ShieldedNoteKind,
    },
    transaction::{ShieldedOutput, ShieldedOutputPlaintext},
};

const TRANSPARENT_PROOF_VERSION: u8 = 1;
pub const MIN_TRANSPARENT_PROOF_SECURITY_BITS: u16 = 128;
#[cfg(test)]
const TRANSPARENT_STATEMENT_DIGEST_DOMAIN: &str = "unchained-transparent-statement-digest-v1";
const NATIVE_TRANSPARENT_BACKEND_KEY_DOMAIN: &str = "unchained-native-transparent-backend-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentProofStatement {
    ShieldedTransfer,
    PrivateDelegation,
    PrivateUndelegation,
    UnbondingClaim,
    PrivateExternalStake,
    ExternalAssetAnchor,
    CheckpointAccumulator,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentProofFamily {
    Stark,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentProofBackend {
    NativeTransparentStarkV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentSealEncoding {
    OpaqueSealBytesV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentCircuit {
    OrdinaryTransferV1,
    PrivateDelegationV1,
    PrivateUndelegationV1,
    UnbondingClaimV1,
    ZcashShieldedStakeV1,
    ExternalAssetAnchorV1,
    CheckpointAccumulatorV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparentCircuitDescriptor {
    pub circuit: TransparentCircuit,
    pub statement: TransparentProofStatement,
    pub proof_family: TransparentProofFamily,
    pub target_security_bits: u16,
    pub public_input_shape: &'static str,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransparentBackendDescriptor {
    pub backend: TransparentProofBackend,
    pub proof_family: TransparentProofFamily,
    pub target_security_bits: u16,
    pub seal_encoding: TransparentSealEncoding,
    pub name: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentProverCapabilities {
    pub backend: TransparentProofBackend,
    pub proof_family: TransparentProofFamily,
    pub target_security_bits: u16,
    pub seal_encoding: TransparentSealEncoding,
    pub supported_circuits: Vec<TransparentCircuit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentProof {
    pub version: u8,
    pub statement: TransparentProofStatement,
    pub circuit: TransparentCircuit,
    pub backend: TransparentProofBackend,
    pub statement_digest: [u8; 32],
    pub seal: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointAccumulatorProof {
    pub journal: CheckpointAccumulatorJournal,
    pub proof: TransparentProof,
}

fn canonical_backend_for_circuit(_circuit: TransparentCircuit) -> TransparentProofBackend {
    TransparentProofBackend::NativeTransparentStarkV1
}

fn ensure_canonical_backend_for_proof(proof: &TransparentProof) -> Result<()> {
    let canonical_backend = canonical_backend_for_circuit(proof.circuit);
    if canonical_backend != proof.backend {
        bail!(
            "transparent proof circuit {:?} was produced by backend {:?}, but canonical backend is {:?}",
            proof.circuit,
            proof.backend,
            canonical_backend
        );
    }
    Ok(())
}

fn supported_circuits_for_backend(backend: TransparentProofBackend) -> Vec<TransparentCircuit> {
    transparent_circuit_inventory()
        .iter()
        .copied()
        .filter(|circuit| canonical_backend_for_circuit(*circuit) == backend)
        .collect()
}

impl TransparentProof {
    pub fn new(statement: TransparentProofStatement, seal: Vec<u8>) -> Self {
        let circuit = canonical_circuit_for_statement(statement);
        let backend = canonical_backend_for_circuit(circuit);
        Self {
            version: TRANSPARENT_PROOF_VERSION,
            statement,
            circuit,
            backend,
            statement_digest: [0u8; 32],
            seal,
        }
    }

    pub fn new_for_circuit(circuit: TransparentCircuit, seal: Vec<u8>) -> Self {
        Self::new_for_circuit_with_digest(circuit, [0u8; 32], seal)
    }

    pub fn new_for_circuit_with_digest(
        circuit: TransparentCircuit,
        statement_digest: [u8; 32],
        seal: Vec<u8>,
    ) -> Self {
        let backend = canonical_backend_for_circuit(circuit);
        Self {
            version: TRANSPARENT_PROOF_VERSION,
            statement: transparent_circuit_descriptor(circuit).statement,
            circuit,
            backend,
            statement_digest,
            seal,
        }
    }

    pub fn descriptor(&self) -> TransparentCircuitDescriptor {
        transparent_circuit_descriptor(self.circuit)
    }

    pub fn validate_metadata(&self) -> Result<()> {
        if self.version != TRANSPARENT_PROOF_VERSION {
            bail!("unsupported transparent proof version {}", self.version);
        }
        let descriptor = self.descriptor();
        let backend = transparent_backend_descriptor(self.backend);
        if descriptor.statement != self.statement {
            bail!(
                "transparent proof circuit {:?} does not match statement {:?}",
                self.circuit,
                self.statement
            );
        }
        if descriptor.proof_family != backend.proof_family {
            bail!(
                "transparent proof backend {:?} does not match proof family {:?}",
                self.backend,
                descriptor.proof_family
            );
        }
        if backend.target_security_bits < MIN_TRANSPARENT_PROOF_SECURITY_BITS {
            bail!(
                "transparent proof backend {:?} violates minimum security budget",
                self.backend
            );
        }
        if descriptor.target_security_bits < MIN_TRANSPARENT_PROOF_SECURITY_BITS {
            bail!(
                "transparent proof circuit {:?} violates minimum security budget",
                self.circuit
            );
        }
        Ok(())
    }
}

pub fn transparent_circuit_inventory() -> &'static [TransparentCircuit] {
    const INVENTORY: &[TransparentCircuit] = &[
        TransparentCircuit::OrdinaryTransferV1,
        TransparentCircuit::PrivateDelegationV1,
        TransparentCircuit::PrivateUndelegationV1,
        TransparentCircuit::UnbondingClaimV1,
        TransparentCircuit::ZcashShieldedStakeV1,
        TransparentCircuit::ExternalAssetAnchorV1,
        TransparentCircuit::CheckpointAccumulatorV1,
    ];
    INVENTORY
}

pub fn transparent_backend_descriptor(
    backend: TransparentProofBackend,
) -> TransparentBackendDescriptor {
    match backend {
        TransparentProofBackend::NativeTransparentStarkV1 => TransparentBackendDescriptor {
            backend,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            seal_encoding: TransparentSealEncoding::OpaqueSealBytesV1,
            name: "native-transparent-stark-v1",
        },
    }
}

pub fn current_prover_capabilities() -> TransparentProverCapabilities {
    let descriptor =
        transparent_backend_descriptor(TransparentProofBackend::NativeTransparentStarkV1);
    TransparentProverCapabilities {
        backend: descriptor.backend,
        proof_family: descriptor.proof_family,
        target_security_bits: descriptor.target_security_bits,
        seal_encoding: descriptor.seal_encoding,
        supported_circuits: supported_circuits_for_backend(descriptor.backend),
    }
}

pub fn transparent_circuit_descriptor(circuit: TransparentCircuit) -> TransparentCircuitDescriptor {
    match circuit {
        TransparentCircuit::OrdinaryTransferV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::ShieldedTransfer,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "shielded-transfer-journal-v1",
            name: "ordinary-transfer-v1",
        },
        TransparentCircuit::PrivateDelegationV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::PrivateDelegation,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "private-delegation-journal-v1",
            name: "private-delegation-v1",
        },
        TransparentCircuit::PrivateUndelegationV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::PrivateUndelegation,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "private-undelegation-journal-v1",
            name: "private-undelegation-v1",
        },
        TransparentCircuit::UnbondingClaimV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::UnbondingClaim,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "unbonding-claim-journal-v1",
            name: "unbonding-claim-v1",
        },
        TransparentCircuit::ZcashShieldedStakeV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::PrivateExternalStake,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "zcash-shielded-stake-anchor-journal-v1",
            name: "zcash-shielded-stake-v1",
        },
        TransparentCircuit::ExternalAssetAnchorV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::ExternalAssetAnchor,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "external-asset-anchor-journal-v1",
            name: "external-asset-anchor-v1",
        },
        TransparentCircuit::CheckpointAccumulatorV1 => TransparentCircuitDescriptor {
            circuit,
            statement: TransparentProofStatement::CheckpointAccumulator,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            public_input_shape: "checkpoint-accumulator-journal-v1",
            name: "checkpoint-accumulator-v1",
        },
    }
}

impl TransparentProverCapabilities {
    pub fn supports_circuit(&self, circuit: TransparentCircuit) -> bool {
        self.supported_circuits.contains(&circuit)
    }

    pub fn validate(&self) -> Result<()> {
        let descriptor = transparent_backend_descriptor(self.backend);
        if descriptor.proof_family != self.proof_family {
            bail!(
                "transparent prover backend {:?} does not match proof family {:?}",
                self.backend,
                self.proof_family
            );
        }
        if descriptor.target_security_bits != self.target_security_bits {
            bail!(
                "transparent prover backend {:?} advertised {} security bits, expected {}",
                self.backend,
                self.target_security_bits,
                descriptor.target_security_bits
            );
        }
        if descriptor.seal_encoding != self.seal_encoding {
            bail!(
                "transparent prover backend {:?} does not match seal encoding {:?}",
                self.backend,
                self.seal_encoding
            );
        }
        if self.target_security_bits < MIN_TRANSPARENT_PROOF_SECURITY_BITS {
            bail!("transparent prover capability budget is below canonical minimum");
        }
        if self.supported_circuits.is_empty() {
            bail!("transparent prover capability list is empty");
        }
        for (index, circuit) in self.supported_circuits.iter().enumerate() {
            if self.supported_circuits[..index].contains(circuit) {
                bail!("transparent prover capability list contains duplicate circuits");
            }
            let circuit_descriptor = transparent_circuit_descriptor(*circuit);
            if circuit_descriptor.proof_family != self.proof_family {
                bail!(
                    "transparent prover backend {:?} cannot serve circuit {:?}",
                    self.backend,
                    circuit
                );
            }
            if circuit_descriptor.target_security_bits > self.target_security_bits {
                bail!(
                    "transparent prover backend {:?} undershoots circuit {:?} security budget",
                    self.backend,
                    circuit
                );
            }
            if canonical_backend_for_circuit(*circuit) != self.backend {
                bail!(
                    "transparent prover backend {:?} is not canonical for circuit {:?}",
                    self.backend,
                    circuit
                );
            }
        }
        Ok(())
    }
}

pub fn canonical_circuit_for_statement(statement: TransparentProofStatement) -> TransparentCircuit {
    match statement {
        TransparentProofStatement::ShieldedTransfer => TransparentCircuit::OrdinaryTransferV1,
        TransparentProofStatement::PrivateDelegation => TransparentCircuit::PrivateDelegationV1,
        TransparentProofStatement::PrivateUndelegation => TransparentCircuit::PrivateUndelegationV1,
        TransparentProofStatement::UnbondingClaim => TransparentCircuit::UnbondingClaimV1,
        TransparentProofStatement::PrivateExternalStake => TransparentCircuit::ZcashShieldedStakeV1,
        TransparentProofStatement::ExternalAssetAnchor => TransparentCircuit::ExternalAssetAnchorV1,
        TransparentProofStatement::CheckpointAccumulator => {
            TransparentCircuit::CheckpointAccumulatorV1
        }
    }
}

#[cfg(test)]
fn transparent_statement_tag(statement: TransparentProofStatement) -> u8 {
    match statement {
        TransparentProofStatement::ShieldedTransfer => 0,
        TransparentProofStatement::PrivateDelegation => 1,
        TransparentProofStatement::PrivateUndelegation => 2,
        TransparentProofStatement::UnbondingClaim => 3,
        TransparentProofStatement::PrivateExternalStake => 4,
        TransparentProofStatement::ExternalAssetAnchor => 5,
        TransparentProofStatement::CheckpointAccumulator => 6,
    }
}

#[cfg(test)]
fn transparent_circuit_tag(circuit: TransparentCircuit) -> u8 {
    match circuit {
        TransparentCircuit::OrdinaryTransferV1 => 0,
        TransparentCircuit::PrivateDelegationV1 => 1,
        TransparentCircuit::PrivateUndelegationV1 => 2,
        TransparentCircuit::UnbondingClaimV1 => 3,
        TransparentCircuit::ZcashShieldedStakeV1 => 4,
        TransparentCircuit::ExternalAssetAnchorV1 => 5,
        TransparentCircuit::CheckpointAccumulatorV1 => 6,
    }
}

#[cfg(test)]
fn statement_digest_for_serializable<T: serde::Serialize>(
    circuit: TransparentCircuit,
    value: &T,
) -> Result<[u8; 32]> {
    let descriptor = transparent_circuit_descriptor(circuit);
    let encoded =
        bincode::serialize(value).context("serialize transparent statement for digest binding")?;
    Ok(proof_core::proof_hash_domain_parts(
        TRANSPARENT_STATEMENT_DIGEST_DOMAIN,
        &[
            &[TRANSPARENT_PROOF_VERSION],
            &[transparent_statement_tag(descriptor.statement)],
            &[transparent_circuit_tag(circuit)],
            descriptor.public_input_shape.as_bytes(),
            encoded.as_slice(),
        ],
    ))
}

#[cfg(test)]
fn ensure_statement_digest(
    proof: &TransparentProof,
    expected: [u8; 32],
    context: &str,
) -> Result<()> {
    if proof.statement_digest != expected {
        bail!("{context} statement digest mismatch");
    }
    Ok(())
}

#[cfg(test)]
fn shielded_journal_statement_digest(
    circuit: TransparentCircuit,
    journal: &ProofShieldedTxJournal,
) -> Result<[u8; 32]> {
    statement_digest_for_serializable(circuit, journal)
}

pub fn shielded_tx_witness_digest(witness: &ProofShieldedTxWitness) -> Result<[u8; 32]> {
    Ok(crate::crypto::blake3_hash(
        &bincode::serialize(witness).context("serialize shielded witness for digest")?,
    ))
}

fn proof_backend_unavailable<T>() -> Result<T> {
    bail!(
        "native transparent proof backend is not implemented; refusing to generate or accept unverifiable proofs"
    )
}

pub fn prove_shielded_tx(
    _witness: &ProofShieldedTxWitness,
) -> Result<(TransparentProof, ProofShieldedTxJournal)> {
    proof_backend_unavailable()
}

pub fn verify_shielded_proof(proof: &TransparentProof) -> Result<ProofShieldedTxJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::ShieldedTransfer,
        "shielded proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn prove_private_delegation(
    _witness: &ProofPrivateDelegationWitness,
) -> Result<(TransparentProof, ProofPrivateDelegationJournal)> {
    proof_backend_unavailable()
}

pub fn verify_private_delegation_proof(
    proof: &TransparentProof,
) -> Result<ProofPrivateDelegationJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateDelegation,
        "private delegation proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn prove_private_undelegation(
    _witness: &ProofPrivateUndelegationWitness,
) -> Result<(TransparentProof, ProofPrivateUndelegationJournal)> {
    proof_backend_unavailable()
}

pub fn verify_private_undelegation_proof(
    proof: &TransparentProof,
) -> Result<ProofPrivateUndelegationJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateUndelegation,
        "private undelegation proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn prove_unbonding_claim(
    _witness: &ProofShieldedTxWitness,
) -> Result<(TransparentProof, ProofShieldedTxJournal)> {
    proof_backend_unavailable()
}

pub fn verify_unbonding_claim_proof(proof: &TransparentProof) -> Result<ProofShieldedTxJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::UnbondingClaim,
        "unbonding claim proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn prove_private_external_stake(
    _witness: &ProofPrivateExternalStakeWitness,
) -> Result<(TransparentProof, ProofPrivateExternalStakeJournal)> {
    proof_backend_unavailable()
}

pub fn verify_private_external_stake_proof(
    proof: &TransparentProof,
) -> Result<ProofPrivateExternalStakeJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateExternalStake,
        "private external stake proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn prove_external_asset_anchor(
    _witness: &ProofExternalAssetAnchorWitness,
) -> Result<(TransparentProof, ProofExternalAssetAnchorJournal)> {
    proof_backend_unavailable()
}

pub fn verify_external_asset_anchor_proof(
    proof: &TransparentProof,
) -> Result<ProofExternalAssetAnchorJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::ExternalAssetAnchor,
        "external asset anchor proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn proof_to_bytes(proof: &TransparentProof) -> Result<Vec<u8>> {
    bincode::serialize(proof).context("serialize transparent proof")
}

pub fn proof_from_bytes(bytes: &[u8]) -> Result<TransparentProof> {
    let proof: TransparentProof =
        bincode::deserialize(bytes).context("decode transparent proof bytes")?;
    proof.validate_metadata()?;
    Ok(proof)
}

pub fn prove_checkpoint_accumulator(
    _checkpoint: &HistoricalUnspentCheckpoint,
    _extension: &HistoricalUnspentExtension,
    _prior: Option<&CheckpointAccumulatorProof>,
) -> Result<CheckpointAccumulatorProof> {
    proof_backend_unavailable()
}

pub fn verify_checkpoint_accumulator_proof(
    proof: &TransparentProof,
) -> Result<CheckpointAccumulatorJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::CheckpointAccumulator,
        "checkpoint accumulator proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    proof_backend_unavailable()
}

pub fn checkpoint_accumulator_verifier_hint() -> Result<[u32; 8]> {
    proof_backend_unavailable()
}

pub fn checkpoint_accumulator_verifier_key_commitment() -> Result<[u8; 32]> {
    Ok(proof_core::proof_hash_domain_parts(
        NATIVE_TRANSPARENT_BACKEND_KEY_DOMAIN,
        &[b"checkpoint-accumulator-v1"],
    ))
}

pub fn output_binding(output: &ShieldedOutput) -> ProofShieldedOutputBinding {
    let public = public_output_from_local(output);
    ProofShieldedOutputBinding {
        note_commitment: public.note_commitment,
        public_output_digest: proof_core::public_output_digest(&public),
    }
}

pub fn public_output_from_local(output: &ShieldedOutput) -> ProofShieldedOutput {
    ProofShieldedOutput {
        note_commitment: output.note_commitment,
        kem_ct: output.kem_ct.to_vec(),
        nonce: output.nonce,
        view_tag: output.view_tag,
        ciphertext: output.ciphertext.clone(),
    }
}

pub fn output_plaintext_to_proof(
    plaintext: &ShieldedOutputPlaintext,
) -> ProofShieldedOutputPlaintext {
    ProofShieldedOutputPlaintext {
        note: note_to_proof(&plaintext.note),
        note_key: plaintext.note_key,
        checkpoint: checkpoint_to_proof(&plaintext.checkpoint),
    }
}

pub fn output_plaintext_from_proof(
    plaintext: &ProofShieldedOutputPlaintext,
) -> Result<ShieldedOutputPlaintext> {
    let owner_signing_pk =
        TaggedSigningPublicKey::from_ml_dsa_65_bytes(&plaintext.note.owner_signing_pk)?;
    let owner_kem_pk = TaggedKemPublicKey::from_ml_kem_768_bytes(&plaintext.note.owner_kem_pk)?;
    Ok(ShieldedOutputPlaintext {
        note: ShieldedNote {
            version: plaintext.note.version,
            kind: note_kind_from_proof(&plaintext.note.kind),
            value: plaintext.note.value,
            birth_epoch: plaintext.note.birth_epoch,
            owner_address: plaintext.note.owner_address,
            owner_signing_key_commitment: plaintext.note.owner_signing_key_commitment,
            owner_kem_key_commitment: plaintext.note.owner_kem_key_commitment,
            owner_signing_pk,
            owner_kem_pk,
            rho: plaintext.note.rho,
            note_randomizer: plaintext.note.note_randomizer,
            note_key_commitment: plaintext.note.note_key_commitment,
            commitment: plaintext.note.commitment,
        },
        note_key: plaintext.note_key,
        checkpoint: HistoricalUnspentCheckpoint {
            version: plaintext.checkpoint.version,
            note_commitment: plaintext.checkpoint.note_commitment,
            birth_epoch: plaintext.checkpoint.birth_epoch,
            covered_through_epoch: plaintext.checkpoint.covered_through_epoch,
            transcript_root: plaintext.checkpoint.transcript_root,
            verified_epoch_count: plaintext.checkpoint.verified_epoch_count,
        },
    })
}

pub fn output_witness_from_local(
    plaintext: &ShieldedOutputPlaintext,
    output: &ShieldedOutput,
    encapsulation_seed: &[u8; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN],
) -> ProofShieldedOutputWitness {
    ProofShieldedOutputWitness {
        plaintext: output_plaintext_to_proof(plaintext),
        public_output: public_output_from_local(output),
        encapsulation_seed: *encapsulation_seed,
    }
}

pub fn input_witness_from_local(
    note: &ShieldedNote,
    note_key: &[u8; 32],
    membership_proof: &NoteMembershipProof,
    historical_checkpoint: &HistoricalUnspentCheckpoint,
    historical_extension: Option<&HistoricalUnspentExtension>,
    historical_accumulator: Option<&CheckpointAccumulatorProof>,
    current_nullifier: &[u8; 32],
) -> Result<ProofShieldedInputWitness> {
    if historical_accumulator.is_some() {
        bail!(
            "historical accumulator witnesses require a transparent proof backend; direct historical extensions remain supported until the native backend is implemented"
        );
    }
    Ok(ProofShieldedInputWitness {
        note: note_to_proof(note),
        note_key: *note_key,
        membership_proof: membership_proof_to_proof(membership_proof),
        historical_checkpoint: checkpoint_to_proof(historical_checkpoint),
        historical_extension: historical_extension.map(extension_to_proof),
        historical_accumulator: None,
        historical_accumulator_verifier_hint: None,
        historical_accumulator_receipt: None,
        current_nullifier: *current_nullifier,
    })
}

fn require_transparent_statement(
    proof: &TransparentProof,
    expected: TransparentProofStatement,
    context: &str,
) -> Result<()> {
    proof
        .validate_metadata()
        .with_context(|| format!("validate {context} metadata"))?;
    if proof.statement != expected {
        bail!(
            "{context} statement mismatch: expected {:?}, got {:?}",
            expected,
            proof.statement
        );
    }
    Ok(())
}

fn note_to_proof(note: &ShieldedNote) -> ProofShieldedNote {
    ProofShieldedNote {
        version: note.version,
        kind: note_kind_to_proof(&note.kind),
        value: note.value,
        birth_epoch: note.birth_epoch,
        owner_address: note.owner_address,
        owner_signing_key_commitment: note.owner_signing_key_commitment,
        owner_kem_key_commitment: note.owner_kem_key_commitment,
        owner_signing_pk: note.owner_signing_pk.bytes.to_vec(),
        owner_kem_pk: note.owner_kem_pk.bytes.to_vec(),
        rho: note.rho,
        note_randomizer: note.note_randomizer,
        note_key_commitment: note.note_key_commitment,
        commitment: note.commitment,
    }
}

fn note_kind_to_proof(kind: &ShieldedNoteKind) -> ProofShieldedNoteKind {
    match kind {
        ShieldedNoteKind::Payment => ProofShieldedNoteKind::Payment,
        ShieldedNoteKind::DelegationShare { validator_id } => {
            ProofShieldedNoteKind::DelegationShare {
                validator_id: *validator_id,
            }
        }
        ShieldedNoteKind::UnbondingClaim {
            validator_id,
            release_epoch,
        } => ProofShieldedNoteKind::UnbondingClaim {
            validator_id: *validator_id,
            release_epoch: *release_epoch,
        },
        ShieldedNoteKind::ExternalStakeReceipt {
            asset_id,
            stake_position_commitment,
        } => ProofShieldedNoteKind::ExternalStakeReceipt {
            asset_id: *asset_id,
            stake_position_commitment: *stake_position_commitment,
        },
    }
}

fn note_kind_from_proof(kind: &ProofShieldedNoteKind) -> ShieldedNoteKind {
    match kind {
        ProofShieldedNoteKind::Payment => ShieldedNoteKind::Payment,
        ProofShieldedNoteKind::DelegationShare { validator_id } => {
            ShieldedNoteKind::DelegationShare {
                validator_id: *validator_id,
            }
        }
        ProofShieldedNoteKind::UnbondingClaim {
            validator_id,
            release_epoch,
        } => ShieldedNoteKind::UnbondingClaim {
            validator_id: *validator_id,
            release_epoch: *release_epoch,
        },
        ProofShieldedNoteKind::ExternalStakeReceipt {
            asset_id,
            stake_position_commitment,
        } => ShieldedNoteKind::ExternalStakeReceipt {
            asset_id: *asset_id,
            stake_position_commitment: *stake_position_commitment,
        },
    }
}

fn membership_proof_to_proof(proof: &NoteMembershipProof) -> ProofNoteMembershipProof {
    ProofNoteMembershipProof {
        note_commitment: proof.note_commitment,
        root: proof.root,
        proof: proof.proof.clone(),
    }
}

fn checkpoint_to_proof(
    checkpoint: &HistoricalUnspentCheckpoint,
) -> ProofHistoricalUnspentCheckpoint {
    ProofHistoricalUnspentCheckpoint {
        version: checkpoint.version,
        note_commitment: checkpoint.note_commitment,
        birth_epoch: checkpoint.birth_epoch,
        covered_through_epoch: checkpoint.covered_through_epoch,
        transcript_root: checkpoint.transcript_root,
        verified_epoch_count: checkpoint.verified_epoch_count,
    }
}

fn extension_to_proof(
    extension: &HistoricalUnspentExtension,
) -> proof_core::HistoricalUnspentExtension {
    proof_core::HistoricalUnspentExtension {
        version: extension.version,
        note_commitment: extension.note_commitment,
        from_epoch: extension.from_epoch,
        through_epoch: extension.through_epoch,
        prior_transcript_root: extension.prior_transcript_root,
        historical_root_digest: extension.historical_root_digest,
        stratum_commitment_root: extension.stratum_commitment_root,
        aggregate_rerandomization_blinding: extension.aggregate_rerandomization_blinding,
        new_transcript_root: extension.new_transcript_root,
        strata: extension.strata.iter().map(stratum_to_proof).collect(),
    }
}

fn stratum_to_proof(stratum: &HistoricalUnspentStratum) -> ProofHistoricalUnspentStratum {
    ProofHistoricalUnspentStratum {
        from_epoch: stratum.from_epoch,
        through_epoch: stratum.through_epoch,
        stratum_historical_root_digest: stratum.stratum_historical_root_digest,
        packet_commitment_root: stratum.packet_commitment_root,
        stratum_rerandomization_blinding: stratum.stratum_rerandomization_blinding,
        stratum_transcript_root: stratum.stratum_transcript_root,
        packets: stratum.packets.iter().map(packet_to_proof).collect(),
    }
}

fn packet_to_proof(packet: &HistoricalUnspentPacket) -> ProofHistoricalUnspentPacket {
    ProofHistoricalUnspentPacket {
        from_epoch: packet.from_epoch,
        through_epoch: packet.through_epoch,
        packet_historical_root_digest: packet.packet_historical_root_digest,
        segment_commitment_root: packet.segment_commitment_root,
        packet_rerandomization_blinding: packet.packet_rerandomization_blinding,
        packet_transcript_root: packet.packet_transcript_root,
        segments: packet.segments.iter().map(segment_to_proof).collect(),
    }
}

fn segment_to_proof(segment: &HistoricalUnspentSegment) -> ProofHistoricalUnspentSegment {
    ProofHistoricalUnspentSegment {
        provider_id: segment.provider_id,
        provider_manifest_digest: segment.provider_manifest_digest,
        from_epoch: segment.from_epoch,
        through_epoch: segment.through_epoch,
        segment_service_root: segment.segment_service_root,
        segment_historical_root_digest: segment.segment_historical_root_digest,
        rerandomization_blinding: segment.rerandomization_blinding,
        segment_transcript_root: segment.segment_transcript_root,
        records: segment
            .records
            .iter()
            .map(absence_record_to_proof)
            .collect(),
    }
}

fn absence_record_to_proof(record: &HistoricalAbsenceRecord) -> ProofHistoricalAbsenceRecord {
    ProofHistoricalAbsenceRecord {
        epoch: record.epoch,
        nullifier: record.nullifier,
        proof: nullifier_non_membership_to_proof(&record.proof),
    }
}

fn nullifier_non_membership_to_proof(
    proof: &NullifierNonMembershipProof,
) -> ProofNullifierNonMembershipProof {
    ProofNullifierNonMembershipProof {
        epoch: proof.epoch,
        queried_nullifier: proof.queried_nullifier,
        root: proof.root,
        set_size: proof.set_size,
        predecessor: proof
            .predecessor
            .as_ref()
            .map(nullifier_membership_to_proof),
        successor: proof.successor.as_ref().map(nullifier_membership_to_proof),
    }
}

fn nullifier_membership_to_proof(
    witness: &NullifierMembershipWitness,
) -> ProofNullifierMembershipWitness {
    ProofNullifierMembershipWitness {
        nullifier: witness.nullifier,
        root: witness.root,
        proof: witness.proof.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_shielded_journal() -> ProofShieldedTxJournal {
        ProofShieldedTxJournal {
            chain_id: [7u8; 32],
            current_epoch: 3,
            note_tree_root: [9u8; 32],
            fee_amount: 11,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    #[test]
    fn transparent_circuit_inventory_is_statement_consistent() {
        for circuit in transparent_circuit_inventory() {
            let descriptor = transparent_circuit_descriptor(*circuit);
            assert_eq!(descriptor.circuit, *circuit);
            assert_eq!(
                canonical_circuit_for_statement(descriptor.statement),
                *circuit
            );
            assert_eq!(descriptor.proof_family, TransparentProofFamily::Stark);
            assert!(descriptor.target_security_bits >= MIN_TRANSPARENT_PROOF_SECURITY_BITS);
            assert!(!descriptor.name.is_empty());
            assert!(!descriptor.public_input_shape.is_empty());
        }
    }

    #[test]
    fn current_prover_capabilities_cover_canonical_inventory() {
        let capabilities = current_prover_capabilities();
        capabilities.validate().expect("valid capabilities");
        assert_eq!(
            capabilities.backend,
            TransparentProofBackend::NativeTransparentStarkV1
        );
        assert_eq!(capabilities.proof_family, TransparentProofFamily::Stark);
        assert_eq!(
            capabilities.supported_circuits,
            transparent_circuit_inventory().to_vec()
        );
        for circuit in transparent_circuit_inventory() {
            assert!(capabilities.supports_circuit(*circuit));
        }
    }

    #[test]
    fn transparent_proof_metadata_rejects_mismatched_statement_and_circuit() {
        let proof = TransparentProof {
            version: TRANSPARENT_PROOF_VERSION,
            statement: TransparentProofStatement::ShieldedTransfer,
            circuit: TransparentCircuit::PrivateDelegationV1,
            backend: TransparentProofBackend::NativeTransparentStarkV1,
            statement_digest: [0u8; 32],
            seal: vec![1, 2, 3],
        };
        let err = proof.validate_metadata().expect_err("metadata mismatch");
        assert!(err.to_string().contains("does not match statement"));
    }

    #[test]
    fn transparent_proof_metadata_accepts_current_backend_binding() {
        let mut capabilities = current_prover_capabilities();
        capabilities.proof_family = TransparentProofFamily::Stark;
        capabilities
            .validate()
            .expect("valid prototype capabilities");

        let proof = TransparentProof {
            version: TRANSPARENT_PROOF_VERSION,
            statement: TransparentProofStatement::ShieldedTransfer,
            circuit: TransparentCircuit::OrdinaryTransferV1,
            backend: TransparentProofBackend::NativeTransparentStarkV1,
            statement_digest: [0u8; 32],
            seal: vec![1],
        };
        proof.validate_metadata().expect("valid proof");
    }

    #[test]
    fn transparent_prover_capabilities_reject_empty_and_duplicate_inventory() {
        let mut empty = current_prover_capabilities();
        empty.supported_circuits.clear();
        let err = empty.validate().expect_err("empty inventory");
        assert!(err.to_string().contains("capability list is empty"));

        let mut duplicate = current_prover_capabilities();
        duplicate
            .supported_circuits
            .push(TransparentCircuit::OrdinaryTransferV1);
        let err = duplicate.validate().expect_err("duplicate inventory");
        assert!(err.to_string().contains("duplicate circuits"));
    }

    #[test]
    fn transparent_prover_capabilities_reject_security_budget_mismatch() {
        let mut capabilities = current_prover_capabilities();
        capabilities.target_security_bits = capabilities.target_security_bits.saturating_add(1);
        let err = capabilities.validate().expect_err("budget mismatch");
        assert!(err.to_string().contains("advertised"));
    }

    #[test]
    fn statement_digest_depends_on_circuit_binding() {
        let journal = sample_shielded_journal();
        let transfer =
            shielded_journal_statement_digest(TransparentCircuit::OrdinaryTransferV1, &journal)
                .expect("transfer digest");
        let claim =
            shielded_journal_statement_digest(TransparentCircuit::UnbondingClaimV1, &journal)
                .expect("claim digest");
        assert_ne!(transfer, claim);
    }

    #[test]
    fn canonical_proof_round_trip_preserves_statement_digest() {
        let journal = sample_shielded_journal();
        let digest =
            shielded_journal_statement_digest(TransparentCircuit::OrdinaryTransferV1, &journal)
                .expect("statement digest");
        let proof = TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::OrdinaryTransferV1,
            digest,
            vec![1, 2, 3, 4],
        );
        let encoded = crate::canonical::encode_transparent_proof(&proof).expect("encode proof");
        let decoded = crate::canonical::decode_transparent_proof(&encoded).expect("decode proof");
        assert_eq!(decoded.statement_digest, digest);
        assert_eq!(decoded, proof);
    }

    #[test]
    fn statement_digest_binding_rejects_mismatch() {
        let journal = sample_shielded_journal();
        let expected =
            shielded_journal_statement_digest(TransparentCircuit::OrdinaryTransferV1, &journal)
                .expect("statement digest");
        let proof = TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::OrdinaryTransferV1,
            [0x55; 32],
            vec![9, 8, 7],
        );
        let err =
            ensure_statement_digest(&proof, expected, "test proof").expect_err("digest mismatch");
        assert!(err.to_string().contains("statement digest mismatch"));
    }
}
