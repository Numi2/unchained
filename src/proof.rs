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
    ProofShieldedTxWitness, ProofZcashShieldedLockClaimJournal, ProofZcashShieldedLockWitness,
};
use serde::{Deserialize, Serialize};

mod zec_native_stark;

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
const TRANSPARENT_STATEMENT_DIGEST_DOMAIN: &str = "unchained-transparent-statement-digest-v1";
const NATIVE_TRANSPARENT_BACKEND_KEY_DOMAIN: &str = "unchained-native-transparent-backend-v1";
const ZCASH_LOCK_CLAIM_PUBLIC_INPUT_SHAPE: &str = "zcash-shielded-lock-claim-v1";
pub const NATIVE_TRANSPARENT_PROOF_UNAVAILABLE_REASON: &str =
    "native transparent proof backend is not implemented; refusing to generate or accept unverifiable proofs";
pub const ZCASH_ORCHARD_IRONWOOD_PROOF_UNAVAILABLE_REASON: &str =
    "native Zcash Orchard/Ironwood proof backend is not implemented; refusing to generate or accept ZEC staking anchor/stake proofs";

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentCircuitReadiness {
    pub journal_shape_validator_available: bool,
    pub statement_digest_binding_available: bool,
    pub native_prover_available: bool,
    pub native_verifier_available: bool,
    pub positive_test_vectors_available: bool,
    pub negative_test_vectors_available: bool,
    pub operator_enabled: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentCircuitActivationEvidence {
    pub native_prover_commitment: Option<[u8; 32]>,
    pub native_verifier_commitment: Option<[u8; 32]>,
    pub positive_test_vector_commitment: Option<[u8; 32]>,
    pub negative_test_vector_commitment: Option<[u8; 32]>,
    pub operator_activation_commitment: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentCircuitStatus {
    pub circuit: TransparentCircuit,
    pub statement: TransparentProofStatement,
    pub backend: TransparentProofBackend,
    pub proof_family: TransparentProofFamily,
    pub target_security_bits: u16,
    pub verifier_key_commitment: [u8; 32],
    pub public_input_shape: String,
    pub name: String,
    pub readiness: TransparentCircuitReadiness,
    pub prover_enabled: bool,
    pub verifier_enabled: bool,
    pub fail_closed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentCircuitActivationManifestEntry {
    pub circuit: TransparentCircuit,
    pub statement: TransparentProofStatement,
    pub backend: TransparentProofBackend,
    pub proof_family: TransparentProofFamily,
    pub target_security_bits: u16,
    pub verifier_key_commitment: [u8; 32],
    pub public_input_shape: String,
    pub name: String,
    pub readiness: TransparentCircuitReadiness,
    pub evidence: TransparentCircuitActivationEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparentNativeBackendActivationManifest {
    pub backend: TransparentProofBackend,
    pub proof_family: TransparentProofFamily,
    pub target_security_bits: u16,
    pub seal_encoding: TransparentSealEncoding,
    pub name: String,
    pub circuits: Vec<TransparentCircuitActivationManifestEntry>,
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
        .filter(|circuit| {
            let status = transparent_circuit_status(*circuit);
            status.backend == backend && status.prover_enabled
        })
        .collect()
}

#[cfg(test)]
fn known_circuits_for_backend(backend: TransparentProofBackend) -> Vec<TransparentCircuit> {
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

pub fn transparent_circuit_activation_manifest_entry(
    circuit: TransparentCircuit,
) -> TransparentCircuitActivationManifestEntry {
    let descriptor = transparent_circuit_descriptor(circuit);
    TransparentCircuitActivationManifestEntry {
        circuit,
        statement: descriptor.statement,
        backend: canonical_backend_for_circuit(circuit),
        proof_family: descriptor.proof_family,
        target_security_bits: descriptor.target_security_bits,
        verifier_key_commitment: transparent_verifier_key_commitment(circuit),
        public_input_shape: descriptor.public_input_shape.to_string(),
        name: descriptor.name.to_string(),
        readiness: transparent_circuit_readiness(circuit),
        evidence: transparent_circuit_activation_evidence(circuit),
    }
}

pub fn current_native_backend_activation_manifest() -> TransparentNativeBackendActivationManifest {
    let descriptor =
        transparent_backend_descriptor(TransparentProofBackend::NativeTransparentStarkV1);
    TransparentNativeBackendActivationManifest {
        backend: descriptor.backend,
        proof_family: descriptor.proof_family,
        target_security_bits: descriptor.target_security_bits,
        seal_encoding: descriptor.seal_encoding,
        name: descriptor.name.to_string(),
        circuits: transparent_circuit_inventory()
            .iter()
            .copied()
            .map(transparent_circuit_activation_manifest_entry)
            .collect(),
    }
}

pub fn transparent_circuit_status(circuit: TransparentCircuit) -> TransparentCircuitStatus {
    let entry = transparent_circuit_activation_manifest_entry(circuit);
    transparent_circuit_status_from_manifest_entry(&entry)
}

fn transparent_circuit_status_from_manifest_entry(
    entry: &TransparentCircuitActivationManifestEntry,
) -> TransparentCircuitStatus {
    TransparentCircuitStatus {
        circuit: entry.circuit,
        statement: entry.statement,
        backend: entry.backend,
        proof_family: entry.proof_family,
        target_security_bits: entry.target_security_bits,
        verifier_key_commitment: entry.verifier_key_commitment,
        public_input_shape: entry.public_input_shape.clone(),
        name: entry.name.clone(),
        readiness: entry.readiness,
        prover_enabled: entry.readiness.prover_advertisement_ready(),
        verifier_enabled: entry.readiness.consensus_activation_ready(),
        fail_closed: !entry.readiness.consensus_activation_ready(),
        reason: transparent_circuit_unavailable_reason(entry.circuit).to_string(),
    }
}

fn transparent_circuit_status_from_current_manifest(
    circuit: TransparentCircuit,
) -> Result<TransparentCircuitStatus> {
    let manifest = current_native_backend_activation_manifest();
    manifest
        .validate()
        .context("validate transparent proof backend activation manifest")?;
    let entry = manifest
        .circuits
        .iter()
        .find(|entry| entry.circuit == circuit)
        .with_context(|| {
            format!("transparent proof backend activation manifest missing circuit {circuit:?}")
        })?;
    Ok(transparent_circuit_status_from_manifest_entry(entry))
}

fn require_transparent_circuit_prover_enabled(circuit: TransparentCircuit) -> Result<()> {
    let status = transparent_circuit_status_from_current_manifest(circuit)?;
    if !status.prover_enabled {
        bail!("{}", status.reason);
    }
    Ok(())
}

fn require_transparent_circuit_verifier_enabled(circuit: TransparentCircuit) -> Result<()> {
    let status = transparent_circuit_status_from_current_manifest(circuit)?;
    if !status.verifier_enabled {
        bail!("{}", status.reason);
    }
    Ok(())
}

pub fn transparent_circuit_status_inventory() -> Vec<TransparentCircuitStatus> {
    current_native_backend_activation_manifest()
        .circuits
        .iter()
        .map(transparent_circuit_status_from_manifest_entry)
        .collect()
}

fn transparent_circuit_unavailable_reason(circuit: TransparentCircuit) -> &'static str {
    match circuit {
        TransparentCircuit::ZcashShieldedStakeV1 | TransparentCircuit::ExternalAssetAnchorV1 => {
            ZCASH_ORCHARD_IRONWOOD_PROOF_UNAVAILABLE_REASON
        }
        TransparentCircuit::OrdinaryTransferV1
        | TransparentCircuit::PrivateDelegationV1
        | TransparentCircuit::PrivateUndelegationV1
        | TransparentCircuit::UnbondingClaimV1
        | TransparentCircuit::CheckpointAccumulatorV1 => {
            NATIVE_TRANSPARENT_PROOF_UNAVAILABLE_REASON
        }
    }
}

pub fn transparent_circuit_readiness(circuit: TransparentCircuit) -> TransparentCircuitReadiness {
    match circuit {
        TransparentCircuit::ExternalAssetAnchorV1 => TransparentCircuitReadiness {
            journal_shape_validator_available: true,
            statement_digest_binding_available: true,
            native_prover_available: true,
            native_verifier_available: true,
            positive_test_vectors_available: true,
            negative_test_vectors_available: true,
            operator_enabled: true,
        },
        _ => TransparentCircuitReadiness {
            journal_shape_validator_available: true,
            statement_digest_binding_available: true,
            native_prover_available: false,
            native_verifier_available: false,
            positive_test_vectors_available: false,
            negative_test_vectors_available: false,
            operator_enabled: false,
        },
    }
}

pub fn transparent_circuit_activation_evidence(
    circuit: TransparentCircuit,
) -> TransparentCircuitActivationEvidence {
    match circuit {
        TransparentCircuit::ExternalAssetAnchorV1 => {
            let artifacts = zec_native_stark::external_asset_anchor_artifacts();
            TransparentCircuitActivationEvidence {
                native_prover_commitment: Some(artifacts.prover_commitment),
                native_verifier_commitment: Some(artifacts.verifier_commitment),
                positive_test_vector_commitment: Some(artifacts.positive_vector_commitment),
                negative_test_vector_commitment: Some(artifacts.negative_vector_commitment),
                operator_activation_commitment: Some(artifacts.operator_commitment),
            }
        }
        _ => TransparentCircuitActivationEvidence::default(),
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
            public_input_shape: "zcash-shielded-stake-lock-binding-journal-v1",
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

pub fn transparent_verifier_key_commitment(circuit: TransparentCircuit) -> [u8; 32] {
    let descriptor = transparent_circuit_descriptor(circuit);
    let backend = transparent_backend_descriptor(canonical_backend_for_circuit(circuit));
    proof_core::proof_hash_domain_parts(
        NATIVE_TRANSPARENT_BACKEND_KEY_DOMAIN,
        &[
            &[TRANSPARENT_PROOF_VERSION],
            backend.name.as_bytes(),
            descriptor.name.as_bytes(),
            descriptor.public_input_shape.as_bytes(),
            &[transparent_statement_tag(descriptor.statement)],
            &[transparent_circuit_tag(circuit)],
            &descriptor.target_security_bits.to_le_bytes(),
        ],
    )
}

impl TransparentCircuitReadiness {
    pub fn consensus_activation_ready(&self) -> bool {
        self.journal_shape_validator_available
            && self.statement_digest_binding_available
            && self.native_verifier_available
            && self.negative_test_vectors_available
            && self.operator_enabled
    }

    pub fn prover_advertisement_ready(&self) -> bool {
        self.consensus_activation_ready()
            && self.native_prover_available
            && self.positive_test_vectors_available
    }
}

impl TransparentCircuitActivationEvidence {
    fn validate_for_readiness(
        &self,
        circuit: TransparentCircuit,
        readiness: &TransparentCircuitReadiness,
    ) -> Result<()> {
        validate_activation_commitment(
            circuit,
            "native prover",
            readiness.native_prover_available,
            self.native_prover_commitment,
        )?;
        validate_activation_commitment(
            circuit,
            "native verifier",
            readiness.native_verifier_available,
            self.native_verifier_commitment,
        )?;
        validate_activation_commitment(
            circuit,
            "positive test vector",
            readiness.positive_test_vectors_available,
            self.positive_test_vector_commitment,
        )?;
        validate_activation_commitment(
            circuit,
            "negative test vector",
            readiness.negative_test_vectors_available,
            self.negative_test_vector_commitment,
        )?;
        validate_activation_commitment(
            circuit,
            "operator activation",
            readiness.operator_enabled,
            self.operator_activation_commitment,
        )
    }
}

fn validate_activation_commitment(
    circuit: TransparentCircuit,
    label: &str,
    enabled: bool,
    commitment: Option<[u8; 32]>,
) -> Result<()> {
    match (enabled, commitment) {
        (true, Some(commitment)) if commitment != [0u8; 32] => Ok(()),
        (true, Some(_)) => bail!(
            "transparent circuit {:?} activation manifest {label} commitment must be nonzero",
            circuit
        ),
        (true, None) => bail!(
            "transparent circuit {:?} activation manifest requires {label} commitment",
            circuit
        ),
        (false, Some(_)) => bail!(
            "transparent circuit {:?} activation manifest has stale {label} commitment while readiness is disabled",
            circuit
        ),
        (false, None) => Ok(()),
    }
}

impl TransparentCircuitStatus {
    pub fn validate(&self) -> Result<()> {
        let descriptor = transparent_circuit_descriptor(self.circuit);
        if self.statement != descriptor.statement {
            bail!("transparent circuit status statement mismatch");
        }
        if self.proof_family != descriptor.proof_family {
            bail!("transparent circuit status proof family mismatch");
        }
        if self.target_security_bits != descriptor.target_security_bits {
            bail!("transparent circuit status security budget mismatch");
        }
        if self.public_input_shape != descriptor.public_input_shape {
            bail!("transparent circuit status public input shape mismatch");
        }
        if self.name != descriptor.name {
            bail!("transparent circuit status name mismatch");
        }
        if self.backend != canonical_backend_for_circuit(self.circuit) {
            bail!("transparent circuit status backend mismatch");
        }
        if self.verifier_key_commitment != transparent_verifier_key_commitment(self.circuit) {
            bail!("transparent circuit status verifier key commitment mismatch");
        }
        if self.readiness != transparent_circuit_readiness(self.circuit) {
            bail!("transparent circuit status readiness mismatch");
        }
        if self.verifier_enabled != self.readiness.consensus_activation_ready() {
            bail!("transparent circuit verifier flag does not match activation readiness");
        }
        if self.prover_enabled != self.readiness.prover_advertisement_ready() {
            bail!("transparent circuit prover flag does not match activation readiness");
        }
        if self.fail_closed == self.readiness.consensus_activation_ready() {
            bail!("transparent circuit fail-closed flag does not match activation readiness");
        }
        if self.fail_closed && self.reason.is_empty() {
            bail!("transparent circuit fail-closed status requires a reason");
        }
        Ok(())
    }
}

impl TransparentCircuitActivationManifestEntry {
    fn validate_for_manifest(
        &self,
        manifest: &TransparentNativeBackendActivationManifest,
    ) -> Result<()> {
        let descriptor = transparent_circuit_descriptor(self.circuit);
        if self.statement != descriptor.statement {
            bail!("transparent circuit activation manifest statement mismatch");
        }
        if self.proof_family != descriptor.proof_family {
            bail!("transparent circuit activation manifest proof family mismatch");
        }
        if self.target_security_bits != descriptor.target_security_bits {
            bail!("transparent circuit activation manifest security budget mismatch");
        }
        if self.target_security_bits < MIN_TRANSPARENT_PROOF_SECURITY_BITS {
            bail!("transparent circuit activation manifest security budget is below minimum");
        }
        if self.public_input_shape != descriptor.public_input_shape {
            bail!("transparent circuit activation manifest public input shape mismatch");
        }
        if self.name != descriptor.name {
            bail!("transparent circuit activation manifest name mismatch");
        }
        if self.backend != manifest.backend {
            bail!("transparent circuit activation manifest backend mismatch");
        }
        if self.backend != canonical_backend_for_circuit(self.circuit) {
            bail!("transparent circuit activation manifest non-canonical backend");
        }
        if self.verifier_key_commitment != transparent_verifier_key_commitment(self.circuit) {
            bail!("transparent circuit activation manifest verifier key commitment mismatch");
        }
        validate_transparent_circuit_readiness(self.circuit, &self.readiness)?;
        self.evidence
            .validate_for_readiness(self.circuit, &self.readiness)
    }
}

impl TransparentNativeBackendActivationManifest {
    pub fn validate(&self) -> Result<()> {
        let descriptor = transparent_backend_descriptor(self.backend);
        if self.proof_family != descriptor.proof_family {
            bail!("transparent native backend activation manifest proof family mismatch");
        }
        if self.target_security_bits != descriptor.target_security_bits {
            bail!("transparent native backend activation manifest security budget mismatch");
        }
        if self.target_security_bits < MIN_TRANSPARENT_PROOF_SECURITY_BITS {
            bail!(
                "transparent native backend activation manifest security budget is below minimum"
            );
        }
        if self.seal_encoding != descriptor.seal_encoding {
            bail!("transparent native backend activation manifest seal encoding mismatch");
        }
        if self.name != descriptor.name {
            bail!("transparent native backend activation manifest name mismatch");
        }
        if self.circuits.len() != transparent_circuit_inventory().len() {
            bail!(
                "transparent native backend activation manifest circuit inventory length mismatch"
            );
        }
        for (index, entry) in self.circuits.iter().enumerate() {
            if self.circuits[..index]
                .iter()
                .any(|prior| prior.circuit == entry.circuit)
            {
                bail!("transparent native backend activation manifest contains duplicate circuit");
            }
        }
        let observed = self
            .circuits
            .iter()
            .map(|entry| entry.circuit)
            .collect::<Vec<_>>();
        if observed != transparent_circuit_inventory() {
            bail!("transparent native backend activation manifest circuit order mismatch");
        }
        for entry in &self.circuits {
            entry.validate_for_manifest(self)?;
        }
        self.validate_zcash_dependency_activation()
    }

    fn circuit_entry(
        &self,
        circuit: TransparentCircuit,
    ) -> Option<&TransparentCircuitActivationManifestEntry> {
        self.circuits.iter().find(|entry| entry.circuit == circuit)
    }

    fn validate_zcash_dependency_activation(&self) -> Result<()> {
        let stake = self
            .circuit_entry(TransparentCircuit::ZcashShieldedStakeV1)
            .context("transparent native backend activation manifest missing ZEC stake circuit")?;
        let anchor = self
            .circuit_entry(TransparentCircuit::ExternalAssetAnchorV1)
            .context("transparent native backend activation manifest missing ZEC anchor circuit")?;

        if stake.readiness.consensus_activation_ready()
            && !anchor.readiness.consensus_activation_ready()
        {
            bail!("Zcash Orchard/Ironwood private stake circuit requires the external asset anchor verifier to be active");
        }
        if stake.readiness.prover_advertisement_ready()
            && !anchor.readiness.prover_advertisement_ready()
        {
            bail!("Zcash Orchard/Ironwood private stake prover requires the external asset anchor prover to be active");
        }
        Ok(())
    }
}

fn validate_transparent_circuit_readiness(
    circuit: TransparentCircuit,
    readiness: &TransparentCircuitReadiness,
) -> Result<()> {
    if !readiness.journal_shape_validator_available {
        bail!(
            "transparent circuit {:?} activation manifest is missing journal shape validation",
            circuit
        );
    }
    if !readiness.statement_digest_binding_available {
        bail!(
            "transparent circuit {:?} activation manifest is missing statement digest binding",
            circuit
        );
    }
    if readiness.negative_test_vectors_available && !readiness.native_verifier_available {
        bail!(
            "transparent circuit {:?} activation manifest has negative vectors without a native verifier",
            circuit
        );
    }
    if readiness.positive_test_vectors_available && !readiness.native_prover_available {
        bail!(
            "transparent circuit {:?} activation manifest has positive vectors without a native prover",
            circuit
        );
    }
    if readiness.native_prover_available && !readiness.native_verifier_available {
        bail!(
            "transparent circuit {:?} activation manifest has a native prover without a native verifier",
            circuit
        );
    }
    if readiness.operator_enabled && !readiness.consensus_activation_ready() {
        bail!(
            "transparent circuit {:?} activation manifest enables the operator gate before verifier readiness",
            circuit
        );
    }
    Ok(())
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

pub fn transparent_statement_digest_for_serializable<T: serde::Serialize>(
    circuit: TransparentCircuit,
    value: &T,
) -> Result<[u8; 32]> {
    let encoded =
        bincode::serialize(value).context("serialize transparent statement for digest binding")?;
    Ok(transparent_statement_digest_for_bytes(circuit, &encoded))
}

fn transparent_statement_digest_for_bytes(circuit: TransparentCircuit, encoded: &[u8]) -> [u8; 32] {
    let descriptor = transparent_circuit_descriptor(circuit);
    transparent_statement_digest_for_public_input_shape(
        circuit,
        descriptor.public_input_shape,
        encoded,
    )
}

fn transparent_statement_digest_for_public_input_shape(
    circuit: TransparentCircuit,
    public_input_shape: &str,
    encoded: &[u8],
) -> [u8; 32] {
    let descriptor = transparent_circuit_descriptor(circuit);
    proof_core::proof_hash_domain_parts(
        TRANSPARENT_STATEMENT_DIGEST_DOMAIN,
        &[
            &[TRANSPARENT_PROOF_VERSION],
            &[transparent_statement_tag(descriptor.statement)],
            &[transparent_circuit_tag(circuit)],
            public_input_shape.as_bytes(),
            &transparent_verifier_key_commitment(circuit),
            encoded,
        ],
    )
}

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

pub fn shielded_journal_statement_digest(
    circuit: TransparentCircuit,
    journal: &ProofShieldedTxJournal,
) -> Result<[u8; 32]> {
    transparent_statement_digest_for_serializable(circuit, journal)
}

pub fn private_external_stake_journal_statement_digest(
    journal: &ProofPrivateExternalStakeJournal,
) -> Result<[u8; 32]> {
    Ok(transparent_statement_digest_for_bytes(
        TransparentCircuit::ZcashShieldedStakeV1,
        &proof_core::encode_private_external_stake_public_inputs(journal),
    ))
}

pub fn zcash_lock_claim_journal_statement_digest(
    journal: &ProofZcashShieldedLockClaimJournal,
) -> Result<[u8; 32]> {
    proof_core::validate_zcash_shielded_lock_claim_journal(journal)
        .context("validate Zcash lock claim journal for statement digest")?;
    Ok(transparent_statement_digest_for_public_input_shape(
        TransparentCircuit::ZcashShieldedStakeV1,
        ZCASH_LOCK_CLAIM_PUBLIC_INPUT_SHAPE,
        &proof_core::encode_zcash_lock_claim_public_inputs(journal),
    ))
}

pub fn external_asset_anchor_journal_statement_digest(
    journal: &ProofExternalAssetAnchorJournal,
) -> Result<[u8; 32]> {
    Ok(transparent_statement_digest_for_bytes(
        TransparentCircuit::ExternalAssetAnchorV1,
        &proof_core::encode_external_asset_anchor_public_inputs(journal),
    ))
}

pub fn validate_private_external_stake_proof_journal(
    proof: &TransparentProof,
    journal: &ProofPrivateExternalStakeJournal,
) -> Result<()> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateExternalStake,
        "private external stake proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    if proof.circuit != TransparentCircuit::ZcashShieldedStakeV1 {
        bail!(
            "private external stake proof circuit mismatch: expected {:?}, got {:?}",
            TransparentCircuit::ZcashShieldedStakeV1,
            proof.circuit
        );
    }
    let expected = private_external_stake_journal_statement_digest(journal)?;
    ensure_statement_digest(proof, expected, "private external stake proof")
}

pub fn validate_external_asset_anchor_proof_journal(
    proof: &TransparentProof,
    journal: &ProofExternalAssetAnchorJournal,
) -> Result<()> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::ExternalAssetAnchor,
        "external asset anchor proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    if proof.circuit != TransparentCircuit::ExternalAssetAnchorV1 {
        bail!(
            "external asset anchor proof circuit mismatch: expected {:?}, got {:?}",
            TransparentCircuit::ExternalAssetAnchorV1,
            proof.circuit
        );
    }
    let expected = external_asset_anchor_journal_statement_digest(journal)?;
    ensure_statement_digest(proof, expected, "external asset anchor proof")
}

pub fn shielded_tx_witness_digest(witness: &ProofShieldedTxWitness) -> Result<[u8; 32]> {
    Ok(crate::crypto::blake3_hash(
        &bincode::serialize(witness).context("serialize shielded witness for digest")?,
    ))
}

fn proof_backend_unavailable<T>() -> Result<T> {
    bail!(NATIVE_TRANSPARENT_PROOF_UNAVAILABLE_REASON)
}

fn zcash_stake_proof_backend_unavailable<T>() -> Result<T> {
    bail!(ZCASH_ORCHARD_IRONWOOD_PROOF_UNAVAILABLE_REASON)
}

pub fn prove_shielded_tx(
    _witness: &ProofShieldedTxWitness,
) -> Result<(TransparentProof, ProofShieldedTxJournal)> {
    require_transparent_circuit_prover_enabled(TransparentCircuit::OrdinaryTransferV1)?;
    proof_backend_unavailable()
}

pub fn verify_shielded_proof(proof: &TransparentProof) -> Result<ProofShieldedTxJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::ShieldedTransfer,
        "shielded proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    require_transparent_circuit_verifier_enabled(TransparentCircuit::OrdinaryTransferV1)?;
    proof_backend_unavailable()
}

pub fn prove_private_delegation(
    _witness: &ProofPrivateDelegationWitness,
) -> Result<(TransparentProof, ProofPrivateDelegationJournal)> {
    require_transparent_circuit_prover_enabled(TransparentCircuit::PrivateDelegationV1)?;
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
    require_transparent_circuit_verifier_enabled(TransparentCircuit::PrivateDelegationV1)?;
    proof_backend_unavailable()
}

pub fn prove_private_undelegation(
    _witness: &ProofPrivateUndelegationWitness,
) -> Result<(TransparentProof, ProofPrivateUndelegationJournal)> {
    require_transparent_circuit_prover_enabled(TransparentCircuit::PrivateUndelegationV1)?;
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
    require_transparent_circuit_verifier_enabled(TransparentCircuit::PrivateUndelegationV1)?;
    proof_backend_unavailable()
}

pub fn prove_unbonding_claim(
    _witness: &ProofShieldedTxWitness,
) -> Result<(TransparentProof, ProofShieldedTxJournal)> {
    require_transparent_circuit_prover_enabled(TransparentCircuit::UnbondingClaimV1)?;
    proof_backend_unavailable()
}

pub fn verify_unbonding_claim_proof(proof: &TransparentProof) -> Result<ProofShieldedTxJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::UnbondingClaim,
        "unbonding claim proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    require_transparent_circuit_verifier_enabled(TransparentCircuit::UnbondingClaimV1)?;
    proof_backend_unavailable()
}

pub fn prove_private_external_stake(
    witness: &ProofPrivateExternalStakeWitness,
) -> Result<(TransparentProof, ProofPrivateExternalStakeJournal)> {
    let _journal = proof_core::validate_private_external_stake_witness(witness)
        .context("validate private external stake witness")?;
    require_transparent_circuit_prover_enabled(TransparentCircuit::ZcashShieldedStakeV1)?;
    zcash_stake_proof_backend_unavailable()
}

pub fn prove_private_external_stake_native_statement_for_ops(
    witness: &ProofPrivateExternalStakeWitness,
) -> Result<(TransparentProof, ProofPrivateExternalStakeJournal)> {
    let (seal, journal) =
        zec_native_stark::prove_private_external_stake_statement_from_witness(witness)?;
    let statement_digest = private_external_stake_journal_statement_digest(&journal)
        .context("compute private external stake statement digest")?;
    Ok((
        TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::ZcashShieldedStakeV1,
            statement_digest,
            seal,
        ),
        journal,
    ))
}

pub fn verify_private_external_stake_native_statement_for_ops(
    proof: &TransparentProof,
) -> Result<ProofPrivateExternalStakeJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateExternalStake,
        "private external stake native statement proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    let journal = zec_native_stark::verify_private_external_stake_statement(proof)?;
    validate_private_external_stake_proof_journal(proof, &journal)?;
    Ok(journal)
}

pub fn prove_zcash_lock_claim_native_statement_for_ops(
    witness: &ProofZcashShieldedLockWitness,
) -> Result<(TransparentProof, ProofZcashShieldedLockClaimJournal)> {
    let (seal, journal) = zec_native_stark::prove_zcash_lock_claim_statement_from_witness(witness)?;
    let statement_digest = zcash_lock_claim_journal_statement_digest(&journal)
        .context("compute Zcash lock claim statement digest")?;
    Ok((
        TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::ZcashShieldedStakeV1,
            statement_digest,
            seal,
        ),
        journal,
    ))
}

pub fn verify_zcash_lock_claim_native_statement_for_ops(
    proof: &TransparentProof,
) -> Result<ProofZcashShieldedLockClaimJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateExternalStake,
        "Zcash lock claim native statement proof",
    )?;
    ensure_canonical_backend_for_proof(proof)?;
    zec_native_stark::verify_zcash_lock_claim_statement(proof)
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
    require_transparent_circuit_verifier_enabled(TransparentCircuit::ZcashShieldedStakeV1)?;
    zcash_stake_proof_backend_unavailable()
}

pub fn prove_external_asset_anchor(
    witness: &ProofExternalAssetAnchorWitness,
) -> Result<(TransparentProof, ProofExternalAssetAnchorJournal)> {
    let journal = proof_core::validate_external_asset_anchor_witness(witness)
        .context("validate external asset anchor witness")?;
    require_transparent_circuit_prover_enabled(TransparentCircuit::ExternalAssetAnchorV1)?;
    let statement_digest = external_asset_anchor_journal_statement_digest(&journal)
        .context("compute external asset anchor statement digest")?;
    let seal = zec_native_stark::prove_external_asset_anchor(&journal, statement_digest)?;
    Ok((
        TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::ExternalAssetAnchorV1,
            statement_digest,
            seal,
        ),
        journal,
    ))
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
    require_transparent_circuit_verifier_enabled(TransparentCircuit::ExternalAssetAnchorV1)?;
    let journal = zec_native_stark::verify_external_asset_anchor(proof)?;
    validate_external_asset_anchor_proof_journal(proof, &journal)?;
    Ok(journal)
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
    require_transparent_circuit_prover_enabled(TransparentCircuit::CheckpointAccumulatorV1)?;
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
    require_transparent_circuit_verifier_enabled(TransparentCircuit::CheckpointAccumulatorV1)?;
    proof_backend_unavailable()
}

pub fn checkpoint_accumulator_verifier_hint() -> Result<[u32; 8]> {
    proof_backend_unavailable()
}

pub fn checkpoint_accumulator_verifier_key_commitment() -> Result<[u8; 32]> {
    Ok(transparent_verifier_key_commitment(
        TransparentCircuit::CheckpointAccumulatorV1,
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

    fn sample_external_asset_anchor_journal() -> ProofExternalAssetAnchorJournal {
        let zcash_anchor_height = 1_337;
        let zcash_block_hash = [4u8; 32];
        let zcash_note_commitment_root = [5u8; 32];
        let zcash_nullifier_root = [6u8; 32];
        ProofExternalAssetAnchorJournal {
            chain_id: [1u8; 32],
            current_epoch: 2,
            asset_id: [3u8; 32],
            zcash_protocol: proof_core::ZCASH_ORCHARD_PROTOCOL,
            zcash_anchor_height,
            zcash_block_hash,
            zcash_note_commitment_root,
            zcash_nullifier_root,
            zcash_anchor_hash: proof_core::zcash_stake_anchor_hash(
                proof_core::ZCASH_ORCHARD_PROTOCOL,
                zcash_anchor_height,
                &zcash_block_hash,
                &zcash_note_commitment_root,
                &zcash_nullifier_root,
            ),
            zcash_confirmation_depth: 24,
        }
    }

    fn sample_external_asset_anchor_witness() -> ProofExternalAssetAnchorWitness {
        let journal = sample_external_asset_anchor_journal();
        ProofExternalAssetAnchorWitness {
            chain_id: journal.chain_id,
            current_epoch: journal.current_epoch,
            asset_id: journal.asset_id,
            zcash_protocol: journal.zcash_protocol,
            zcash_anchor_height: journal.zcash_anchor_height,
            zcash_block_hash: journal.zcash_block_hash,
            zcash_note_commitment_root: journal.zcash_note_commitment_root,
            zcash_nullifier_root: journal.zcash_nullifier_root,
            zcash_anchor_hash: journal.zcash_anchor_hash,
            zcash_confirmation_depth: journal.zcash_confirmation_depth,
        }
    }

    fn sample_private_external_stake_journal() -> ProofPrivateExternalStakeJournal {
        let anchor = sample_external_asset_anchor_journal();
        let external_nullifier = [7u8; 32];
        let stake_position_commitment = [8u8; 32];
        let zcash_lock = sample_zcash_lock_binding(
            anchor.zcash_protocol,
            anchor.zcash_anchor_hash,
            external_nullifier,
            stake_position_commitment,
        );
        ProofPrivateExternalStakeJournal {
            chain_id: anchor.chain_id,
            current_epoch: anchor.current_epoch,
            asset_id: anchor.asset_id,
            zcash_protocol: anchor.zcash_protocol,
            zcash_anchor_height: anchor.zcash_anchor_height,
            zcash_block_hash: anchor.zcash_block_hash,
            zcash_note_commitment_root: anchor.zcash_note_commitment_root,
            zcash_nullifier_root: anchor.zcash_nullifier_root,
            zcash_anchor_hash: anchor.zcash_anchor_hash,
            zcash_confirmation_depth: anchor.zcash_confirmation_depth,
            activation_epoch: 64,
            external_nullifier,
            stake_position_commitment,
            zcash_lock,
            receipt_note_commitment: [9u8; 32],
            receipt_output: ProofShieldedOutputBinding {
                note_commitment: [9u8; 32],
                public_output_digest: [10u8; 32],
            },
        }
    }

    fn sample_zcash_lock_witness(
        protocol: u8,
        anchor_hash: [u8; 32],
        external_nullifier: [u8; 32],
        stake_position_commitment: [u8; 32],
    ) -> proof_core::ProofZcashShieldedLockWitness {
        proof_core::ProofZcashShieldedLockWitness {
            version: proof_core::ZCASH_LOCK_PROOF_ENVELOPE_VERSION,
            protocol,
            anchor_hash,
            external_nullifier,
            stake_position_commitment,
            action_commitment: [0x61; 32],
            lock_commitment: [0x62; 32],
            proof: vec![0x63, 0x64, 0x65],
        }
    }

    fn sample_zcash_lock_binding(
        protocol: u8,
        anchor_hash: [u8; 32],
        external_nullifier: [u8; 32],
        stake_position_commitment: [u8; 32],
    ) -> proof_core::ProofZcashShieldedLockBinding {
        let witness = sample_zcash_lock_witness(
            protocol,
            anchor_hash,
            external_nullifier,
            stake_position_commitment,
        );
        proof_core::validate_zcash_shielded_lock_witness(
            &witness,
            protocol,
            &anchor_hash,
            &external_nullifier,
            &stake_position_commitment,
        )
        .expect("valid sample Zcash lock binding")
    }

    fn sample_private_external_stake_receipt_output(
        asset_id: [u8; 32],
        stake_position_commitment: [u8; 32],
        current_epoch: u64,
    ) -> ProofShieldedOutputWitness {
        use chacha20poly1305::{
            aead::{Aead, NewAead},
            Key, XChaCha20Poly1305, XNonce,
        };

        let (_kem_sk, owner_kem_pk) =
            crate::crypto::ml_kem_768_generate_deterministic(&[0x21; 32], &[0x22; 32]);
        let owner_signing_pk = TaggedSigningPublicKey::zero_ml_dsa_65();
        let note_key = [0x23; 32];
        let note = ShieldedNote::new_with_kind(
            ShieldedNoteKind::ExternalStakeReceipt {
                asset_id,
                stake_position_commitment,
            },
            1,
            current_epoch,
            owner_signing_pk,
            owner_kem_pk.clone(),
            note_key,
            [0x24; 32],
            [0x25; 32],
        );
        let plaintext = ShieldedOutputPlaintext {
            checkpoint: HistoricalUnspentCheckpoint::genesis(note.commitment, current_epoch),
            note,
            note_key,
        };
        let encapsulation_seed = [0x26; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN];
        let nonce = [0x27; 24];
        let plaintext_bytes = bincode::serialize(&output_plaintext_to_proof(&plaintext))
            .expect("serialize receipt output plaintext");
        let (kem_ct, shared_key) = owner_kem_pk
            .encapsulate_deterministic(&encapsulation_seed)
            .expect("deterministic receipt KEM encapsulation");
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(&shared_key))
            .encrypt(XNonce::from_slice(&nonce), plaintext_bytes.as_ref())
            .expect("encrypt receipt output");
        let output = ShieldedOutput {
            note_commitment: plaintext.note.commitment,
            kem_ct,
            nonce,
            view_tag: crate::crypto::view_tag(&shared_key),
            ciphertext,
        };
        output_witness_from_local(&plaintext, &output, &encapsulation_seed)
    }

    fn sample_private_external_stake_witness() -> ProofPrivateExternalStakeWitness {
        let journal = sample_private_external_stake_journal();
        ProofPrivateExternalStakeWitness {
            chain_id: journal.chain_id,
            current_epoch: journal.current_epoch,
            asset_id: journal.asset_id,
            zcash_protocol: journal.zcash_protocol,
            zcash_anchor_height: journal.zcash_anchor_height,
            zcash_block_hash: journal.zcash_block_hash,
            zcash_note_commitment_root: journal.zcash_note_commitment_root,
            zcash_nullifier_root: journal.zcash_nullifier_root,
            zcash_anchor_hash: journal.zcash_anchor_hash,
            zcash_confirmation_depth: journal.zcash_confirmation_depth,
            activation_epoch: journal.activation_epoch,
            external_nullifier: journal.external_nullifier,
            stake_position_commitment: journal.stake_position_commitment,
            zcash_lock: sample_zcash_lock_witness(
                journal.zcash_protocol,
                journal.zcash_anchor_hash,
                journal.external_nullifier,
                journal.stake_position_commitment,
            ),
            receipt_output: sample_private_external_stake_receipt_output(
                journal.asset_id,
                journal.stake_position_commitment,
                journal.current_epoch,
            ),
        }
    }

    fn manifest_entry_mut(
        manifest: &mut TransparentNativeBackendActivationManifest,
        circuit: TransparentCircuit,
    ) -> &mut TransparentCircuitActivationManifestEntry {
        manifest
            .circuits
            .iter_mut()
            .find(|entry| entry.circuit == circuit)
            .expect("manifest circuit entry")
    }

    fn activation_commitment(seed: u8) -> [u8; 32] {
        [seed; 32]
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
            assert_ne!(transparent_verifier_key_commitment(*circuit), [0u8; 32]);
        }
    }

    #[test]
    fn transparent_verifier_key_commitments_are_circuit_bound() {
        let commitments = transparent_circuit_inventory()
            .iter()
            .map(|circuit| (*circuit, transparent_verifier_key_commitment(*circuit)))
            .collect::<Vec<_>>();
        for (index, (circuit, commitment)) in commitments.iter().enumerate() {
            assert_ne!(*commitment, [0u8; 32]);
            assert!(!commitments[..index]
                .iter()
                .any(|(prior_circuit, prior)| prior_circuit != circuit && prior == commitment));
        }
    }

    #[test]
    fn current_prover_capabilities_advertise_live_anchor_circuit() {
        let capabilities = current_prover_capabilities();
        capabilities.validate().expect("valid capabilities");
        assert_eq!(
            capabilities.backend,
            TransparentProofBackend::NativeTransparentStarkV1
        );
        assert_eq!(capabilities.proof_family, TransparentProofFamily::Stark);
        assert_eq!(
            capabilities.supported_circuits,
            vec![TransparentCircuit::ExternalAssetAnchorV1]
        );
        let known_circuits = known_circuits_for_backend(capabilities.backend);
        assert_eq!(known_circuits, transparent_circuit_inventory().to_vec());
        for circuit in transparent_circuit_inventory() {
            assert_eq!(
                capabilities.supports_circuit(*circuit),
                *circuit == TransparentCircuit::ExternalAssetAnchorV1
            );
        }
    }

    #[test]
    fn current_native_backend_activation_manifest_enables_anchor_only() {
        let manifest = current_native_backend_activation_manifest();
        manifest.validate().expect("valid manifest");
        assert_eq!(
            manifest.backend,
            TransparentProofBackend::NativeTransparentStarkV1
        );
        assert_eq!(
            manifest
                .circuits
                .iter()
                .map(|entry| entry.circuit)
                .collect::<Vec<_>>(),
            transparent_circuit_inventory().to_vec()
        );
        for entry in &manifest.circuits {
            let descriptor = transparent_circuit_descriptor(entry.circuit);
            assert_eq!(entry.statement, descriptor.statement);
            assert_eq!(entry.public_input_shape, descriptor.public_input_shape);
            assert_eq!(
                entry.verifier_key_commitment,
                transparent_verifier_key_commitment(entry.circuit)
            );
            assert_eq!(
                entry.readiness.consensus_activation_ready(),
                entry.circuit == TransparentCircuit::ExternalAssetAnchorV1
            );
            assert_eq!(
                entry.readiness.prover_advertisement_ready(),
                entry.circuit == TransparentCircuit::ExternalAssetAnchorV1
            );
            assert_eq!(
                entry.evidence,
                transparent_circuit_activation_evidence(entry.circuit)
            );
            if entry.circuit == TransparentCircuit::ExternalAssetAnchorV1 {
                assert_ne!(
                    entry.evidence,
                    TransparentCircuitActivationEvidence::default()
                );
            } else {
                assert_eq!(
                    entry.evidence,
                    TransparentCircuitActivationEvidence::default()
                );
            }

            let status = transparent_circuit_status_from_manifest_entry(entry);
            assert_eq!(
                status.prover_enabled,
                entry.circuit == TransparentCircuit::ExternalAssetAnchorV1
            );
            assert_eq!(
                status.verifier_enabled,
                entry.circuit == TransparentCircuit::ExternalAssetAnchorV1
            );
            assert_eq!(
                status.fail_closed,
                entry.circuit != TransparentCircuit::ExternalAssetAnchorV1
            );
            assert_eq!(
                status.readiness,
                transparent_circuit_readiness(entry.circuit)
            );
        }
    }

    #[test]
    fn activation_manifest_rejects_wrong_verifier_key_commitment() {
        let mut manifest = current_native_backend_activation_manifest();
        manifest_entry_mut(&mut manifest, TransparentCircuit::ZcashShieldedStakeV1)
            .verifier_key_commitment = [0x55; 32];
        let err = manifest
            .validate()
            .expect_err("tampered verifier key commitment");
        assert!(err.to_string().contains("verifier key commitment"));
    }

    #[test]
    fn activation_manifest_rejects_operator_gate_without_verifier_evidence() {
        let mut manifest = current_native_backend_activation_manifest();
        manifest_entry_mut(&mut manifest, TransparentCircuit::PrivateDelegationV1)
            .readiness
            .operator_enabled = true;
        let err = manifest
            .validate()
            .expect_err("operator gate cannot open without verifier evidence");
        assert!(err.to_string().contains("operator gate"));
    }

    #[test]
    fn activation_manifest_rejects_verifier_flag_without_evidence_commitment() {
        let mut manifest = current_native_backend_activation_manifest();
        manifest_entry_mut(&mut manifest, TransparentCircuit::PrivateDelegationV1)
            .readiness
            .native_verifier_available = true;
        let err = manifest
            .validate()
            .expect_err("native verifier flag needs artifact evidence");
        assert!(err
            .to_string()
            .contains("requires native verifier commitment"));
    }

    #[test]
    fn activation_manifest_rejects_stale_evidence_without_readiness_flag() {
        let mut manifest = current_native_backend_activation_manifest();
        manifest_entry_mut(&mut manifest, TransparentCircuit::PrivateDelegationV1)
            .evidence
            .native_verifier_commitment = Some(activation_commitment(0x31));
        let err = manifest
            .validate()
            .expect_err("stale verifier evidence must not validate");
        assert!(err.to_string().contains("stale native verifier commitment"));
    }

    #[test]
    fn activation_manifest_rejects_zero_evidence_commitment() {
        let mut manifest = current_native_backend_activation_manifest();
        let entry = manifest_entry_mut(&mut manifest, TransparentCircuit::PrivateDelegationV1);
        entry.readiness.native_verifier_available = true;
        entry.evidence.native_verifier_commitment = Some([0u8; 32]);
        let err = manifest
            .validate()
            .expect_err("zero verifier evidence must not validate");
        assert!(err.to_string().contains("must be nonzero"));
    }

    #[test]
    fn activation_manifest_rejects_stake_activation_without_anchor() {
        let mut manifest = current_native_backend_activation_manifest();
        {
            let entry = manifest_entry_mut(&mut manifest, TransparentCircuit::ZcashShieldedStakeV1);
            entry.readiness.native_prover_available = true;
            entry.readiness.native_verifier_available = true;
            entry.readiness.positive_test_vectors_available = true;
            entry.readiness.negative_test_vectors_available = true;
            entry.readiness.operator_enabled = true;
            entry.evidence.native_prover_commitment = Some(activation_commitment(0x40));
            entry.evidence.native_verifier_commitment = Some(activation_commitment(0x41));
            entry.evidence.positive_test_vector_commitment = Some(activation_commitment(0x42));
            entry.evidence.negative_test_vector_commitment = Some(activation_commitment(0x42));
            entry.evidence.operator_activation_commitment = Some(activation_commitment(0x43));
        }
        {
            let entry =
                manifest_entry_mut(&mut manifest, TransparentCircuit::ExternalAssetAnchorV1);
            entry.readiness.native_prover_available = false;
            entry.readiness.native_verifier_available = false;
            entry.readiness.positive_test_vectors_available = false;
            entry.readiness.negative_test_vectors_available = false;
            entry.readiness.operator_enabled = false;
            entry.evidence = TransparentCircuitActivationEvidence::default();
        }
        let err = manifest
            .validate()
            .expect_err("ZEC stake cannot activate without anchor circuit");
        assert!(err
            .to_string()
            .contains("requires the external asset anchor"));
    }

    #[test]
    fn activation_manifest_rejects_prover_vectors_without_native_prover() {
        let mut manifest = current_native_backend_activation_manifest();
        manifest_entry_mut(&mut manifest, TransparentCircuit::PrivateDelegationV1)
            .readiness
            .positive_test_vectors_available = true;
        let err = manifest
            .validate()
            .expect_err("positive vectors need native prover evidence");
        assert!(err.to_string().contains("positive vectors"));
    }

    #[test]
    fn runtime_activation_guards_use_manifest_fail_closed_reasons() {
        let err =
            require_transparent_circuit_prover_enabled(TransparentCircuit::OrdinaryTransferV1)
                .expect_err("ordinary prover remains disabled");
        assert_eq!(err.to_string(), NATIVE_TRANSPARENT_PROOF_UNAVAILABLE_REASON);

        let err =
            require_transparent_circuit_verifier_enabled(TransparentCircuit::ZcashShieldedStakeV1)
                .expect_err("ZEC stake verifier remains disabled");
        assert_eq!(
            err.to_string(),
            ZCASH_ORCHARD_IRONWOOD_PROOF_UNAVAILABLE_REASON
        );

        require_transparent_circuit_verifier_enabled(TransparentCircuit::ExternalAssetAnchorV1)
            .expect("ZEC anchor verifier is active");
    }

    #[test]
    fn transparent_circuit_status_inventory_matches_fail_closed_capabilities() {
        let statuses = transparent_circuit_status_inventory();
        assert_eq!(statuses.len(), transparent_circuit_inventory().len());
        assert_eq!(
            statuses
                .iter()
                .map(|status| status.circuit)
                .collect::<Vec<_>>(),
            transparent_circuit_inventory().to_vec()
        );
        for status in &statuses {
            status.validate().expect("valid circuit status");
            let descriptor = transparent_circuit_descriptor(status.circuit);
            assert_eq!(status.statement, descriptor.statement);
            assert_eq!(status.proof_family, descriptor.proof_family);
            assert_eq!(status.target_security_bits, descriptor.target_security_bits);
            assert_eq!(
                status.verifier_key_commitment,
                transparent_verifier_key_commitment(status.circuit)
            );
            assert_eq!(status.public_input_shape, descriptor.public_input_shape);
            assert_eq!(status.name, descriptor.name);
            assert_eq!(
                status.readiness,
                transparent_circuit_readiness(status.circuit)
            );
            assert_eq!(
                status.backend,
                canonical_backend_for_circuit(status.circuit)
            );
            let anchor = status.circuit == TransparentCircuit::ExternalAssetAnchorV1;
            assert_eq!(status.prover_enabled, anchor);
            assert_eq!(status.verifier_enabled, anchor);
            assert_eq!(status.fail_closed, !anchor);
            if status.fail_closed {
                assert!(!status.reason.is_empty());
            }
        }

        let enabled = statuses
            .iter()
            .filter(|status| status.prover_enabled)
            .map(|status| status.circuit)
            .collect::<Vec<_>>();
        assert_eq!(enabled, current_prover_capabilities().supported_circuits);
    }

    #[test]
    fn transparent_circuit_status_validation_rejects_unsafe_activation_drift() {
        let mut status = transparent_circuit_status(TransparentCircuit::ZcashShieldedStakeV1);
        status.verifier_enabled = true;
        let err = status
            .validate()
            .expect_err("verifier flag must match readiness");
        assert!(err.to_string().contains("verifier flag"));

        let mut status = transparent_circuit_status(TransparentCircuit::ZcashShieldedStakeV1);
        status.fail_closed = false;
        let err = status
            .validate()
            .expect_err("fail-closed flag must match readiness");
        assert!(err.to_string().contains("fail-closed flag"));

        let mut status = transparent_circuit_status(TransparentCircuit::ZcashShieldedStakeV1);
        status.readiness.native_verifier_available = true;
        let err = status
            .validate()
            .expect_err("readiness must match canonical circuit readiness");
        assert!(err.to_string().contains("readiness mismatch"));
    }

    #[test]
    fn zcash_circuit_status_reports_stake_closed_anchor_live() {
        let stake = transparent_circuit_status(TransparentCircuit::ZcashShieldedStakeV1);
        stake.validate().expect("valid ZEC stake status");
        assert!(!stake.readiness.native_prover_available);
        assert!(!stake.readiness.native_verifier_available);
        assert!(stake.fail_closed);
        assert_eq!(
            stake.reason,
            ZCASH_ORCHARD_IRONWOOD_PROOF_UNAVAILABLE_REASON
        );

        let anchor = transparent_circuit_status(TransparentCircuit::ExternalAssetAnchorV1);
        anchor.validate().expect("valid ZEC anchor status");
        assert!(anchor.readiness.native_prover_available);
        assert!(anchor.readiness.native_verifier_available);
        assert!(anchor.readiness.consensus_activation_ready());
        assert!(anchor.readiness.prover_advertisement_ready());
        assert!(anchor.prover_enabled);
        assert!(anchor.verifier_enabled);
        assert!(!anchor.fail_closed);
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
    fn transparent_prover_capabilities_accept_live_anchor_inventory() {
        let capabilities = current_prover_capabilities();
        capabilities.validate().expect("anchor inventory is valid");
        assert_eq!(
            capabilities.supported_circuits,
            vec![TransparentCircuit::ExternalAssetAnchorV1]
        );
    }

    #[test]
    fn transparent_prover_capabilities_reject_duplicate_inventory() {
        let empty = current_prover_capabilities();
        empty.validate().expect("anchor inventory is valid");

        let mut duplicate = current_prover_capabilities();
        duplicate.supported_circuits = vec![
            TransparentCircuit::OrdinaryTransferV1,
            TransparentCircuit::OrdinaryTransferV1,
        ];
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
    fn zcash_statement_digest_binds_anchor_material_and_circuit() {
        let anchor = sample_external_asset_anchor_journal();
        let anchor_digest =
            external_asset_anchor_journal_statement_digest(&anchor).expect("anchor digest");
        assert_eq!(
            anchor_digest,
            transparent_statement_digest_for_bytes(
                TransparentCircuit::ExternalAssetAnchorV1,
                &proof_core::encode_external_asset_anchor_public_inputs(&anchor)
            )
        );

        let mut mutated_anchor = anchor.clone();
        mutated_anchor.zcash_nullifier_root = [0x99; 32];
        mutated_anchor.zcash_anchor_hash = proof_core::zcash_stake_anchor_hash(
            mutated_anchor.zcash_protocol,
            mutated_anchor.zcash_anchor_height,
            &mutated_anchor.zcash_block_hash,
            &mutated_anchor.zcash_note_commitment_root,
            &mutated_anchor.zcash_nullifier_root,
        );
        let mutated_anchor_digest = external_asset_anchor_journal_statement_digest(&mutated_anchor)
            .expect("mutated anchor digest");
        assert_ne!(anchor_digest, mutated_anchor_digest);

        let stake = sample_private_external_stake_journal();
        let stake_digest =
            private_external_stake_journal_statement_digest(&stake).expect("stake digest");
        assert_ne!(anchor_digest, stake_digest);
    }

    #[test]
    fn zcash_proof_journal_digest_validators_bind_returned_journals() {
        let anchor = sample_external_asset_anchor_journal();
        let anchor_digest =
            external_asset_anchor_journal_statement_digest(&anchor).expect("anchor digest");
        let anchor_proof = TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::ExternalAssetAnchorV1,
            anchor_digest,
            vec![1, 2, 3],
        );
        validate_external_asset_anchor_proof_journal(&anchor_proof, &anchor)
            .expect("anchor proof digest matches returned journal");

        let mut forged_anchor = anchor.clone();
        forged_anchor.zcash_confirmation_depth = forged_anchor.zcash_confirmation_depth + 1;
        let err = validate_external_asset_anchor_proof_journal(&anchor_proof, &forged_anchor)
            .expect_err("forged anchor journal must not match proof digest");
        assert!(err.to_string().contains("statement digest mismatch"));

        let stake = sample_private_external_stake_journal();
        let stake_digest =
            private_external_stake_journal_statement_digest(&stake).expect("stake digest");
        let stake_proof = TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::ZcashShieldedStakeV1,
            stake_digest,
            vec![4, 5, 6],
        );
        validate_private_external_stake_proof_journal(&stake_proof, &stake)
            .expect("stake proof digest matches returned journal");

        let err = validate_private_external_stake_proof_journal(&anchor_proof, &stake)
            .expect_err("anchor proof must not validate as stake proof");
        assert!(err.to_string().contains("statement mismatch"));
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

    #[test]
    fn zcash_external_asset_anchor_native_stark_round_trips() {
        let witness = sample_external_asset_anchor_witness();
        let (proof, journal) =
            prove_external_asset_anchor(&witness).expect("prove external asset anchor");
        assert_eq!(journal, sample_external_asset_anchor_journal());
        assert_eq!(proof.circuit, TransparentCircuit::ExternalAssetAnchorV1);
        assert_ne!(proof.statement_digest, [0u8; 32]);
        assert!(!proof.seal.is_empty());

        let verified =
            verify_external_asset_anchor_proof(&proof).expect("verify external asset anchor");
        assert_eq!(verified, journal);

        let mut tampered = proof.clone();
        tampered.statement_digest[0] ^= 1;
        let err = verify_external_asset_anchor_proof(&tampered)
            .expect_err("tampered statement digest must not verify");
        assert!(
            err.to_string().contains("statement digest mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zcash_private_external_stake_native_statement_seal_round_trips_internally() {
        let journal = sample_private_external_stake_journal();
        let statement_digest =
            private_external_stake_journal_statement_digest(&journal).expect("stake digest");
        let seal =
            zec_native_stark::prove_private_external_stake_statement(&journal, statement_digest)
                .expect("prove private stake public statement");
        let proof = TransparentProof::new_for_circuit_with_digest(
            TransparentCircuit::ZcashShieldedStakeV1,
            statement_digest,
            seal,
        );

        let verified = zec_native_stark::verify_private_external_stake_statement(&proof)
            .expect("verify private stake public statement");
        assert_eq!(verified, journal);

        let mut tampered = proof.clone();
        tampered.statement_digest[0] ^= 1;
        let err = zec_native_stark::verify_private_external_stake_statement(&tampered)
            .expect_err("tampered private stake statement digest must not verify");
        assert!(
            err.to_string().contains("statement digest mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zcash_lock_claim_native_statement_ops_round_trips() {
        let stake = sample_private_external_stake_journal();
        let witness = sample_zcash_lock_witness(
            stake.zcash_protocol,
            stake.zcash_anchor_hash,
            stake.external_nullifier,
            stake.stake_position_commitment,
        );
        let expected_journal = proof_core::validate_zcash_shielded_lock_claim_witness(&witness)
            .expect("valid Zcash lock claim witness");

        let (proof, journal) = prove_zcash_lock_claim_native_statement_for_ops(&witness)
            .expect("prove Zcash lock claim native statement");
        assert_eq!(journal, expected_journal);
        assert_eq!(proof.circuit, TransparentCircuit::ZcashShieldedStakeV1);
        assert_ne!(proof.statement_digest, [0u8; 32]);
        assert!(!proof.seal.is_empty());

        let verified = verify_zcash_lock_claim_native_statement_for_ops(&proof)
            .expect("verify Zcash lock claim native statement");
        assert_eq!(verified, journal);

        let err = verify_private_external_stake_proof(&proof)
            .expect_err("consensus private stake verifier must stay fail-closed");
        assert!(
            err.to_string().contains("Orchard/Ironwood"),
            "unexpected error: {err:?}"
        );

        let mut tampered = proof.clone();
        tampered.statement_digest[0] ^= 1;
        let err = verify_zcash_lock_claim_native_statement_for_ops(&tampered)
            .expect_err("tampered Zcash lock claim statement digest must not verify");
        assert!(
            err.to_string().contains("statement digest mismatch"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zcash_private_external_stake_native_statement_ops_proves_from_full_witness() {
        let witness = sample_private_external_stake_witness();
        let expected_journal = proof_core::validate_private_external_stake_witness(&witness)
            .expect("valid private external stake witness");

        let (proof, journal) = prove_private_external_stake_native_statement_for_ops(&witness)
            .expect("prove private external stake native statement from witness");
        assert_eq!(journal, expected_journal);
        assert_eq!(proof.circuit, TransparentCircuit::ZcashShieldedStakeV1);
        assert_ne!(proof.statement_digest, [0u8; 32]);
        assert!(!proof.seal.is_empty());

        let verified = verify_private_external_stake_native_statement_for_ops(&proof)
            .expect("verify private external stake native statement");
        assert_eq!(verified, journal);

        let err = verify_private_external_stake_proof(&proof)
            .expect_err("consensus private stake verifier must stay fail-closed");
        assert!(
            err.to_string().contains("Orchard/Ironwood"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zcash_private_external_stake_proofs_fail_closed_until_native_backend_exists() {
        let stake_proof = TransparentProof::new(
            TransparentProofStatement::PrivateExternalStake,
            vec![1, 2, 3],
        );
        let err = verify_private_external_stake_proof(&stake_proof)
            .expect_err("ZEC stake proofs must fail closed");
        assert!(
            err.to_string().contains("Orchard/Ironwood"),
            "unexpected error: {err:?}"
        );

        let anchor_proof = TransparentProof::new(
            TransparentProofStatement::ExternalAssetAnchor,
            vec![4, 5, 6],
        );
        let err = verify_external_asset_anchor_proof(&anchor_proof)
            .expect_err("invalid ZEC anchor proof must not verify");
        assert!(
            err.to_string().contains("native ZEC STARK seal"),
            "unexpected error: {err:?}"
        );
    }
}
