use anyhow::{anyhow, bail, Context, Result};
use methods::{
    CHECKPOINT_ACCUMULATOR_METHOD_ELF, CHECKPOINT_ACCUMULATOR_METHOD_ID,
    PRIVATE_DELEGATION_METHOD_ELF, PRIVATE_DELEGATION_METHOD_ID, PRIVATE_UNDELEGATION_METHOD_ELF,
    PRIVATE_UNDELEGATION_METHOD_ID, SHIELDED_SPEND_METHOD_ELF, SHIELDED_SPEND_METHOD_ID,
    UNBONDING_CLAIM_METHOD_ELF, UNBONDING_CLAIM_METHOD_ID,
};
use once_cell::sync::Lazy;
use proof_core::{
    CheckpointAccumulatorJournal, CheckpointAccumulatorStepWitness,
    HistoricalAbsenceRecord as ProofHistoricalAbsenceRecord,
    HistoricalUnspentCheckpoint as ProofHistoricalUnspentCheckpoint,
    HistoricalUnspentPacket as ProofHistoricalUnspentPacket,
    HistoricalUnspentSegment as ProofHistoricalUnspentSegment,
    HistoricalUnspentStratum as ProofHistoricalUnspentStratum,
    NoteMembershipProof as ProofNoteMembershipProof,
    NullifierMembershipWitness as ProofNullifierMembershipWitness,
    NullifierNonMembershipProof as ProofNullifierNonMembershipProof, ProofPrivateDelegationJournal,
    ProofPrivateDelegationWitness, ProofPrivateUndelegationJournal,
    ProofPrivateUndelegationWitness, ProofShieldedInputWitness, ProofShieldedNote,
    ProofShieldedNoteKind, ProofShieldedOutput, ProofShieldedOutputBinding,
    ProofShieldedOutputPlaintext, ProofShieldedOutputWitness, ProofShieldedTxJournal,
    ProofShieldedTxWitness,
};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf, sync::Mutex};

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

mod native_transfer;
use native_transfer::OrdinaryTransferBackend;

const TRANSPARENT_PROOF_VERSION: u8 = 1;
pub const MIN_TRANSPARENT_PROOF_SECURITY_BITS: u16 = 128;
const TRANSPARENT_VERIFIER_KEY_COMMITMENT_DOMAIN: &str = "unchained-transparent-verifier-key-v1";
const TRANSPARENT_STATEMENT_DIGEST_DOMAIN: &str = "unchained-transparent-statement-digest-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentProofStatement {
    ShieldedTransfer,
    PrivateDelegation,
    PrivateUndelegation,
    UnbondingClaim,
    CheckpointAccumulator,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentProofFamily {
    Stark,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransparentProofBackend {
    PrototypeRisc0StarkV1,
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

const PROOF_FIXTURE_DIR_ENV: &str = "UNCHAINED_PROOF_FIXTURE_DIR";
const PROOF_FIXTURE_MINT_ENV: &str = "UNCHAINED_ALLOW_PROOF_FIXTURE_MINT";

static VERIFIED_SHIELDED_RECEIPTS: Lazy<Mutex<HashMap<[u8; 32], ProofShieldedTxJournal>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static VERIFIED_PRIVATE_DELEGATION_RECEIPTS: Lazy<
    Mutex<HashMap<[u8; 32], ProofPrivateDelegationJournal>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
static VERIFIED_PRIVATE_UNDELEGATION_RECEIPTS: Lazy<
    Mutex<HashMap<[u8; 32], ProofPrivateUndelegationJournal>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));

struct TransparentBackendBinding {
    verifier_key_commitment: [u8; 32],
    method_id: [u32; 8],
    elf: &'static [u8],
}

fn receipt_cache_key(bytes: &[u8]) -> [u8; 32] {
    crate::crypto::blake3_hash(bytes)
}

fn configured_backend_for_circuit(_circuit: TransparentCircuit) -> TransparentProofBackend {
    TransparentProofBackend::PrototypeRisc0StarkV1
}

fn verifier_key_commitment_from_method_id(method_id: [u32; 8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(&method_id));
    for word in method_id {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    proof_core::proof_hash_bytes(TRANSPARENT_VERIFIER_KEY_COMMITMENT_DOMAIN, &bytes)
}

fn backend_binding(method_id: [u32; 8], elf: &'static [u8]) -> TransparentBackendBinding {
    TransparentBackendBinding {
        verifier_key_commitment: verifier_key_commitment_from_method_id(method_id),
        method_id,
        elf,
    }
}

fn transparent_backend_binding(
    circuit: TransparentCircuit,
    backend: TransparentProofBackend,
) -> Result<TransparentBackendBinding> {
    let binding = match (circuit, backend) {
        (
            TransparentCircuit::OrdinaryTransferV1,
            TransparentProofBackend::PrototypeRisc0StarkV1,
        ) => backend_binding(SHIELDED_SPEND_METHOD_ID, SHIELDED_SPEND_METHOD_ELF),
        (
            TransparentCircuit::PrivateDelegationV1,
            TransparentProofBackend::PrototypeRisc0StarkV1,
        ) => backend_binding(PRIVATE_DELEGATION_METHOD_ID, PRIVATE_DELEGATION_METHOD_ELF),
        (
            TransparentCircuit::PrivateUndelegationV1,
            TransparentProofBackend::PrototypeRisc0StarkV1,
        ) => backend_binding(
            PRIVATE_UNDELEGATION_METHOD_ID,
            PRIVATE_UNDELEGATION_METHOD_ELF,
        ),
        (TransparentCircuit::UnbondingClaimV1, TransparentProofBackend::PrototypeRisc0StarkV1) => {
            backend_binding(UNBONDING_CLAIM_METHOD_ID, UNBONDING_CLAIM_METHOD_ELF)
        }
        (
            TransparentCircuit::CheckpointAccumulatorV1,
            TransparentProofBackend::PrototypeRisc0StarkV1,
        ) => backend_binding(
            CHECKPOINT_ACCUMULATOR_METHOD_ID,
            CHECKPOINT_ACCUMULATOR_METHOD_ELF,
        ),
    };
    Ok(binding)
}

fn configured_backend_binding(circuit: TransparentCircuit) -> Result<TransparentBackendBinding> {
    transparent_backend_binding(circuit, configured_backend_for_circuit(circuit))
}

fn backend_binding_for_proof(proof: &TransparentProof) -> Result<TransparentBackendBinding> {
    let binding = transparent_backend_binding(proof.circuit, proof.backend)?;
    let configured_backend = configured_backend_for_circuit(proof.circuit);
    if configured_backend != proof.backend {
        bail!(
            "transparent proof circuit {:?} was produced by backend {:?}, but canonical backend is {:?}",
            proof.circuit,
            proof.backend,
            configured_backend
        );
    }
    Ok(binding)
}

fn supported_circuits_for_backend(backend: TransparentProofBackend) -> Vec<TransparentCircuit> {
    transparent_circuit_inventory()
        .iter()
        .copied()
        .filter(|circuit| configured_backend_for_circuit(*circuit) == backend)
        .collect()
}

impl TransparentProof {
    pub fn new(statement: TransparentProofStatement, seal: Vec<u8>) -> Self {
        let circuit = canonical_circuit_for_statement(statement);
        let backend = configured_backend_for_circuit(circuit);
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
        let backend = configured_backend_for_circuit(circuit);
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
        TransparentCircuit::CheckpointAccumulatorV1,
    ];
    INVENTORY
}

pub fn transparent_backend_descriptor(
    backend: TransparentProofBackend,
) -> TransparentBackendDescriptor {
    match backend {
        TransparentProofBackend::PrototypeRisc0StarkV1 => TransparentBackendDescriptor {
            backend,
            proof_family: TransparentProofFamily::Stark,
            target_security_bits: MIN_TRANSPARENT_PROOF_SECURITY_BITS,
            seal_encoding: TransparentSealEncoding::OpaqueSealBytesV1,
            name: "prototype-risc0-stark-v1",
        },
    }
}

pub fn current_prover_capabilities() -> TransparentProverCapabilities {
    let descriptor = transparent_backend_descriptor(TransparentProofBackend::PrototypeRisc0StarkV1);
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
        for circuit in &self.supported_circuits {
            let circuit_descriptor = transparent_circuit_descriptor(*circuit);
            if circuit_descriptor.proof_family != self.proof_family {
                bail!(
                    "transparent prover backend {:?} cannot serve circuit {:?}",
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
        TransparentProofStatement::CheckpointAccumulator => {
            TransparentCircuit::CheckpointAccumulatorV1
        }
    }
}

fn proof_fixture_dir() -> Option<PathBuf> {
    std::env::var_os(PROOF_FIXTURE_DIR_ENV).map(PathBuf::from)
}

fn proof_fixture_mint_allowed() -> bool {
    matches!(
        std::env::var(PROOF_FIXTURE_MINT_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

fn transparent_statement_tag(statement: TransparentProofStatement) -> u8 {
    match statement {
        TransparentProofStatement::ShieldedTransfer => 0,
        TransparentProofStatement::PrivateDelegation => 1,
        TransparentProofStatement::PrivateUndelegation => 2,
        TransparentProofStatement::UnbondingClaim => 3,
        TransparentProofStatement::CheckpointAccumulator => 4,
    }
}

fn transparent_circuit_tag(circuit: TransparentCircuit) -> u8 {
    match circuit {
        TransparentCircuit::OrdinaryTransferV1 => 0,
        TransparentCircuit::PrivateDelegationV1 => 1,
        TransparentCircuit::PrivateUndelegationV1 => 2,
        TransparentCircuit::UnbondingClaimV1 => 3,
        TransparentCircuit::CheckpointAccumulatorV1 => 4,
    }
}

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

fn shielded_journal_statement_digest(
    circuit: TransparentCircuit,
    journal: &ProofShieldedTxJournal,
) -> Result<[u8; 32]> {
    statement_digest_for_serializable(circuit, journal)
}

fn private_delegation_statement_digest(
    journal: &ProofPrivateDelegationJournal,
) -> Result<[u8; 32]> {
    statement_digest_for_serializable(TransparentCircuit::PrivateDelegationV1, journal)
}

fn private_undelegation_statement_digest(
    journal: &ProofPrivateUndelegationJournal,
) -> Result<[u8; 32]> {
    statement_digest_for_serializable(TransparentCircuit::PrivateUndelegationV1, journal)
}

fn checkpoint_accumulator_statement_digest(
    journal: &CheckpointAccumulatorJournal,
) -> Result<[u8; 32]> {
    statement_digest_for_serializable(TransparentCircuit::CheckpointAccumulatorV1, journal)
}

fn shielded_receipt_fixture_path(id: &[u8; 32]) -> Option<PathBuf> {
    proof_fixture_dir().map(|dir| {
        dir.join("shielded-spend")
            .join(format!("{}.bin", hex::encode(id)))
    })
}

fn load_cached_shielded_proof_seal(id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let Some(path) = shielded_receipt_fixture_path(id) else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(fs::read(&path).with_context(|| {
        format!("read cached shielded receipt fixture {}", path.display())
    })?))
}

fn store_cached_shielded_proof_seal(id: &[u8; 32], bytes: &[u8]) -> Result<()> {
    let Some(path) = shielded_receipt_fixture_path(id) else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create cached shielded receipt fixture directory {}",
                parent.display()
            )
        })?;
    }
    if path.exists() {
        return Ok(());
    }
    fs::write(&path, bytes)
        .with_context(|| format!("write cached shielded receipt fixture {}", path.display()))
}

pub fn shielded_tx_fixture_id(witness: &ProofShieldedTxWitness) -> Result<[u8; 32]> {
    Ok(crate::crypto::blake3_hash(
        &bincode::serialize(witness).context("serialize shielded witness for fixture id")?,
    ))
}

fn verify_supported_receipt_kind(
    receipt: &Receipt,
    context: &str,
    allow_composite: bool,
) -> Result<()> {
    match &receipt.inner {
        InnerReceipt::Composite(_) if allow_composite => Ok(()),
        InnerReceipt::Succinct(_) => Ok(()),
        InnerReceipt::Groth16(_) => bail!("{context} must be a STARK receipt"),
        InnerReceipt::Composite(_) => bail!("{context} requires a succinct STARK receipt"),
        InnerReceipt::Fake(_) => bail!("{context} must not be a fake receipt"),
        _ => bail!("{context} uses an unsupported receipt format"),
    }
}

pub fn prove_shielded_tx(
    witness: &ProofShieldedTxWitness,
) -> Result<(TransparentProof, ProofShieldedTxJournal)> {
    let circuit = TransparentCircuit::OrdinaryTransferV1;
    let binding = configured_backend_binding(circuit)?;
    let prepared = native_transfer::prepare_native_transfer_witness(witness)?;
    let _native_transfer_scaffold =
        native_transfer::build_native_transfer_stark_scaffold(&prepared);
    let fixture_id = shielded_tx_fixture_id(witness)?;
    if let Some(seal) = load_cached_shielded_proof_seal(&fixture_id)? {
        let journal = verify_shielded_seal_bytes(&seal)?;
        let proof = TransparentProof::new_for_circuit_with_digest(
            circuit,
            shielded_journal_statement_digest(circuit, &journal)?,
            seal,
        );
        return Ok((proof, journal));
    }
    if let Some(path) = shielded_receipt_fixture_path(&fixture_id) {
        if !proof_fixture_mint_allowed() {
            bail!(
                "missing cached shielded receipt fixture {}; set {}=1 to mint it",
                path.display(),
                PROOF_FIXTURE_MINT_ENV
            );
        }
    }
    let backend = native_transfer::PrototypeRisc0OrdinaryTransferBackend::new(binding);
    let (seal, journal) = backend.prove(&prepared)?;
    let proof = TransparentProof::new_for_circuit_with_digest(
        circuit,
        shielded_journal_statement_digest(circuit, &journal)?,
        seal,
    );
    store_cached_shielded_proof_seal(&fixture_id, &proof.seal)?;
    Ok((proof, journal))
}

pub fn verify_shielded_proof(proof: &TransparentProof) -> Result<ProofShieldedTxJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::ShieldedTransfer,
        "shielded proof",
    )?;
    let _ = backend_binding_for_proof(proof)?;
    let journal = verify_shielded_seal_bytes(&proof.seal)?;
    ensure_statement_digest(
        proof,
        shielded_journal_statement_digest(TransparentCircuit::OrdinaryTransferV1, &journal)?,
        "shielded proof",
    )?;
    Ok(journal)
}

fn verify_shielded_seal_bytes(bytes: &[u8]) -> Result<ProofShieldedTxJournal> {
    let binding = configured_backend_binding(TransparentCircuit::OrdinaryTransferV1)?;
    let cache_key = receipt_cache_key(bytes);
    if let Some(journal) = VERIFIED_SHIELDED_RECEIPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&cache_key)
        .cloned()
    {
        return Ok(journal);
    }
    let backend = native_transfer::PrototypeRisc0OrdinaryTransferBackend::new(binding);
    let journal = backend.verify(bytes)?;
    VERIFIED_SHIELDED_RECEIPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(cache_key, journal.clone());
    Ok(journal)
}

pub fn prove_private_delegation(
    witness: &ProofPrivateDelegationWitness,
) -> Result<(TransparentProof, ProofPrivateDelegationJournal)> {
    let circuit = TransparentCircuit::PrivateDelegationV1;
    let binding = configured_backend_binding(circuit)?;
    let mut builder = ExecutorEnv::builder();
    for input in &witness.shielded.inputs {
        match (
            input.historical_accumulator.as_ref(),
            input.historical_accumulator_receipt.as_ref(),
        ) {
            (Some(accumulator), Some(bytes)) => {
                let journal = verify_checkpoint_accumulator_seal_bytes(bytes)?;
                if &journal != accumulator {
                    bail!("historical accumulator witness does not match its receipt");
                }
                builder.add_assumption(receipt_from_bytes(bytes)?);
            }
            (Some(_), None) => bail!("historical accumulator receipt is missing"),
            (None, Some(_)) => bail!("unexpected accumulator receipt without a journal"),
            (None, None) => {}
        }
    }
    let env = builder
        .write(witness)
        .context("serialize private delegation witness")?
        .build()
        .context("build private delegation executor environment")?;
    let prove_info = default_prover()
        .prove_with_opts(env, binding.elf, &ProverOpts::fast())
        .context("prove private delegation witness")?;
    let receipt = prove_info.receipt;
    verify_supported_receipt_kind(&receipt, "private delegation receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify locally generated private delegation receipt")?;
    let journal = decode_private_delegation_journal(&receipt)?;
    Ok((
        TransparentProof::new_for_circuit_with_digest(
            circuit,
            private_delegation_statement_digest(&journal)?,
            receipt_to_seal_bytes(&receipt)?,
        ),
        journal,
    ))
}

pub fn verify_private_delegation_proof(
    proof: &TransparentProof,
) -> Result<ProofPrivateDelegationJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateDelegation,
        "private delegation proof",
    )?;
    let _ = backend_binding_for_proof(proof)?;
    let journal = verify_private_delegation_seal_bytes(&proof.seal)?;
    ensure_statement_digest(
        proof,
        private_delegation_statement_digest(&journal)?,
        "private delegation proof",
    )?;
    Ok(journal)
}

fn verify_private_delegation_seal_bytes(bytes: &[u8]) -> Result<ProofPrivateDelegationJournal> {
    let binding = configured_backend_binding(TransparentCircuit::PrivateDelegationV1)?;
    let cache_key = receipt_cache_key(bytes);
    if let Some(journal) = VERIFIED_PRIVATE_DELEGATION_RECEIPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&cache_key)
        .cloned()
    {
        return Ok(journal);
    }
    let receipt = receipt_from_bytes(bytes)?;
    verify_supported_receipt_kind(&receipt, "private delegation receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify private delegation receipt")?;
    let journal = decode_private_delegation_journal(&receipt)?;
    VERIFIED_PRIVATE_DELEGATION_RECEIPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(cache_key, journal.clone());
    Ok(journal)
}

pub fn prove_private_undelegation(
    witness: &ProofPrivateUndelegationWitness,
) -> Result<(TransparentProof, ProofPrivateUndelegationJournal)> {
    let circuit = TransparentCircuit::PrivateUndelegationV1;
    let binding = configured_backend_binding(circuit)?;
    let mut builder = ExecutorEnv::builder();
    for input in &witness.shielded.inputs {
        match (
            input.historical_accumulator.as_ref(),
            input.historical_accumulator_receipt.as_ref(),
        ) {
            (Some(accumulator), Some(bytes)) => {
                let journal = verify_checkpoint_accumulator_seal_bytes(bytes)?;
                if &journal != accumulator {
                    bail!("historical accumulator witness does not match its receipt");
                }
                builder.add_assumption(receipt_from_bytes(bytes)?);
            }
            (Some(_), None) => bail!("historical accumulator receipt is missing"),
            (None, Some(_)) => bail!("unexpected accumulator receipt without a journal"),
            (None, None) => {}
        }
    }
    let env = builder
        .write(witness)
        .context("serialize private undelegation witness")?
        .build()
        .context("build private undelegation executor environment")?;
    let prove_info = default_prover()
        .prove_with_opts(env, binding.elf, &ProverOpts::fast())
        .context("prove private undelegation witness")?;
    let receipt = prove_info.receipt;
    verify_supported_receipt_kind(&receipt, "private undelegation receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify locally generated private undelegation receipt")?;
    let journal = decode_private_undelegation_journal(&receipt)?;
    Ok((
        TransparentProof::new_for_circuit_with_digest(
            circuit,
            private_undelegation_statement_digest(&journal)?,
            receipt_to_seal_bytes(&receipt)?,
        ),
        journal,
    ))
}

pub fn verify_private_undelegation_proof(
    proof: &TransparentProof,
) -> Result<ProofPrivateUndelegationJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::PrivateUndelegation,
        "private undelegation proof",
    )?;
    let _ = backend_binding_for_proof(proof)?;
    let journal = verify_private_undelegation_seal_bytes(&proof.seal)?;
    ensure_statement_digest(
        proof,
        private_undelegation_statement_digest(&journal)?,
        "private undelegation proof",
    )?;
    Ok(journal)
}

fn verify_private_undelegation_seal_bytes(bytes: &[u8]) -> Result<ProofPrivateUndelegationJournal> {
    let binding = configured_backend_binding(TransparentCircuit::PrivateUndelegationV1)?;
    let cache_key = receipt_cache_key(bytes);
    if let Some(journal) = VERIFIED_PRIVATE_UNDELEGATION_RECEIPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&cache_key)
        .cloned()
    {
        return Ok(journal);
    }
    let receipt = receipt_from_bytes(bytes)?;
    verify_supported_receipt_kind(&receipt, "private undelegation receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify private undelegation receipt")?;
    let journal = decode_private_undelegation_journal(&receipt)?;
    VERIFIED_PRIVATE_UNDELEGATION_RECEIPTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(cache_key, journal.clone());
    Ok(journal)
}

pub fn prove_unbonding_claim(
    witness: &ProofShieldedTxWitness,
) -> Result<(TransparentProof, ProofShieldedTxJournal)> {
    let circuit = TransparentCircuit::UnbondingClaimV1;
    let binding = configured_backend_binding(circuit)?;
    let mut builder = ExecutorEnv::builder();
    for input in &witness.inputs {
        match (
            input.historical_accumulator.as_ref(),
            input.historical_accumulator_receipt.as_ref(),
        ) {
            (Some(accumulator), Some(bytes)) => {
                let journal = verify_checkpoint_accumulator_seal_bytes(bytes)?;
                if &journal != accumulator {
                    bail!("historical accumulator witness does not match its receipt");
                }
                builder.add_assumption(receipt_from_bytes(bytes)?);
            }
            (Some(_), None) => bail!("historical accumulator receipt is missing"),
            (None, Some(_)) => bail!("unexpected accumulator receipt without a journal"),
            (None, None) => {}
        }
    }
    let env = builder
        .write(witness)
        .context("serialize unbonding claim witness")?
        .build()
        .context("build unbonding claim executor environment")?;
    let prove_info = default_prover()
        .prove_with_opts(env, binding.elf, &ProverOpts::fast())
        .context("prove unbonding claim witness")?;
    let receipt = prove_info.receipt;
    verify_supported_receipt_kind(&receipt, "unbonding claim receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify locally generated unbonding claim receipt")?;
    let journal = decode_shielded_tx_journal(&receipt)?;
    Ok((
        TransparentProof::new_for_circuit_with_digest(
            circuit,
            shielded_journal_statement_digest(circuit, &journal)?,
            receipt_to_seal_bytes(&receipt)?,
        ),
        journal,
    ))
}

pub fn verify_unbonding_claim_proof(proof: &TransparentProof) -> Result<ProofShieldedTxJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::UnbondingClaim,
        "unbonding claim proof",
    )?;
    let _ = backend_binding_for_proof(proof)?;
    let journal = verify_unbonding_claim_seal_bytes(&proof.seal)?;
    ensure_statement_digest(
        proof,
        shielded_journal_statement_digest(TransparentCircuit::UnbondingClaimV1, &journal)?,
        "unbonding claim proof",
    )?;
    Ok(journal)
}

fn verify_unbonding_claim_seal_bytes(bytes: &[u8]) -> Result<ProofShieldedTxJournal> {
    let binding = configured_backend_binding(TransparentCircuit::UnbondingClaimV1)?;
    let receipt = receipt_from_bytes(bytes)?;
    verify_supported_receipt_kind(&receipt, "unbonding claim receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify unbonding claim receipt")?;
    decode_shielded_tx_journal(&receipt)
}

fn receipt_to_seal_bytes(receipt: &Receipt) -> Result<Vec<u8>> {
    bincode::serialize(receipt).context("serialize shielded receipt")
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
    checkpoint: &HistoricalUnspentCheckpoint,
    extension: &HistoricalUnspentExtension,
    prior: Option<&CheckpointAccumulatorProof>,
) -> Result<CheckpointAccumulatorProof> {
    let circuit = TransparentCircuit::CheckpointAccumulatorV1;
    let binding = configured_backend_binding(circuit)?;
    if extension.strata.is_empty() {
        bail!("checkpoint accumulator requires a non-empty extension");
    }
    if prior.is_none()
        && checkpoint
            != &HistoricalUnspentCheckpoint::genesis(
                checkpoint.note_commitment,
                checkpoint.birth_epoch,
            )
    {
        bail!("checkpoint accumulator bootstrap must start from genesis");
    }
    if let Some(prior) = prior {
        if prior.journal.note_commitment != checkpoint.note_commitment {
            bail!("prior accumulator note mismatch");
        }
        if prior.journal.birth_epoch != checkpoint.birth_epoch {
            bail!("prior accumulator birth epoch mismatch");
        }
    }

    let mut prior_journal = prior.map(|proof| proof.journal.clone());
    let mut prior_receipt = prior
        .map(|proof| receipt_from_bytes(&proof.proof.seal))
        .transpose()?;
    let mut current_receipt = None;
    let mut current_journal = None;

    for stratum in &extension.strata {
        let mut builder = ExecutorEnv::builder();
        if let Some(receipt) = prior_receipt.as_ref() {
            builder.add_assumption(receipt.clone());
        }
        let env = builder
            .write(&CheckpointAccumulatorStepWitness {
                accumulator_verifier_key_commitment: binding.verifier_key_commitment,
                accumulator_verifier_hint: binding.method_id,
                note_commitment: checkpoint.note_commitment,
                birth_epoch: checkpoint.birth_epoch,
                prior_accumulator: prior_journal.clone(),
                stratum: stratum_to_proof(stratum),
            })
            .context("serialize checkpoint accumulator step witness")?
            .build()
            .context("build checkpoint accumulator executor environment")?;
        let prove_info = default_prover()
            .prove_with_opts(env, binding.elf, &ProverOpts::fast())
            .context("prove checkpoint accumulator step")?;
        let receipt = prove_info.receipt;
        verify_supported_receipt_kind(&receipt, "checkpoint accumulator receipt", true)?;
        receipt
            .verify(binding.method_id)
            .context("verify locally generated checkpoint accumulator receipt")?;
        let journal = decode_checkpoint_accumulator_journal(&receipt)?;
        prior_journal = Some(journal.clone());
        prior_receipt = Some(receipt.clone());
        current_journal = Some(journal);
        current_receipt = Some(receipt);
    }

    let journal =
        current_journal.ok_or_else(|| anyhow!("missing checkpoint accumulator journal"))?;
    Ok(CheckpointAccumulatorProof {
        proof: TransparentProof::new_for_circuit_with_digest(
            circuit,
            checkpoint_accumulator_statement_digest(&journal)?,
            receipt_to_seal_bytes(
                &current_receipt
                    .ok_or_else(|| anyhow!("missing checkpoint accumulator receipt"))?,
            )?,
        ),
        journal,
    })
}

pub fn verify_checkpoint_accumulator_proof(
    proof: &TransparentProof,
) -> Result<CheckpointAccumulatorJournal> {
    require_transparent_statement(
        proof,
        TransparentProofStatement::CheckpointAccumulator,
        "checkpoint accumulator proof",
    )?;
    let _ = backend_binding_for_proof(proof)?;
    let journal = verify_checkpoint_accumulator_seal_bytes(&proof.seal)?;
    ensure_statement_digest(
        proof,
        checkpoint_accumulator_statement_digest(&journal)?,
        "checkpoint accumulator proof",
    )?;
    Ok(journal)
}

fn verify_checkpoint_accumulator_seal_bytes(bytes: &[u8]) -> Result<CheckpointAccumulatorJournal> {
    let binding = configured_backend_binding(TransparentCircuit::CheckpointAccumulatorV1)?;
    let receipt = receipt_from_bytes(bytes)?;
    verify_supported_receipt_kind(&receipt, "checkpoint accumulator receipt", true)?;
    receipt
        .verify(binding.method_id)
        .context("verify checkpoint accumulator receipt")?;
    decode_checkpoint_accumulator_journal(&receipt)
}

pub fn checkpoint_accumulator_verifier_hint() -> [u32; 8] {
    configured_backend_binding(TransparentCircuit::CheckpointAccumulatorV1)
        .expect("configured checkpoint accumulator backend binding")
        .method_id
}

pub fn checkpoint_accumulator_verifier_key_commitment() -> [u8; 32] {
    configured_backend_binding(TransparentCircuit::CheckpointAccumulatorV1)
        .expect("configured checkpoint accumulator backend binding")
        .verifier_key_commitment
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
) -> ProofShieldedInputWitness {
    let historical_accumulator_verifier_hint = historical_accumulator.map(|proof| {
        backend_binding_for_proof(&proof.proof)
            .expect("checkpoint accumulator proof must use the configured backend")
            .method_id
    });
    ProofShieldedInputWitness {
        note: note_to_proof(note),
        note_key: *note_key,
        membership_proof: membership_proof_to_proof(membership_proof),
        historical_checkpoint: checkpoint_to_proof(historical_checkpoint),
        historical_extension: historical_extension.map(extension_to_proof),
        historical_accumulator: historical_accumulator.map(|proof| proof.journal.clone()),
        historical_accumulator_verifier_hint,
        historical_accumulator_receipt: historical_accumulator
            .map(|proof| proof.proof.seal.clone()),
        current_nullifier: *current_nullifier,
    }
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

fn decode_shielded_tx_journal(receipt: &Receipt) -> Result<ProofShieldedTxJournal> {
    receipt
        .journal
        .decode()
        .map_err(|err| anyhow!("decode shielded receipt journal: {err}"))
}

fn decode_private_delegation_journal(receipt: &Receipt) -> Result<ProofPrivateDelegationJournal> {
    receipt
        .journal
        .decode()
        .map_err(|err| anyhow!("decode private delegation receipt journal: {err}"))
}

fn decode_private_undelegation_journal(
    receipt: &Receipt,
) -> Result<ProofPrivateUndelegationJournal> {
    receipt
        .journal
        .decode()
        .map_err(|err| anyhow!("decode private undelegation receipt journal: {err}"))
}

fn decode_checkpoint_accumulator_journal(
    receipt: &Receipt,
) -> Result<CheckpointAccumulatorJournal> {
    receipt
        .journal
        .decode()
        .map_err(|err| anyhow!("decode checkpoint accumulator receipt journal: {err}"))
}

fn receipt_from_bytes(bytes: &[u8]) -> Result<Receipt> {
    bincode::deserialize(bytes).context("decode receipt bytes")
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

    fn sample_proof_note(seed: u8) -> ProofShieldedNote {
        ProofShieldedNote {
            version: proof_core::SHIELDED_NOTE_VERSION,
            kind: ProofShieldedNoteKind::Payment,
            value: seed as u64 + 10,
            birth_epoch: 1,
            owner_address: [seed; 32],
            owner_signing_key_commitment: [seed.wrapping_add(6); 32],
            owner_kem_key_commitment: [seed.wrapping_add(7); 32],
            owner_signing_pk: vec![seed; 32],
            owner_kem_pk: vec![seed.wrapping_add(1); 64],
            rho: [seed.wrapping_add(2); 32],
            note_randomizer: [seed.wrapping_add(3); 32],
            note_key_commitment: [seed.wrapping_add(4); 32],
            commitment: [seed.wrapping_add(5); 32],
        }
    }

    fn sample_prepared_native_transfer() -> native_transfer::NativeTransferPreparedWitness {
        let input_note = sample_proof_note(1);
        let output_note = sample_proof_note(21);
        let journal = ProofShieldedTxJournal {
            chain_id: [7u8; 32],
            current_epoch: 3,
            note_tree_root: [9u8; 32],
            fee_amount: 1,
            inputs: vec![proof_core::ProofShieldedInputBinding {
                current_nullifier: [11u8; 32],
                historical_from_epoch: 1,
                historical_through_epoch: 2,
                historical_root_digest: [12u8; 32],
            }],
            outputs: vec![ProofShieldedOutputBinding {
                note_commitment: output_note.commitment,
                public_output_digest: [14u8; 32],
            }],
        };
        native_transfer::NativeTransferPreparedWitness {
            source_witness: ProofShieldedTxWitness {
                chain_id: journal.chain_id,
                current_epoch: journal.current_epoch,
                note_tree_root: journal.note_tree_root,
                fee_amount: journal.fee_amount,
                inputs: Vec::new(),
                outputs: Vec::new(),
            },
            public_inputs: native_transfer::NativeTransferPublicInputs {
                statement_digest: [15u8; 32],
                journal: journal.clone(),
            },
            private_inputs: native_transfer::NativeTransferPrivateInputs {
                inputs: vec![native_transfer::NativeTransferPrivateInput {
                    witness: ProofShieldedInputWitness {
                        note: input_note.clone(),
                        note_key: [16u8; 32],
                        membership_proof: ProofNoteMembershipProof {
                            note_commitment: input_note.commitment,
                            root: journal.note_tree_root,
                            proof: Vec::new(),
                        },
                        historical_checkpoint: ProofHistoricalUnspentCheckpoint {
                            version: proof_core::SHIELDED_CHECKPOINT_VERSION,
                            note_commitment: input_note.commitment,
                            birth_epoch: 1,
                            covered_through_epoch: 2,
                            transcript_root: [17u8; 32],
                            verified_epoch_count: 2,
                        },
                        historical_extension: None,
                        historical_accumulator: None,
                        historical_accumulator_verifier_hint: None,
                        historical_accumulator_receipt: None,
                        current_nullifier: [11u8; 32],
                    },
                }],
                outputs: vec![native_transfer::NativeTransferPrivateOutput {
                    plaintext: ProofShieldedOutputPlaintext {
                        note: output_note.clone(),
                        note_key: [18u8; 32],
                        checkpoint: ProofHistoricalUnspentCheckpoint {
                            version: proof_core::SHIELDED_CHECKPOINT_VERSION,
                            note_commitment: output_note.commitment,
                            birth_epoch: 3,
                            covered_through_epoch: 2,
                            transcript_root: [19u8; 32],
                            verified_epoch_count: 0,
                        },
                    },
                }],
            },
            envelope_bindings: vec![native_transfer::NativeTransferEnvelopeBinding {
                binding: journal.outputs[0].clone(),
                public_output: ProofShieldedOutput {
                    note_commitment: output_note.commitment,
                    kem_ct: vec![20u8; 32],
                    nonce: [21u8; proof_core::SHIELDED_OUTPUT_NONCE_LEN],
                    view_tag: 22,
                    ciphertext: vec![23u8; 48],
                },
            }],
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
            TransparentProofBackend::PrototypeRisc0StarkV1
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
            backend: TransparentProofBackend::PrototypeRisc0StarkV1,
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
            backend: TransparentProofBackend::PrototypeRisc0StarkV1,
            statement_digest: [0u8; 32],
            seal: vec![1],
        };
        proof.validate_metadata().expect("valid proof");
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

    #[test]
    fn native_transfer_scaffold_tracks_arity_and_adapter_gaps() {
        let prepared = sample_prepared_native_transfer();
        let scaffold = native_transfer::build_native_transfer_stark_scaffold(&prepared);
        assert_eq!(scaffold.public_inputs, prepared.public_inputs);
        assert_eq!(scaffold.trace_layout.input_rows, 1);
        assert_eq!(scaffold.trace_layout.output_rows, 1);
        assert_eq!(scaffold.trace_layout.history_rows, 0);
        assert_eq!(scaffold.trace_layout.finalize_rows, 2);
        assert_eq!(scaffold.trace_layout.transition_rows, 4);
        assert_eq!(scaffold.trace_layout.padded_rows, 4);
        assert_eq!(scaffold.envelope_binding_count, 1);
        assert!(scaffold.requires_ciphertext_adapter);
        assert_eq!(scaffold.history_record_count, 0);
    }
}
