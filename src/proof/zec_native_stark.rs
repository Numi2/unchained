use anyhow::{bail, Context, Result};
use proof_core::{
    ProofExternalAssetAnchorJournal, ProofExternalAssetAnchorWitness,
    ProofPrivateExternalStakeJournal, ProofPrivateExternalStakeWitness,
    ProofZcashShieldedLockClaimJournal, ProofZcashShieldedLockWitness,
};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions,
    Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use super::{TransparentCircuit, TransparentProof};

const SEAL_MAGIC: &[u8; 8] = b"UZECSTK1";
const SEAL_VERSION: u8 = 1;
const DIGEST_FIELD_ELEMENTS: usize = 5;
const TRACE_LENGTH: usize = 64;
const ANCHOR_PUBLIC_INPUT_LEN: usize = 213;
#[allow(dead_code)]
const ZCASH_LOCK_CLAIM_PUBLIC_INPUT_LEN: usize = 226;
#[allow(dead_code)]
const PRIVATE_STAKE_PUBLIC_INPUT_LEN: usize = 509;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SealArtifacts {
    pub(super) prover_commitment: [u8; 32],
    pub(super) verifier_commitment: [u8; 32],
    pub(super) positive_vector_commitment: [u8; 32],
    pub(super) negative_vector_commitment: [u8; 32],
    pub(super) operator_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZecStatementPublicInputs {
    elements: Vec<BaseElement>,
}

impl ToElements<BaseElement> for ZecStatementPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.elements.clone()
    }
}

struct ZecStatementAir {
    context: AirContext<BaseElement>,
    inputs: ZecStatementPublicInputs,
}

impl Air for ZecStatementAir {
    type BaseField = BaseElement;
    type PublicInputs = ZecStatementPublicInputs;

    fn new(
        trace_info: TraceInfo,
        pub_inputs: ZecStatementPublicInputs,
        options: ProofOptions,
    ) -> Self {
        assert_eq!(pub_inputs.elements.len() + 1, trace_info.width());
        let degrees = vec![TransitionConstraintDegree::new(1); trace_info.width()];
        let num_assertions = pub_inputs.elements.len() + 2;
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            inputs: pub_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        for (index, result) in result.iter_mut().enumerate() {
            *result = if index < self.inputs.elements.len() {
                frame.next()[index] - frame.current()[index]
            } else {
                frame.next()[index] - frame.current()[index] - E::ONE
            };
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = self
            .inputs
            .elements
            .iter()
            .enumerate()
            .map(|(column, element)| Assertion::single(column, 0, *element))
            .collect::<Vec<_>>();
        let counter_column = self.inputs.elements.len();
        assertions.push(Assertion::single(counter_column, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(
            counter_column,
            self.trace_length() - 1,
            BaseElement::new((TRACE_LENGTH - 1) as u64),
        ));
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct ZecStatementProver {
    options: ProofOptions,
}

impl ZecStatementProver {
    fn new() -> Self {
        Self {
            options: zec_statement_proof_options(),
        }
    }
}

impl Prover for ZecStatementProver {
    type BaseField = BaseElement;
    type Air = ZecStatementAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ZecStatementPublicInputs {
        let counter_column = trace.width() - 1;
        ZecStatementPublicInputs {
            elements: (0..counter_column)
                .map(|column| trace.get(column, 0))
                .collect(),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub(super) fn external_asset_anchor_artifacts() -> SealArtifacts {
    SealArtifacts {
        prover_commitment: artifact_commitment("external-asset-anchor-prover"),
        verifier_commitment: artifact_commitment("external-asset-anchor-verifier"),
        positive_vector_commitment: artifact_commitment("external-asset-anchor-positive-vector"),
        negative_vector_commitment: artifact_commitment("external-asset-anchor-negative-vector"),
        operator_commitment: artifact_commitment("external-asset-anchor-operator"),
    }
}

pub(super) fn prove_external_asset_anchor(
    journal: &ProofExternalAssetAnchorJournal,
    statement_digest: [u8; 32],
) -> Result<Vec<u8>> {
    validate_external_asset_anchor_journal(journal)?;
    let public_input_bytes = proof_core::encode_external_asset_anchor_public_inputs(journal);
    let trace = build_statement_trace(statement_digest, &public_input_bytes);
    let stark_proof = ZecStatementProver::new()
        .prove(trace)
        .context("prove external asset anchor native STARK statement")?;
    Ok(encode_seal(
        TransparentCircuit::ExternalAssetAnchorV1,
        &public_input_bytes,
        &stark_proof.to_bytes(),
    ))
}

pub(super) fn verify_external_asset_anchor(
    proof: &TransparentProof,
) -> Result<ProofExternalAssetAnchorJournal> {
    let decoded = decode_seal(&proof.seal)?;
    if decoded.circuit != TransparentCircuit::ExternalAssetAnchorV1 {
        bail!(
            "native ZEC STARK seal circuit mismatch: expected {:?}, got {:?}",
            TransparentCircuit::ExternalAssetAnchorV1,
            decoded.circuit
        );
    }
    if decoded.public_inputs.len() != ANCHOR_PUBLIC_INPUT_LEN {
        bail!("native ZEC anchor seal has invalid public input length");
    }

    let journal = decode_external_asset_anchor_public_inputs(decoded.public_inputs)?;
    validate_external_asset_anchor_journal(&journal)?;

    let expected_statement_digest = super::external_asset_anchor_journal_statement_digest(&journal)
        .context("compute external asset anchor statement digest")?;
    if proof.statement_digest != expected_statement_digest {
        bail!("external asset anchor proof statement digest mismatch");
    }

    verify_stark_statement(
        &decoded.stark_proof,
        proof.statement_digest,
        decoded.public_inputs,
    )
    .context("verify external asset anchor native STARK statement")?;
    Ok(journal)
}

#[allow(dead_code)]
pub(super) fn prove_private_external_stake_statement(
    journal: &ProofPrivateExternalStakeJournal,
    statement_digest: [u8; 32],
) -> Result<Vec<u8>> {
    validate_private_external_stake_public_journal(journal)?;
    let public_input_bytes = proof_core::encode_private_external_stake_public_inputs(journal);
    let trace = build_statement_trace(statement_digest, &public_input_bytes);
    let stark_proof = ZecStatementProver::new()
        .prove(trace)
        .context("prove private external stake native STARK statement")?;
    Ok(encode_seal(
        TransparentCircuit::ZcashShieldedStakeV1,
        &public_input_bytes,
        &stark_proof.to_bytes(),
    ))
}

pub(super) fn prove_private_external_stake_statement_from_witness(
    witness: &ProofPrivateExternalStakeWitness,
) -> Result<(Vec<u8>, ProofPrivateExternalStakeJournal)> {
    let journal = proof_core::validate_private_external_stake_witness(witness)
        .context("validate private external stake witness for native statement proof")?;
    let statement_digest = super::private_external_stake_journal_statement_digest(&journal)
        .context("compute private external stake statement digest")?;
    let seal = prove_private_external_stake_statement(&journal, statement_digest)?;
    Ok((seal, journal))
}

pub(super) fn prove_zcash_lock_claim_statement_from_witness(
    witness: &ProofZcashShieldedLockWitness,
) -> Result<(Vec<u8>, ProofZcashShieldedLockClaimJournal)> {
    let journal = proof_core::validate_zcash_shielded_lock_claim_witness(witness)
        .context("validate Zcash lock claim witness for native statement proof")?;
    let statement_digest = super::zcash_lock_claim_journal_statement_digest(&journal)
        .context("compute Zcash lock claim statement digest")?;
    let seal = prove_zcash_lock_claim_statement(&journal, statement_digest)?;
    Ok((seal, journal))
}

pub(super) fn prove_zcash_lock_claim_statement(
    journal: &ProofZcashShieldedLockClaimJournal,
    statement_digest: [u8; 32],
) -> Result<Vec<u8>> {
    proof_core::validate_zcash_shielded_lock_claim_journal(journal)
        .context("validate Zcash lock claim journal")?;
    let public_input_bytes = proof_core::encode_zcash_lock_claim_public_inputs(journal);
    let trace = build_statement_trace(statement_digest, &public_input_bytes);
    let stark_proof = ZecStatementProver::new()
        .prove(trace)
        .context("prove Zcash lock claim native STARK statement")?;
    Ok(encode_seal(
        TransparentCircuit::ZcashShieldedStakeV1,
        &public_input_bytes,
        &stark_proof.to_bytes(),
    ))
}

pub(super) fn verify_zcash_lock_claim_statement(
    proof: &TransparentProof,
) -> Result<ProofZcashShieldedLockClaimJournal> {
    let decoded = decode_seal(&proof.seal)?;
    if decoded.circuit != TransparentCircuit::ZcashShieldedStakeV1 {
        bail!(
            "native ZEC STARK seal circuit mismatch: expected {:?}, got {:?}",
            TransparentCircuit::ZcashShieldedStakeV1,
            decoded.circuit
        );
    }
    if decoded.public_inputs.len() != ZCASH_LOCK_CLAIM_PUBLIC_INPUT_LEN {
        bail!("native ZEC lock claim seal has invalid public input length");
    }

    let journal = decode_zcash_lock_claim_public_inputs(decoded.public_inputs)?;
    proof_core::validate_zcash_shielded_lock_claim_journal(&journal)
        .context("validate decoded Zcash lock claim journal")?;

    let expected_statement_digest = super::zcash_lock_claim_journal_statement_digest(&journal)
        .context("compute Zcash lock claim statement digest")?;
    if proof.statement_digest != expected_statement_digest {
        bail!("Zcash lock claim proof statement digest mismatch");
    }

    verify_stark_statement(
        &decoded.stark_proof,
        proof.statement_digest,
        decoded.public_inputs,
    )
    .context("verify Zcash lock claim native STARK statement")?;
    Ok(journal)
}

#[allow(dead_code)]
pub(super) fn verify_private_external_stake_statement(
    proof: &TransparentProof,
) -> Result<ProofPrivateExternalStakeJournal> {
    let decoded = decode_seal(&proof.seal)?;
    if decoded.circuit != TransparentCircuit::ZcashShieldedStakeV1 {
        bail!(
            "native ZEC STARK seal circuit mismatch: expected {:?}, got {:?}",
            TransparentCircuit::ZcashShieldedStakeV1,
            decoded.circuit
        );
    }
    if decoded.public_inputs.len() != PRIVATE_STAKE_PUBLIC_INPUT_LEN {
        bail!("native ZEC private stake seal has invalid public input length");
    }

    let journal = decode_private_external_stake_public_inputs(decoded.public_inputs)?;
    validate_private_external_stake_public_journal(&journal)?;

    let expected_statement_digest =
        super::private_external_stake_journal_statement_digest(&journal)
            .context("compute private external stake statement digest")?;
    if proof.statement_digest != expected_statement_digest {
        bail!("private external stake proof statement digest mismatch");
    }

    verify_stark_statement(
        &decoded.stark_proof,
        proof.statement_digest,
        decoded.public_inputs,
    )
    .context("verify private external stake native STARK statement")?;
    Ok(journal)
}

fn validate_external_asset_anchor_journal(journal: &ProofExternalAssetAnchorJournal) -> Result<()> {
    let witness = ProofExternalAssetAnchorWitness {
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
    };
    let validated = proof_core::validate_external_asset_anchor_witness(&witness)
        .context("validate external asset anchor journal")?;
    if &validated != journal {
        bail!("external asset anchor journal is not canonical");
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_private_external_stake_public_journal(
    journal: &ProofPrivateExternalStakeJournal,
) -> Result<()> {
    validate_zcash_public_anchor_fields(
        journal.chain_id,
        journal.current_epoch,
        journal.asset_id,
        journal.zcash_protocol,
        journal.zcash_anchor_height,
        &journal.zcash_block_hash,
        &journal.zcash_note_commitment_root,
        &journal.zcash_nullifier_root,
        &journal.zcash_anchor_hash,
        journal.zcash_confirmation_depth,
    )?;
    if journal.activation_epoch < journal.current_epoch {
        bail!("private external stake activation epoch cannot be in the past");
    }
    if journal.external_nullifier == [0u8; 32] {
        bail!("private external stake external nullifier cannot be zero");
    }
    if journal.stake_position_commitment == [0u8; 32] {
        bail!("private external stake position commitment cannot be zero");
    }
    proof_core::validate_zcash_shielded_lock_binding(
        &journal.zcash_lock,
        journal.zcash_protocol,
        &journal.zcash_anchor_hash,
        &journal.external_nullifier,
        &journal.stake_position_commitment,
    )
    .context("validate private external stake Zcash lock binding")?;
    if journal.receipt_note_commitment == [0u8; 32] {
        bail!("private external stake receipt note commitment cannot be zero");
    }
    if journal.receipt_output.note_commitment != journal.receipt_note_commitment {
        bail!("private external stake receipt output commitment mismatch");
    }
    if journal.receipt_output.public_output_digest == [0u8; 32] {
        bail!("private external stake receipt output digest cannot be zero");
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_zcash_public_anchor_fields(
    _chain_id: [u8; 32],
    _current_epoch: u64,
    asset_id: [u8; 32],
    zcash_protocol: u8,
    zcash_anchor_height: u64,
    zcash_block_hash: &[u8; 32],
    zcash_note_commitment_root: &[u8; 32],
    zcash_nullifier_root: &[u8; 32],
    zcash_anchor_hash: &[u8; 32],
    zcash_confirmation_depth: u32,
) -> Result<()> {
    if asset_id == [0u8; 32] {
        bail!("ZEC public statement asset id cannot be zero");
    }
    match zcash_protocol {
        proof_core::ZCASH_ORCHARD_PROTOCOL | proof_core::ZCASH_IRONWOOD_PROTOCOL => {}
        other => bail!("unsupported Zcash shielded protocol tag {other}"),
    }
    if zcash_anchor_height == 0 {
        bail!("ZEC public statement anchor height cannot be zero");
    }
    if zcash_confirmation_depth == 0 {
        bail!("ZEC public statement confirmation depth cannot be zero");
    }
    if zcash_block_hash == &[0u8; 32] {
        bail!("ZEC public statement block hash cannot be zero");
    }
    if zcash_note_commitment_root == &[0u8; 32] {
        bail!("ZEC public statement note commitment root cannot be zero");
    }
    if zcash_nullifier_root == &[0u8; 32] {
        bail!("ZEC public statement nullifier root cannot be zero");
    }
    let expected_anchor_hash = proof_core::zcash_stake_anchor_hash(
        zcash_protocol,
        zcash_anchor_height,
        zcash_block_hash,
        zcash_note_commitment_root,
        zcash_nullifier_root,
    );
    if zcash_anchor_hash != &expected_anchor_hash {
        bail!("ZEC public statement anchor hash mismatch");
    }
    Ok(())
}

fn verify_stark_statement(
    stark_proof_bytes: &[u8],
    statement_digest: [u8; 32],
    public_input_bytes: &[u8],
) -> Result<()> {
    let stark_proof = Proof::from_bytes(stark_proof_bytes)
        .map_err(|err| anyhow::anyhow!("decode native ZEC STARK proof: {err}"))?;
    let public_inputs = public_inputs_from_statement(statement_digest, public_input_bytes);
    let acceptable_options = AcceptableOptions::OptionSet(vec![zec_statement_proof_options()]);
    winterfell::verify::<
        ZecStatementAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(stark_proof, public_inputs, &acceptable_options)
    .map_err(|err| anyhow::anyhow!("native ZEC STARK verification failed: {err}"))
}

fn build_statement_trace(
    statement_digest: [u8; 32],
    public_input_bytes: &[u8],
) -> TraceTable<BaseElement> {
    let elements = statement_elements(statement_digest, public_input_bytes);
    let mut columns = elements
        .iter()
        .map(|element| vec![*element; TRACE_LENGTH])
        .collect::<Vec<_>>();
    columns.push(
        (0..TRACE_LENGTH)
            .map(|step| BaseElement::new(step as u64))
            .collect(),
    );
    TraceTable::init(columns)
}

fn public_inputs_from_statement(
    statement_digest: [u8; 32],
    public_input_bytes: &[u8],
) -> ZecStatementPublicInputs {
    ZecStatementPublicInputs {
        elements: statement_elements(statement_digest, public_input_bytes),
    }
}

fn statement_elements(statement_digest: [u8; 32], public_input_bytes: &[u8]) -> Vec<BaseElement> {
    let mut elements = Vec::with_capacity(
        DIGEST_FIELD_ELEMENTS + public_input_bytes.len().div_ceil(field_payload_bytes()),
    );
    for (index, chunk) in statement_digest.chunks(7).enumerate() {
        elements.push(field_element_from_chunk(
            chunk,
            index + 1 == DIGEST_FIELD_ELEMENTS,
        ));
    }
    for (index, chunk) in public_input_bytes.chunks(field_payload_bytes()).enumerate() {
        let is_last = index + 1 == public_input_bytes.len().div_ceil(field_payload_bytes());
        elements.push(field_element_from_chunk(chunk, is_last));
    }
    elements
}

fn field_payload_bytes() -> usize {
    7
}

fn field_element_from_chunk(chunk: &[u8], is_last: bool) -> BaseElement {
    let mut buf = [0u8; 8];
    buf[..chunk.len()].copy_from_slice(chunk);
    if is_last && chunk.len() < field_payload_bytes() {
        buf[chunk.len()] = 1;
    }
    BaseElement::new(u64::from_le_bytes(buf))
}

fn zec_statement_proof_options() -> ProofOptions {
    ProofOptions::new(
        64,
        8,
        0,
        FieldExtension::Cubic,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn artifact_commitment(label: &str) -> [u8; 32] {
    proof_core::proof_hash_domain_parts(
        "unchained-zec-native-stark-artifact-v1",
        &[
            &[SEAL_VERSION],
            label.as_bytes(),
            SEAL_MAGIC.as_slice(),
            &(TRACE_LENGTH as u32).to_le_bytes(),
            &(statement_elements([0u8; 32], &[0u8; ANCHOR_PUBLIC_INPUT_LEN]).len() as u32)
                .to_le_bytes(),
            &[64, 8, 0, FieldExtension::Cubic as u8, 8, 31],
        ],
    )
}

fn encode_seal(
    circuit: TransparentCircuit,
    public_inputs: &[u8],
    stark_proof_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + public_inputs.len() + stark_proof_bytes.len());
    out.extend_from_slice(SEAL_MAGIC);
    out.push(SEAL_VERSION);
    out.push(circuit_tag(circuit));
    out.extend_from_slice(&(public_inputs.len() as u32).to_le_bytes());
    out.extend_from_slice(public_inputs);
    out.extend_from_slice(&(stark_proof_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(stark_proof_bytes);
    out
}

struct DecodedSeal<'a> {
    circuit: TransparentCircuit,
    public_inputs: &'a [u8],
    stark_proof: &'a [u8],
}

fn decode_seal(seal: &[u8]) -> Result<DecodedSeal<'_>> {
    let mut offset = 0;
    let magic = take(seal, &mut offset, SEAL_MAGIC.len())?;
    if magic != SEAL_MAGIC {
        bail!("invalid native ZEC STARK seal magic");
    }
    let version = take_u8(seal, &mut offset)?;
    if version != SEAL_VERSION {
        bail!("unsupported native ZEC STARK seal version {version}");
    }
    let circuit = circuit_from_tag(take_u8(seal, &mut offset)?)?;
    let public_input_len = take_u32(seal, &mut offset)? as usize;
    let public_inputs = take(seal, &mut offset, public_input_len)?;
    let stark_proof_len = take_u32(seal, &mut offset)? as usize;
    let stark_proof = take(seal, &mut offset, stark_proof_len)?;
    if offset != seal.len() {
        bail!("native ZEC STARK seal has trailing bytes");
    }
    Ok(DecodedSeal {
        circuit,
        public_inputs,
        stark_proof,
    })
}

fn decode_external_asset_anchor_public_inputs(
    encoded: &[u8],
) -> Result<ProofExternalAssetAnchorJournal> {
    let mut offset = 0;
    let chain_id = take_fixed::<32>(encoded, &mut offset)?;
    let current_epoch = take_u64(encoded, &mut offset)?;
    let asset_id = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_protocol = take_u8(encoded, &mut offset)?;
    let zcash_anchor_height = take_u64(encoded, &mut offset)?;
    let zcash_block_hash = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_note_commitment_root = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_nullifier_root = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_anchor_hash = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_confirmation_depth = take_u32(encoded, &mut offset)?;
    if offset != encoded.len() {
        bail!("external asset anchor public inputs have trailing bytes");
    }
    Ok(ProofExternalAssetAnchorJournal {
        chain_id,
        current_epoch,
        asset_id,
        zcash_protocol,
        zcash_anchor_height,
        zcash_block_hash,
        zcash_note_commitment_root,
        zcash_nullifier_root,
        zcash_anchor_hash,
        zcash_confirmation_depth,
    })
}

fn decode_zcash_lock_claim_public_inputs(
    encoded: &[u8],
) -> Result<ProofZcashShieldedLockClaimJournal> {
    let mut offset = 0;
    let version = take_u8(encoded, &mut offset)?;
    let protocol = take_u8(encoded, &mut offset)?;
    let anchor_hash = take_fixed::<32>(encoded, &mut offset)?;
    let external_nullifier = take_fixed::<32>(encoded, &mut offset)?;
    let stake_position_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let action_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let lock_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let proof_digest = take_fixed::<32>(encoded, &mut offset)?;
    let claim_digest = take_fixed::<32>(encoded, &mut offset)?;
    if offset != encoded.len() {
        bail!("Zcash lock claim public inputs have trailing bytes");
    }
    Ok(ProofZcashShieldedLockClaimJournal {
        version,
        protocol,
        anchor_hash,
        external_nullifier,
        stake_position_commitment,
        binding: proof_core::ProofZcashShieldedLockBinding {
            action_commitment,
            lock_commitment,
            proof_digest,
            claim_digest,
        },
    })
}

#[allow(dead_code)]
fn decode_private_external_stake_public_inputs(
    encoded: &[u8],
) -> Result<ProofPrivateExternalStakeJournal> {
    let mut offset = 0;
    let chain_id = take_fixed::<32>(encoded, &mut offset)?;
    let current_epoch = take_u64(encoded, &mut offset)?;
    let asset_id = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_protocol = take_u8(encoded, &mut offset)?;
    let zcash_anchor_height = take_u64(encoded, &mut offset)?;
    let zcash_block_hash = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_note_commitment_root = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_nullifier_root = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_anchor_hash = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_confirmation_depth = take_u32(encoded, &mut offset)?;
    let activation_epoch = take_u64(encoded, &mut offset)?;
    let external_nullifier = take_fixed::<32>(encoded, &mut offset)?;
    let stake_position_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_lock_action_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_lock_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_lock_proof_digest = take_fixed::<32>(encoded, &mut offset)?;
    let zcash_lock_claim_digest = take_fixed::<32>(encoded, &mut offset)?;
    let receipt_note_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let receipt_output_note_commitment = take_fixed::<32>(encoded, &mut offset)?;
    let receipt_output_public_output_digest = take_fixed::<32>(encoded, &mut offset)?;
    if offset != encoded.len() {
        bail!("private external stake public inputs have trailing bytes");
    }
    Ok(ProofPrivateExternalStakeJournal {
        chain_id,
        current_epoch,
        asset_id,
        zcash_protocol,
        zcash_anchor_height,
        zcash_block_hash,
        zcash_note_commitment_root,
        zcash_nullifier_root,
        zcash_anchor_hash,
        zcash_confirmation_depth,
        activation_epoch,
        external_nullifier,
        stake_position_commitment,
        zcash_lock: proof_core::ProofZcashShieldedLockBinding {
            action_commitment: zcash_lock_action_commitment,
            lock_commitment: zcash_lock_commitment,
            proof_digest: zcash_lock_proof_digest,
            claim_digest: zcash_lock_claim_digest,
        },
        receipt_note_commitment,
        receipt_output: proof_core::ProofShieldedOutputBinding {
            note_commitment: receipt_output_note_commitment,
            public_output_digest: receipt_output_public_output_digest,
        },
    })
}

fn circuit_tag(circuit: TransparentCircuit) -> u8 {
    match circuit {
        TransparentCircuit::ExternalAssetAnchorV1 => 5,
        TransparentCircuit::ZcashShieldedStakeV1 => 4,
        TransparentCircuit::OrdinaryTransferV1 => 0,
        TransparentCircuit::PrivateDelegationV1 => 1,
        TransparentCircuit::PrivateUndelegationV1 => 2,
        TransparentCircuit::UnbondingClaimV1 => 3,
        TransparentCircuit::CheckpointAccumulatorV1 => 6,
    }
}

fn circuit_from_tag(tag: u8) -> Result<TransparentCircuit> {
    match tag {
        0 => Ok(TransparentCircuit::OrdinaryTransferV1),
        1 => Ok(TransparentCircuit::PrivateDelegationV1),
        2 => Ok(TransparentCircuit::PrivateUndelegationV1),
        3 => Ok(TransparentCircuit::UnbondingClaimV1),
        4 => Ok(TransparentCircuit::ZcashShieldedStakeV1),
        5 => Ok(TransparentCircuit::ExternalAssetAnchorV1),
        6 => Ok(TransparentCircuit::CheckpointAccumulatorV1),
        other => bail!("unsupported native ZEC STARK seal circuit tag {other}"),
    }
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .context("native ZEC STARK seal offset overflow")?;
    if end > bytes.len() {
        bail!("truncated native ZEC STARK seal");
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn take_fixed<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let slice = take(bytes, offset, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    Ok(take(bytes, offset, 1)?[0])
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_fixed(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_fixed(bytes, offset)?))
}
