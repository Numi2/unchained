use anyhow::{anyhow, bail, Context, Result};
use methods::{
    CHECKPOINT_ACCUMULATOR_METHOD_ELF, CHECKPOINT_ACCUMULATOR_METHOD_ID,
    PRIVATE_DELEGATION_METHOD_ELF, PRIVATE_DELEGATION_METHOD_ID, SHIELDED_SPEND_METHOD_ELF,
    SHIELDED_SPEND_METHOD_ID,
};
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
    ProofPrivateDelegationWitness, ProofShieldedInputWitness, ProofShieldedNote,
    ProofShieldedNoteKind, ProofShieldedOutput, ProofShieldedOutputBinding,
    ProofShieldedOutputPlaintext, ProofShieldedOutputWitness, ProofShieldedTxJournal,
    ProofShieldedTxWitness,
};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover, ProverOpts, Receipt};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointAccumulatorProof {
    pub journal: CheckpointAccumulatorJournal,
    pub receipt: Vec<u8>,
}

pub fn prove_shielded_tx(
    witness: &ProofShieldedTxWitness,
) -> Result<(Receipt, ProofShieldedTxJournal)> {
    let mut builder = ExecutorEnv::builder();
    for input in &witness.inputs {
        match (
            input.historical_accumulator.as_ref(),
            input.historical_accumulator_receipt.as_ref(),
        ) {
            (Some(accumulator), Some(bytes)) => {
                let journal = verify_checkpoint_accumulator_receipt_bytes(bytes)?;
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
        .context("serialize shielded proof witness")?
        .build()
        .context("build zkVM executor environment")?;
    let prove_info = default_prover()
        .prove_with_opts(env, SHIELDED_SPEND_METHOD_ELF, &ProverOpts::succinct())
        .context("prove shielded transaction witness")?;
    let receipt = prove_info.receipt;
    match &receipt.inner {
        InnerReceipt::Succinct(_) => {}
        _ => bail!("shielded spends require a succinct STARK receipt"),
    }
    receipt
        .verify(SHIELDED_SPEND_METHOD_ID)
        .context("verify locally generated shielded receipt")?;
    let journal = decode_shielded_tx_journal(&receipt)?;
    Ok((receipt, journal))
}

pub fn verify_shielded_receipt_bytes(bytes: &[u8]) -> Result<ProofShieldedTxJournal> {
    let receipt = receipt_from_bytes(bytes)?;
    match &receipt.inner {
        InnerReceipt::Succinct(_) => {}
        _ => bail!("only succinct STARK receipts are accepted"),
    }
    receipt
        .verify(SHIELDED_SPEND_METHOD_ID)
        .context("verify shielded receipt")?;
    decode_shielded_tx_journal(&receipt)
}

pub fn prove_private_delegation(
    witness: &ProofPrivateDelegationWitness,
) -> Result<(Receipt, ProofPrivateDelegationJournal)> {
    let mut builder = ExecutorEnv::builder();
    for input in &witness.shielded.inputs {
        match (
            input.historical_accumulator.as_ref(),
            input.historical_accumulator_receipt.as_ref(),
        ) {
            (Some(accumulator), Some(bytes)) => {
                let journal = verify_checkpoint_accumulator_receipt_bytes(bytes)?;
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
        .prove_with_opts(env, PRIVATE_DELEGATION_METHOD_ELF, &ProverOpts::succinct())
        .context("prove private delegation witness")?;
    let receipt = prove_info.receipt;
    match &receipt.inner {
        InnerReceipt::Succinct(_) => {}
        _ => bail!("private delegation requires a succinct STARK receipt"),
    }
    receipt
        .verify(PRIVATE_DELEGATION_METHOD_ID)
        .context("verify locally generated private delegation receipt")?;
    let journal = decode_private_delegation_journal(&receipt)?;
    Ok((receipt, journal))
}

pub fn verify_private_delegation_receipt_bytes(
    bytes: &[u8],
) -> Result<ProofPrivateDelegationJournal> {
    let receipt = receipt_from_bytes(bytes)?;
    match &receipt.inner {
        InnerReceipt::Succinct(_) => {}
        _ => bail!("only succinct private delegation receipts are accepted"),
    }
    receipt
        .verify(PRIVATE_DELEGATION_METHOD_ID)
        .context("verify private delegation receipt")?;
    decode_private_delegation_journal(&receipt)
}

pub fn receipt_to_bytes(receipt: &Receipt) -> Result<Vec<u8>> {
    bincode::serialize(receipt).context("serialize shielded receipt")
}

pub fn prove_checkpoint_accumulator(
    checkpoint: &HistoricalUnspentCheckpoint,
    extension: &HistoricalUnspentExtension,
    prior: Option<&CheckpointAccumulatorProof>,
) -> Result<CheckpointAccumulatorProof> {
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
        .map(|proof| receipt_from_bytes(&proof.receipt))
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
                accumulator_image_id: CHECKPOINT_ACCUMULATOR_METHOD_ID,
                note_commitment: checkpoint.note_commitment,
                birth_epoch: checkpoint.birth_epoch,
                prior_accumulator: prior_journal.clone(),
                stratum: stratum_to_proof(stratum),
            })
            .context("serialize checkpoint accumulator step witness")?
            .build()
            .context("build checkpoint accumulator executor environment")?;
        let prove_info = default_prover()
            .prove_with_opts(
                env,
                CHECKPOINT_ACCUMULATOR_METHOD_ELF,
                &ProverOpts::succinct(),
            )
            .context("prove checkpoint accumulator step")?;
        let receipt = prove_info.receipt;
        match &receipt.inner {
            InnerReceipt::Succinct(_) => {}
            _ => bail!("checkpoint accumulator requires a succinct STARK receipt"),
        }
        receipt
            .verify(CHECKPOINT_ACCUMULATOR_METHOD_ID)
            .context("verify locally generated checkpoint accumulator receipt")?;
        let journal = decode_checkpoint_accumulator_journal(&receipt)?;
        prior_journal = Some(journal.clone());
        prior_receipt = Some(receipt.clone());
        current_journal = Some(journal);
        current_receipt = Some(receipt);
    }

    Ok(CheckpointAccumulatorProof {
        journal: current_journal
            .ok_or_else(|| anyhow!("missing checkpoint accumulator journal"))?,
        receipt: receipt_to_bytes(
            &current_receipt.ok_or_else(|| anyhow!("missing checkpoint accumulator receipt"))?,
        )?,
    })
}

pub fn verify_checkpoint_accumulator_receipt_bytes(
    bytes: &[u8],
) -> Result<CheckpointAccumulatorJournal> {
    let receipt = receipt_from_bytes(bytes)?;
    match &receipt.inner {
        InnerReceipt::Succinct(_) => {}
        _ => bail!("only succinct checkpoint accumulator receipts are accepted"),
    }
    receipt
        .verify(CHECKPOINT_ACCUMULATOR_METHOD_ID)
        .context("verify checkpoint accumulator receipt")?;
    decode_checkpoint_accumulator_journal(&receipt)
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
    historical_accumulator: Option<&CheckpointAccumulatorProof>,
    current_nullifier: &[u8; 32],
) -> ProofShieldedInputWitness {
    ProofShieldedInputWitness {
        note: note_to_proof(note),
        note_key: *note_key,
        membership_proof: membership_proof_to_proof(membership_proof),
        historical_checkpoint: checkpoint_to_proof(historical_checkpoint),
        historical_accumulator: historical_accumulator.map(|proof| proof.journal.clone()),
        historical_accumulator_receipt: historical_accumulator.map(|proof| proof.receipt.clone()),
        current_nullifier: *current_nullifier,
    }
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
