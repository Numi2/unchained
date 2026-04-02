use anyhow::{anyhow, bail, Context, Result};
use methods::{SHIELDED_SPEND_METHOD_ELF, SHIELDED_SPEND_METHOD_ID};
use proof_core::{
    HistoricalAbsenceRecord as ProofHistoricalAbsenceRecord,
    HistoricalUnspentCheckpoint as ProofHistoricalUnspentCheckpoint,
    HistoricalUnspentExtension as ProofHistoricalUnspentExtension,
    NoteMembershipProof as ProofNoteMembershipProof,
    NullifierMembershipWitness as ProofNullifierMembershipWitness,
    NullifierNonMembershipProof as ProofNullifierNonMembershipProof, ProofShieldedInputWitness,
    ProofShieldedNote, ProofShieldedOutput, ProofShieldedOutputBinding,
    ProofShieldedOutputPlaintext, ProofShieldedOutputWitness, ProofShieldedTxJournal,
    ProofShieldedTxWitness,
};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover, ProverOpts, Receipt};

use crate::{
    shielded::{
        HistoricalAbsenceRecord, HistoricalUnspentCheckpoint, HistoricalUnspentExtension,
        NoteMembershipProof, NullifierMembershipWitness, NullifierNonMembershipProof, ShieldedNote,
    },
    transaction::{ShieldedOutput, ShieldedOutputPlaintext},
};

pub fn prove_shielded_tx(
    witness: &ProofShieldedTxWitness,
) -> Result<(Receipt, ProofShieldedTxJournal)> {
    let env = ExecutorEnv::builder()
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
    let receipt: Receipt = bincode::deserialize(bytes).context("decode shielded receipt bytes")?;
    match &receipt.inner {
        InnerReceipt::Succinct(_) => {}
        _ => bail!("only succinct STARK receipts are accepted"),
    }
    receipt
        .verify(SHIELDED_SPEND_METHOD_ID)
        .context("verify shielded receipt")?;
    decode_shielded_tx_journal(&receipt)
}

pub fn receipt_to_bytes(receipt: &Receipt) -> Result<Vec<u8>> {
    bincode::serialize(receipt).context("serialize shielded receipt")
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

pub fn output_witness_from_local(
    plaintext: &ShieldedOutputPlaintext,
    output: &ShieldedOutput,
) -> ProofShieldedOutputWitness {
    ProofShieldedOutputWitness {
        plaintext: output_plaintext_to_proof(plaintext),
        public_output: public_output_from_local(output),
    }
}

pub fn input_witness_from_local(
    note: &ShieldedNote,
    note_key: &[u8; 32],
    membership_proof: &NoteMembershipProof,
    historical_checkpoint: &HistoricalUnspentCheckpoint,
    historical_extension: &HistoricalUnspentExtension,
    current_nullifier: &[u8; 32],
) -> ProofShieldedInputWitness {
    ProofShieldedInputWitness {
        note: note_to_proof(note),
        note_key: *note_key,
        membership_proof: membership_proof_to_proof(membership_proof),
        historical_checkpoint: checkpoint_to_proof(historical_checkpoint),
        historical_extension: extension_to_proof(historical_extension),
        current_nullifier: *current_nullifier,
    }
}

fn decode_shielded_tx_journal(receipt: &Receipt) -> Result<ProofShieldedTxJournal> {
    receipt
        .journal
        .decode()
        .map_err(|err| anyhow!("decode shielded receipt journal: {err}"))
}

fn note_to_proof(note: &ShieldedNote) -> ProofShieldedNote {
    ProofShieldedNote {
        version: note.version,
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

fn extension_to_proof(extension: &HistoricalUnspentExtension) -> ProofHistoricalUnspentExtension {
    ProofHistoricalUnspentExtension {
        version: extension.version,
        note_commitment: extension.note_commitment,
        from_epoch: extension.from_epoch,
        through_epoch: extension.through_epoch,
        prior_transcript_root: extension.prior_transcript_root,
        new_transcript_root: extension.new_transcript_root,
        records: extension
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
