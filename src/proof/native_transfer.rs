#[cfg(feature = "local-prover")]
use anyhow::bail;
use anyhow::{Context, Result};
use proof_core::ProofShieldedTxJournal;
#[cfg(feature = "local-prover")]
use proof_core::{ProofShieldedOutputBinding, ProofShieldedTxWitness};
#[cfg(feature = "local-prover")]
use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts};
#[cfg(feature = "local-prover")]
use serde::{Deserialize, Serialize};

use super::{
    decode_shielded_tx_journal, receipt_from_bytes, verify_supported_receipt_kind,
    TransparentBackendBinding,
};
#[cfg(feature = "local-prover")]
use super::{
    prover_elf_for_circuit, receipt_to_seal_bytes, shielded_journal_statement_digest,
    verify_checkpoint_accumulator_seal_bytes, TransparentCircuit,
};

#[cfg(feature = "local-prover")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferPublicInputs {
    pub statement_digest: [u8; 32],
    pub journal: ProofShieldedTxJournal,
}

#[cfg(feature = "local-prover")]
#[derive(Debug, Clone)]
pub(crate) struct NativeTransferPreparedWitness {
    pub source_witness: ProofShieldedTxWitness,
    pub public_inputs: NativeTransferPublicInputs,
}

pub(crate) struct PrototypeRisc0OrdinaryTransferBackend {
    binding: TransparentBackendBinding,
}

impl PrototypeRisc0OrdinaryTransferBackend {
    pub(crate) fn new(binding: TransparentBackendBinding) -> Self {
        Self { binding }
    }
}

impl PrototypeRisc0OrdinaryTransferBackend {
    #[cfg(feature = "local-prover")]
    pub(crate) fn prove(
        &self,
        prepared: &NativeTransferPreparedWitness,
    ) -> Result<(Vec<u8>, ProofShieldedTxJournal)> {
        let mut builder = ExecutorEnv::builder();
        for input in &prepared.source_witness.inputs {
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
            .write(&prepared.source_witness)
            .context("serialize shielded proof witness")?
            .build()
            .context("build zkVM executor environment")?;
        let elf = prover_elf_for_circuit(TransparentCircuit::OrdinaryTransferV1);
        let prove_info = default_prover()
            .prove_with_opts(env, elf, &ProverOpts::fast())
            .context("prove shielded transaction witness")?;
        let receipt = prove_info.receipt;
        verify_supported_receipt_kind(&receipt, "shielded spend receipt", true)?;
        receipt
            .verify(self.binding.method_id)
            .context("verify locally generated shielded receipt")?;
        let journal = decode_shielded_tx_journal(&receipt)?;
        if journal != prepared.public_inputs.journal {
            bail!("prototype transfer backend journal does not match prepared public inputs");
        }
        Ok((receipt_to_seal_bytes(&receipt)?, journal))
    }

    pub(crate) fn verify(&self, seal: &[u8]) -> Result<ProofShieldedTxJournal> {
        let receipt = receipt_from_bytes(seal)?;
        verify_supported_receipt_kind(&receipt, "shielded receipt", true)?;
        receipt
            .verify(self.binding.method_id)
            .context("verify shielded receipt")?;
        decode_shielded_tx_journal(&receipt)
    }
}

#[cfg(feature = "local-prover")]
pub(crate) fn prepare_native_transfer_witness(
    witness: &ProofShieldedTxWitness,
) -> Result<NativeTransferPreparedWitness> {
    let journal = proof_core::validate_shielded_tx_witness(witness)
        .context("derive native transfer public journal from witness")?;
    let statement_digest =
        shielded_journal_statement_digest(TransparentCircuit::OrdinaryTransferV1, &journal)?;

    if witness.outputs.len() != journal.outputs.len() {
        bail!("shielded witness output count does not match the prepared public journal");
    }
    for (output, binding) in witness.outputs.iter().zip(&journal.outputs) {
        let public_output = output.public_output.clone();
        let expected_binding = ProofShieldedOutputBinding {
            note_commitment: public_output.note_commitment,
            public_output_digest: proof_core::public_output_digest(&public_output),
        };
        if &expected_binding != binding {
            bail!("shielded output binding does not match the prepared public journal");
        }
    }

    Ok(NativeTransferPreparedWitness {
        source_witness: witness.clone(),
        public_inputs: NativeTransferPublicInputs {
            statement_digest,
            journal,
        },
    })
}
