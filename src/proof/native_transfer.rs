use anyhow::{bail, Context, Result};
use proof_core::{
    ProofShieldedInputWitness, ProofShieldedOutputBinding, ProofShieldedOutputPlaintext,
    ProofShieldedTxJournal, ProofShieldedTxWitness,
};
use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts};
use serde::{Deserialize, Serialize};

use super::{
    decode_shielded_tx_journal, receipt_from_bytes, receipt_to_seal_bytes,
    shielded_journal_statement_digest, verify_supported_receipt_kind, ProofShieldedOutput,
    TransparentBackendBinding, TransparentCircuit,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferPublicInputs {
    pub statement_digest: [u8; 32],
    pub journal: ProofShieldedTxJournal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferPrivateInput {
    pub witness: ProofShieldedInputWitness,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferPrivateOutput {
    pub plaintext: ProofShieldedOutputPlaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferEnvelopeBinding {
    pub binding: ProofShieldedOutputBinding,
    pub public_output: ProofShieldedOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferPrivateInputs {
    pub inputs: Vec<NativeTransferPrivateInput>,
    pub outputs: Vec<NativeTransferPrivateOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferTraceLayout {
    pub input_rows: u32,
    pub output_rows: u32,
    pub history_rows: u32,
    pub finalize_rows: u32,
    pub transition_rows: u32,
    pub padded_rows: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NativeTransferStarkScaffold {
    pub public_inputs: NativeTransferPublicInputs,
    pub trace_layout: NativeTransferTraceLayout,
    pub envelope_binding_count: u32,
    pub requires_ciphertext_adapter: bool,
    pub history_record_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeTransferPreparedWitness {
    pub source_witness: ProofShieldedTxWitness,
    pub public_inputs: NativeTransferPublicInputs,
    pub private_inputs: NativeTransferPrivateInputs,
    pub envelope_bindings: Vec<NativeTransferEnvelopeBinding>,
}

pub(crate) trait OrdinaryTransferBackend {
    fn prove(
        &self,
        prepared: &NativeTransferPreparedWitness,
    ) -> Result<(Vec<u8>, ProofShieldedTxJournal)>;

    fn verify(&self, seal: &[u8]) -> Result<ProofShieldedTxJournal>;
}

pub(crate) struct PrototypeRisc0OrdinaryTransferBackend {
    binding: TransparentBackendBinding,
}

impl PrototypeRisc0OrdinaryTransferBackend {
    pub(crate) fn new(binding: TransparentBackendBinding) -> Self {
        Self { binding }
    }
}

impl OrdinaryTransferBackend for PrototypeRisc0OrdinaryTransferBackend {
    fn prove(
        &self,
        prepared: &NativeTransferPreparedWitness,
    ) -> Result<(Vec<u8>, ProofShieldedTxJournal)> {
        let env = ExecutorEnv::builder()
            .write(&prepared.source_witness)
            .context("serialize shielded proof witness")?
            .build()
            .context("build zkVM executor environment")?;
        let prove_info = default_prover()
            .prove_with_opts(env, self.binding.elf, &ProverOpts::fast())
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

    fn verify(&self, seal: &[u8]) -> Result<ProofShieldedTxJournal> {
        let receipt = receipt_from_bytes(seal)?;
        verify_supported_receipt_kind(&receipt, "shielded receipt", true)?;
        receipt
            .verify(self.binding.method_id)
            .context("verify shielded receipt")?;
        decode_shielded_tx_journal(&receipt)
    }
}

pub(crate) fn prepare_native_transfer_witness(
    witness: &ProofShieldedTxWitness,
) -> Result<NativeTransferPreparedWitness> {
    let journal = proof_core::validate_shielded_tx_witness(witness)
        .context("derive native transfer public journal from witness")?;
    let statement_digest =
        shielded_journal_statement_digest(TransparentCircuit::OrdinaryTransferV1, &journal)?;

    for input in &witness.inputs {
        if input.historical_extension.is_none() {
            bail!("ordinary transfer native witness requires direct historical extensions");
        }
        if input.historical_accumulator.is_some()
            || input.historical_accumulator_verifier_hint.is_some()
            || input.historical_accumulator_receipt.is_some()
        {
            bail!("ordinary transfer native witness must not carry accumulator receipts");
        }
    }

    let envelope_bindings = witness
        .outputs
        .iter()
        .zip(&journal.outputs)
        .map(|(output, binding)| {
            let public_output = output.public_output.clone();
            let expected_binding = ProofShieldedOutputBinding {
                note_commitment: public_output.note_commitment,
                public_output_digest: proof_core::public_output_digest(&public_output),
            };
            if &expected_binding != binding {
                bail!("shielded output binding does not match the prepared public journal");
            }
            Ok(NativeTransferEnvelopeBinding {
                binding: binding.clone(),
                public_output,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let private_inputs = NativeTransferPrivateInputs {
        inputs: witness
            .inputs
            .iter()
            .cloned()
            .map(|witness| NativeTransferPrivateInput { witness })
            .collect(),
        outputs: witness
            .outputs
            .iter()
            .map(|output| NativeTransferPrivateOutput {
                plaintext: output.plaintext.clone(),
            })
            .collect(),
    };

    Ok(NativeTransferPreparedWitness {
        source_witness: witness.clone(),
        public_inputs: NativeTransferPublicInputs {
            statement_digest,
            journal,
        },
        private_inputs,
        envelope_bindings,
    })
}

fn input_history_record_count(input: &NativeTransferPrivateInput) -> u32 {
    input
        .witness
        .historical_extension
        .as_ref()
        .map(|extension| {
            extension
                .strata
                .iter()
                .map(|stratum| {
                    stratum
                        .packets
                        .iter()
                        .map(|packet| {
                            packet
                                .segments
                                .iter()
                                .map(|segment| segment.records.len() as u32)
                                .sum::<u32>()
                        })
                        .sum::<u32>()
                })
                .sum::<u32>()
        })
        .unwrap_or(0)
}

pub(crate) fn build_native_transfer_stark_scaffold(
    prepared: &NativeTransferPreparedWitness,
) -> NativeTransferStarkScaffold {
    let input_rows = prepared.private_inputs.inputs.len() as u32;
    let output_rows = prepared.private_inputs.outputs.len() as u32;
    let history_rows = prepared
        .private_inputs
        .inputs
        .iter()
        .map(input_history_record_count)
        .sum::<u32>();
    let finalize_rows = 2;
    let transition_rows = input_rows
        .saturating_add(output_rows)
        .saturating_add(history_rows)
        .saturating_add(finalize_rows);
    let padded_rows = transition_rows.max(1).next_power_of_two();
    NativeTransferStarkScaffold {
        public_inputs: prepared.public_inputs.clone(),
        trace_layout: NativeTransferTraceLayout {
            input_rows,
            output_rows,
            history_rows,
            finalize_rows,
            transition_rows,
            padded_rows,
        },
        envelope_binding_count: prepared.envelope_bindings.len() as u32,
        requires_ciphertext_adapter: true,
        history_record_count: history_rows,
    }
}
