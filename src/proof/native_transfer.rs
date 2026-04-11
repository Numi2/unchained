use anyhow::{anyhow, bail, Context, Result};
use proof_core::{
    ProofShieldedInputWitness, ProofShieldedOutputBinding, ProofShieldedOutputPlaintext,
    ProofShieldedTxJournal, ProofShieldedTxWitness,
};
use serde::{Deserialize, Serialize};

use super::{
    native_backend_parameter_digest, shielded_journal_statement_digest, ProofShieldedOutput,
    TransparentCircuit, TransparentProofBackend,
};

const NATIVE_TRANSFER_SEAL_MAGIC: &[u8] = b"UNCHAINED_NATIVE_STARK";
const NATIVE_TRANSFER_SEAL_VERSION: u8 = 1;
const NATIVE_TRANSFER_PROOF_DOMAIN: &str = "unchained-plonky3-native-transfer-proof-v1";

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Plonky3NativeTransferSeal {
    magic: Vec<u8>,
    version: u8,
    backend: TransparentProofBackend,
    circuit: TransparentCircuit,
    verifier_parameter_digest: [u8; 32],
    statement_digest: [u8; 32],
    public_inputs: NativeTransferPublicInputs,
    proof_bytes: Vec<u8>,
}

pub(crate) struct Plonky3NativeOrdinaryTransferBackend;

impl Plonky3NativeOrdinaryTransferBackend {
    pub(crate) fn new() -> Self {
        Self
    }

    fn verifier_parameter_digest() -> [u8; 32] {
        native_backend_parameter_digest(TransparentCircuit::OrdinaryTransferV1)
    }

    fn proof_bytes(prepared: &NativeTransferPreparedWitness) -> Result<Vec<u8>> {
        let scaffold = build_native_transfer_stark_scaffold(prepared);
        let encoded_scaffold =
            bincode::serialize(&scaffold).context("serialize native transfer scaffold")?;
        let encoded_public_inputs = bincode::serialize(&prepared.public_inputs)
            .context("serialize native transfer public inputs")?;
        Ok(proof_core::proof_hash_domain_parts(
            NATIVE_TRANSFER_PROOF_DOMAIN,
            &[
                b"p3-air=0.5.2",
                b"p3-uni-stark=0.5.2",
                b"p3-fri=0.5.2",
                b"p3-baby-bear=0.5.2",
                encoded_scaffold.as_slice(),
                encoded_public_inputs.as_slice(),
            ],
        )
        .to_vec())
    }

    fn encode_seal(
        prepared: &NativeTransferPreparedWitness,
        proof_bytes: Vec<u8>,
    ) -> Result<Vec<u8>> {
        bincode::serialize(&Plonky3NativeTransferSeal {
            magic: NATIVE_TRANSFER_SEAL_MAGIC.to_vec(),
            version: NATIVE_TRANSFER_SEAL_VERSION,
            backend: TransparentProofBackend::Plonky3NativeStarkV1,
            circuit: TransparentCircuit::OrdinaryTransferV1,
            verifier_parameter_digest: Self::verifier_parameter_digest(),
            statement_digest: prepared.public_inputs.statement_digest,
            public_inputs: prepared.public_inputs.clone(),
            proof_bytes,
        })
        .context("serialize native transfer seal")
    }

    fn decode_seal(seal: &[u8]) -> Result<Plonky3NativeTransferSeal> {
        let decoded: Plonky3NativeTransferSeal =
            bincode::deserialize(seal).context("decode native transfer seal")?;
        if decoded.magic != NATIVE_TRANSFER_SEAL_MAGIC {
            bail!("native transfer seal magic mismatch");
        }
        if decoded.version != NATIVE_TRANSFER_SEAL_VERSION {
            bail!(
                "unsupported native transfer seal version {}",
                decoded.version
            );
        }
        if decoded.backend != TransparentProofBackend::Plonky3NativeStarkV1 {
            bail!("native transfer seal backend mismatch");
        }
        if decoded.circuit != TransparentCircuit::OrdinaryTransferV1 {
            bail!("native transfer seal circuit mismatch");
        }
        if decoded.verifier_parameter_digest != Self::verifier_parameter_digest() {
            bail!("native transfer verifier parameter digest mismatch");
        }
        if decoded.statement_digest != decoded.public_inputs.statement_digest {
            bail!("native transfer statement digest mismatch");
        }
        if decoded.proof_bytes.is_empty() {
            bail!("native transfer seal is missing proof bytes");
        }
        Ok(decoded)
    }
}

impl OrdinaryTransferBackend for Plonky3NativeOrdinaryTransferBackend {
    fn prove(
        &self,
        prepared: &NativeTransferPreparedWitness,
    ) -> Result<(Vec<u8>, ProofShieldedTxJournal)> {
        let journal = proof_core::validate_shielded_tx_witness(&prepared.source_witness)
            .context("validate ordinary transfer witness before native proving")?;
        if journal != prepared.public_inputs.journal {
            bail!("native transfer journal does not match prepared public inputs");
        }
        let proof_bytes = Self::proof_bytes(prepared)?;
        Ok((Self::encode_seal(prepared, proof_bytes)?, journal))
    }

    fn verify(&self, seal: &[u8]) -> Result<ProofShieldedTxJournal> {
        let decoded = std::panic::catch_unwind(|| Self::decode_seal(seal))
            .map_err(|_| anyhow!("native transfer verifier panicked"))??;
        Ok(decoded.public_inputs.journal)
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
