use crate::{
    canonical::{CanonicalReader, CanonicalWriter},
    crypto::{self, ML_KEM_768_CT_BYTES},
    node_identity::{
        build_client_config_with_alpn, build_server_config_with_alpn,
        load_local_ingress_key_material_in_dir, ExpectedPeerStore, NodeIdentity, NodeRecordV2,
    },
    proof,
    shielded::{HistoricalUnspentCheckpoint, HistoricalUnspentExtension},
};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    Key, XChaCha20Poly1305, XNonce,
};
use proof_core::{
    ProofPrivateDelegationWitness, ProofPrivateUndelegationWitness, ProofShieldedTxWitness,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::Endpoint;
use rand::RngCore;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{self, Duration};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const PROOF_ASSISTANT_ALPN: &[u8] = b"unchained-proof-assistant/v1";
const PROOF_ASSISTANT_ENVELOPE_VERSION: u8 = 1;
const PROOF_ASSISTANT_REQUEST_VERSION: u8 = 1;
const PROOF_ASSISTANT_RESPONSE_VERSION: u8 = 1;
const PROOF_ASSISTANT_HYBRID_KEY_DOMAIN: &str = "unchained-proof-assistant-hybrid-key-v1";
const DEFAULT_MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const PROOF_ASSISTANT_STREAM_WINDOW_BYTES: u32 = 8 * 1024 * 1024;
const PROOF_ASSISTANT_CONNECTION_WINDOW_BYTES: u32 = 32 * 1024 * 1024;
const PROOF_ASSISTANT_SEND_WINDOW_BYTES: u64 = 32 * 1024 * 1024;
const PROOF_ASSISTANT_IDLE_TIMEOUT_SECS: u64 = 30;
const PROOF_ASSISTANT_KEEP_ALIVE_SECS: u64 = 5;
const PROOF_ASSISTANT_HEADER_BYTES: usize = 1 + 32 + 32 + ML_KEM_768_CT_BYTES + 24;

enum ProofAssistantRequest {
    ShieldedTx {
        request_id: [u8; 32],
        witness: Vec<u8>,
    },
    PrivateDelegation {
        request_id: [u8; 32],
        witness: Vec<u8>,
    },
    PrivateUndelegation {
        request_id: [u8; 32],
        witness: Vec<u8>,
    },
    UnbondingClaim {
        request_id: [u8; 32],
        witness: Vec<u8>,
    },
    CheckpointAccumulator {
        request_id: [u8; 32],
        checkpoint: Vec<u8>,
        extension: Vec<u8>,
        prior: Option<Vec<u8>>,
    },
}

enum ProofAssistantResponse {
    Proof {
        request_id: [u8; 32],
        proof: Vec<u8>,
    },
    Error {
        request_id: [u8; 32],
        message: String,
    },
}

#[derive(Clone)]
pub struct ProofAssistantClient {
    endpoint: Arc<Endpoint>,
    server_record: NodeRecordV2,
    submit_timeout: Duration,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ProofAssistantPolicy {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub submit_timeout: Duration,
}

impl Default for ProofAssistantPolicy {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            submit_timeout: Duration::from_secs(30),
        }
    }
}

pub struct ProofAssistantServer {
    endpoint: Endpoint,
    ingress_keys: crate::node_identity::IngressKeyMaterial,
    server_node_id: [u8; 32],
    policy: ProofAssistantPolicy,
}

impl ProofAssistantClient {
    pub fn new(
        server_record: NodeRecordV2,
        max_request_bytes: usize,
        max_response_bytes: usize,
        submit_timeout: Duration,
    ) -> Result<Self> {
        let chain_id = server_record
            .chain_id
            .ok_or_else(|| anyhow!("proof assistant node record must be bound to a chain"))?;
        let _ = chain_id;
        let expected = ExpectedPeerStore::new();
        expected.remember(&server_record);
        let rustls_client = build_client_config_with_alpn(None, expected, PROOF_ASSISTANT_ALPN)?;
        let transport_config = proof_assistant_transport_config()?;
        let mut endpoint = Endpoint::client(std::net::SocketAddr::from(([0, 0, 0, 0], 0)))?;
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client)?));
        client_config.transport_config(transport_config);
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint: Arc::new(endpoint),
            server_record,
            submit_timeout,
            max_request_bytes,
            max_response_bytes,
        })
    }

    pub fn chain_id(&self) -> Result<[u8; 32]> {
        self.server_record
            .chain_id
            .ok_or_else(|| anyhow!("proof assistant node record must be bound to a chain"))
    }

    pub async fn prove_shielded_tx(
        &self,
        witness: &ProofShieldedTxWitness,
    ) -> Result<proof::TransparentProof> {
        let request_id = random_request_id();
        let witness_bytes = bincode::serialize(witness)
            .context("serialize shielded tx witness for proof assistant")?;
        let response = self
            .exchange_request(ProofAssistantRequest::ShieldedTx {
                request_id,
                witness: witness_bytes,
            })
            .await?;
        let proof = self.expect_proof(response, request_id, "shielded tx")?;
        let _ = proof::verify_shielded_proof(&proof)?;
        Ok(proof)
    }

    pub async fn prove_private_delegation(
        &self,
        witness: &ProofPrivateDelegationWitness,
    ) -> Result<proof::TransparentProof> {
        let request_id = random_request_id();
        let witness_bytes = bincode::serialize(witness)
            .context("serialize private delegation witness for proof assistant")?;
        let response = self
            .exchange_request(ProofAssistantRequest::PrivateDelegation {
                request_id,
                witness: witness_bytes,
            })
            .await?;
        let proof = self.expect_proof(response, request_id, "private delegation")?;
        let _ = proof::verify_private_delegation_proof(&proof)?;
        Ok(proof)
    }

    pub async fn prove_private_undelegation(
        &self,
        witness: &ProofPrivateUndelegationWitness,
    ) -> Result<proof::TransparentProof> {
        let request_id = random_request_id();
        let witness_bytes = bincode::serialize(witness)
            .context("serialize private undelegation witness for proof assistant")?;
        let response = self
            .exchange_request(ProofAssistantRequest::PrivateUndelegation {
                request_id,
                witness: witness_bytes,
            })
            .await?;
        let proof = self.expect_proof(response, request_id, "private undelegation")?;
        let _ = proof::verify_private_undelegation_proof(&proof)?;
        Ok(proof)
    }

    pub async fn prove_unbonding_claim(
        &self,
        witness: &ProofShieldedTxWitness,
    ) -> Result<proof::TransparentProof> {
        let request_id = random_request_id();
        let witness_bytes = bincode::serialize(witness)
            .context("serialize unbonding claim witness for proof assistant")?;
        let response = self
            .exchange_request(ProofAssistantRequest::UnbondingClaim {
                request_id,
                witness: witness_bytes,
            })
            .await?;
        let proof = self.expect_proof(response, request_id, "unbonding claim")?;
        let _ = proof::verify_unbonding_claim_proof(&proof)?;
        Ok(proof)
    }

    pub async fn prove_checkpoint_accumulator(
        &self,
        checkpoint: &HistoricalUnspentCheckpoint,
        extension: &HistoricalUnspentExtension,
        prior: Option<&proof::CheckpointAccumulatorProof>,
    ) -> Result<proof::CheckpointAccumulatorProof> {
        let request_id = random_request_id();
        let checkpoint_bytes = bincode::serialize(checkpoint)
            .context("serialize checkpoint accumulator checkpoint for proof assistant")?;
        let extension_bytes = bincode::serialize(extension)
            .context("serialize checkpoint accumulator extension for proof assistant")?;
        let prior_bytes = prior
            .map(|proof| {
                bincode::serialize(proof)
                    .context("serialize checkpoint accumulator prior proof for proof assistant")
            })
            .transpose()?;
        let response = self
            .exchange_request(ProofAssistantRequest::CheckpointAccumulator {
                request_id,
                checkpoint: checkpoint_bytes,
                extension: extension_bytes,
                prior: prior_bytes,
            })
            .await?;
        let proof = self.expect_proof(response, request_id, "checkpoint accumulator")?;
        Ok(proof::CheckpointAccumulatorProof {
            journal: proof::verify_checkpoint_accumulator_proof(&proof)?,
            proof,
        })
    }

    fn expect_proof(
        &self,
        response: ProofAssistantResponse,
        request_id: [u8; 32],
        label: &str,
    ) -> Result<proof::TransparentProof> {
        match response {
            ProofAssistantResponse::Proof {
                request_id: echoed_request_id,
                proof,
            } => {
                if echoed_request_id != request_id {
                    bail!("proof assistant {label} request_id mismatch");
                }
                proof::proof_from_bytes(&proof)
            }
            ProofAssistantResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                if echoed_request_id != request_id {
                    bail!("proof assistant {label} request_id mismatch");
                }
                bail!("proof assistant {label} failed: {message}");
            }
        }
    }

    async fn exchange_request(
        &self,
        request: ProofAssistantRequest,
    ) -> Result<ProofAssistantResponse> {
        let envelope =
            seal_request_to_server(&request, &self.server_record, self.max_request_bytes)?;
        let connection = time::timeout(
            self.submit_timeout,
            self.endpoint.connect(
                self.server_record.primary_address()?,
                &self.server_record.server_name(),
            )?,
        )
        .await
        .context("proof assistant dial timed out")??;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("proof assistant failed to open stream")?;
        send.write_all(&envelope)
            .await
            .context("proof assistant failed to write request envelope")?;
        send.finish()
            .context("proof assistant failed to finish request stream")?;
        let response_bytes = recv
            .read_to_end(self.max_response_bytes)
            .await
            .context("proof assistant failed while waiting for response")?;
        decode_response(&response_bytes)
    }
}

impl Drop for ProofAssistantClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.endpoint) == 1 {
            self.endpoint.close(0u32.into(), b"shutdown");
        }
    }
}

impl ProofAssistantServer {
    pub fn bind(
        identity: &NodeIdentity,
        listen_addr: std::net::SocketAddr,
        policy: ProofAssistantPolicy,
    ) -> Result<Self> {
        let rustls_server = build_server_config_with_alpn(identity, PROOF_ASSISTANT_ALPN, false)?;
        let transport_config = proof_assistant_transport_config()?;
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_server)?));
        server_config.transport_config(transport_config);
        let endpoint = Endpoint::server(server_config, listen_addr)?;
        Ok(Self {
            endpoint,
            ingress_keys: load_local_ingress_key_material_in_dir(identity.dir())?,
            server_node_id: identity.node_id(),
            policy,
        })
    }

    pub async fn serve(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let endpoint = self.endpoint.clone();
        let server = Arc::new(self);
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let server = server.clone();
                    tokio::spawn(async move {
                        if let Err(err) = server.handle_connection(incoming).await {
                            eprintln!("proof assistant connection failed: {err}");
                        }
                    });
                }
            }
        }
        server.endpoint.close(0u32.into(), b"shutdown");
        Ok(())
    }

    async fn handle_connection(&self, incoming: quinn::Incoming) -> Result<()> {
        let connection = time::timeout(self.policy.submit_timeout, incoming)
            .await
            .context("proof assistant handshake timed out")??;
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::TimedOut) => break,
                Err(err) => return Err(err.into()),
            };
            let envelope = recv
                .read_to_end(self.policy.max_request_bytes + PROOF_ASSISTANT_HEADER_BYTES + 16)
                .await
                .context("proof assistant failed while reading request envelope")?;
            let request =
                open_request_from_envelope(&envelope, &self.ingress_keys, self.server_node_id)?;
            let response = self.handle_request(request).await?;
            send.write_all(&encode_response(&response)?)
                .await
                .context("proof assistant failed to write response")?;
            send.finish()
                .context("proof assistant failed to finish response stream")?;
        }
        Ok(())
    }

    async fn handle_request(
        &self,
        request: ProofAssistantRequest,
    ) -> Result<ProofAssistantResponse> {
        tokio::task::spawn_blocking(move || handle_request_blocking(request))
            .await
            .map_err(|err| anyhow!(err))?
    }
}

fn handle_request_blocking(request: ProofAssistantRequest) -> Result<ProofAssistantResponse> {
    let request_id = request.request_id();
    let result: Result<ProofAssistantResponse> = match request {
        ProofAssistantRequest::ShieldedTx {
            request_id,
            witness,
        } => {
            let witness: ProofShieldedTxWitness = bincode::deserialize(&witness)
                .context("deserialize shielded tx witness in proof assistant")?;
            let (proof, _journal) = proof::prove_shielded_tx(&witness)?;
            Ok(ProofAssistantResponse::Proof {
                request_id,
                proof: proof::proof_to_bytes(&proof)?,
            })
        }
        ProofAssistantRequest::PrivateDelegation {
            request_id,
            witness,
        } => {
            let witness: ProofPrivateDelegationWitness = bincode::deserialize(&witness)
                .context("deserialize private delegation witness in proof assistant")?;
            let (proof, _journal) = proof::prove_private_delegation(&witness)?;
            Ok(ProofAssistantResponse::Proof {
                request_id,
                proof: proof::proof_to_bytes(&proof)?,
            })
        }
        ProofAssistantRequest::PrivateUndelegation {
            request_id,
            witness,
        } => {
            let witness: ProofPrivateUndelegationWitness = bincode::deserialize(&witness)
                .context("deserialize private undelegation witness in proof assistant")?;
            let (proof, _journal) = proof::prove_private_undelegation(&witness)?;
            Ok(ProofAssistantResponse::Proof {
                request_id,
                proof: proof::proof_to_bytes(&proof)?,
            })
        }
        ProofAssistantRequest::UnbondingClaim {
            request_id,
            witness,
        } => {
            let witness: ProofShieldedTxWitness = bincode::deserialize(&witness)
                .context("deserialize unbonding claim witness in proof assistant")?;
            let (proof, _journal) = proof::prove_unbonding_claim(&witness)?;
            Ok(ProofAssistantResponse::Proof {
                request_id,
                proof: proof::proof_to_bytes(&proof)?,
            })
        }
        ProofAssistantRequest::CheckpointAccumulator {
            request_id,
            checkpoint,
            extension,
            prior,
        } => {
            let checkpoint: HistoricalUnspentCheckpoint = bincode::deserialize(&checkpoint)
                .context("deserialize checkpoint accumulator checkpoint in proof assistant")?;
            let extension: HistoricalUnspentExtension = bincode::deserialize(&extension)
                .context("deserialize checkpoint accumulator extension in proof assistant")?;
            let prior: Option<proof::CheckpointAccumulatorProof> = prior
                .map(|bytes| {
                    bincode::deserialize(&bytes).context(
                        "deserialize checkpoint accumulator prior proof in proof assistant",
                    )
                })
                .transpose()?;
            let accumulator =
                proof::prove_checkpoint_accumulator(&checkpoint, &extension, prior.as_ref())?;
            Ok(ProofAssistantResponse::Proof {
                request_id,
                proof: proof::proof_to_bytes(&accumulator.proof)?,
            })
        }
    };
    match result {
        Ok(response) => Ok(response),
        Err(err) => Ok(ProofAssistantResponse::Error {
            request_id,
            message: err.to_string(),
        }),
    }
}

fn random_request_id() -> [u8; 32] {
    let mut request_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut request_id);
    request_id
}

impl ProofAssistantRequest {
    fn request_id(&self) -> [u8; 32] {
        match self {
            ProofAssistantRequest::ShieldedTx { request_id, .. }
            | ProofAssistantRequest::PrivateDelegation { request_id, .. }
            | ProofAssistantRequest::PrivateUndelegation { request_id, .. }
            | ProofAssistantRequest::UnbondingClaim { request_id, .. }
            | ProofAssistantRequest::CheckpointAccumulator { request_id, .. } => *request_id,
        }
    }
}

fn seal_request_to_server(
    request: &ProofAssistantRequest,
    server_record: &NodeRecordV2,
    max_request_bytes: usize,
) -> Result<Vec<u8>> {
    let plaintext = encode_request(request)?;
    if plaintext.len() > max_request_bytes {
        bail!("proof assistant request exceeds configured maximum size");
    }
    let x25519_secret = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let server_x25519 = X25519PublicKey::from(server_record.ingress_x25519_pk);
    let x25519_shared = x25519_secret.diffie_hellman(&server_x25519);
    let (kem_ct, kem_shared) = server_record.ingress_kem_pk.encapsulate()?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let symmetric_key = derive_hybrid_key(
        &server_record.node_id,
        x25519_public.as_bytes(),
        x25519_shared.as_bytes(),
        &kem_shared,
        &nonce,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow!("failed to encrypt proof assistant request"))?;
    let mut envelope = Vec::with_capacity(PROOF_ASSISTANT_HEADER_BYTES + ciphertext.len());
    envelope.push(PROOF_ASSISTANT_ENVELOPE_VERSION);
    envelope.extend_from_slice(&server_record.node_id);
    envelope.extend_from_slice(x25519_public.as_bytes());
    envelope.extend_from_slice(&kem_ct);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_request_from_envelope(
    envelope: &[u8],
    ingress_keys: &crate::node_identity::IngressKeyMaterial,
    server_node_id: [u8; 32],
) -> Result<ProofAssistantRequest> {
    if envelope.len() < PROOF_ASSISTANT_HEADER_BYTES + 16 {
        bail!("proof assistant envelope is truncated");
    }
    if envelope.first().copied() != Some(PROOF_ASSISTANT_ENVELOPE_VERSION) {
        bail!("unsupported proof assistant envelope version");
    }
    let mut target_node_id = [0u8; 32];
    target_node_id.copy_from_slice(&envelope[1..33]);
    if target_node_id != server_node_id {
        bail!("proof assistant envelope targets the wrong node identity");
    }
    let mut ephemeral_x25519_pk = [0u8; 32];
    ephemeral_x25519_pk.copy_from_slice(&envelope[33..65]);
    let mut kem_ct = [0u8; ML_KEM_768_CT_BYTES];
    kem_ct.copy_from_slice(&envelope[65..65 + ML_KEM_768_CT_BYTES]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[65 + ML_KEM_768_CT_BYTES..65 + ML_KEM_768_CT_BYTES + 24]);
    let ciphertext = &envelope[PROOF_ASSISTANT_HEADER_BYTES..];
    let kem_secret = crypto::ml_kem_768_secret_key_from_bytes(&ingress_keys.kem_secret);
    let kem_shared = crypto::ml_kem_768_decapsulate(&kem_secret, &kem_ct)?;
    let x25519_secret = X25519StaticSecret::from(ingress_keys.x25519_secret);
    let x25519_public = X25519PublicKey::from(ephemeral_x25519_pk);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_public);
    let symmetric_key = derive_hybrid_key(
        &server_node_id,
        &ephemeral_x25519_pk,
        x25519_shared.as_bytes(),
        &kem_shared,
        &nonce,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| anyhow!("failed to decrypt proof assistant envelope"))?;
    decode_request(&plaintext)
}

fn derive_hybrid_key(
    server_node_id: &[u8; 32],
    ephemeral_x25519_pk: &[u8; 32],
    x25519_shared: &[u8; 32],
    kem_shared: &[u8; 32],
    nonce: &[u8; 24],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PROOF_ASSISTANT_HYBRID_KEY_DOMAIN);
    hasher.update(server_node_id);
    hasher.update(ephemeral_x25519_pk);
    hasher.update(x25519_shared);
    hasher.update(kem_shared);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

fn encode_request(request: &ProofAssistantRequest) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(PROOF_ASSISTANT_REQUEST_VERSION);
    match request {
        ProofAssistantRequest::ShieldedTx {
            request_id,
            witness,
        } => {
            writer.write_u8(1);
            writer.write_fixed(request_id);
            writer.write_bytes(witness)?;
        }
        ProofAssistantRequest::PrivateDelegation {
            request_id,
            witness,
        } => {
            writer.write_u8(2);
            writer.write_fixed(request_id);
            writer.write_bytes(witness)?;
        }
        ProofAssistantRequest::PrivateUndelegation {
            request_id,
            witness,
        } => {
            writer.write_u8(3);
            writer.write_fixed(request_id);
            writer.write_bytes(witness)?;
        }
        ProofAssistantRequest::UnbondingClaim {
            request_id,
            witness,
        } => {
            writer.write_u8(4);
            writer.write_fixed(request_id);
            writer.write_bytes(witness)?;
        }
        ProofAssistantRequest::CheckpointAccumulator {
            request_id,
            checkpoint,
            extension,
            prior,
        } => {
            writer.write_u8(5);
            writer.write_fixed(request_id);
            writer.write_bytes(checkpoint)?;
            writer.write_bytes(extension)?;
            writer.write_bool(prior.is_some());
            if let Some(prior) = prior {
                writer.write_bytes(prior)?;
            }
        }
    }
    Ok(writer.into_vec())
}

fn decode_request(bytes: &[u8]) -> Result<ProofAssistantRequest> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != PROOF_ASSISTANT_REQUEST_VERSION {
        bail!("unsupported proof assistant request version {}", version);
    }
    let request = match reader.read_u8()? {
        1 => ProofAssistantRequest::ShieldedTx {
            request_id: reader.read_fixed()?,
            witness: reader.read_bytes()?,
        },
        2 => ProofAssistantRequest::PrivateDelegation {
            request_id: reader.read_fixed()?,
            witness: reader.read_bytes()?,
        },
        3 => ProofAssistantRequest::PrivateUndelegation {
            request_id: reader.read_fixed()?,
            witness: reader.read_bytes()?,
        },
        4 => ProofAssistantRequest::UnbondingClaim {
            request_id: reader.read_fixed()?,
            witness: reader.read_bytes()?,
        },
        5 => {
            let request_id = reader.read_fixed()?;
            let checkpoint = reader.read_bytes()?;
            let extension = reader.read_bytes()?;
            let prior = if reader.read_bool()? {
                Some(reader.read_bytes()?)
            } else {
                None
            };
            ProofAssistantRequest::CheckpointAccumulator {
                request_id,
                checkpoint,
                extension,
                prior,
            }
        }
        other => bail!("unsupported proof assistant request tag {}", other),
    };
    reader.finish()?;
    Ok(request)
}

fn encode_response(response: &ProofAssistantResponse) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(PROOF_ASSISTANT_RESPONSE_VERSION);
    match response {
        ProofAssistantResponse::Proof { request_id, proof } => {
            writer.write_u8(1);
            writer.write_fixed(request_id);
            writer.write_bytes(proof)?;
        }
        ProofAssistantResponse::Error {
            request_id,
            message,
        } => {
            writer.write_u8(2);
            writer.write_fixed(request_id);
            writer.write_string(message)?;
        }
    }
    Ok(writer.into_vec())
}

fn decode_response(bytes: &[u8]) -> Result<ProofAssistantResponse> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != PROOF_ASSISTANT_RESPONSE_VERSION {
        bail!("unsupported proof assistant response version {}", version);
    }
    let response = match reader.read_u8()? {
        1 => ProofAssistantResponse::Proof {
            request_id: reader.read_fixed()?,
            proof: reader.read_bytes()?,
        },
        2 => ProofAssistantResponse::Error {
            request_id: reader.read_fixed()?,
            message: reader.read_string()?,
        },
        other => bail!("unsupported proof assistant response tag {}", other),
    };
    reader.finish()?;
    Ok(response)
}

fn proof_assistant_transport_config() -> Result<Arc<quinn::TransportConfig>> {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(PROOF_ASSISTANT_STREAM_WINDOW_BYTES));
    transport.receive_window(quinn::VarInt::from_u32(
        PROOF_ASSISTANT_CONNECTION_WINDOW_BYTES,
    ));
    transport.send_window(PROOF_ASSISTANT_SEND_WINDOW_BYTES);
    transport.max_idle_timeout(Some(
        Duration::from_secs(PROOF_ASSISTANT_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|_| anyhow!("invalid proof assistant idle timeout"))?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(PROOF_ASSISTANT_KEEP_ALIVE_SECS)));
    Ok(Arc::new(transport))
}
