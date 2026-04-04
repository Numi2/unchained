use crate::{
    canonical::{
        decode_recipient_handle, encode_recipient_handle, read_tagged_kem_public_key,
        read_tagged_signing_public_key, write_tagged_kem_public_key,
        write_tagged_signing_public_key, CanonicalReader, CanonicalWriter,
    },
    crypto::{
        self, TaggedKemPublicKey, TaggedSigningPublicKey, ML_KEM_768_CT_BYTES, ML_KEM_768_SK_BYTES,
    },
    node_identity::{
        build_client_config_with_alpn, build_server_config_with_alpn,
        load_local_ingress_key_material_in_dir, ExpectedPeerStore, IngressKeyMaterial,
        NodeIdentity, NodeRecordV2,
    },
    wallet::RecipientHandle,
};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    Key, XChaCha20Poly1305, XNonce,
};
use chalamet_pir::{client::Client as PirClient, server::Server as PirServer, SEED_BYTE_LEN};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::Endpoint;
use rand::RngCore;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, DB};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;
use tokio::time::{self, Duration};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const DISCOVERY_ALPN: &[u8] = b"unchained-discovery/v1";
const DISCOVERY_ENVELOPE_VERSION: u8 = 1;
const DISCOVERY_REQUEST_VERSION: u8 = 1;
const DISCOVERY_RESPONSE_VERSION: u8 = 1;
const DISCOVERY_MANIFEST_VERSION: u8 = 1;
const DISCOVERY_RECORD_VERSION: u8 = 1;
const DISCOVERY_MAILBOX_REQUEST_VERSION: u8 = 1;
const DISCOVERY_MAILBOX_RESPONSE_VERSION: u8 = 1;
const DISCOVERY_LOCATOR_PREFIX: &str = "uc1";
const DISCOVERY_RECORD_DOMAIN: &str = "unchained-discovery-record-v1";
const DISCOVERY_LOCATOR_DOMAIN: &str = "unchained-discovery-locator-v1";
const DISCOVERY_MAILBOX_ID_DOMAIN: &str = "unchained-discovery-mailbox-id-v1";
const DISCOVERY_MAILBOX_AUTH_DOMAIN: &str = "unchained-discovery-mailbox-auth-v1";
const DISCOVERY_RESPONSE_AUTH_DOMAIN: &str = "unchained-discovery-response-auth-v1";
const DISCOVERY_MAILBOX_KEY_DOMAIN: &str = "unchained-discovery-mailbox-key-v1";
const DISCOVERY_HYBRID_KEY_DOMAIN: &str = "unchained-discovery-hybrid-key-v1";
const DISCOVERY_MESSAGE_AEAD_DOMAIN: &str = "unchained-discovery-message-aead-v1";
const DISCOVERY_MANIFEST_ID_DOMAIN: &str = "unchained-discovery-manifest-id-v1";
const DISCOVERY_STORE_DIR: &str = "discovery_service";
const DISCOVERY_RECORD_BYTES: usize = 8192;
const DISCOVERY_REQUEST_PLAINTEXT_BYTES: usize = 2048;
const DISCOVERY_RESPONSE_PLAINTEXT_BYTES: usize = 8192;
const DISCOVERY_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const DISCOVERY_CONNECTION_WINDOW_BYTES: u32 = 64 * 1024 * 1024;
const DISCOVERY_SEND_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
const DISCOVERY_IDLE_TIMEOUT_SECS: u64 = 30;
const DISCOVERY_KEEP_ALIVE_SECS: u64 = 5;
const DISCOVERY_HEADER_BYTES: usize = 1 + 32 + 32 + ML_KEM_768_CT_BYTES + 24;
const DISCOVERY_CF_LOCATOR: &str = "locator_record";
const DISCOVERY_CF_MAILBOX_AUTH: &str = "mailbox_auth";
const DISCOVERY_CF_MAILBOX_REQUEST: &str = "mailbox_request";
const DISCOVERY_CF_RESPONSE_SLOT: &str = "response_slot";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiscoveryRecord {
    pub version: u8,
    pub chain_id: [u8; 32],
    pub locator_id: [u8; 32],
    pub owner_signing_pk: TaggedSigningPublicKey,
    pub mailbox_id: [u8; 32],
    pub mailbox_kem_pk: TaggedKemPublicKey,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryManifest {
    pub version: u8,
    pub chain_id: [u8; 32],
    pub server_node_id: [u8; 32],
    pub arity: u32,
    pub record_count: u64,
    pub record_bytes: u32,
    pub issued_unix_ms: u64,
    pub manifest_id: [u8; 32],
    pub seed_mu: [u8; SEED_BYTE_LEN],
    pub hint_bytes: Vec<u8>,
    pub filter_param_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRequestMessage {
    pub request_id: [u8; 32],
    pub response_slot_id: [u8; 32],
    pub envelope: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleRequestPlaintext {
    pub version: u8,
    pub chain_id: [u8; 32],
    pub locator_id: [u8; 32],
    pub request_id: [u8; 32],
    pub response_slot_id: [u8; 32],
    pub response_auth_token: [u8; 32],
    pub response_kem_pk: TaggedKemPublicKey,
    pub requested_amount: u64,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleResponsePlaintext {
    pub version: u8,
    pub chain_id: [u8; 32],
    pub locator_id: [u8; 32],
    pub request_id: [u8; 32],
    pub handle: RecipientHandle,
    pub issued_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DiscoveryPolicy {
    pub record_ttl: Duration,
    pub submit_timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_pending_requests: usize,
    pub max_pending_responses: usize,
    pub pir_arity: u32,
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        Self {
            record_ttl: Duration::from_secs(3600),
            submit_timeout: Duration::from_secs(10),
            max_request_bytes: 4 * 1024 * 1024,
            max_response_bytes: 32 * 1024 * 1024,
            max_pending_requests: 4096,
            max_pending_responses: 4096,
            pir_arity: 4,
        }
    }
}

#[derive(Clone)]
pub struct DiscoveryClient {
    endpoint: Arc<Endpoint>,
    server_record: NodeRecordV2,
    submit_timeout: Duration,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

pub struct DiscoveryServer {
    endpoint: Endpoint,
    ingress_keys: IngressKeyMaterial,
    server_node_id: [u8; 32],
    chain_id: [u8; 32],
    policy: DiscoveryPolicy,
    store: Arc<DiscoveryStateStore>,
    index: Arc<RwLock<DiscoveryIndexState>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LocatorRegistration {
    record: DiscoveryRecord,
    mailbox_auth_hash: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredMailboxMessage {
    response_slot_id: [u8; 32],
    response_slot_auth_hash: [u8; 32],
    envelope: Vec<u8>,
    created_unix_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredResponseSlot {
    auth_hash: [u8; 32],
    envelope: Option<Vec<u8>>,
    created_unix_ms: u64,
}

#[derive(Clone)]
struct DiscoveryIndexState {
    manifest: DiscoveryManifest,
    server: Option<PirServer>,
}

struct DiscoveryStateStore {
    db: DB,
    path: PathBuf,
}

enum DiscoveryRequest {
    FetchManifest {
        request_id: [u8; 32],
    },
    PublishRecord {
        request_id: [u8; 32],
        record: Vec<u8>,
        mailbox_auth_token: [u8; 32],
    },
    PirQuery {
        request_id: [u8; 32],
        manifest_id: [u8; 32],
        query: Vec<u8>,
    },
    PostMailboxRequest {
        request_id: [u8; 32],
        mailbox_id: [u8; 32],
        response_slot_id: [u8; 32],
        response_slot_auth_hash: [u8; 32],
        envelope: Vec<u8>,
    },
    PollMailbox {
        request_id: [u8; 32],
        mailbox_id: [u8; 32],
        auth_token: [u8; 32],
        max_messages: u32,
    },
    PostHandleResponse {
        request_id: [u8; 32],
        response_slot_id: [u8; 32],
        auth_token: [u8; 32],
        envelope: Vec<u8>,
    },
    PollHandleResponse {
        request_id: [u8; 32],
        response_slot_id: [u8; 32],
        auth_token: [u8; 32],
    },
}

enum DiscoveryResponse {
    Manifest {
        request_id: [u8; 32],
        manifest: Vec<u8>,
    },
    Published {
        request_id: [u8; 32],
    },
    Pir {
        request_id: [u8; 32],
        response: Vec<u8>,
    },
    MailboxMessages {
        request_id: [u8; 32],
        messages: Vec<MailboxRequestMessage>,
    },
    Posted {
        request_id: [u8; 32],
    },
    HandleResponse {
        request_id: [u8; 32],
        envelope: Option<Vec<u8>>,
    },
    Error {
        request_id: [u8; 32],
        message: String,
    },
}

impl DiscoveryRecord {
    pub fn validate(
        &self,
        expected_locator_id: &[u8; 32],
        expected_chain_id: &[u8; 32],
    ) -> Result<()> {
        if self.version != DISCOVERY_RECORD_VERSION {
            bail!("unsupported discovery record version {}", self.version);
        }
        if &self.chain_id != expected_chain_id {
            bail!("discovery record chain_id mismatch");
        }
        if &self.locator_id != expected_locator_id {
            bail!("discovery record locator_id mismatch");
        }
        if self.expires_unix_ms <= self.issued_unix_ms {
            bail!("discovery record expiration must be after issuance");
        }
        if now_unix_ms() >= self.expires_unix_ms {
            bail!("discovery record has expired");
        }
        let derived = locator_id_from_signing_pk(&self.owner_signing_pk);
        if derived != self.locator_id {
            bail!("discovery record owner key does not match locator");
        }
        let signable = encode_discovery_record_signable(
            &self.chain_id,
            &self.locator_id,
            &self.owner_signing_pk,
            &self.mailbox_id,
            &self.mailbox_kem_pk,
            self.issued_unix_ms,
            self.expires_unix_ms,
        )?;
        self.owner_signing_pk.verify(&signable, &self.sig)?;
        Ok(())
    }
}

impl DiscoveryClient {
    pub fn new(
        server_record: NodeRecordV2,
        max_request_bytes: usize,
        max_response_bytes: usize,
        submit_timeout: Duration,
    ) -> Result<Self> {
        let chain_id = server_record
            .chain_id
            .ok_or_else(|| anyhow!("discovery node record must be bound to a chain"))?;
        let _ = chain_id;
        let expected = ExpectedPeerStore::new();
        expected.remember(&server_record);
        let rustls_client = build_client_config_with_alpn(None, expected, DISCOVERY_ALPN)?;
        let transport_config = discovery_transport_config()?;
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
            .ok_or_else(|| anyhow!("discovery node record must be bound to a chain"))
    }

    pub async fn fetch_manifest(&self) -> Result<DiscoveryManifest> {
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::FetchManifest { request_id })
            .await?;
        match response {
            DiscoveryResponse::Manifest {
                request_id: echoed_request_id,
                manifest,
            } => {
                ensure_request_id("discovery manifest", request_id, echoed_request_id)?;
                decode_manifest(&manifest)
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id("discovery manifest", request_id, echoed_request_id)?;
                bail!("discovery manifest fetch failed: {message}");
            }
            other => bail!(
                "unexpected discovery manifest response: {}",
                response_tag(&other)
            ),
        }
    }

    pub async fn publish_record(
        &self,
        record: &DiscoveryRecord,
        mailbox_auth_token: &[u8; 32],
    ) -> Result<()> {
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::PublishRecord {
                request_id,
                record: encode_discovery_record(record)?,
                mailbox_auth_token: *mailbox_auth_token,
            })
            .await?;
        match response {
            DiscoveryResponse::Published {
                request_id: echoed_request_id,
            }
            | DiscoveryResponse::Posted {
                request_id: echoed_request_id,
            } => {
                ensure_request_id("discovery publish", request_id, echoed_request_id)?;
                Ok(())
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id("discovery publish", request_id, echoed_request_id)?;
                bail!("discovery publish failed: {message}");
            }
            other => bail!(
                "unexpected discovery publish response: {}",
                response_tag(&other)
            ),
        }
    }

    pub async fn resolve_locator(&self, locator: &str) -> Result<DiscoveryRecord> {
        let locator_id = parse_locator(locator)?;
        let manifest = self.fetch_manifest().await?;
        if manifest.record_count == 0 {
            bail!("locator not found");
        }
        let mut client = PirClient::setup(
            &manifest.seed_mu,
            &manifest.hint_bytes,
            &manifest.filter_param_bytes,
        )
        .map_err(|err| anyhow!("failed to initialize discovery PIR client: {err:?}"))?;
        let query = client
            .query(&locator_id)
            .map_err(|err| anyhow!("failed to build discovery PIR query: {err:?}"))?;
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::PirQuery {
                request_id,
                manifest_id: manifest.manifest_id,
                query,
            })
            .await?;
        let response_bytes = match response {
            DiscoveryResponse::Pir {
                request_id: echoed_request_id,
                response,
            } => {
                ensure_request_id("discovery query", request_id, echoed_request_id)?;
                response
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id("discovery query", request_id, echoed_request_id)?;
                bail!("discovery query failed: {message}");
            }
            other => bail!(
                "unexpected discovery query response: {}",
                response_tag(&other)
            ),
        };
        let encoded_record = client
            .process_response(&locator_id, &response_bytes)
            .map_err(|_| anyhow!("locator not found"))?;
        let record = decode_pir_record(&encoded_record)?;
        record.validate(&locator_id, &manifest.chain_id)?;
        Ok(record)
    }

    pub async fn post_mailbox_request(
        &self,
        mailbox_id: [u8; 32],
        response_slot_id: [u8; 32],
        response_slot_auth_token: [u8; 32],
        envelope: Vec<u8>,
    ) -> Result<[u8; 32]> {
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::PostMailboxRequest {
                request_id,
                mailbox_id,
                response_slot_id,
                response_slot_auth_hash: response_auth_hash(&response_slot_auth_token),
                envelope,
            })
            .await?;
        match response {
            DiscoveryResponse::Posted {
                request_id: echoed_request_id,
            } => {
                ensure_request_id(
                    "discovery post mailbox request",
                    request_id,
                    echoed_request_id,
                )?;
                Ok(request_id)
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id(
                    "discovery post mailbox request",
                    request_id,
                    echoed_request_id,
                )?;
                bail!("discovery mailbox post failed: {message}");
            }
            other => bail!(
                "unexpected discovery mailbox-post response: {}",
                response_tag(&other)
            ),
        }
    }

    pub async fn poll_mailbox(
        &self,
        mailbox_id: [u8; 32],
        auth_token: [u8; 32],
        max_messages: u32,
    ) -> Result<Vec<MailboxRequestMessage>> {
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::PollMailbox {
                request_id,
                mailbox_id,
                auth_token,
                max_messages,
            })
            .await?;
        match response {
            DiscoveryResponse::MailboxMessages {
                request_id: echoed_request_id,
                messages,
            } => {
                ensure_request_id("discovery poll mailbox", request_id, echoed_request_id)?;
                Ok(messages)
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id("discovery poll mailbox", request_id, echoed_request_id)?;
                bail!("discovery mailbox poll failed: {message}");
            }
            other => bail!(
                "unexpected discovery mailbox-poll response: {}",
                response_tag(&other)
            ),
        }
    }

    pub async fn post_handle_response(
        &self,
        response_slot_id: [u8; 32],
        auth_token: [u8; 32],
        envelope: Vec<u8>,
    ) -> Result<()> {
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::PostHandleResponse {
                request_id,
                response_slot_id,
                auth_token,
                envelope,
            })
            .await?;
        match response {
            DiscoveryResponse::Posted {
                request_id: echoed_request_id,
            } => {
                ensure_request_id(
                    "discovery post handle response",
                    request_id,
                    echoed_request_id,
                )?;
                Ok(())
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id(
                    "discovery post handle response",
                    request_id,
                    echoed_request_id,
                )?;
                bail!("discovery handle response post failed: {message}");
            }
            other => bail!(
                "unexpected discovery handle-response response: {}",
                response_tag(&other)
            ),
        }
    }

    pub async fn poll_handle_response(
        &self,
        response_slot_id: [u8; 32],
        auth_token: [u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let request_id = random_request_id();
        let response = self
            .exchange_request(DiscoveryRequest::PollHandleResponse {
                request_id,
                response_slot_id,
                auth_token,
            })
            .await?;
        match response {
            DiscoveryResponse::HandleResponse {
                request_id: echoed_request_id,
                envelope,
            } => {
                ensure_request_id(
                    "discovery poll handle response",
                    request_id,
                    echoed_request_id,
                )?;
                Ok(envelope)
            }
            DiscoveryResponse::Error {
                request_id: echoed_request_id,
                message,
            } => {
                ensure_request_id(
                    "discovery poll handle response",
                    request_id,
                    echoed_request_id,
                )?;
                bail!("discovery handle response poll failed: {message}");
            }
            other => bail!(
                "unexpected discovery handle-response poll response: {}",
                response_tag(&other)
            ),
        }
    }

    async fn exchange_request(&self, request: DiscoveryRequest) -> Result<DiscoveryResponse> {
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
        .context("discovery dial timed out")??;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("discovery failed to open stream")?;
        send.write_all(&envelope)
            .await
            .context("discovery failed to write request envelope")?;
        send.finish()
            .context("discovery failed to finish request stream")?;
        let response_bytes = recv
            .read_to_end(self.max_response_bytes)
            .await
            .context("discovery failed while waiting for response")?;
        decode_response(&response_bytes)
    }
}

impl Drop for DiscoveryClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.endpoint) == 1 {
            self.endpoint.close(0u32.into(), b"shutdown");
        }
    }
}

impl DiscoveryServer {
    pub fn bind(
        identity: &NodeIdentity,
        listen_addr: std::net::SocketAddr,
        state_path: &str,
        policy: DiscoveryPolicy,
    ) -> Result<Self> {
        let chain_id = identity
            .record()
            .chain_id
            .ok_or_else(|| anyhow!("discovery server node record must be bound to a chain"))?;
        let rustls_server = build_server_config_with_alpn(identity, DISCOVERY_ALPN, false)?;
        let transport_config = discovery_transport_config()?;
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_server)?));
        server_config.transport_config(transport_config);
        let endpoint = Endpoint::server(server_config, listen_addr)?;
        let store = Arc::new(DiscoveryStateStore::open(state_path)?);
        let index = Arc::new(RwLock::new(DiscoveryIndexState::empty(chain_id)?));
        let server = Self {
            endpoint,
            ingress_keys: load_local_ingress_key_material_in_dir(identity.dir())?,
            server_node_id: identity.node_id(),
            chain_id,
            policy,
            store,
            index,
        };
        server.refresh_index()?;
        Ok(server)
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
                            eprintln!("discovery connection failed: {err}");
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
            .context("discovery handshake timed out")??;
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::TimedOut) => break,
                Err(err) => return Err(err.into()),
            };
            let envelope = recv
                .read_to_end(self.policy.max_request_bytes + DISCOVERY_HEADER_BYTES + 16)
                .await
                .context("discovery failed while reading request envelope")?;
            let request =
                open_request_from_envelope(&envelope, &self.ingress_keys, self.server_node_id)?;
            let response = self.handle_request(request)?;
            send.write_all(&encode_response(&response)?)
                .await
                .context("discovery failed to write response")?;
            send.finish()
                .context("discovery failed to finish response stream")?;
        }
        Ok(())
    }

    fn handle_request(&self, request: DiscoveryRequest) -> Result<DiscoveryResponse> {
        let request_id = request.request_id();
        let result: Result<DiscoveryResponse> = match request {
            DiscoveryRequest::FetchManifest { request_id } => {
                let manifest = self
                    .index
                    .read()
                    .map_err(|_| anyhow!("discovery index lock poisoned"))?
                    .manifest
                    .clone();
                Ok(DiscoveryResponse::Manifest {
                    request_id,
                    manifest: encode_manifest(&manifest)?,
                })
            }
            DiscoveryRequest::PublishRecord {
                request_id,
                record,
                mailbox_auth_token,
            } => {
                let record = decode_discovery_record(&record)?;
                record.validate(&record.locator_id, &self.chain_id)?;
                let registration = LocatorRegistration {
                    record: record.clone(),
                    mailbox_auth_hash: mailbox_auth_hash(&mailbox_auth_token),
                };
                self.store.put_registration(&registration)?;
                self.store
                    .put_mailbox_auth(&record.mailbox_id, &registration.mailbox_auth_hash)?;
                self.refresh_index()?;
                Ok(DiscoveryResponse::Published { request_id })
            }
            DiscoveryRequest::PirQuery {
                request_id,
                manifest_id,
                query,
            } => {
                let guard = self
                    .index
                    .read()
                    .map_err(|_| anyhow!("discovery index lock poisoned"))?;
                if guard.manifest.manifest_id != manifest_id {
                    bail!("discovery manifest changed; refetch and retry");
                }
                let server = guard
                    .server
                    .as_ref()
                    .ok_or_else(|| anyhow!("locator not found"))?;
                let response = server
                    .respond(&query)
                    .map_err(|err| anyhow!("failed to answer discovery PIR query: {err:?}"))?;
                Ok(DiscoveryResponse::Pir {
                    request_id,
                    response,
                })
            }
            DiscoveryRequest::PostMailboxRequest {
                request_id,
                mailbox_id,
                response_slot_id,
                response_slot_auth_hash,
                envelope,
            } => {
                self.ensure_mailbox_exists(&mailbox_id)?;
                self.ensure_pending_request_capacity()?;
                self.ensure_response_slot_capacity()?;
                let message_key = mailbox_request_key(&mailbox_id, &request_id);
                let message = StoredMailboxMessage {
                    response_slot_id,
                    response_slot_auth_hash,
                    envelope,
                    created_unix_ms: now_unix_ms(),
                };
                self.store.put_mailbox_request(&message_key, &message)?;
                if self.store.get_response_slot(&response_slot_id)?.is_none() {
                    self.store.put_response_slot(
                        &response_slot_id,
                        &StoredResponseSlot {
                            auth_hash: response_slot_auth_hash,
                            envelope: None,
                            created_unix_ms: now_unix_ms(),
                        },
                    )?;
                }
                Ok(DiscoveryResponse::Posted { request_id })
            }
            DiscoveryRequest::PollMailbox {
                request_id,
                mailbox_id,
                auth_token,
                max_messages,
            } => {
                self.verify_mailbox_auth(&mailbox_id, &auth_token)?;
                let mut messages = Vec::new();
                for (key, request_id_bytes, message) in self
                    .store
                    .take_mailbox_requests(&mailbox_id, max_messages as usize)?
                {
                    messages.push(MailboxRequestMessage {
                        request_id: request_id_bytes,
                        response_slot_id: message.response_slot_id,
                        envelope: message.envelope,
                    });
                    self.store.delete_mailbox_request(&key)?;
                }
                Ok(DiscoveryResponse::MailboxMessages {
                    request_id,
                    messages,
                })
            }
            DiscoveryRequest::PostHandleResponse {
                request_id,
                response_slot_id,
                auth_token,
                envelope,
            } => {
                let mut slot = self
                    .store
                    .get_response_slot(&response_slot_id)?
                    .ok_or_else(|| anyhow!("unknown response slot"))?;
                let auth_hash = response_auth_hash(&auth_token);
                if slot.auth_hash != auth_hash {
                    bail!("invalid response slot auth token");
                }
                slot.envelope = Some(envelope);
                self.store.put_response_slot(&response_slot_id, &slot)?;
                Ok(DiscoveryResponse::Posted { request_id })
            }
            DiscoveryRequest::PollHandleResponse {
                request_id,
                response_slot_id,
                auth_token,
            } => {
                let slot = self
                    .store
                    .get_response_slot(&response_slot_id)?
                    .ok_or_else(|| anyhow!("unknown response slot"))?;
                let auth_hash = response_auth_hash(&auth_token);
                if slot.auth_hash != auth_hash {
                    bail!("invalid response slot auth token");
                }
                let envelope = slot.envelope.clone();
                if envelope.is_some() {
                    self.store.delete_response_slot(&response_slot_id)?;
                }
                Ok(DiscoveryResponse::HandleResponse {
                    request_id,
                    envelope,
                })
            }
        };
        match result {
            Ok(response) => Ok(response),
            Err(err) => Ok(DiscoveryResponse::Error {
                request_id,
                message: err.to_string(),
            }),
        }
    }

    fn ensure_mailbox_exists(&self, mailbox_id: &[u8; 32]) -> Result<()> {
        if self.store.get_mailbox_auth(mailbox_id)?.is_none() {
            bail!("unknown mailbox");
        }
        Ok(())
    }

    fn ensure_pending_request_capacity(&self) -> Result<()> {
        let count = self.store.count_cf(DISCOVERY_CF_MAILBOX_REQUEST)?;
        if count >= self.policy.max_pending_requests {
            bail!("discovery mailbox request queue is full");
        }
        Ok(())
    }

    fn ensure_response_slot_capacity(&self) -> Result<()> {
        let count = self.store.count_cf(DISCOVERY_CF_RESPONSE_SLOT)?;
        if count >= self.policy.max_pending_responses {
            bail!("discovery response queue is full");
        }
        Ok(())
    }

    fn verify_mailbox_auth(&self, mailbox_id: &[u8; 32], auth_token: &[u8; 32]) -> Result<()> {
        let Some(expected_hash) = self.store.get_mailbox_auth(mailbox_id)? else {
            bail!("unknown mailbox");
        };
        if expected_hash != mailbox_auth_hash(auth_token) {
            bail!("invalid mailbox auth token");
        }
        Ok(())
    }

    fn refresh_index(&self) -> Result<()> {
        let records = self.store.list_active_registrations(self.chain_id)?;
        let next_state = DiscoveryIndexState::build(
            self.chain_id,
            self.server_node_id,
            self.policy.pir_arity,
            &records,
        )?;
        *self
            .index
            .write()
            .map_err(|_| anyhow!("discovery index lock poisoned"))? = next_state;
        Ok(())
    }
}

impl DiscoveryIndexState {
    fn empty(chain_id: [u8; 32]) -> Result<Self> {
        let manifest = build_manifest(
            chain_id,
            [0u8; 32],
            4,
            0,
            [0u8; SEED_BYTE_LEN],
            Vec::new(),
            Vec::new(),
        )?;
        Ok(Self {
            manifest,
            server: None,
        })
    }

    fn build(
        chain_id: [u8; 32],
        server_node_id: [u8; 32],
        arity: u32,
        registrations: &[LocatorRegistration],
    ) -> Result<Self> {
        if registrations.is_empty() {
            let manifest = build_manifest(
                chain_id,
                server_node_id,
                arity,
                0,
                [0u8; SEED_BYTE_LEN],
                Vec::new(),
                Vec::new(),
            )?;
            return Ok(Self {
                manifest,
                server: None,
            });
        }
        let mut seed_mu = [0u8; SEED_BYTE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed_mu);
        let encoded_entries = registrations
            .iter()
            .map(|registration| {
                Ok((
                    registration.record.locator_id.to_vec(),
                    encode_pir_record(&registration.record)?,
                ))
            })
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>>>()?;
        let refs = encoded_entries
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect::<HashMap<&[u8], &[u8]>>();
        let (server, hint_bytes, filter_param_bytes) = match arity {
            3 => PirServer::setup::<3>(&seed_mu, refs),
            4 => PirServer::setup::<4>(&seed_mu, refs),
            other => bail!("unsupported discovery PIR arity {other}"),
        }
        .map_err(|err| anyhow!("failed to build discovery PIR index: {err:?}"))?;
        let manifest = build_manifest(
            chain_id,
            server_node_id,
            arity,
            registrations.len() as u64,
            seed_mu,
            hint_bytes,
            filter_param_bytes,
        )?;
        Ok(Self {
            manifest,
            server: Some(server),
        })
    }
}

impl DiscoveryStateStore {
    fn open(path: &str) -> Result<Self> {
        let path = PathBuf::from(path);
        std::fs::create_dir_all(&path)?;
        let cf_names = [
            "default",
            DISCOVERY_CF_LOCATOR,
            DISCOVERY_CF_MAILBOX_AUTH,
            DISCOVERY_CF_MAILBOX_REQUEST,
            DISCOVERY_CF_RESPONSE_SLOT,
        ];
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let mut cf_descriptors = Vec::new();
        for name in cf_names {
            let mut opts = Options::default();
            opts.set_write_buffer_size(64 * 1024 * 1024);
            if name == DISCOVERY_CF_MAILBOX_REQUEST {
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                opts.set_optimize_filters_for_hits(true);
            }
            cf_descriptors.push(ColumnFamilyDescriptor::new(name, opts));
        }
        let db = DB::open_cf_descriptors(&db_opts, &path, cf_descriptors).with_context(|| {
            format!(
                "failed to open discovery state database at {}",
                path.display()
            )
        })?;
        Ok(Self { db, path })
    }

    fn put_registration(&self, registration: &LocatorRegistration) -> Result<()> {
        self.put(
            DISCOVERY_CF_LOCATOR,
            &registration.record.locator_id,
            registration,
        )
    }

    fn put_mailbox_auth(&self, mailbox_id: &[u8; 32], auth_hash: &[u8; 32]) -> Result<()> {
        self.put(DISCOVERY_CF_MAILBOX_AUTH, mailbox_id, auth_hash)
    }

    fn get_mailbox_auth(&self, mailbox_id: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        self.get(DISCOVERY_CF_MAILBOX_AUTH, mailbox_id)
    }

    fn put_mailbox_request(&self, key: &[u8], message: &StoredMailboxMessage) -> Result<()> {
        self.put(DISCOVERY_CF_MAILBOX_REQUEST, key, message)
    }

    fn delete_mailbox_request(&self, key: &[u8]) -> Result<()> {
        self.delete(DISCOVERY_CF_MAILBOX_REQUEST, key)
    }

    fn put_response_slot(
        &self,
        response_slot_id: &[u8; 32],
        slot: &StoredResponseSlot,
    ) -> Result<()> {
        self.put(DISCOVERY_CF_RESPONSE_SLOT, response_slot_id, slot)
    }

    fn get_response_slot(&self, response_slot_id: &[u8; 32]) -> Result<Option<StoredResponseSlot>> {
        self.get(DISCOVERY_CF_RESPONSE_SLOT, response_slot_id)
    }

    fn delete_response_slot(&self, response_slot_id: &[u8; 32]) -> Result<()> {
        self.delete(DISCOVERY_CF_RESPONSE_SLOT, response_slot_id)
    }

    fn list_active_registrations(&self, chain_id: [u8; 32]) -> Result<Vec<LocatorRegistration>> {
        let now = now_unix_ms();
        let cf = self
            .db
            .cf_handle(DISCOVERY_CF_LOCATOR)
            .ok_or_else(|| anyhow!("missing discovery locator CF"))?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        let mut registrations = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            let registration: LocatorRegistration = bincode::deserialize(&value)?;
            if registration.record.chain_id != chain_id {
                continue;
            }
            if registration.record.expires_unix_ms <= now {
                continue;
            }
            registrations.push(registration);
        }
        Ok(registrations)
    }

    fn take_mailbox_requests(
        &self,
        mailbox_id: &[u8; 32],
        max_messages: usize,
    ) -> Result<Vec<(Vec<u8>, [u8; 32], StoredMailboxMessage)>> {
        if max_messages == 0 {
            return Ok(Vec::new());
        }
        let cf = self
            .db
            .cf_handle(DISCOVERY_CF_MAILBOX_REQUEST)
            .ok_or_else(|| anyhow!("missing discovery mailbox-request CF"))?;
        let iter = self.db.iterator_cf(
            cf,
            IteratorMode::From(mailbox_id, rocksdb::Direction::Forward),
        );
        let mut out = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if key.len() < 64 || &key[..32] != mailbox_id {
                break;
            }
            let mut request_id = [0u8; 32];
            request_id.copy_from_slice(&key[32..64]);
            let message: StoredMailboxMessage = bincode::deserialize(&value)?;
            out.push((key.to_vec(), request_id, message));
            if out.len() >= max_messages {
                break;
            }
        }
        Ok(out)
    }

    fn count_cf(&self, cf_name: &str) -> Result<usize> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow!("missing discovery column family '{cf_name}'"))?;
        Ok(self.db.iterator_cf(cf, IteratorMode::Start).count())
    }

    fn put<T: serde::Serialize>(&self, cf_name: &str, key: &[u8], value: &T) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow!("missing discovery column family '{cf_name}'"))?;
        let encoded = bincode::serialize(value)?;
        self.db.put_cf(cf, key, encoded)?;
        Ok(())
    }

    fn get<T: serde::de::DeserializeOwned>(&self, cf_name: &str, key: &[u8]) -> Result<Option<T>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow!("missing discovery column family '{cf_name}'"))?;
        match self.db.get_cf(cf, key)? {
            Some(value) => Ok(Some(bincode::deserialize(&value)?)),
            None => Ok(None),
        }
    }

    fn delete(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow!("missing discovery column family '{cf_name}'"))?;
        self.db.delete_cf(cf, key)?;
        Ok(())
    }
}

impl Drop for DiscoveryStateStore {
    fn drop(&mut self) {
        let _ = &self.path;
    }
}

impl DiscoveryRequest {
    fn request_id(&self) -> [u8; 32] {
        match self {
            DiscoveryRequest::FetchManifest { request_id }
            | DiscoveryRequest::PublishRecord { request_id, .. }
            | DiscoveryRequest::PirQuery { request_id, .. }
            | DiscoveryRequest::PostMailboxRequest { request_id, .. }
            | DiscoveryRequest::PollMailbox { request_id, .. }
            | DiscoveryRequest::PostHandleResponse { request_id, .. }
            | DiscoveryRequest::PollHandleResponse { request_id, .. } => *request_id,
        }
    }
}

pub fn discovery_state_path(base_path: &str, configured: Option<&str>) -> String {
    configured
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            Path::new(base_path)
                .join(DISCOVERY_STORE_DIR)
                .to_string_lossy()
                .into_owned()
        })
}

pub fn locator_id_from_signing_pk(pk: &TaggedSigningPublicKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_LOCATOR_DOMAIN);
    hasher.update(pk.as_slice());
    *hasher.finalize().as_bytes()
}

pub fn locator_from_signing_pk(pk: &TaggedSigningPublicKey) -> String {
    format_locator(&locator_id_from_signing_pk(pk))
}

pub fn format_locator(locator_id: &[u8; 32]) -> String {
    format!("{DISCOVERY_LOCATOR_PREFIX}{}", hex::encode(locator_id))
}

pub fn parse_locator(locator: &str) -> Result<[u8; 32]> {
    let trimmed = locator.trim();
    let raw = trimmed
        .strip_prefix(DISCOVERY_LOCATOR_PREFIX)
        .ok_or_else(|| anyhow!("locator must start with {DISCOVERY_LOCATOR_PREFIX}"))?;
    let decoded = hex::decode(raw)?;
    if decoded.len() != 32 {
        bail!("locator must encode exactly 32 bytes");
    }
    let mut locator_id = [0u8; 32];
    locator_id.copy_from_slice(&decoded);
    Ok(locator_id)
}

pub fn mailbox_id_for_locator(chain_id: &[u8; 32], locator_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_MAILBOX_ID_DOMAIN);
    hasher.update(chain_id);
    hasher.update(locator_id);
    *hasher.finalize().as_bytes()
}

pub fn mailbox_auth_token(
    lock_seed: &[u8; 32],
    chain_id: &[u8; 32],
    locator_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_MAILBOX_AUTH_DOMAIN);
    hasher.update(lock_seed);
    hasher.update(chain_id);
    hasher.update(locator_id);
    *hasher.finalize().as_bytes()
}

pub fn response_slot_auth_token() -> [u8; 32] {
    random_request_id()
}

pub fn derive_mailbox_kem_keypair(
    lock_seed: &[u8; 32],
    address: &[u8; 32],
    chain_id: &[u8; 32],
) -> ([u8; ML_KEM_768_SK_BYTES], TaggedKemPublicKey) {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_MAILBOX_KEY_DOMAIN);
    hasher.update(lock_seed);
    hasher.update(address);
    hasher.update(chain_id);
    let mut xof = hasher.finalize_xof();
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    xof.fill(&mut d);
    xof.fill(&mut z);
    let (sk, pk) = crypto::ml_kem_768_generate_deterministic(&d, &z);
    (crypto::ml_kem_768_secret_key_to_bytes(&sk), pk)
}

pub fn build_signed_discovery_record(
    signing_key_pkcs8: &[u8],
    signing_pk: &TaggedSigningPublicKey,
    chain_id: [u8; 32],
    mailbox_kem_pk: TaggedKemPublicKey,
    record_ttl: Duration,
) -> Result<(String, [u8; 32], [u8; 32], DiscoveryRecord)> {
    let locator_id = locator_id_from_signing_pk(signing_pk);
    let locator = format_locator(&locator_id);
    let mailbox_id = mailbox_id_for_locator(&chain_id, &locator_id);
    let signing_key = crypto::ml_dsa_65_keypair_from_pkcs8(signing_key_pkcs8)?;
    let issued_unix_ms = now_unix_ms();
    let expires_unix_ms = issued_unix_ms.saturating_add(record_ttl.as_millis() as u64);
    let signable = encode_discovery_record_signable(
        &chain_id,
        &locator_id,
        signing_pk,
        &mailbox_id,
        &mailbox_kem_pk,
        issued_unix_ms,
        expires_unix_ms,
    )?;
    let sig = crypto::ml_dsa_65_sign(&signing_key, &signable)?;
    Ok((
        locator,
        locator_id,
        mailbox_id,
        DiscoveryRecord {
            version: DISCOVERY_RECORD_VERSION,
            chain_id,
            locator_id,
            owner_signing_pk: signing_pk.clone(),
            mailbox_id,
            mailbox_kem_pk,
            issued_unix_ms,
            expires_unix_ms,
            sig,
        },
    ))
}

pub fn encode_handle_request_plaintext(request: &HandleRequestPlaintext) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(request.version);
    writer.write_fixed(&request.chain_id);
    writer.write_fixed(&request.locator_id);
    writer.write_fixed(&request.request_id);
    writer.write_fixed(&request.response_slot_id);
    writer.write_fixed(&request.response_auth_token);
    write_tagged_kem_public_key(&mut writer, &request.response_kem_pk);
    writer.write_u64(request.requested_amount);
    writer.write_u64(request.issued_unix_ms);
    writer.write_u64(request.expires_unix_ms);
    Ok(writer.into_vec())
}

pub fn decode_handle_request_plaintext(bytes: &[u8]) -> Result<HandleRequestPlaintext> {
    let mut reader = CanonicalReader::new(bytes);
    let request = HandleRequestPlaintext {
        version: reader.read_u8()?,
        chain_id: reader.read_fixed()?,
        locator_id: reader.read_fixed()?,
        request_id: reader.read_fixed()?,
        response_slot_id: reader.read_fixed()?,
        response_auth_token: reader.read_fixed()?,
        response_kem_pk: read_tagged_kem_public_key(&mut reader)?,
        requested_amount: reader.read_u64()?,
        issued_unix_ms: reader.read_u64()?,
        expires_unix_ms: reader.read_u64()?,
    };
    reader.finish()?;
    if request.version != DISCOVERY_MAILBOX_REQUEST_VERSION {
        bail!(
            "unsupported discovery mailbox request version {}",
            request.version
        );
    }
    Ok(request)
}

pub fn encode_handle_response_plaintext(response: &HandleResponsePlaintext) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(response.version);
    writer.write_fixed(&response.chain_id);
    writer.write_fixed(&response.locator_id);
    writer.write_fixed(&response.request_id);
    writer.write_bytes(&encode_recipient_handle(&response.handle)?)?;
    writer.write_u64(response.issued_unix_ms);
    Ok(writer.into_vec())
}

pub fn decode_handle_response_plaintext(bytes: &[u8]) -> Result<HandleResponsePlaintext> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    let chain_id = reader.read_fixed()?;
    let locator_id = reader.read_fixed()?;
    let request_id = reader.read_fixed()?;
    let handle_bytes = reader.read_bytes()?;
    let issued_unix_ms = reader.read_u64()?;
    reader.finish()?;
    if version != DISCOVERY_MAILBOX_RESPONSE_VERSION {
        bail!("unsupported discovery mailbox response version {}", version);
    }
    Ok(HandleResponsePlaintext {
        version,
        chain_id,
        locator_id,
        request_id,
        handle: decode_recipient_handle(&handle_bytes)?,
        issued_unix_ms,
    })
}

pub fn seal_handle_request(
    request: &HandleRequestPlaintext,
    mailbox_kem_pk: &TaggedKemPublicKey,
) -> Result<Vec<u8>> {
    seal_padded_message(
        DISCOVERY_MAILBOX_REQUEST_VERSION,
        &encode_handle_request_plaintext(request)?,
        mailbox_kem_pk,
        DISCOVERY_REQUEST_PLAINTEXT_BYTES,
    )
}

pub fn open_handle_request(
    envelope: &[u8],
    mailbox_kem_sk: &[u8; ML_KEM_768_SK_BYTES],
) -> Result<HandleRequestPlaintext> {
    let plaintext = open_padded_message(envelope, mailbox_kem_sk)?;
    decode_handle_request_plaintext(&plaintext)
}

pub fn seal_handle_response(
    response: &HandleResponsePlaintext,
    response_kem_pk: &TaggedKemPublicKey,
) -> Result<Vec<u8>> {
    seal_padded_message(
        DISCOVERY_MAILBOX_RESPONSE_VERSION,
        &encode_handle_response_plaintext(response)?,
        response_kem_pk,
        DISCOVERY_RESPONSE_PLAINTEXT_BYTES,
    )
}

pub fn open_handle_response(
    envelope: &[u8],
    response_kem_sk: &[u8; ML_KEM_768_SK_BYTES],
) -> Result<HandleResponsePlaintext> {
    let plaintext = open_padded_message(envelope, response_kem_sk)?;
    decode_handle_response_plaintext(&plaintext)
}

fn response_tag(response: &DiscoveryResponse) -> &'static str {
    match response {
        DiscoveryResponse::Manifest { .. } => "manifest",
        DiscoveryResponse::Published { .. } => "published",
        DiscoveryResponse::Pir { .. } => "pir",
        DiscoveryResponse::MailboxMessages { .. } => "mailbox_messages",
        DiscoveryResponse::Posted { .. } => "posted",
        DiscoveryResponse::HandleResponse { .. } => "handle_response",
        DiscoveryResponse::Error { .. } => "error",
    }
}

fn ensure_request_id(label: &str, expected: [u8; 32], actual: [u8; 32]) -> Result<()> {
    if expected != actual {
        bail!("{label} request_id mismatch");
    }
    Ok(())
}

fn build_manifest(
    chain_id: [u8; 32],
    server_node_id: [u8; 32],
    arity: u32,
    record_count: u64,
    seed_mu: [u8; SEED_BYTE_LEN],
    hint_bytes: Vec<u8>,
    filter_param_bytes: Vec<u8>,
) -> Result<DiscoveryManifest> {
    let issued_unix_ms = now_unix_ms();
    let mut manifest = DiscoveryManifest {
        version: DISCOVERY_MANIFEST_VERSION,
        chain_id,
        server_node_id,
        arity,
        record_count,
        record_bytes: DISCOVERY_RECORD_BYTES as u32,
        issued_unix_ms,
        manifest_id: [0u8; 32],
        seed_mu,
        hint_bytes,
        filter_param_bytes,
    };
    manifest.manifest_id = manifest_id(&manifest)?;
    Ok(manifest)
}

fn manifest_id(manifest: &DiscoveryManifest) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_MANIFEST_ID_DOMAIN);
    hasher.update(&encode_manifest_without_id(manifest)?);
    Ok(*hasher.finalize().as_bytes())
}

fn encode_manifest_without_id(manifest: &DiscoveryManifest) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(manifest.version);
    writer.write_fixed(&manifest.chain_id);
    writer.write_fixed(&manifest.server_node_id);
    writer.write_u32(manifest.arity);
    writer.write_u64(manifest.record_count);
    writer.write_u32(manifest.record_bytes);
    writer.write_u64(manifest.issued_unix_ms);
    writer.write_fixed(&manifest.seed_mu);
    writer.write_bytes(&manifest.hint_bytes)?;
    writer.write_bytes(&manifest.filter_param_bytes)?;
    Ok(writer.into_vec())
}

fn encode_manifest(manifest: &DiscoveryManifest) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(&encode_manifest_without_id(manifest)?)?;
    writer.write_fixed(&manifest.manifest_id);
    Ok(writer.into_vec())
}

fn decode_manifest(bytes: &[u8]) -> Result<DiscoveryManifest> {
    let mut reader = CanonicalReader::new(bytes);
    let body = reader.read_bytes()?;
    let decoded_manifest_id = reader.read_fixed()?;
    reader.finish()?;
    let mut body_reader = CanonicalReader::new(&body);
    let manifest = DiscoveryManifest {
        version: body_reader.read_u8()?,
        chain_id: body_reader.read_fixed()?,
        server_node_id: body_reader.read_fixed()?,
        arity: body_reader.read_u32()?,
        record_count: body_reader.read_u64()?,
        record_bytes: body_reader.read_u32()?,
        issued_unix_ms: body_reader.read_u64()?,
        manifest_id: decoded_manifest_id,
        seed_mu: body_reader.read_fixed()?,
        hint_bytes: body_reader.read_bytes()?,
        filter_param_bytes: body_reader.read_bytes()?,
    };
    body_reader.finish()?;
    if manifest.version != DISCOVERY_MANIFEST_VERSION {
        bail!(
            "unsupported discovery manifest version {}",
            manifest.version
        );
    }
    if manifest.manifest_id != manifest_id(&manifest)? {
        bail!("invalid discovery manifest id");
    }
    Ok(manifest)
}

fn encode_discovery_record_signable(
    chain_id: &[u8; 32],
    locator_id: &[u8; 32],
    owner_signing_pk: &TaggedSigningPublicKey,
    mailbox_id: &[u8; 32],
    mailbox_kem_pk: &TaggedKemPublicKey,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(DISCOVERY_RECORD_DOMAIN.as_bytes())?;
    writer.write_fixed(chain_id);
    writer.write_fixed(locator_id);
    write_tagged_signing_public_key(&mut writer, owner_signing_pk);
    writer.write_fixed(mailbox_id);
    write_tagged_kem_public_key(&mut writer, mailbox_kem_pk);
    writer.write_u64(issued_unix_ms);
    writer.write_u64(expires_unix_ms);
    Ok(writer.into_vec())
}

fn encode_discovery_record(record: &DiscoveryRecord) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(record.version);
    writer.write_fixed(&record.chain_id);
    writer.write_fixed(&record.locator_id);
    write_tagged_signing_public_key(&mut writer, &record.owner_signing_pk);
    writer.write_fixed(&record.mailbox_id);
    write_tagged_kem_public_key(&mut writer, &record.mailbox_kem_pk);
    writer.write_u64(record.issued_unix_ms);
    writer.write_u64(record.expires_unix_ms);
    writer.write_bytes(&record.sig)?;
    Ok(writer.into_vec())
}

fn decode_discovery_record(bytes: &[u8]) -> Result<DiscoveryRecord> {
    let mut reader = CanonicalReader::new(bytes);
    let record = DiscoveryRecord {
        version: reader.read_u8()?,
        chain_id: reader.read_fixed()?,
        locator_id: reader.read_fixed()?,
        owner_signing_pk: read_tagged_signing_public_key(&mut reader)?,
        mailbox_id: reader.read_fixed()?,
        mailbox_kem_pk: read_tagged_kem_public_key(&mut reader)?,
        issued_unix_ms: reader.read_u64()?,
        expires_unix_ms: reader.read_u64()?,
        sig: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(record)
}

fn encode_pir_record(record: &DiscoveryRecord) -> Result<Vec<u8>> {
    let raw = encode_discovery_record(record)?;
    if raw.len() + 4 > DISCOVERY_RECORD_BYTES {
        bail!(
            "discovery record exceeds fixed PIR row size ({} > {})",
            raw.len() + 4,
            DISCOVERY_RECORD_BYTES
        );
    }
    let mut out = vec![0u8; DISCOVERY_RECORD_BYTES];
    out[..4].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    out[4..4 + raw.len()].copy_from_slice(&raw);
    Ok(out)
}

fn decode_pir_record(bytes: &[u8]) -> Result<DiscoveryRecord> {
    if bytes.len() != DISCOVERY_RECORD_BYTES {
        bail!("invalid PIR record width");
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[..4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 || len > DISCOVERY_RECORD_BYTES - 4 {
        bail!("invalid PIR record length");
    }
    decode_discovery_record(&bytes[4..4 + len])
}

fn random_request_id() -> [u8; 32] {
    let mut request_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut request_id);
    request_id
}

fn seal_request_to_server(
    request: &DiscoveryRequest,
    server_record: &NodeRecordV2,
    max_request_bytes: usize,
) -> Result<Vec<u8>> {
    let plaintext = encode_request(request)?;
    if plaintext.len() > max_request_bytes {
        bail!("discovery request exceeds configured maximum size");
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
        .map_err(|_| anyhow!("failed to encrypt discovery request"))?;
    let mut envelope = Vec::with_capacity(DISCOVERY_HEADER_BYTES + ciphertext.len());
    envelope.push(DISCOVERY_ENVELOPE_VERSION);
    envelope.extend_from_slice(&server_record.node_id);
    envelope.extend_from_slice(x25519_public.as_bytes());
    envelope.extend_from_slice(&kem_ct);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_request_from_envelope(
    envelope: &[u8],
    ingress_keys: &IngressKeyMaterial,
    server_node_id: [u8; 32],
) -> Result<DiscoveryRequest> {
    if envelope.len() < DISCOVERY_HEADER_BYTES + 16 {
        bail!("discovery envelope is truncated");
    }
    if envelope.first().copied() != Some(DISCOVERY_ENVELOPE_VERSION) {
        bail!("unsupported discovery envelope version");
    }
    let mut target_node_id = [0u8; 32];
    target_node_id.copy_from_slice(&envelope[1..33]);
    if target_node_id != server_node_id {
        bail!("discovery envelope targets the wrong node identity");
    }
    let mut ephemeral_x25519_pk = [0u8; 32];
    ephemeral_x25519_pk.copy_from_slice(&envelope[33..65]);
    let mut kem_ct = [0u8; ML_KEM_768_CT_BYTES];
    kem_ct.copy_from_slice(&envelope[65..65 + ML_KEM_768_CT_BYTES]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[65 + ML_KEM_768_CT_BYTES..65 + ML_KEM_768_CT_BYTES + 24]);
    let ciphertext = &envelope[DISCOVERY_HEADER_BYTES..];
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
        .map_err(|_| anyhow!("failed to decrypt discovery envelope"))?;
    decode_request(&plaintext)
}

fn derive_hybrid_key(
    server_node_id: &[u8; 32],
    ephemeral_x25519_pk: &[u8; 32],
    x25519_shared: &[u8; 32],
    kem_shared: &[u8; 32],
    nonce: &[u8; 24],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_HYBRID_KEY_DOMAIN);
    hasher.update(server_node_id);
    hasher.update(ephemeral_x25519_pk);
    hasher.update(x25519_shared);
    hasher.update(kem_shared);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

fn encode_request(request: &DiscoveryRequest) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(DISCOVERY_REQUEST_VERSION);
    match request {
        DiscoveryRequest::FetchManifest { request_id } => {
            writer.write_u8(0);
            writer.write_fixed(request_id);
        }
        DiscoveryRequest::PublishRecord {
            request_id,
            record,
            mailbox_auth_token,
        } => {
            writer.write_u8(1);
            writer.write_fixed(request_id);
            writer.write_bytes(record)?;
            writer.write_fixed(mailbox_auth_token);
        }
        DiscoveryRequest::PirQuery {
            request_id,
            manifest_id,
            query,
        } => {
            writer.write_u8(2);
            writer.write_fixed(request_id);
            writer.write_fixed(manifest_id);
            writer.write_bytes(query)?;
        }
        DiscoveryRequest::PostMailboxRequest {
            request_id,
            mailbox_id,
            response_slot_id,
            response_slot_auth_hash,
            envelope,
        } => {
            writer.write_u8(3);
            writer.write_fixed(request_id);
            writer.write_fixed(mailbox_id);
            writer.write_fixed(response_slot_id);
            writer.write_fixed(response_slot_auth_hash);
            writer.write_bytes(envelope)?;
        }
        DiscoveryRequest::PollMailbox {
            request_id,
            mailbox_id,
            auth_token,
            max_messages,
        } => {
            writer.write_u8(4);
            writer.write_fixed(request_id);
            writer.write_fixed(mailbox_id);
            writer.write_fixed(auth_token);
            writer.write_u32(*max_messages);
        }
        DiscoveryRequest::PostHandleResponse {
            request_id,
            response_slot_id,
            auth_token,
            envelope,
        } => {
            writer.write_u8(5);
            writer.write_fixed(request_id);
            writer.write_fixed(response_slot_id);
            writer.write_fixed(auth_token);
            writer.write_bytes(envelope)?;
        }
        DiscoveryRequest::PollHandleResponse {
            request_id,
            response_slot_id,
            auth_token,
        } => {
            writer.write_u8(6);
            writer.write_fixed(request_id);
            writer.write_fixed(response_slot_id);
            writer.write_fixed(auth_token);
        }
    }
    Ok(writer.into_vec())
}

fn decode_request(bytes: &[u8]) -> Result<DiscoveryRequest> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != DISCOVERY_REQUEST_VERSION {
        bail!("unsupported discovery request version {}", version);
    }
    let request = match reader.read_u8()? {
        0 => DiscoveryRequest::FetchManifest {
            request_id: reader.read_fixed()?,
        },
        1 => DiscoveryRequest::PublishRecord {
            request_id: reader.read_fixed()?,
            record: reader.read_bytes()?,
            mailbox_auth_token: reader.read_fixed()?,
        },
        2 => DiscoveryRequest::PirQuery {
            request_id: reader.read_fixed()?,
            manifest_id: reader.read_fixed()?,
            query: reader.read_bytes()?,
        },
        3 => DiscoveryRequest::PostMailboxRequest {
            request_id: reader.read_fixed()?,
            mailbox_id: reader.read_fixed()?,
            response_slot_id: reader.read_fixed()?,
            response_slot_auth_hash: reader.read_fixed()?,
            envelope: reader.read_bytes()?,
        },
        4 => DiscoveryRequest::PollMailbox {
            request_id: reader.read_fixed()?,
            mailbox_id: reader.read_fixed()?,
            auth_token: reader.read_fixed()?,
            max_messages: reader.read_u32()?,
        },
        5 => DiscoveryRequest::PostHandleResponse {
            request_id: reader.read_fixed()?,
            response_slot_id: reader.read_fixed()?,
            auth_token: reader.read_fixed()?,
            envelope: reader.read_bytes()?,
        },
        6 => DiscoveryRequest::PollHandleResponse {
            request_id: reader.read_fixed()?,
            response_slot_id: reader.read_fixed()?,
            auth_token: reader.read_fixed()?,
        },
        other => bail!("unsupported discovery request tag {}", other),
    };
    reader.finish()?;
    Ok(request)
}

fn encode_response(response: &DiscoveryResponse) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(DISCOVERY_RESPONSE_VERSION);
    match response {
        DiscoveryResponse::Manifest {
            request_id,
            manifest,
        } => {
            writer.write_u8(0);
            writer.write_fixed(request_id);
            writer.write_bytes(manifest)?;
        }
        DiscoveryResponse::Published { request_id } => {
            writer.write_u8(1);
            writer.write_fixed(request_id);
        }
        DiscoveryResponse::Pir {
            request_id,
            response,
        } => {
            writer.write_u8(2);
            writer.write_fixed(request_id);
            writer.write_bytes(response)?;
        }
        DiscoveryResponse::MailboxMessages {
            request_id,
            messages,
        } => {
            writer.write_u8(3);
            writer.write_fixed(request_id);
            writer.write_vec(messages, |writer, message| {
                writer.write_fixed(&message.request_id);
                writer.write_fixed(&message.response_slot_id);
                writer.write_bytes(&message.envelope)?;
                Ok(())
            })?;
        }
        DiscoveryResponse::Posted { request_id } => {
            writer.write_u8(4);
            writer.write_fixed(request_id);
        }
        DiscoveryResponse::HandleResponse {
            request_id,
            envelope,
        } => {
            writer.write_u8(5);
            writer.write_fixed(request_id);
            writer.write_bool(envelope.is_some());
            if let Some(envelope) = envelope {
                writer.write_bytes(envelope)?;
            }
        }
        DiscoveryResponse::Error {
            request_id,
            message,
        } => {
            writer.write_u8(6);
            writer.write_fixed(request_id);
            writer.write_string(message)?;
        }
    }
    Ok(writer.into_vec())
}

fn decode_response(bytes: &[u8]) -> Result<DiscoveryResponse> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != DISCOVERY_RESPONSE_VERSION {
        bail!("unsupported discovery response version {}", version);
    }
    let response = match reader.read_u8()? {
        0 => DiscoveryResponse::Manifest {
            request_id: reader.read_fixed()?,
            manifest: reader.read_bytes()?,
        },
        1 => DiscoveryResponse::Published {
            request_id: reader.read_fixed()?,
        },
        2 => DiscoveryResponse::Pir {
            request_id: reader.read_fixed()?,
            response: reader.read_bytes()?,
        },
        3 => DiscoveryResponse::MailboxMessages {
            request_id: reader.read_fixed()?,
            messages: reader.read_vec(|reader| {
                Ok(MailboxRequestMessage {
                    request_id: reader.read_fixed()?,
                    response_slot_id: reader.read_fixed()?,
                    envelope: reader.read_bytes()?,
                })
            })?,
        },
        4 => DiscoveryResponse::Posted {
            request_id: reader.read_fixed()?,
        },
        5 => {
            let request_id = reader.read_fixed()?;
            let envelope = if reader.read_bool()? {
                Some(reader.read_bytes()?)
            } else {
                None
            };
            DiscoveryResponse::HandleResponse {
                request_id,
                envelope,
            }
        }
        6 => DiscoveryResponse::Error {
            request_id: reader.read_fixed()?,
            message: reader.read_string()?,
        },
        other => bail!("unsupported discovery response tag {}", other),
    };
    reader.finish()?;
    Ok(response)
}

fn seal_padded_message(
    message_version: u8,
    plaintext: &[u8],
    recipient_kem_pk: &TaggedKemPublicKey,
    target_plaintext_bytes: usize,
) -> Result<Vec<u8>> {
    let padded = pad_plaintext(plaintext, target_plaintext_bytes)?;
    let (kem_ct, shared_key) = recipient_kem_pk.encapsulate()?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let symmetric_key = derive_message_key(message_version, &shared_key, &nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), padded.as_ref())
        .map_err(|_| anyhow!("failed to encrypt discovery mailbox message"))?;
    let mut envelope = Vec::with_capacity(1 + ML_KEM_768_CT_BYTES + 24 + ciphertext.len());
    envelope.push(message_version);
    envelope.extend_from_slice(&kem_ct);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_padded_message(
    envelope: &[u8],
    recipient_kem_sk_bytes: &[u8; ML_KEM_768_SK_BYTES],
) -> Result<Vec<u8>> {
    if envelope.len() < 1 + ML_KEM_768_CT_BYTES + 24 + 16 {
        bail!("discovery mailbox envelope is truncated");
    }
    let message_version = envelope[0];
    let mut kem_ct = [0u8; ML_KEM_768_CT_BYTES];
    kem_ct.copy_from_slice(&envelope[1..1 + ML_KEM_768_CT_BYTES]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[1 + ML_KEM_768_CT_BYTES..1 + ML_KEM_768_CT_BYTES + 24]);
    let ciphertext = &envelope[1 + ML_KEM_768_CT_BYTES + 24..];
    let recipient_kem_sk = crypto::ml_kem_768_secret_key_from_bytes(recipient_kem_sk_bytes);
    let shared_key = crypto::ml_kem_768_decapsulate(&recipient_kem_sk, &kem_ct)?;
    let symmetric_key = derive_message_key(message_version, &shared_key, &nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let padded = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| anyhow!("failed to decrypt discovery mailbox message"))?;
    unpad_plaintext(&padded)
}

fn derive_message_key(message_version: u8, shared_key: &[u8; 32], nonce: &[u8; 24]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_MESSAGE_AEAD_DOMAIN);
    hasher.update(&[message_version]);
    hasher.update(shared_key);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

fn pad_plaintext(plaintext: &[u8], target_plaintext_bytes: usize) -> Result<Vec<u8>> {
    if plaintext.len() + 4 > target_plaintext_bytes {
        bail!("discovery mailbox plaintext exceeds fixed padded size");
    }
    let mut padded = vec![0u8; target_plaintext_bytes];
    padded[..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    padded[4..4 + plaintext.len()].copy_from_slice(plaintext);
    Ok(padded)
}

fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 4 {
        bail!("discovery mailbox plaintext is truncated");
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&padded[..4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > padded.len() - 4 {
        bail!("discovery mailbox plaintext length is invalid");
    }
    Ok(padded[4..4 + len].to_vec())
}

fn mailbox_request_key(mailbox_id: &[u8; 32], request_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(mailbox_id);
    key.extend_from_slice(request_id);
    key
}

fn mailbox_auth_hash(token: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_MAILBOX_AUTH_DOMAIN);
    hasher.update(token);
    *hasher.finalize().as_bytes()
}

fn response_auth_hash(token: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DISCOVERY_RESPONSE_AUTH_DOMAIN);
    hasher.update(token);
    *hasher.finalize().as_bytes()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn discovery_transport_config() -> Result<Arc<quinn::TransportConfig>> {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(DISCOVERY_STREAM_WINDOW_BYTES));
    transport.receive_window(quinn::VarInt::from_u32(DISCOVERY_CONNECTION_WINDOW_BYTES));
    transport.send_window(DISCOVERY_SEND_WINDOW_BYTES);
    transport.max_idle_timeout(Some(
        Duration::from_secs(DISCOVERY_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|_| anyhow!("invalid discovery idle timeout"))?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(DISCOVERY_KEEP_ALIVE_SECS)));
    Ok(Arc::new(transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn locator_roundtrip_is_stable() -> Result<()> {
        let key = crypto::ml_dsa_65_generate()?;
        let pk = crypto::ml_dsa_65_public_key(&key);
        let locator = locator_from_signing_pk(&pk);
        let locator_id = parse_locator(&locator)?;
        assert_eq!(locator_id, locator_id_from_signing_pk(&pk));
        Ok(())
    }

    #[test]
    fn discovery_record_roundtrip_and_validation() -> Result<()> {
        let key = crypto::ml_dsa_65_generate()?;
        let pk = crypto::ml_dsa_65_public_key(&key);
        let pkcs8 = crypto::ml_dsa_65_keypair_to_pkcs8(&key)?;
        let chain_id = [7u8; 32];
        let (_kem_sk, kem_pk) = crypto::ml_kem_768_generate();
        let (_locator, locator_id, _mailbox_id, record) =
            build_signed_discovery_record(&pkcs8, &pk, chain_id, kem_pk, Duration::from_secs(60))?;
        let encoded = encode_discovery_record(&record)?;
        let decoded = decode_discovery_record(&encoded)?;
        decoded.validate(&locator_id, &chain_id)?;
        Ok(())
    }

    #[test]
    fn mailbox_request_and_response_roundtrip() -> Result<()> {
        let (_request_sk, request_pk) = crypto::ml_kem_768_generate();
        let request_sk = crypto::ml_kem_768_secret_key_to_bytes(&_request_sk);
        let request = HandleRequestPlaintext {
            version: DISCOVERY_MAILBOX_REQUEST_VERSION,
            chain_id: [1u8; 32],
            locator_id: [2u8; 32],
            request_id: [3u8; 32],
            response_slot_id: [4u8; 32],
            response_auth_token: [5u8; 32],
            response_kem_pk: request_pk.clone(),
            requested_amount: 42,
            issued_unix_ms: 10,
            expires_unix_ms: 20,
        };
        let envelope = seal_handle_request(&request, &request_pk)?;
        let opened = open_handle_request(&envelope, &request_sk)?;
        assert_eq!(opened, request);

        let key = crypto::ml_dsa_65_generate()?;
        let pk = crypto::ml_dsa_65_public_key(&key);
        let pkcs8 = crypto::ml_dsa_65_keypair_to_pkcs8(&key)?;
        let chain_id = [9u8; 32];
        let (_locator, _locator_id, _mailbox_id, record) = build_signed_discovery_record(
            &pkcs8,
            &pk,
            chain_id,
            request_pk.clone(),
            Duration::from_secs(60),
        )?;
        let handle = RecipientHandle {
            chain_id,
            signing_pk: record.owner_signing_pk.clone(),
            receive_key_id: [6u8; 32],
            kem_pk: request_pk.clone(),
            issued_unix_ms: 30,
            expires_unix_ms: 40,
            sig: vec![1, 2, 3],
        };
        let response = HandleResponsePlaintext {
            version: DISCOVERY_MAILBOX_RESPONSE_VERSION,
            chain_id,
            locator_id: record.locator_id,
            request_id: [3u8; 32],
            handle: handle.clone(),
            issued_unix_ms: 50,
        };
        let response_envelope = seal_handle_response(&response, &request_pk)?;
        let opened_response = open_handle_response(&response_envelope, &request_sk)?;
        assert_eq!(opened_response.handle, handle);
        Ok(())
    }
}
