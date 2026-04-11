use crate::{
    canonical::{self, CanonicalReader, CanonicalWriter},
    crypto::{self, ML_KEM_768_CT_BYTES},
    node_control::{
        CompactCommittedCoin, CompactShieldedOutput, CompactWalletSyncDelta, CompactWalletSyncHead,
        NodeControlClient, WalletSendRuntimeMaterial,
    },
    node_identity::{
        build_client_config_with_alpn, build_server_config_with_alpn,
        load_local_ingress_key_material_in_dir, tls_peer_spki, ExpectedPeerStore, NodeIdentity,
        NodeRecordV3,
    },
    transaction::Tx,
};
use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    Key, XChaCha20Poly1305, XNonce,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::Endpoint;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::thread;
use tokio::sync::{broadcast, Mutex as AsyncMutex};
use tokio::time::{self, Duration, MissedTickBehavior};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const WALLET_TO_RELAY_ALPN: &[u8] = b"unchained-ingress-wallet/v1";
const RELAY_TO_GATEWAY_ALPN: &[u8] = b"unchained-ingress-relay/v1";
const INGRESS_ENVELOPE_VERSION: u8 = 1;
const GATEWAY_SUBMISSION_VERSION: u8 = 1;
const INGRESS_ACCEPT_VERSION: u8 = 1;
const INGRESS_HYBRID_KEY_DOMAIN: &str = "unchained-ingress-hybrid-key-v1";
const INGRESS_ENVELOPE_FILL_DOMAIN: &str = "unchained-ingress-envelope-fill-v1";
const DEFAULT_ENVELOPE_SIZE_BYTES: usize = 2 * 1024 * 1024;
const MAX_INGRESS_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUEUE_DEPTH: usize = 2048;
const INGRESS_STREAM_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
const INGRESS_CONNECTION_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const INGRESS_SEND_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
const INGRESS_IDLE_TIMEOUT_SECS: u64 = 30;
const INGRESS_KEEP_ALIVE_SECS: u64 = 5;
const LIGHT_CLIENT_SYNC_MAX_COINS_PER_REQUEST: u32 = 512;
const LIGHT_CLIENT_SYNC_MAX_OUTPUTS_PER_REQUEST: u32 = 256;

#[derive(Debug, Clone)]
enum GatewaySubmission {
    Tx(Tx),
    Cover {
        cover_id: [u8; 32],
    },
    CompactWalletSyncHead {
        request_id: [u8; 32],
    },
    CompactWalletSyncDelta {
        request_id: [u8; 32],
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    },
    WalletSendRuntimeMaterial {
        request_id: [u8; 32],
    },
}

#[derive(Debug, Clone)]
enum IngressAccept {
    Submitted {
        submission_id: [u8; 32],
    },
    CompactWalletSyncHead {
        request_id: [u8; 32],
        head: CompactWalletSyncHead,
    },
    CompactWalletSyncDelta {
        request_id: [u8; 32],
        delta: CompactWalletSyncDelta,
    },
    WalletSendRuntimeMaterial {
        request_id: [u8; 32],
        material: WalletSendRuntimeMaterial,
    },
}

#[derive(Debug, Clone)]
struct WalletRateState {
    window_started_at: std::time::Instant,
    messages_in_window: u32,
}

#[derive(Debug, Clone)]
struct PendingGatewaySubmission {
    submission_id: [u8; 32],
    submission: GatewaySubmission,
}

#[derive(Clone)]
pub struct IngressClient {
    endpoint: Arc<Endpoint>,
    relay_record: NodeRecordV3,
    gateway_record: NodeRecordV3,
    chain_id: [u8; 32],
    envelope_size_bytes: usize,
    submit_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct AccessRelayPolicy {
    pub rate_limit_window: Duration,
    pub max_wallet_messages_per_window: u32,
    pub envelope_size_bytes: usize,
    pub submit_timeout: Duration,
}

impl Default for AccessRelayPolicy {
    fn default() -> Self {
        Self {
            rate_limit_window: Duration::from_secs(60),
            max_wallet_messages_per_window: 128,
            envelope_size_bytes: DEFAULT_ENVELOPE_SIZE_BYTES,
            submit_timeout: Duration::from_secs(10),
        }
    }
}

pub struct AccessRelayServer {
    endpoint: Endpoint,
    gateway_records: HashMap<[u8; 32], NodeRecordV3>,
    gateway_expected_peers: Arc<ExpectedPeerStore>,
    gateway_client_config: quinn::ClientConfig,
    policy: AccessRelayPolicy,
    wallet_rate_state: Arc<AsyncMutex<HashMap<IpAddr, WalletRateState>>>,
}

#[derive(Debug, Clone)]
pub struct SubmissionGatewayPolicy {
    pub release_window: Duration,
    pub max_batch_txs: usize,
    pub max_queue_depth: usize,
    pub envelope_size_bytes: usize,
    pub submit_timeout: Duration,
}

impl Default for SubmissionGatewayPolicy {
    fn default() -> Self {
        Self {
            release_window: Duration::from_millis(50),
            max_batch_txs: 32,
            max_queue_depth: MAX_QUEUE_DEPTH,
            envelope_size_bytes: DEFAULT_ENVELOPE_SIZE_BYTES,
            submit_timeout: Duration::from_secs(10),
        }
    }
}

pub struct SubmissionGatewayServer {
    endpoint: Endpoint,
    ingress_keys: crate::node_identity::IngressKeyMaterial,
    allowed_relays_by_auth_spki: HashMap<Vec<u8>, NodeRecordV3>,
    validator_client: NodeControlClient,
    policy: SubmissionGatewayPolicy,
    queue: Arc<AsyncMutex<VecDeque<PendingGatewaySubmission>>>,
    queued_submission_ids: Arc<AsyncMutex<HashMap<[u8; 32], usize>>>,
}

impl IngressClient {
    pub fn new(
        relay_record: NodeRecordV3,
        gateway_record: NodeRecordV3,
        envelope_size_bytes: usize,
        submit_timeout: Duration,
    ) -> Result<Self> {
        if relay_record.node_id == gateway_record.node_id {
            bail!(
                "wallet ingress requires distinct access relay and submission gateway identities"
            );
        }
        let relay_chain_id = relay_record
            .chain_id
            .ok_or_else(|| anyhow!("access relay node record must be bound to a chain"))?;
        let gateway_chain_id = gateway_record
            .chain_id
            .ok_or_else(|| anyhow!("submission gateway node record must be bound to a chain"))?;
        if relay_chain_id != gateway_chain_id {
            bail!(
                "wallet ingress requires relay and gateway records on the same chain: {} vs {}",
                hex::encode(relay_chain_id),
                hex::encode(gateway_chain_id),
            );
        }
        let expected = ExpectedPeerStore::new();
        expected.remember(&relay_record);
        let rustls_client = build_client_config_with_alpn(None, expected, WALLET_TO_RELAY_ALPN)?;
        let transport_config = ingress_transport_config()?;
        let mut endpoint = Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client)?));
        client_config.transport_config(transport_config);
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint: Arc::new(endpoint),
            relay_record,
            gateway_record,
            chain_id: relay_chain_id,
            envelope_size_bytes: envelope_size_bytes.max(DEFAULT_ENVELOPE_SIZE_BYTES),
            submit_timeout,
        })
    }

    pub fn chain_id(&self) -> Result<[u8; 32]> {
        Ok(self.chain_id)
    }

    pub async fn submit_tx(&self, tx: &Tx) -> Result<[u8; 32]> {
        self.submit_submission(GatewaySubmission::Tx(tx.clone()))
            .await
    }

    pub async fn submit_cover(&self) -> Result<[u8; 32]> {
        let mut cover_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut cover_id);
        self.submit_submission(GatewaySubmission::Cover { cover_id })
            .await
    }

    pub async fn compact_wallet_sync_head(&self) -> Result<CompactWalletSyncHead> {
        let mut request_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut request_id);
        match self
            .exchange_submission(GatewaySubmission::CompactWalletSyncHead { request_id })
            .await?
        {
            IngressAccept::CompactWalletSyncHead {
                request_id: echoed_request_id,
                head,
            } => {
                if echoed_request_id != request_id {
                    bail!("ingress compact-wallet-sync-head request_id mismatch");
                }
                Ok(head)
            }
            other => bail!("unexpected ingress compact-wallet-sync-head response: {other:?}"),
        }
    }

    pub async fn request_compact_wallet_sync_delta(
        &self,
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    ) -> Result<CompactWalletSyncDelta> {
        let mut request_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut request_id);
        match self
            .exchange_submission(GatewaySubmission::CompactWalletSyncDelta {
                request_id,
                next_coin_index,
                next_output_index,
                max_coins,
                max_outputs,
            })
            .await?
        {
            IngressAccept::CompactWalletSyncDelta {
                request_id: echoed_request_id,
                delta,
            } => {
                if echoed_request_id != request_id {
                    bail!("ingress compact-wallet-sync-delta request_id mismatch");
                }
                Ok(delta)
            }
            other => bail!("unexpected ingress compact-wallet-sync-delta response: {other:?}"),
        }
    }

    pub async fn wallet_send_runtime_material(&self) -> Result<WalletSendRuntimeMaterial> {
        let mut request_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut request_id);
        match self
            .exchange_submission(GatewaySubmission::WalletSendRuntimeMaterial { request_id })
            .await?
        {
            IngressAccept::WalletSendRuntimeMaterial {
                request_id: echoed_request_id,
                material,
            } => {
                if echoed_request_id != request_id {
                    bail!("ingress wallet-send-runtime-material request_id mismatch");
                }
                Ok(material)
            }
            other => bail!("unexpected ingress wallet-send-runtime-material response: {other:?}"),
        }
    }

    pub fn compact_wallet_sync_head_blocking(&self) -> Result<CompactWalletSyncHead> {
        let client = self.clone();
        thread::Builder::new()
            .name("unchained-ingress-sync-head".into())
            .spawn(move || -> Result<CompactWalletSyncHead> {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build ingress compact-sync-head runtime")?
                    .block_on(client.compact_wallet_sync_head())
            })
            .context("spawn ingress compact-sync-head thread")?
            .join()
            .map_err(|_| anyhow!("ingress compact-sync-head thread panicked"))?
    }

    pub fn request_compact_wallet_sync_delta_blocking(
        &self,
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    ) -> Result<CompactWalletSyncDelta> {
        let client = self.clone();
        thread::Builder::new()
            .name("unchained-ingress-sync-delta".into())
            .spawn(move || -> Result<CompactWalletSyncDelta> {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build ingress compact-sync-delta runtime")?
                    .block_on(client.request_compact_wallet_sync_delta(
                        next_coin_index,
                        next_output_index,
                        max_coins,
                        max_outputs,
                    ))
            })
            .context("spawn ingress compact-sync-delta thread")?
            .join()
            .map_err(|_| anyhow!("ingress compact-sync-delta thread panicked"))?
    }

    pub fn wallet_send_runtime_material_blocking(&self) -> Result<WalletSendRuntimeMaterial> {
        let client = self.clone();
        thread::Builder::new()
            .name("unchained-ingress-send-runtime".into())
            .spawn(move || -> Result<WalletSendRuntimeMaterial> {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build ingress send-runtime-material runtime")?
                    .block_on(client.wallet_send_runtime_material())
            })
            .context("spawn ingress send-runtime-material thread")?
            .join()
            .map_err(|_| anyhow!("ingress send-runtime-material thread panicked"))?
    }

    async fn submit_submission(&self, submission: GatewaySubmission) -> Result<[u8; 32]> {
        let submission_id = submission.submission_id()?;
        match self.exchange_submission(submission).await? {
            IngressAccept::Submitted {
                submission_id: accepted_submission_id,
            } => {
                if accepted_submission_id != submission_id {
                    bail!("ingress relay ack submission_id mismatch");
                }
                Ok(submission_id)
            }
            other => bail!("unexpected ingress submission response: {other:?}"),
        }
    }

    async fn exchange_submission(&self, submission: GatewaySubmission) -> Result<IngressAccept> {
        let envelope = seal_submission_to_gateway(
            &submission,
            &self.gateway_record,
            self.envelope_size_bytes,
        )?;
        let connection = time::timeout(
            self.submit_timeout,
            self.endpoint.connect(
                self.relay_record.primary_address()?,
                &self.relay_record.server_name(),
            )?,
        )
        .await
        .context("wallet ingress relay dial timed out")??;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("wallet ingress failed to open relay stream")?;
        send.write_all(&envelope)
            .await
            .context("wallet ingress failed to write padded envelope to relay")?;
        send.finish()
            .context("wallet ingress failed to finish relay stream")?;
        let response = recv
            .read_to_end(MAX_INGRESS_RESPONSE_BYTES)
            .await
            .context("wallet ingress failed while waiting for relay response")?;
        decode_ingress_accept(&response)
    }
}

impl Drop for IngressClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.endpoint) == 1 {
            self.endpoint.close(0u32.into(), b"shutdown");
        }
    }
}

impl AccessRelayServer {
    pub fn bind(
        identity: &NodeIdentity,
        gateway_records: Vec<NodeRecordV3>,
        listen_addr: SocketAddr,
        policy: AccessRelayPolicy,
    ) -> Result<Self> {
        if gateway_records.is_empty() {
            bail!("access relay requires at least one configured submission gateway");
        }
        let mut by_id = HashMap::new();
        let gateway_expected_peers = ExpectedPeerStore::new();
        for record in gateway_records {
            if record.node_id == identity.node_id() {
                bail!("access relay and submission gateway must not share the same node identity");
            }
            gateway_expected_peers.remember(&record);
            by_id.insert(record.node_id, record);
        }
        let rustls_server = build_server_config_with_alpn(identity, WALLET_TO_RELAY_ALPN, false)?;
        let rustls_client = build_client_config_with_alpn(
            Some(identity),
            gateway_expected_peers.clone(),
            RELAY_TO_GATEWAY_ALPN,
        )?;
        let transport_config = ingress_transport_config()?;
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_server)?));
        server_config.transport_config(transport_config.clone());
        let mut endpoint = Endpoint::server(server_config, listen_addr)?;
        let mut default_client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client)?));
        default_client_config.transport_config(transport_config.clone());
        endpoint.set_default_client_config(default_client_config);
        Ok(Self {
            endpoint,
            gateway_records: by_id,
            gateway_expected_peers: gateway_expected_peers.clone(),
            gateway_client_config: {
                let mut client_config = quinn::ClientConfig::new(Arc::new(
                    QuicClientConfig::try_from(build_client_config_with_alpn(
                        Some(identity),
                        gateway_expected_peers.clone(),
                        RELAY_TO_GATEWAY_ALPN,
                    )?)?,
                ));
                client_config.transport_config(transport_config);
                client_config
            },
            policy,
            wallet_rate_state: Arc::new(AsyncMutex::new(HashMap::new())),
        })
    }

    pub async fn serve(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let endpoint = self.endpoint.clone();
        let relay = Arc::new(self);
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let relay = relay.clone();
                    tokio::spawn(async move {
                        if let Err(err) = relay.handle_wallet_connection(incoming).await {
                            eprintln!("access relay connection failed: {err}");
                        }
                    });
                }
            }
        }
        relay.endpoint.close(0u32.into(), b"shutdown");
        Ok(())
    }

    async fn handle_wallet_connection(&self, incoming: quinn::Incoming) -> Result<()> {
        let connection = time::timeout(self.policy.submit_timeout, incoming)
            .await
            .context("wallet ingress handshake timed out")??;
        let remote_ip = connection.remote_address().ip();
        loop {
            self.enforce_wallet_rate_limit(remote_ip).await?;
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::TimedOut) => break,
                Err(err) => return Err(err.into()),
            };
            let envelope = recv
                .read_to_end((self.policy.envelope_size_bytes + 1) as usize)
                .await
                .context("access relay failed while reading the padded wallet envelope")?;
            if envelope.len() != self.policy.envelope_size_bytes {
                bail!(
                    "wallet ingress envelope size {} does not match the configured fixed size {}",
                    envelope.len(),
                    self.policy.envelope_size_bytes
                );
            }
            let gateway_id = parse_gateway_id(&envelope)?;
            let gateway_record =
                self.gateway_records
                    .get(&gateway_id)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!("wallet ingress envelope targets an unknown submission gateway")
                    })?;
            let ack = self.forward_to_gateway(&gateway_record, envelope).await?;
            send.write_all(&encode_ingress_accept(&ack)?)
                .await
                .context("access relay failed to write wallet ack")?;
            send.finish()
                .context("access relay failed to finish wallet ack stream")?;
        }
        Ok(())
    }

    async fn enforce_wallet_rate_limit(&self, remote_ip: IpAddr) -> Result<()> {
        let mut guard = self.wallet_rate_state.lock().await;
        let now = std::time::Instant::now();
        let state = guard.entry(remote_ip).or_insert(WalletRateState {
            window_started_at: now,
            messages_in_window: 0,
        });
        if now.duration_since(state.window_started_at) >= self.policy.rate_limit_window {
            state.window_started_at = now;
            state.messages_in_window = 0;
        }
        state.messages_in_window = state.messages_in_window.saturating_add(1);
        if state.messages_in_window > self.policy.max_wallet_messages_per_window {
            bail!("wallet ingress rate limit exceeded");
        }
        Ok(())
    }

    async fn forward_to_gateway(
        &self,
        gateway_record: &NodeRecordV3,
        envelope: Vec<u8>,
    ) -> Result<IngressAccept> {
        self.gateway_expected_peers.remember(gateway_record);
        let connection = time::timeout(
            self.policy.submit_timeout,
            self.endpoint.connect_with(
                self.gateway_client_config.clone(),
                gateway_record.primary_address()?,
                &gateway_record.server_name(),
            )?,
        )
        .await
        .context("submission gateway dial timed out")??;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("access relay failed to open gateway stream")?;
        send.write_all(&encode_gateway_forward(&envelope)?)
            .await
            .context(
                "access relay failed to forward the padded envelope to the submission gateway",
            )?;
        send.finish()
            .context("access relay failed to finish the gateway stream")?;
        let ack = recv
            .read_to_end(MAX_INGRESS_RESPONSE_BYTES)
            .await
            .context("access relay failed while waiting for the submission gateway response")?;
        decode_ingress_accept(&ack)
    }
}

impl SubmissionGatewayServer {
    pub fn bind(
        identity: &NodeIdentity,
        allowed_relays: Vec<NodeRecordV3>,
        listen_addr: SocketAddr,
        validator_control_base_path: &str,
        policy: SubmissionGatewayPolicy,
    ) -> Result<Self> {
        if allowed_relays.is_empty() {
            bail!("submission gateway requires at least one configured access relay");
        }
        let mut allowed_by_auth_spki = HashMap::new();
        for relay in allowed_relays {
            if relay.node_id == identity.node_id() {
                bail!("submission gateway and access relay must not share the same node identity");
            }
            allowed_by_auth_spki.insert(relay.auth_spki.clone(), relay);
        }
        let rustls_server = build_server_config_with_alpn(identity, RELAY_TO_GATEWAY_ALPN, true)?;
        let transport_config = ingress_transport_config()?;
        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_server)?));
        server_config.transport_config(transport_config);
        let endpoint = Endpoint::server(server_config, listen_addr)?;
        Ok(Self {
            endpoint,
            ingress_keys: load_local_ingress_key_material_in_dir(identity.dir())?,
            allowed_relays_by_auth_spki: allowed_by_auth_spki,
            validator_client: NodeControlClient::new(validator_control_base_path),
            policy,
            queue: Arc::new(AsyncMutex::new(VecDeque::new())),
            queued_submission_ids: Arc::new(AsyncMutex::new(HashMap::new())),
        })
    }

    pub async fn serve(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let gateway = Arc::new(self);
        let release_gateway = gateway.clone();
        let mut interval = time::interval(release_gateway.policy.release_window);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let release_task = tokio::spawn(async move {
            loop {
                interval.tick().await;
                if let Err(err) = release_gateway.release_batch().await {
                    eprintln!("submission gateway release failed: {err}");
                }
            }
        });
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                incoming = gateway.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let gateway = gateway.clone();
                    tokio::spawn(async move {
                        if let Err(err) = gateway.handle_relay_connection(incoming).await {
                            eprintln!("submission gateway connection failed: {err}");
                        }
                    });
                }
            }
        }
        release_task.abort();
        gateway.endpoint.close(0u32.into(), b"shutdown");
        Ok(())
    }

    async fn handle_relay_connection(&self, incoming: quinn::Incoming) -> Result<()> {
        let connection = time::timeout(self.policy.submit_timeout, incoming)
            .await
            .context("relay ingress handshake timed out")??;
        let tls_spki = tls_peer_spki(connection.peer_identity())?;
        if !self.allowed_relays_by_auth_spki.contains_key(&tls_spki) {
            bail!("submission gateway rejected an unconfigured access relay");
        }
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::TimedOut) => break,
                Err(err) => return Err(err.into()),
            };
            let frame = recv
                .read_to_end(self.policy.envelope_size_bytes + 64)
                .await
                .context("submission gateway failed while reading the forwarded relay frame")?;
            let forwarded_envelope = decode_gateway_forward(&frame)?;
            if forwarded_envelope.len() != self.policy.envelope_size_bytes {
                bail!("submission gateway received an envelope with the wrong fixed size");
            }
            let submission = open_submission_from_envelope(
                &forwarded_envelope,
                &self.ingress_keys,
                self.policy.envelope_size_bytes,
                self.endpoint.local_addr()?.port(),
            )?;
            let submission_id = submission.submission_id()?;
            let response = self.handle_submission(submission_id, submission).await?;
            send.write_all(&encode_ingress_accept(&response)?)
                .await
                .context("submission gateway failed to write relay response")?;
            send.finish()
                .context("submission gateway failed to finish relay response stream")?;
        }
        Ok(())
    }

    async fn handle_submission(
        &self,
        submission_id: [u8; 32],
        submission: GatewaySubmission,
    ) -> Result<IngressAccept> {
        match submission {
            GatewaySubmission::Tx(tx) => {
                self.queue_submission(submission_id, GatewaySubmission::Tx(tx))
                    .await?;
                Ok(IngressAccept::Submitted { submission_id })
            }
            GatewaySubmission::Cover { cover_id } => {
                self.queue_submission(submission_id, GatewaySubmission::Cover { cover_id })
                    .await?;
                Ok(IngressAccept::Submitted { submission_id })
            }
            GatewaySubmission::CompactWalletSyncHead { request_id } => {
                Ok(IngressAccept::CompactWalletSyncHead {
                    request_id,
                    head: self
                        .validator_client
                        .compact_wallet_sync_head_async()
                        .await?,
                })
            }
            GatewaySubmission::CompactWalletSyncDelta {
                request_id,
                next_coin_index,
                next_output_index,
                max_coins,
                max_outputs,
            } => Ok(IngressAccept::CompactWalletSyncDelta {
                request_id,
                delta: self
                    .validator_client
                    .request_compact_wallet_sync_delta_async(
                        next_coin_index,
                        next_output_index,
                        max_coins.min(LIGHT_CLIENT_SYNC_MAX_COINS_PER_REQUEST),
                        max_outputs.min(LIGHT_CLIENT_SYNC_MAX_OUTPUTS_PER_REQUEST),
                    )
                    .await?,
            }),
            GatewaySubmission::WalletSendRuntimeMaterial { request_id } => {
                Ok(IngressAccept::WalletSendRuntimeMaterial {
                    request_id,
                    material: self
                        .validator_client
                        .wallet_send_runtime_material_async()
                        .await?,
                })
            }
        }
    }

    async fn queue_submission(
        &self,
        submission_id: [u8; 32],
        submission: GatewaySubmission,
    ) -> Result<()> {
        let mut queued_ids = self.queued_submission_ids.lock().await;
        if queued_ids.contains_key(&submission_id) {
            return Ok(());
        }
        let mut queue = self.queue.lock().await;
        if queue.len() >= self.policy.max_queue_depth {
            bail!("submission gateway queue is full");
        }
        queue.push_back(PendingGatewaySubmission {
            submission_id,
            submission,
        });
        queued_ids.insert(submission_id, 1);
        Ok(())
    }

    async fn release_batch(&self) -> Result<()> {
        let mut drained = Vec::new();
        {
            let mut queue = self.queue.lock().await;
            while drained.len() < self.policy.max_batch_txs {
                let Some(next) = queue.pop_front() else {
                    break;
                };
                drained.push(next);
            }
        }
        if drained.is_empty() {
            return Ok(());
        }
        for pending in drained {
            self.queued_submission_ids
                .lock()
                .await
                .remove(&pending.submission_id);
            match pending.submission {
                GatewaySubmission::Tx(tx) => {
                    let _ = self.validator_client.submit_tx_async(&tx).await?;
                }
                GatewaySubmission::Cover { .. } => {}
                GatewaySubmission::CompactWalletSyncHead { .. }
                | GatewaySubmission::CompactWalletSyncDelta { .. }
                | GatewaySubmission::WalletSendRuntimeMaterial { .. } => {
                    bail!("submission gateway queued a non-batched light-client request")
                }
            }
        }
        Ok(())
    }
}

impl GatewaySubmission {
    fn submission_id(&self) -> Result<[u8; 32]> {
        match self {
            Self::Tx(tx) => tx.id(),
            Self::Cover { cover_id } => Ok(*cover_id),
            Self::CompactWalletSyncHead { request_id } => Ok(*request_id),
            Self::CompactWalletSyncDelta { request_id, .. } => Ok(*request_id),
            Self::WalletSendRuntimeMaterial { request_id } => Ok(*request_id),
        }
    }
}

fn parse_gateway_id(envelope: &[u8]) -> Result<[u8; 32]> {
    if envelope.len() < 1 + 32 {
        bail!("ingress envelope is truncated");
    }
    if envelope[0] != INGRESS_ENVELOPE_VERSION {
        bail!("unsupported ingress envelope version {}", envelope[0]);
    }
    let mut gateway_id = [0u8; 32];
    gateway_id.copy_from_slice(&envelope[1..33]);
    Ok(gateway_id)
}

fn seal_submission_to_gateway(
    submission: &GatewaySubmission,
    gateway_record: &NodeRecordV3,
    envelope_size_bytes: usize,
) -> Result<Vec<u8>> {
    let envelope_size_bytes = envelope_size_bytes.max(DEFAULT_ENVELOPE_SIZE_BYTES);
    let header_size = 1 + 32 + 32 + ML_KEM_768_CT_BYTES + 24;
    if envelope_size_bytes <= header_size + 16 + 4 {
        bail!("configured ingress envelope size is too small");
    }
    let plaintext_capacity = envelope_size_bytes - header_size - 16;
    let plaintext = encode_gateway_submission(submission)?;
    if plaintext.len() + 4 > plaintext_capacity {
        bail!("transaction exceeds the configured fixed ingress envelope size");
    }
    let mut padded_plaintext = vec![0u8; plaintext_capacity];
    padded_plaintext[..4].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    padded_plaintext[4..4 + plaintext.len()].copy_from_slice(&plaintext);
    fill_padding(
        &mut padded_plaintext[4 + plaintext.len()..],
        gateway_record.node_id,
        &plaintext,
    );

    let x25519_secret = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let gateway_x25519 = X25519PublicKey::from(gateway_record.ingress_x25519_pk);
    let x25519_shared = x25519_secret.diffie_hellman(&gateway_x25519);
    let (kem_ct, kem_shared) = gateway_record.ingress_kem_pk.encapsulate()?;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let symmetric_key = derive_hybrid_key(
        &gateway_record.node_id,
        x25519_public.as_bytes(),
        x25519_shared.as_bytes(),
        &kem_shared,
        &nonce,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), padded_plaintext.as_ref())
        .map_err(|_| anyhow!("failed to encrypt ingress envelope"))?;
    let mut envelope = Vec::with_capacity(envelope_size_bytes);
    envelope.push(INGRESS_ENVELOPE_VERSION);
    envelope.extend_from_slice(&gateway_record.node_id);
    envelope.extend_from_slice(x25519_public.as_bytes());
    envelope.extend_from_slice(&kem_ct);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn open_submission_from_envelope(
    envelope: &[u8],
    ingress_keys: &crate::node_identity::IngressKeyMaterial,
    envelope_size_bytes: usize,
    _local_port: u16,
) -> Result<GatewaySubmission> {
    if envelope.len() != envelope_size_bytes {
        bail!("ingress envelope size mismatch");
    }
    if envelope.first().copied() != Some(INGRESS_ENVELOPE_VERSION) {
        bail!("unsupported ingress envelope version");
    }
    let header_size = 1 + 32 + 32 + ML_KEM_768_CT_BYTES + 24;
    let mut gateway_id = [0u8; 32];
    gateway_id.copy_from_slice(&envelope[1..33]);
    let mut ephemeral_x25519_pk = [0u8; 32];
    ephemeral_x25519_pk.copy_from_slice(&envelope[33..65]);
    let mut kem_ct = [0u8; ML_KEM_768_CT_BYTES];
    kem_ct.copy_from_slice(&envelope[65..65 + ML_KEM_768_CT_BYTES]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&envelope[65 + ML_KEM_768_CT_BYTES..65 + ML_KEM_768_CT_BYTES + 24]);
    let ciphertext = &envelope[header_size..];
    let kem_secret = crypto::ml_kem_768_secret_key_from_bytes(&ingress_keys.kem_secret);
    let kem_shared = crypto::ml_kem_768_decapsulate(&kem_secret, &kem_ct)?;
    let x25519_secret = X25519StaticSecret::from(ingress_keys.x25519_secret);
    let x25519_public = X25519PublicKey::from(ephemeral_x25519_pk);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_public);
    let symmetric_key = derive_hybrid_key(
        &gateway_id,
        &ephemeral_x25519_pk,
        x25519_shared.as_bytes(),
        &kem_shared,
        &nonce,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let padded_plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| anyhow!("failed to decrypt ingress envelope"))?;
    if padded_plaintext.len() < 4 {
        bail!("decrypted ingress payload is truncated");
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&padded_plaintext[..4]);
    let payload_len = u32::from_le_bytes(len_bytes) as usize;
    if payload_len > padded_plaintext.len().saturating_sub(4) {
        bail!("decrypted ingress payload length is invalid");
    }
    decode_gateway_submission(&padded_plaintext[4..4 + payload_len])
}

fn derive_hybrid_key(
    gateway_id: &[u8; 32],
    ephemeral_x25519_pk: &[u8; 32],
    x25519_shared: &[u8; 32],
    kem_shared: &[u8; 32],
    nonce: &[u8; 24],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(INGRESS_HYBRID_KEY_DOMAIN);
    hasher.update(gateway_id);
    hasher.update(ephemeral_x25519_pk);
    hasher.update(x25519_shared);
    hasher.update(kem_shared);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

fn fill_padding(padding: &mut [u8], gateway_id: [u8; 32], plaintext: &[u8]) {
    if padding.is_empty() {
        return;
    }
    let mut hasher = blake3::Hasher::new_derive_key(INGRESS_ENVELOPE_FILL_DOMAIN);
    hasher.update(&gateway_id);
    hasher.update(&(plaintext.len() as u64).to_le_bytes());
    hasher.update(plaintext);
    let mut xof = hasher.finalize_xof();
    xof.fill(padding);
}

fn encode_gateway_submission(submission: &GatewaySubmission) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(GATEWAY_SUBMISSION_VERSION);
    match submission {
        GatewaySubmission::Tx(tx) => {
            writer.write_u8(1);
            writer.write_bytes(&canonical::encode_tx(tx)?)?;
        }
        GatewaySubmission::Cover { cover_id } => {
            writer.write_u8(2);
            writer.write_fixed(cover_id);
        }
        GatewaySubmission::CompactWalletSyncHead { request_id } => {
            writer.write_u8(3);
            writer.write_fixed(request_id);
        }
        GatewaySubmission::CompactWalletSyncDelta {
            request_id,
            next_coin_index,
            next_output_index,
            max_coins,
            max_outputs,
        } => {
            writer.write_u8(4);
            writer.write_fixed(request_id);
            writer.write_u64(*next_coin_index);
            writer.write_u64(*next_output_index);
            writer.write_u32(*max_coins);
            writer.write_u32(*max_outputs);
        }
        GatewaySubmission::WalletSendRuntimeMaterial { request_id } => {
            writer.write_u8(5);
            writer.write_fixed(request_id);
        }
    }
    Ok(writer.into_vec())
}

fn decode_gateway_submission(bytes: &[u8]) -> Result<GatewaySubmission> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != GATEWAY_SUBMISSION_VERSION {
        bail!("unsupported gateway submission version {}", version);
    }
    let submission = match reader.read_u8()? {
        1 => GatewaySubmission::Tx(canonical::decode_tx(&reader.read_bytes()?)?),
        2 => GatewaySubmission::Cover {
            cover_id: reader.read_fixed()?,
        },
        3 => GatewaySubmission::CompactWalletSyncHead {
            request_id: reader.read_fixed()?,
        },
        4 => GatewaySubmission::CompactWalletSyncDelta {
            request_id: reader.read_fixed()?,
            next_coin_index: reader.read_u64()?,
            next_output_index: reader.read_u64()?,
            max_coins: reader.read_u32()?,
            max_outputs: reader.read_u32()?,
        },
        5 => GatewaySubmission::WalletSendRuntimeMaterial {
            request_id: reader.read_fixed()?,
        },
        other => bail!("unsupported gateway submission tag {}", other),
    };
    reader.finish()?;
    Ok(submission)
}

fn encode_gateway_forward(envelope: &[u8]) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(1);
    writer.write_bytes(envelope)?;
    Ok(writer.into_vec())
}

fn decode_gateway_forward(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != 1 {
        bail!("unsupported relay forward version {}", version);
    }
    let envelope = reader.read_bytes()?;
    reader.finish()?;
    Ok(envelope)
}

fn write_compact_committed_coin(
    writer: &mut CanonicalWriter,
    coin: &CompactCommittedCoin,
) -> Result<()> {
    writer.write_u64(coin.scan_index);
    writer.write_u64(coin.birth_epoch);
    writer.write_bytes(&canonical::encode_coin(&coin.coin)?)?;
    Ok(())
}

fn read_compact_committed_coin(reader: &mut CanonicalReader<'_>) -> Result<CompactCommittedCoin> {
    Ok(CompactCommittedCoin {
        scan_index: reader.read_u64()?,
        birth_epoch: reader.read_u64()?,
        coin: canonical::decode_coin(&reader.read_bytes()?)?,
    })
}

fn write_compact_shielded_output(
    writer: &mut CanonicalWriter,
    output: &CompactShieldedOutput,
) -> Result<()> {
    writer.write_u64(output.scan_index);
    writer.write_fixed(&output.tx_id);
    writer.write_u32(output.output_index);
    writer.write_fixed(&output.note_commitment);
    writer.write_fixed(&output.kem_ct);
    writer.write_fixed(&output.nonce);
    writer.write_u8(output.detection_tag);
    writer.write_bytes(&output.ciphertext)?;
    Ok(())
}

fn read_compact_shielded_output(reader: &mut CanonicalReader<'_>) -> Result<CompactShieldedOutput> {
    Ok(CompactShieldedOutput {
        scan_index: reader.read_u64()?,
        tx_id: reader.read_fixed()?,
        output_index: reader.read_u32()?,
        note_commitment: reader.read_fixed()?,
        kem_ct: reader.read_fixed()?,
        nonce: reader.read_fixed()?,
        detection_tag: reader.read_u8()?,
        ciphertext: reader.read_bytes()?,
    })
}

fn encode_compact_wallet_sync_head(head: &CompactWalletSyncHead) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&head.chain_id);
    writer.write_u64(head.current_nullifier_epoch);
    writer.write_u64(head.latest_finalized_anchor_num);
    writer.write_u64(head.committed_coin_count);
    writer.write_u64(head.shielded_output_count);
    Ok(writer.into_vec())
}

fn decode_compact_wallet_sync_head(bytes: &[u8]) -> Result<CompactWalletSyncHead> {
    let mut reader = CanonicalReader::new(bytes);
    let head = CompactWalletSyncHead {
        chain_id: reader.read_fixed()?,
        current_nullifier_epoch: reader.read_u64()?,
        latest_finalized_anchor_num: reader.read_u64()?,
        committed_coin_count: reader.read_u64()?,
        shielded_output_count: reader.read_u64()?,
    };
    reader.finish()?;
    Ok(head)
}

fn encode_compact_wallet_sync_delta(delta: &CompactWalletSyncDelta) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(&encode_compact_wallet_sync_head(&delta.head)?)?;
    writer.write_vec(&delta.committed_coins, |writer, coin| {
        write_compact_committed_coin(writer, coin)
    })?;
    writer.write_vec(&delta.shielded_outputs, |writer, output| {
        write_compact_shielded_output(writer, output)
    })?;
    Ok(writer.into_vec())
}

fn decode_compact_wallet_sync_delta(bytes: &[u8]) -> Result<CompactWalletSyncDelta> {
    let mut reader = CanonicalReader::new(bytes);
    let delta = CompactWalletSyncDelta {
        head: decode_compact_wallet_sync_head(&reader.read_bytes()?)?,
        committed_coins: reader.read_vec(read_compact_committed_coin)?,
        shielded_outputs: reader.read_vec(read_compact_shielded_output)?,
    };
    reader.finish()?;
    Ok(delta)
}

fn encode_wallet_send_runtime_material(material: &WalletSendRuntimeMaterial) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(&encode_compact_wallet_sync_head(
        &material.compact_wallet_sync,
    )?)?;
    writer.write_u64(material.latest_finalized_anchor_epoch);
    writer.write_vec(&material.registered_validator_pools, |writer, pool| {
        writer.write_bytes(&canonical::encode_validator_pool(pool)?)
    })?;
    writer.write_bytes(&canonical::encode_note_commitment_tree(
        &material.note_tree,
    )?)?;
    writer.write_bytes(&canonical::encode_nullifier_root_ledger(
        &material.root_ledger,
    )?)?;
    writer.write_vec(&material.historical_nullifier_windows, |writer, window| {
        writer.write_bytes(&canonical::encode_historical_nullifier_window(window)?)
    })?;
    Ok(writer.into_vec())
}

fn decode_wallet_send_runtime_material(bytes: &[u8]) -> Result<WalletSendRuntimeMaterial> {
    let mut reader = CanonicalReader::new(bytes);
    let material = WalletSendRuntimeMaterial {
        compact_wallet_sync: decode_compact_wallet_sync_head(&reader.read_bytes()?)?,
        latest_finalized_anchor_epoch: reader.read_u64()?,
        registered_validator_pools: reader
            .read_vec(|reader| canonical::decode_validator_pool(&reader.read_bytes()?))?,
        note_tree: canonical::decode_note_commitment_tree(&reader.read_bytes()?)?,
        root_ledger: canonical::decode_nullifier_root_ledger(&reader.read_bytes()?)?,
        historical_nullifier_windows: reader.read_vec(|reader| {
            canonical::decode_historical_nullifier_window(&reader.read_bytes()?)
        })?,
    };
    reader.finish()?;
    Ok(material)
}

fn encode_ingress_accept(accept: &IngressAccept) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(INGRESS_ACCEPT_VERSION);
    match accept {
        IngressAccept::Submitted { submission_id } => {
            writer.write_u8(1);
            writer.write_fixed(submission_id);
        }
        IngressAccept::CompactWalletSyncHead { request_id, head } => {
            writer.write_u8(2);
            writer.write_fixed(request_id);
            writer.write_bytes(&encode_compact_wallet_sync_head(head)?)?;
        }
        IngressAccept::CompactWalletSyncDelta { request_id, delta } => {
            writer.write_u8(3);
            writer.write_fixed(request_id);
            writer.write_bytes(&encode_compact_wallet_sync_delta(delta)?)?;
        }
        IngressAccept::WalletSendRuntimeMaterial {
            request_id,
            material,
        } => {
            writer.write_u8(4);
            writer.write_fixed(request_id);
            writer.write_bytes(&encode_wallet_send_runtime_material(material)?)?;
        }
    }
    Ok(writer.into_vec())
}

fn ingress_transport_config() -> Result<Arc<quinn::TransportConfig>> {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(INGRESS_STREAM_WINDOW_BYTES));
    transport.receive_window(quinn::VarInt::from_u32(INGRESS_CONNECTION_WINDOW_BYTES));
    transport.send_window(INGRESS_SEND_WINDOW_BYTES);
    transport.max_idle_timeout(Some(
        Duration::from_secs(INGRESS_IDLE_TIMEOUT_SECS)
            .try_into()
            .map_err(|_| anyhow!("invalid ingress idle timeout"))?,
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(INGRESS_KEEP_ALIVE_SECS)));
    Ok(Arc::new(transport))
}

fn decode_ingress_accept(bytes: &[u8]) -> Result<IngressAccept> {
    let mut reader = CanonicalReader::new(bytes);
    let version = reader.read_u8()?;
    if version != INGRESS_ACCEPT_VERSION {
        bail!("unsupported ingress accept version {}", version);
    }
    let accept = match reader.read_u8()? {
        1 => IngressAccept::Submitted {
            submission_id: reader.read_fixed()?,
        },
        2 => IngressAccept::CompactWalletSyncHead {
            request_id: reader.read_fixed()?,
            head: decode_compact_wallet_sync_head(&reader.read_bytes()?)?,
        },
        3 => IngressAccept::CompactWalletSyncDelta {
            request_id: reader.read_fixed()?,
            delta: decode_compact_wallet_sync_delta(&reader.read_bytes()?)?,
        },
        4 => IngressAccept::WalletSendRuntimeMaterial {
            request_id: reader.read_fixed()?,
            material: decode_wallet_send_runtime_material(&reader.read_bytes()?)?,
        },
        other => bail!("unsupported ingress accept tag {}", other),
    };
    reader.finish()?;
    Ok(accept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coin::Coin,
        proof::{TransparentProof, TransparentProofStatement},
        shielded,
        transaction::{OrdinaryPrivateTransfer, ShieldedOutput, Tx},
        wallet::Wallet,
    };
    use std::sync::Arc;
    use tempfile::TempDir;

    fn dummy_proof(statement: TransparentProofStatement, seed: u8) -> TransparentProof {
        TransparentProof::new(statement, vec![seed; 16])
    }

    #[test]
    fn ingress_envelopes_are_fixed_size_and_round_trip() -> Result<()> {
        std::env::set_var("WALLET_PASSPHRASE", "ingress-envelope-test-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(crate::storage::WalletStore::open(
            &tempdir.path().to_string_lossy(),
        )?);
        let wallet = Wallet::load_or_create_private(wallet_store)?;
        let _ = crate::node_identity::init_root_in_dir(tempdir.path())?;
        let (_, request) = crate::node_identity::prepare_auth_request_in_dir(
            tempdir.path(),
            crate::protocol::CURRENT.version,
            Some([7u8; 32]),
            vec!["127.0.0.1:9".to_string()],
            None,
        )?;
        let (_, record_text) =
            crate::node_identity::sign_auth_request_in_dir(tempdir.path(), &request, 30)?;
        let _ = crate::node_identity::install_node_record_in_dir(tempdir.path(), &record_text)?;
        let record = crate::node_identity::load_local_runtime_record_in_dir(
            tempdir.path(),
            crate::protocol::CURRENT.version,
            Some([7u8; 32]),
            vec!["127.0.0.1:9".to_string()],
        )?;
        let ingress_keys = load_local_ingress_key_material_in_dir(tempdir.path())?;
        let tx = Tx::new(
            vec![[1u8; 32]],
            vec![ShieldedOutput {
                note_commitment: [2u8; 32],
                kem_ct: [0u8; crypto::ML_KEM_768_CT_BYTES],
                nonce: [3u8; 24],
                view_tag: [4u8; 1][0],
                ciphertext: vec![5u8; 32],
            }],
            1,
            dummy_proof(TransparentProofStatement::ShieldedTransfer, 6),
        );
        let envelope = seal_submission_to_gateway(
            &GatewaySubmission::Tx(tx.clone()),
            &record,
            DEFAULT_ENVELOPE_SIZE_BYTES,
        )?;
        assert_eq!(envelope.len(), DEFAULT_ENVELOPE_SIZE_BYTES);
        let reopened = open_submission_from_envelope(
            &envelope,
            &ingress_keys,
            DEFAULT_ENVELOPE_SIZE_BYTES,
            9,
        )?;
        match reopened {
            GatewaySubmission::Tx(reopened_tx) => assert_eq!(reopened_tx, tx),
            GatewaySubmission::Cover { .. }
            | GatewaySubmission::CompactWalletSyncHead { .. }
            | GatewaySubmission::CompactWalletSyncDelta { .. }
            | GatewaySubmission::WalletSendRuntimeMaterial { .. } => {
                bail!("unexpected non-transaction submission")
            }
        }
        assert_eq!(parse_gateway_id(&envelope)?, record.node_id);
        assert_eq!(record.ingress_kem_pk, ingress_keys.kem_public);
        assert_eq!(record.ingress_x25519_pk, ingress_keys.x25519_public);
        let _ = wallet.address();
        let _ = Coin::new([0u8; 32], 0, [0u8; 32]);
        let _ = shielded::ShieldedNoteKind::payment();
        let _ = OrdinaryPrivateTransfer {
            nullifiers: vec![],
            outputs: vec![],
            fee_amount: 0,
            proof: dummy_proof(TransparentProofStatement::ShieldedTransfer, 0),
        };
        Ok(())
    }

    #[test]
    fn ingress_roles_require_distinct_node_identities() -> Result<()> {
        let tempdir = TempDir::new()?;
        let _ = crate::node_identity::init_root_in_dir(tempdir.path())?;
        let addresses = vec!["127.0.0.1:0".to_string()];
        let (_, request) = crate::node_identity::prepare_auth_request_in_dir(
            tempdir.path(),
            crate::protocol::CURRENT.version,
            Some([9u8; 32]),
            addresses.clone(),
            None,
        )?;
        let (_, record_text) =
            crate::node_identity::sign_auth_request_in_dir(tempdir.path(), &request, 30)?;
        let _ = crate::node_identity::install_node_record_in_dir(tempdir.path(), &record_text)?;
        let identity = crate::node_identity::NodeIdentity::load_runtime_in_dir(
            tempdir.path(),
            crate::protocol::CURRENT.version,
            Some([9u8; 32]),
            addresses,
        )?;
        let record = identity.record().clone();

        let relay_err = match AccessRelayServer::bind(
            &identity,
            vec![record.clone()],
            SocketAddr::from(([127, 0, 0, 1], 0)),
            AccessRelayPolicy::default(),
        ) {
            Ok(_) => bail!("access relay should reject a gateway with the same identity"),
            Err(err) => err,
        };
        assert!(relay_err
            .to_string()
            .contains("must not share the same node identity"));

        let gateway_err = match SubmissionGatewayServer::bind(
            &identity,
            vec![record],
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &tempdir.path().to_string_lossy(),
            SubmissionGatewayPolicy::default(),
        ) {
            Ok(_) => bail!("submission gateway should reject a relay with the same identity"),
            Err(err) => err,
        };
        assert!(gateway_err
            .to_string()
            .contains("must not share the same node identity"));
        Ok(())
    }
}
