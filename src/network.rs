use crate::canonical::{self, CanonicalReader, CanonicalWriter};
use crate::consensus::{
    calculate_retarget_consensus, DEFAULT_MEM_KIB, RETARGET_INTERVAL, TARGET_LEADING_ZEROS,
};
use crate::epoch::{Anchor, MerkleTree};
use crate::metrics;
use crate::node_identity::{
    build_client_config, build_server_config, load_local_node_id, tls_peer_spki,
    verify_record_matches_tls, ExpectedPeerStore, NodeIdentity, NodeRecordV2, SignedEnvelope,
    TrustPolicy,
};
use crate::protocol::CURRENT as PROTOCOL;
use crate::storage::Store;
use crate::sync::SyncState;
use crate::{
    coin::{Coin, CoinCandidate},
    config, crypto,
    shielded::{
        local_archive_provider_manifest, route_checkpoint_requests, ArchiveDirectory,
        ArchiveProviderManifest, ArchiveShardBundle, CheckpointBatchRequest,
        CheckpointBatchResponse, CheckpointExtensionRequest, HistoricalUnspentExtension,
        ShieldedSyncServer,
    },
};
use anyhow::{anyhow, bail, Context, Result};
use once_cell::sync::Lazy;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint};
use rand::RngCore;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex as AsyncMutex, RwLock};
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

static QUIET_NET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet_logging(quiet: bool) {
    QUIET_NET.store(quiet, Ordering::Relaxed);
}

macro_rules! net_log {
    ($($arg:tt)*) => {
        if !QUIET_NET.load(Ordering::Relaxed) {
            println!($($arg)*);
        }
    };
}

#[allow(unused_imports)]
use net_log;

const MAX_WIRE_BYTES: usize = 8 * 1024 * 1024;
const HELLO_KNOWN_RECORDS: usize = 32;
const SEEN_TTL_SECS: u64 = 180;
const PENDING_ANCHOR_TTL_SECS: u64 = 300;
const REDIAL_INTERVAL_SECS: u64 = 15;
const IDENTITY_REFRESH_SECS: u64 = 3600;
const EPOCH_REPAIR_INTERVAL_SECS: u64 = 2;
const EPOCH_REPAIR_LOOKBACK: u64 = 32;
const RANGE_REQ_DEDUP_SECS: u64 = 5;
const HASH_REQ_DEDUP_SECS: u64 = 10;
const REQUEST_FANOUT_DEFAULT: usize = 2;
const REQUEST_FANOUT_HEADERS: usize = 3;
const REQUEST_FANOUT_TIP: usize = 4;
const REQUEST_FANOUT_RECOVERY: usize = 4;
const ARCHIVE_MANIFEST_REFRESH_SECS: u64 = 15;

static RECENT_HASH_REQS: Lazy<Mutex<HashMap<[u8; 32], Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static RECENT_RANGE_REQS: Lazy<Mutex<HashMap<u64, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub type NetHandle = Arc<Network>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitedMessage {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochLeavesBundle {
    pub epoch_num: u64,
    pub merkle_root: [u8; 32],
    pub leaves: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedIdsBundle {
    pub epoch_num: u64,
    pub merkle_root: [u8; 32],
    pub coin_ids: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCandidatesResponse {
    pub epoch_hash: [u8; 32],
    pub candidates: Vec<CoinCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochHeadersRange {
    pub start_height: u64,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactEpoch {
    pub anchor: Anchor,
    pub short_ids: Vec<[u8; 8]>,
    pub prefilled: Vec<(u32, Coin)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochGetTxn {
    pub epoch_hash: [u8; 32],
    pub indexes: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochTxn {
    pub epoch_hash: [u8; 32],
    pub indexes: Vec<u32>,
    pub coins: Vec<Coin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochHeadersBatch {
    pub start_height: u64,
    pub headers: Vec<Anchor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochByHash {
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct CheckpointBatchEvent {
    response_to_message_id: [u8; 32],
    provider_id: [u8; 32],
    response: CheckpointBatchResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveShardRequest {
    pub provider_id: [u8; 32],
    pub shard_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HelloMessage {
    record: NodeRecordV2,
    known_records: Vec<NodeRecordV2>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum WireTopic {
    Anchor,
    CoinCandidate,
    Coin,
    Tx,
    CompactEpoch,
    RateLimited,
    EpochLeaves,
    EpochSelectedResponse,
    EpochCandidatesResponse,
    EpochHeadersResponse,
    EpochByHashResponse,
    RequestEpoch,
    RequestEpochHeadersRange,
    RequestEpochByHash,
    RequestCoin,
    RequestLatestEpoch,
    RequestEpochTxn,
    EpochTxn,
    RequestEpochSelected,
    RequestEpochLeaves,
    RequestEpochCandidates,
    NodeRecord,
    ArchiveManifest,
    RequestArchiveShard,
    ArchiveShard,
    RequestCheckpointBatch,
    CheckpointBatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TopicFrame {
    topic: WireTopic,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireMessage {
    Hello(HelloMessage),
    Envelope(SignedEnvelope),
}

fn wire_topic_id(topic: WireTopic) -> u8 {
    match topic {
        WireTopic::Anchor => 1,
        WireTopic::CoinCandidate => 2,
        WireTopic::Coin => 3,
        WireTopic::Tx => 4,
        WireTopic::CompactEpoch => 5,
        WireTopic::RateLimited => 6,
        WireTopic::EpochLeaves => 7,
        WireTopic::EpochSelectedResponse => 8,
        WireTopic::EpochCandidatesResponse => 9,
        WireTopic::EpochHeadersResponse => 10,
        WireTopic::EpochByHashResponse => 11,
        WireTopic::RequestEpoch => 12,
        WireTopic::RequestEpochHeadersRange => 13,
        WireTopic::RequestEpochByHash => 14,
        WireTopic::RequestCoin => 15,
        WireTopic::RequestLatestEpoch => 16,
        WireTopic::RequestEpochTxn => 17,
        WireTopic::EpochTxn => 18,
        WireTopic::RequestEpochSelected => 19,
        WireTopic::RequestEpochLeaves => 20,
        WireTopic::RequestEpochCandidates => 21,
        WireTopic::NodeRecord => 22,
        WireTopic::ArchiveManifest => 23,
        WireTopic::RequestArchiveShard => 24,
        WireTopic::ArchiveShard => 25,
        WireTopic::RequestCheckpointBatch => 26,
        WireTopic::CheckpointBatch => 27,
    }
}

fn decode_wire_topic(id: u8) -> Result<WireTopic> {
    Ok(match id {
        1 => WireTopic::Anchor,
        2 => WireTopic::CoinCandidate,
        3 => WireTopic::Coin,
        4 => WireTopic::Tx,
        5 => WireTopic::CompactEpoch,
        6 => WireTopic::RateLimited,
        7 => WireTopic::EpochLeaves,
        8 => WireTopic::EpochSelectedResponse,
        9 => WireTopic::EpochCandidatesResponse,
        10 => WireTopic::EpochHeadersResponse,
        11 => WireTopic::EpochByHashResponse,
        12 => WireTopic::RequestEpoch,
        13 => WireTopic::RequestEpochHeadersRange,
        14 => WireTopic::RequestEpochByHash,
        15 => WireTopic::RequestCoin,
        16 => WireTopic::RequestLatestEpoch,
        17 => WireTopic::RequestEpochTxn,
        18 => WireTopic::EpochTxn,
        19 => WireTopic::RequestEpochSelected,
        20 => WireTopic::RequestEpochLeaves,
        21 => WireTopic::RequestEpochCandidates,
        22 => WireTopic::NodeRecord,
        23 => WireTopic::ArchiveManifest,
        24 => WireTopic::RequestArchiveShard,
        25 => WireTopic::ArchiveShard,
        26 => WireTopic::RequestCheckpointBatch,
        27 => WireTopic::CheckpointBatch,
        other => bail!("unsupported wire topic {}", other),
    })
}

fn encode_u64_body(value: u64) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.write_u64(value);
    writer.into_vec()
}

fn decode_u64_body(bytes: &[u8]) -> Result<u64> {
    let mut reader = CanonicalReader::new(bytes);
    let value = reader.read_u64()?;
    reader.finish()?;
    Ok(value)
}

fn encode_bytes32_body(value: &[u8; 32]) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(value);
    writer.into_vec()
}

fn decode_bytes32_body(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut reader = CanonicalReader::new(bytes);
    let value = reader.read_fixed()?;
    reader.finish()?;
    Ok(value)
}

fn encode_empty_body() -> Vec<u8> {
    Vec::new()
}

fn decode_empty_body(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        bail!("expected empty wire body")
    }
}

fn encode_archive_shard_request(request: &ArchiveShardRequest) -> Vec<u8> {
    let mut writer = CanonicalWriter::new();
    writer.write_fixed(&request.provider_id);
    writer.write_u64(request.shard_id);
    writer.into_vec()
}

fn decode_archive_shard_request(bytes: &[u8]) -> Result<ArchiveShardRequest> {
    let mut reader = CanonicalReader::new(bytes);
    let request = ArchiveShardRequest {
        provider_id: reader.read_fixed()?,
        shard_id: reader.read_u64()?,
    };
    reader.finish()?;
    Ok(request)
}

fn encode_topic_frame(topic: WireTopic, body: Vec<u8>) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(wire_topic_id(topic));
    writer.write_bytes(&body)?;
    Ok(writer.into_vec())
}

fn decode_topic_frame(bytes: &[u8]) -> Result<TopicFrame> {
    let mut reader = CanonicalReader::new(bytes);
    let topic = decode_wire_topic(reader.read_u8()?)?;
    let body = reader.read_bytes()?;
    reader.finish()?;
    Ok(TopicFrame { topic, body })
}

fn encode_hello_message(message: &HelloMessage) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(&canonical::encode_node_record(&message.record)?)?;
    writer.write_vec(&message.known_records, |writer, record| {
        writer.write_bytes(&canonical::encode_node_record(record)?)?;
        Ok(())
    })?;
    Ok(writer.into_vec())
}

fn decode_hello_message(bytes: &[u8]) -> Result<HelloMessage> {
    let mut reader = CanonicalReader::new(bytes);
    let record = canonical::decode_node_record(&reader.read_bytes()?)?;
    let known_records = reader.read_vec(|reader| {
        let bytes = reader.read_bytes()?;
        canonical::decode_node_record(&bytes)
    })?;
    reader.finish()?;
    Ok(HelloMessage {
        record,
        known_records,
    })
}

fn encode_wire_message(message: &WireMessage) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    match message {
        WireMessage::Hello(message) => {
            writer.write_u8(1);
            writer.write_bytes(&encode_hello_message(message)?)?;
        }
        WireMessage::Envelope(envelope) => {
            writer.write_u8(2);
            writer.write_bytes(&canonical::encode_signed_envelope(envelope)?)?;
        }
    }
    Ok(writer.into_vec())
}

fn decode_wire_message(bytes: &[u8]) -> Result<WireMessage> {
    let mut reader = CanonicalReader::new(bytes);
    let kind = reader.read_u8()?;
    let payload = reader.read_bytes()?;
    reader.finish()?;
    match kind {
        1 => Ok(WireMessage::Hello(decode_hello_message(&payload)?)),
        2 => Ok(WireMessage::Envelope(canonical::decode_signed_envelope(
            &payload,
        )?)),
        other => bail!("unsupported wire message {}", other),
    }
}

#[derive(Debug, Clone)]
struct PendingAnchor {
    anchor: Anchor,
    received_at: Instant,
}

#[derive(Clone)]
struct RuntimeState {
    db: Arc<Store>,
    sync_state: Arc<Mutex<SyncState>>,
    identity: Arc<RwLock<NodeIdentity>>,
    endpoint: Endpoint,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    client_config: quinn::ClientConfig,
    expected_peers: Arc<ExpectedPeerStore>,
    trust_policy: TrustPolicy,
    bootstrap_records: Vec<NodeRecordV2>,
    max_peers: usize,
    connection_timeout: Duration,
    published_addresses: Vec<String>,
    banned_node_ids: HashSet<[u8; 32]>,
    known_records: Arc<RwLock<HashMap<[u8; 32], NodeRecordV2>>>,
    peers: Arc<RwLock<HashMap<[u8; 32], Connection>>>,
    connected_peers: Arc<Mutex<HashSet<[u8; 32]>>>,
    pending_anchors: Arc<AsyncMutex<HashMap<u64, Vec<PendingAnchor>>>>,
    seen_messages: Arc<AsyncMutex<HashMap<[u8; 32], Instant>>>,
    anchor_tx: broadcast::Sender<Anchor>,
    tx_tx: broadcast::Sender<crate::transaction::Tx>,
    rate_limited_tx: broadcast::Sender<RateLimitedMessage>,
    headers_tx: broadcast::Sender<EpochHeadersBatch>,
    checkpoint_tx: broadcast::Sender<CheckpointBatchEvent>,
    archive_manifests: Arc<RwLock<HashMap<[u8; 32], ArchiveProviderManifest>>>,
    peer_exchange: bool,
}

#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    tx_tx: broadcast::Sender<crate::transaction::Tx>,
    rate_limited_tx: broadcast::Sender<RateLimitedMessage>,
    headers_tx: broadcast::Sender<EpochHeadersBatch>,
    checkpoint_tx: broadcast::Sender<CheckpointBatchEvent>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
    connected_peers: Arc<Mutex<HashSet<[u8; 32]>>>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    endpoint: Arc<AsyncMutex<Option<Endpoint>>>,
    db: Arc<Store>,
    archive_sync_timeout: Duration,
    local_node_id: [u8; 32],
    known_records: Arc<RwLock<HashMap<[u8; 32], NodeRecordV2>>>,
    archive_manifests: Arc<RwLock<HashMap<[u8; 32], ArchiveProviderManifest>>>,
}

enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(CoinCandidate),
    GossipTx(crate::transaction::Tx),
    GossipCompactEpoch(CompactEpoch),
    GossipRateLimited(RateLimitedMessage),
    RequestEpoch(u64),
    RequestEpochHeadersRange(EpochHeadersRange),
    RequestEpochByHash([u8; 32]),
    RequestCoin([u8; 32]),
    RequestLatestEpoch,
    RequestEpochTxn(EpochGetTxn),
    RequestEpochSelected(u64),
    RequestEpochLeaves(u64),
    GossipEpochLeaves(EpochLeavesBundle),
    RequestEpochCandidates([u8; 32]),
    RequestEpochDirect(u64),
    EnsureArchiveEpochs(Vec<u64>),
    RequestCheckpointBatch {
        record: NodeRecordV2,
        request: CheckpointBatchRequest,
        reply: oneshot::Sender<Result<[u8; 32]>>,
    },
    RedialBootstraps,
}

#[cfg(test)]
pub fn testing_stub_handle() -> NetHandle {
    let tempdir = tempfile::tempdir().expect("create tempdir for network stub");
    let db = Arc::new(
        Store::open(&tempdir.path().to_string_lossy()).expect("open temp store for network stub"),
    );
    std::mem::forget(tempdir);
    let (tx_tx, _) = broadcast::channel(1);
    let (anchor_tx, _) = broadcast::channel(1);
    let (rate_limited_tx, _) = broadcast::channel(1);
    let (headers_tx, _) = broadcast::channel::<EpochHeadersBatch>(1);
    let (checkpoint_tx, _) = broadcast::channel::<CheckpointBatchEvent>(1);
    let (command_tx, _) = mpsc::unbounded_channel();
    Arc::new(Network {
        anchor_tx,
        tx_tx,
        rate_limited_tx,
        headers_tx,
        checkpoint_tx,
        command_tx,
        connected_peers: Arc::new(Mutex::new(HashSet::new())),
        shutdown: CancellationToken::new(),
        tasks: TaskTracker::new(),
        endpoint: Arc::new(AsyncMutex::new(None)),
        db,
        archive_sync_timeout: Duration::from_secs(1),
        local_node_id: [0u8; 32],
        known_records: Arc::new(RwLock::new(HashMap::new())),
        archive_manifests: Arc::new(RwLock::new(HashMap::new())),
    })
}

pub fn peer_id_string() -> Result<String> {
    load_local_node_id()
}

impl RuntimeState {
    fn local_chain_id(&self) -> Option<[u8; 32]> {
        self.db.get_chain_id().ok()
    }

    async fn local_node_id(&self) -> [u8; 32] {
        self.identity.read().await.node_id()
    }

    async fn build_hello(&self) -> HelloMessage {
        let record = self.identity.read().await.record().clone();
        let known_records = {
            let guard = self.known_records.read().await;
            guard
                .values()
                .filter(|known| known.node_id != record.node_id)
                .take(HELLO_KNOWN_RECORDS)
                .cloned()
                .collect::<Vec<_>>()
        };
        HelloMessage {
            record,
            known_records,
        }
    }

    async fn refresh_local_identity(&self) -> Result<()> {
        let chain_id = self.local_chain_id();
        let refreshed = {
            let mut identity = self.identity.write().await;
            identity.refresh(PROTOCOL.version, chain_id, self.published_addresses.clone())?
        };
        if refreshed {
            let record = self.identity.read().await.record().clone();
            self.remember_record(record).await?;
        }
        Ok(())
    }

    async fn remember_record(&self, record: NodeRecordV2) -> Result<bool> {
        let now_unix_ms = unix_ms();
        record.validate(now_unix_ms)?;
        self.trust_policy.ensure_record_allowed(&record)?;
        if self.banned_node_ids.contains(&record.node_id) {
            bail!("record belongs to a banned node");
        }
        let local_node = self.local_node_id().await;
        if record.node_id == local_node {
            return Ok(false);
        }
        if !chain_compatible(self.local_chain_id(), record.chain_id) {
            bail!("record chain_id is incompatible with the local chain");
        }

        let mut should_store = false;
        {
            let mut guard = self.known_records.write().await;
            match guard.get(&record.node_id) {
                Some(existing) if existing.expires_unix_ms >= record.expires_unix_ms => {}
                _ => {
                    guard.insert(record.node_id, record.clone());
                    should_store = true;
                }
            }
        }
        if should_store {
            let bytes = canonical::encode_node_record(&record)?;
            self.db.store_node_record(&record.node_id, &bytes)?;
        }
        self.expected_peers.remember(&record);
        Ok(should_store)
    }

    async fn ingest_discovered_records(&self, records: Vec<NodeRecordV2>) {
        for record in records {
            match self.remember_record(record).await {
                Ok(_) => {}
                Err(e) => {
                    net_log!("⚠️  Ignoring discovered node record: {}", e);
                }
            }
        }
    }

    async fn local_archive_manifest(&self) -> Result<ArchiveProviderManifest> {
        let ledger = self.db.load_shielded_root_ledger()?.unwrap_or_default();
        let mut available_epochs = BTreeSet::new();
        for epoch in ledger.roots.keys() {
            if self.db.load_shielded_nullifier_epoch(*epoch)?.is_some() {
                available_epochs.insert(*epoch);
            }
        }
        local_archive_provider_manifest(
            self.local_node_id().await,
            &ledger,
            PROTOCOL.archive_shard_epoch_span,
            &available_epochs,
        )
    }

    async fn refresh_local_archive_manifest(&self) -> Result<ArchiveProviderManifest> {
        let manifest = self.local_archive_manifest().await?;
        self.db.store_shielded_archive_provider(&manifest)?;
        self.archive_manifests
            .write()
            .await
            .insert(manifest.provider_id, manifest.clone());
        Ok(manifest)
    }

    async fn local_archive_directory(&self) -> Result<ArchiveDirectory> {
        let ledger = self.db.load_shielded_root_ledger()?.unwrap_or_default();
        let mut providers = self
            .archive_manifests
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let local_manifest = self.local_archive_manifest().await?;
        if let Some(existing) = providers
            .iter_mut()
            .find(|existing| existing.provider_id == local_manifest.provider_id)
        {
            *existing = local_manifest;
        } else {
            providers.push(local_manifest);
        }
        ArchiveDirectory::from_root_ledger_and_providers(
            &ledger,
            PROTOCOL.archive_shard_epoch_span,
            providers,
        )
    }

    async fn build_local_checkpoint_batch_response(
        &self,
        request: &CheckpointBatchRequest,
    ) -> Result<Option<CheckpointBatchResponse>> {
        let manifest = self.local_archive_manifest().await?;
        if request.provider_id != manifest.provider_id {
            return Ok(None);
        }
        let directory = ArchiveDirectory::from_root_ledger_and_providers(
            &self.db.load_shielded_root_ledger()?.unwrap_or_default(),
            PROTOCOL.archive_shard_epoch_span,
            vec![manifest.clone()],
        )?;
        request.validate_against_manifest(&manifest, &directory)?;

        let mut server = ShieldedSyncServer::new();
        let mut needed_epochs = BTreeSet::new();
        for checkpoint_request in &request.requests {
            for query in &checkpoint_request.queries {
                needed_epochs.insert(query.epoch);
            }
        }
        for epoch in needed_epochs {
            let archived = self
                .db
                .load_shielded_nullifier_epoch(epoch)?
                .ok_or_else(|| anyhow!("missing nullifier archive for epoch {}", epoch))?;
            server.insert_archived_epoch(archived)?;
        }
        Ok(Some(CheckpointBatchResponse {
            provider_id: manifest.provider_id,
            provider_manifest_digest: manifest.manifest_digest,
            responses: server.serve_checkpoints_batch(&manifest, &request.requests)?,
        }))
    }

    async fn ingest_archive_manifest(
        &self,
        record: &NodeRecordV2,
        manifest: ArchiveProviderManifest,
    ) -> Result<()> {
        if manifest.provider_id != record.node_id {
            bail!("archive manifest provider id does not match the envelope signer");
        }
        let directory = ArchiveDirectory::from_root_ledger_and_providers(
            &self.db.load_shielded_root_ledger()?.unwrap_or_default(),
            PROTOCOL.archive_shard_epoch_span,
            vec![manifest.clone()],
        )?;
        manifest.validate(&directory)?;
        self.db.store_shielded_archive_provider(&manifest)?;
        self.archive_manifests
            .write()
            .await
            .insert(manifest.provider_id, manifest);
        Ok(())
    }

    async fn request_missing_archive_epochs(&self, epochs: &[u64]) -> Result<()> {
        if epochs.is_empty() {
            return Ok(());
        }
        let wanted = epochs.iter().copied().collect::<BTreeSet<_>>();
        let directory = self.local_archive_directory().await?;
        let mut available_epochs = BTreeSet::new();
        for epoch in &wanted {
            if self.db.load_shielded_nullifier_epoch(*epoch)?.is_some() {
                available_epochs.insert(*epoch);
            }
        }
        let missing_shards = directory.shard_ids_covering_epochs(&wanted, &available_epochs);
        let rotation_round = unix_ms();
        for shard_id in missing_shards {
            let provider = match directory.provider_for_shard(shard_id, rotation_round) {
                Ok(provider) => provider.clone(),
                Err(_) => continue,
            };
            let record = {
                let guard = self.known_records.read().await;
                guard.get(&provider.provider_id).cloned()
            };
            let Some(record) = record else {
                continue;
            };
            let _ = self
                .sign_and_send_to_record_related(
                    record,
                    WireTopic::RequestArchiveShard,
                    encode_archive_shard_request(&ArchiveShardRequest {
                        provider_id: provider.provider_id,
                        shard_id,
                    }),
                    None,
                )
                .await?;
        }
        Ok(())
    }

    async fn build_local_archive_shard_bundle(
        &self,
        request: &ArchiveShardRequest,
    ) -> Result<Option<ArchiveShardBundle>> {
        if request.provider_id != self.local_node_id().await {
            return Ok(None);
        }
        let manifest = self.local_archive_manifest().await?;
        let directory = ArchiveDirectory::from_root_ledger_and_providers(
            &self.db.load_shielded_root_ledger()?.unwrap_or_default(),
            PROTOCOL.archive_shard_epoch_span,
            vec![manifest.clone()],
        )?;
        let Some(shard) = directory.shard(request.shard_id).cloned() else {
            return Ok(None);
        };
        if !manifest.serves_shard(shard.shard_id, &shard.root_digest) {
            return Ok(None);
        }
        let mut epochs = Vec::with_capacity(shard.epoch_roots.len());
        for (epoch, _) in &shard.epoch_roots {
            let Some(archived) = self.db.load_shielded_nullifier_epoch(*epoch)? else {
                return Ok(None);
            };
            epochs.push(archived);
        }
        Ok(Some(ArchiveShardBundle {
            provider_id: manifest.provider_id,
            provider_manifest_digest: manifest.manifest_digest,
            shard,
            epochs,
        }))
    }

    async fn register_connection(
        &self,
        record: NodeRecordV2,
        connection: Connection,
    ) -> Result<()> {
        let existing = {
            let mut guard = self.peers.write().await;
            guard.insert(record.node_id, connection.clone())
        };
        if let Some(previous) = existing {
            previous.close(0u32.into(), b"superseded");
        }
        if let Ok(mut peers) = self.connected_peers.lock() {
            peers.insert(record.node_id);
            metrics::PEERS.set(peers.len() as i64);
        }
        let discovered = self.remember_record(record.clone()).await?;
        if discovered && self.peer_exchange {
            let _ = self
                .sign_and_broadcast(
                    WireTopic::NodeRecord,
                    canonical::encode_node_record(&record)?,
                )
                .await;
        }
        if let Ok(manifest) = self.refresh_local_archive_manifest().await {
            match canonical::encode_archive_provider_manifest(&manifest) {
                Ok(body) => match self
                    .sign_topic_envelope(WireTopic::ArchiveManifest, body)
                    .await
                {
                    Ok(envelope) => match encode_wire_message(&WireMessage::Envelope(envelope)) {
                        Ok(bytes) => {
                            if let Err(e) = self.maybe_send_bytes(&connection, &bytes).await {
                                net_log!(
                                    "⚠️  Failed to publish archive manifest to {}: {}",
                                    hex::encode(record.node_id),
                                    e
                                );
                            }
                        }
                        Err(e) => {
                            net_log!(
                                "⚠️  Failed to encode archive manifest for {}: {}",
                                hex::encode(record.node_id),
                                e
                            );
                        }
                    },
                    Err(e) => {
                        net_log!(
                            "⚠️  Failed to sign archive manifest for {}: {}",
                            hex::encode(record.node_id),
                            e
                        );
                    }
                },
                Err(e) => {
                    net_log!(
                        "⚠️  Failed to serialize archive manifest for {}: {}",
                        hex::encode(record.node_id),
                        e
                    );
                }
            }
        }
        Ok(())
    }

    async fn unregister_connection(&self, node_id: [u8; 32]) {
        {
            let mut guard = self.peers.write().await;
            guard.remove(&node_id);
        }
        if let Ok(mut peers) = self.connected_peers.lock() {
            peers.remove(&node_id);
            metrics::PEERS.set(peers.len() as i64);
        }
    }

    async fn maybe_send_bytes(&self, connection: &Connection, bytes: &[u8]) -> Result<()> {
        let mut stream = connection.open_uni().await?;
        stream.write_all(bytes).await?;
        stream.finish()?;
        Ok(())
    }

    async fn send_bytes_to_peer(&self, node_id: [u8; 32], bytes: &[u8]) -> Result<bool> {
        let connection = {
            let guard = self.peers.read().await;
            guard.get(&node_id).cloned()
        };
        let Some(connection) = connection else {
            return Ok(false);
        };
        if let Err(e) = self.maybe_send_bytes(&connection, bytes).await {
            net_log!("⚠️  Failed to send to {}: {}", hex::encode(node_id), e);
            self.unregister_connection(node_id).await;
            return Ok(false);
        }
        Ok(true)
    }

    async fn broadcast_envelope(
        &self,
        envelope: SignedEnvelope,
        exclude: Option<[u8; 32]>,
    ) -> Result<()> {
        let bytes = encode_wire_message(&WireMessage::Envelope(envelope))?;
        let peers = {
            let guard = self.peers.read().await;
            guard
                .iter()
                .filter_map(|(node_id, connection)| {
                    if exclude == Some(*node_id) {
                        None
                    } else {
                        Some((*node_id, connection.clone()))
                    }
                })
                .collect::<Vec<_>>()
        };
        for (node_id, connection) in peers {
            if let Err(e) = self.maybe_send_bytes(&connection, &bytes).await {
                net_log!("⚠️  Failed to send to {}: {}", hex::encode(node_id), e);
                self.unregister_connection(node_id).await;
            }
        }
        Ok(())
    }

    async fn sign_topic_envelope(&self, topic: WireTopic, body: Vec<u8>) -> Result<SignedEnvelope> {
        self.sign_topic_envelope_related(topic, body, None).await
    }

    async fn sign_topic_envelope_related(
        &self,
        topic: WireTopic,
        body: Vec<u8>,
        response_to_message_id: Option<[u8; 32]>,
    ) -> Result<SignedEnvelope> {
        let payload = encode_topic_frame(topic, body)?;
        let identity = self.identity.read().await.clone();
        let envelope = SignedEnvelope::new_related(
            &identity,
            PROTOCOL.version,
            self.local_chain_id(),
            payload,
            response_to_message_id,
        )?;
        self.mark_message_seen(envelope.message_id).await;
        Ok(envelope)
    }

    async fn sign_and_broadcast(&self, topic: WireTopic, body: Vec<u8>) -> Result<()> {
        let envelope = self.sign_topic_envelope(topic, body).await?;
        self.broadcast_envelope(envelope, None).await
    }

    async fn sign_and_send_to_peer_related(
        &self,
        node_id: [u8; 32],
        topic: WireTopic,
        body: Vec<u8>,
        response_to_message_id: Option<[u8; 32]>,
    ) -> Result<bool> {
        let bytes = encode_wire_message(&WireMessage::Envelope(
            self.sign_topic_envelope_related(topic, body, response_to_message_id)
                .await?,
        ))?;
        self.send_bytes_to_peer(node_id, &bytes).await
    }

    async fn sign_and_send_to_targets(
        &self,
        topic: WireTopic,
        body: Vec<u8>,
        fanout: usize,
    ) -> Result<usize> {
        let targets = self.select_request_targets(topic, &body, fanout).await;
        if targets.is_empty() {
            return Ok(0);
        }
        let bytes = encode_wire_message(&WireMessage::Envelope(
            self.sign_topic_envelope(topic, body).await?,
        ))?;
        let mut sent = 0usize;
        for record in targets {
            if self.send_bytes_to_target(record, bytes.clone()).await? {
                sent += 1;
            }
        }
        Ok(sent)
    }

    async fn sign_and_send_to_record_related(
        &self,
        record: NodeRecordV2,
        topic: WireTopic,
        body: Vec<u8>,
        response_to_message_id: Option<[u8; 32]>,
    ) -> Result<bool> {
        let bytes = encode_wire_message(&WireMessage::Envelope(
            self.sign_topic_envelope_related(topic, body, response_to_message_id)
                .await?,
        ))?;
        self.send_bytes_to_target(record, bytes).await
    }

    async fn sign_and_send_to_record_related_with_id(
        &self,
        record: NodeRecordV2,
        topic: WireTopic,
        body: Vec<u8>,
        response_to_message_id: Option<[u8; 32]>,
    ) -> Result<[u8; 32]> {
        let envelope = self
            .sign_topic_envelope_related(topic, body, response_to_message_id)
            .await?;
        let message_id = envelope.message_id;
        let bytes = encode_wire_message(&WireMessage::Envelope(envelope))?;
        let _ = self.send_bytes_to_target(record, bytes).await?;
        Ok(message_id)
    }

    async fn send_bytes_to_target(&self, record: NodeRecordV2, bytes: Vec<u8>) -> Result<bool> {
        if self.send_bytes_to_peer(record.node_id, &bytes).await? {
            return Ok(true);
        }
        self.schedule_dial_and_send(record, bytes);
        Ok(false)
    }

    fn schedule_dial_and_send(&self, record: NodeRecordV2, bytes: Vec<u8>) {
        let state = self.clone();
        self.tasks.spawn(async move {
            if let Err(e) = state.dial_record(record.clone()).await {
                net_log!(
                    "⚠️  Failed to dial request target {}: {}",
                    hex::encode(record.node_id),
                    e
                );
                return;
            }
            if let Err(e) = state.send_bytes_to_peer(record.node_id, &bytes).await {
                net_log!(
                    "⚠️  Failed to send queued request to {}: {}",
                    hex::encode(record.node_id),
                    e
                );
            }
        });
    }

    fn schedule_dial(&self, record: NodeRecordV2) {
        let state = self.clone();
        self.tasks.spawn(async move {
            if let Err(e) = state.dial_record(record.clone()).await {
                net_log!(
                    "⚠️  Failed to dial discovered peer {}: {}",
                    hex::encode(record.node_id),
                    e
                );
            }
        });
    }

    async fn select_request_targets(
        &self,
        topic: WireTopic,
        body: &[u8],
        fanout: usize,
    ) -> Vec<NodeRecordV2> {
        let route_key = request_route_key(topic, body);
        let connected = {
            let guard = self.peers.read().await;
            guard.keys().copied().collect::<HashSet<_>>()
        };
        let local_node_id = self.local_node_id().await;
        let local_chain_id = self.local_chain_id();
        let mut records = {
            let guard = self.known_records.read().await;
            guard.values().cloned().collect::<Vec<_>>()
        };
        records.retain(|record| {
            record.node_id != local_node_id
                && !self.banned_node_ids.contains(&record.node_id)
                && chain_compatible(local_chain_id, record.chain_id)
        });
        records.sort_by_key(|record| {
            (
                !connected.contains(&record.node_id),
                request_route_rank(&route_key, &record.node_id),
            )
        });
        if fanout < records.len() {
            records.truncate(fanout);
        }
        records
    }

    async fn mark_message_seen(&self, message_id: [u8; 32]) -> bool {
        let now = Instant::now();
        let mut guard = self.seen_messages.lock().await;
        guard.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(SEEN_TTL_SECS));
        guard.insert(message_id, now).is_none()
    }

    async fn validate_peer_record(
        &self,
        record: NodeRecordV2,
        expected: Option<&NodeRecordV2>,
        tls_spki: &[u8],
    ) -> Result<NodeRecordV2> {
        record.validate(unix_ms())?;
        self.trust_policy.ensure_record_allowed(&record)?;
        if record.protocol_version != PROTOCOL.version {
            bail!("protocol version mismatch");
        }
        if !chain_compatible(self.local_chain_id(), record.chain_id) {
            bail!("record chain_id is incompatible with the local chain");
        }
        if self.banned_node_ids.contains(&record.node_id) {
            bail!("remote node is banned");
        }
        if record.node_id == self.local_node_id().await {
            bail!("remote node record matches the local node");
        }
        verify_record_matches_tls(&record, tls_spki)?;
        if let Some(expected) = expected {
            if expected.node_id != record.node_id || expected.root_spki != record.root_spki {
                bail!("remote node record does not match the expected bootstrap identity");
            }
        }
        Ok(record)
    }

    async fn dial_record(&self, record: NodeRecordV2) -> Result<()> {
        if self.banned_node_ids.contains(&record.node_id) {
            return Ok(());
        }
        if record.node_id == self.local_node_id().await {
            return Ok(());
        }
        if self.peers.read().await.contains_key(&record.node_id) {
            return Ok(());
        }
        if self.peers.read().await.len() >= self.max_peers {
            return Ok(());
        }

        self.expected_peers.remember(&record);
        let addr = record.primary_address()?;
        let server_name = record.server_name();
        let connecting =
            self.endpoint
                .connect_with(self.client_config.clone(), addr, &server_name)?;
        let connection = tokio::time::timeout(self.connection_timeout, connecting)
            .await
            .context("outbound dial timed out")??;
        let tls_spki = tls_peer_spki(connection.peer_identity())?;

        let (mut send, mut recv) = connection.open_bi().await?;
        write_wire_message(&mut send, &WireMessage::Hello(self.build_hello().await)).await?;
        let remote_hello = read_hello_message(&mut recv).await?;
        let remote_record = self
            .validate_peer_record(remote_hello.record, Some(&record), &tls_spki)
            .await?;
        drop(send);
        drop(recv);
        self.ingest_discovered_records(remote_hello.known_records)
            .await;
        self.register_connection(remote_record.clone(), connection.clone())
            .await?;
        let state = self.clone();
        self.tasks.spawn(async move {
            state.run_connection(remote_record, connection).await;
        });
        Ok(())
    }

    async fn accept_connection(&self, incoming: quinn::Incoming) -> Result<()> {
        let connection = tokio::time::timeout(self.connection_timeout, incoming)
            .await
            .context("inbound handshake timed out")??;
        let tls_spki = tls_peer_spki(connection.peer_identity())?;
        let (mut send, mut recv) = connection.accept_bi().await?;
        let remote_hello = read_hello_message(&mut recv).await?;
        let remote_record = self
            .validate_peer_record(remote_hello.record, None, &tls_spki)
            .await?;
        write_wire_message(&mut send, &WireMessage::Hello(self.build_hello().await)).await?;
        drop(send);
        drop(recv);
        self.ingest_discovered_records(remote_hello.known_records)
            .await;
        self.register_connection(remote_record.clone(), connection.clone())
            .await?;
        let state = self.clone();
        self.tasks.spawn(async move {
            state.run_connection(remote_record, connection).await;
        });
        Ok(())
    }

    async fn run_connection(&self, record: NodeRecordV2, connection: Connection) {
        loop {
            match tokio::select! {
                _ = self.shutdown.cancelled() => {
                    connection.close(0u32.into(), b"shutdown");
                    break;
                }
                result = connection.accept_uni() => result,
            } {
                Ok(mut recv) => {
                    let bytes = match recv.read_to_end(MAX_WIRE_BYTES).await {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            net_log!(
                                "⚠️  Failed reading stream from {}: {}",
                                hex::encode(record.node_id),
                                e
                            );
                            break;
                        }
                    };
                    let message: WireMessage = match decode_wire_message(&bytes) {
                        Ok(message) => message,
                        Err(e) => {
                            net_log!(
                                "⚠️  Invalid wire message from {}: {}",
                                hex::encode(record.node_id),
                                e
                            );
                            connection.close(0u32.into(), b"invalid-wire-message");
                            break;
                        }
                    };
                    match message {
                        WireMessage::Hello(_) => {
                            net_log!(
                                "⚠️  Protocol violation from {}: unexpected post-handshake hello",
                                hex::encode(record.node_id)
                            );
                            connection.close(0u32.into(), b"protocol-violation");
                            break;
                        }
                        WireMessage::Envelope(envelope) => {
                            if let Err(e) = self.handle_envelope(record.clone(), envelope).await {
                                net_log!(
                                    "⚠️  Dropping envelope from {}: {}",
                                    hex::encode(record.node_id),
                                    e
                                );
                                connection.close(0u32.into(), b"invalid-envelope");
                                break;
                            }
                        }
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
                Err(quinn::ConnectionError::LocallyClosed) => break,
                Err(e) => {
                    net_log!(
                        "⚠️  Connection to {} closed: {}",
                        hex::encode(record.node_id),
                        e
                    );
                    break;
                }
            }
        }
        self.unregister_connection(record.node_id).await;
    }

    async fn handle_envelope(
        &self,
        connection_record: NodeRecordV2,
        envelope: SignedEnvelope,
    ) -> Result<()> {
        let connection_node_id = connection_record.node_id;
        let response_to_message_id = envelope.response_to_message_id;
        let author_record = if envelope.node_id == connection_record.node_id {
            connection_record
        } else {
            let discovered = {
                let guard = self.known_records.read().await;
                guard.get(&envelope.node_id).cloned()
            };
            let Some(discovered) = discovered else {
                net_log!(
                    "⚠️  Dropping relayed envelope from unknown author {} via {}",
                    hex::encode(envelope.node_id),
                    hex::encode(connection_record.node_id)
                );
                return Ok(());
            };
            discovered
        };
        envelope.verify(&author_record, unix_ms())?;
        let first_time = self.mark_message_seen(envelope.message_id).await;
        let frame: TopicFrame = decode_topic_frame(&envelope.payload)?;
        if first_time && should_relay_topic(frame.topic) {
            self.broadcast_envelope(envelope.clone(), Some(connection_node_id))
                .await?;
        }
        self.handle_topic(
            author_record,
            envelope.message_id,
            response_to_message_id,
            frame,
        )
        .await
    }

    async fn handle_topic(
        &self,
        record: NodeRecordV2,
        message_id: [u8; 32],
        response_to_message_id: Option<[u8; 32]>,
        frame: TopicFrame,
    ) -> Result<()> {
        match frame.topic {
            WireTopic::Anchor | WireTopic::EpochByHashResponse => {
                let anchor = canonical::decode_anchor(&frame.body)?;
                self.handle_anchor(anchor).await?;
            }
            WireTopic::CoinCandidate => {
                let candidate = canonical::decode_coin_candidate(&frame.body)?;
                if validate_coin_candidate(&candidate, &self.db).is_ok() {
                    let key = Store::candidate_key(&candidate.epoch_hash, &candidate.id);
                    self.db.put("coin_candidate", &key, &candidate)?;
                } else {
                    metrics::VALIDATION_FAIL_COIN.inc();
                }
            }
            WireTopic::Coin => {
                let coin = canonical::decode_coin(&frame.body)?;
                self.db.put("coin", &coin.id, &coin)?;
                if let Ok(Some(anchor)) = self.db.get::<Anchor>("anchor", &coin.epoch_hash) {
                    let _ = self.db.put_coin_epoch(&coin.id, anchor.num);
                }
            }
            WireTopic::Tx => {
                let tx = canonical::decode_tx(&frame.body)?;
                match validate_tx(&tx, &self.db) {
                    Ok(()) => {
                        tx.apply(&self.db)?;
                        let _ = self.tx_tx.send(tx);
                    }
                    Err(err) => return Err(anyhow!("rejecting invalid tx: {err}")),
                }
            }
            WireTopic::CompactEpoch => {
                let compact = canonical::decode_compact_epoch(&frame.body)?;
                metrics::COMPACT_EPOCHS_RECV.inc();
                self.handle_anchor(compact.anchor).await?;
            }
            WireTopic::RateLimited => {
                let msg = canonical::decode_rate_limited_message(&frame.body)?;
                let _ = self.rate_limited_tx.send(msg);
            }
            WireTopic::NodeRecord => {
                let discovered = canonical::decode_node_record(&frame.body)?;
                let is_new = self.remember_record(discovered.clone()).await?;
                if is_new {
                    if self.peer_exchange {
                        let _ = self
                            .sign_and_broadcast(
                                WireTopic::NodeRecord,
                                canonical::encode_node_record(&discovered)?,
                            )
                            .await;
                    }
                    self.schedule_dial(discovered);
                }
            }
            WireTopic::EpochLeaves => {
                let bundle = canonical::decode_epoch_leaves_bundle(&frame.body)?;
                let epoch_num = bundle.epoch_num;
                self.store_epoch_leaves_bundle(bundle)?;
                self.repair_epoch_state(epoch_num).await?;
            }
            WireTopic::EpochSelectedResponse => {
                let bundle = canonical::decode_selected_ids_bundle(&frame.body)?;
                let epoch_num = bundle.epoch_num;
                self.store_selected_ids_bundle(bundle)?;
                self.repair_epoch_state(epoch_num).await?;
            }
            WireTopic::EpochCandidatesResponse => {
                let response = canonical::decode_epoch_candidates_response(&frame.body)?;
                for candidate in response.candidates {
                    if validate_coin_candidate(&candidate, &self.db).is_ok() {
                        let key = Store::candidate_key(&candidate.epoch_hash, &candidate.id);
                        let _ = self.db.put("coin_candidate", &key, &candidate);
                    }
                }
            }
            WireTopic::EpochHeadersResponse => {
                let batch = canonical::decode_epoch_headers_batch(&frame.body)?;
                if let Some(last) = batch.headers.last() {
                    if let Ok(mut sync) = self.sync_state.lock() {
                        sync.highest_seen_epoch = sync.highest_seen_epoch.max(last.num);
                    }
                }
                let _ = self.headers_tx.send(batch);
            }
            WireTopic::RequestEpoch => {
                let epoch = decode_u64_body(&frame.body)?;
                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", &epoch.to_le_bytes()) {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::Anchor,
                            canonical::encode_anchor(&anchor)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestEpochHeadersRange => {
                let range = canonical::decode_epoch_headers_range(&frame.body)?;
                let mut headers = Vec::new();
                let end = range.start_height.saturating_add(range.count as u64);
                for height in range.start_height..end {
                    match self.db.get::<Anchor>("epoch", &height.to_le_bytes())? {
                        Some(anchor) => headers.push(anchor),
                        None => break,
                    }
                }
                if !headers.is_empty() {
                    let batch = EpochHeadersBatch {
                        start_height: range.start_height,
                        headers,
                    };
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::EpochHeadersResponse,
                            canonical::encode_epoch_headers_batch(&batch)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestEpochByHash => {
                let req = canonical::decode_epoch_by_hash(&frame.body)?;
                if let Ok(Some(anchor)) = self.db.get::<Anchor>("anchor", &req.hash) {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::EpochByHashResponse,
                            canonical::encode_anchor(&anchor)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestCoin => {
                let coin_id = decode_bytes32_body(&frame.body)?;
                if let Ok(Some(coin)) = self.db.get::<Coin>("coin", &coin_id) {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::Coin,
                            canonical::encode_coin(&coin)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestLatestEpoch => {
                decode_empty_body(&frame.body)?;
                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::Anchor,
                            canonical::encode_anchor(&anchor)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestEpochTxn => {
                let req = canonical::decode_epoch_get_txn(&frame.body)?;
                let txn = self.lookup_epoch_txn(&req)?;
                if !txn.coins.is_empty() {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::EpochTxn,
                            canonical::encode_epoch_txn(&txn)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::EpochTxn => {
                let txn = canonical::decode_epoch_txn(&frame.body)?;
                let epoch_num = self
                    .db
                    .get::<Anchor>("anchor", &txn.epoch_hash)?
                    .map(|anchor| anchor.num)
                    .ok_or_else(|| anyhow!("epoch txn references unknown anchor"))?;
                self.store_epoch_txn(txn)?;
                self.repair_epoch_state(epoch_num).await?;
            }
            WireTopic::RequestEpochSelected => {
                let epoch_num = decode_u64_body(&frame.body)?;
                let ids = self.db.get_selected_coin_ids_for_epoch(epoch_num)?;
                if !ids.is_empty() {
                    let merkle_root = MerkleTree::build_root(&ids.iter().copied().collect());
                    let bundle = SelectedIdsBundle {
                        epoch_num,
                        merkle_root,
                        coin_ids: ids,
                    };
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::EpochSelectedResponse,
                            canonical::encode_selected_ids_bundle(&bundle)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestEpochLeaves => {
                let epoch_num = decode_u64_body(&frame.body)?;
                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                    if let Ok(Some(leaves)) = self.db.get_epoch_leaves(epoch_num) {
                        let bundle = EpochLeavesBundle {
                            epoch_num,
                            merkle_root: anchor.merkle_root,
                            leaves,
                        };
                        let _ = self
                            .sign_and_send_to_peer_related(
                                record.node_id,
                                WireTopic::EpochLeaves,
                                canonical::encode_epoch_leaves_bundle(&bundle)?,
                                Some(message_id),
                            )
                            .await?;
                    }
                }
            }
            WireTopic::RequestEpochCandidates => {
                let epoch_hash = decode_bytes32_body(&frame.body)?;
                let candidates = self.db.get_coin_candidates_by_epoch_hash(&epoch_hash)?;
                if !candidates.is_empty() {
                    let response = EpochCandidatesResponse {
                        epoch_hash,
                        candidates,
                    };
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::EpochCandidatesResponse,
                            canonical::encode_epoch_candidates_response(&response)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::RequestCheckpointBatch => {
                let request = canonical::decode_checkpoint_batch_request(&frame.body)?;
                if let Some(response) = self.build_local_checkpoint_batch_response(&request).await?
                {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::CheckpointBatch,
                            canonical::encode_checkpoint_batch_response(&response)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::CheckpointBatch => {
                let response = canonical::decode_checkpoint_batch_response(&frame.body)?;
                if response.provider_id != record.node_id {
                    bail!("checkpoint batch response provider does not match the envelope signer");
                }
                let response_to_message_id = response_to_message_id
                    .ok_or_else(|| anyhow!("checkpoint batch response is missing correlation"))?;
                let _ = self.checkpoint_tx.send(CheckpointBatchEvent {
                    response_to_message_id,
                    provider_id: response.provider_id,
                    response,
                });
            }
            WireTopic::ArchiveManifest => {
                let manifest = canonical::decode_archive_provider_manifest(&frame.body)?;
                self.ingest_archive_manifest(&record, manifest.clone())
                    .await?;
                let wanted = (manifest.coverage_first_epoch..=manifest.coverage_last_epoch)
                    .collect::<Vec<_>>();
                self.request_missing_archive_epochs(&wanted).await?;
            }
            WireTopic::RequestArchiveShard => {
                let request = decode_archive_shard_request(&frame.body)?;
                if let Some(bundle) = self.build_local_archive_shard_bundle(&request).await? {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::ArchiveShard,
                            canonical::encode_archive_shard_bundle(&bundle)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::ArchiveShard => {
                let bundle = canonical::decode_archive_shard_bundle(&frame.body)?;
                if bundle.provider_id != record.node_id {
                    bail!("archive shard bundle provider does not match the envelope signer");
                }
                let directory = self.local_archive_directory().await?;
                let manifest = directory.provider(&bundle.provider_id)?.clone();
                bundle.validate(&manifest, &directory)?;
                for archived in bundle.epochs {
                    self.db.store_shielded_nullifier_epoch(&archived)?;
                }
                let _ = self.refresh_local_archive_manifest().await;
            }
        }

        if let Ok(mut sync) = self.sync_state.lock() {
            sync.highest_seen_epoch = sync.highest_seen_epoch.max(
                record
                    .chain_id
                    .and_then(|_| self.db.get::<Anchor>("epoch", b"latest").ok().flatten())
                    .map(|anchor| anchor.num)
                    .unwrap_or(sync.highest_seen_epoch),
            );
        }
        Ok(())
    }

    fn lookup_epoch_txn(&self, req: &EpochGetTxn) -> Result<EpochTxn> {
        let Some(anchor) = self.db.get::<Anchor>("anchor", &req.epoch_hash)? else {
            return Ok(EpochTxn {
                epoch_hash: req.epoch_hash,
                indexes: Vec::new(),
                coins: Vec::new(),
            });
        };
        let ids = self.db.get_selected_coin_ids_for_epoch(anchor.num)?;
        let mut indexes = Vec::new();
        let mut coins = Vec::new();
        for index in &req.indexes {
            if let Some(coin_id) = ids.get(*index as usize) {
                if let Some(coin) = self.db.get::<Coin>("coin", coin_id)? {
                    indexes.push(*index);
                    coins.push(coin);
                }
            }
        }
        Ok(EpochTxn {
            epoch_hash: req.epoch_hash,
            indexes,
            coins,
        })
    }

    fn store_epoch_leaves_bundle(&self, bundle: EpochLeavesBundle) -> Result<()> {
        let computed = MerkleTree::compute_root_from_sorted_leaves(&bundle.leaves);
        if computed != bundle.merkle_root {
            bail!("epoch leaves bundle merkle root mismatch");
        }
        if let Some(anchor) = self
            .db
            .get::<Anchor>("epoch", &bundle.epoch_num.to_le_bytes())?
        {
            if anchor.merkle_root != bundle.merkle_root {
                bail!("epoch leaves bundle does not match local anchor");
            }
        }
        self.db
            .store_epoch_leaves(bundle.epoch_num, &bundle.leaves)?;
        let levels = MerkleTree::build_levels_from_sorted_leaves(&bundle.leaves);
        self.db.store_epoch_levels(bundle.epoch_num, &levels)?;
        Ok(())
    }

    fn store_selected_ids_bundle(&self, bundle: SelectedIdsBundle) -> Result<()> {
        let computed_root = MerkleTree::build_root(&bundle.coin_ids.iter().copied().collect());
        if computed_root != bundle.merkle_root {
            bail!("selected ids bundle merkle root mismatch");
        }
        if let Some(anchor) = self
            .db
            .get::<Anchor>("epoch", &bundle.epoch_num.to_le_bytes())?
        {
            if anchor.merkle_root != bundle.merkle_root {
                bail!("selected ids bundle does not match local anchor");
            }
            if anchor.coin_count as usize != bundle.coin_ids.len() {
                bail!("selected ids bundle coin count does not match local anchor");
            }
        }
        let mut batch = WriteBatch::default();
        let Some(sel_cf) = self.db.db.cf_handle("epoch_selected") else {
            bail!("epoch_selected column family missing");
        };
        for coin_id in bundle.coin_ids {
            let mut key = Vec::with_capacity(8 + 32);
            key.extend_from_slice(&bundle.epoch_num.to_le_bytes());
            key.extend_from_slice(&coin_id);
            batch.put_cf(sel_cf, &key, &[]);
        }
        self.db.write_batch(batch)?;
        Ok(())
    }

    async fn repair_epoch_state(&self, epoch_num: u64) -> Result<()> {
        let Some(anchor) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes())? else {
            return Ok(());
        };
        let ids = self.db.get_selected_coin_ids_for_epoch(epoch_num)?;
        if ids.is_empty() {
            let _ = self
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochSelected,
                    encode_u64_body(epoch_num),
                    REQUEST_FANOUT_RECOVERY,
                )
                .await?;
        } else {
            let mut indexes = Vec::new();
            for (index, coin_id) in ids.iter().enumerate() {
                if self.db.get::<Coin>("coin", coin_id)?.is_none() {
                    indexes.push(index as u32);
                }
            }
            if !indexes.is_empty() {
                let _ = self
                    .sign_and_send_to_targets(
                        WireTopic::RequestEpochTxn,
                        canonical::encode_epoch_get_txn(&EpochGetTxn {
                            epoch_hash: anchor.hash,
                            indexes,
                        })?,
                        REQUEST_FANOUT_RECOVERY,
                    )
                    .await?;
            }
        }
        if self.db.get_epoch_leaves(epoch_num)?.is_none() {
            let _ = self
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochLeaves,
                    encode_u64_body(epoch_num),
                    REQUEST_FANOUT_RECOVERY,
                )
                .await?;
        }
        Ok(())
    }

    async fn repair_recent_epochs(&self) -> Result<()> {
        let Some(latest) = self.db.get::<Anchor>("epoch", b"latest")? else {
            return Ok(());
        };
        let start = latest
            .num
            .saturating_sub(EPOCH_REPAIR_LOOKBACK.saturating_sub(1));
        for epoch_num in start..=latest.num {
            let Some(anchor) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes())? else {
                continue;
            };
            if anchor.coin_count == 0 {
                continue;
            }
            self.repair_epoch_state(epoch_num).await?;
        }
        Ok(())
    }

    fn store_epoch_txn(&self, txn: EpochTxn) -> Result<Vec<[u8; 32]>> {
        if txn.indexes.len() != txn.coins.len() {
            bail!("epoch txn indexes length does not match coin payloads");
        }
        let Some(anchor) = self.db.get::<Anchor>("anchor", &txn.epoch_hash)? else {
            bail!("epoch txn references unknown anchor");
        };
        let ids = self.db.get_selected_coin_ids_for_epoch(anchor.num)?;
        if ids.is_empty() {
            bail!("epoch txn arrived before selected ids were recovered");
        }
        let Some(coin_cf) = self.db.db.cf_handle("coin") else {
            bail!("coin column family missing");
        };
        let Some(coin_epoch_cf) = self.db.db.cf_handle("coin_epoch") else {
            bail!("coin_epoch column family missing");
        };
        let Some(rev_cf) = self.db.db.cf_handle("coin_epoch_by_epoch") else {
            bail!("coin_epoch_by_epoch column family missing");
        };

        let mut batch = WriteBatch::default();
        let mut recovered = Vec::with_capacity(txn.coins.len());
        for (index, coin) in txn.indexes.into_iter().zip(txn.coins.into_iter()) {
            let Some(expected_coin_id) = ids.get(index as usize) else {
                bail!("epoch txn index {} is out of range", index);
            };
            if &coin.id != expected_coin_id {
                bail!("epoch txn coin id does not match selected ids bundle");
            }
            let coin_bytes = bincode::serialize(&coin)?;
            batch.put_cf(coin_cf, &coin.id, &coin_bytes);
            batch.put_cf(coin_epoch_cf, &coin.id, &anchor.num.to_le_bytes());
            let mut rev_key = Vec::with_capacity(8 + 32);
            rev_key.extend_from_slice(&anchor.num.to_le_bytes());
            rev_key.extend_from_slice(&coin.id);
            batch.put_cf(rev_cf, &rev_key, &[]);
            recovered.push(coin.id);
        }
        self.db.write_batch(batch)?;
        Ok(recovered)
    }

    async fn buffer_anchor(&self, anchor: Anchor) {
        let mut pending = self.pending_anchors.lock().await;
        let entry = pending.entry(anchor.num).or_default();
        if !entry
            .iter()
            .any(|existing| existing.anchor.hash == anchor.hash)
        {
            entry.push(PendingAnchor {
                anchor,
                received_at: Instant::now(),
            });
        }
    }

    async fn process_pending_anchors(&self, starting_height: u64) -> Result<()> {
        let mut height = starting_height;
        loop {
            let candidates = {
                let mut pending = self.pending_anchors.lock().await;
                let now = Instant::now();
                pending.retain(|_, anchors| {
                    anchors.retain(|anchor| {
                        now.duration_since(anchor.received_at)
                            < Duration::from_secs(PENDING_ANCHOR_TTL_SECS)
                    });
                    !anchors.is_empty()
                });
                pending.remove(&height)
            };
            let Some(mut candidates) = candidates else {
                break;
            };
            candidates.sort_by(|a, b| {
                b.anchor
                    .cumulative_work
                    .cmp(&a.anchor.cumulative_work)
                    .then_with(|| b.anchor.num.cmp(&a.anchor.num))
            });

            let mut adopted = false;
            let mut rejected = Vec::new();
            for pending in candidates {
                if validate_anchor(&pending.anchor, &self.db).is_ok() {
                    let current_best = self.db.get::<Anchor>("epoch", b"latest")?;
                    if pending.anchor.is_better_chain(&current_best) {
                        self.adopt_anchor(pending.anchor.clone()).await?;
                    }
                    adopted = true;
                } else {
                    rejected.push(pending);
                }
            }
            if !rejected.is_empty() {
                let mut pending = self.pending_anchors.lock().await;
                pending.entry(height).or_default().extend(rejected);
            }
            if !adopted {
                break;
            }
            height = height.saturating_add(1);
        }
        Ok(())
    }

    async fn handle_anchor(&self, anchor: Anchor) -> Result<()> {
        if let Ok(mut sync) = self.sync_state.lock() {
            sync.highest_seen_epoch = sync.highest_seen_epoch.max(anchor.num);
            sync.peer_confirmed_tip = true;
        }
        self.db.put("anchor", &anchor.hash, &anchor)?;
        if let Ok(Some(latest)) = self.db.get::<Anchor>("epoch", b"latest") {
            if latest.hash == anchor.hash {
                return Ok(());
            }
        }

        match validate_anchor(&anchor, &self.db) {
            Ok(()) => {
                let current_best = self.db.get::<Anchor>("epoch", b"latest")?;
                if anchor.is_better_chain(&current_best) {
                    self.adopt_anchor(anchor.clone()).await?;
                }
                self.process_pending_anchors(anchor.num.saturating_add(1))
                    .await?;
            }
            Err(err) => {
                metrics::VALIDATION_FAIL_ANCHOR.inc();
                self.buffer_anchor(anchor.clone()).await;
                if anchor.num > 0 {
                    let _ = self
                        .sign_and_send_to_targets(
                            WireTopic::RequestEpoch,
                            encode_u64_body(anchor.num.saturating_sub(1)),
                            REQUEST_FANOUT_RECOVERY,
                        )
                        .await;
                    if err.contains("Retarget window incomplete") || err.contains("Previous anchor")
                    {
                        let start = anchor.num.saturating_sub(64);
                        let range = EpochHeadersRange {
                            start_height: start,
                            count: 128,
                        };
                        let _ = self
                            .sign_and_send_to_targets(
                                WireTopic::RequestEpochHeadersRange,
                                canonical::encode_epoch_headers_range(&range),
                                REQUEST_FANOUT_HEADERS,
                            )
                            .await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn adopt_anchor(&self, anchor: Anchor) -> Result<()> {
        self.db.put("epoch", &anchor.num.to_le_bytes(), &anchor)?;
        self.db.put("epoch", b"latest", &anchor)?;
        metrics::EPOCH_HEIGHT.set(anchor.num as i64);
        if let Err(e) = persist_selected_for_anchor(&self.db, &anchor) {
            net_log!(
                "⚠️  Unable to reconstruct selected coins for epoch {}: {}",
                anchor.num,
                e
            );
            let _ = self.repair_epoch_state(anchor.num).await;
        }
        let _ = self.anchor_tx.send(anchor);
        Ok(())
    }
}

pub async fn spawn(
    net_cfg: config::Net,
    _p2p_cfg: config::P2p,
    db: Arc<Store>,
    sync_state: Arc<Mutex<SyncState>>,
) -> Result<NetHandle> {
    if net_cfg.quiet_by_default {
        set_quiet_logging(true);
    }

    let published_addresses = published_addresses(&net_cfg);
    let identity = NodeIdentity::load_runtime_in_dir(
        db.base_path(),
        PROTOCOL.version,
        db.get_chain_id().ok(),
        published_addresses.clone(),
    )?;
    let local_record = identity.record().clone();
    net_log!("🆔 Local node ID: {}", hex::encode(identity.node_id()));

    let expected_peers = ExpectedPeerStore::new();
    let rustls_server = build_server_config(&identity)?;
    let rustls_client = build_client_config(&identity, expected_peers.clone())?;

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_server)?));
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client)?));

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), net_cfg.listen_port);
    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config.clone());

    let bootstrap_records = load_bootstrap_records(&net_cfg.bootstrap)?;
    let trust_policy = TrustPolicy::load(&bootstrap_records, &net_cfg.trust_updates)?;
    let banned_node_ids = net_cfg
        .banned_peer_ids
        .iter()
        .filter_map(|value| decode_node_id_hex(value).ok())
        .collect::<HashSet<_>>();

    let persisted_records = load_persisted_records(&db, &banned_node_ids)?;
    let persisted_archive_manifests = db.load_shielded_archive_providers()?;
    let (anchor_tx, _) = broadcast::channel(256);
    let (tx_tx, _) = broadcast::channel(256);
    let (rate_limited_tx, _) = broadcast::channel(64);
    let (headers_tx, _) = broadcast::channel(256);
    let (checkpoint_tx, _) = broadcast::channel(256);
    let connected_peers = Arc::new(Mutex::new(HashSet::new()));
    let shutdown = CancellationToken::new();
    let tasks = TaskTracker::new();

    let state = RuntimeState {
        db,
        sync_state,
        identity: Arc::new(RwLock::new(identity)),
        endpoint: endpoint.clone(),
        shutdown: shutdown.clone(),
        tasks: tasks.clone(),
        client_config,
        expected_peers,
        trust_policy,
        bootstrap_records: bootstrap_records.clone(),
        max_peers: net_cfg.max_peers as usize,
        connection_timeout: Duration::from_secs(net_cfg.connection_timeout_secs.max(1)),
        published_addresses,
        banned_node_ids: banned_node_ids.clone(),
        known_records: Arc::new(RwLock::new(HashMap::new())),
        peers: Arc::new(RwLock::new(HashMap::new())),
        connected_peers: connected_peers.clone(),
        pending_anchors: Arc::new(AsyncMutex::new(HashMap::new())),
        seen_messages: Arc::new(AsyncMutex::new(HashMap::new())),
        anchor_tx: anchor_tx.clone(),
        tx_tx: tx_tx.clone(),
        rate_limited_tx: rate_limited_tx.clone(),
        headers_tx: headers_tx.clone(),
        checkpoint_tx: checkpoint_tx.clone(),
        archive_manifests: Arc::new(RwLock::new(
            persisted_archive_manifests
                .into_iter()
                .map(|manifest| (manifest.provider_id, manifest))
                .collect(),
        )),
        peer_exchange: net_cfg.peer_exchange,
    };

    {
        let mut records = state.known_records.write().await;
        records.insert(local_record.node_id, local_record.clone());
    }
    for record in bootstrap_records
        .iter()
        .chain(persisted_records.iter())
        .cloned()
    {
        let _ = state.remember_record(record).await;
    }
    let _ = state.refresh_local_archive_manifest().await;

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let net = Arc::new(Network {
        anchor_tx,
        tx_tx,
        rate_limited_tx,
        headers_tx,
        checkpoint_tx,
        command_tx: command_tx.clone(),
        connected_peers,
        shutdown,
        tasks,
        endpoint: Arc::new(AsyncMutex::new(Some(endpoint.clone()))),
        db: state.db.clone(),
        archive_sync_timeout: Duration::from_secs(net_cfg.sync_timeout_secs.max(1)),
        local_node_id: local_record.node_id,
        known_records: state.known_records.clone(),
        archive_manifests: state.archive_manifests.clone(),
    });

    {
        let state = state.clone();
        let tasks = state.tasks.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    maybe_command = command_rx.recv() => {
                        let Some(command) = maybe_command else {
                            break;
                        };
                        if let Err(e) = handle_command(&state, command).await {
                            net_log!("⚠️  Network command failed: {}", e);
                        }
                    }
                }
            }
        });
    }

    {
        let state = state.clone();
        let endpoint = endpoint.clone();
        let tasks = state.tasks.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break;
                        };
                        let state = state.clone();
                        let tasks = state.tasks.clone();
                        tasks.spawn(async move {
                            if let Err(e) = state.accept_connection(incoming).await {
                                net_log!("⚠️  Failed to accept connection: {}", e);
                            }
                        });
                    }
                }
            }
        });
    }

    {
        let state = state.clone();
        let tasks = state.tasks.clone();
        tasks.spawn(async move {
            loop {
                if state.shutdown.is_cancelled() {
                    break;
                }
                let records = {
                    let guard = state.known_records.read().await;
                    guard.values().cloned().collect::<Vec<_>>()
                };
                for record in records {
                    if state.shutdown.is_cancelled() {
                        break;
                    }
                    let _ = state.dial_record(record).await;
                }
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(REDIAL_INTERVAL_SECS)) => {}
                }
            }
        });
    }

    {
        let state = state.clone();
        let tasks = state.tasks.clone();
        tasks.spawn(async move {
            let mut refresh_tick =
                tokio::time::interval(Duration::from_secs(IDENTITY_REFRESH_SECS));
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    _ = refresh_tick.tick() => {
                        if let Err(e) = state.refresh_local_identity().await {
                            net_log!("⚠️  Failed to refresh local node record: {}", e);
                        }
                    }
                }
            }
        });
    }

    {
        let state = state.clone();
        let tasks = state.tasks.clone();
        tasks.spawn(async move {
            let mut manifest_tick =
                tokio::time::interval(Duration::from_secs(ARCHIVE_MANIFEST_REFRESH_SECS));
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    _ = manifest_tick.tick() => {
                        match state.refresh_local_archive_manifest().await {
                            Ok(manifest) => {
                                match canonical::encode_archive_provider_manifest(&manifest) {
                                    Ok(bytes) => {
                                        let _ = state
                                            .sign_and_broadcast(WireTopic::ArchiveManifest, bytes)
                                            .await;
                                    }
                                    Err(e) => {
                                        net_log!("⚠️  Failed to encode local archive manifest: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                net_log!("⚠️  Failed to refresh local archive manifest: {}", e);
                            }
                        }
                    }
                }
            }
        });
    }

    {
        let state = state.clone();
        let tasks = state.tasks.clone();
        tasks.spawn(async move {
            let mut repair_tick =
                tokio::time::interval(Duration::from_secs(EPOCH_REPAIR_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    _ = repair_tick.tick() => {
                        if let Err(e) = state.repair_recent_epochs().await {
                            net_log!("⚠️  Failed to repair recent epoch state: {}", e);
                        }
                        let wanted = state
                            .db
                            .load_shielded_root_ledger()
                            .ok()
                            .flatten()
                            .map(|ledger| ledger.roots.keys().copied().collect::<Vec<_>>())
                            .unwrap_or_default();
                        if let Err(e) = state.request_missing_archive_epochs(&wanted).await {
                            net_log!("⚠️  Failed to repair archive state: {}", e);
                        }
                    }
                }
            }
        });
    }

    Ok(net)
}

async fn handle_command(state: &RuntimeState, command: NetworkCommand) -> Result<()> {
    match command {
        NetworkCommand::GossipAnchor(anchor) => {
            state
                .sign_and_broadcast(WireTopic::Anchor, canonical::encode_anchor(&anchor)?)
                .await?;
        }
        NetworkCommand::GossipCoin(coin) => {
            state
                .sign_and_broadcast(
                    WireTopic::CoinCandidate,
                    canonical::encode_coin_candidate(&coin)?,
                )
                .await?;
        }
        NetworkCommand::GossipTx(tx) => {
            state
                .sign_and_broadcast(WireTopic::Tx, canonical::encode_tx(&tx)?)
                .await?;
        }
        NetworkCommand::GossipCompactEpoch(compact) => {
            state
                .sign_and_broadcast(
                    WireTopic::CompactEpoch,
                    canonical::encode_compact_epoch(&compact)?,
                )
                .await?;
        }
        NetworkCommand::GossipRateLimited(msg) => {
            state
                .sign_and_broadcast(
                    WireTopic::RateLimited,
                    canonical::encode_rate_limited_message(&msg)?,
                )
                .await?;
        }
        NetworkCommand::RequestEpoch(epoch) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpoch,
                    encode_u64_body(epoch),
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::RequestEpochDirect(epoch) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpoch,
                    encode_u64_body(epoch),
                    REQUEST_FANOUT_RECOVERY,
                )
                .await?;
        }
        NetworkCommand::RequestEpochHeadersRange(range) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochHeadersRange,
                    canonical::encode_epoch_headers_range(&range),
                    REQUEST_FANOUT_HEADERS,
                )
                .await?;
        }
        NetworkCommand::RequestEpochByHash(hash) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochByHash,
                    canonical::encode_epoch_by_hash(&EpochByHash { hash }),
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::RequestCoin(coin_id) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestCoin,
                    encode_bytes32_body(&coin_id),
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::RequestLatestEpoch => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestLatestEpoch,
                    encode_empty_body(),
                    REQUEST_FANOUT_TIP,
                )
                .await?;
        }
        NetworkCommand::RequestEpochTxn(req) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochTxn,
                    canonical::encode_epoch_get_txn(&req)?,
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::RequestEpochSelected(epoch_num) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochSelected,
                    encode_u64_body(epoch_num),
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::RequestEpochLeaves(epoch_num) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochLeaves,
                    encode_u64_body(epoch_num),
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::GossipEpochLeaves(bundle) => {
            state
                .sign_and_broadcast(
                    WireTopic::EpochLeaves,
                    canonical::encode_epoch_leaves_bundle(&bundle)?,
                )
                .await?;
        }
        NetworkCommand::RequestEpochCandidates(epoch_hash) => {
            let _ = state
                .sign_and_send_to_targets(
                    WireTopic::RequestEpochCandidates,
                    encode_bytes32_body(&epoch_hash),
                    REQUEST_FANOUT_DEFAULT,
                )
                .await?;
        }
        NetworkCommand::EnsureArchiveEpochs(epochs) => {
            state.request_missing_archive_epochs(&epochs).await?;
        }
        NetworkCommand::RequestCheckpointBatch {
            record,
            request,
            reply,
        } => {
            let result = async {
                state
                    .sign_and_send_to_record_related_with_id(
                        record,
                        WireTopic::RequestCheckpointBatch,
                        canonical::encode_checkpoint_batch_request(&request)?,
                        None,
                    )
                    .await
            }
            .await;
            let _ = reply.send(result);
        }
        NetworkCommand::RedialBootstraps => {
            for record in state.bootstrap_records.clone() {
                let _ = state.dial_record(record).await;
            }
        }
    }
    Ok(())
}

impl Network {
    pub async fn gossip_anchor(&self, anchor: &Anchor) {
        let _ = self
            .command_tx
            .send(NetworkCommand::GossipAnchor(anchor.clone()));
    }

    pub async fn gossip_coin(&self, coin: &CoinCandidate) {
        let _ = self
            .command_tx
            .send(NetworkCommand::GossipCoin(coin.clone()));
    }

    pub async fn gossip_tx(&self, tx: &crate::transaction::Tx) {
        let _ = self.tx_tx.send(tx.clone());
        let _ = self.command_tx.send(NetworkCommand::GossipTx(tx.clone()));
    }

    pub async fn gossip_compact_epoch(&self, compact: CompactEpoch) {
        let _ = self
            .command_tx
            .send(NetworkCommand::GossipCompactEpoch(compact));
    }

    pub async fn gossip_rate_limited(&self, msg: RateLimitedMessage) {
        let _ = self.command_tx.send(NetworkCommand::GossipRateLimited(msg));
    }

    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> {
        self.anchor_tx.subscribe()
    }

    pub fn tx_subscribe(&self) -> broadcast::Receiver<crate::transaction::Tx> {
        self.tx_tx.subscribe()
    }

    pub fn headers_subscribe(&self) -> broadcast::Receiver<EpochHeadersBatch> {
        self.headers_tx.subscribe()
    }

    pub fn rate_limited_subscribe(&self) -> broadcast::Receiver<RateLimitedMessage> {
        self.rate_limited_tx.subscribe()
    }

    fn checkpoint_subscribe(&self) -> broadcast::Receiver<CheckpointBatchEvent> {
        self.checkpoint_tx.subscribe()
    }

    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> {
        self.anchor_tx.clone()
    }

    pub async fn request_epoch(&self, epoch: u64) {
        let _ = self.command_tx.send(NetworkCommand::RequestEpoch(epoch));
    }

    pub async fn request_epoch_direct(&self, epoch: u64) {
        let _ = self
            .command_tx
            .send(NetworkCommand::RequestEpochDirect(epoch));
    }

    pub async fn request_epoch_headers_range(&self, start_height: u64, count: u32) {
        let aligned_start = start_height;
        let now = Instant::now();
        let mut allow = true;
        if let Ok(mut map) = RECENT_RANGE_REQS.lock() {
            map.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(RANGE_REQ_DEDUP_SECS));
            allow = !map.contains_key(&aligned_start);
            if allow {
                map.insert(aligned_start, now);
            }
        }
        if allow {
            let _ = self
                .command_tx
                .send(NetworkCommand::RequestEpochHeadersRange(
                    EpochHeadersRange {
                        start_height: aligned_start,
                        count,
                    },
                ));
        }
    }

    pub async fn request_epoch_by_hash(&self, hash: [u8; 32]) {
        let now = Instant::now();
        let mut allow = true;
        if let Ok(mut map) = RECENT_HASH_REQS.lock() {
            map.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(HASH_REQ_DEDUP_SECS));
            allow = !map.contains_key(&hash);
            if allow {
                map.insert(hash, now);
            }
        }
        if allow {
            let _ = self
                .command_tx
                .send(NetworkCommand::RequestEpochByHash(hash));
        }
    }

    pub async fn request_coin(&self, coin_id: [u8; 32]) {
        let _ = self.command_tx.send(NetworkCommand::RequestCoin(coin_id));
    }

    pub async fn request_latest_epoch(&self) {
        let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch);
    }

    pub async fn request_epoch_selected(&self, epoch_num: u64) {
        let _ = self
            .command_tx
            .send(NetworkCommand::RequestEpochSelected(epoch_num));
    }

    pub async fn request_epoch_txn(&self, epoch_hash: [u8; 32], indexes: Vec<u32>) {
        let _ = self
            .command_tx
            .send(NetworkCommand::RequestEpochTxn(EpochGetTxn {
                epoch_hash,
                indexes,
            }));
    }

    pub async fn request_epoch_candidates(&self, epoch_hash: [u8; 32]) {
        let _ = self
            .command_tx
            .send(NetworkCommand::RequestEpochCandidates(epoch_hash));
    }

    pub async fn request_epoch_leaves(&self, epoch_num: u64) {
        let _ = self
            .command_tx
            .send(NetworkCommand::RequestEpochLeaves(epoch_num));
    }

    pub async fn gossip_epoch_leaves(&self, bundle: EpochLeavesBundle) {
        let _ = self
            .command_tx
            .send(NetworkCommand::GossipEpochLeaves(bundle));
    }

    pub fn peer_count(&self) -> usize {
        self.connected_peers
            .lock()
            .map(|peers| peers.len())
            .unwrap_or(0)
    }

    pub async fn redial_bootstraps(&self) {
        let _ = self.command_tx.send(NetworkCommand::RedialBootstraps);
    }

    pub async fn ensure_archive_epochs(&self, epochs: &[u64]) -> Result<()> {
        if epochs.is_empty() {
            return Ok(());
        }
        let deadline = Instant::now() + self.archive_sync_timeout;
        loop {
            let missing = epochs
                .iter()
                .copied()
                .filter(|epoch| {
                    self.db
                        .load_shielded_nullifier_epoch(*epoch)
                        .ok()
                        .flatten()
                        .is_none()
                })
                .collect::<Vec<_>>();
            if missing.is_empty() {
                return Ok(());
            }
            let _ = self
                .command_tx
                .send(NetworkCommand::EnsureArchiveEpochs(missing));
            if Instant::now() >= deadline {
                bail!("timed out waiting for archive epochs to synchronize");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn local_archive_directory(&self) -> Result<ArchiveDirectory> {
        let ledger = self.db.load_shielded_root_ledger()?.unwrap_or_default();
        let mut providers = self
            .archive_manifests
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let local_manifest = local_archive_provider_manifest(
            self.local_node_id,
            &ledger,
            PROTOCOL.archive_shard_epoch_span,
            &crate::transaction::local_available_archive_epochs(self.db.as_ref(), &ledger)?,
        )?;
        if let Some(existing) = providers
            .iter_mut()
            .find(|existing| existing.provider_id == local_manifest.provider_id)
        {
            *existing = local_manifest;
        } else {
            providers.push(local_manifest);
        }
        ArchiveDirectory::from_root_ledger_and_providers(
            &ledger,
            PROTOCOL.archive_shard_epoch_span,
            providers,
        )
    }

    async fn local_checkpoint_batch_response(
        &self,
        request: &CheckpointBatchRequest,
    ) -> Result<Option<CheckpointBatchResponse>> {
        let directory = self.local_archive_directory().await?;
        let manifest = directory.provider(&self.local_node_id)?.clone();
        if request.provider_id != manifest.provider_id {
            return Ok(None);
        }
        request.validate_against_manifest(&manifest, &directory)?;
        let mut server = ShieldedSyncServer::new();
        let mut needed_epochs = BTreeSet::new();
        for checkpoint_request in &request.requests {
            for query in &checkpoint_request.queries {
                needed_epochs.insert(query.epoch);
            }
        }
        for epoch in needed_epochs {
            let archived = self
                .db
                .load_shielded_nullifier_epoch(epoch)?
                .ok_or_else(|| anyhow!("missing nullifier archive for epoch {}", epoch))?;
            server.insert_archived_epoch(archived)?;
        }
        Ok(Some(CheckpointBatchResponse {
            provider_id: manifest.provider_id,
            provider_manifest_digest: manifest.manifest_digest,
            responses: server.serve_checkpoints_batch(&manifest, &request.requests)?,
        }))
    }

    async fn await_checkpoint_batch_response(
        &self,
        receiver: &mut broadcast::Receiver<CheckpointBatchEvent>,
        request_message_id: [u8; 32],
        provider_id: [u8; 32],
        deadline: Instant,
    ) -> Result<CheckpointBatchResponse> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("timed out waiting for checkpoint batch response");
            }
            match tokio::time::timeout(remaining, receiver.recv()).await {
                Ok(Ok(event))
                    if event.response_to_message_id == request_message_id
                        && event.provider_id == provider_id =>
                {
                    return Ok(event.response);
                }
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    bail!("checkpoint response channel closed")
                }
                Err(_) => bail!("timed out waiting for checkpoint batch response"),
            }
        }
    }

    pub async fn request_historical_extensions(
        &self,
        requests: &[CheckpointExtensionRequest],
        rotation_round: u64,
    ) -> Result<Vec<HistoricalUnspentExtension>> {
        crate::transaction::ensure_shielded_runtime_state(self.db.as_ref())?;
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let directory = self.local_archive_directory().await?;
        let routed_batches = route_checkpoint_requests(
            &directory,
            requests,
            rotation_round,
            PROTOCOL.oblivious_sync_min_batch as usize,
            PROTOCOL.max_historical_nullifier_batch as usize,
        )?;
        let mut results = requests
            .iter()
            .map(|request| {
                if request.queries.is_empty() {
                    Some(request.checkpoint.empty_extension())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut routable_index_map = Vec::new();
        for (request_index, request) in requests.iter().enumerate() {
            if !request.queries.is_empty() {
                routable_index_map.push(request_index);
            }
        }
        let mut response_rx = self.checkpoint_subscribe();
        let deadline = Instant::now() + self.archive_sync_timeout;

        for batch in routed_batches {
            let manifest = directory.provider(&batch.provider_id)?.clone();
            let checkpoint_request = CheckpointBatchRequest {
                provider_id: manifest.provider_id,
                provider_manifest_digest: manifest.manifest_digest,
                requests: batch
                    .requests
                    .iter()
                    .map(|routed| routed.request.clone())
                    .collect(),
            };

            let checkpoint_response = if manifest.provider_id == self.local_node_id {
                self.local_checkpoint_batch_response(&checkpoint_request)
                    .await?
                    .ok_or_else(|| anyhow!("local archive provider refused checkpoint batch"))?
            } else {
                let record = {
                    let guard = self.known_records.read().await;
                    guard.get(&manifest.provider_id).cloned()
                }
                .ok_or_else(|| anyhow!("missing node record for archive provider"))?;
                let (reply_tx, reply_rx) = oneshot::channel();
                self.command_tx
                    .send(NetworkCommand::RequestCheckpointBatch {
                        record,
                        request: checkpoint_request.clone(),
                        reply: reply_tx,
                    })
                    .map_err(|_| anyhow!("checkpoint request channel closed"))?;
                let request_message_id = reply_rx
                    .await
                    .map_err(|_| anyhow!("checkpoint request sender dropped"))??;
                self.await_checkpoint_batch_response(
                    &mut response_rx,
                    request_message_id,
                    manifest.provider_id,
                    deadline,
                )
                .await?
            };

            checkpoint_response.verify_against_manifest(&manifest, &directory)?;
            if checkpoint_response.responses.len() != batch.requests.len() {
                bail!("checkpoint batch response length mismatch");
            }

            for (routed, response) in batch.requests.iter().zip(checkpoint_response.responses) {
                response.verify_against_manifest(&manifest, &directory)?;
                if let Some(routed_index) = routed.request_index {
                    let request_index = *routable_index_map
                        .get(routed_index)
                        .ok_or_else(|| anyhow!("missing routed historical extension index"))?;
                    let mut blinding = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut blinding);
                    results[request_index] = Some(response.rerandomize(blinding));
                }
            }
        }

        results
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow!("missing routed historical extension"))
    }

    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        if let Some(endpoint) = self.endpoint.lock().await.take() {
            endpoint.close(0u32.into(), b"shutdown");
            endpoint.wait_idle().await;
        }
        if let Ok(mut peers) = self.connected_peers.lock() {
            peers.clear();
            metrics::PEERS.set(0);
        }
        self.tasks.close();
        self.tasks.wait().await;
    }
}

pub fn encode_wire_hello(
    record: NodeRecordV2,
    known_records: Vec<NodeRecordV2>,
) -> Result<Vec<u8>> {
    encode_wire_message(&WireMessage::Hello(HelloMessage {
        record,
        known_records,
    }))
}

pub fn encode_wire_envelope(envelope: &SignedEnvelope) -> Result<Vec<u8>> {
    encode_wire_message(&WireMessage::Envelope(envelope.clone()))
}

async fn write_wire_message(send: &mut quinn::SendStream, message: &WireMessage) -> Result<()> {
    let bytes = encode_wire_message(message)?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}

async fn read_hello_message(recv: &mut quinn::RecvStream) -> Result<HelloMessage> {
    let bytes = recv.read_to_end(MAX_WIRE_BYTES).await?;
    let message = decode_wire_message(&bytes)?;
    match message {
        WireMessage::Hello(hello) => Ok(hello),
        WireMessage::Envelope(_) => bail!("expected hello message"),
    }
}

fn published_addresses(net_cfg: &config::Net) -> Vec<String> {
    let ip = net_cfg
        .public_ip
        .as_ref()
        .and_then(|raw| raw.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    vec![SocketAddr::new(ip, net_cfg.listen_port).to_string()]
}

fn decode_node_id_hex(value: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(value.trim())?;
    if raw.len() != 32 {
        bail!("node id must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn load_bootstrap_records(items: &[String]) -> Result<Vec<NodeRecordV2>> {
    let mut out = Vec::new();
    for item in items {
        let record = load_bootstrap_record(item)?;
        record.validate(unix_ms())?;
        out.push(record);
    }
    Ok(out)
}

fn load_bootstrap_record(item: &str) -> Result<NodeRecordV2> {
    let trimmed = item.trim();
    if Path::new(trimmed).exists() {
        let bytes = fs::read(trimmed)?;
        if let Ok(record) = canonical::decode_node_record(&bytes) {
            return Ok(record);
        }
        let text = String::from_utf8(bytes).context("bootstrap file is not valid UTF-8")?;
        return NodeRecordV2::decode_compact(text.trim());
    }
    NodeRecordV2::decode_compact(trimmed)
}

fn load_persisted_records(db: &Store, banned: &HashSet<[u8; 32]>) -> Result<Vec<NodeRecordV2>> {
    let mut out = Vec::new();
    for bytes in db.load_node_records()? {
        let Ok(record) = canonical::decode_node_record(&bytes) else {
            continue;
        };
        if banned.contains(&record.node_id) {
            continue;
        }
        if record.validate(unix_ms()).is_ok() {
            out.push(record);
        }
    }
    Ok(out)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn request_route_key(topic: WireTopic, body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("unchained-request-route-v1");
    hasher.update(&[wire_topic_id(topic)]);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

fn request_route_rank(route_key: &[u8; 32], node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("unchained-request-rank-v1");
    hasher.update(route_key);
    hasher.update(node_id);
    *hasher.finalize().as_bytes()
}

fn should_relay_topic(topic: WireTopic) -> bool {
    matches!(
        topic,
        WireTopic::Anchor
            | WireTopic::CoinCandidate
            | WireTopic::Tx
            | WireTopic::CompactEpoch
            | WireTopic::RateLimited
            | WireTopic::NodeRecord
    )
}

fn chain_compatible(local_chain_id: Option<[u8; 32]>, remote_chain_id: Option<[u8; 32]>) -> bool {
    match local_chain_id {
        Some(local_chain_id) => remote_chain_id == Some(local_chain_id),
        None => true,
    }
}

fn validate_coin_candidate(coin: &CoinCandidate, db: &Store) -> Result<(), String> {
    let anchor: Anchor = db
        .get_epoch_for_coin(&coin.id)
        .ok()
        .flatten()
        .and_then(|n| db.get::<Anchor>("epoch", &n.to_le_bytes()).ok().flatten())
        .or_else(|| db.get::<Anchor>("anchor", &coin.epoch_hash).ok().flatten())
        .ok_or_else(|| {
            format!(
                "Coin references non-existent committed epoch (coin_id={})",
                hex::encode(coin.id)
            )
        })?;

    if coin.creator_address == [0u8; 32] {
        return Err("Invalid creator address".into());
    }
    if coin.creator_pk.address() != coin.creator_address {
        return Err("Creator public key/address mismatch".into());
    }

    let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
    let calculated_pow =
        crypto::argon2id_pow(&header, anchor.mem_kib).map_err(|e| e.to_string())?;
    if calculated_pow != coin.pow_hash {
        return Err("PoW validation failed".into());
    }
    if !calculated_pow
        .iter()
        .take(anchor.difficulty)
        .all(|byte| *byte == 0)
    {
        return Err(format!(
            "PoW does not meet difficulty: requires {} leading zero bytes",
            anchor.difficulty
        ));
    }
    if Coin::calculate_id(&coin.epoch_hash, coin.nonce, &coin.creator_address) != coin.id {
        return Err("Coin ID mismatch".into());
    }
    Ok(())
}

fn validate_tx(tx: &crate::transaction::Tx, db: &Store) -> Result<(), String> {
    tx.validate(db).map_err(|e| e.to_string())
}

fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    if anchor.hash == [0u8; 32] {
        return Err("Anchor hash cannot be zero".into());
    }
    if anchor.difficulty == 0 {
        return Err("Difficulty cannot be zero".into());
    }
    if anchor.mem_kib == 0 {
        return Err("Memory cannot be zero".into());
    }
    if anchor.num == 0 {
        if anchor.difficulty != TARGET_LEADING_ZEROS || anchor.mem_kib != DEFAULT_MEM_KIB {
            return Err("Consensus params mismatch at genesis".into());
        }
        let expected = Anchor::expected_work_for_difficulty(anchor.difficulty);
        if anchor.cumulative_work != expected {
            return Err("Genesis cumulative_work mismatch".into());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&anchor.merkle_root);
        if *hasher.finalize().as_bytes() != anchor.hash {
            return Err("Genesis hash mismatch".into());
        }
        return Ok(());
    }
    if anchor.merkle_root == [0u8; 32] && anchor.coin_count > 0 {
        return Err("Merkle root cannot be zero when coins are present".into());
    }

    let prev = db
        .get::<Anchor>("epoch", &(anchor.num - 1).to_le_bytes())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Previous anchor #{} not found", anchor.num - 1))?;

    let (expected_difficulty, expected_mem_kib) = if anchor.num % RETARGET_INTERVAL == 0 {
        let start = anchor.num.saturating_sub(RETARGET_INTERVAL);
        let window = db
            .get_or_build_retarget_window(anchor.num)
            .map_err(|e| e.to_string())?;
        match window {
            Some(window) if window.len() as u64 == RETARGET_INTERVAL => {
                calculate_retarget_consensus(&window)
            }
            _ => return Err(format!("Retarget window incomplete starting at {}", start)),
        }
    } else {
        (prev.difficulty, prev.mem_kib)
    };

    if anchor.difficulty != expected_difficulty || anchor.mem_kib != expected_mem_kib {
        return Err(format!(
            "Consensus params mismatch. Expected difficulty={}, mem_kib={}, got difficulty={}, mem_kib={}",
            expected_difficulty, expected_mem_kib, anchor.difficulty, anchor.mem_kib
        ));
    }

    let expected_work = Anchor::expected_work_for_difficulty(anchor.difficulty);
    let expected_cumulative_work = prev.cumulative_work.saturating_add(expected_work);
    if anchor.cumulative_work != expected_cumulative_work {
        return Err(format!(
            "Invalid cumulative work. Expected: {}, Got: {}",
            expected_cumulative_work, anchor.cumulative_work
        ));
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(&anchor.merkle_root);
    hasher.update(&prev.hash);
    if *hasher.finalize().as_bytes() != anchor.hash {
        return Err("Anchor hash mismatch".into());
    }
    Ok(())
}

fn persist_selected_for_anchor(db: &Store, anchor: &Anchor) -> Result<()> {
    if anchor.num == 0 {
        return Ok(());
    }
    let parent = db
        .get::<Anchor>("epoch", &(anchor.num - 1).to_le_bytes())?
        .ok_or_else(|| anyhow!("missing parent anchor"))?;
    let (candidates, _) =
        crate::epoch::select_candidates_for_epoch(db, &parent, anchor.coin_count as usize, None);
    let selected_ids = candidates
        .iter()
        .map(|candidate| candidate.id)
        .collect::<HashSet<_>>();
    let mut leaves = selected_ids
        .iter()
        .map(Coin::id_to_leaf_hash)
        .collect::<Vec<_>>();
    leaves.sort();
    if MerkleTree::compute_root_from_sorted_leaves(&leaves) != anchor.merkle_root
        || selected_ids.len() as u32 != anchor.coin_count
    {
        bail!("candidate reconstruction does not match anchor merkle root");
    }
    let levels = MerkleTree::build_levels_from_sorted_leaves(&leaves);

    let Some(coin_cf) = db.db.cf_handle("coin") else {
        bail!("coin column family missing");
    };
    let Some(coin_epoch_cf) = db.db.cf_handle("coin_epoch") else {
        bail!("coin_epoch column family missing");
    };
    let Some(rev_cf) = db.db.cf_handle("coin_epoch_by_epoch") else {
        bail!("coin_epoch_by_epoch column family missing");
    };
    let Some(sel_cf) = db.db.cf_handle("epoch_selected") else {
        bail!("epoch_selected column family missing");
    };
    let Some(leaves_cf) = db.db.cf_handle("epoch_leaves") else {
        bail!("epoch_leaves column family missing");
    };
    let Some(levels_cf) = db.db.cf_handle("epoch_levels") else {
        bail!("epoch_levels column family missing");
    };

    let mut batch = WriteBatch::default();
    for candidate in candidates {
        let coin = candidate.into_confirmed();
        let coin_bytes = bincode::serialize(&coin)?;
        batch.put_cf(coin_cf, &coin.id, &coin_bytes);
        batch.put_cf(coin_epoch_cf, &coin.id, &anchor.num.to_le_bytes());
        let mut rev_key = Vec::with_capacity(8 + 32);
        rev_key.extend_from_slice(&anchor.num.to_le_bytes());
        rev_key.extend_from_slice(&coin.id);
        batch.put_cf(rev_cf, &rev_key, &[]);
        let mut selected_key = Vec::with_capacity(8 + 32);
        selected_key.extend_from_slice(&anchor.num.to_le_bytes());
        selected_key.extend_from_slice(&coin.id);
        batch.put_cf(sel_cf, &selected_key, &[]);
    }
    batch.put_cf(
        leaves_cf,
        &anchor.num.to_le_bytes(),
        &bincode::serialize(&leaves)?,
    );
    batch.put_cf(
        levels_cf,
        &anchor.num.to_le_bytes(),
        &bincode::serialize(&levels)?,
    );
    db.write_batch(batch)?;
    metrics::SELECTED_COINS.set(anchor.coin_count as i64);
    Ok(())
}
