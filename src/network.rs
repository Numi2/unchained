use crate::canonical::{self, CanonicalReader, CanonicalWriter};
use crate::consensus::{
    OrderingPath, QuorumCertificate, ValidatorId, ValidatorVote, DAG_BFT_TIMEOUT_MS,
    FAST_PATH_TIMEOUT_MS,
};
use crate::epoch::{Anchor, AnchorProposal, MerkleTree};
use crate::metrics;
use crate::node_identity::{
    build_client_config, build_server_config, load_local_node_id, tls_peer_spki,
    verify_record_matches_tls, ExpectedPeerStore, NodeIdentity, NodeRecordV2, SignedEnvelope,
    TrustPolicy,
};
use crate::protocol::CURRENT as PROTOCOL;
use crate::staking::{
    expected_validator_set_for_epoch, load_or_compute_active_validator_set,
    register_genesis_local_validator_pool,
};
use crate::storage::Store;
use crate::sync::SyncState;
use crate::transaction::{SharedStateBatch, SharedStateDagBatch};
use crate::{
    coin::{Coin, CoinCandidate},
    config,
    shielded::{
        local_archive_custody_commitments, local_archive_provider_manifest,
        local_archive_replica_attestations, route_checkpoint_requests, ArchiveCustodyCommitment,
        ArchiveDirectory, ArchiveProviderManifest, ArchiveReplicaAttestation,
        ArchiveRetrievalReceipt, ArchiveServiceLedger, ArchiveShardBundle, CheckpointBatchRequest,
        CheckpointBatchResponse, CheckpointExtensionRequest, HistoricalUnspentExtension,
        ShieldedSyncServer,
    },
};
use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::ML_DSA_65;
use once_cell::sync::Lazy;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint};
use rand::RngCore;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
const ARCHIVE_REBALANCE_INTERVAL_SECS: u64 = 15;

static RECENT_HASH_REQS: Lazy<Mutex<HashMap<[u8; 32], Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static RECENT_RANGE_REQS: Lazy<Mutex<HashMap<u64, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub type NetHandle = Arc<Network>;

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
    message_id: [u8; 32],
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
    AnchorProposal,
    ValidatorVote,
    SharedStateDagBatch,
    CoinCandidate,
    Coin,
    Tx,
    CompactEpoch,
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
    ArchiveReplica,
    RequestArchiveShard,
    ArchiveShard,
    RequestCheckpointBatch,
    CheckpointBatch,
    ArchiveCustodyCommitment,
    ArchiveRetrievalReceipt,
    RequestSharedStateDagBatch,
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
        WireTopic::AnchorProposal => 2,
        WireTopic::ValidatorVote => 3,
        WireTopic::SharedStateDagBatch => 4,
        WireTopic::CoinCandidate => 5,
        WireTopic::Coin => 6,
        WireTopic::Tx => 7,
        WireTopic::CompactEpoch => 8,
        WireTopic::EpochLeaves => 9,
        WireTopic::EpochSelectedResponse => 10,
        WireTopic::EpochCandidatesResponse => 11,
        WireTopic::EpochHeadersResponse => 12,
        WireTopic::EpochByHashResponse => 13,
        WireTopic::RequestEpoch => 14,
        WireTopic::RequestEpochHeadersRange => 15,
        WireTopic::RequestEpochByHash => 16,
        WireTopic::RequestCoin => 17,
        WireTopic::RequestLatestEpoch => 18,
        WireTopic::RequestEpochTxn => 19,
        WireTopic::EpochTxn => 20,
        WireTopic::RequestEpochSelected => 21,
        WireTopic::RequestEpochLeaves => 22,
        WireTopic::RequestEpochCandidates => 23,
        WireTopic::NodeRecord => 24,
        WireTopic::ArchiveManifest => 25,
        WireTopic::ArchiveReplica => 26,
        WireTopic::RequestArchiveShard => 27,
        WireTopic::ArchiveShard => 28,
        WireTopic::RequestCheckpointBatch => 29,
        WireTopic::CheckpointBatch => 30,
        WireTopic::ArchiveCustodyCommitment => 31,
        WireTopic::ArchiveRetrievalReceipt => 32,
        WireTopic::RequestSharedStateDagBatch => 33,
    }
}

fn decode_wire_topic(id: u8) -> Result<WireTopic> {
    Ok(match id {
        1 => WireTopic::Anchor,
        2 => WireTopic::AnchorProposal,
        3 => WireTopic::ValidatorVote,
        4 => WireTopic::SharedStateDagBatch,
        5 => WireTopic::CoinCandidate,
        6 => WireTopic::Coin,
        7 => WireTopic::Tx,
        8 => WireTopic::CompactEpoch,
        9 => WireTopic::EpochLeaves,
        10 => WireTopic::EpochSelectedResponse,
        11 => WireTopic::EpochCandidatesResponse,
        12 => WireTopic::EpochHeadersResponse,
        13 => WireTopic::EpochByHashResponse,
        14 => WireTopic::RequestEpoch,
        15 => WireTopic::RequestEpochHeadersRange,
        16 => WireTopic::RequestEpochByHash,
        17 => WireTopic::RequestCoin,
        18 => WireTopic::RequestLatestEpoch,
        19 => WireTopic::RequestEpochTxn,
        20 => WireTopic::EpochTxn,
        21 => WireTopic::RequestEpochSelected,
        22 => WireTopic::RequestEpochLeaves,
        23 => WireTopic::RequestEpochCandidates,
        24 => WireTopic::NodeRecord,
        25 => WireTopic::ArchiveManifest,
        26 => WireTopic::ArchiveReplica,
        27 => WireTopic::RequestArchiveShard,
        28 => WireTopic::ArchiveShard,
        29 => WireTopic::RequestCheckpointBatch,
        30 => WireTopic::CheckpointBatch,
        31 => WireTopic::ArchiveCustodyCommitment,
        32 => WireTopic::ArchiveRetrievalReceipt,
        33 => WireTopic::RequestSharedStateDagBatch,
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

struct PendingAnchorCertification {
    proposal: AnchorProposal,
    proposal_message_id: [u8; 32],
    votes: BTreeMap<ValidatorId, ValidatorVote>,
    reply: Option<oneshot::Sender<Result<QuorumCertificate>>>,
    created_at: Instant,
}

struct PendingSharedStateProposal {
    proposer_record: NodeRecordV2,
    proposal_message_id: [u8; 32],
    proposal: AnchorProposal,
    received_at: Instant,
}

#[derive(Debug, Clone)]
struct SharedStateDagPlan {
    round: u64,
    frontier: Vec<[u8; 32]>,
    ordered_batches: Vec<SharedStateDagBatch>,
    aggregate_batch: SharedStateBatch,
}

#[derive(Debug, Clone, Copy)]
struct P2pPolicy {
    max_validation_failures_per_peer: u32,
    peer_ban_duration: Duration,
    rate_limit_window: Duration,
    max_messages_per_window: u32,
}

impl P2pPolicy {
    fn from_config(cfg: &config::P2p) -> Self {
        Self {
            max_validation_failures_per_peer: cfg.max_validation_failures_per_peer.max(1),
            peer_ban_duration: Duration::from_secs(cfg.peer_ban_duration_secs.max(1)),
            rate_limit_window: Duration::from_secs(cfg.rate_limit_window_secs.max(1)),
            max_messages_per_window: cfg.max_messages_per_window.max(1),
        }
    }
}

#[derive(Debug, Clone)]
struct PeerPolicyState {
    window_started_at: Instant,
    messages_in_window: u32,
    validation_failures: u32,
    banned_until: Option<Instant>,
}

impl PeerPolicyState {
    fn new(now: Instant) -> Self {
        Self {
            window_started_at: now,
            messages_in_window: 0,
            validation_failures: 0,
            banned_until: None,
        }
    }
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
    p2p_policy: P2pPolicy,
    peer_policy: Arc<AsyncMutex<HashMap<[u8; 32], PeerPolicyState>>>,
    known_records: Arc<RwLock<HashMap<[u8; 32], NodeRecordV2>>>,
    peers: Arc<RwLock<HashMap<[u8; 32], Connection>>>,
    connected_peers: Arc<Mutex<HashSet<[u8; 32]>>>,
    pending_anchors: Arc<AsyncMutex<HashMap<u64, Vec<PendingAnchor>>>>,
    seen_messages: Arc<AsyncMutex<HashMap<[u8; 32], Instant>>>,
    anchor_tx: broadcast::Sender<Anchor>,
    tx_tx: broadcast::Sender<crate::transaction::Tx>,
    headers_tx: broadcast::Sender<EpochHeadersBatch>,
    checkpoint_tx: broadcast::Sender<CheckpointBatchEvent>,
    pending_anchor_certifications: Arc<AsyncMutex<HashMap<[u8; 32], PendingAnchorCertification>>>,
    pending_shared_state_proposals: Arc<AsyncMutex<Vec<PendingSharedStateProposal>>>,
    cast_anchor_votes: Arc<AsyncMutex<HashMap<[u8; 32], Instant>>>,
    archive_manifests: Arc<RwLock<HashMap<[u8; 32], ArchiveProviderManifest>>>,
    archive_replicas: Arc<RwLock<HashMap<([u8; 32], u64), ArchiveReplicaAttestation>>>,
    peer_exchange: bool,
}

#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    tx_tx: broadcast::Sender<crate::transaction::Tx>,
    headers_tx: broadcast::Sender<EpochHeadersBatch>,
    checkpoint_tx: broadcast::Sender<CheckpointBatchEvent>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
    connected_peers: Arc<Mutex<HashSet<[u8; 32]>>>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    endpoint: Arc<AsyncMutex<Option<Endpoint>>>,
    db: Arc<Store>,
    identity: Option<Arc<RwLock<NodeIdentity>>>,
    archive_sync_timeout: Duration,
    local_node_id: [u8; 32],
    known_records: Arc<RwLock<HashMap<[u8; 32], NodeRecordV2>>>,
    archive_manifests: Arc<RwLock<HashMap<[u8; 32], ArchiveProviderManifest>>>,
    archive_replicas: Arc<RwLock<HashMap<([u8; 32], u64), ArchiveReplicaAttestation>>>,
}

enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(CoinCandidate),
    GossipTx(crate::transaction::Tx),
    GossipSharedStateDagBatch(SharedStateDagBatch),
    GossipCompactEpoch(CompactEpoch),
    ProposeAnchor {
        proposal: AnchorProposal,
        reply: oneshot::Sender<Result<QuorumCertificate>>,
    },
    AbandonAnchorProposal([u8; 32]),
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
    GossipArchiveRetrievalReceipt(ArchiveRetrievalReceipt),
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
    let (headers_tx, _) = broadcast::channel::<EpochHeadersBatch>(1);
    let (checkpoint_tx, _) = broadcast::channel::<CheckpointBatchEvent>(1);
    let (command_tx, _) = mpsc::unbounded_channel();
    Arc::new(Network {
        anchor_tx,
        tx_tx,
        headers_tx,
        checkpoint_tx,
        command_tx,
        connected_peers: Arc::new(Mutex::new(HashSet::new())),
        shutdown: CancellationToken::new(),
        tasks: TaskTracker::new(),
        endpoint: Arc::new(AsyncMutex::new(None)),
        db,
        identity: None,
        archive_sync_timeout: Duration::from_secs(1),
        local_node_id: [0u8; 32],
        known_records: Arc::new(RwLock::new(HashMap::new())),
        archive_manifests: Arc::new(RwLock::new(HashMap::new())),
        archive_replicas: Arc::new(RwLock::new(HashMap::new())),
    })
}

pub fn peer_id_string() -> Result<String> {
    load_local_node_id()
}

impl RuntimeState {
    fn local_chain_id(&self) -> Option<[u8; 32]> {
        Some(self.db.effective_chain_id())
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

    async fn peer_is_temporarily_banned(&self, node_id: [u8; 32]) -> bool {
        let now = Instant::now();
        let mut guard = self.peer_policy.lock().await;
        if let Some(state) = guard.get_mut(&node_id) {
            if let Some(until) = state.banned_until {
                if now < until {
                    return true;
                }
                state.banned_until = None;
                state.validation_failures = 0;
                state.messages_in_window = 0;
                state.window_started_at = now;
            }
        }
        false
    }

    async fn enforce_peer_allowed(&self, node_id: [u8; 32]) -> Result<()> {
        if self.banned_node_ids.contains(&node_id) {
            bail!("peer is banned");
        }
        if self.peer_is_temporarily_banned(node_id).await {
            bail!("peer is temporarily banned");
        }
        Ok(())
    }

    async fn record_inbound_message(&self, node_id: [u8; 32]) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.peer_policy.lock().await;
        let state = guard
            .entry(node_id)
            .or_insert_with(|| PeerPolicyState::new(now));
        if let Some(until) = state.banned_until {
            if now < until {
                bail!("peer is temporarily banned");
            }
            state.banned_until = None;
            state.validation_failures = 0;
            state.messages_in_window = 0;
            state.window_started_at = now;
        }
        if now.duration_since(state.window_started_at) >= self.p2p_policy.rate_limit_window {
            state.window_started_at = now;
            state.messages_in_window = 0;
        }
        state.messages_in_window = state.messages_in_window.saturating_add(1);
        if state.messages_in_window > self.p2p_policy.max_messages_per_window {
            state.banned_until = Some(now + self.p2p_policy.peer_ban_duration);
            bail!("peer exceeded the configured ingress message budget");
        }
        Ok(())
    }

    async fn record_validation_failure(&self, node_id: [u8; 32]) {
        let now = Instant::now();
        let mut guard = self.peer_policy.lock().await;
        let state = guard
            .entry(node_id)
            .or_insert_with(|| PeerPolicyState::new(now));
        if let Some(until) = state.banned_until {
            if now < until {
                return;
            }
            state.banned_until = None;
            state.validation_failures = 0;
            state.messages_in_window = 0;
            state.window_started_at = now;
        }
        state.validation_failures = state.validation_failures.saturating_add(1);
        if state.validation_failures >= self.p2p_policy.max_validation_failures_per_peer {
            state.banned_until = Some(now + self.p2p_policy.peer_ban_duration);
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
        self.enforce_peer_allowed(record.node_id).await?;
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
        let _ = self.refresh_archive_operator_scorecards().await;
        Ok(manifest)
    }

    async fn local_archive_replicas(&self) -> Result<Vec<ArchiveReplicaAttestation>> {
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
            *existing = local_manifest.clone();
        } else {
            providers.push(local_manifest.clone());
        }
        let persisted_replicas = self
            .archive_replicas
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let directory =
            ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_accounting(
                &ledger,
                PROTOCOL.archive_shard_epoch_span,
                providers,
                persisted_replicas,
                self.db.load_shielded_archive_service_ledgers()?,
            )?;
        local_archive_replica_attestations(
            local_manifest.provider_id,
            &directory,
            PROTOCOL.archive_retention_horizon_epochs,
        )
    }

    async fn refresh_local_archive_replicas(&self) -> Result<Vec<ArchiveReplicaAttestation>> {
        let replicas = self.local_archive_replicas().await?;
        let mut guard = self.archive_replicas.write().await;
        for replica in &replicas {
            self.db.store_shielded_archive_replica(replica)?;
            guard.insert((replica.provider_id, replica.shard_id), replica.clone());
        }
        drop(guard);
        let _ = self.refresh_archive_operator_scorecards().await;
        Ok(replicas)
    }

    async fn local_archive_custody_commitments(&self) -> Result<Vec<ArchiveCustodyCommitment>> {
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
            *existing = local_manifest.clone();
        } else {
            providers.push(local_manifest.clone());
        }
        let mut replicas = self
            .archive_replicas
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        replicas.extend(self.local_archive_replicas().await?);
        let directory =
            ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_accounting(
                &ledger,
                PROTOCOL.archive_shard_epoch_span,
                providers,
                replicas,
                self.db.load_shielded_archive_service_ledgers()?,
            )?;
        local_archive_custody_commitments(
            local_manifest.provider_id,
            &directory,
            PROTOCOL.archive_provider_replica_count as usize,
            PROTOCOL.archive_retention_horizon_epochs,
        )
    }

    async fn refresh_local_archive_custody_commitments(
        &self,
    ) -> Result<Vec<ArchiveCustodyCommitment>> {
        let commitments = self.local_archive_custody_commitments().await?;
        for commitment in &commitments {
            self.db
                .store_shielded_archive_custody_commitment(commitment)?;
        }
        let _ = self.refresh_archive_operator_scorecards().await;
        Ok(commitments)
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
        let mut replicas = self
            .archive_replicas
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        replicas.extend(self.local_archive_replicas().await?);
        ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_evidence(
            &ledger,
            PROTOCOL.archive_shard_epoch_span,
            providers,
            replicas,
            self.db.load_shielded_archive_service_ledgers()?,
            self.db.load_shielded_archive_custody_commitments()?,
            self.db.load_shielded_archive_retrieval_receipts()?,
        )
    }

    async fn refresh_archive_operator_scorecards(&self) -> Result<()> {
        let directory = self.local_archive_directory().await?;
        for scorecard in directory.operator_scorecards(
            PROTOCOL.archive_provider_replica_count as usize,
            PROTOCOL.archive_retention_horizon_epochs,
        ) {
            self.db
                .store_shielded_archive_operator_scorecard(&scorecard)?;
        }
        Ok(())
    }

    async fn update_archive_service_ledger(
        &self,
        provider_id: [u8; 32],
        provider_manifest_digest: [u8; 32],
        update: impl FnOnce(&mut ArchiveServiceLedger),
    ) -> Result<()> {
        let mut ledger = self
            .db
            .load_shielded_archive_service_ledger(&provider_id)?
            .unwrap_or_else(|| ArchiveServiceLedger::new(provider_id, provider_manifest_digest));
        if ledger.provider_manifest_digest != provider_manifest_digest {
            ledger = ArchiveServiceLedger::new(provider_id, provider_manifest_digest);
        }
        update(&mut ledger);
        self.db.store_shielded_archive_service_ledger(&ledger)?;
        self.refresh_archive_operator_scorecards().await?;
        Ok(())
    }

    async fn ingest_archive_custody_commitment(
        &self,
        record: &NodeRecordV2,
        commitment: ArchiveCustodyCommitment,
    ) -> Result<()> {
        if commitment.provider_id != record.node_id {
            bail!("archive custody commitment provider id does not match the envelope signer");
        }
        let directory = self.local_archive_directory().await?;
        commitment.validate(&directory)?;
        self.db
            .store_shielded_archive_custody_commitment(&commitment)?;
        self.refresh_archive_operator_scorecards().await?;
        Ok(())
    }

    async fn ingest_archive_retrieval_receipt(
        &self,
        record: &NodeRecordV2,
        receipt: ArchiveRetrievalReceipt,
    ) -> Result<()> {
        if receipt.requester_id != record.node_id {
            bail!("archive retrieval receipt requester id does not match the envelope signer");
        }
        let directory = self.local_archive_directory().await?;
        receipt.validate(&directory)?;
        self.db.store_shielded_archive_retrieval_receipt(&receipt)?;
        self.refresh_archive_operator_scorecards().await?;
        Ok(())
    }

    async fn publish_archive_retrieval_receipt(
        &self,
        receipt: ArchiveRetrievalReceipt,
    ) -> Result<()> {
        self.db.store_shielded_archive_retrieval_receipt(&receipt)?;
        self.refresh_archive_operator_scorecards().await?;
        self.sign_and_broadcast(
            WireTopic::ArchiveRetrievalReceipt,
            canonical::encode_archive_retrieval_receipt(&receipt)?,
        )
        .await
    }

    async fn build_local_checkpoint_batch_response(
        &self,
        request: &CheckpointBatchRequest,
    ) -> Result<Option<CheckpointBatchResponse>> {
        let manifest = self.local_archive_manifest().await?;
        if request.provider_id != manifest.provider_id {
            return Ok(None);
        }
        let directory =
            ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_accounting(
                &self.db.load_shielded_root_ledger()?.unwrap_or_default(),
                PROTOCOL.archive_shard_epoch_span,
                vec![manifest.clone()],
                self.local_archive_replicas().await?,
                self.db.load_shielded_archive_service_ledgers()?,
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
        let directory =
            ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_accounting(
                &self.db.load_shielded_root_ledger()?.unwrap_or_default(),
                PROTOCOL.archive_shard_epoch_span,
                vec![manifest.clone()],
                Vec::new(),
                self.db.load_shielded_archive_service_ledgers()?,
            )?;
        manifest.validate(&directory)?;
        self.db.store_shielded_archive_provider(&manifest)?;
        self.archive_manifests
            .write()
            .await
            .insert(manifest.provider_id, manifest);
        self.refresh_archive_operator_scorecards().await?;
        Ok(())
    }

    async fn ingest_archive_replica(
        &self,
        record: &NodeRecordV2,
        replica: ArchiveReplicaAttestation,
    ) -> Result<()> {
        if replica.provider_id != record.node_id {
            bail!("archive replica provider id does not match the envelope signer");
        }
        let directory = self.local_archive_directory().await?;
        replica.validate(&directory)?;
        self.db.store_shielded_archive_replica(&replica)?;
        self.archive_replicas
            .write()
            .await
            .insert((replica.provider_id, replica.shard_id), replica);
        self.refresh_archive_operator_scorecards().await?;
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
            if let Err(err) = self
                .sign_and_send_to_record_related(
                    record,
                    WireTopic::RequestArchiveShard,
                    encode_archive_shard_request(&ArchiveShardRequest {
                        provider_id: provider.provider_id,
                        shard_id,
                    }),
                    None,
                )
                .await
            {
                let _ = self
                    .update_archive_service_ledger(
                        provider.provider_id,
                        provider.manifest_digest,
                        |ledger| ledger.record_archive_shard_failure(),
                    )
                    .await;
                return Err(err);
            }
        }
        Ok(())
    }

    async fn rebalance_archive_replication(&self) -> Result<()> {
        let directory = self.local_archive_directory().await?;
        if directory.shards.is_empty() {
            return Ok(());
        }

        let local_node_id = self.local_node_id().await;
        let local_manifest = self.local_archive_manifest().await?;
        let mut candidates = {
            let guard = self.known_records.read().await;
            guard.keys().copied().collect::<Vec<_>>()
        };
        candidates.push(local_node_id);
        let assignments = directory.custody_assignments(
            &candidates,
            PROTOCOL.archive_provider_replica_count as usize,
        );
        for assignment in assignments {
            if !assignment.custodians.contains(&local_node_id) {
                continue;
            }
            let Some(shard) = directory.shard(assignment.shard_id) else {
                continue;
            };
            if local_manifest.serves_shard(shard.shard_id, &shard.root_digest) {
                continue;
            }
            let missing_epochs = (shard.first_epoch..=shard.last_epoch)
                .filter(|epoch| {
                    self.db
                        .load_shielded_nullifier_epoch(*epoch)
                        .ok()
                        .flatten()
                        .is_none()
                })
                .collect::<Vec<_>>();
            if missing_epochs.is_empty() {
                continue;
            }
            self.request_missing_archive_epochs(&missing_epochs).await?;
            break;
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
        let directory =
            ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_accounting(
                &self.db.load_shielded_root_ledger()?.unwrap_or_default(),
                PROTOCOL.archive_shard_epoch_span,
                vec![manifest.clone()],
                Vec::new(),
                self.db.load_shielded_archive_service_ledgers()?,
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

    async fn mark_anchor_vote_cast(&self, proposal_hash: [u8; 32]) -> bool {
        let now = Instant::now();
        let mut guard = self.cast_anchor_votes.lock().await;
        guard
            .retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(PENDING_ANCHOR_TTL_SECS));
        guard.insert(proposal_hash, now).is_none()
    }

    fn pending_anchor_vote_power(
        proposal: &AnchorProposal,
        votes: &BTreeMap<ValidatorId, ValidatorVote>,
    ) -> Result<u64> {
        let mut signed_voting_power = 0u64;
        for voter in votes.keys() {
            let validator = proposal
                .validator_set
                .validator(voter)
                .ok_or_else(|| anyhow!("pending anchor vote references unknown validator"))?;
            signed_voting_power = signed_voting_power
                .checked_add(validator.voting_power)
                .ok_or_else(|| anyhow!("pending anchor vote power overflow"))?;
        }
        Ok(signed_voting_power)
    }

    fn pending_anchor_qc(
        pending: &PendingAnchorCertification,
    ) -> Result<Option<QuorumCertificate>> {
        let signed_voting_power =
            Self::pending_anchor_vote_power(&pending.proposal, &pending.votes)?;
        if signed_voting_power < pending.proposal.validator_set.quorum_threshold {
            return Ok(None);
        }
        Ok(Some(QuorumCertificate::from_votes(
            &pending.proposal.validator_set,
            pending.proposal.vote_target(),
            pending.votes.values().cloned().collect(),
        )?))
    }

    async fn remove_pending_anchor_proposal(&self, proposal_hash: [u8; 32]) {
        let mut guard = self.pending_anchor_certifications.lock().await;
        guard.remove(&proposal_hash);
    }

    async fn fail_pending_anchor_proposal(&self, proposal_hash: [u8; 32], message: String) {
        let reply = {
            let mut guard = self.pending_anchor_certifications.lock().await;
            guard
                .remove(&proposal_hash)
                .and_then(|mut pending| pending.reply.take())
        };
        if let Some(reply) = reply {
            let _ = reply.send(Err(anyhow!(message)));
        }
    }

    async fn register_pending_anchor_proposal(
        &self,
        proposal: AnchorProposal,
        proposal_message_id: [u8; 32],
        local_vote: ValidatorVote,
        reply: oneshot::Sender<Result<QuorumCertificate>>,
    ) -> Result<()> {
        let proposal_hash = proposal.hash;
        let mut pending = PendingAnchorCertification {
            proposal,
            proposal_message_id,
            votes: BTreeMap::new(),
            reply: Some(reply),
            created_at: Instant::now(),
        };
        pending.votes.insert(local_vote.voter, local_vote);
        let ready_qc = Self::pending_anchor_qc(&pending)?;

        let mut guard = self.pending_anchor_certifications.lock().await;
        guard.retain(|_, pending| {
            pending.created_at.elapsed() < Duration::from_secs(PENDING_ANCHOR_TTL_SECS)
        });
        if let Some(qc) = ready_qc {
            if let Some(reply) = pending.reply.take() {
                let _ = reply.send(Ok(qc));
            }
            guard.remove(&proposal_hash);
        } else {
            guard.insert(proposal_hash, pending);
        }
        Ok(())
    }

    async fn start_local_anchor_proposal(
        &self,
        proposal: AnchorProposal,
        reply: oneshot::Sender<Result<QuorumCertificate>>,
    ) -> Result<()> {
        let start_result: Result<(SignedEnvelope, ValidatorVote)> = async {
            let identity = self.identity.read().await;
            let local_validator_id = ValidatorId::from_hot_key(&identity.record().auth_spki);
            let local_validator = proposal
                .validator_set
                .validator(&local_validator_id)
                .cloned()
                .ok_or_else(|| anyhow!("local node is not part of the finalized validator set"))?;
            let expected_leader = proposal.validator_set.leader_for(proposal.position);
            if local_validator.id != expected_leader {
                bail!(
                    "local node is not the deterministic leader for epoch {} slot {}",
                    proposal.position.epoch,
                    proposal.position.slot
                );
            }
            let target = proposal.vote_target();
            let local_vote = ValidatorVote {
                voter: local_validator.id,
                target: target.clone(),
                signature: identity.sign_consensus_message(&target.signing_bytes())?,
            };
            drop(identity);
            let envelope = self
                .sign_topic_envelope(
                    WireTopic::AnchorProposal,
                    canonical::encode_anchor_proposal(&proposal)?,
                )
                .await?;
            Ok((envelope, local_vote))
        }
        .await;

        let (envelope, local_vote) = match start_result {
            Ok(values) => values,
            Err(err) => {
                let _ = reply.send(Err(anyhow!(err.to_string())));
                return Ok(());
            }
        };

        let proposal_message_id = envelope.message_id;
        self.register_pending_anchor_proposal(
            proposal.clone(),
            proposal_message_id,
            local_vote,
            reply,
        )
        .await?;
        if let Err(err) = self.broadcast_envelope(envelope, None).await {
            self.fail_pending_anchor_proposal(proposal.hash, err.to_string())
                .await;
        }
        Ok(())
    }

    async fn cast_anchor_proposal_vote(
        &self,
        proposer_record: &NodeRecordV2,
        proposal_message_id: [u8; 32],
        proposal: AnchorProposal,
    ) -> Result<()> {
        let local_node_id = self.local_node_id().await;
        if proposer_record.node_id == local_node_id {
            return Ok(());
        }
        let parent = if proposal.num == 0 {
            None
        } else {
            Some(
                self.db
                    .get::<Anchor>("epoch", &(proposal.num - 1).to_le_bytes())?
                    .ok_or_else(|| anyhow!("checkpoint proposal parent is unavailable"))?,
            )
        };
        validate_anchor_proposal_against_store(&proposal, parent.as_ref(), self.db.as_ref())
            .map_err(|err| anyhow!(err))?;
        validate_anchor_proposal_author(&proposal, proposer_record)?;
        if proposal.ordering_path == OrderingPath::DagBftSharedState {
            if let Some(missing_batch_id) =
                first_missing_shared_state_dag_batch(&proposal, self.db.as_ref())?
            {
                self.queue_shared_state_proposal(
                    proposer_record.clone(),
                    proposal_message_id,
                    proposal.clone(),
                )
                .await;
                self.request_shared_state_dag_batch_from(proposer_record.clone(), missing_batch_id)
                    .await?;
                return Ok(());
            }
            validate_shared_state_dag_plan_for_proposal(
                &proposal,
                parent.as_ref(),
                self.db.as_ref(),
            )
            .map_err(|err| anyhow!(err))?;
        }

        let local_validator_id = {
            let identity = self.identity.read().await;
            ValidatorId::from_hot_key(&identity.record().auth_spki)
        };
        let Some(local_validator) = proposal
            .validator_set
            .validator(&local_validator_id)
            .cloned()
        else {
            return Ok(());
        };
        if !self.mark_anchor_vote_cast(proposal.hash).await {
            return Ok(());
        }
        let target = proposal.vote_target();
        let signature = {
            let identity = self.identity.read().await;
            identity.sign_consensus_message(&target.signing_bytes())?
        };
        let vote = ValidatorVote {
            voter: local_validator.id,
            target: target.clone(),
            signature,
        };

        let _ = self
            .sign_and_send_to_record_related(
                proposer_record.clone(),
                WireTopic::ValidatorVote,
                canonical::encode_validator_vote(&vote)?,
                Some(proposal_message_id),
            )
            .await?;
        Ok(())
    }

    async fn record_anchor_vote(
        &self,
        voter_record: &NodeRecordV2,
        response_to_message_id: Option<[u8; 32]>,
        vote: ValidatorVote,
    ) -> Result<()> {
        let proposal_hash = vote.target.block_digest;
        let mut completion = None;
        {
            let mut guard = self.pending_anchor_certifications.lock().await;
            guard.retain(|_, pending| {
                pending.created_at.elapsed() < Duration::from_secs(PENDING_ANCHOR_TTL_SECS)
            });
            let Some(pending) = guard.get_mut(&proposal_hash) else {
                return Ok(());
            };
            if response_to_message_id != Some(pending.proposal_message_id) {
                bail!("validator vote correlation does not match the pending proposal");
            }
            validate_anchor_vote(&pending.proposal, voter_record, &vote)?;
            pending.votes.insert(vote.voter, vote);
            if let Some(qc) = Self::pending_anchor_qc(pending)? {
                completion = Some((pending.reply.take(), qc));
            }
            if completion.is_some() {
                guard.remove(&proposal_hash);
            }
        }
        if let Some((Some(reply), qc)) = completion {
            let _ = reply.send(Ok(qc));
        }
        Ok(())
    }

    async fn queue_shared_state_proposal(
        &self,
        proposer_record: NodeRecordV2,
        proposal_message_id: [u8; 32],
        proposal: AnchorProposal,
    ) {
        let mut guard = self.pending_shared_state_proposals.lock().await;
        guard.retain(|pending| {
            pending.received_at.elapsed() < Duration::from_secs(PENDING_ANCHOR_TTL_SECS)
        });
        guard.push(PendingSharedStateProposal {
            proposer_record,
            proposal_message_id,
            proposal,
            received_at: Instant::now(),
        });
    }

    async fn request_shared_state_dag_batch(&self, batch_id: [u8; 32]) -> Result<()> {
        let _ = self
            .sign_and_send_to_targets(
                WireTopic::RequestSharedStateDagBatch,
                encode_bytes32_body(&batch_id),
                REQUEST_FANOUT_DEFAULT,
            )
            .await?;
        Ok(())
    }

    async fn request_shared_state_dag_batch_from(
        &self,
        record: NodeRecordV2,
        batch_id: [u8; 32],
    ) -> Result<()> {
        let _ = self
            .sign_and_send_to_record_related(
                record,
                WireTopic::RequestSharedStateDagBatch,
                encode_bytes32_body(&batch_id),
                None,
            )
            .await?;
        Ok(())
    }

    async fn ingest_shared_state_dag_batch(&self, batch: SharedStateDagBatch) -> Result<()> {
        if self
            .db
            .load_shared_state_dag_batch(&batch.batch_id)?
            .is_some()
        {
            return Ok(());
        }
        batch.batch.validate_against_store(self.db.as_ref())?;
        let validator_set = load_or_compute_active_validator_set(self.db.as_ref(), batch.epoch)
            .map_err(anyhow::Error::from)?;
        if validator_set.validator(&batch.author).is_none() {
            bail!("shared-state DAG batch author is not part of the active validator set");
        }
        if self
            .db
            .has_shared_state_dag_batch_author(batch.epoch, batch.round, &batch.author)?
        {
            let existing = self
                .db
                .load_shared_state_dag_round(batch.epoch, batch.round)?;
            if existing.iter().any(|existing| {
                existing.author == batch.author && existing.batch_id != batch.batch_id
            }) {
                bail!(
                    "validator already authored a different shared-state DAG batch for this round"
                );
            }
        }
        self.db.store_shared_state_dag_batch(&batch)?;

        let pending = {
            let mut guard = self.pending_shared_state_proposals.lock().await;
            std::mem::take(&mut *guard)
        };
        for pending in pending {
            let _ = self
                .cast_anchor_proposal_vote(
                    &pending.proposer_record,
                    pending.proposal_message_id,
                    pending.proposal,
                )
                .await;
        }

        let next_height = self
            .db
            .get::<Anchor>("epoch", b"latest")?
            .map(|anchor| anchor.num.saturating_add(1))
            .unwrap_or(0);
        self.process_pending_anchors(next_height).await?;
        Ok(())
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
        self.enforce_peer_allowed(record.node_id).await?;
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
        if self.enforce_peer_allowed(record.node_id).await.is_err() {
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
                    if let Err(e) = self.record_inbound_message(record.node_id).await {
                        net_log!(
                            "⚠️  Closing {} after ingress policy violation: {}",
                            hex::encode(record.node_id),
                            e
                        );
                        connection.close(0u32.into(), b"rate-limit");
                        break;
                    }
                    let message: WireMessage = match decode_wire_message(&bytes) {
                        Ok(message) => message,
                        Err(e) => {
                            self.record_validation_failure(record.node_id).await;
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
                            self.record_validation_failure(record.node_id).await;
                            net_log!(
                                "⚠️  Protocol violation from {}: unexpected post-handshake hello",
                                hex::encode(record.node_id)
                            );
                            connection.close(0u32.into(), b"protocol-violation");
                            break;
                        }
                        WireMessage::Envelope(envelope) => {
                            if let Err(e) = self.handle_envelope(record.clone(), envelope).await {
                                self.record_validation_failure(record.node_id).await;
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
            WireTopic::AnchorProposal => {
                let proposal = canonical::decode_anchor_proposal(&frame.body)?;
                self.cast_anchor_proposal_vote(&record, message_id, proposal)
                    .await?;
            }
            WireTopic::ValidatorVote => {
                let vote = canonical::decode_validator_vote(&frame.body)?;
                self.record_anchor_vote(&record, response_to_message_id, vote)
                    .await?;
            }
            WireTopic::SharedStateDagBatch => {
                let batch = canonical::decode_shared_state_dag_batch(&frame.body)?;
                self.ingest_shared_state_dag_batch(batch).await?;
            }
            WireTopic::CoinCandidate => {
                let candidate = canonical::decode_coin_candidate(&frame.body)?;
                match validate_coin_candidate(&candidate, &self.db) {
                    Ok(()) => {
                        let key = Store::candidate_key(&candidate.epoch_hash, &candidate.id);
                        self.db.put("coin_candidate", &key, &candidate)?;
                    }
                    Err(err) => {
                        metrics::VALIDATION_FAIL_COIN.inc();
                        bail!("rejecting invalid coin candidate: {err}");
                    }
                }
            }
            WireTopic::Coin => {
                let _ = canonical::decode_coin(&frame.body)?;
                bail!("unsolicited committed coin frames are not part of the canonical protocol");
            }
            WireTopic::Tx => {
                let tx = canonical::decode_tx(&frame.body)?;
                let tx_id = tx.id()?;
                if self.db.get_raw_bytes("tx", &tx_id)?.is_some() {
                    return Ok(());
                }
                if matches!(tx, crate::transaction::Tx::SharedState(_)) {
                    if self.db.load_shared_state_pending_tx(&tx_id)?.is_some() {
                        return Ok(());
                    }
                    match validate_tx(&tx, &self.db) {
                        Ok(()) => {
                            self.db.store_shared_state_pending_tx(&tx_id, &tx)?;
                        }
                        Err(err) => return Err(anyhow!("rejecting invalid tx: {err}")),
                    }
                } else {
                    match validate_tx(&tx, &self.db) {
                        Ok(()) => {
                            tx.apply(&self.db)?;
                        }
                        Err(err) => return Err(anyhow!("rejecting invalid tx: {err}")),
                    }
                }
                let _ = self.tx_tx.send(tx);
            }
            WireTopic::RequestSharedStateDagBatch => {
                let batch_id = decode_bytes32_body(&frame.body)?;
                if let Some(batch) = self.db.load_shared_state_dag_batch(&batch_id)? {
                    let _ = self
                        .sign_and_send_to_peer_related(
                            record.node_id,
                            WireTopic::SharedStateDagBatch,
                            canonical::encode_shared_state_dag_batch(&batch)?,
                            Some(message_id),
                        )
                        .await?;
                }
            }
            WireTopic::CompactEpoch => {
                let compact = canonical::decode_compact_epoch(&frame.body)?;
                metrics::COMPACT_EPOCHS_RECV.inc();
                self.handle_anchor(compact.anchor).await?;
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
                    match validate_coin_candidate(&candidate, &self.db) {
                        Ok(()) => {
                            let key = Store::candidate_key(&candidate.epoch_hash, &candidate.id);
                            let _ = self.db.put("coin_candidate", &key, &candidate);
                        }
                        Err(err) => {
                            metrics::VALIDATION_FAIL_COIN.inc();
                            bail!("rejecting invalid epoch candidate response: {err}");
                        }
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
                let _ = decode_bytes32_body(&frame.body)?;
                bail!("coin-by-id recovery is unsupported; use epoch transaction recovery only");
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
                    message_id,
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
            WireTopic::ArchiveReplica => {
                let replica = canonical::decode_archive_replica_attestation(&frame.body)?;
                self.ingest_archive_replica(&record, replica).await?;
            }
            WireTopic::ArchiveCustodyCommitment => {
                let commitment = canonical::decode_archive_custody_commitment(&frame.body)?;
                self.ingest_archive_custody_commitment(&record, commitment)
                    .await?;
            }
            WireTopic::ArchiveRetrievalReceipt => {
                let receipt = canonical::decode_archive_retrieval_receipt(&frame.body)?;
                self.ingest_archive_retrieval_receipt(&record, receipt)
                    .await?;
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
                let shard_count = bundle.epochs.len() as u64;
                for archived in bundle.epochs {
                    self.db.store_shielded_nullifier_epoch(&archived)?;
                }
                let _ = self
                    .update_archive_service_ledger(
                        manifest.provider_id,
                        manifest.manifest_digest,
                        |ledger| ledger.record_archive_shard_success(shard_count.max(1), unix_ms()),
                    )
                    .await;
                if let Some(request_message_id) = response_to_message_id {
                    let receipt = ArchiveRetrievalReceipt::new(
                        self.local_node_id().await,
                        manifest.provider_id,
                        manifest.manifest_digest,
                        crate::shielded::ArchiveRetrievalKind::ArchiveShard,
                        request_message_id,
                        Some(message_id),
                        bundle.shard.first_epoch,
                        bundle.shard.last_epoch,
                        Some(bundle.shard.shard_id),
                        shard_count.max(1).min(u32::MAX as u64) as u32,
                        true,
                        0,
                        unix_ms(),
                    );
                    let _ = self.publish_archive_retrieval_receipt(receipt).await;
                }
                let _ = self.refresh_local_archive_manifest().await;
                let _ = self.refresh_local_archive_replicas().await;
                let _ = self.refresh_local_archive_custody_commitments().await;
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
            candidates.sort_by_key(|pending| pending.anchor.hash);

            let mut adopted = false;
            let mut rejected = Vec::new();
            for pending in candidates {
                if validate_anchor(&pending.anchor, &self.db).is_ok() {
                    if self
                        .db
                        .get::<Anchor>("epoch", &pending.anchor.num.to_le_bytes())?
                        .is_none()
                    {
                        self.adopt_anchor(pending.anchor.clone()).await?;
                        adopted = true;
                        break;
                    }
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
        if anchor.ordering_path == OrderingPath::DagBftSharedState {
            let proposal = AnchorProposal {
                num: anchor.num,
                hash: anchor.hash,
                parent_hash: anchor.parent_hash,
                position: anchor.position,
                ordering_path: anchor.ordering_path,
                merkle_root: anchor.merkle_root,
                coin_count: anchor.coin_count,
                dag_round: anchor.dag_round,
                dag_frontier: anchor.dag_frontier.clone(),
                ordered_batch_ids: anchor.ordered_batch_ids.clone(),
                ordered_tx_root: anchor.ordered_tx_root,
                ordered_tx_count: anchor.ordered_tx_count,
                validator_set: anchor.validator_set.clone(),
            };
            if let Some(missing_batch_id) =
                first_missing_shared_state_dag_batch(&proposal, self.db.as_ref())?
            {
                let _ = self.request_shared_state_dag_batch(missing_batch_id).await;
                self.buffer_anchor(anchor).await;
                return Ok(());
            }
        }

        match validate_anchor(&anchor, &self.db) {
            Ok(()) => {
                if self
                    .db
                    .get::<Anchor>("epoch", &anchor.num.to_le_bytes())?
                    .is_none()
                {
                    self.adopt_anchor(anchor.clone()).await?;
                }
                self.process_pending_anchors(anchor.num.saturating_add(1))
                    .await?;
            }
            Err(_err) => {
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
        Ok(())
    }

    async fn adopt_anchor(&self, anchor: Anchor) -> Result<()> {
        let parent = if anchor.num == 0 {
            None
        } else {
            self.db
                .get::<Anchor>("epoch", &(anchor.num - 1).to_le_bytes())?
        };
        let shared_state_batch = if anchor.ordering_path == OrderingPath::DagBftSharedState {
            Some(
                reconstruct_shared_state_dag_plan(
                    self.db.as_ref(),
                    parent.as_ref(),
                    &anchor.validator_set,
                    anchor.dag_round,
                )?
                .ok_or_else(|| {
                    anyhow!("shared-state DAG plan for finalized anchor is unavailable")
                })?
                .aggregate_batch,
            )
        } else {
            None
        };
        persist_finalized_anchor(self.db.as_ref(), &anchor)?;
        metrics::EPOCH_HEIGHT.set(anchor.num as i64);
        if let Err(e) = persist_selected_for_anchor(&self.db, &anchor) {
            net_log!(
                "⚠️  Unable to reconstruct selected coins for epoch {}: {}",
                anchor.num,
                e
            );
            let _ = self.repair_epoch_state(anchor.num).await;
        }
        if let Some(batch) = shared_state_batch {
            for tx in batch.txs {
                let _ = self.tx_tx.send(tx);
            }
        }
        let _ = self.anchor_tx.send(anchor);
        Ok(())
    }
}

pub async fn spawn(
    net_cfg: config::Net,
    p2p_cfg: config::P2p,
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
        Some(db.effective_chain_id()),
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
    if net_cfg.strict_trust && bootstrap_records.is_empty() {
        bail!("strict trust is enabled, but no bootstrap node records were configured");
    }
    let trust_policy = TrustPolicy::load(&bootstrap_records, &net_cfg.trust_updates)?
        .with_strict_root_pinning(net_cfg.strict_trust);
    let banned_node_ids = net_cfg
        .banned_peer_ids
        .iter()
        .filter_map(|value| decode_node_id_hex(value).ok())
        .collect::<HashSet<_>>();

    let persisted_records = load_persisted_records(&db, &banned_node_ids)?;
    let persisted_archive_manifests = db.load_shielded_archive_providers()?;
    let persisted_archive_replicas = db.load_shielded_archive_replicas()?;
    let (anchor_tx, _) = broadcast::channel(256);
    let (tx_tx, _) = broadcast::channel(256);
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
        p2p_policy: P2pPolicy::from_config(&p2p_cfg),
        peer_policy: Arc::new(AsyncMutex::new(HashMap::new())),
        known_records: Arc::new(RwLock::new(HashMap::new())),
        peers: Arc::new(RwLock::new(HashMap::new())),
        connected_peers: connected_peers.clone(),
        pending_anchors: Arc::new(AsyncMutex::new(HashMap::new())),
        seen_messages: Arc::new(AsyncMutex::new(HashMap::new())),
        anchor_tx: anchor_tx.clone(),
        tx_tx: tx_tx.clone(),
        headers_tx: headers_tx.clone(),
        checkpoint_tx: checkpoint_tx.clone(),
        pending_anchor_certifications: Arc::new(AsyncMutex::new(HashMap::new())),
        pending_shared_state_proposals: Arc::new(AsyncMutex::new(Vec::new())),
        cast_anchor_votes: Arc::new(AsyncMutex::new(HashMap::new())),
        archive_manifests: Arc::new(RwLock::new(
            persisted_archive_manifests
                .into_iter()
                .map(|manifest| (manifest.provider_id, manifest))
                .collect(),
        )),
        archive_replicas: Arc::new(RwLock::new(
            persisted_archive_replicas
                .into_iter()
                .map(|replica| ((replica.provider_id, replica.shard_id), replica))
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
    let _ = state.refresh_local_archive_replicas().await;
    let _ = state.refresh_local_archive_custody_commitments().await;

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let net = Arc::new(Network {
        anchor_tx,
        tx_tx,
        headers_tx,
        checkpoint_tx,
        command_tx: command_tx.clone(),
        connected_peers,
        shutdown,
        tasks,
        endpoint: Arc::new(AsyncMutex::new(Some(endpoint.clone()))),
        db: state.db.clone(),
        identity: Some(state.identity.clone()),
        archive_sync_timeout: Duration::from_secs(net_cfg.sync_timeout_secs.max(1)),
        local_node_id: local_record.node_id,
        known_records: state.known_records.clone(),
        archive_manifests: state.archive_manifests.clone(),
        archive_replicas: state.archive_replicas.clone(),
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
                                match state.refresh_local_archive_replicas().await {
                                    Ok(replicas) => {
                                        for replica in replicas {
                                            match canonical::encode_archive_replica_attestation(&replica) {
                                                Ok(bytes) => {
                                                    let _ = state
                                                        .sign_and_broadcast(WireTopic::ArchiveReplica, bytes)
                                                        .await;
                                                }
                                                Err(e) => {
                                                    net_log!("⚠️  Failed to encode local archive replica: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        net_log!("⚠️  Failed to refresh local archive replicas: {}", e);
                                    }
                                }
                                match state.refresh_local_archive_custody_commitments().await {
                                    Ok(commitments) => {
                                        for commitment in commitments {
                                            match canonical::encode_archive_custody_commitment(&commitment) {
                                                Ok(bytes) => {
                                                    let _ = state
                                                        .sign_and_broadcast(
                                                            WireTopic::ArchiveCustodyCommitment,
                                                            bytes,
                                                        )
                                                        .await;
                                                }
                                                Err(e) => {
                                                    net_log!("⚠️  Failed to encode archive custody commitment: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        net_log!("⚠️  Failed to refresh local archive custody commitments: {}", e);
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
            let mut rebalance_tick =
                tokio::time::interval(Duration::from_secs(ARCHIVE_REBALANCE_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = state.shutdown.cancelled() => break,
                    _ = rebalance_tick.tick() => {
                        if let Err(e) = state.rebalance_archive_replication().await {
                            net_log!("⚠️  Failed to rebalance archive replication: {}", e);
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
        NetworkCommand::GossipSharedStateDagBatch(batch) => {
            state
                .sign_and_broadcast(
                    WireTopic::SharedStateDagBatch,
                    canonical::encode_shared_state_dag_batch(&batch)?,
                )
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
        NetworkCommand::ProposeAnchor { proposal, reply } => {
            if let Err(err) = state.start_local_anchor_proposal(proposal, reply).await {
                net_log!("⚠️  Failed to start local anchor proposal: {}", err);
            }
        }
        NetworkCommand::AbandonAnchorProposal(proposal_hash) => {
            state.remove_pending_anchor_proposal(proposal_hash).await;
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
            let _ = coin_id;
            bail!("coin-by-id recovery is unsupported; use epoch transaction recovery only");
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
        NetworkCommand::GossipArchiveRetrievalReceipt(receipt) => {
            state.publish_archive_retrieval_receipt(receipt).await?;
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
    pub fn select_pending_shared_state_batch(&self) -> Result<Option<SharedStateBatch>> {
        select_pending_shared_state_batch(self.db.as_ref())
    }

    pub async fn submit_tx(&self, tx: &crate::transaction::Tx) -> Result<[u8; 32]> {
        let tx_id = tx.id()?;
        if self.db.get_raw_bytes("tx", &tx_id)?.is_some() {
            return Ok(tx_id);
        }
        match tx {
            crate::transaction::Tx::OrdinaryPrivateTransfer(_) => {
                tx.apply(&self.db)?;
                let _ = self.tx_tx.send(tx.clone());
                let _ = self.command_tx.send(NetworkCommand::GossipTx(tx.clone()));
            }
            crate::transaction::Tx::SharedState(_) => {
                if self.db.load_shared_state_pending_tx(&tx_id)?.is_none() {
                    tx.validate(&self.db)?;
                    self.db.store_shared_state_pending_tx(&tx_id, tx)?;
                    let _ = self.tx_tx.send(tx.clone());
                    let _ = self.command_tx.send(NetworkCommand::GossipTx(tx.clone()));
                }
            }
        }
        Ok(tx_id)
    }

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

    pub async fn gossip_shared_state_dag_batch(&self, batch: &SharedStateDagBatch) {
        let _ = self
            .command_tx
            .send(NetworkCommand::GossipSharedStateDagBatch(batch.clone()));
    }

    pub async fn gossip_compact_epoch(&self, compact: CompactEpoch) {
        let _ = self
            .command_tx
            .send(NetworkCommand::GossipCompactEpoch(compact));
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

    fn checkpoint_subscribe(&self) -> broadcast::Receiver<CheckpointBatchEvent> {
        self.checkpoint_tx.subscribe()
    }

    async fn update_archive_service_ledger(
        &self,
        provider_id: [u8; 32],
        provider_manifest_digest: [u8; 32],
        update: impl FnOnce(&mut ArchiveServiceLedger),
    ) -> Result<()> {
        let mut ledger = self
            .db
            .load_shielded_archive_service_ledger(&provider_id)?
            .unwrap_or_else(|| ArchiveServiceLedger::new(provider_id, provider_manifest_digest));
        if ledger.provider_manifest_digest != provider_manifest_digest {
            ledger = ArchiveServiceLedger::new(provider_id, provider_manifest_digest);
        }
        update(&mut ledger);
        self.db.store_shielded_archive_service_ledger(&ledger)?;
        let directory = self.local_archive_directory().await?;
        for scorecard in directory.operator_scorecards(
            PROTOCOL.archive_provider_replica_count as usize,
            PROTOCOL.archive_retention_horizon_epochs,
        ) {
            self.db
                .store_shielded_archive_operator_scorecard(&scorecard)?;
        }
        Ok(())
    }

    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> {
        self.anchor_tx.clone()
    }

    pub async fn certify_local_anchor(
        &self,
        num: u64,
        parent: Option<&Anchor>,
        merkle_root: [u8; 32],
        coin_count: u32,
        dag_round: u64,
        dag_frontier: Vec<[u8; 32]>,
        ordered_batch_ids: Vec<[u8; 32]>,
        ordered_tx_root: [u8; 32],
        ordered_tx_count: u32,
        ordering_path: OrderingPath,
    ) -> Result<Anchor> {
        let position = Anchor::position_for_num(num);
        let validator_set = match parent {
            Some(parent) if parent.position.epoch == position.epoch => parent.validator_set.clone(),
            Some(_) => load_or_compute_active_validator_set(self.db.as_ref(), position.epoch)?,
            None => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or_else(|| anyhow!("local node identity is unavailable"))?
                    .clone();
                let identity = identity.read().await;
                register_genesis_local_validator_pool(self.db.as_ref(), identity.record())?;
                load_or_compute_active_validator_set(self.db.as_ref(), position.epoch)?
            }
        };

        let proposal = AnchorProposal::new(
            num,
            parent.map(|parent| parent.hash),
            ordering_path,
            merkle_root,
            coin_count,
            dag_round,
            dag_frontier,
            ordered_batch_ids,
            ordered_tx_root,
            ordered_tx_count,
            validator_set,
        )?;

        let timeout_ms = match ordering_path {
            OrderingPath::FastPathPrivateTransfer => FAST_PATH_TIMEOUT_MS,
            OrderingPath::DagBftSharedState => DAG_BFT_TIMEOUT_MS,
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::ProposeAnchor {
                proposal: proposal.clone(),
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("anchor proposal command channel closed"))?;

        let qc = match tokio::time::timeout(Duration::from_millis(timeout_ms), reply_rx).await {
            Ok(Ok(Ok(qc))) => qc,
            Ok(Ok(Err(err))) => {
                let _ = self
                    .command_tx
                    .send(NetworkCommand::AbandonAnchorProposal(proposal.hash));
                return Err(err);
            }
            Ok(Err(_)) => {
                let _ = self
                    .command_tx
                    .send(NetworkCommand::AbandonAnchorProposal(proposal.hash));
                bail!("local anchor proposal waiter dropped");
            }
            Err(_) => {
                let _ = self
                    .command_tx
                    .send(NetworkCommand::AbandonAnchorProposal(proposal.hash));
                bail!(
                    "timed out collecting quorum votes for epoch {} slot {}",
                    proposal.position.epoch,
                    proposal.position.slot
                );
            }
        };

        let anchor = proposal.finalize(qc)?;
        anchor.validate_against_parent(parent)?;
        Ok(anchor)
    }

    pub async fn author_local_shared_state_batch(
        &self,
        batch: &SharedStateBatch,
    ) -> Result<SharedStateDagBatch> {
        batch.validate_against_store(self.db.as_ref())?;
        let parent = self.db.get::<Anchor>("epoch", b"latest")?;
        let next_num = parent
            .as_ref()
            .map(|anchor| anchor.num.saturating_add(1))
            .unwrap_or(0);
        let position = Anchor::position_for_num(next_num);
        let validator_set = match parent.as_ref() {
            Some(parent) if parent.position.epoch == position.epoch => parent.validator_set.clone(),
            Some(_) => load_or_compute_active_validator_set(self.db.as_ref(), position.epoch)?,
            None => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or_else(|| anyhow!("local node identity is unavailable"))?
                    .clone();
                let identity = identity.read().await;
                register_genesis_local_validator_pool(self.db.as_ref(), identity.record())?;
                load_or_compute_active_validator_set(self.db.as_ref(), position.epoch)?
            }
        };
        let local_validator_id = {
            let identity = self
                .identity
                .as_ref()
                .ok_or_else(|| anyhow!("local node identity is unavailable"))?
                .read()
                .await;
            ValidatorId::from_hot_key(&identity.record().auth_spki)
        };
        if validator_set.validator(&local_validator_id).is_none() {
            bail!("local node is not part of the active validator set");
        }

        let finalized_round = shared_state_parent_round(parent.as_ref(), position.epoch);
        let highest_quorum_round = highest_quorum_shared_state_dag_plan(
            self.db.as_ref(),
            parent.as_ref(),
            &validator_set,
        )?
        .map(|plan| plan.round)
        .unwrap_or(finalized_round);
        let highest_seen_round = self
            .db
            .load_highest_shared_state_dag_round(position.epoch)?
            .unwrap_or(finalized_round);
        let target_round = if highest_seen_round > highest_quorum_round {
            highest_quorum_round.saturating_add(1)
        } else {
            highest_quorum_round.saturating_add(1)
        };

        if self.db.has_shared_state_dag_batch_author(
            position.epoch,
            target_round,
            &local_validator_id,
        )? {
            let existing = self
                .db
                .load_shared_state_dag_round(position.epoch, target_round)?
                .into_iter()
                .find(|existing| existing.author == local_validator_id)
                .ok_or_else(|| anyhow!("shared-state DAG author index is inconsistent"))?;
            return Ok(existing);
        }

        let parents = if target_round == 1 {
            Vec::new()
        } else if target_round.saturating_sub(1) == finalized_round {
            shared_state_parent_frontier(parent.as_ref(), position.epoch)
        } else {
            reconstruct_shared_state_dag_plan(
                self.db.as_ref(),
                parent.as_ref(),
                &validator_set,
                target_round.saturating_sub(1),
            )?
            .ok_or_else(|| anyhow!("previous shared-state DAG round is not yet quorum-available"))?
            .frontier
        };

        let dag_batch = SharedStateDagBatch::new(
            position.epoch,
            target_round,
            local_validator_id,
            parents,
            batch.clone(),
        )?;
        self.db.store_shared_state_dag_batch(&dag_batch)?;
        self.gossip_shared_state_dag_batch(&dag_batch).await;
        Ok(dag_batch)
    }

    pub async fn finalize_available_shared_state_anchor(&self) -> Result<Option<Anchor>> {
        let parent = self.db.get::<Anchor>("epoch", b"latest")?;
        let next_num = parent
            .as_ref()
            .map(|anchor| anchor.num.saturating_add(1))
            .unwrap_or(0);
        let position = Anchor::position_for_num(next_num);
        let validator_set = match parent.as_ref() {
            Some(parent) if parent.position.epoch == position.epoch => parent.validator_set.clone(),
            Some(_) => load_or_compute_active_validator_set(self.db.as_ref(), position.epoch)?,
            None => {
                let identity = self
                    .identity
                    .as_ref()
                    .ok_or_else(|| anyhow!("local node identity is unavailable"))?
                    .clone();
                let identity = identity.read().await;
                register_genesis_local_validator_pool(self.db.as_ref(), identity.record())?;
                load_or_compute_active_validator_set(self.db.as_ref(), position.epoch)?
            }
        };
        let local_validator_id = {
            let identity = self
                .identity
                .as_ref()
                .ok_or_else(|| anyhow!("local node identity is unavailable"))?
                .read()
                .await;
            ValidatorId::from_hot_key(&identity.record().auth_spki)
        };
        if validator_set.leader_for(position) != local_validator_id {
            return Ok(None);
        }

        let Some(plan) = highest_quorum_shared_state_dag_plan(
            self.db.as_ref(),
            parent.as_ref(),
            &validator_set,
        )?
        else {
            return Ok(None);
        };
        let ordered_batch_ids = plan
            .ordered_batches
            .iter()
            .map(|batch| batch.batch_id)
            .collect::<Vec<_>>();
        let anchor = self
            .certify_local_anchor(
                next_num,
                parent.as_ref(),
                [0u8; 32],
                0,
                plan.round,
                plan.frontier.clone(),
                ordered_batch_ids,
                plan.aggregate_batch.ordered_tx_root,
                plan.aggregate_batch.ordered_tx_count()?,
                OrderingPath::DagBftSharedState,
            )
            .await?;
        persist_finalized_anchor(self.db.as_ref(), &anchor)?;
        let _ = self.anchor_tx.send(anchor.clone());
        for tx in &plan.aggregate_batch.txs {
            let _ = self.tx_tx.send(tx.clone());
        }
        self.gossip_anchor(&anchor).await;
        Ok(Some(anchor))
    }

    pub async fn finalize_local_shared_state_batch(
        &self,
        batch: &SharedStateBatch,
    ) -> Result<Anchor> {
        let _ = self.author_local_shared_state_batch(batch).await?;
        self.finalize_available_shared_state_anchor()
            .await?
            .ok_or_else(|| {
                anyhow!("shared-state DAG round is not yet quorum-available for finalization")
            })
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
        let mut replicas = self
            .archive_replicas
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let local_directory =
            ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_accounting(
                &ledger,
                PROTOCOL.archive_shard_epoch_span,
                providers,
                replicas.clone(),
                self.db.load_shielded_archive_service_ledgers()?,
            )?;
        replicas.extend(local_archive_replica_attestations(
            self.local_node_id,
            &local_directory,
            PROTOCOL.archive_retention_horizon_epochs,
        )?);
        let mut custody_commitments = self.db.load_shielded_archive_custody_commitments()?;
        custody_commitments.extend(local_archive_custody_commitments(
            self.local_node_id,
            &local_directory,
            PROTOCOL.archive_provider_replica_count as usize,
            PROTOCOL.archive_retention_horizon_epochs,
        )?);
        ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_evidence(
            &ledger,
            PROTOCOL.archive_shard_epoch_span,
            local_directory.providers,
            replicas,
            self.db.load_shielded_archive_service_ledgers()?,
            custody_commitments,
            self.db.load_shielded_archive_retrieval_receipts()?,
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
    ) -> Result<CheckpointBatchEvent> {
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
                    return Ok(event);
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
                    Ok(Some(request.local_checkpoint()?.empty_extension()))
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let mut segment_results = vec![Vec::new(); requests.len()];
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
            let started = Instant::now();
            let receipt_from_epoch = batch
                .requests
                .iter()
                .flat_map(|routed| routed.request.queries.iter().map(|query| query.epoch))
                .min()
                .unwrap_or(0);
            let receipt_through_epoch = batch
                .requests
                .iter()
                .flat_map(|routed| routed.request.queries.iter().map(|query| query.epoch))
                .max()
                .unwrap_or(receipt_from_epoch);
            let mut request_message_id = None;
            let response_result: Result<CheckpointBatchEvent> = async {
                if manifest.provider_id == self.local_node_id {
                    Ok(CheckpointBatchEvent {
                        message_id: [0u8; 32],
                        response_to_message_id: [0u8; 32],
                        provider_id: manifest.provider_id,
                        response: self
                            .local_checkpoint_batch_response(&checkpoint_request)
                            .await?
                            .ok_or_else(|| {
                                anyhow!("local archive provider refused checkpoint batch")
                            })?,
                    })
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
                    request_message_id = Some(
                        reply_rx
                            .await
                            .map_err(|_| anyhow!("checkpoint request sender dropped"))??,
                    );
                    self.await_checkpoint_batch_response(
                        &mut response_rx,
                        request_message_id.expect("request message id"),
                        manifest.provider_id,
                        deadline,
                    )
                    .await
                }
            }
            .await;
            let emit_failure_receipt = |latency_ms: u64| {
                if let Some(request_message_id) = request_message_id {
                    let _ = self
                        .command_tx
                        .send(NetworkCommand::GossipArchiveRetrievalReceipt(
                            ArchiveRetrievalReceipt::new(
                                self.local_node_id,
                                manifest.provider_id,
                                manifest.manifest_digest,
                                crate::shielded::ArchiveRetrievalKind::CheckpointBatch,
                                request_message_id,
                                None,
                                receipt_from_epoch,
                                receipt_through_epoch,
                                None,
                                0,
                                false,
                                latency_ms,
                                unix_ms(),
                            ),
                        ));
                }
            };
            let checkpoint_event = match response_result {
                Ok(response) => response,
                Err(err) => {
                    let latency_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                    emit_failure_receipt(latency_ms);
                    let _ = self
                        .update_archive_service_ledger(
                            manifest.provider_id,
                            manifest.manifest_digest,
                            |ledger| ledger.record_checkpoint_failure(),
                        )
                        .await;
                    return Err(err);
                }
            };
            let response_message_id = checkpoint_event.message_id;
            let checkpoint_response = checkpoint_event.response;

            if let Err(err) = checkpoint_response.verify_against_manifest(&manifest, &directory) {
                let latency_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                emit_failure_receipt(latency_ms);
                let _ = self
                    .update_archive_service_ledger(
                        manifest.provider_id,
                        manifest.manifest_digest,
                        |ledger| ledger.record_checkpoint_failure(),
                    )
                    .await;
                return Err(err);
            }
            if checkpoint_response.responses.len() != batch.requests.len() {
                let latency_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                emit_failure_receipt(latency_ms);
                bail!("checkpoint batch response length mismatch");
            }
            let served_segments = batch
                .requests
                .iter()
                .filter(|routed| routed.request_index.is_some())
                .count() as u64;
            let latency_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            if let Some(request_message_id) = request_message_id {
                let _ = self
                    .command_tx
                    .send(NetworkCommand::GossipArchiveRetrievalReceipt(
                        ArchiveRetrievalReceipt::new(
                            self.local_node_id,
                            manifest.provider_id,
                            manifest.manifest_digest,
                            crate::shielded::ArchiveRetrievalKind::CheckpointBatch,
                            request_message_id,
                            Some(response_message_id),
                            receipt_from_epoch,
                            receipt_through_epoch,
                            None,
                            served_segments.max(1).min(u32::MAX as u64) as u32,
                            true,
                            latency_ms,
                            unix_ms(),
                        ),
                    ));
            }
            let _ = self
                .update_archive_service_ledger(
                    manifest.provider_id,
                    manifest.manifest_digest,
                    |ledger| {
                        ledger.record_checkpoint_success(
                            served_segments.max(1),
                            latency_ms,
                            unix_ms(),
                        )
                    },
                )
                .await;

            for (routed, response) in batch.requests.iter().zip(checkpoint_response.responses) {
                response.verify_against_request(&routed.request, &manifest, &directory)?;
                if let Some(request_index) = routed.request_index {
                    let mut blinding = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut blinding);
                    segment_results[request_index]
                        .push((routed.segment_index, response.rerandomize(blinding)));
                }
            }
        }

        for (request_index, request) in requests.iter().enumerate() {
            if request.queries.is_empty() {
                continue;
            }
            let mut segments = std::mem::take(&mut segment_results[request_index]);
            if segments.is_empty() {
                bail!("missing routed historical extension segments");
            }
            segments.sort_by_key(|(segment_index, _)| *segment_index);
            let mut aggregate_blinding = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut aggregate_blinding);
            results[request_index] = Some(HistoricalUnspentExtension::aggregate(
                request.local_checkpoint()?,
                segments.into_iter().map(|(_, segment)| segment).collect(),
                aggregate_blinding,
            )?);
        }

        results
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow!("missing aggregated historical extension"))
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
            | WireTopic::AnchorProposal
            | WireTopic::SharedStateDagBatch
            | WireTopic::CoinCandidate
            | WireTopic::Tx
            | WireTopic::CompactEpoch
            | WireTopic::NodeRecord
    )
}

fn chain_compatible(local_chain_id: Option<[u8; 32]>, remote_chain_id: Option<[u8; 32]>) -> bool {
    matches!(
        (local_chain_id, remote_chain_id),
        (Some(local_chain_id), Some(remote_chain_id)) if local_chain_id == remote_chain_id
    )
}

fn validate_coin_candidate(coin: &CoinCandidate, db: &Store) -> Result<(), String> {
    let _anchor: Anchor = db
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

    let expected_digest = CoinCandidate::admission_digest(
        &coin.epoch_hash,
        coin.nonce,
        &coin.creator_address,
        &coin.creator_pk,
        &coin.lock_hash,
    );
    if coin.admission_digest != expected_digest {
        return Err("candidate admission digest mismatch".into());
    }
    if Coin::calculate_id(&coin.epoch_hash, coin.nonce, &coin.creator_address) != coin.id {
        return Err("Coin ID mismatch".into());
    }
    Ok(())
}

fn validate_tx(tx: &crate::transaction::Tx, db: &Store) -> Result<(), String> {
    tx.validate(db).map_err(|e| e.to_string())
}

fn validate_anchor_proposal_against_store(
    proposal: &AnchorProposal,
    parent: Option<&Anchor>,
    db: &Store,
) -> Result<(), String> {
    proposal
        .validate_against_parent(parent)
        .map_err(|e| e.to_string())?;
    let epoch_boundary = parent
        .map(|parent| parent.position.epoch != proposal.position.epoch)
        .unwrap_or(true);
    if !epoch_boundary {
        return Ok(());
    }
    match expected_validator_set_for_epoch(db, proposal.position.epoch)
        .map_err(|e| e.to_string())?
    {
        Some(expected) => {
            if expected != proposal.validator_set {
                return Err(format!(
                    "checkpoint committee for epoch {} does not match canonical activation state",
                    proposal.position.epoch
                ));
            }
        }
        None if proposal.num == 0 => {}
        None => {
            return Err(format!(
                "missing validator pool state for epoch {}; cannot validate epoch-boundary committee change",
                proposal.position.epoch
            ));
        }
    }
    Ok(())
}

fn validate_anchor_proposal_author(
    proposal: &AnchorProposal,
    proposer_record: &NodeRecordV2,
) -> Result<()> {
    let proposer_id = ValidatorId::from_hot_key(&proposer_record.auth_spki);
    let expected_leader = proposal.validator_set.leader_for(proposal.position);
    if proposer_id != expected_leader {
        bail!("checkpoint proposal author is not the deterministic leader");
    }
    if proposal.validator_set.validator(&proposer_id).is_none() {
        bail!("checkpoint proposal author is not part of the validator set");
    }
    Ok(())
}

fn validate_anchor_vote(
    proposal: &AnchorProposal,
    voter_record: &NodeRecordV2,
    vote: &ValidatorVote,
) -> Result<()> {
    let expected_voter = ValidatorId::from_hot_key(&voter_record.auth_spki);
    if vote.voter != expected_voter {
        bail!("validator vote author does not match the envelope signer");
    }
    let target = proposal.vote_target();
    if vote.target != target {
        bail!("validator vote target does not match the pending proposal");
    }
    let validator = proposal
        .validator_set
        .validator(&vote.voter)
        .ok_or_else(|| anyhow!("validator vote references an unknown validator"))?;
    UnparsedPublicKey::new(&ML_DSA_65, validator.keys.hot_ml_dsa_65_spki.as_slice())
        .verify(&target.signing_bytes(), vote.signature.as_slice())
        .map_err(|_| anyhow!("validator vote signature verification failed"))?;
    Ok(())
}

fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    let parent = if anchor.num == 0 {
        None
    } else {
        Some(
            db.get::<Anchor>("epoch", &(anchor.num - 1).to_le_bytes())
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("Previous checkpoint #{} not found", anchor.num - 1))?,
        )
    };
    validate_anchor_proposal_against_store(
        &AnchorProposal {
            num: anchor.num,
            hash: anchor.hash,
            parent_hash: anchor.parent_hash,
            position: anchor.position,
            ordering_path: anchor.ordering_path,
            merkle_root: anchor.merkle_root,
            coin_count: anchor.coin_count,
            dag_round: anchor.dag_round,
            dag_frontier: anchor.dag_frontier.clone(),
            ordered_batch_ids: anchor.ordered_batch_ids.clone(),
            ordered_tx_root: anchor.ordered_tx_root,
            ordered_tx_count: anchor.ordered_tx_count,
            validator_set: anchor.validator_set.clone(),
        },
        parent.as_ref(),
        db,
    )?;
    if anchor.ordering_path == OrderingPath::DagBftSharedState {
        validate_shared_state_dag_plan_for_proposal(
            &AnchorProposal {
                num: anchor.num,
                hash: anchor.hash,
                parent_hash: anchor.parent_hash,
                position: anchor.position,
                ordering_path: anchor.ordering_path,
                merkle_root: anchor.merkle_root,
                coin_count: anchor.coin_count,
                dag_round: anchor.dag_round,
                dag_frontier: anchor.dag_frontier.clone(),
                ordered_batch_ids: anchor.ordered_batch_ids.clone(),
                ordered_tx_root: anchor.ordered_tx_root,
                ordered_tx_count: anchor.ordered_tx_count,
                validator_set: anchor.validator_set.clone(),
            },
            parent.as_ref(),
            db,
        )?;
    }
    anchor
        .validate_against_parent(parent.as_ref())
        .map_err(|e| e.to_string())
}

fn shared_state_parent_round(parent: Option<&Anchor>, epoch: u64) -> u64 {
    parent
        .filter(|parent| parent.position.epoch == epoch)
        .map(|parent| parent.dag_round)
        .unwrap_or(0)
}

fn shared_state_parent_frontier(parent: Option<&Anchor>, epoch: u64) -> Vec<[u8; 32]> {
    parent
        .filter(|parent| parent.position.epoch == epoch)
        .map(|parent| parent.dag_frontier.clone())
        .unwrap_or_default()
}

fn sort_dag_batches_for_round(batches: &mut [SharedStateDagBatch]) {
    batches.sort_by(|left, right| {
        left.author
            .cmp(&right.author)
            .then(left.batch_id.cmp(&right.batch_id))
    });
}

fn frontier_for_round(batches: &[SharedStateDagBatch]) -> Vec<[u8; 32]> {
    let mut frontier = batches
        .iter()
        .map(|batch| batch.batch_id)
        .collect::<Vec<_>>();
    frontier.sort();
    frontier
}

fn first_missing_shared_state_dag_batch(
    proposal: &AnchorProposal,
    db: &Store,
) -> Result<Option<[u8; 32]>> {
    let mut seen = BTreeSet::new();
    for batch_id in proposal
        .dag_frontier
        .iter()
        .chain(proposal.ordered_batch_ids.iter())
    {
        if !seen.insert(*batch_id) {
            continue;
        }
        if db.load_shared_state_dag_batch(batch_id)?.is_none() {
            return Ok(Some(*batch_id));
        }
    }
    Ok(None)
}

fn validate_shared_state_dag_batch_basic(
    batch: &SharedStateDagBatch,
    validator_set: &crate::consensus::ValidatorSet,
    expected_parents: &[[u8; 32]],
    db: &Store,
) -> Result<()> {
    batch.validate()?;
    if batch.epoch != validator_set.epoch {
        bail!("shared-state DAG batch epoch does not match the validator set");
    }
    if validator_set.validator(&batch.author).is_none() {
        bail!("shared-state DAG batch author is not part of the active validator set");
    }
    if batch.parents != expected_parents {
        bail!("shared-state DAG batch parent frontier does not match the deterministic previous round frontier");
    }
    if db
        .load_shared_state_dag_batch_finalization(&batch.batch_id)?
        .is_some()
    {
        bail!("shared-state DAG batch is already finalized");
    }
    batch.batch.validate_against_store(db)?;
    Ok(())
}

fn reconstruct_shared_state_dag_plan(
    db: &Store,
    parent: Option<&Anchor>,
    validator_set: &crate::consensus::ValidatorSet,
    target_round: u64,
) -> Result<Option<SharedStateDagPlan>> {
    if target_round == 0 {
        return Ok(None);
    }

    let epoch = validator_set.epoch;
    let finalized_round = shared_state_parent_round(parent, epoch);
    if target_round <= finalized_round {
        return Ok(None);
    }

    let mut previous_frontier = shared_state_parent_frontier(parent, epoch);
    let mut ordered_batches = Vec::new();

    for round in (finalized_round + 1)..=target_round {
        let mut round_batches = db.load_shared_state_dag_round(epoch, round)?;
        if round_batches.is_empty() {
            return Ok(None);
        }
        sort_dag_batches_for_round(&mut round_batches);
        let expected_parents = if round == 1 {
            Vec::new()
        } else {
            previous_frontier.clone()
        };
        let mut seen_authors = HashSet::new();
        let mut signed_voting_power = 0u64;
        for batch in &round_batches {
            if !seen_authors.insert(batch.author) {
                bail!("shared-state DAG round contains duplicate validator authors");
            }
            validate_shared_state_dag_batch_basic(batch, validator_set, &expected_parents, db)?;
            let validator = validator_set
                .validator(&batch.author)
                .ok_or_else(|| anyhow!("missing validator for shared-state DAG batch author"))?;
            signed_voting_power = signed_voting_power
                .checked_add(validator.voting_power)
                .ok_or_else(|| anyhow!("shared-state DAG round voting power overflow"))?;
        }
        if signed_voting_power < validator_set.quorum_threshold {
            return Ok(None);
        }
        previous_frontier = frontier_for_round(&round_batches);
        ordered_batches.extend(round_batches);
    }

    let aggregate_batch = SharedStateBatch::from_dag_batches(&ordered_batches)?;
    if aggregate_batch.is_empty() {
        return Ok(None);
    }

    Ok(Some(SharedStateDagPlan {
        round: target_round,
        frontier: previous_frontier,
        ordered_batches,
        aggregate_batch,
    }))
}

fn highest_quorum_shared_state_dag_plan(
    db: &Store,
    parent: Option<&Anchor>,
    validator_set: &crate::consensus::ValidatorSet,
) -> Result<Option<SharedStateDagPlan>> {
    let epoch = validator_set.epoch;
    let finalized_round = shared_state_parent_round(parent, epoch);
    let Some(highest_round) = db.load_highest_shared_state_dag_round(epoch)? else {
        return Ok(None);
    };
    if highest_round <= finalized_round {
        return Ok(None);
    }

    let mut best = None;
    for round in (finalized_round + 1)..=highest_round {
        match reconstruct_shared_state_dag_plan(db, parent, validator_set, round)? {
            Some(plan) => best = Some(plan),
            None => break,
        }
    }
    Ok(best)
}

fn validate_shared_state_dag_plan_for_proposal(
    proposal: &AnchorProposal,
    parent: Option<&Anchor>,
    db: &Store,
) -> Result<(), String> {
    if proposal.ordering_path != OrderingPath::DagBftSharedState {
        return Err("shared-state DAG plan cannot be attached to a fast-path proposal".to_string());
    }
    let plan =
        reconstruct_shared_state_dag_plan(db, parent, &proposal.validator_set, proposal.dag_round)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "shared-state DAG round is not locally quorum-available".to_string())?;
    let ordered_batch_ids = plan
        .ordered_batches
        .iter()
        .map(|batch| batch.batch_id)
        .collect::<Vec<_>>();
    if proposal.dag_frontier != plan.frontier {
        return Err(
            "shared-state DAG frontier does not match the locally reconstructed quorum frontier"
                .to_string(),
        );
    }
    if proposal.ordered_batch_ids != ordered_batch_ids {
        return Err(
            "shared-state ordered DAG batch list does not match the locally reconstructed order"
                .to_string(),
        );
    }
    if proposal.ordered_tx_root != plan.aggregate_batch.ordered_tx_root {
        return Err(
            "shared-state ordered tx root does not match the locally reconstructed DAG order"
                .to_string(),
        );
    }
    let ordered_tx_count = plan
        .aggregate_batch
        .ordered_tx_count()
        .map_err(|e| e.to_string())?;
    if proposal.ordered_tx_count != ordered_tx_count {
        return Err(
            "shared-state ordered tx count does not match the locally reconstructed DAG order"
                .to_string(),
        );
    }
    Ok(())
}

fn select_pending_shared_state_batch(db: &Store) -> Result<Option<SharedStateBatch>> {
    let mut pending = db.load_shared_state_pending_txs()?;
    pending.sort_by_key(|(tx_id, _)| *tx_id);

    let mut selected = Vec::new();
    let mut seen_nullifiers = HashSet::new();
    let mut seen_conflicts = HashSet::new();
    for (tx_id, tx) in pending {
        if !matches!(tx, crate::transaction::Tx::SharedState(_)) {
            let _ = db.delete_shared_state_pending_tx(&tx_id);
            continue;
        }
        if db.get_raw_bytes("tx", &tx_id)?.is_some() {
            let _ = db.delete_shared_state_pending_tx(&tx_id);
            continue;
        }
        if tx.validate(db).is_err() {
            let _ = db.delete_shared_state_pending_tx(&tx_id);
            continue;
        }
        let conflict_keys = tx.shared_state_conflict_keys()?;
        if tx
            .nullifiers()
            .iter()
            .any(|nullifier| seen_nullifiers.contains(nullifier))
            || conflict_keys.iter().any(|key| seen_conflicts.contains(key))
        {
            continue;
        }
        for nullifier in tx.nullifiers() {
            seen_nullifiers.insert(*nullifier);
        }
        for conflict_key in conflict_keys {
            seen_conflicts.insert(conflict_key);
        }
        selected.push(tx);
        if selected.len() >= PROTOCOL.max_shared_state_txs_per_checkpoint as usize {
            break;
        }
    }

    if selected.is_empty() {
        return Ok(None);
    }
    Ok(Some(SharedStateBatch::new(selected)?))
}

fn persist_finalized_anchor(db: &Store, anchor: &Anchor) -> Result<()> {
    if anchor.ordering_path == OrderingPath::DagBftSharedState {
        let parent = if anchor.num == 0 {
            None
        } else {
            db.get::<Anchor>("epoch", &(anchor.num - 1).to_le_bytes())?
        };
        validate_shared_state_dag_plan_for_proposal(
            &AnchorProposal {
                num: anchor.num,
                hash: anchor.hash,
                parent_hash: anchor.parent_hash,
                position: anchor.position,
                ordering_path: anchor.ordering_path,
                merkle_root: anchor.merkle_root,
                coin_count: anchor.coin_count,
                dag_round: anchor.dag_round,
                dag_frontier: anchor.dag_frontier.clone(),
                ordered_batch_ids: anchor.ordered_batch_ids.clone(),
                ordered_tx_root: anchor.ordered_tx_root,
                ordered_tx_count: anchor.ordered_tx_count,
                validator_set: anchor.validator_set.clone(),
            },
            parent.as_ref(),
            db,
        )
        .map_err(|err| anyhow!(err))?;
        let dag_batches = anchor
            .ordered_batch_ids
            .iter()
            .map(|batch_id| {
                db.load_shared_state_dag_batch(batch_id)?.ok_or_else(|| {
                    anyhow!("shared-state DAG batch for finalized anchor is missing")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let batch = SharedStateBatch::from_dag_batches(&dag_batches)?;
        batch.apply_finalized(db)?;
        for batch_id in &anchor.ordered_batch_ids {
            db.mark_shared_state_dag_batch_finalized(batch_id, anchor.num)?;
        }
    }
    db.store_validator_committee(&anchor.validator_set)?;
    db.put("epoch", &anchor.num.to_le_bytes(), anchor)?;
    db.put("epoch", b"latest", anchor)?;
    db.put("anchor", &anchor.hash, anchor)?;
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
