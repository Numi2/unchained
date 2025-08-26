// network.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Network layer for Unchained.
//! Spends are gossiped/served using the V3 hashlock flow only.

use crate::{
    storage::Store, epoch::Anchor, coin::{Coin, CoinCandidate}, transfer::Spend, crypto, config, sync::SyncState,
};
use crate::consensus::{
    calculate_retarget_consensus,
    TARGET_LEADING_ZEROS,
    DEFAULT_MEM_KIB,
    RETARGET_INTERVAL,
};
use std::sync::{Arc, Mutex};
// use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};
// use pqcrypto_traits::kem::Ciphertext as _;
use libp2p::{
    gossipsub,
    identity, quic, swarm::SwarmEvent, PeerId, Swarm, Transport, Multiaddr,
    futures::StreamExt, core::muxing::StreamMuxerBox,
};
use libp2p::gossipsub::{
    IdentTopic, MessageAuthenticity, IdentityTransform,
    AllowAllSubscriptionFilter, Behaviour as Gossipsub, Event as GossipsubEvent,
};
use bincode;
use std::collections::{HashMap, VecDeque, HashSet};
use std::time::Instant;
use std::str::FromStr;
use tokio::sync::{broadcast, mpsc};
use hex;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use serde::{Serialize, Deserialize};
use once_cell::sync::Lazy;
use rocksdb::WriteBatch;

static QUIET_NET: AtomicBool = AtomicBool::new(false);
/// Toggle routine network message logging. Errors/warnings still log.
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

// Routine network logs (informational chatter) — always suppressed by default.
// Enable only for debugging by toggling ALLOW_ROUTINE_NET to true.
static ALLOW_ROUTINE_NET: AtomicBool = AtomicBool::new(false);
macro_rules! net_routine {
    ($($arg:tt)*) => {
        if ALLOW_ROUTINE_NET.load(Ordering::Relaxed) {
            println!($($arg)*);
        }
    };
}
#[allow(unused_imports)]
use net_routine;

// Pending compact epochs keyed by epoch hash; TTL is enforced on access
static PENDING_COMPACTS: Lazy<Mutex<std::collections::HashMap<[u8;32], (CompactEpoch, std::time::Instant)>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
// Dedup map for epoch txn requests to avoid spamming
static RECENT_EPOCH_TX_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
static EPOCH_TX_REQS_PER_PEER: Lazy<Mutex<std::collections::HashMap<PeerId, (std::time::Instant, u32)>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
const EPOCH_TX_REQ_DEDUP_MS: u64 = 1000;
const MAX_COMPACT_REQ_BATCH: usize = 132; // 132 is the max number of compact epochs that can be requested in a single batch
const PENDING_COMPACT_TTL_SECS: u64 = 60;
const COMPACT_MAX_MISSING_PCT_DEFAULT: u8 = 20;
const MAX_FULL_BODY_REQ_BATCH: usize = 256;
const EPOCH_TX_REQS_PER_PEER_WINDOW_MS: u64 = 2000;
const EPOCH_TX_REQS_PER_PEER_MAX: u32 = 8;
// Candidate request dedup/throttle
static RECENT_EPOCH_CAND_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
const EPOCH_CAND_REQ_DEDUP_MS: u64 = 1000;
const MAX_EPOCH_CAND_RESP: usize = 2048;

#[allow(dead_code)]
fn try_publish_gossip(
    swarm: &mut Swarm<Gossipsub<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &str,
    data: Vec<u8>,
    context: &str,
) {
    if let Err(e) = swarm.behaviour_mut().publish(IdentTopic::new(topic), data) {
        let es = e.to_string();
        let is_insufficient = es.contains("InsufficientPeers")
            || es.contains("InsufficientPeersForTopic")
            || es.contains("NoPeersSubscribedToTopic");
        // Treat temporary queue saturation as benign for noisy contexts
        if (context == "epoch-leaves" || context == "epoch-leaves-req") && es.contains("AllQueuesFull") { return; }
        if !is_insufficient {
            eprintln!("⚠️  Failed to publish {} ({}): {}", context, topic, es);
        }
    }
}

const TOP_ANCHOR: &str = "unchained/anchor/v1";
const TOP_COIN: &str = "unchained/coin/v1";
const TOP_COIN_PROOF_REQUEST: &str = "unchained/coin_proof_request/v1";
const TOP_COIN_PROOF_RESPONSE: &str = "unchained/coin_proof_response/v1";
const TOP_SPEND: &str = "unchained/spend/v2";
const TOP_SPEND_REQUEST: &str = "unchained/spend_request/v2";    // payload: [u8;32] coin_id
const TOP_SPEND_RESPONSE: &str = "unchained/spend_response/v2";  // payload: Option<Spend>
const TOP_EPOCH_REQUEST: &str = "unchained/epoch_request/v1";
const TOP_COIN_REQUEST: &str = "unchained/coin_request/v1";
const TOP_LATEST_REQUEST: &str = "unchained/latest_request/v1";
const TOP_PEER_ADDR: &str = "unchained/peer_addr/v1";            // payload: String multiaddr
const TOP_EPOCH_LEAVES: &str = "unchained/epoch_leaves/v1";       // payload: EpochLeavesBundle
const TOP_EPOCH_LEAVES_REQUEST: &str = "unchained/epoch_leaves_request/v1"; // payload: u64 epoch number
const TOP_EPOCH_SELECTED_REQUEST: &str = "unchained/epoch_selected_request/v1"; // payload: u64 epoch number
const TOP_EPOCH_SELECTED_RESPONSE: &str = "unchained/epoch_selected_response/v1"; // payload: SelectedIdsBundle
// Commitment request/response topics removed to prevent metadata leakage
const TOP_RATE_LIMITED: &str = "unchained/limited_24h/v1";
// Headers-first skeleton sync (additive topics; legacy-safe)
const TOP_EPOCH_HEADERS_REQUEST: &str = "unchained/epoch_headers_request/v1";   // payload: EpochHeadersRange
const TOP_EPOCH_HEADERS_RESPONSE: &str = "unchained/epoch_headers_response/v1"; // payload: EpochHeadersBatch
// Compact epoch relay (additive)
const TOP_EPOCH_COMPACT: &str = "unchained/epoch_compact/v1";   // payload: CompactEpoch
const TOP_EPOCH_GET_TXN: &str = "unchained/epoch_get_txn/v1";    // payload: (epoch_hash, indexes)
const TOP_EPOCH_TXN: &str = "unchained/epoch_txn/v1";            // payload: (epoch_hash, txs)
// New additive topics for pre-seal candidate pulls
const TOP_EPOCH_CANDIDATES_REQUEST: &str = "unchained/epoch_candidates_request/v1"; // payload: [u8;32] epoch_hash
const TOP_EPOCH_CANDIDATES_RESPONSE: &str = "unchained/epoch_candidates_response/v1"; // payload: EpochCandidatesResponse

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitedMessage {
    pub content: String,
}

// Removed unused TopicQuota

#[derive(Debug, Clone)]
struct PeerScore {
    validation_failures: u32,
    banned_until: Option<Instant>,
    message_count: u32,
    window_start: Instant,
    max_validation_failures: u32,
    ban_duration_secs: u64,
    rate_limit_window_secs: u64,
    max_messages_per_window: u32,
}

impl PeerScore {
    fn new(p2p_cfg: &config::P2p) -> Self {
        Self {
            validation_failures: 0,
            banned_until: None,
            message_count: 0,
            window_start: Instant::now(),
            max_validation_failures: p2p_cfg.max_validation_failures_per_peer,
            ban_duration_secs: p2p_cfg.peer_ban_duration_secs,
            rate_limit_window_secs: p2p_cfg.rate_limit_window_secs,
            max_messages_per_window: p2p_cfg.max_messages_per_window,
        }
    }

    fn record_validation_failure(&mut self) {
        self.validation_failures += 1;
        if self.validation_failures >= self.max_validation_failures {
            self.banned_until = Some(Instant::now() + std::time::Duration::from_secs(self.ban_duration_secs));
        }
    }

    fn is_banned(&mut self) -> bool {
        if let Some(banned_until) = self.banned_until {
            if Instant::now() < banned_until {
                return true;
            }
            self.banned_until = None;
            self.validation_failures = 0;
        }
        false
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > std::time::Duration::from_secs(self.rate_limit_window_secs) {
            self.window_start = now;
            self.message_count = 0;
        }
        self.message_count += 1;
        self.message_count <= self.max_messages_per_window
    }
}

fn validate_coin_candidate(coin: &CoinCandidate, db: &Store) -> Result<(), String> {
    // Use committing epoch if known; fallback to legacy anchor lookup by hash
    let anchor: Anchor = db.get_epoch_for_coin(&coin.id)
        .ok()
        .flatten()
        .and_then(|n| db.get::<Anchor>("epoch", &n.to_le_bytes()).ok().flatten())
        .or_else(|| db.get::<Anchor>("anchor", &coin.epoch_hash).ok().flatten())
        .ok_or_else(|| format!("Coin references non-existent committed epoch (coin_id={})", hex::encode(coin.id)))?;

    if coin.creator_address == [0u8; 32] { return Err("Invalid creator address".into()); }
    
    let mem_kib = anchor.mem_kib;
    let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
    let calculated_pow = crypto::argon2id_pow(&header, mem_kib).map_err(|e| e.to_string())?;
    if calculated_pow != coin.pow_hash { return Err("PoW validation failed".into()); }
    if !calculated_pow.iter().take(anchor.difficulty).all(|&b| b == 0) {
        return Err(format!(
            "PoW does not meet difficulty: requires {} leading zero bytes",
            anchor.difficulty
        ));
    }
    if Coin::calculate_id(&coin.epoch_hash, coin.nonce, &coin.creator_address) != coin.id { return Err("Coin ID mismatch".into()); }
    Ok(())
}

fn validate_spend(sp: &Spend, db: &Store) -> Result<(), String> {
    // Delegate to core validator for single source of truth
    match sp.validate(db) {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    if anchor.hash == [0u8; 32] { return Err("Anchor hash cannot be zero".into()); }
    if anchor.difficulty == 0 { return Err("Difficulty cannot be zero".into()); }
    if anchor.mem_kib == 0 { return Err("Memory cannot be zero".into()); }
    // Special-case genesis: no previous anchor exists. Validate self-consistency only.
    if anchor.num == 0 {
        // Check cumulative work matches expected for the given difficulty
        let expected = Anchor::expected_work_for_difficulty(anchor.difficulty);
        if anchor.cumulative_work != expected { return Err("Genesis cumulative_work mismatch".into()); }
        // Recompute hash = blake3(merkle_root)
        let mut h = blake3::Hasher::new();
        h.update(&anchor.merkle_root);
        let recomputed = *h.finalize().as_bytes();
        if recomputed != anchor.hash { return Err("Genesis hash mismatch".into()); }
        return Ok(());
    }
    if anchor.merkle_root == [0u8; 32] && anchor.coin_count > 0 { return Err("Merkle root cannot be zero when coins are present".into()); }
    if anchor.num == 0 {
        // Enforce consensus-locked parameters for genesis
        if anchor.difficulty != TARGET_LEADING_ZEROS || anchor.mem_kib != DEFAULT_MEM_KIB {
            net_log!(
                "❌ Consensus mismatch at genesis: expected diff={}, mem_kib={}, got diff={}, mem_kib={}",
                TARGET_LEADING_ZEROS, DEFAULT_MEM_KIB, anchor.difficulty, anchor.mem_kib
            );
            return Err("Consensus params mismatch at genesis".into());
        }
        if anchor.cumulative_work != Anchor::expected_work_for_difficulty(anchor.difficulty) {
            return Err("Genesis cumulative work incorrect".into());
        }
        // For genesis, hash should be BLAKE3(merkle_root)
        let mut h = blake3::Hasher::new();
        h.update(&anchor.merkle_root);
        let expected = *h.finalize().as_bytes();
        if anchor.hash != expected { return Err("Anchor hash mismatch".into()); }
        return Ok(());
    }
    let prev: Anchor = db
        .get("epoch", &(anchor.num - 1).to_le_bytes())
        .map_err(|e| e.to_string())?
        .ok_or(format!("Previous anchor #{} not found", anchor.num - 1))?;

    // Deterministically compute expected consensus parameters for this height.
    let (exp_diff, exp_mem) = if anchor.num % RETARGET_INTERVAL == 0 {
        // Collect the last RETARGET_INTERVAL anchors ending at prev
        let mut recent: Vec<Anchor> = Vec::new();
        let start = anchor.num.saturating_sub(RETARGET_INTERVAL);
        for n in start..anchor.num {
            if let Ok(Some(a)) = db.get::<Anchor>("epoch", &n.to_le_bytes()) {
                recent.push(a);
            }
        }
        calculate_retarget_consensus(&recent)
    } else {
        (prev.difficulty, prev.mem_kib)
    };
    if anchor.difficulty != exp_diff || anchor.mem_kib != exp_mem {
        net_log!(
            "❌ Consensus mismatch at epoch {}: expected diff={}, mem_kib={}, got diff={}, mem_kib={}",
            anchor.num, exp_diff, exp_mem, anchor.difficulty, anchor.mem_kib
        );
        return Err(format!(
            "Consensus params mismatch. Expected difficulty={}, mem_kib={}, got difficulty={}, mem_kib={}",
            exp_diff, exp_mem, anchor.difficulty, anchor.mem_kib
        ));
    }
    let expected_work = Anchor::expected_work_for_difficulty(anchor.difficulty);
    let expected_cum = prev.cumulative_work.saturating_add(expected_work);
    if anchor.cumulative_work != expected_cum {
        return Err(format!("Invalid cumulative work. Expected: {}, Got: {}", expected_cum, anchor.cumulative_work));
    }
    // Recompute anchor hash: BLAKE3(merkle_root || prev.hash)
    let mut h = blake3::Hasher::new();
    h.update(&anchor.merkle_root);
    h.update(&prev.hash);
    let expected = *h.finalize().as_bytes();
    if anchor.hash != expected { return Err("Anchor hash mismatch".into()); }
    Ok(())
}

pub type NetHandle = Arc<Network>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinProofRequest { pub coin_id: [u8; 32] }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinProofResponse {
    pub coin: Coin,
    pub anchor: Anchor,
    pub proof: Vec<([u8; 32], bool)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochLeavesBundle {
    pub epoch_num: u64,
    pub merkle_root: [u8; 32],
    pub leaves: Vec<[u8; 32]>, // sorted leaf hashes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedIdsBundle {
    pub epoch_num: u64,
    pub merkle_root: [u8; 32],
    pub coin_ids: Vec<[u8; 32]>, // selected coin ids for this epoch
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCandidatesResponse {
    pub epoch_hash: [u8; 32],
    pub candidates: Vec<CoinCandidate>,
}

// Commitment request/response data structures removed
// --- Headers-first skeleton sync message types (additive, legacy-safe) ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochHeadersRange {
    pub start_height: u64,
    pub count: u32,
}

// --- Compact epoch structures ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactEpoch {
    pub anchor: Anchor,
    pub short_ids: Vec<[u8; 8]>,      // short ids of coins expected to be in mempool/view
    pub prefilled: Vec<(u32, Coin)>,  // (index, full coin)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochGetTxn {
    pub epoch_hash: [u8;32],
    pub indexes: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochTxn {
    pub epoch_hash: [u8;32],
    pub coins: Vec<Coin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochHeadersBatch {
    pub start_height: u64,
    pub headers: Vec<Anchor>,
}

#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    proof_tx: broadcast::Sender<CoinProofResponse>,
    spend_tx: broadcast::Sender<Spend>,
    // removed commitment channels
    rate_limited_tx: broadcast::Sender<RateLimitedMessage>,
    headers_tx: broadcast::Sender<EpochHeadersBatch>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
    connected_peers: Arc<Mutex<HashSet<PeerId>>>,
}

#[derive(Debug, Clone)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(CoinCandidate),
    
    GossipSpend(Spend),
    GossipCompactEpoch(CompactEpoch),
    GossipRateLimited(RateLimitedMessage),
    RequestEpoch(u64),
    RequestEpochHeadersRange(EpochHeadersRange),
    RequestSpend([u8;32]),
    RequestCoin([u8; 32]),
    RequestLatestEpoch,
    RequestCoinProof([u8; 32]),
    RequestEpochTxn(EpochGetTxn),
    RequestEpochLeaves(u64),
    // Send epoch-selected request for a specific epoch (queued + retried)
    RequestEpochSelected(u64),
    GossipEpochLeaves(EpochLeavesBundle),
    // removed commitment gossip
    RequestEpochCandidates([u8; 32]),
}

fn load_or_create_peer_identity() -> anyhow::Result<identity::Keypair> {
    let path = "peer_identity.key";
    if Path::new(path).exists() {
        let key_data = fs::read(path)?;
        return Ok(identity::Keypair::from_protobuf_encoding(&key_data)?);
    }
    let keypair = identity::Keypair::generate_ed25519();
    let bytes = keypair.to_protobuf_encoding()?;
    fs::write(path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(keypair)
}

/// Returns the local libp2p PeerId as a string, creating a persistent
/// identity file `peer_identity.key` on first use if it does not exist.
pub fn peer_id_string() -> anyhow::Result<String> {
    let id_keys = load_or_create_peer_identity()?;
    let peer_id = PeerId::from(id_keys.public());
    Ok(peer_id.to_string())
}

pub async fn spawn(
    net_cfg: config::Net,
    p2p_cfg: config::P2p,
    db: Arc<Store>,
    sync_state: Arc<Mutex<SyncState>>,
) -> anyhow::Result<NetHandle> {
    let id_keys = load_or_create_peer_identity()?;
    let peer_id = PeerId::from(id_keys.public());
    net_log!("🆔 Local peer ID: {}", peer_id);
    
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(std::time::Duration::from_millis(500))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .mesh_n_low(2)
        .mesh_outbound_min(1)
        .mesh_n(12)
        .mesh_n_high(102)
        .flood_publish(true)
        .max_transmit_size(8 * 1024 * 1024) // 8 MiB cap
        .build()?;
        
    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub_config,
    ).map_err(|e| anyhow::anyhow!(e))?;
    for t in [
        TOP_ANCHOR, TOP_COIN, TOP_SPEND,
        TOP_EPOCH_REQUEST, TOP_COIN_REQUEST, TOP_LATEST_REQUEST,
        TOP_COIN_PROOF_REQUEST, TOP_COIN_PROOF_RESPONSE,
        TOP_EPOCH_LEAVES, TOP_EPOCH_LEAVES_REQUEST,
        TOP_EPOCH_SELECTED_REQUEST, TOP_EPOCH_SELECTED_RESPONSE,
        TOP_SPEND_REQUEST, TOP_SPEND_RESPONSE,
        TOP_PEER_ADDR,
        TOP_RATE_LIMITED,
        TOP_EPOCH_HEADERS_REQUEST, TOP_EPOCH_HEADERS_RESPONSE,
        TOP_EPOCH_COMPACT, TOP_EPOCH_GET_TXN, TOP_EPOCH_TXN,
        TOP_EPOCH_CANDIDATES_REQUEST, TOP_EPOCH_CANDIDATES_RESPONSE,
    ] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    let mut swarm = Swarm::new(
        transport,
        gs,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(std::time::Duration::from_secs(120))
    );
    
    let mut port = net_cfg.listen_port;
    loop {
        let listen_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port);
        match swarm.listen_on(listen_addr.parse()?) {
            Ok(_) => break,
            Err(e) if e.to_string().contains("Address already in use") => {
                port += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }
    
    if let Some(public_ip) = &net_cfg.public_ip {
        let external_addr: Multiaddr = format!("/ip4/{}/udp/{}/quic-v1", public_ip, port).parse()?;
        swarm.add_external_address(external_addr.clone());
    }

    for addr in &net_cfg.bootstrap {
        net_log!("🔗 Dialing bootstrap node: {}", addr);
        match swarm.dial(addr.parse::<Multiaddr>()?) {
            Ok(_) => net_log!("✅ Bootstrap dial initiated"),
            Err(e) => println!("❌ Failed to dial bootstrap node: {}", e),
        }
    }

    let connected_peers: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));

    let (spend_tx, _) = broadcast::channel(1024);
    // Increase anchor broadcast capacity to reduce lag in consumers (e.g., miner)
    let (anchor_tx, _) = broadcast::channel(4096);
    let (proof_tx, _) = broadcast::channel(256);
    // removed commitment channels
    let (rate_limited_tx, _) = broadcast::channel(64);
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let (headers_tx, _headers_rx) = broadcast::channel::<EpochHeadersBatch>(1024);
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), proof_tx: proof_tx.clone(), spend_tx: spend_tx.clone(), rate_limited_tx: rate_limited_tx.clone(), headers_tx: headers_tx.clone(), command_tx: command_tx.clone(), connected_peers: connected_peers.clone() });

    let mut peer_scores: HashMap<PeerId, PeerScore> = HashMap::new();
    let mut pending_commands: VecDeque<NetworkCommand> = VecDeque::new();
    let mut orphan_anchors: HashMap<u64, Vec<Anchor>> = HashMap::new();
    // Buffer for out-of-order spends (by coin_id)
    let mut pending_spends: HashMap<[u8;32], Vec<Spend>> = HashMap::new();
    let mut pending_spend_deadline: HashMap<[u8;32], std::time::Instant> = HashMap::new();
    // Pending coin-proof requests we could not answer immediately (awaiting leaves/coins)
    let mut pending_proof_requests: HashMap<[u8;32], std::time::Instant> = HashMap::new();
    // Per-topic quotas for the custom rate-limited topic
    let mut inbound_quota: HashMap<PeerId, (std::time::Instant, u32)> = HashMap::new();
    let mut outbound_quota: (std::time::Instant, u32) = (std::time::Instant::now(), 0);

    const MAX_ORPHAN_ANCHORS: usize = 6048;
    const ORPHAN_BUFFER_TIP_WINDOW: u64 = 5024; // only buffer orphans within this distance of local tip
    static RECENT_PROOF_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    static RECENT_SPEND_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    // Deduplicate coin fetch requests when we receive spends for unknown coins
    static RECENT_COIN_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    // Deduplicate epoch selected-id requests (helps reconstruct selection index on followers)
    
    static RECENT_LEAVES_REQS: Lazy<Mutex<std::collections::HashMap<u64, std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    static RECENT_EPOCH_REQS: Lazy<Mutex<std::collections::HashMap<u64, std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    const EPOCH_REQ_DEDUP_SECS: u64 = 8;
    // Deduplicate and throttle responses to latest-epoch requests
    static RECENT_LATEST_REQS: Lazy<Mutex<std::collections::HashMap<PeerId, (std::time::Instant, u64)>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    static LAST_LATEST_ANNOUNCE: Lazy<Mutex<std::time::Instant>> = Lazy::new(|| Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(1)));
    const LATEST_REQ_DEDUP_SECS: u64 = 8; // per-peer TTL for duplicate latest requests at same height
    const LATEST_GLOBAL_THROTTLE_MS: u64 = 1000; // minimum gap between our latest responses
    const PENDING_SPEND_TTL_SECS: u64 = 15;
    const PENDING_PROOF_TTL_SECS: u64 = 30;
    const REORG_BACKFILL: u64 = 64; // proactively backfill up to 64 predecessors on hash mismatch
    // Global aggregation cadence for alt-fork summaries
    const ALT_FORK_LOG_THROTTLE_SECS: u64 = 60;
    // Throttle noisy reorg logs (per-height)
    const REORG_LOG_THROTTLE_SECS: u64 = 30;
    static LAST_MISMATCH_LOGS: Lazy<Mutex<std::collections::HashMap<u64, std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    static LAST_MISSING_FORK_LOGS: Lazy<Mutex<std::collections::HashMap<u64, std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    
    // Aggregate alternate-fork events per height and periodically emit a summary
    struct AltForkAgg {
        first_seen: std::time::Instant,     
        last_emit: std::time::Instant,
        peers: std::collections::HashSet<String>,
        hashes: std::collections::HashSet<[u8;32]>,
    }
    static ALT_FORK_AGG: Lazy<Mutex<std::collections::HashMap<u64, AltForkAgg>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

    // Attempt to reorg to a better chain using buffered anchors.
    fn attempt_reorg(
        db: &Store,
        orphan_anchors: &mut HashMap<u64, Vec<Anchor>>,
        anchor_tx: &broadcast::Sender<Anchor>,
        sync_state: &Arc<Mutex<SyncState>>,
        command_tx: &mpsc::UnboundedSender<NetworkCommand>,
    ) {
        let current_latest = match db.get::<Anchor>("epoch", b"latest") {
            Ok(Some(a)) => a,
            _ => return,
        };
        // Fast-path: adopt the lowest contiguous buffered segment immediately above current tip
        // This helps initial catch-up by extending the tip sequentially when possible.
        let mut near_parent = current_latest.clone();
        let mut near_chain: Vec<Anchor> = Vec::new();
        let mut h_near = current_latest.num.saturating_add(1);
        loop {
            let Some(cands) = orphan_anchors.get(&h_near) else { break; };
            if cands.is_empty() { break; }
            let mut linked: Option<Anchor> = None;
            for alt in cands {
                let expected_work = Anchor::expected_work_for_difficulty(alt.difficulty);
                let expected_cum = near_parent.cumulative_work.saturating_add(expected_work);
                if alt.cumulative_work != expected_cum { continue; }
                let mut hsh = blake3::Hasher::new();
                hsh.update(&alt.merkle_root);
                hsh.update(&near_parent.hash);
                let recomputed = *hsh.finalize().as_bytes();
                if alt.hash == recomputed { linked = Some(alt.clone()); break; }
            }
            if let Some(next) = linked {
                near_chain.push(next.clone());
                near_parent = next;
                h_near = h_near.saturating_add(1);
            } else { break; }
        }
        if let Some(near_tip) = near_chain.last() {
            if near_tip.cumulative_work > current_latest.cumulative_work {
                let (Some(epoch_cf), Some(anchor_cf), Some(sel_cf), Some(leaves_cf), Some(coin_cf), Some(coin_epoch_cf), Some(spend_cf), Some(nullifier_cf), Some(commitment_used_cf)) = (
                    db.db.cf_handle("epoch"),
                    db.db.cf_handle("anchor"),
                    db.db.cf_handle("epoch_selected"),
                    db.db.cf_handle("epoch_leaves"),
                    db.db.cf_handle("coin"),
                    db.db.cf_handle("coin_epoch"),
                    db.db.cf_handle("spend"),
                    db.db.cf_handle("nullifier"),
                    db.db.cf_handle("commitment_used"),
                ) else { return; };
                let mut batch = WriteBatch::default();
                let mut parent = current_latest.clone();
                for alt in &near_chain {
                    // 1) Overwrite anchor mappings for this epoch and advance latest
                    let ser = match bincode::serialize(alt) { Ok(v) => v, Err(_) => return };
                    batch.put_cf(epoch_cf, alt.num.to_le_bytes(), &ser);
                    batch.put_cf(epoch_cf, b"latest", &ser);
                    batch.put_cf(anchor_cf, &alt.hash, &ser);

                    // 2) Remove previously confirmed coins that belonged to the replaced chain at this epoch
                    if let Ok(prev_selected_ids) = db.get_selected_coin_ids_for_epoch(alt.num) {
                        for id in prev_selected_ids {
                            batch.delete_cf(coin_cf, &id);
                            batch.delete_cf(coin_epoch_cf, &id);
                            if let Ok(Some(sp)) = db.get::<crate::transfer::Spend>("spend", &id) {
                                batch.delete_cf(spend_cf, &id);
                                batch.delete_cf(nullifier_cf, &sp.nullifier);
                                if sp.unlock_preimage.is_some() {
                                    if let Some(next_lock) = sp.next_lock_hash {
                                        if let Ok(chain_id) = db.get_chain_id() {
                                            let cid = crate::crypto::commitment_id_v1(&sp.to.one_time_pk, &sp.to.kyber_ct, &next_lock, &sp.coin_id, sp.to.amount_le, &chain_id);
                                            batch.delete_cf(commitment_used_cf, &cid);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 3) Clear old per-epoch selected index keys and leaves
                    let prefix = alt.num.to_le_bytes();
                    let iter = db.db.iterator_cf(sel_cf, rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
                    for item in iter {
                        if let Ok((k, _)) = item {
                            if k.len() >= 8 && &k[0..8] == prefix {
                                batch.delete_cf(sel_cf, k);
                                continue;
                            }
                        }
                        break;
                    }
                    batch.delete_cf(leaves_cf, &prefix);

                    // 4) Attempt to reconstruct selected set using canonical selector
                    let cap = alt.coin_count as usize;
                    let (candidates, _total_candidates) = crate::epoch::select_candidates_for_epoch(&db, &parent, cap, None);
                    let selected_ids: std::collections::HashSet<[u8;32]> = candidates.iter().map(|c| c.id).collect();
                    let mut leaves: Vec<[u8;32]> = selected_ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
                    leaves.sort();
                    let computed_root = if leaves.is_empty() { [0u8;32] } else {
                        let mut tmp = leaves.clone();
                        while tmp.len() > 1 {
                            let mut next = Vec::new();
                            for chunk in tmp.chunks(2) {
                                let mut hasher = blake3::Hasher::new();
                                hasher.update(&chunk[0]);
                                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                                next.push(*hasher.finalize().as_bytes());
                            }
                            tmp = next;
                        }
                        tmp[0]
                    };

                    if computed_root == alt.merkle_root && selected_ids.len() as u32 == alt.coin_count {
                        for cand in &candidates {
                            let coin = cand.clone().into_confirmed();
                            if let Ok(bytes) = bincode::serialize(&coin) { batch.put_cf(coin_cf, &coin.id, &bytes); }
                            batch.put_cf(coin_epoch_cf, &coin.id, &alt.num.to_le_bytes());
                        }
                        for coin_id in &selected_ids {
                            let mut key = Vec::with_capacity(8 + 32);
                            key.extend_from_slice(&alt.num.to_le_bytes());
                            key.extend_from_slice(coin_id);
                            batch.put_cf(sel_cf, &key, &[]);
                        }
                        if let Ok(bytes) = bincode::serialize(&leaves) { batch.put_cf(leaves_cf, &alt.num.to_le_bytes(), &bytes); }
                    } else {
                        net_log!(
                            "⚠️ Reorg: unable to reconstruct selected set for epoch {} (merkle {} vs computed {}, count {} vs {})",
                            alt.num,
                            hex::encode(alt.merkle_root),
                            hex::encode(computed_root),
                            alt.coin_count,
                            selected_ids.len()
                        );
                        let _ = command_tx.send(NetworkCommand::RequestEpochLeaves(alt.num));
                    }
                    parent = alt.clone();
                }
                if let Err(e) = db.db.write(batch) { eprintln!("🔥 Reorg write failed: {}", e); return; }
                for alt in &near_chain { let _ = anchor_tx.send(alt.clone()); }
                if let Ok(mut st) = sync_state.lock() { st.highest_seen_epoch = near_tip.num; }
                for alt in &near_chain {
                    if let Some(vec) = orphan_anchors.get_mut(&alt.num) {
                        vec.retain(|a| a.hash != alt.hash);
                        if vec.is_empty() { orphan_anchors.remove(&alt.num); }
                    }
                }
                net_log!("🔁 Reorg adopted up to epoch {} (sequential catch-up)", near_tip.num);
                return;
            }
        }
        let Some(&max_buf_height) = orphan_anchors.keys().max() else { return };
        if max_buf_height <= current_latest.num { return; }

        // Determine earliest contiguous height present in the orphan buffer
        let mut h = max_buf_height;
        while h > 0 {
            match orphan_anchors.get(&h) {
                Some(v) if !v.is_empty() => { h -= 1; }
                _ => break,
            }
        }
        let first_height = if orphan_anchors.get(&h).is_some() { h } else { h + 1 };
        if first_height > max_buf_height { return; }
        let fork_height = first_height.saturating_sub(1);
        net_routine!("🔎 Reorg: considering buffered segment {}..={} ({} epochs). Fork height candidate: {}",
            first_height,
            max_buf_height,
            (max_buf_height - first_height + 1),
            fork_height
        );

        // Build candidate parents at fork point: local chain and any alternates at fork height
        let mut parent_candidates: Vec<Anchor> = Vec::new();
        if let Ok(Some(local_parent)) = db.get::<Anchor>("epoch", &fork_height.to_le_bytes()) {
            parent_candidates.push(local_parent);
        }
        if let Some(alts_at_fork) = orphan_anchors.get(&fork_height) {
            for a in alts_at_fork { parent_candidates.push(a.clone()); }
        }
        if parent_candidates.is_empty() {
            // Throttle log spam per-fork height
            let now = std::time::Instant::now();
            let mut allow_log = true;
            if let Ok(mut map) = LAST_MISSING_FORK_LOGS.lock() {
                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(REORG_LOG_THROTTLE_SECS));
                if let Some(last) = map.get(&fork_height) {
                    if now.duration_since(*last) < std::time::Duration::from_secs(REORG_LOG_THROTTLE_SECS) { allow_log = false; }
                }
                if allow_log { map.insert(fork_height, now); }
            }
            if allow_log {
                net_routine!("⛔ Reorg: missing fork anchor at height {} (local and alternates)", fork_height);
            }
            // Pre-deduplicate epoch requests before enqueuing
            let start = fork_height.saturating_sub(REORG_BACKFILL);
            if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
            }
            if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                for n in start..=fork_height {
                    if !map.contains_key(&n) {
                        let _ = command_tx.send(NetworkCommand::RequestEpoch(n));
                        map.insert(n, now);
                    }
                }
            }
            return;
        }

        // Try to assemble a valid alternate branch from first_height..=max_buf_height using BFS across candidates
        let chosen_chain: Vec<Anchor>;
        let mut resolved_parent: Option<Anchor> = None;
        let parent_hashes: std::collections::HashSet<[u8; 32]> = parent_candidates.iter().map(|p| p.hash).collect();
        let mut back: std::collections::HashMap<[u8; 32], [u8; 32]> = std::collections::HashMap::new(); // child.hash -> parent.hash
        let mut node_by_hash: std::collections::HashMap<[u8; 32], Anchor> = std::collections::HashMap::new();
        for p in &parent_candidates { node_by_hash.insert(p.hash, p.clone()); }
        let mut frontier: Vec<Anchor> = parent_candidates.clone();
        let mut last_frontier: Vec<Anchor> = Vec::new();
        let mut advanced = false;
        for height in first_height..=max_buf_height {
            let Some(cands) = orphan_anchors.get(&height) else { break; };
            if cands.is_empty() { break; }
            let mut next_frontier: Vec<Anchor> = Vec::new();
            for p in &frontier {
                for alt in cands {
                    let expected_work = Anchor::expected_work_for_difficulty(alt.difficulty);
                    let expected_cum = p.cumulative_work.saturating_add(expected_work);
                    if alt.cumulative_work != expected_cum { continue; }
                    let mut hsh = blake3::Hasher::new();
                    hsh.update(&alt.merkle_root);
                    hsh.update(&p.hash);
                    let recomputed = *hsh.finalize().as_bytes();
                    if alt.hash == recomputed {
                        // Link p -> alt
                        if !back.contains_key(&alt.hash) { back.insert(alt.hash, p.hash); }
                        next_frontier.push(alt.clone());
                    }
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            // Deduplicate by hash to prevent frontier explosion
            let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            let mut deduped: Vec<Anchor> = Vec::new();
            for a in next_frontier {
                if seen.insert(a.hash) {
                    node_by_hash.insert(a.hash, a.clone());
                    deduped.push(a);
                }
            }
            last_frontier = deduped.clone();
            frontier = deduped;
            advanced = true;
        }
        if !advanced {
            let now = std::time::Instant::now();
            let mut allow_log = true;
            if let Ok(mut map) = LAST_MISMATCH_LOGS.lock() {
                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(REORG_LOG_THROTTLE_SECS));
                if let Some(last) = map.get(&first_height) {
                    if now.duration_since(*last) < std::time::Duration::from_secs(REORG_LOG_THROTTLE_SECS) { allow_log = false; }
                }
                if allow_log { map.insert(first_height, now); }
            }
            if allow_log {
                net_log!("⛔ Reorg: anchor hash mismatch at {} (no candidate links to provided parents)", first_height);
            }
            if first_height > 0 {
                let start = fork_height.saturating_sub(REORG_BACKFILL);
                let end = first_height - 1;
                for n in start..=end { let _ = command_tx.send(NetworkCommand::RequestEpoch(n)); }
            }
            let _ = command_tx.send(NetworkCommand::RequestEpoch(fork_height));
            return;
        }

        // Choose the best reachable tip from the last successful frontier
        let Some(seg_tip) = last_frontier.iter().max_by_key(|a| a.cumulative_work).cloned() else { return };

        // Reconstruct the chosen chain from seg_tip back to one of the parents
        let mut chain_rev: Vec<Anchor> = Vec::new();
        let mut cur = seg_tip.clone();
        chain_rev.push(cur.clone());
        while let Some(prev_hash) = back.get(&cur.hash) {
            if parent_hashes.contains(prev_hash) {
                resolved_parent = node_by_hash.get(prev_hash).cloned();
                break;
            }
            if let Some(prev) = node_by_hash.get(prev_hash).cloned() {
                chain_rev.push(prev.clone());
                cur = prev;
            } else { break; }
        }
        chain_rev.reverse();
        chosen_chain = chain_rev;
        if chosen_chain.is_empty() { return; }

        let Some(seg_tip) = chosen_chain.last() else { return; };
        if seg_tip.cumulative_work <= current_latest.cumulative_work {
            net_routine!("ℹ️  Reorg: candidate tip #{} cum_work {} not better than current #{} cum_work {}",
                seg_tip.num, seg_tip.cumulative_work, current_latest.num, current_latest.cumulative_work);
            return;
        }

        // Adopt: overwrite epochs and latest pointer; reconcile per-epoch selected/leaves/coins
        let (Some(epoch_cf), Some(anchor_cf), Some(sel_cf), Some(leaves_cf), Some(coin_cf), Some(coin_epoch_cf), Some(spend_cf), Some(nullifier_cf), Some(commitment_used_cf)) = (
            db.db.cf_handle("epoch"),
            db.db.cf_handle("anchor"),
            db.db.cf_handle("epoch_selected"),
            db.db.cf_handle("epoch_leaves"),
            db.db.cf_handle("coin"),
            db.db.cf_handle("coin_epoch"),
            db.db.cf_handle("spend"),
            db.db.cf_handle("nullifier"),
            db.db.cf_handle("commitment_used"),
        ) else { return; };
        let mut batch = WriteBatch::default();

        let mut parent = match resolved_parent { Some(p) => p, None => return };
        for alt in &chosen_chain {
            // 1) Overwrite anchor mappings for this epoch and advance latest
            let ser = match bincode::serialize(alt) { Ok(v) => v, Err(_) => return };
            batch.put_cf(epoch_cf, alt.num.to_le_bytes(), &ser);
            batch.put_cf(epoch_cf, b"latest", &ser);
            batch.put_cf(anchor_cf, &alt.hash, &ser);

            // 2) Remove previously confirmed coins that belonged to the replaced chain at this epoch
            if let Ok(prev_selected_ids) = db.get_selected_coin_ids_for_epoch(alt.num) {
                for id in prev_selected_ids {
                    // Remove coin object
                    batch.delete_cf(coin_cf, &id);
                    // Remove coin->epoch index
                    batch.delete_cf(coin_epoch_cf, &id);
                    // If we had a spend recorded for this coin on the old branch, remove it and its nullifier
                    if let Ok(Some(sp)) = db.get::<crate::transfer::Spend>("spend", &id) {
                        batch.delete_cf(spend_cf, &id);
                        batch.delete_cf(nullifier_cf, &sp.nullifier);
                        // Also roll back commitment_used marker deterministically if this was a V3 spend
                        if sp.unlock_preimage.is_some() {
                            if let Some(next_lock) = sp.next_lock_hash {
                                if let Ok(chain_id) = db.get_chain_id() {
                                    let cid = crate::crypto::commitment_id_v1(&sp.to.one_time_pk, &sp.to.kyber_ct, &next_lock, &sp.coin_id, sp.to.amount_le, &chain_id);
                                    batch.delete_cf(commitment_used_cf, &cid);
                                }
                            }
                        }
                    }
                }
            }

            // 3) Clear old per-epoch selected index keys and leaves
            let prefix = alt.num.to_le_bytes();
            let iter = db.db.iterator_cf(sel_cf, rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
            for item in iter {
                if let Ok((k, _)) = item {
                    if k.len() >= 8 && &k[0..8] == prefix {
                        batch.delete_cf(sel_cf, k);
                        continue;
                    }
                }
                break;
            }
            batch.delete_cf(leaves_cf, &prefix);

            // 4) Attempt to reconstruct selected set using canonical selector
            let cap = alt.coin_count as usize;
            let (candidates, _total_candidates) = crate::epoch::select_candidates_for_epoch(&db, &parent, cap, None);

            let selected_ids: std::collections::HashSet<[u8;32]> = candidates.iter().map(|c| c.id).collect();
            let mut leaves: Vec<[u8;32]> = selected_ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
            leaves.sort();
            let computed_root = if leaves.is_empty() { [0u8;32] } else {
                let mut tmp = leaves.clone();
                while tmp.len() > 1 {
                    let mut next = Vec::new();
                    for chunk in tmp.chunks(2) {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(&chunk[0]);
                        hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                        next.push(*hasher.finalize().as_bytes());
                    }
                    tmp = next;
                }
                tmp[0]
            };

            if computed_root == alt.merkle_root && selected_ids.len() as u32 == alt.coin_count {
                for cand in &candidates {
                    let coin = cand.clone().into_confirmed();
                    if let Ok(bytes) = bincode::serialize(&coin) {
                        batch.put_cf(coin_cf, &coin.id, &bytes);
                    }
                    // Maintain coin->epoch index for spend validation and wallet lookups
                    batch.put_cf(coin_epoch_cf, &coin.id, &alt.num.to_le_bytes());
                }
                for coin_id in &selected_ids {
                    let mut key = Vec::with_capacity(8 + 32);
                    key.extend_from_slice(&alt.num.to_le_bytes());
                    key.extend_from_slice(coin_id);
                    batch.put_cf(sel_cf, &key, &[]);
                }
                if let Ok(bytes) = bincode::serialize(&leaves) {
                    batch.put_cf(leaves_cf, &alt.num.to_le_bytes(), &bytes);
                }
            } else {
                net_log!(
                    "⚠️ Reorg: unable to reconstruct selected set for epoch {} (merkle {} vs computed {}, count {} vs {})",
                    alt.num,
                    hex::encode(alt.merkle_root),
                    hex::encode(computed_root),
                    alt.coin_count,
                    selected_ids.len()
                );
                // Request authoritative sorted leaves so we can serve proofs and backfill indices
                let _ = command_tx.send(NetworkCommand::RequestEpochLeaves(alt.num));
            }

            // Advance parent
            parent = alt.clone();
        }

        if let Err(e) = db.db.write(batch) {
            eprintln!("🔥 Reorg write failed: {}", e);
            return;
        }
        for alt in &chosen_chain { let _ = anchor_tx.send(alt.clone()); }
        if let Ok(mut st) = sync_state.lock() {
            st.highest_seen_epoch = seg_tip.num;
        }
        for alt in &chosen_chain {
            if let Some(vec) = orphan_anchors.get_mut(&alt.num) {
                vec.retain(|a| a.hash != alt.hash);
                if vec.is_empty() { orphan_anchors.remove(&alt.num); }
            }
        }
        net_log!("🔁 Reorg adopted up to epoch {} (better cumulative work)", seg_tip.num);
    }

    tokio::spawn(async move {       
        // Track peers being dialed to avoid duplicate concurrent dials
        let mut dialing_peers: HashSet<PeerId> = HashSet::new();
        // Track time of last dial attempt per peer for TTL de-duplication
        let mut recent_peer_dials: HashMap<PeerId, Instant> = HashMap::new();
        // Rate-limit self address advertisement to avoid connect storms
        const PEER_ADDR_ADVERTISE_MIN_SECS: u64 = 60;
        const PEER_DIAL_DEDUP_SECS: u64 = 30;
        let mut last_peer_addr_advertise: Instant = Instant::now() - std::time::Duration::from_secs(PEER_ADDR_ADVERTISE_MIN_SECS);
        // Periodic retry timer to flush pending publishes even without connection events
        let mut retry_timer = tokio::time::interval(std::time::Duration::from_millis(200));
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            if let Some(pid) = peer_id { dialing_peers.remove(&pid); }
                            eprintln!("⚠️  Outgoing connection error: {:?}", error);
                        },
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            net_log!("🤝 Connected to peer: {}", peer_id);
                            peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            if let Ok(mut set) = connected_peers.lock() {
                                set.insert(peer_id);
                                crate::metrics::PEERS.set(set.len() as i64);
                            }
                            // Clear dialing-in-progress marker on success
                            dialing_peers.remove(&peer_id);
                            // After connecting, exchange external address (if enabled)
                            if net_cfg.peer_exchange {
                                // Prefer observed external addresses learned from peers; fallback to configured public_ip
                                let to_advertise = swarm
                                    .external_addresses()
                                    .next()
                                    .map(|a| format!("{}/p2p/{}", a, swarm.local_peer_id()))
                                    .or_else(|| net_cfg.public_ip.clone().map(|ip|
                                        format!("/ip4/{}/udp/{}/quic-v1/p2p/{}", ip, port, swarm.local_peer_id())
                                    ));
                                if let Some(addr) = to_advertise {
                                    let ok_public = addr.starts_with("/ip4/") && addr.contains("/udp/") && addr.contains("/quic-v1/");
                                    if ok_public {
                                        if let Some(ip_str) = addr.split('/').nth(3) {
                                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() { if ip.is_private() || ip.is_loopback() { continue; } }
                                        }
                                    }
                                    // Rate-limit our advertisement to avoid causing reciprocal dial storms
                                    if Instant::now().duration_since(last_peer_addr_advertise) > std::time::Duration::from_secs(PEER_ADDR_ADVERTISE_MIN_SECS) {
                                        if let Ok(data) = bincode::serialize(&addr) {
                                            try_publish_gossip(&mut swarm, TOP_PEER_ADDR, data, "peer-addr");
                                        }
                                        last_peer_addr_advertise = Instant::now();
                                    }
                                }
                            }
                            let mut still_pending = VecDeque::new();
                            while let Some(cmd) = pending_commands.pop_front() {
                                let (t, data) = match &cmd {
                                    NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                                    NetworkCommand::GossipCompactEpoch(c) => (TOP_EPOCH_COMPACT, bincode::serialize(&c).ok()),
                                    NetworkCommand::GossipCoin(c)   => (TOP_COIN, bincode::serialize(&c).ok()),
                                    
                                    NetworkCommand::GossipSpend(sp) => (TOP_SPEND, bincode::serialize(&sp).ok()),
                                    NetworkCommand::GossipRateLimited(m) => (TOP_RATE_LIMITED, bincode::serialize(&m).ok()),
                                    NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                                    NetworkCommand::RequestEpochHeadersRange(range) => (TOP_EPOCH_HEADERS_REQUEST, bincode::serialize(&range).ok()),
                                    NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                                    NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok()),
                                    NetworkCommand::RequestCoinProof(id) => (TOP_COIN_PROOF_REQUEST, bincode::serialize(&CoinProofRequest{ coin_id: *id }).ok()),
                                    NetworkCommand::RequestSpend(id) => (TOP_SPEND_REQUEST, bincode::serialize(&id).ok()),
                                    NetworkCommand::RequestEpochTxn(req) => (TOP_EPOCH_GET_TXN, bincode::serialize(&req).ok()),
                                    NetworkCommand::RequestEpochSelected(epoch) => (TOP_EPOCH_SELECTED_REQUEST, bincode::serialize(&epoch).ok()),
                                    NetworkCommand::RequestEpochLeaves(epoch) => (TOP_EPOCH_LEAVES_REQUEST, bincode::serialize(&epoch).ok()),
                                    NetworkCommand::RequestEpochCandidates(hash) => (TOP_EPOCH_CANDIDATES_REQUEST, bincode::serialize(&hash).ok()),
                                    NetworkCommand::GossipEpochLeaves(bundle) => (TOP_EPOCH_LEAVES, bincode::serialize(&bundle).ok()),
                                    // commitment gossip removed
                                };
                                if let Some(d) = data {
                                    if swarm.behaviour_mut().publish(IdentTopic::new(t), d).is_err() {
                                        still_pending.push_back(cmd);
                                    }
                                }
                            }
                            pending_commands = still_pending;
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            net_log!("👋 Disconnected from peer: {} due to {:?}", peer_id, cause);
                            if let Ok(mut set) = connected_peers.lock() {
                                set.remove(&peer_id);
                                crate::metrics::PEERS.set(set.len() as i64);
                            }
                            // Allow re-dial in the future
                            dialing_peers.remove(&peer_id);
                        },
                        SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) => {
                            let Some(peer_id) = message.source else { continue };
                            let topic_str = message.topic.as_str();
                            let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            let rate_limit_exempt = topic_str == TOP_ANCHOR || topic_str == TOP_RATE_LIMITED;
                            if score.is_banned() || (!rate_limit_exempt && !score.check_rate_limit()) { continue; }
                            
                            match topic_str {
                                TOP_RATE_LIMITED => {
                                    if let Ok(msg) = bincode::deserialize::<RateLimitedMessage>(&message.data) {
                                        // enforce per-sender quota: 2 messages per 24h per peer
                                        let entry = inbound_quota.entry(peer_id).or_insert((std::time::Instant::now(), 0));
                                        let now = std::time::Instant::now();
                                        if now.duration_since(entry.0) > std::time::Duration::from_secs(24 * 60 * 60) {
                                            *entry = (now, 0);
                                        }
                                        entry.1 += 1;
                                        if entry.1 <= 2 {
                                            let _ = rate_limited_tx.send(msg);
                                        }
                                    }
                                },
                                TOP_PEER_ADDR => if net_cfg.peer_exchange {
                                    if let Ok(addr) = bincode::deserialize::<String>(&message.data) {
                                        if !addr.starts_with("/ip4/") || !addr.contains("/udp/") || !addr.contains("/quic-v1/") { continue; }
                                        let Some(id_str) = addr.split("/p2p/").last() else { continue };
                                        let Ok(remote_pid) = PeerId::from_str(id_str) else { continue };
                                        if remote_pid == *swarm.local_peer_id() { continue; }
                                        if let Some(ip_str) = addr.split('/').nth(3) {
                                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() { if ip.is_private() || ip.is_loopback() { continue; } }
                                        }
                                        if addr.parse::<Multiaddr>().is_err() { continue; }
                                        db.store_peer_addr(&addr).ok();
                                        // Avoid redundant dials or dialing above capacity
                                        let already_connected = connected_peers.lock().map(|s| s.contains(&remote_pid)).unwrap_or(false);
                                        if already_connected || dialing_peers.contains(&remote_pid) { continue; }
                                        let under_cap = connected_peers.lock().map(|s| s.len()).unwrap_or(usize::MAX) < net_cfg.max_peers as usize;
                                        if !under_cap { continue; }
                                        // TTL de-dup on dials
                                        let now = Instant::now();
                                        recent_peer_dials.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(PEER_DIAL_DEDUP_SECS));
                                        if recent_peer_dials.contains_key(&remote_pid) { continue; }
                                        if let Ok(m) = addr.parse::<Multiaddr>() {
                                            match swarm.dial(m) {
                                                Ok(()) => {
                                                    dialing_peers.insert(remote_pid);
                                                    recent_peer_dials.insert(remote_pid, now);
                                                },
                                                Err(e) => {
                                                    eprintln!("❌ Failed to dial advertised peer {}: {}", id_str, e);
                                                }
                                            }
                                        }
                                    }
                                },
                                TOP_ANCHOR => if let Ok( a) = bincode::deserialize::<Anchor>(&message.data) {
                                    if let Ok(Some(latest)) = db.get::<Anchor>("epoch", b"latest") {
                                        if a.num == latest.num && a.hash == latest.hash {
                                            if let Ok(mut st) = sync_state.lock() {
                                                if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                st.peer_confirmed_tip = true;
                                            }
                                            continue;
                                        }
                                    }
                                    if score.check_rate_limit() { net_routine!("⚓ Received anchor for epoch {} from peer: {}", a.num, peer_id); }
                                    match validate_anchor(&a, &db) {
                                        Ok(()) => {
                                            if let Ok(mut st) = sync_state.lock() {
                                                if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                st.peer_confirmed_tip = true;
                                            }
                                            if a.is_better_chain(&db.get("epoch", b"latest").unwrap_or(None)) {
                                                net_log!("✅ Storing anchor for epoch {}", a.num);
                                                if db.put("epoch", &a.num.to_le_bytes(), &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                if db.put("anchor", &a.hash, &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                if db.put("epoch", b"latest", &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                let _ = anchor_tx.send(a.clone());

                                                if a.num > 0 {
                                                    if let Ok(Some(parent)) = db.get::<Anchor>("epoch", &(a.num - 1).to_le_bytes()) {
                                                        let mut candidates = match db.get_coin_candidates_by_epoch_hash(&parent.hash) {
                                                            Ok(v) => v,
                                                            Err(_) => Vec::new(),
                                                        };
                                                        if parent.difficulty > 0 {
                                                            candidates.retain(|c| c.pow_hash.iter().take(parent.difficulty).all(|b| *b == 0));
                                                        }
                                                        let cap = a.coin_count as usize;
                                                        if cap == 0 {
                                                        } else if candidates.len() > cap {
                                                            let _ = candidates.select_nth_unstable_by(cap - 1, |x, y| x
                                                                .pow_hash
                                                                .cmp(&y.pow_hash)
                                                                .then_with(|| x.id.cmp(&y.id))
                                                            );
                                                            candidates.truncate(cap);
                                                            candidates.sort_by(|x, y| x.pow_hash.cmp(&y.pow_hash).then_with(|| x.id.cmp(&y.id)));
                                                        } else {
                                                            candidates.sort_by(|x, y| x.pow_hash.cmp(&y.pow_hash).then_with(|| x.id.cmp(&y.id)));
                                                        }

                                                        let selected_ids: std::collections::HashSet<[u8;32]> = candidates.iter().map(|c| c.id).collect();
                                                        let mut leaves: Vec<[u8;32]> = selected_ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
                                                        leaves.sort();
                                                        let computed_root = crate::epoch::MerkleTree::compute_root_from_sorted_leaves(&leaves);

                                                        if computed_root == a.merkle_root && selected_ids.len() as u32 == a.coin_count {
                                                            if let (Some(coin_cf), Some(coin_epoch_cf), Some(sel_cf), Some(leaves_cf)) = (
                                                                db.db.cf_handle("coin"),
                                                                db.db.cf_handle("coin_epoch"),
                                                                db.db.cf_handle("epoch_selected"),
                                                                db.db.cf_handle("epoch_leaves"),
                                                            ) {
                                                                let mut batch = rocksdb::WriteBatch::default();
                                                                for cand in &candidates {
                                                                    let coin = cand.clone().into_confirmed();
                                                                    if let Ok(bytes) = bincode::serialize(&coin) {
                                                                        batch.put_cf(coin_cf, &coin.id, &bytes);
                                                                    }
                                                                    batch.put_cf(coin_epoch_cf, &coin.id, &a.num.to_le_bytes());
                                                                }
                                                                for coin_id in &selected_ids {
                                                                    let mut key = Vec::with_capacity(8 + 32);
                                                                    key.extend_from_slice(&a.num.to_le_bytes());
                                                                    key.extend_from_slice(coin_id);
                                                                    batch.put_cf(sel_cf, &key, &[]);
                                                                }
                                                                if let Ok(bytes) = bincode::serialize(&leaves) {
                                                                    batch.put_cf(leaves_cf, &a.num.to_le_bytes(), &bytes);
                                                                }
                                                                if let Err(e) = db.db.write(batch) {
                                                                    eprintln!("⚠️ Failed to persist selected coins for epoch {}: {}", a.num, e);
                                                                } else {
                                                                    net_log!("🪙 Confirmed {} coins for adopted epoch {}", selected_ids.len(), a.num);
                                                                    // Proactively gossip epoch leaves to help peers serve proofs
                                                                    let bundle = EpochLeavesBundle { epoch_num: a.num, merkle_root: a.merkle_root, leaves: leaves.clone() };
                                                                    if let Ok(data) = bincode::serialize(&bundle) {
                                                                        try_publish_gossip(&mut swarm, TOP_EPOCH_LEAVES, data, "epoch-leaves");
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            // Ask peers for the authoritative sorted leaves so we can serve proofs
                                                            let now = std::time::Instant::now();
                                                            if let Ok(mut map) = RECENT_LEAVES_REQS.lock() {
                                                                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(5));
                                                                if !map.contains_key(&a.num) {
                                                                    if let Ok(bytes) = bincode::serialize(&a.num) {
                                                                        try_publish_gossip(&mut swarm, TOP_EPOCH_LEAVES_REQUEST, bytes, "epoch-leaves-req");
                                                                    }
                                                                    map.insert(a.num, now);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            if let Ok(Some(existing)) = db.get::<Anchor>("epoch", &a.num.to_le_bytes()) {
                                                if existing.hash != a.hash {
                                                    let entry = orphan_anchors.entry(a.num).or_default();
                                                    if !entry.iter().any(|x| x.hash == a.hash) {
                                                        net_routine!("🔀 Buffered alternate anchor at height {} (valid but not adopted)", a.num);
                                                        entry.push(a.clone());
                                                    }
                                                }
                                            }

                                            attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                            let orphan_len: usize = orphan_anchors.values().map(|v| v.len()).sum();
                                            crate::metrics::ORPHAN_BUFFER_LEN.set(orphan_len as i64);
                                            if orphan_len > MAX_ORPHAN_ANCHORS {
                                                // Prefer dropping the farthest height from current tip to keep near-tip continuity
                                                let drop_key = if let Ok(Some(lat)) = db.get::<Anchor>("epoch", b"latest") {
                                                    orphan_anchors
                                                        .keys()
                                                        .copied()
                                                        .max_by_key(|h| if *h >= lat.num { h - lat.num } else { lat.num - *h })
                                                } else {
                                                    orphan_anchors.keys().copied().max()
                                                };
                                                if let Some(old) = drop_key {
                                                    orphan_anchors.remove(&old);
                                                    eprintln!("⚠️ Orphan buffer cap exceeded, dropping epoch {} (farthest from tip)", old);
                                                }
                                            }
                                        }
                                        Err(e) if e.starts_with("Previous anchor") => {
                                            // Only buffer orphans near our local tip; skip when we don't have a tip yet
                                            let mut allow_buffer = false;
                                            if let Ok(Some(lat)) = db.get::<Anchor>("epoch", b"latest") {
                                                let dist = if a.num >= lat.num { a.num - lat.num } else { lat.num - a.num };
                                                if dist <= ORPHAN_BUFFER_TIP_WINDOW { allow_buffer = true; }
                                            }
                                            if allow_buffer {
                                                let entry = orphan_anchors.entry(a.num).or_default();
                                                if !entry.iter().any(|x| x.hash == a.hash) {
                                                    entry.push(a.clone());
                                                    net_routine!("⏳ Buffered orphan anchor for epoch {}", a.num);
                                                }
                                            }
                                            
                                            if let Ok(mut state) = sync_state.lock() {
                                                if a.num > state.highest_seen_epoch {
                                                    state.highest_seen_epoch = a.num;
                                                }
                                                state.peer_confirmed_tip = true;
                                            }
                                            if a.num > 0 {
                                                // Proactively backfill a range of predecessors to accelerate catch-up
                                                let now = std::time::Instant::now();
                                                if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                                                    map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                                                }
                                                let start = a.num.saturating_sub(REORG_BACKFILL);
                                                let end = a.num - 1;
                                                if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                                                    for n in start..=end {
                                                        if !map.contains_key(&n) {
                                                            if let Ok(bytes) = bincode::serialize(&n) {
                                                                let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                                                map.insert(n, now);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                        },
                                        Err(e) => {
                                            if e.contains("hash mismatch") {
                                                let entry = orphan_anchors.entry(a.num).or_default();
                                                let is_new = !entry.iter().any(|x| x.hash == a.hash);
                                                if is_new {
                                                    // Aggregate per-height unique peers and hashes; emit summary at throttle interval
                                                    let now = std::time::Instant::now();
                                                    if let Ok(mut agg) = ALT_FORK_AGG.lock() {
                                                        use std::collections::hash_map::Entry as HMEntry;
                                                        match agg.entry(a.num) {
                                                            HMEntry::Occupied(mut o) => {
                                                                let v = o.get_mut();
                                                                v.peers.insert(peer_id.to_string());
                                                                v.hashes.insert(a.hash);
                                                                if now.duration_since(v.last_emit) >= std::time::Duration::from_secs(ALT_FORK_LOG_THROTTLE_SECS) {
                                                                    net_routine!(
                                                                        "🔀 Alt-fork @{}: {} unique peers, {} unique hashes observed – buffering for reorg",
                                                                        a.num,
                                                                        v.peers.len(),
                                                                        v.hashes.len(),
                                                                    );
                                                                    crate::metrics::ALT_FORK_EVENTS.inc();
                                                                    v.last_emit = now;
                                                                }
                                                            }
                                                            HMEntry::Vacant(v) => {
                                                                let mut peers = std::collections::HashSet::new();
                                                                peers.insert(peer_id.to_string());
                                                                let mut hashes = std::collections::HashSet::new();
                                                                hashes.insert(a.hash);
                                                                v.insert(AltForkAgg { first_seen: now, last_emit: now, peers, hashes });
                                                                net_routine!(
                                                                    "🔀 Alt-fork @{}: {} unique peers, {} unique hashes observed – buffering for reorg",
                                                                    a.num,
                                                                    1,
                                                                    1,
                                                                );
                                                                crate::metrics::ALT_FORK_EVENTS.inc();
                                                            }
                                                        }
                                                    }
                                                    entry.push(a.clone());
                                                }
                                                if a.num > 0 {
                                                    let now = std::time::Instant::now();
                                                    if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                                                        map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                                                    }
                                                    let start = a.num.saturating_sub(REORG_BACKFILL);
                                                    let end = a.num - 1;
                                                    if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                                                        for n in start..=end {
                                                            if !map.contains_key(&n) {
                                                                if let Ok(bytes) = bincode::serialize(&n) {
                                                                    let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                                                    map.insert(n, now);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Periodically clean up stale aggregation to bound memory
                                                if let Ok(mut agg) = ALT_FORK_AGG.lock() {
                                                    let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(60);
                                                    agg.retain(|_, v| v.first_seen >= cutoff);
                                                }
                                                if let Ok(mut st) = sync_state.lock() {
                                                    if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                    st.peer_confirmed_tip = true;
                                                }
                                                attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                            } else {
                                                net_log!("❌ Anchor validation from {} failed: {}", peer_id, e);
                                                crate::metrics::VALIDATION_FAIL_ANCHOR.inc();
                                                score.record_validation_failure();
                                            }
                                        }
                                    }
                                },
                                TOP_EPOCH_COMPACT => if let Ok(cmp) = bincode::deserialize::<CompactEpoch>(&message.data) {
                                    crate::metrics::COMPACT_EPOCHS_RECV.inc();
                                    let cmp_anchor = cmp.anchor.clone();
                                    // Store prefilled coins immediately
                                    if let (Some(coin_cf), Some(coin_epoch_cf)) = (db.db.cf_handle("coin"), db.db.cf_handle("coin_epoch")) {
                                        let mut batch = rocksdb::WriteBatch::default();
                                        for (idx, c) in &cmp.prefilled {
                                            let _ = idx; // index tracked via short_ids order
                                            if let Ok(bytes) = bincode::serialize(c) { batch.put_cf(coin_cf, &c.id, &bytes); }
                                            batch.put_cf(coin_epoch_cf, &c.id, &cmp_anchor.num.to_le_bytes());
                                        }
                                        let _ = db.db.write(batch);
                                    }
                                    // Cache compact by epoch hash with TTL
                                    if let Ok(mut map) = PENDING_COMPACTS.lock() {
                                        let now = std::time::Instant::now();
                                        map.retain(|_, (_c, t)| now.duration_since(*t) < std::time::Duration::from_secs(PENDING_COMPACT_TTL_SECS));
                                        map.insert(cmp_anchor.hash, (cmp.clone(), now));
                                    }
                                    // Build satisfied index set: prefilled + short_ids that match coins we already have
                                    let mut satisfied: std::collections::HashSet<u32> = cmp.prefilled.iter().map(|(i, _)| *i).collect();
                                    if let Ok(ids) = db.get_selected_coin_ids_for_epoch(cmp_anchor.num) {
                                        // Map short_id -> present
                                        let mut have: std::collections::HashSet<[u8;8]> = std::collections::HashSet::new();
                                        for id in ids {
                                            if let Ok(Some(_)) = db.get::<Coin>("coin", &id) {
                                                let mut hasher = blake3::Hasher::new(); hasher.update(&id);
                                                let digest = *hasher.finalize().as_bytes();
                                                let mut short = [0u8;8]; short.copy_from_slice(&digest[..8]);
                                                have.insert(short);
                                            }
                                        }
                                        for (i, sid) in cmp.short_ids.iter().enumerate() {
                                            if have.contains(sid) { satisfied.insert(i as u32); }
                                        }
                                    } else {
                                        // Ask peers for leaves to reconstruct index order deterministically
                                        let _ = command_tx.send(NetworkCommand::RequestEpochLeaves(cmp_anchor.num));
                                    }
                                    // Determine missing indexes
                                    let mut missing: Vec<u32> = Vec::new();
                                    for i in 0..cmp_anchor.coin_count { if !satisfied.contains(&i) { missing.push(i); } }
                                    if missing.is_empty() {
                                        // Finalize anchor
                                        if validate_anchor(&cmp_anchor, &db).is_ok() {
                                            if db.put("epoch", &cmp_anchor.num.to_le_bytes(), &cmp_anchor).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                            if db.put("anchor", &cmp_anchor.hash, &cmp_anchor).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                        	                let better = cmp_anchor.is_better_chain(&db.get("epoch", b"latest").unwrap_or(None));
                                            if better { if db.put("epoch", b"latest", &cmp_anchor).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); } }
                                            let _ = anchor_tx.send(cmp_anchor.clone());
                                            // After adoption, reconcile orphan buffer near tip
                                            attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                        }
                                    } else {
                                        // Fallback: if missing percentage exceeds threshold, request full epoch bodies by id
                                        let missing_pct = ((missing.len() as u64) * 100 / cmp_anchor.coin_count as u64) as u8;
                                        let threshold = {
                                            // Attempt to read a threshold from a lazily captured config snapshot if available
                                            static THRESHOLD: once_cell::sync::OnceCell<u8> = once_cell::sync::OnceCell::new();
                                            *THRESHOLD.get_or_init(|| {
                                                // Best-effort: try to read metrics bind as a proxy to ensure config parsed; fallback to 20
                                                COMPACT_MAX_MISSING_PCT_DEFAULT
                                            })
                                        };
                                        if missing_pct > threshold {
                                            crate::metrics::COMPACT_FALLBACKS.inc();
                                            if let Ok(ids) = db.get_selected_coin_ids_for_epoch(cmp_anchor.num) {
                                                for chunk in ids.chunks(MAX_FULL_BODY_REQ_BATCH) {
                                                    for id in chunk {
                                                        let _ = command_tx.send(NetworkCommand::RequestCoin(*id));
                                                    }
                                                }
                                            }
                                        } else {
                                            let now = std::time::Instant::now();
                                            let allow = RECENT_EPOCH_TX_REQS.lock().map(|mut m| {
                                                m.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_millis(EPOCH_TX_REQ_DEDUP_MS));
                                                if !m.contains_key(&cmp_anchor.hash) { m.insert(cmp_anchor.hash, now); true } else { false }
                                            }).unwrap_or(false);
                                            if allow {
                                                if missing.len() > MAX_COMPACT_REQ_BATCH { missing.truncate(MAX_COMPACT_REQ_BATCH); }
                                                crate::metrics::COMPACT_TX_REQ.inc();
                                                let _ = command_tx.send(NetworkCommand::RequestEpochTxn(EpochGetTxn { epoch_hash: cmp_anchor.hash, indexes: missing }));
                                            }
                                        }
                                    }
                                },
                                TOP_EPOCH_GET_TXN => if let Ok(req) = bincode::deserialize::<EpochGetTxn>(&message.data) {
                                    // Per-peer rate limit: allow at most EPOCH_TX_REQS_PER_PEER_MAX in EPOCH_TX_REQS_PER_PEER_WINDOW_MS
                                    let now = std::time::Instant::now();
                                    let over_limit = EPOCH_TX_REQS_PER_PEER.lock().map(|mut m| {
                                        m.retain(|_, (t, _)| now.duration_since(*t) < std::time::Duration::from_millis(EPOCH_TX_REQS_PER_PEER_WINDOW_MS));
                                        let entry = m.entry(peer_id).or_insert((now, 0));
                                        if now.duration_since(entry.1.checked_sub(0).map(|_| entry.0).unwrap_or(now)) >= std::time::Duration::from_millis(EPOCH_TX_REQS_PER_PEER_WINDOW_MS) {
                                            *entry = (now, 0);
                                        }
                                        entry.1 = entry.1.saturating_add(1);
                                        entry.1 > EPOCH_TX_REQS_PER_PEER_MAX
                                    }).unwrap_or(false);
                                    if over_limit { eprintln!("⚠️  Rate limiting epoch_txn requests from peer {}", peer_id); continue; }
                                    // Serve requested coin bodies for an epoch if we have them
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &req.epoch_hash) {
                                        let mut coins: Vec<Coin> = Vec::new();
                                        // Recreate selected list order by scanning selected_ids index
                                        if let Ok(ids) = db.get_selected_coin_ids_for_epoch(anchor.num) {
                                            for idx in req.indexes.iter().copied() {
                                                if let Some(id) = ids.get(idx as usize) {
                                                    if let Ok(Some(c)) = db.get::<Coin>("coin", id) { coins.push(c); }
                                                }
                                            }
                                            if let Ok(data) = bincode::serialize(&EpochTxn { epoch_hash: req.epoch_hash, coins }) {
                                                swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_TXN), data).ok();
                                            }
                                        }
                                    }
                                },
                                TOP_EPOCH_TXN => if let Ok(resp) = bincode::deserialize::<EpochTxn>(&message.data) {
                                    crate::metrics::COMPACT_TX_RESP.inc();
                                    // Merge received coins into DB
                                    for c in &resp.coins {
                                        if let (Some(coin_cf), Some(coin_epoch_cf)) = (db.db.cf_handle("coin"), db.db.cf_handle("coin_epoch")) {
                                            let mut batch = rocksdb::WriteBatch::default();
                                            if let Ok(bytes) = bincode::serialize(c) { batch.put_cf(coin_cf, &c.id, &bytes); }
                                            if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &resp.epoch_hash) {
                                                batch.put_cf(coin_epoch_cf, &c.id, &anchor.num.to_le_bytes());
                                            }
                                            let _ = db.db.write(batch);
                                        }
                                    }
                                    // Check if we can finalize the cached compact now
                                    if let Ok(mut map) = PENDING_COMPACTS.lock() {
                                        if let Some((cmp, _t)) = map.get(&resp.epoch_hash).cloned() {
                                            // Defensive: verify prefilled positions are consistent with short-ids
                                            let mut ok_positions = true;
                                            for (idx, coin) in &cmp.prefilled {
                                                let mut hasher = blake3::Hasher::new(); hasher.update(&coin.id);
                                                let digest = *hasher.finalize().as_bytes();
                                                let mut short = [0u8;8]; short.copy_from_slice(&digest[..8]);
                                                if cmp.short_ids.get(*idx as usize) != Some(&short) { ok_positions = false; break; }
                                            }
                                            if !ok_positions { continue; }
                                            // Recompute satisfaction using short_ids mapping
                                            let mut satisfied: std::collections::HashSet<u32> = cmp.prefilled.iter().map(|(i, _)| *i).collect();
                                            if let Ok(ids) = db.get_selected_coin_ids_for_epoch(cmp.anchor.num) {
                                                let mut have: std::collections::HashSet<[u8;8]> = std::collections::HashSet::new();
                                                for id in ids {
                                                    if let Ok(Some(_)) = db.get::<Coin>("coin", &id) {
                                                        let mut hasher = blake3::Hasher::new(); hasher.update(&id);
                                                        let digest = *hasher.finalize().as_bytes();
                                                        let mut short = [0u8;8]; short.copy_from_slice(&digest[..8]);
                                                        have.insert(short);
                                                    }
                                                }
                                                for (i, sid) in cmp.short_ids.iter().enumerate() {
                                                    if have.contains(sid) { satisfied.insert(i as u32); }
                                                }
                                            }
                                            let mut missing_any = false;
                                            for i in 0..cmp.anchor.coin_count { if !satisfied.contains(&i) { missing_any = true; break; } }
                                            if !missing_any {
                                                if db.put("epoch", &cmp.anchor.num.to_le_bytes(), &cmp.anchor).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                if db.put("anchor", &cmp.anchor.hash, &cmp.anchor).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                if db.put("epoch", b"latest", &cmp.anchor).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                let _ = anchor_tx.send(cmp.anchor.clone());
                                                map.remove(&resp.epoch_hash);
                                            }
                                        }
                                    }
                                },
                                TOP_COIN => {
                                    if let Ok(coin) = bincode::deserialize::<Coin>(&message.data) {
                                        // Only store coin object locally
                                        db.put("coin", &coin.id, &coin).ok();
                                        // If we already know an anchor at this coin's epoch hash, and can map its epoch number, set coin_epoch
                                        if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &coin.epoch_hash) {
                                            // Find epoch by anchor.hash
                                            if let Ok(Some(epoch_anchor)) = db.get::<Anchor>("epoch", &anchor.num.to_le_bytes()) {
                                                let _ = db.put_coin_epoch(&coin.id, epoch_anchor.num);
                                            }
                                        }

                                        // If we had buffered spends for this coin due to it being missing, try to validate/apply them now
                                        if let Some(mut queued) = pending_spends.remove(&coin.id) {
                                            let mut made_progress = true;
                                            while made_progress {
                                                made_progress = false;
                                                let mut remaining: Vec<Spend> = Vec::new();
                                                for q in queued.drain(..) {
                                                    if validate_spend(&q, &db).is_ok() {
                                                        let seen = db.get::<[u8;1]>("nullifier", &q.nullifier).ok().flatten().is_some();
                                                        if let (Some(sp_cf), Some(nf_cf)) = (db.db.cf_handle("spend"), db.db.cf_handle("nullifier")) {
                                                            let mut batch = rocksdb::WriteBatch::default();
                                                            if let Ok(bytes) = bincode::serialize(&q) {
                                                                batch.put_cf(sp_cf, &q.coin_id, &bytes);
                                                            }
                                                            if !seen { batch.put_cf(nf_cf, &q.nullifier, &[1u8;1]); }
                                                            if q.unlock_preimage.is_some() {
                                                                if let Some(next_lock) = q.next_lock_hash {
                                                                    if let (Some(cid_cf), Ok(chain_id)) = (db.db.cf_handle("commitment_used"), db.get_chain_id()) {
                                                                        let cid = crate::crypto::commitment_id_v1(&q.to.one_time_pk, &q.to.kyber_ct, &next_lock, &q.coin_id, q.to.amount_le, &chain_id);
                                                                        batch.put_cf(cid_cf, &cid, &[1u8;1]);
                                                                    }
                                                                }
                                                            }
                                                            let _ = db.db.write(batch);
                                                        }
                                                        let _ = spend_tx.send(q.clone());
                                                        made_progress = true;
                                                    } else {
                                                        remaining.push(q);
                                                    }
                                                }
                                                if remaining.is_empty() { break; }
                                                queued = remaining;
                                            }
                                            if !queued.is_empty() {
                                                pending_spends.insert(coin.id, queued);
                                                pending_spend_deadline.insert(coin.id, std::time::Instant::now());
                                            } else {
                                                pending_spend_deadline.remove(&coin.id);
                                            }
                                        }

                                        // If we still have no spend for this coin, proactively request it once (helps catch-up cases)
                                        if db.get_spend_tolerant(&coin.id).ok().flatten().is_none() {
                                            let now = std::time::Instant::now();
                                            if let Ok(mut map) = RECENT_SPEND_REQS.lock() {
                                                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                                if !map.contains_key(&coin.id) {
                                                    // Route via queue for retry/backoff
                                                    let _ = command_tx.send(NetworkCommand::RequestSpend(coin.id));
                                                    map.insert(coin.id, now);
                                                }
                                            }
                                        }
                                    } else if let Ok(cand) = crate::coin::decode_candidate(&message.data) {
                                        if validate_coin_candidate(&cand, &db).is_ok() {
                                            let key = Store::candidate_key(&cand.epoch_hash, &cand.id);
                                            db.put("coin_candidate", &key, &cand).ok();
                                        } else {
                                            crate::metrics::VALIDATION_FAIL_COIN.inc();
                                            score.record_validation_failure();
                                        }
                                    }
                                },
                                // V1 transfers are fully deprecated on wire: no TOP_TX* handling

                                TOP_SPEND => if let Ok(sp) = bincode::deserialize::<Spend>(&message.data) {
                                    // Purge expired buffered spends occasionally
                                    let now = std::time::Instant::now();
                                    pending_spend_deadline.retain(|coin, dl| {
                                        if now.duration_since(*dl) > std::time::Duration::from_secs(PENDING_SPEND_TTL_SECS) {
                                            pending_spends.remove(coin);
                                            false
                                        } else { true }
                                    });

                                    match validate_spend(&sp, &db) {
                                        Ok(()) => {
                                            let seen = db.get::<[u8;1]>("nullifier", &sp.nullifier).ok().flatten().is_some();
                                            if seen { continue; }
                                            if let (Some(sp_cf), Some(nf_cf)) = (db.db.cf_handle("spend"), db.db.cf_handle("nullifier")) {
                                                let mut batch = rocksdb::WriteBatch::default();
                                                if let Ok(bytes) = bincode::serialize(&sp) {
                                                    batch.put_cf(sp_cf, &sp.coin_id, &bytes);
                                                }
                                                batch.put_cf(nf_cf, &sp.nullifier, &[1u8;1]);
                                                if sp.unlock_preimage.is_some() {
                                                    if let Some(next_lock) = sp.next_lock_hash {
                                                        if let (Some(cid_cf), Ok(chain_id)) = (db.db.cf_handle("commitment_used"), db.get_chain_id()) {
                                                            let cid = crate::crypto::commitment_id_v1(&sp.to.one_time_pk, &sp.to.kyber_ct, &next_lock, &sp.coin_id, sp.to.amount_le, &chain_id);
                                                            batch.put_cf(cid_cf, &cid, &[1u8;1]);
                                                        }
                                                    }
                                                }
                                                let _ = db.db.write(batch);
                                            }
                                            let _ = spend_tx.send(sp.clone());
                                            // Hard invariant: after a confirmed spend is processed, coin must exist
                                            if db.get::<Coin>("coin", &sp.coin_id).ok().flatten().is_none() {
                                                eprintln!("❌ Invariant violated: spend applied but coin missing: {}", hex::encode(sp.coin_id));
                                            }

                                            // Try to apply any buffered successor spends in order
                                            if let Some(mut queued) = pending_spends.remove(&sp.coin_id) {
                                                // naive pass: keep attempting until no progress
                                                let mut made_progress = true;
                                                while made_progress {
                                                    made_progress = false;
                                                    let mut remaining: Vec<Spend> = Vec::new();
                                                    for q in queued.drain(..) {
                                                        if validate_spend(&q, &db).is_ok() {
                                                            let seen = db.get::<[u8;1]>("nullifier", &q.nullifier).ok().flatten().is_some();
                                                            if let (Some(sp_cf), Some(nf_cf)) = (db.db.cf_handle("spend"), db.db.cf_handle("nullifier")) {
                                                                let mut batch = rocksdb::WriteBatch::default();
                                                                if let Ok(bytes) = bincode::serialize(&q) {
                                                                    batch.put_cf(sp_cf, &q.coin_id, &bytes);
                                                                }
                                                                if !seen { batch.put_cf(nf_cf, &q.nullifier, &[1u8;1]); }
                                                                if q.unlock_preimage.is_some() {
                                                                    if let Some(next_lock) = q.next_lock_hash {
                                                                        if let (Some(cid_cf), Ok(chain_id)) = (db.db.cf_handle("commitment_used"), db.get_chain_id()) {
                                                                            let cid = crate::crypto::commitment_id_v1(&q.to.one_time_pk, &q.to.kyber_ct, &next_lock, &q.coin_id, q.to.amount_le, &chain_id);
                                                                            batch.put_cf(cid_cf, &cid, &[1u8;1]);
                                                                        }
                                                                    }
                                                                }
                                                                let _ = db.db.write(batch);
                                                            }
                                                            let _ = spend_tx.send(q.clone());
                                                            made_progress = true;
                                                        } else {
                                                            remaining.push(q);
                                                        }
                                                    }
                                                    if remaining.is_empty() { break; }
                                                    queued = remaining;
                                                }
                                                if !queued.is_empty() {
                                                    // Put back remaining still-invalid spends and extend deadline
                                                    pending_spends.insert(sp.coin_id, queued);
                                                    pending_spend_deadline.insert(sp.coin_id, std::time::Instant::now());
                                                } else {
                                                    pending_spend_deadline.remove(&sp.coin_id);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            let es = e.clone();
                                            // If authorization fails, we may be missing the predecessor spend; buffer and request latest
                                            if es.contains("Invalid hashlock preimage") || es.contains("Previous spend missing next_lock_hash") {
                                                let coin_id = sp.coin_id;
                                                pending_spends.entry(coin_id).or_default().push(sp);
                                                pending_spend_deadline.insert(coin_id, std::time::Instant::now());
                                                // Dedup spend fetch requests
                                                let now = std::time::Instant::now();
                                                if let Ok(mut map) = RECENT_SPEND_REQS.lock() {
                                                    map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                                    if !map.contains_key(&coin_id) {
                                                        // Ask peers via queue for retry/backoff
                                                        let _ = command_tx.send(NetworkCommand::RequestSpend(coin_id));
                                                        map.insert(coin_id, now);
                                                    }
                                                }
                                        } else if es.contains("Referenced coin does not exist") {
                                                let coin_id = sp.coin_id;
                                                // Buffer this spend until the coin is fetched
                                                pending_spends.entry(coin_id).or_default().push(sp);
                                                pending_spend_deadline.insert(coin_id, std::time::Instant::now());
                                                // Deduplicate coin fetch requests
                                                let now = std::time::Instant::now();
                                                if let Ok(mut map) = RECENT_COIN_REQS.lock() {
                                                    map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                                    if !map.contains_key(&coin_id) {
                                                        let _ = command_tx.send(NetworkCommand::RequestCoin(coin_id));
                                                        map.insert(coin_id, now);
                                                    }
                                                }
                                            } else if es.contains("Anchor not found") || es.contains("coin->epoch index") {
                                                let coin_id = sp.coin_id;
                                                pending_spends.entry(coin_id).or_default().push(sp);
                                                pending_spend_deadline.insert(coin_id, std::time::Instant::now());
                                                let _ = command_tx.send(NetworkCommand::RequestLatestEpoch);
                                            } else {
                                                crate::metrics::VALIDATION_FAIL_TRANSFER.inc();
                                                score.record_validation_failure();
                                            }
                                        }
                                    }
                                },
                                TOP_SPEND_REQUEST => if let Ok(coin_id) = bincode::deserialize::<[u8;32]>(&message.data) {
                                    if let Ok(Some(sp)) = db.get_spend_tolerant(&coin_id) {
                                        if let Ok(data) = bincode::serialize(&Some(sp)) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_SPEND_RESPONSE), data).ok();
                                        }
                                    } else {
                                        if let Ok(data) = bincode::serialize(&Option::<Spend>::None) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_SPEND_RESPONSE), data).ok();
                                        }
                                    }
                                },
                                TOP_SPEND_RESPONSE => if let Ok(resp) = bincode::deserialize::<Option<Spend>>(&message.data) {
                                    if let Some(sp) = resp {
                                        match validate_spend(&sp, &db) {
                                            Ok(()) => {
                                                let seen = db.get::<[u8;1]>("nullifier", &sp.nullifier).ok().flatten().is_some();
                                                if let (Some(sp_cf), Some(nf_cf)) = (db.db.cf_handle("spend"), db.db.cf_handle("nullifier")) {
                                                    let mut batch = rocksdb::WriteBatch::default();
                                                    if let Ok(bytes) = bincode::serialize(&sp) {
                                                        batch.put_cf(sp_cf, &sp.coin_id, &bytes);
                                                    }
                                                    if !seen { batch.put_cf(nf_cf, &sp.nullifier, &[1u8;1]); }
                                                    if sp.unlock_preimage.is_some() {
                                                        if let Some(next_lock) = sp.next_lock_hash {
                                                            if let (Some(cid_cf), Ok(chain_id)) = (db.db.cf_handle("commitment_used"), db.get_chain_id()) {
                                                                let cid = crate::crypto::commitment_id_v1(&sp.to.one_time_pk, &sp.to.kyber_ct, &next_lock, &sp.coin_id, sp.to.amount_le, &chain_id);
                                                                batch.put_cf(cid_cf, &cid, &[1u8;1]);
                                                            }
                                                        }
                                                    }
                                                    let _ = db.db.write(batch);
                                                }
                                                let _ = spend_tx.send(sp.clone());
                                                // Try apply any buffered successors now that base is present
                                                if let Some(mut queued) = pending_spends.remove(&sp.coin_id) {
                                                    let mut made_progress = true;
                                                    while made_progress {
                                                        made_progress = false;
                                                        let mut remaining: Vec<Spend> = Vec::new();
                                                        for q in queued.drain(..) {
                                                            if validate_spend(&q, &db).is_ok() {
                                                                if let (Some(sp_cf), Some(nf_cf)) = (db.db.cf_handle("spend"), db.db.cf_handle("nullifier")) {
                                                                    let mut batch = rocksdb::WriteBatch::default();
                                                                    if let Ok(bytes) = bincode::serialize(&q) {
                                                                        batch.put_cf(sp_cf, &q.coin_id, &bytes);
                                                                    }
                                                                    batch.put_cf(nf_cf, &q.nullifier, &[1u8;1]);
                                                                    let _ = db.db.write(batch);
                                                                }
                                                                let _ = spend_tx.send(q.clone());
                                                                made_progress = true;
                                                            } else {
                                                                remaining.push(q);
                                                            }
                                                        }
                                                        if remaining.is_empty() { break; }
                                                        queued = remaining;
                                                    }
                                                    if !queued.is_empty() {
                                                        pending_spends.insert(sp.coin_id, queued);
                                                        pending_spend_deadline.insert(sp.coin_id, std::time::Instant::now());
                                                    } else {
                                                        pending_spend_deadline.remove(&sp.coin_id);
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let es = e.clone();
                                                if es.contains("Invalid hashlock preimage") || es.contains("Previous spend missing next_lock_hash") {
                                                    let coin_id = sp.coin_id;
                                                    pending_spends.entry(coin_id).or_default().push(sp);
                                                    pending_spend_deadline.insert(coin_id, std::time::Instant::now());
                                                    // Ask peers for their latest spend for this coin
                                                    let now = std::time::Instant::now();
                                                    if let Ok(mut map) = RECENT_SPEND_REQS.lock() {
                                                        map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                                        if !map.contains_key(&coin_id) {
                                                            if let Ok(data) = bincode::serialize(&coin_id) {
                                                                try_publish_gossip(&mut swarm, TOP_SPEND_REQUEST, data, "spend-req");
                                                            }
                                                            map.insert(coin_id, now);
                                                        }
                                                    }
                                                } else if es.contains("Referenced coin does not exist") {
                                                    let coin_id = sp.coin_id;
                                                    pending_spends.entry(coin_id).or_default().push(sp);
                                                    pending_spend_deadline.insert(coin_id, std::time::Instant::now());
                                                    let now = std::time::Instant::now();
                                                    if let Ok(mut map) = RECENT_COIN_REQS.lock() {
                                                        map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                                        if !map.contains_key(&coin_id) {
                                                            if let Ok(data) = bincode::serialize(&coin_id) {
                                                                try_publish_gossip(&mut swarm, TOP_COIN_REQUEST, data, "coin-req");
                                                            }
                                                            map.insert(coin_id, now);
                                                        }
                                                    }
                                                } else if es.contains("Anchor not found") || es.contains("coin->epoch index") {
                                                    let coin_id = sp.coin_id;
                                                    pending_spends.entry(coin_id).or_default().push(sp);
                                                    pending_spend_deadline.insert(coin_id, std::time::Instant::now());
                                                    let _ = command_tx.send(NetworkCommand::RequestLatestEpoch);
                                                } else {
                                                    crate::metrics::VALIDATION_FAIL_TRANSFER.inc();
                                                    score.record_validation_failure();
                                                }
                                            }
                                        }
                                    }
                                },
                                TOP_LATEST_REQUEST => if let Ok(()) = bincode::deserialize::<()>(&message.data) {
                                    let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                                    let allow_log = score.check_rate_limit();
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                        let now = std::time::Instant::now();
                                        // Per-peer TTL dedup for same-latest-height requests
                                        let mut skip_due_to_dedup = false;
                                        if let Ok(mut map) = RECENT_LATEST_REQS.lock() {
                                            map.retain(|_, (t, _)| now.duration_since(*t) < std::time::Duration::from_secs(LATEST_REQ_DEDUP_SECS));
                                            if let Some((last_t, last_epoch)) = map.get(&peer_id) {
                                                if *last_epoch == anchor.num && now.duration_since(*last_t) < std::time::Duration::from_secs(LATEST_REQ_DEDUP_SECS) {
                                                    skip_due_to_dedup = true;
                                                }
                                            }
                                            if !skip_due_to_dedup { map.insert(peer_id, (now, anchor.num)); }
                                        }
                                        if skip_due_to_dedup { continue; }

                                        // Global throttle to avoid spamming network-wide anchor gossip
                                        let mut throttled = false;
                                        if let Ok(mut last) = LAST_LATEST_ANNOUNCE.lock() {
                                            if now.duration_since(*last) < std::time::Duration::from_millis(LATEST_GLOBAL_THROTTLE_MS) {
                                                throttled = true;
                                            } else {
                                                *last = now;
                                            }
                                        }

                                        if allow_log { net_routine!("📨 Received latest epoch request from peer: {}", peer_id); }
                                        if throttled { continue; }
                                        if allow_log { net_routine!("📤 Sending latest epoch {} to peer", anchor.num); }
                                        if let Ok(data) = bincode::serialize(&anchor) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), data).ok();
                                        }
                                    } else {
                                        if allow_log { net_routine!("⚠️  No latest epoch found to send"); }
                                    }
                                },
                                TOP_EPOCH_REQUEST => if let Ok(n) = bincode::deserialize::<u64>(&message.data) {
                                    net_routine!("📨 Received request for epoch {} from peer: {}", n, peer_id);
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &n.to_le_bytes()) {
                                        net_routine!("📤 Sending epoch {} to peer", n);
                                        if let Ok(data) = bincode::serialize(&anchor) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), data).ok();
                                        }
                                    } else { net_routine!("⚠️  Epoch {} not found", n); }
                                },
                                TOP_EPOCH_HEADERS_REQUEST => if let Ok(range) = bincode::deserialize::<EpochHeadersRange>(&message.data) {
                                    let start = range.start_height;
                                    let count = range.count as u64;
                                    let end_exclusive = start.saturating_add(count);
                                    let mut batch: Vec<Anchor> = Vec::new();
                                    for h in start..end_exclusive {
                                        if let Ok(Some(a)) = db.get::<Anchor>("epoch", &h.to_le_bytes()) {
                                            batch.push(a);
                                        } else {
                                            break;
                                        }
                                    }
                                    if !batch.is_empty() {
                                        let resp = EpochHeadersBatch { start_height: start, headers: batch };
                                        if let Ok(data) = bincode::serialize(&resp) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_HEADERS_RESPONSE), data).ok();
                                        }
                                    }
                                },
                                TOP_EPOCH_HEADERS_RESPONSE => if let Ok(batch) = bincode::deserialize::<EpochHeadersBatch>(&message.data) {
                                    // Re-broadcast internally for sync skeleton
                                    let _ = headers_tx.send(batch);
                                },
                                TOP_COIN_REQUEST => if let Ok(id) = bincode::deserialize::<[u8; 32]>(&message.data) {
                                    if let Ok(Some(coin)) = db.get::<Coin>("coin", &id) {
                                        if let Ok(data) = bincode::serialize(&coin) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), data).ok();
                                        }
                                    } else {
                                        // Try to reconstruct coin if possible from epoch selection meta
                                        if let Ok(Some(epoch_num)) = db.get_epoch_for_coin(&id) {
                                            if let Ok(Some(_anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                                if let Ok(selected_ids) = db.get_selected_coin_ids_for_epoch(epoch_num) {
                                                    if selected_ids.contains(&id) {
                                                        // Construct a minimal confirmed Coin using stored selection and known creator later via gossip
                                                        // We cannot reconstruct creator_pk; skip reconstruction here.
                                                        // Ask peers for selected ids as a hint to prompt them to gossip the coin to us
                                                        // Route via queue for retry/backoff instead of direct publish
                                                        let _ = command_tx.send(NetworkCommand::RequestEpochSelected(epoch_num));
                                                    }
                                                }
                                                // Send a proof request; peers serving proofs include the Coin in the response
                                                // Send via queue to benefit from retry
                                                let _ = command_tx.send(NetworkCommand::RequestCoinProof(id));
                                            }
                                        }
                                    }
                                },
                                TOP_COIN_PROOF_REQUEST => if let Ok(req) = bincode::deserialize::<CoinProofRequest>(&message.data) {
                                    let now = std::time::Instant::now();
                                    if let Ok(mut map) = RECENT_PROOF_REQS.lock() {
                                        map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                        if map.contains_key(&req.coin_id) { continue; }
                                        map.insert(req.coin_id, now);
                                    } else {
                                        eprintln!("proof-req dedup map mutex poisoned; proceeding without dedup");
                                    }
                                    if let Ok(Some(coin)) = db.get::<Coin>("coin", &req.coin_id) {
                                        if let Ok(Some(epoch_num)) = db.get_epoch_for_coin(&coin.id) {
                                            if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                                let mut responded = false;
                                                if let Ok(Some(leaves)) = db.get_epoch_leaves(anchor.num) {
                                                    let target_leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
                                                    if leaves.binary_search(&target_leaf).is_ok() {
                                                        if let Some(proof) = crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &target_leaf) {
                                                            let resp = CoinProofResponse { coin: coin.clone(), anchor: anchor.clone(), proof };
                                                            if let Ok(data) = bincode::serialize(&resp) {
                                                                swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_PROOF_RESPONSE), data).ok();
                                                                crate::metrics::PROOFS_SERVED.inc();
                                                                responded = true;
                                                            }
                                                        }
                                                    }
                                                }
                                                if !responded {
                                                    if let Ok(selected_ids) = db.get_selected_coin_ids_for_epoch(anchor.num) {
                                                        let set: HashSet<[u8; 32]> = HashSet::from_iter(selected_ids.into_iter());
                                                        if set.contains(&coin.id) {
                                                            if let Some(proof) = crate::epoch::MerkleTree::build_proof(&set, &coin.id) {
                                                                let resp = CoinProofResponse { coin: coin.clone(), anchor: anchor.clone(), proof };
                                                                if let Ok(data) = bincode::serialize(&resp) {
                                                                    swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_PROOF_RESPONSE), data).ok();
                                                                    crate::metrics::PROOFS_SERVED.inc();
                                                                    responded = true;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if !responded {
                                                    if let Ok(all_confirmed) = db.iterate_coins() {
                                                        let mut ids: Vec<[u8;32]> = all_confirmed
                                                            .into_iter()
                                                            .filter(|c| db.get_epoch_for_coin(&c.id).ok().flatten() == Some(anchor.num))
                                                            .map(|c| c.id)
                                                            .collect();
                                                        if ids.len() as u32 == anchor.coin_count {
                                                            let set: HashSet<[u8;32]> = HashSet::from_iter(ids.drain(..));
                                                            if set.contains(&coin.id) {
                                                                if let Some(proof) = crate::epoch::MerkleTree::build_proof(&set, &coin.id) {
                                                                    let resp = CoinProofResponse { coin, anchor: anchor.clone(), proof };
                                                                    if let Ok(data) = bincode::serialize(&resp) {
                                                                        swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_PROOF_RESPONSE), data).ok();
                                                                        crate::metrics::PROOFS_SERVED.inc();
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            pending_proof_requests.insert(req.coin_id, std::time::Instant::now());
                                                        }
                                                    } else {
                                                        pending_proof_requests.insert(req.coin_id, std::time::Instant::now());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                TOP_COIN_PROOF_RESPONSE => if let Ok(resp) = bincode::deserialize::<CoinProofResponse>(&message.data) {
                                    let _ = proof_tx.send(resp);
                                },
                                TOP_EPOCH_LEAVES => if let Ok(bundle) = bincode::deserialize::<EpochLeavesBundle>(&message.data) {
                                    // Validate bundle against stored anchor
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &bundle.epoch_num.to_le_bytes()) {
                                        if anchor.merkle_root != bundle.merkle_root { continue; }
                                        if anchor.coin_count as usize != bundle.leaves.len() { continue; }
                                        // Recompute root from provided leaves (sorted) and verify
                                        let mut leaves = bundle.leaves.clone();
                                        leaves.sort();
                                        let computed_root = crate::epoch::MerkleTree::compute_root_from_sorted_leaves(&leaves);
                                        if computed_root != anchor.merkle_root { continue; }
                                        // Persist leaves for proof serving only if not already stored identically
                                        let already_have_same = match db.get_epoch_leaves(bundle.epoch_num) {
                                            Ok(Some(existing)) => existing == leaves,
                                            _ => false,
                                        };
                                        if !already_have_same {
                                            if db.store_epoch_leaves(bundle.epoch_num, &leaves).is_ok() {
                                                net_log!("🌿 Stored epoch {} leaves from peer", bundle.epoch_num);
                                            }
                                        }
                                        // Try to serve any pending coin-proof requests that belong to this epoch
                                        let now = std::time::Instant::now();
                                        pending_proof_requests.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(PENDING_PROOF_TTL_SECS));
                                        let mut satisfied: Vec<[u8;32]> = Vec::new();
                                        for (coin_id, _) in pending_proof_requests.iter() {
                                            if let Ok(Some(coin)) = db.get::<Coin>("coin", coin_id) {
                                                if db.get_epoch_for_coin(&coin.id).ok().flatten() == Some(anchor.num) {
                                                    let target_leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
                                                    if leaves.binary_search(&target_leaf).is_ok() {
                                                        if let Some(proof) = crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &target_leaf) {
                                                            let resp = CoinProofResponse { coin: coin.clone(), anchor: anchor.clone(), proof };
                                                            if let Ok(data) = bincode::serialize(&resp) {
                                                                swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_PROOF_RESPONSE), data).ok();
                                                                crate::metrics::PROOFS_SERVED.inc();
                                                                satisfied.push(*coin_id);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        for id in satisfied { pending_proof_requests.remove(&id); }
                                    }
                                },
                                TOP_EPOCH_LEAVES_REQUEST => if let Ok(epoch_num) = bincode::deserialize::<u64>(&message.data) {
                                    // If we have leaves, gossip them immediately
                                    if let Ok(Some(leaves)) = db.get_epoch_leaves(epoch_num) {
                                        if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                            let bundle = EpochLeavesBundle { epoch_num, merkle_root: anchor.merkle_root, leaves };
                                            if let Ok(data) = bincode::serialize(&bundle) {
                                                try_publish_gossip(&mut swarm, TOP_EPOCH_LEAVES, data, "epoch-leaves");
                                            }
                                        }
                                    } else {
                                        // No leaves yet: attempt to reconstruct from selected index
                                        if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                            if let Ok(selected_ids) = db.get_selected_coin_ids_for_epoch(epoch_num) {
                                                let mut leaves: Vec<[u8;32]> = selected_ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
                                                leaves.sort();
                                                let computed_root = crate::epoch::MerkleTree::compute_root_from_sorted_leaves(&leaves);
                                                if computed_root == anchor.merkle_root {
                                                    let bundle = EpochLeavesBundle { epoch_num, merkle_root: anchor.merkle_root, leaves };
                                                    if let Ok(data) = bincode::serialize(&bundle) {
                                                        try_publish_gossip(&mut swarm, TOP_EPOCH_LEAVES, data, "epoch-leaves");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                TOP_EPOCH_SELECTED_REQUEST => if let Ok(epoch_num) = bincode::deserialize::<u64>(&message.data) {
                                    if let Ok(Some(_anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                        if let Ok(ids) = db.get_selected_coin_ids_for_epoch(epoch_num) {
                                            if let Ok(Some(anchor2)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                                if ids.len() as u32 != anchor2.coin_count { continue; }
                                                let response = SelectedIdsBundle { epoch_num, merkle_root: anchor2.merkle_root, coin_ids: ids };
                                                if let Ok(data) = bincode::serialize(&response) {
                                                    try_publish_gossip(&mut swarm, TOP_EPOCH_SELECTED_RESPONSE, data, "epoch-selected");
                                                }
                                            }
                                        }
                                    }
                                },
                                TOP_EPOCH_CANDIDATES_REQUEST => if let Ok(epoch_hash) = bincode::deserialize::<[u8;32]>(&message.data) {
                                    // Rate-limit by hash to avoid spam
                                    let now = std::time::Instant::now();
                                    let allow = RECENT_EPOCH_CAND_REQS.lock().map(|mut m| {
                                        m.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_millis(EPOCH_CAND_REQ_DEDUP_MS));
                                        if !m.contains_key(&epoch_hash) { m.insert(epoch_hash, now); true } else { false }
                                    }).unwrap_or(false);
                                    if !allow { continue; }
                                    // Collect candidates for this epoch hash (V3 only). Cap response size.
                                    if let Ok(mut list) = db.get_coin_candidates_by_epoch_hash(&epoch_hash) {
                                        if list.len() > MAX_EPOCH_CAND_RESP { list.truncate(MAX_EPOCH_CAND_RESP); }
                                        let resp = EpochCandidatesResponse { epoch_hash, candidates: list };
                                        if let Ok(data) = bincode::serialize(&resp) {
                                            try_publish_gossip(&mut swarm, TOP_EPOCH_CANDIDATES_RESPONSE, data, "epoch-candidates");
                                        }
                                    }
                                },
                                TOP_EPOCH_SELECTED_RESPONSE => if let Ok(bundle) = bincode::deserialize::<SelectedIdsBundle>(&message.data) {
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &bundle.epoch_num.to_le_bytes()) {
                                        if anchor.merkle_root != bundle.merkle_root { continue; }
                                        if anchor.coin_count as usize != bundle.coin_ids.len() { continue; }
                                        let mut leaves: Vec<[u8;32]> = bundle.coin_ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
                                        leaves.sort();
                                        let computed_root = crate::epoch::MerkleTree::compute_root_from_sorted_leaves(&leaves);
                                        if computed_root != anchor.merkle_root { continue; }
                                        // Deduplicate: skip writing if both leaves and selected IDs already match
                                        let mut skip_write = false;
                                        let leaves_match = match db.get_epoch_leaves(bundle.epoch_num) {
                                            Ok(Some(existing)) => existing == leaves,
                                            _ => false,
                                        };
                                        if leaves_match {
                                            if let Ok(existing_ids) = db.get_selected_coin_ids_for_epoch(bundle.epoch_num) {
                                                if existing_ids.len() == bundle.coin_ids.len() {
                                                    let a: std::collections::HashSet<[u8;32]> = std::collections::HashSet::from_iter(existing_ids.into_iter());
                                                    let b: std::collections::HashSet<[u8;32]> = std::collections::HashSet::from_iter(bundle.coin_ids.iter().copied());
                                                    if a == b { skip_write = true; }
                                                }
                                            }
                                        }
                                        if skip_write { continue; }
                                        if let (Some(sel_cf), Some(leaves_cf)) = (db.db.cf_handle("epoch_selected"), db.db.cf_handle("epoch_leaves")) {
                                            let mut batch = rocksdb::WriteBatch::default();
                                            for coin_id in &bundle.coin_ids {
                                                let mut key = Vec::with_capacity(8 + 32);
                                                key.extend_from_slice(&bundle.epoch_num.to_le_bytes());
                                                key.extend_from_slice(coin_id);
                                                batch.put_cf(sel_cf, &key, &[]);
                                            }
                                            if let Ok(bytes) = bincode::serialize(&leaves) {
                                                batch.put_cf(leaves_cf, &bundle.epoch_num.to_le_bytes(), &bytes);
                                            }
                                            let _ = db.db.write(batch);
                                        }
                                    }
                                },
                                TOP_EPOCH_CANDIDATES_RESPONSE => if let Ok(resp) = bincode::deserialize::<EpochCandidatesResponse>(&message.data) {
                                    // Best-effort import of candidates; validate first
                                    for cand in resp.candidates {
                                        if validate_coin_candidate(&cand, &db).is_ok() {
                                            let key = Store::candidate_key(&cand.epoch_hash, &cand.id);
                                            db.put("coin_candidate", &key, &cand).ok();
                                        }
                                    }
                                },
                                // Commitment request/response removed to prevent metadata leakage.
                                _ => {}
                            }
                        },
                        _ => {}
                    }
                },
                // Periodically retry pending publishes to avoid stalls until a reconnect
                _ = retry_timer.tick() => {
                    // Only attempt retries if we have any connected peers
                    let have_peers = connected_peers.lock().map(|s| !s.is_empty()).unwrap_or(false);
                    if !have_peers || pending_commands.is_empty() { continue; }
                    let mut still_pending = VecDeque::new();
                    while let Some(cmd) = pending_commands.pop_front() {
                        let (t, data) = match &cmd {
                            NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                            NetworkCommand::GossipCompactEpoch(c) => (TOP_EPOCH_COMPACT, bincode::serialize(&c).ok()),
                            NetworkCommand::GossipCoin(c)   => (TOP_COIN, bincode::serialize(&c).ok()),
                            NetworkCommand::GossipSpend(sp) => (TOP_SPEND, bincode::serialize(&sp).ok()),
                            NetworkCommand::GossipRateLimited(m) => (TOP_RATE_LIMITED, bincode::serialize(&m).ok()),
                            NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                            NetworkCommand::RequestEpochHeadersRange(range) => (TOP_EPOCH_HEADERS_REQUEST, bincode::serialize(&range).ok()),
                            NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                            NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok()),
                            NetworkCommand::RequestCoinProof(id) => (TOP_COIN_PROOF_REQUEST, bincode::serialize(&CoinProofRequest{ coin_id: *id }).ok()),
                            NetworkCommand::RequestSpend(id) => (TOP_SPEND_REQUEST, bincode::serialize(&id).ok()),
                            NetworkCommand::RequestEpochTxn(req) => (TOP_EPOCH_GET_TXN, bincode::serialize(&req).ok()),
                            NetworkCommand::RequestEpochSelected(epoch) => (TOP_EPOCH_SELECTED_REQUEST, bincode::serialize(&epoch).ok()),
                            NetworkCommand::RequestEpochLeaves(epoch) => (TOP_EPOCH_LEAVES_REQUEST, bincode::serialize(&epoch).ok()),
                            NetworkCommand::RequestEpochCandidates(hash) => (TOP_EPOCH_CANDIDATES_REQUEST, bincode::serialize(&hash).ok()),
                            NetworkCommand::GossipEpochLeaves(bundle) => (TOP_EPOCH_LEAVES, bincode::serialize(&bundle).ok()),
                        };
                        if let Some(d) = data {
                            if swarm.behaviour_mut().publish(IdentTopic::new(t), d).is_err() {
                                still_pending.push_back(cmd);
                            }
                        }
                    }
                    pending_commands = still_pending;
                },
                Some(command) = command_rx.recv() => {
                    match &command {
                        NetworkCommand::RequestEpochSelected(epoch_num) => {
                            // Dedup: avoid spamming same epoch within short window
                            let now = std::time::Instant::now();
                            if let Ok(mut map) = RECENT_LEAVES_REQS.lock() {
                                // Reuse leaves-req map to dedup epoch selected-requests with same TTL
                                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                                if !map.contains_key(epoch_num) {
                                    if let Ok(data) = bincode::serialize(epoch_num) {
                                        if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_SELECTED_REQUEST), data).is_err() {
                                            pending_commands.push_back(command);
                                        } else {
                                            map.insert(*epoch_num, now);
                                        }
                                    }
                                }
                            }
                        }
                        NetworkCommand::RequestEpoch(n) => {
                            let now = std::time::Instant::now();
                            if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                            }
                            if let Ok(mut map) = RECENT_EPOCH_REQS.lock() {
                                if !map.contains_key(n) {
                                    if let Ok(data) = bincode::serialize(n) {
                                        if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), data).is_err() {
                                            pending_commands.push_back(command);
                                        } else {
                                            map.insert(*n, now);
                                        }
                                    }
                                }
                            }
                        }
                        NetworkCommand::RequestEpochHeadersRange(range) => {
                            if let Ok(data) = bincode::serialize(range) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_HEADERS_REQUEST), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::GossipCompactEpoch(c) => {
                            if let Ok(data) = bincode::serialize(c) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_COMPACT), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestEpochTxn(req) => {
                            if let Ok(data) = bincode::serialize(req) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_GET_TXN), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::GossipAnchor(a) => {
                            if let Ok(data) = bincode::serialize(a) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::GossipCoin(c) => {
                            if let Ok(data) = bincode::serialize(c) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        
                        NetworkCommand::GossipSpend(sp) => {
                            if let Ok(data) = bincode::serialize(sp) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_SPEND), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestCoin(id) => {
                            if let Ok(data) = bincode::serialize(id) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_REQUEST), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestLatestEpoch => {
                            if let Ok(data) = bincode::serialize(&()) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_LATEST_REQUEST), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestCoinProof(id) => {
                            if let Ok(data) = bincode::serialize(&CoinProofRequest{ coin_id: *id }) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_PROOF_REQUEST), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestSpend(id) => {
                            if let Ok(data) = bincode::serialize(id) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_SPEND_REQUEST), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestEpochLeaves(epoch) => {
                            if let Ok(data) = bincode::serialize(epoch) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_LEAVES_REQUEST), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        NetworkCommand::RequestEpochCandidates(hash) => {
                            let now = std::time::Instant::now();
                            let allow = RECENT_EPOCH_CAND_REQS.lock().map(|mut m| {
                                m.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_millis(EPOCH_CAND_REQ_DEDUP_MS));
                                if !m.contains_key(hash) { m.insert(*hash, now); true } else { false }
                            }).unwrap_or(false);
                            if allow {
                                if let Ok(data) = bincode::serialize(hash) {
                                    if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_CANDIDATES_REQUEST), data).is_err() {
                                        pending_commands.push_back(command);
                                    }
                                }
                            }
                        }
                        NetworkCommand::GossipEpochLeaves(bundle) => {
                            if let Ok(data) = bincode::serialize(bundle) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_LEAVES), data).is_err() {
                                    pending_commands.push_back(command);
                                }
                            }
                        }
                        // Commitment gossip removed
                        NetworkCommand::GossipRateLimited(m) => {
                            // enforce 2 messages per 24 hours for outbound from this node
                            let (start, count) = outbound_quota;
                            let now = std::time::Instant::now();
                            let mut start_mut = start;
                            let mut count_mut = count;
                            if now.duration_since(start_mut) > std::time::Duration::from_secs(24 * 60 * 60) {
                                start_mut = now;
                                count_mut = 0;
                            }
                            if count_mut < 2 {
                                if let Ok(data) = bincode::serialize(m) {
                                    if swarm.behaviour_mut().publish(IdentTopic::new(TOP_RATE_LIMITED), data).is_err() {
                                        pending_commands.push_back(command);
                                    } else {
                                        count_mut += 1;
                                    }
                                }
                            } else {
                                eprintln!("⚠️  Rate limit exceeded for topic {} (2 msgs/24h). Dropping message.", TOP_RATE_LIMITED);
                            }
                            outbound_quota = (start_mut, count_mut);
                        }
                    }
                }
            }
        }
    });
    Ok(net)
}

impl Network {
    pub async fn gossip_anchor(&self, a: &Anchor) { let _ = self.command_tx.send(NetworkCommand::GossipAnchor(a.clone())); }
    pub async fn gossip_coin(&self, c: &CoinCandidate) {
        // Gossip the new-format candidate only (V3-only)
        let _ = self.command_tx.send(NetworkCommand::GossipCoin(c.clone()));
    }
    pub async fn gossip_spend(&self, sp: &Spend) { let _ = self.command_tx.send(NetworkCommand::GossipSpend(sp.clone())); }
    pub async fn gossip_compact_epoch(&self, compact: CompactEpoch) { let _ = self.command_tx.send(NetworkCommand::GossipCompactEpoch(compact)); }
    pub async fn gossip_rate_limited(&self, msg: RateLimitedMessage) { let _ = self.command_tx.send(NetworkCommand::GossipRateLimited(msg)); }
    pub async fn request_spend(&self, id: [u8;32]) { let _ = self.command_tx.send(NetworkCommand::RequestSpend(id)); }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> { self.anchor_tx.subscribe() }
    pub fn proof_subscribe(&self) -> broadcast::Receiver<CoinProofResponse> { self.proof_tx.subscribe() }
    pub fn spend_subscribe(&self) -> broadcast::Receiver<Spend> { self.spend_tx.subscribe() }
    pub fn headers_subscribe(&self) -> broadcast::Receiver<EpochHeadersBatch> { self.headers_tx.subscribe() }
    // Commitment subscription interfaces removed
    pub fn rate_limited_subscribe(&self) -> broadcast::Receiver<RateLimitedMessage> { self.rate_limited_tx.subscribe() }
    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> { self.anchor_tx.clone() }
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    pub async fn request_epoch_headers_range(&self, start_height: u64, count: u32) {
        let range = EpochHeadersRange { start_height, count };
        let _ = self.command_tx.send(NetworkCommand::RequestEpochHeadersRange(range));
    }
    pub async fn request_coin(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoin(id)); }
    pub async fn request_latest_epoch(&self) { let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch); }
    pub async fn request_coin_proof(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoinProof(id)); }
    pub async fn request_epoch_selected(&self, epoch_num: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpochSelected(epoch_num)); }
    pub async fn request_epoch_txn(&self, epoch_hash: [u8;32], indexes: Vec<u32>) {
        let req = EpochGetTxn { epoch_hash, indexes };
        let _ = self.command_tx.send(NetworkCommand::RequestEpochTxn(req));
    }
    pub async fn request_epoch_candidates(&self, epoch_hash: [u8;32]) { let _ = self.command_tx.send(NetworkCommand::RequestEpochCandidates(epoch_hash)); }
    pub async fn request_epoch_leaves(&self, epoch_num: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpochLeaves(epoch_num)); }
    // Note: We do not keep an explicit command variant; selected requests are sent directly when needed.
    pub async fn gossip_epoch_leaves(&self, bundle: EpochLeavesBundle) { let _ = self.command_tx.send(NetworkCommand::GossipEpochLeaves(bundle)); }
    // Commitment gossip removed
    
    /// Gets the current number of connected peers
    pub fn peer_count(&self) -> usize {
        self.connected_peers.lock().map(|s| s.len()).unwrap_or(0)
    }
}