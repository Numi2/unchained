use crate::{
    storage::Store, epoch::Anchor, coin::{Coin, CoinCandidate}, transfer::Transfer, config, sync::SyncState,
};
use std::sync::{Arc, Mutex};
use pqcrypto_traits::sign::PublicKey as _;
use libp2p::{
    gossipsub,
    identity, quic, swarm::SwarmEvent, PeerId, Swarm, Transport, Multiaddr,
    futures::StreamExt, core::muxing::StreamMuxerBox,
    request_response::{Event as ReqRespEvent, Message as ReqRespMessage},
    identify,
    ping,
};
use libp2p::swarm::NetworkBehaviour;
use pqcrypto_kyber::kyber768::{PublicKey as KyberPk, SecretKey as KyberSk, Ciphertext as KyberCt};
use pqcrypto_traits::kem::{PublicKey as KyberPkTrait, Ciphertext as KyberCtTrait};
use libp2p::gossipsub::{
    IdentTopic, MessageAuthenticity, IdentityTransform,
    AllowAllSubscriptionFilter, Behaviour as Gossipsub, Event as GossipsubEvent,
};
use bincode;
use std::collections::{HashMap, VecDeque, HashSet};
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};
use hex;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use serde::{Serialize, Deserialize};
use once_cell::sync::Lazy;
use ed25519_dalek::{Verifier as _, Signature as DalekSig};
use rand_chacha;
use std::time::Duration;

/// Best-effort public IPv4 discovery using a set of HTTPS endpoints.
/// Returns None if detection fails within the provided timeout per endpoint.
pub async fn detect_public_ipv4(timeout_ms: u64) -> Option<String> {
    use futures::future::join_all;
    let urls: [&str; 4] = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
    ];
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .user_agent("unchained-node/1.0")
        .build()
        .ok()?;
    // Fire all requests concurrently and return the first valid public IPv4
    let futs = urls.iter().map(|u| {
        let c = client.clone();
        async move {
            if let Ok(resp) = c.get(*u).send().await {
                if let Ok(body) = resp.text().await {
                    let s = body.trim();
                    if let Ok(std::net::IpAddr::V4(ipv4)) = s.parse() {
                        let o = ipv4.octets();
                        let is_private = o[0] == 10
                            || (o[0] == 172 && (16..=31).contains(&o[1]))
                            || (o[0] == 192 && o[1] == 168)
                            || (o[0] == 100 && (64..=127).contains(&o[1]))
                            || o[0] == 127
                            || (o[0] == 169 && o[1] == 254);
                        if !is_private { return Some(ipv4.to_string()); }
                    }
                }
            }
            None
        }
    });
    let results = join_all(futs).await;
    for r in results {
        if r.is_some() { return r; }
    }
    None
}

static QUIET_NET: AtomicBool = AtomicBool::new(false);
static CONNECTED_PEER_COUNT: AtomicUsize = AtomicUsize::new(0);
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

// try_publish_gossip removed (unused)

const TOP_ANCHOR: &str = "unchained/anchor/v1";
const TOP_COIN: &str = "unchained/coin/v1";
// Proof topics removed; proofs are served via RPC/HTTP only
const TOP_TX: &str = "unchained/tx/v1";
const TOP_LATEST_REQUEST: &str = "unchained/latest_request/v1";
const TOP_AUTH: &str = "unchained/auth/v1";

// Minimal announcement types for privacy-preserving gossip
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnchorAnnounce { num: u64, #[serde(with = "serde_big_array::BigArray")] hash: [u8; 32] }
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoinAnnounce { #[serde(with = "serde_big_array::BigArray")] epoch_hash: [u8; 32], #[serde(with = "serde_big_array::BigArray")] coin_id: [u8; 32] }
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferAnnounce { #[serde(with = "serde_big_array::BigArray")] tx_id: [u8; 32] }

#[derive(Debug, Clone)]
struct PeerScore {
    message_count: u32,
    window_start: Instant,
    rate_limit_window_secs: u64,
    max_messages_per_window: u32,
        // Per-peer candidate quota within current epoch window
        candidate_count: u32,
        max_candidates_per_window: u32,
}

impl PeerScore {
    fn new(p2p_cfg: &config::P2p) -> Self {
            Self {
                message_count: 0,
                window_start: Instant::now(),
                rate_limit_window_secs: p2p_cfg.rate_limit_window_secs,
                max_messages_per_window: p2p_cfg.max_messages_per_window,
                candidate_count: 0,
                max_candidates_per_window: 2048,
            }
    }

    // No banning logic in this profile

    fn is_banned(&mut self) -> bool { false }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > std::time::Duration::from_secs(self.rate_limit_window_secs) {
            self.window_start = now;
            self.message_count = 0;
                self.candidate_count = 0;
        }
        self.message_count += 1;
        self.message_count <= self.max_messages_per_window
    }

        fn allow_candidate(&mut self) -> bool {
            if self.candidate_count >= self.max_candidates_per_window {
                return false;
            }
            self.candidate_count += 1;
            true
        }
}

// validate_coin_candidate removed (unused)

// validate_transfer removed (unused)

// validate_anchor removed; anchors are fetched and validated through epoch manager/rpc paths

pub type NetHandle = Arc<Network>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinProofResponse {
    pub coin: Coin,
    pub anchor: Anchor,
    pub proof: Vec<([u8; 32], bool)>,
}

#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    proof_tx: broadcast::Sender<CoinProofResponse>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
    coin_id_tx: broadcast::Sender<[u8; 32]>,
}

#[derive(Debug, Clone)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(CoinCandidate),
    GossipTransfer(Transfer),
    RequestAuthHello,
    RequestEpoch(u64),
    RequestEpochSummary(u64),
    RequestCoin([u8; 32]),
    RequestLatestEpoch,
    RequestCoinProof([u8; 32]),
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
    _sync_state: Arc<Mutex<SyncState>>,
    epoch_cfg: config::Epoch,
    mining_cfg: config::Mining,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> anyhow::Result<NetHandle> {
    let id_keys = load_or_create_peer_identity()?;
    let peer_id = PeerId::from(id_keys.public());
            net_log!("🆔 Local peer ID: {}", peer_id);
    // Load PQ network identity for handshake gating
    let (pq_pk, pq_sk) = crate::crypto::load_or_create_pq_identity().map_err(|e| anyhow::anyhow!("pq identity: {}", e))?;
    // Load node Kyber KEM identity once and pin; fail fast if not available
    let (node_ky_pk, node_ky_sk) = crate::crypto::load_or_create_node_kyber().map_err(|e| anyhow::anyhow!("node kyber: {}", e))?;
    let node_ky_pk_bytes: Vec<u8> = node_ky_pk.as_bytes().to_vec();
    
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(std::time::Duration::from_millis(750))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .mesh_n_low(3)
        .mesh_outbound_min(3)
        .flood_publish(false)
        .build()?;
        
    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub_config,
    ).map_err(|e| anyhow::anyhow!(e))?;
    for t in [TOP_AUTH, TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_LATEST_REQUEST] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    // Compose behaviours: gossipsub + PQ RPC
    #[derive(NetworkBehaviour)]
    pub struct Behaviour {
        pub gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter>,
        pub rpc: crate::rpc::RpcBehaviour,
        pub identify: identify::Behaviour,
        pub ping: ping::Behaviour,
    }

    let behaviour = {
        let identify_cfg = identify::Config::new(
            "unchained/1.0".into(),
            id_keys.public(),
        );
        let ping_cfg = ping::Config::new()
            .with_interval(std::time::Duration::from_secs(3));
        Behaviour {
            gs,
            rpc: crate::rpc::build_rpc_behaviour(),
            identify: identify::Behaviour::new(identify_cfg),
            ping: ping::Behaviour::new(ping_cfg),
        }
    };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
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

    // Helper: compute our external addr prefix to detect self-dials
    let self_peer_id_str = peer_id.to_string();
    let self_external_prefix: Option<String> = net_cfg.public_ip.as_ref().map(|ip| format!("/ip4/{}/udp/{}/quic-v1", ip, port));

    // Initial bootstrap dials with self-dial guard
    for addr in &net_cfg.bootstrap {
        let is_self_peer = addr.contains(&format!("/p2p/{}", self_peer_id_str));
        let is_self_addr = self_external_prefix.as_ref().map(|p| addr.starts_with(p)).unwrap_or(false);
        if is_self_peer || is_self_addr {
            net_log!("⚠️  Skipping bootstrap that resolves to our own node: {}", addr);
            continue;
        }
        net_log!("🔗 Dialing bootstrap node: {}", addr);
        match swarm.dial(addr.parse::<Multiaddr>()?) {
            Ok(_) => net_log!("✅ Bootstrap dial initiated"),
            Err(e) => println!("❌ Failed to dial bootstrap node: {}", e),
        }
    }

    let (anchor_tx, _) = broadcast::channel(256);
    let (proof_tx, _) = broadcast::channel(256);
    let (coin_id_tx, _) = broadcast::channel(1024);
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), proof_tx: proof_tx.clone(), command_tx: command_tx.clone(), coin_id_tx: coin_id_tx.clone() });

    let mut peer_scores: HashMap<PeerId, PeerScore> = HashMap::new();
    let mut pending_commands: VecDeque<NetworkCommand> = VecDeque::new();
    const MAX_PENDING_COMMANDS: usize = 4096;
    // orphan_anchors removed; full anchors are fetched via RPC
    let mut connected_peers: HashSet<PeerId> = HashSet::new();
    let mut pq_authed: HashSet<PeerId> = HashSet::new();
    let mut identified_peers: HashSet<PeerId> = HashSet::new();
    #[derive(Clone)]
    struct PeerStaticKeys { kyber_pk: Vec<u8>, ed25519_pk: Vec<u8>, dilithium_pk: [u8; crate::crypto::DILITHIUM3_PK_BYTES] }
    let mut peer_keys: HashMap<PeerId, PeerStaticKeys> = HashMap::new();

    // LRU-ish cache for RPC ClientHello replay nonces per peer (drop replays before decap)
    static RECENT_CLIENT_HELLOS: Lazy<Mutex<std::collections::HashMap<(String, [u8;32]), std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

    // Pending RPC state for decrypting responses
    #[derive(Clone)]
    struct PendingRpc {
        client_sk: KyberSk,
        client_u: crate::rpc::ClientHelloUnsigned,
        requested_method: crate::rpc::RpcMethod,
    }
    let mut pending_rpcs: HashMap<u64, PendingRpc> = HashMap::new();

    // For redial/backoff, keep a local copy of net config
    let net_cfg_clone = net_cfg.clone();
    let target_min_peers = net_cfg_clone.min_peers.max(1) as usize;
    tokio::spawn(async move {
        // Periodic redial timer with exponential backoff when we have no peers
        let mut redial_timer = tokio::time::interval(std::time::Duration::from_millis(1500));
        // Periodically (re)send PQ auth hello until peers are authenticated to avoid race with gossipsub mesh setup
        let mut auth_retry_timer = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut redial_backoff_secs: u64 = 1;
        let mut last_redial_instant = std::time::Instant::now() - std::time::Duration::from_secs(60);
        loop {
            tokio::select! {
                _ = redial_timer.tick() => {
                    // If we are below target, probe dials with adaptive backoff
                    if connected_peers.len() < target_min_peers {
                        if last_redial_instant.elapsed() >= std::time::Duration::from_secs(redial_backoff_secs) {
                            // Apply same self-dial guard during redial
                            let self_pid = peer_id.to_string();
                            let self_prefix = net_cfg_clone.public_ip.as_ref().map(|ip| format!("/ip4/{}/udp/{}/quic-v1", ip, port));
                            for addr in &net_cfg_clone.bootstrap {
                                let is_self_peer = addr.contains(&format!("/p2p/{}", self_pid));
                                let is_self_addr = self_prefix.as_ref().map(|p| addr.starts_with(p)).unwrap_or(false);
                                if is_self_peer || is_self_addr {
                                    net_log!("⚠️  Skipping redial to self address: {}", addr);
                                    continue;
                                }
                                net_log!("🔁 Redial attempt (backoff {}s) to {}", redial_backoff_secs, addr);
                                if let Err(e) = swarm.dial(addr.parse::<Multiaddr>().unwrap_or_else(|_| "/ip4/127.0.0.1/udp/31000/quic-v1".parse().unwrap())) {
                                    println!("❌ Redial failed: {}", e);
                                }
                            }
                            last_redial_instant = std::time::Instant::now();
                            // Increase backoff only if we have zero peers; otherwise keep it modest to fill to min_peers faster
                            if connected_peers.is_empty() {
                                redial_backoff_secs = (redial_backoff_secs.saturating_mul(2)).min(30);
                            } else {
                                redial_backoff_secs = (redial_backoff_secs + 1).min(10);
                            }
                        }
                    } else {
                        // Reset backoff once we have at least one peer
                        redial_backoff_secs = 1;
                    }
                },
                _ = auth_retry_timer.tick() => {
                    // Re-advertise PQ auth hello to any connected peer that hasn't been marked authenticated yet.
                    // This mitigates timing where the initial publish happens before gossipsub mesh is ready.
                    if !connected_peers.is_empty() {
                        // Prepare hello once per tick
                        #[derive(Debug, Clone, Serialize, Deserialize)]
                        struct NetHelloUnsigned {
                            handshake_version: u8,
                            local_peer_id: String,
                            #[serde(with = "serde_big_array::BigArray")]
                            dilithium_pk: [u8; crate::crypto::DILITHIUM3_PK_BYTES],
                            ed25519_pk: Vec<u8>,
                            kyber_pk: Vec<u8>,
                            expiry_unix_secs: u64,
                        }
                        #[derive(Debug, Clone, Serialize, Deserialize)]
                        struct NetHello {
                            unsigned: NetHelloUnsigned,
                            sig_ed25519: Vec<u8>,
                            #[serde(with = "serde_big_array::BigArray")]
                            sig_dilithium: [u8; crate::crypto::DILITHIUM3_SIG_BYTES],
                        }
                        let ed_pk_bytes: Vec<u8> = id_keys.public().try_into_ed25519().map(|p| p.to_bytes().to_vec()).unwrap_or_default();
                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                        pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                        let unsigned = NetHelloUnsigned {
                            handshake_version: 1,
                            local_peer_id: peer_id.to_string(),
                            dilithium_pk: pq_pk_arr,
                            ed25519_pk: ed_pk_bytes.clone(),
                            kyber_pk: node_ky_pk_bytes.clone(),
                            expiry_unix_secs: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()) + 3600,
                        };
                        let unsigned_ser = bincode::serialize(&unsigned).unwrap_or_default();
                        let sig_ed25519 = id_keys.sign(&unsigned_ser).unwrap_or_default();
                        let sig_dilithium = crate::crypto::pq_sign_detached(&unsigned_ser, &pq_sk);
                        let hello = NetHello { unsigned, sig_ed25519, sig_dilithium };
                        if let Ok(bytes) = bincode::serialize(&hello) {
                            // Only resend if there exists at least one not-yet-authed peer
                            let need_resend = connected_peers.iter().any(|p| !pq_authed.contains(p));
                            if need_resend {
                                let _ = swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_AUTH), bytes);
                            }
                        }
                    }
                },
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id: remote_peer_id, .. } => {
                            // Guard against accidental self-connections (e.g., hairpin via public IP)
                            if remote_peer_id == peer_id {
                                net_log!("⚠️  Self-connection detected; dropping: {}", remote_peer_id);
                                let _ = swarm.disconnect_peer_id(remote_peer_id);
                                continue;
                            }
                            // Only log the first time we see a connection for this peer to avoid duplicate logs
                            let is_new_peer = connected_peers.insert(remote_peer_id);
                            if is_new_peer {
                                net_log!("🤝 Connected to peer: {}", remote_peer_id);
                                // Diagnostic: indicate PQ TLS preference is active (aws-lc-rs installed)
                                net_log!("🔐 Transport: rustls prefer-post-quantum active (aws-lc-rs provider installed)");
                            }
                            peer_scores.entry(remote_peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                            CONNECTED_PEER_COUNT.store(connected_peers.len(), Ordering::Relaxed);
                            // Help gossipsub mesh stabilize early
                            swarm.behaviour_mut().gs.add_explicit_peer(&remote_peer_id);
                            // Prepare and immediately publish PQ auth hello over gossip to avoid servers that
                            // require early auth advertisement on connect.
                            let ed_pk_bytes: Vec<u8> = id_keys.public().try_into_ed25519().map(|p| p.to_bytes().to_vec()).unwrap_or_default();
                            #[derive(Debug, Clone, Serialize, Deserialize)]
                            struct NetHelloUnsigned {
                                handshake_version: u8,
                                local_peer_id: String,
                                #[serde(with = "serde_big_array::BigArray")]
                                dilithium_pk: [u8; crate::crypto::DILITHIUM3_PK_BYTES],
                                ed25519_pk: Vec<u8>,
                                kyber_pk: Vec<u8>,
                                expiry_unix_secs: u64,
                            }
                            #[derive(Debug, Clone, Serialize, Deserialize)]
                            struct NetHello {
                                unsigned: NetHelloUnsigned,
                                sig_ed25519: Vec<u8>,
                                #[serde(with = "serde_big_array::BigArray")]
                                sig_dilithium: [u8; crate::crypto::DILITHIUM3_SIG_BYTES],
                            }
                            let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                            pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                            let unsigned = NetHelloUnsigned {
                                handshake_version: 1,
                                local_peer_id: peer_id.to_string(),
                                dilithium_pk: pq_pk_arr,
                                ed25519_pk: ed_pk_bytes.clone(),
                                kyber_pk: node_ky_pk_bytes.clone(),
                                expiry_unix_secs: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()) + 3600,
                            };
                            let unsigned_ser = bincode::serialize(&unsigned).unwrap_or_default();
                            let sig_ed25519 = id_keys.sign(&unsigned_ser).unwrap_or_default();
                            let sig_dilithium = crate::crypto::pq_sign_detached(&unsigned_ser, &pq_sk);
                            let hello = NetHello { unsigned, sig_ed25519, sig_dilithium };
                            if let Ok(bytes) = bincode::serialize(&hello) {
                                let _ = swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_AUTH), bytes);
                            }
                            let mut still_pending = VecDeque::new();
                            while let Some(cmd) = pending_commands.pop_front() {
                                match &cmd {
                                    // Gossip-only items can be published immediately
                                    NetworkCommand::GossipAnchor(a) => {
                                        if let Ok(d) = bincode::serialize(&a) {
                                            if swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_ANCHOR), d).is_err() {
                                                if still_pending.len() >= MAX_PENDING_COMMANDS { let _ = still_pending.pop_front(); crate::metrics::PENDING_CMD_DROPS.inc(); }
                                                still_pending.push_back(cmd);
                                                crate::metrics::PENDING_CMD_QUEUE_LEN.set(still_pending.len() as i64);
                                            } else {
                                                crate::metrics::MSGS_OUT_ANCHOR.inc();
                                            }
                                        }
                                    },
                                    NetworkCommand::GossipCoin(c) => {
                                        if let Ok(d) = bincode::serialize(&c) {
                                            if swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_COIN), d).is_err() {
                                                if still_pending.len() >= MAX_PENDING_COMMANDS { let _ = still_pending.pop_front(); crate::metrics::PENDING_CMD_DROPS.inc(); }
                                                still_pending.push_back(cmd);
                                                crate::metrics::PENDING_CMD_QUEUE_LEN.set(still_pending.len() as i64);
                                            } else {
                                                crate::metrics::MSGS_OUT_COIN.inc();
                                            }
                                        }
                                    },
                                    NetworkCommand::GossipTransfer(tx) => {
                                        if let Ok(d) = bincode::serialize(&tx) {
                                            if swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_TX), d).is_err() {
                                                if still_pending.len() >= MAX_PENDING_COMMANDS { let _ = still_pending.pop_front(); crate::metrics::PENDING_CMD_DROPS.inc(); }
                                                still_pending.push_back(cmd);
                                                crate::metrics::PENDING_CMD_QUEUE_LEN.set(still_pending.len() as i64);
                                            } else {
                                                crate::metrics::MSGS_OUT_TX.inc();
                                            }
                                        }
                                    },
                                    // RPC-bound items must wait until PQ auth completes and peer keys are known.
                                    // Keep them pending to be flushed on PQ auth completion.
                                    NetworkCommand::RequestEpoch(_)
                                    | NetworkCommand::RequestEpochSummary(_)
                                    | NetworkCommand::RequestAuthHello
                                    | NetworkCommand::RequestCoin(_)
                                    | NetworkCommand::RequestCoinProof(_)
                                    | NetworkCommand::RequestLatestEpoch => {
                                        if still_pending.len() >= MAX_PENDING_COMMANDS { let _ = still_pending.pop_front(); crate::metrics::PENDING_CMD_DROPS.inc(); }
                                        still_pending.push_back(cmd);
                                        crate::metrics::PENDING_CMD_QUEUE_LEN.set(still_pending.len() as i64);
                                    }
                                }
                            }
                            pending_commands = still_pending;
                            crate::metrics::PENDING_CMD_QUEUE_LEN.set(pending_commands.len() as i64);
                            // Request Identify to stabilize and discover supported protocols
                            if !identified_peers.contains(&remote_peer_id) {
                                // Ensure Identify is requested promptly
                                let _ = swarm.behaviour_mut().identify.push(std::iter::once(remote_peer_id));
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            net_log!("👋 Disconnected from peer: {} due to {:?}", peer_id, cause);
                            connected_peers.remove(&peer_id);
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                            CONNECTED_PEER_COUNT.store(connected_peers.len(), Ordering::Relaxed);
                            // Trigger immediate redial cycle by resetting last_redial_instant
                            last_redial_instant = std::time::Instant::now() - std::time::Duration::from_secs(redial_backoff_secs);
                            // If we dropped below target, proactively dial without waiting for timer
                            if connected_peers.len() < target_min_peers {
                                for addr in &net_cfg_clone.bootstrap {
                                    let _ = swarm.dial(addr.parse::<Multiaddr>().unwrap_or_else(|_| "/ip4/127.0.0.1/udp/31000/quic-v1".parse().unwrap()));
                                }
                            }
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Gs(GossipsubEvent::Message { message, .. })) => {
                            let source_opt = message.source;
                            let topic_str = message.topic.as_str();
                            // Use the actual source peer for accounting/gating when available; fall back to local only if unknown
                            let src_peer = source_opt.unwrap_or(peer_id);
                            let score = peer_scores.entry(src_peer).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            // Do not rate-limit inbound anchors – they are essential for fast catch-up.
                            let rate_limit_exempt = topic_str == TOP_ANCHOR || topic_str == TOP_AUTH;
                            if score.is_banned() {
                                crate::metrics::BANNED_DROPS.inc();
                                continue;
                            }
                            if !rate_limit_exempt && !score.check_rate_limit() {
                                crate::metrics::RATE_LIMIT_DROPS.inc();
                                continue;
                            }
                            // Gate non-auth topics behind PQ handshake, but allow TOP_ANCHOR to pass pre-auth
                            // so new nodes can learn the tip and enqueue RPC fetches which will be flushed
                            // once PQ auth completes.
                            if topic_str != TOP_AUTH && topic_str != TOP_ANCHOR && !pq_authed.contains(&src_peer) {
                                // silently ignore pre-auth non-auth topics (except anchors)
                                continue;
                            }
                            match topic_str {
                                TOP_AUTH => {
                                    // Expect handshake
                                    #[derive(Debug, Clone, Serialize, Deserialize)]
                                    struct NetHelloUnsigned { handshake_version: u8, local_peer_id: String, #[serde(with = "serde_big_array::BigArray")] dilithium_pk: [u8; crate::crypto::DILITHIUM3_PK_BYTES], ed25519_pk: Vec<u8>, kyber_pk: Vec<u8>, expiry_unix_secs: u64 }
                                    #[derive(Debug, Clone, Serialize, Deserialize)]
                                    struct NetHello { unsigned: NetHelloUnsigned, sig_ed25519: Vec<u8>, #[serde(with = "serde_big_array::BigArray")] sig_dilithium: [u8; crate::crypto::DILITHIUM3_SIG_BYTES] }
                                    if let Ok(hello) = bincode::deserialize::<NetHello>(&message.data) {
                                        // Derive claimed peer id from the signed ed25519 key
                                        let derived_peer = match libp2p::identity::ed25519::PublicKey::try_from_bytes(&hello.unsigned.ed25519_pk) {
                                            Ok(lp) => PeerId::from(libp2p::identity::PublicKey::from(lp)),
                                            Err(e) => { eprintln!("TOP_AUTH: bad ed25519 pk from peer {:?}: {}", source_opt, e); continue; }
                                        };
                                        // Prefer libp2p-reported source when available, otherwise fall back to derived
                                        let auth_peer = source_opt.unwrap_or_else(|| derived_peer.clone());
                                        // If already authenticated, ignore repeated hellos to avoid log spam
                                        if pq_authed.contains(&auth_peer) { continue; }
                                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                        if hello.unsigned.expiry_unix_secs < now { eprintln!("TOP_AUTH: hello expired from {}", auth_peer); continue; }
                                        // Verify the message binds to the claimed peer id
                                        if derived_peer != auth_peer { eprintln!("TOP_AUTH: derived peer {:?} != source {:?}", derived_peer, auth_peer); continue; }
                                        if hello.unsigned.local_peer_id != derived_peer.to_string() { eprintln!("TOP_AUTH: local_peer_id mismatch for {}", auth_peer); continue; }
                                        // Verify ed25519 signature (dalek)
                                        let dalek_pk = match ed25519_dalek::PublicKey::from_bytes(&hello.unsigned.ed25519_pk) { Ok(p)=>p, Err(e)=>{ eprintln!("TOP_AUTH: bad ed25519 pk bytes from {}: {}", auth_peer, e); continue; } };
                                        let dalek_sig = match DalekSig::from_bytes(&hello.sig_ed25519) { Ok(s)=>s, Err(e)=>{ eprintln!("TOP_AUTH: bad ed25519 sig from {}: {}", auth_peer, e); continue; } };
                                        if dalek_pk.verify(&bincode::serialize(&hello.unsigned).unwrap_or_default(), &dalek_sig).is_err() { eprintln!("TOP_AUTH: ed25519 verify failed for {}", auth_peer); continue; }
                                        // Verify dilithium signature
                                        let pk_pq = match pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&hello.unsigned.dilithium_pk) { Ok(p)=>p, Err(_)=>{ eprintln!("TOP_AUTH: bad dilithium pk from {}", auth_peer); continue; } };
                                        if !crate::crypto::pq_verify_detached(&bincode::serialize(&hello.unsigned).unwrap_or_default(), &hello.sig_dilithium, &pk_pq) { eprintln!("TOP_AUTH: dilithium verify failed for {}", auth_peer); continue; }
                                        let first_time = pq_authed.insert(auth_peer);
                                        peer_keys.insert(auth_peer, PeerStaticKeys { kyber_pk: hello.unsigned.kyber_pk.clone(), ed25519_pk: hello.unsigned.ed25519_pk.clone(), dilithium_pk: hello.unsigned.dilithium_pk });
                                        if first_time {
                                            net_log!("✅ PQ auth completed for peer: {}", src_peer);
                                            // Kick off sync immediately after auth by sending AuthHello then requesting latest anchor
                                            let _ = command_tx.send(NetworkCommand::RequestAuthHello);
                                            let _ = command_tx.send(NetworkCommand::RequestLatestEpoch);
                                            // Now that PQ auth is complete and peer static keys are pinned, flush any pending RPC commands
                                            // by re-enqueuing them onto the command channel to be sent via RPC.
                                            let mut flushed = 0usize;
                                            while let Some(cmd) = pending_commands.pop_front() {
                                                // Only re-enqueue RPC-bound items; gossip ones are transient and handled elsewhere
                                                match cmd {
                                                    NetworkCommand::RequestEpoch(_)
                                                    | NetworkCommand::RequestEpochSummary(_)
                                                    | NetworkCommand::RequestCoin(_)
                                                    | NetworkCommand::RequestCoinProof(_)
                                                    | NetworkCommand::RequestLatestEpoch => { let _ = command_tx.send(cmd); flushed += 1; },
                                                    other => { // Keep gossip leftovers in the queue
                                                        pending_commands.push_back(other);
                                                        continue;
                                                    }
                                                }
                                            }
                                            if flushed > 0 { crate::metrics::PENDING_CMD_QUEUE_LEN.set(pending_commands.len() as i64); }
                                        }
                                    } else {
                                        eprintln!("TOP_AUTH: failed to deserialize hello from {:?}", source_opt);
                                    }
                                },
                                // Gossip only announces anchor id and height; bodies via RPC
                                TOP_ANCHOR => if let Ok(ann) = bincode::deserialize::<AnchorAnnounce>(&message.data) {
                                    crate::metrics::MSGS_IN_ANCHOR.inc();
                                    // Always request full anchor by number over RPC
                                    net_log!("📣 Announced anchor #{} (hash {}) — requesting payload via RPC", ann.num, hex::encode(ann.hash));
                                    // Update highest seen epoch for sync state
                                    {
                                        let mut st = _sync_state.lock().unwrap();
                                        if ann.num > st.highest_seen_epoch { st.highest_seen_epoch = ann.num; }
                                    }
                                    // Request both summary and header directly; whichever lands first advances us
                                    let _ = command_tx.send(NetworkCommand::RequestEpochSummary(ann.num));
                                    let _ = command_tx.send(NetworkCommand::RequestEpoch(ann.num));
                                },
                                // Gossip coin: announce only epoch_hash + coin_id
                                TOP_COIN => if let Ok(ann) = bincode::deserialize::<CoinAnnounce>(&message.data) {
                                    crate::metrics::MSGS_IN_COIN.inc();
                                    // Enforce per-peer candidate quota
                                    // Use the actual source peer for accounting, not the local peer id
                                    let score = peer_scores.entry(src_peer).or_insert_with(|| PeerScore::new(&p2p_cfg));
                                    if !score.allow_candidate() { continue; }
                                    // Immediately broadcast coin id to local subscribers (epoch manager)
                                    let _ = anchor_tx.send(Anchor { version: 0, num: 0, hash: [0u8;32], merkle_root: [0u8;32], transfers_root: [0u8;32], work_root: [0u8;32], target_nbits: 0, mem_kib: 0, t_cost: 0, coin_count: 0, cumulative_work: primitive_types::U256::zero() }); // no-op to avoid unused warnings
                                    let _ = coin_id_tx.send(ann.coin_id);
                                    // Actively fetch candidate and validate early to mitigate DoS
                                    let _ = command_tx.send(NetworkCommand::RequestCoin(ann.coin_id));
                                    // Also request a proof for probabilistic verifiers later if needed
                                    let _ = command_tx.send(NetworkCommand::RequestCoinProof(ann.coin_id));
                                },
                                // Gossip transfer: announce only tx_id
                                TOP_TX => if let Ok(_ann) = bincode::deserialize::<TransferAnnounce>(&message.data) {
                                    crate::metrics::MSGS_IN_TX.inc();
                                },
                                TOP_LATEST_REQUEST => if let Ok(()) = bincode::deserialize::<()>(&message.data) {
                                    crate::metrics::MSGS_IN_LATEST_REQ.inc();
                                    // Only log once every 5 seconds per peer to avoid spam
                                    let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                                    if score.check_rate_limit() {
                                        net_log!("📨 Received latest epoch request from peer: {}", peer_id);
                                    }
                                    // No gossip payloads; use RPC instead
                                },
                                // TOP_EPOCH_REQUEST removed from gossip
                                // TOP_COIN_REQUEST removed from gossip
                                // Proof topics removed: ignore
                                _ => {}
                            }
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Rpc(ReqRespEvent::Message { peer, message, .. })) => {
                            match message {
                                ReqRespMessage::Request { request, channel, .. } => {
                                    // Defer RPC gating until after decrypting the method so we can allow AuthHello pre-auth.

                                    // Verify client hello signatures and binding (plaintext hello is part of request)
                                    let client_u = &request.client_hello.unsigned;
                                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                    if client_u.expiry_unix_secs < now { 
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(
                                            channel,
                                            crate::rpc::seal_response(
                                                request.request_id,
                                                request.stream_id,
                                                client_u.clone(),
                                                server_ed_pk,
                                                pq_pk_arr,
                                                |m| id_keys.sign(m).unwrap_or_default(),
                                                |m| crate::crypto::pq_sign_detached(m, &pq_sk),
                                                |client_pk_bytes| { let pk = KyberPk::from_bytes(client_pk_bytes).expect("kyber pk"); crate::crypto::kyber_encapsulate(&pk) },
                                                node_ky_pk_bytes.clone(),
                                                crate::rpc::PINNED_SUITES,
                                                &peer_id.to_string(),
                                                &peer.to_string(),
                                                &crate::rpc::RpcResponsePayload::Error("client hello expired".into())
                                            )
                                        );
                                        continue; 
                                    }
                                    // Bind to peer ids claimed by client. Enforce mapping to libp2p peer id (ed25519)
                                    if client_u.remote_peer_id != peer_id.to_string() || client_u.local_peer_id != peer.to_string() {
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(
                                            channel,
                                            crate::rpc::seal_response(
                                                request.request_id,
                                                request.stream_id,
                                                client_u.clone(),
                                                server_ed_pk,
                                                pq_pk_arr,
                                                |m| id_keys.sign(m).unwrap_or_default(),
                                                |m| crate::crypto::pq_sign_detached(m, &pq_sk),
                                                |client_pk_bytes| { let pk = KyberPk::from_bytes(client_pk_bytes).expect("kyber pk"); crate::crypto::kyber_encapsulate(&pk) },
                                                node_ky_pk_bytes.clone(),
                                                crate::rpc::PINNED_SUITES,
                                                &peer_id.to_string(),
                                                &peer.to_string(),
                                                &crate::rpc::RpcResponsePayload::Error("peer id binding".into())
                                            )
                                        );
                                        continue;
                                    }
                                    // Anti-replay on (peer, nonce)
                                    {
                                        let mut map = RECENT_CLIENT_HELLOS.lock().unwrap();
                                        let key = (peer.to_string(), client_u.nonce);
                                        // TTL 5 minutes
                                        let ttl = std::time::Duration::from_secs(300);
                                        let nowi = std::time::Instant::now();
                                        map.retain(|_, t| nowi.saturating_duration_since(*t) < ttl);
                                        if map.contains_key(&key) {
                                            let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                            let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                            let _ = swarm.behaviour_mut().rpc.send_response(
                                                channel,
                                                crate::rpc::seal_response(
                                                    request.request_id,
                                                    request.stream_id,
                                                    client_u.clone(),
                                                    server_ed_pk,
                                                    pq_pk_arr,
                                                    |m| id_keys.sign(m).unwrap_or_default(),
                                                    |m| crate::crypto::pq_sign_detached(m, &pq_sk),
                                                    |client_pk_bytes| { let pk = KyberPk::from_bytes(client_pk_bytes).expect("kyber pk"); crate::crypto::kyber_encapsulate(&pk) },
                                                    node_ky_pk_bytes.clone(),
                                                    crate::rpc::PINNED_SUITES,
                                                    &peer_id.to_string(),
                                                    &peer.to_string(),
                                                    &crate::rpc::RpcResponsePayload::Error("client hello replay".into())
                                                )
                                            );
                                            continue;
                                        } else {
                                            map.insert(key, nowi);
                                        }
                                    }
                                    // Verify ed25519 signature on client hello (plaintext; prevents DoS before decap)
                                    let ser_u = bincode::serialize(client_u).unwrap_or_default();
                                    let ed_ok = if request.client_hello.sig_ed25519.len() == 64 {
                                        if let Ok(edpk) = ed25519_dalek::PublicKey::from_bytes(&client_u.ed25519_pk) {
                                            if let Ok(sig) = ed25519_dalek::Signature::from_bytes(&request.client_hello.sig_ed25519) {
                                                edpk.verify(&ser_u, &sig).is_ok()
                                            } else { false }
                                        } else { false }
                                    } else { false };
                                    if !ed_ok { 
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(
                                            channel,
                                            crate::rpc::seal_response(
                                                request.request_id,
                                                request.stream_id,
                                                client_u.clone(),
                                                server_ed_pk,
                                                pq_pk_arr,
                                                |m| id_keys.sign(m).unwrap_or_default(),
                                                |m| crate::crypto::pq_sign_detached(m, &pq_sk),
                                                |client_pk_bytes| { let pk = KyberPk::from_bytes(client_pk_bytes).expect("kyber pk"); crate::crypto::kyber_encapsulate(&pk) },
                                                node_ky_pk_bytes.clone(),
                                                crate::rpc::PINNED_SUITES,
                                                &peer_id.to_string(),
                                                &peer.to_string(),
                                                &crate::rpc::RpcResponsePayload::Error("bad ed25519".into())
                                            )
                                        );
                                        continue;
                                    }
                                    // Verify Dilithium signature on client hello
                                    let pq_ok = if let Ok(pqpk) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&client_u.dilithium_pk) {
                                        crate::crypto::pq_verify_detached(&ser_u, &request.client_hello.sig_dilithium, &pqpk)
                                    } else { false };
                                    if !pq_ok {
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(
                                            channel,
                                            crate::rpc::seal_response(
                                                request.request_id,
                                                request.stream_id,
                                                client_u.clone(),
                                                server_ed_pk,
                                                pq_pk_arr,
                                                |m| id_keys.sign(m).unwrap_or_default(),
                                                |m| crate::crypto::pq_sign_detached(m, &pq_sk),
                                                |client_pk_bytes| { let pk = KyberPk::from_bytes(client_pk_bytes).expect("kyber pk"); crate::crypto::kyber_encapsulate(&pk) },
                                                node_ky_pk_bytes.clone(),
                                                crate::rpc::PINNED_SUITES,
                                                &peer_id.to_string(),
                                                &peer.to_string(),
                                                &crate::rpc::RpcResponsePayload::Error("bad dilithium".into())
                                            )
                                        );
                                        continue;
                                    }

                                    // Decrypt request using C2S AEAD, then build server response under S2C AEAD
                                    let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                    let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                                    pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                    // Use node Kyber secret (loaded at startup) for C2S decapsulation
                                    let kyber_ss = if let Ok(ct) = KyberCt::from_bytes(&request.client_kyber_ct) { crate::crypto::kyber_decapsulate(ct.as_bytes(), &node_ky_sk) } else { None };
                                    let payload = if let Some(ss) = kyber_ss {
                                        let c2s = crate::rpc::derive_c2s_master(&ss, &request.client_hello.unsigned, &server_ed_pk, &pq_pk_arr);
                                        let aad_extra = bincode::serialize(&request.client_hello.unsigned).unwrap_or_default();
                                        if let Some(pt) = crate::rpc::aead_decrypt_c2s(&c2s, &request.client_kyber_ct, request.request_id, &aad_extra, &request.method_enc) {
                                            if let Ok(method) = bincode::deserialize::<crate::rpc::RpcMethod>(&pt) {
                                                if !pq_authed.contains(&peer) {
                                                    match method {
                                                        crate::rpc::RpcMethod::AuthHello => {
                                                            // Treat a valid AuthHello RPC as completing PQ auth if gossip-based TOP_AUTH was missed.
                                                            // Persist the client's static keys for this session and mark authenticated.
                                                            let cu = &request.client_hello.unsigned;
                                                            let _ = pq_authed.insert(peer);
                                                            peer_keys.insert(peer, PeerStaticKeys {
                                                                kyber_pk: cu.client_kyber_pk.clone(),
                                                                ed25519_pk: cu.ed25519_pk.to_vec(),
                                                                dilithium_pk: cu.dilithium_pk,
                                                            });
                                                            net_log!("✅ PQ auth completed via RPC for peer: {}", peer);
                                                            // Respond OK with no payload; client pins keys from ServerHello
                                                            crate::rpc::RpcResponsePayload::Anchor(None)
                                                        }
                                                        _ => {
                                                            net_log!("⛔ RPC from unauthenticated peer ({}); responding 'unauthenticated'", peer);
                                                            crate::rpc::RpcResponsePayload::Error("unauthenticated".into())
                                                        }
                                                    }
                                                } else {
                                                    match method {
                                                        crate::rpc::RpcMethod::AuthHello => {
                                                            crate::rpc::RpcResponsePayload::Anchor(None)
                                                        }
                                                        crate::rpc::RpcMethod::LatestAnchor => {
                                                            net_log!("📨 RPC LatestAnchor from {}", peer);
                                                            let a = db.get::<Anchor>("epoch", b"latest").unwrap_or(None);
                                                            crate::rpc::RpcResponsePayload::Anchor(a)
                                                        }
                                                        crate::rpc::RpcMethod::Epoch(n) => {
                                                            let a = db.get::<Anchor>("epoch", &n.to_le_bytes()).unwrap_or(None);
                                                            crate::rpc::RpcResponsePayload::Anchor(a)
                                                        }
                                                        crate::rpc::RpcMethod::EpochSelectedIds(n) => {
                                                            let ids = db.get_selected_coin_ids_for_epoch(n).unwrap_or_default();
                                                            if ids.is_empty() { crate::rpc::RpcResponsePayload::EpochSelectedIds(None) } else { crate::rpc::RpcResponsePayload::EpochSelectedIds(Some(crate::rpc::EpochSelected{ epoch: n, ids })) }
                                                        }
                                                        crate::rpc::RpcMethod::EpochSummary(n) => {
                                                            let a_opt = db.get::<Anchor>("epoch", &n.to_le_bytes()).unwrap_or(None);
                                                            if let Some(a) = a_opt.clone() {
                                                                let ids = db.get_selected_coin_ids_for_epoch(n).unwrap_or_default();
                                                                // Collect coins for ids (best-effort; require all to exist)
                                                                let mut coins: Vec<Coin> = Vec::new();
                                                                for id in &ids {
                                                                    if let Ok(Some(c)) = db.get::<Coin>("coin", id) { coins.push(c); }
                                                                }
                                                                crate::rpc::RpcResponsePayload::EpochSummary(Some(crate::rpc::EpochSummary { anchor: a, selected_coin_ids: ids, coins }))
                                                            } else {
                                                                crate::rpc::RpcResponsePayload::EpochSummary(None)
                                                            }
                                                        }
                                                        crate::rpc::RpcMethod::CoinProof(id) => {
                                                            if let Ok(Some(coin)) = db.get::<Coin>("coin", &id) {
                                                                if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &coin.epoch_hash) {
                                                                    if let Ok(selected_ids) = db.get_selected_coin_ids_for_epoch(anchor.num) {
                                                                        let set: HashSet<[u8; 32]> = HashSet::from_iter(selected_ids.into_iter());
                                                                        if set.contains(&coin.id) {
                                                                            if let Some(proof) = crate::epoch::MerkleTree::build_proof(&set, &coin.id) {
                                                                                crate::rpc::RpcResponsePayload::CoinProof(Some((coin, anchor, proof)))
                                                                            } else { crate::rpc::RpcResponsePayload::CoinProof(None) }
                                                                        } else { crate::rpc::RpcResponsePayload::CoinProof(None) }
                                                                    } else { crate::rpc::RpcResponsePayload::CoinProof(None) }
                                                                } else { crate::rpc::RpcResponsePayload::CoinProof(None) }
                                                            } else { crate::rpc::RpcResponsePayload::CoinProof(None) }
                                                        }
                                                        crate::rpc::RpcMethod::Coin(id) => {
                                                            let c = db.get::<Coin>("coin", &id).unwrap_or(None);
                                                            crate::rpc::RpcResponsePayload::Coin(c)
                                                        }
                                                        crate::rpc::RpcMethod::CoinCandidate { epoch_hash, coin_id } => {
                                                            let composite = crate::storage::Store::candidate_key(&epoch_hash, &coin_id);
                                                            if let Ok(Some(c)) = db.get::<crate::coin::CoinCandidate>("coin_candidate", &composite) {
                                                                crate::rpc::RpcResponsePayload::CoinCandidate(Some(c))
                                                            } else { crate::rpc::RpcResponsePayload::CoinCandidate(None) }
                                                        }
                                                        crate::rpc::RpcMethod::TransferById(tx_id) => {
                                                            let t = db.get::<crate::transfer::Transfer>("transfer", &tx_id).unwrap_or(None);
                                                            crate::rpc::RpcResponsePayload::Transfer(t)
                                                        }
                                                    }
                                                }
                                            } else { crate::rpc::RpcResponsePayload::Error("bad method".into()) }
                                        } else { crate::rpc::RpcResponsePayload::Error("decrypt req".into()) }
                                    } else { crate::rpc::RpcResponsePayload::Error("kyber decap".into()) };
                                    let resp = crate::rpc::seal_response(
                                        request.request_id,
                                        request.stream_id,
                                        request.client_hello.unsigned.clone(),
                                        server_ed_pk,
                                        pq_pk_arr,
                                        |m| id_keys.sign(m).unwrap_or_default(),
                                        |m| crate::crypto::pq_sign_detached(m, &pq_sk),
                                        |client_pk_bytes| {
                                            let pk = KyberPk::from_bytes(client_pk_bytes).expect("kyber pk");
                                            crate::crypto::kyber_encapsulate(&pk)
                                        },
                                        node_ky_pk_bytes.clone(),
                                        crate::rpc::PINNED_SUITES,
                                        &peer_id.to_string(),
                                        &peer.to_string(),
                                        &payload,
                                    );
                                    let _ = swarm.behaviour_mut().rpc.send_response(channel, resp);
                                }
                                ReqRespMessage::Response { response, .. } => {
                                    // Do not remove the pending RPC until we verify and process the response
                                    if let Some(p) = pending_rpcs.get(&response.request_id).cloned() {
                                        // Verify server authenticity and binding before any decryption/use
                                        // 1) Ensure we have pinned keys for this peer
                                        let Some(keys) = peer_keys.get(&peer) else { continue; };
                                        let server_hello = &response.server_hello;
                                        let server_u = &server_hello.unsigned;
                                        // 2) Suites and expiry
                                        if server_u.suites != crate::rpc::PINNED_SUITES { continue; }
                                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                        if server_u.expiry_unix_secs < now { continue; }
                                        // 3) Peer-ID binding
                                        if server_u.local_peer_id != peer.to_string() { continue; }
                                        if server_u.remote_peer_id != peer_id.to_string() { continue; }
                                        // 4) Kyber ciphertext integrity: outer equals inner
                                        if response.kyber_ct != server_u.kyber_ct { continue; }
                                        // 5) Bind ServerHello to pinned static keys learned during TOP_AUTH
                                        //    ed25519 and dilithium must match exactly
                                        let mut pinned_ed = [0u8;32];
                                        if keys.ed25519_pk.len() != 32 { continue; }
                                        pinned_ed.copy_from_slice(&keys.ed25519_pk);
                                        if server_u.ed25519_pk != pinned_ed { continue; }
                                        if server_u.dilithium_pk != keys.dilithium_pk { continue; }
                                        //    Kyber server static pk must also match pinned
                                        if server_u.server_kyber_pk != keys.kyber_pk { continue; }
                                        // 6) Verify signatures over ServerHelloUnsigned using pinned keys
                                        let ser_u = match bincode::serialize(server_u) { Ok(v)=>v, Err(_)=>{ continue; } };
                                        // ed25519
                                        let ed_ok = if server_hello.sig_ed25519.len() == 64 {
                                            if let Ok(edpk) = ed25519_dalek::PublicKey::from_bytes(&pinned_ed) {
                                                if let Ok(sig) = ed25519_dalek::Signature::from_bytes(&server_hello.sig_ed25519) {
                                                    edpk.verify(&ser_u, &sig).is_ok()
                                                } else { false }
                                            } else { false }
                                        } else { false };
                                         if !ed_ok { continue; }
                                        // dilithium
                                        let pq_ok = if let Ok(pqpk) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&keys.dilithium_pk) {
                                            crate::crypto::pq_verify_detached(&ser_u, &server_hello.sig_dilithium, &pqpk)
                                        } else { false };
                                         if !pq_ok { continue; }

                                        // Passed authenticity checks → proceed to decapsulation and payload open
                                        if let Ok(ct) = KyberCt::from_bytes(&response.kyber_ct) {
                                            let ss = crate::crypto::kyber_decapsulate(ct.as_bytes(), &p.client_sk);
                                            if let Some(ssb) = ss {
                                                if let Some(payload) = crate::rpc::open_response(&response, &p.client_u, &response.server_hello.unsigned, &ssb) {
                                                    match payload {
                                                        crate::rpc::RpcResponsePayload::Anchor(Some(a)) => {
                                                            // Reflect network progress for the sync loop
                                                            {
                                                                let mut st = _sync_state.lock().unwrap();
                                                                if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                            }
                                                            // Request full epoch summary to persist and validate
                                                            let _ = command_tx.send(NetworkCommand::RequestEpochSummary(a.num));
                                                        }
                                                        crate::rpc::RpcResponsePayload::EpochSummary(Some(summary)) => {
                                                            // Reflect network progress for the sync loop
                                                            {
                                                                let mut st = _sync_state.lock().unwrap();
                                                                if summary.anchor.num > st.highest_seen_epoch { st.highest_seen_epoch = summary.anchor.num; }
                                                            }
                                                            // Validate before persistence/broadcast
                                                            let prev = if summary.anchor.num > 0 { db.get::<Anchor>("epoch", &(summary.anchor.num-1).to_le_bytes()).unwrap_or(None) } else { None };
                                                            // Validate; use provided coins and ids
                                                            let ids: Vec<[u8;32]> = summary.selected_coin_ids.clone();
                                                            match crate::epoch::validate_anchor(&db, &epoch_cfg, &mining_cfg, &summary.anchor, prev.as_ref(), &ids, &summary.coins) {
                                                                Ok(()) => {
                                                                    // Persist: anchor
                                                                    let _ = db.put("epoch", &summary.anchor.num.to_le_bytes(), &summary.anchor);
                                                                    let _ = db.put("anchor", &summary.anchor.hash, &summary.anchor);
                                                                    let _ = db.put("epoch", b"latest", &summary.anchor);
                                                                    // Persist: selected ids index
                                                                    if let Some(sel_cf) = db.db.cf_handle("epoch_selected") {
                                                                        let mut batch = rocksdb::WriteBatch::default();
                                                                        for coin in &summary.selected_coin_ids {
                                                                            let mut key = Vec::with_capacity(8+32);
                                                                            key.extend_from_slice(&summary.anchor.num.to_le_bytes());
                                                                            key.extend_from_slice(coin);
                                                                            batch.put_cf(sel_cf, &key, &[]);
                                                                        }
                                                                        let _ = db.write_batch(batch);
                                                                    }
                                                                    // Persist: coins (confirmed)
                                                                    if let Some(coin_cf) = db.db.cf_handle("coin") {
                                                                        let mut batch = rocksdb::WriteBatch::default();
                                                                        for coin in &summary.coins {
                                                                            if let Ok(bytes) = bincode::serialize(coin) {
                                                                                batch.put_cf(coin_cf, &coin.id, &bytes);
                                                                            }
                                                                        }
                                                                        let _ = db.write_batch(batch);
                                                                    }
                                                                    let _ = anchor_tx.send(summary.anchor);
                                                                }
                                                                Err(e) => {
                                                                    eprintln!("❌ Invalid anchor summary: {}", e);
                                                                    crate::metrics::VALIDATION_FAIL_ANCHOR.inc();
                                                                }
                                                            }
                                                        }
                                                        crate::rpc::RpcResponsePayload::EpochSelectedIds(Some(sel)) => {
                                                            // Reflect network progress for the sync loop
                                                            {
                                                                let mut st = _sync_state.lock().unwrap();
                                                                if sel.epoch > st.highest_seen_epoch { st.highest_seen_epoch = sel.epoch; }
                                                            }
                                                            // Probabilistic verification path: fetch anchor and sample coin proofs
                                                            let epoch_num = sel.epoch;
                                                            // Request anchor body first
                                                            let _ = command_tx.send(NetworkCommand::RequestEpoch(epoch_num));
                                                            // Spawn a short-lived task to perform sampling once anchor is available locally
                                                            let db_clone = db.clone();
                                                            let anchor_tx_clone = anchor_tx.clone();
                                                            tokio::spawn(async move {
                                                                // Wait briefly for anchor persistence
                                                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                                                if let Ok(Some(anchor)) = db_clone.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                                                    // Recompute merkle root from ids and check vs anchor
                                                                    let set: std::collections::HashSet<[u8;32]> = std::collections::HashSet::from_iter(sel.ids.iter().cloned());
                                                                    let mr = crate::epoch::MerkleTree::build_root(&set);
                                                                    if mr != anchor.merkle_root { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                    // Reconstruct work_root deterministically from ids and locally recomputed work for sampled coins only is not sufficient to validate work_root; we require full set to recompute.
                                                                    // For probabilistic mode, verify sampled work leaves via Merkle proofs against anchor.work_root.
                                                                    // Sample size to detect 1% cheating with 99.9% certainty ≈ 690 samples
                                                                    let sample_n: usize = 690.min(sel.ids.len());
                                                                    // Deterministic sampling: use anchor.hash as RNG seed
                                                                    use rand::{SeedableRng, Rng};
                                                                    let mut seed = [0u8;32]; seed.copy_from_slice(&anchor.hash);
                                                                    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
                                                                    let mut ok_count = 0usize;
                                                                    for _ in 0..sample_n {
                                                                        let idx = rng.gen_range(0..sel.ids.len());
                                                                        let cid = sel.ids[idx];
                                                                        // Try local cache first, then fetch coin and proof over RPC on miss
                                                                        if let Ok(Some(coin)) = db_clone.get::<Coin>("coin", &cid) {
                                                                            let leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
                                                                            if let Ok(ids2) = db_clone.get_selected_coin_ids_for_epoch(anchor.num) {
                                                                                let set2 = std::collections::HashSet::from_iter(ids2.into_iter());
                                                                                if let Some(proof) = crate::epoch::MerkleTree::build_proof(&set2, &coin.id) {
                                                                                    if crate::epoch::MerkleTree::verify_proof(&leaf, &proof, &anchor.merkle_root) { ok_count += 1; } else { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                                } else { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                            } else { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                            // Verify work leaf against anchor.work_root
                                                                            let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
                                                                            if let Ok(pow) = crate::crypto::argon2id_pow(&header, &anchor.hash, anchor.mem_kib, 1) {
                                                                                let w = crate::crypto::work_from_pow_hash(&pow);
                                                                                let mut wbytes = [0u8;32]; w.to_big_endian(&mut wbytes);
                                                                                let mut h = blake3::Hasher::new(); h.update(b"workleaf"); h.update(&coin.id); h.update(&wbytes);
                                                                                let work_leaf = *h.finalize().as_bytes();
                                                                                // Build work proof from stored sorted leaves for this epoch (if present)
                                                                                if let Ok(Some(work_leaves)) = db_clone.get_epoch_work_leaves(anchor.num) {
                                                                                    // Rebuild proof locally
                                                                                    let mut level = work_leaves.clone();
                                                                                    // Find position of our leaf hash
                                                                                    if let Some(mut index) = level.iter().position(|x| x == &work_leaf) {
                                                                                        let mut proof_vec: Vec<([u8;32], bool)> = Vec::new();
                                                                                        while level.len() > 1 {
                                                                                            let (sib, sib_left) = if index % 2 == 0 {
                                                                                                (*level.get(index + 1).unwrap_or(&level[index]), false)
                                                                                            } else { (level[index - 1], true) };
                                                                                            proof_vec.push((sib, sib_left));
                                                                                            let mut next: Vec<[u8;32]> = Vec::with_capacity((level.len()+1)/2);
                                                                                            for chunk in level.chunks(2) {
                                                                                                let mut hh = blake3::Hasher::new();
                                                                                                hh.update(b"worknode");
                                                                                                hh.update(&chunk[0]);
                                                                                                hh.update(chunk.get(1).unwrap_or(&chunk[0]));
                                                                                                next.push(*hh.finalize().as_bytes());
                                                                                            }
                                                                                            index /= 2;
                                                                                            level = next;
                                                                                        }
                                                                                        // Verify proof result equals anchor.work_root
                                                                                        let mut comp = work_leaf;
                                                                                        for (sib, sib_left) in &proof_vec {
                                                                                            let mut hh = blake3::Hasher::new(); hh.update(b"worknode");
                                                                                            if *sib_left { hh.update(sib); hh.update(&comp); } else { hh.update(&comp); hh.update(sib); }
                                                                                            comp = *hh.finalize().as_bytes();
                                                                                        }
                                                                                        if comp != anchor.work_root { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                                    } else { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                                } else {
                                                                                    // If work leaves not available, proactively fetch EpochSummary and rebuild cache
                                                                                    if let Ok(Some(a2)) = db_clone.get::<Anchor>("epoch", &anchor.num.to_le_bytes()) {
                                                                                        // Request full summary via network command to hydrate cache
                                                                                        let _ = anchor_tx_clone.send(a2.clone());
                                                                                    }
                                                                                    // Skip counting this sample now; retry next
                                                                                    continue;
                                                                                }
                                                                            } else { crate::metrics::VALIDATION_FAIL_ANCHOR.inc(); return; }
                                                                        } else {
                                                                            // Fetch coin proof over RPC and verify
                                                                            // Enqueue a proof request; the RPC response path will push into proof_tx
                                                                            // This async branch waits briefly for a response and verifies
                                                                            // Note: best-effort — do not fail the entire sampling if a single fetch misses
                                                                            let _ = anchor_tx_clone.send(anchor.clone());
                                                                            // Skip this sample until coin is hydrated
                                                                            continue;
                                                                        }
                                                                    }
                                                                    if ok_count == sample_n {
                                                                        // Passed probabilistic verification → accept anchor
                                                                        let _ = anchor_tx_clone.send(anchor);
                                                                    }
                                                                }
                                                            });
                                                        }
                                                        crate::rpc::RpcResponsePayload::EpochSelectedIds(None) => {
                                                            // No selection set materialized on server for this epoch; request full summary instead
                                                            if let crate::rpc::RpcMethod::EpochSelectedIds(epoch_num) = p.requested_method {
                                                                let _ = command_tx.send(NetworkCommand::RequestEpochSummary(epoch_num));
                                                            }
                                                        }
                                                        crate::rpc::RpcResponsePayload::CoinProof(Some((coin, anchor, proof))) => {
                                                            let resp = CoinProofResponse { coin, anchor, proof };
                                                            let _ = proof_tx.send(resp);
                                                        }
                                                        crate::rpc::RpcResponsePayload::Error(err) => {
                                                            // If the server rejected due to unauthenticated (race: server hasn't seen our TOP_AUTH yet), retry the original method.
                                                            if err == "unauthenticated" {
                                                                if let crate::rpc::RpcMethod::LatestAnchor = p.requested_method {
                                                                    net_log!("⏳ LatestAnchor RPC unauthenticated by {}; waiting for server-side PQ auth", peer);
                                                                }
                                                                match p.requested_method {
                                                                    crate::rpc::RpcMethod::AuthHello => { let _ = command_tx.send(NetworkCommand::RequestLatestEpoch); },
                                                                    crate::rpc::RpcMethod::LatestAnchor => { let _ = command_tx.send(NetworkCommand::RequestLatestEpoch); },
                                                                    crate::rpc::RpcMethod::Epoch(n) => { let _ = command_tx.send(NetworkCommand::RequestEpoch(n)); },
                                                                    crate::rpc::RpcMethod::EpochSelectedIds(n) => { let _ = command_tx.send(NetworkCommand::RequestEpoch(n)); },
                                                                    crate::rpc::RpcMethod::EpochSummary(n) => { let _ = command_tx.send(NetworkCommand::RequestEpochSummary(n)); },
                                                                    crate::rpc::RpcMethod::Coin(id) => { let _ = command_tx.send(NetworkCommand::RequestCoin(id)); },
                                                                    crate::rpc::RpcMethod::CoinProof(id) => { let _ = command_tx.send(NetworkCommand::RequestCoinProof(id)); },
                                                                    crate::rpc::RpcMethod::CoinCandidate { .. } => { /* not issued via NetworkCommand in this path */ }
                                                                    crate::rpc::RpcMethod::TransferById(_)=> { /* not issued here */ }
                                                                }
                                                            } else {
                                                                eprintln!("RPC error payload from {}: {}", peer, err);
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                        // Response processed; remove pending entry now
                                        let _ = pending_rpcs.remove(&response.request_id);
                                    }
                                }
                            }
                        },
                        // Log identify results for interoperability debugging
                        SwarmEvent::Behaviour(BehaviourEvent::Identify(ev)) => {
                            match ev {
                                identify::Event::Received { peer_id, info, .. } => {
                                    net_log!("🪪 Identify from {}: agent={} proto={:?}", peer_id, info.agent_version, info.protocol_version);
                                    net_log!("🧩 Supported protocols ({}): {:?}", info.protocols.len(), info.protocols);
                                    identified_peers.insert(peer_id);
                                    // Trigger initial sync request now that Identify succeeded
                                    let _ = command_tx.send(NetworkCommand::RequestLatestEpoch);
                                }
                                identify::Event::Sent { peer_id, .. } => {
                                    net_log!("🪪 Identify sent to {}", peer_id);
                                }
                                _ => {}
                            }
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Ping(ev)) => {
                            match ev.result {
                                Ok(rtt) => net_log!("🏓 Ping RTT: {:?}", rtt),
                                Err(e) => net_log!("🏓 Ping error: {:?}", e),
                            }
                        },
                        _ => {}
                    }
                },
                Some(command) = command_rx.recv() => {
                    // Helper to send an RPC request via PQ AEAD with C2S request encryption
                    let mut send_rpc = |swarm_mut: &mut libp2p::Swarm<Behaviour>, method: crate::rpc::RpcMethod| {
                        // Prefer a connected peer that has completed PQ auth (i.e., keys are pinned)
                        if let Some(peer) = connected_peers.iter().find(|p| peer_keys.contains_key(*p)).cloned() {
                            // Require peer static keys from PQ auth
                            let Some(keys) = peer_keys.get(&peer) else {
                                // Requeue until we have peer keys
                                if pending_commands.len() >= MAX_PENDING_COMMANDS { let _ = pending_commands.pop_front(); crate::metrics::PENDING_CMD_DROPS.inc(); }
                                pending_commands.push_back(command.clone());
                                crate::metrics::PENDING_CMD_QUEUE_LEN.set(pending_commands.len() as i64);
                                return;
                            };
                            let ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                            let mut dilithium_pk = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                            dilithium_pk.copy_from_slice(pq_pk.as_bytes());
                            let (client_pk, client_sk) = crate::crypto::kyber_keypair_generate();
                            let client_kyber_pk = client_pk.as_bytes().to_vec();
                            let unsigned = crate::rpc::ClientHelloUnsigned {
                                handshake_version: 1,
                                suites: crate::rpc::PINNED_SUITES.to_string(),
                                local_peer_id: peer_id.to_string(),
                                remote_peer_id: peer.to_string(),
                                ed25519_pk: ed_pk,
                                dilithium_pk,
                                expiry_unix_secs: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()) + 3600,
                                client_kyber_pk,
                                nonce: {
                                    let mut n = [0u8;32];
                                    use rand::RngCore; rand::rngs::OsRng.fill_bytes(&mut n);
                                    n
                                },
                            };
                            let ser_u = bincode::serialize(&unsigned).unwrap_or_default();
                            let sig_ed25519 = id_keys.sign(&ser_u).unwrap_or_default();
                            let sig_dilithium = crate::crypto::pq_sign_detached(&ser_u, &pq_sk);
                            let client_hello = crate::rpc::ClientHello { unsigned: unsigned.clone(), sig_ed25519, sig_dilithium };
                            // Monotonic request IDs per stream to harden nonce scheduling
                            static REQ_COUNTER: once_cell::sync::Lazy<std::sync::atomic::AtomicU64> = once_cell::sync::Lazy::new(|| std::sync::atomic::AtomicU64::new(1));
                            let request_id = REQ_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let stream_id = 1; // single logical stream per peer for now
                            // Encrypt method using client-side Kyber encapsulation to server static node key from auth
                            let Ok(server_ky_pk) = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&keys.kyber_pk) else {
                                // Requeue if server kyber pk invalid
                                if pending_commands.len() >= MAX_PENDING_COMMANDS { let _ = pending_commands.pop_front(); crate::metrics::PENDING_CMD_DROPS.inc(); }
                                pending_commands.push_back(command.clone());
                                crate::metrics::PENDING_CMD_QUEUE_LEN.set(pending_commands.len() as i64);
                                return;
                            };
                            let (client_ct, client_ss) = crate::crypto::kyber_encapsulate(&server_ky_pk);
                            let aad_extra = bincode::serialize(&unsigned).unwrap_or_default();
                            let method_pt = bincode::serialize(&method).unwrap_or_default();
                            // Derive C2S using server's static keys from auth
                            let mut server_ed = [0u8;32];
                            if keys.ed25519_pk.len() == 32 { server_ed.copy_from_slice(&keys.ed25519_pk); }
                            let c2s = crate::rpc::derive_c2s_master(&client_ss, &unsigned, &server_ed, &keys.dilithium_pk);
                            let method_enc = crate::rpc::aead_encrypt_c2s(&c2s, &client_ct, request_id, &aad_extra, &method_pt);
                            let req = crate::rpc::RpcRequest { request_id, stream_id, client_hello, client_kyber_ct: client_ct, method_enc };
                            pending_rpcs.insert(request_id, PendingRpc { client_sk, client_u: unsigned, requested_method: method.clone() });
                            let _ = swarm_mut.behaviour_mut().rpc.send_request(&peer, req);
                        } else {
                            if pending_commands.len() >= MAX_PENDING_COMMANDS {
                                let _ = pending_commands.pop_front();
                                crate::metrics::PENDING_CMD_DROPS.inc();
                            }
                            pending_commands.push_back(command.clone());
                            crate::metrics::PENDING_CMD_QUEUE_LEN.set(pending_commands.len() as i64);
                        }
                    };
                    match &command {
                        NetworkCommand::GossipAnchor(a) => {
                            let ann = AnchorAnnounce { num: a.num, hash: a.hash };
                            if let Ok(d) = bincode::serialize(&ann) { let _ = swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_ANCHOR), d); }
                            crate::metrics::MSGS_OUT_ANCHOR.inc();
                        }
                        NetworkCommand::GossipCoin(c) => {
                            let ann = CoinAnnounce { epoch_hash: c.epoch_hash, coin_id: c.id };
                            if let Ok(d) = bincode::serialize(&ann) { let _ = swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_COIN), d); }
                            crate::metrics::MSGS_OUT_COIN.inc();
                        }
                        NetworkCommand::GossipTransfer(tx) => {
                            let ann = TransferAnnounce { tx_id: tx.hash() };
                            if let Ok(d) = bincode::serialize(&ann) { let _ = swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_TX), d); }
                            crate::metrics::MSGS_OUT_TX.inc();
                        }
                        NetworkCommand::RequestAuthHello => send_rpc(&mut swarm, crate::rpc::RpcMethod::AuthHello),
                        NetworkCommand::RequestLatestEpoch => {
                            // Best-effort gossip marker for observability (not used for payload)
                            if let Ok(d) = bincode::serialize(&()) { let _ = swarm.behaviour_mut().gs.publish(IdentTopic::new(TOP_LATEST_REQUEST), d); }
                            crate::metrics::MSGS_OUT_LATEST_REQ.inc();
                            send_rpc(&mut swarm, crate::rpc::RpcMethod::LatestAnchor)
                        },
                        NetworkCommand::RequestEpoch(n) => send_rpc(&mut swarm, crate::rpc::RpcMethod::Epoch(*n)),
                        NetworkCommand::RequestEpochSummary(n) => send_rpc(&mut swarm, crate::rpc::RpcMethod::EpochSummary(*n)),
                        NetworkCommand::RequestCoin(id) => send_rpc(&mut swarm, crate::rpc::RpcMethod::Coin(*id)),
                        NetworkCommand::RequestCoinProof(id) => send_rpc(&mut swarm, crate::rpc::RpcMethod::CoinProof(*id)),
                    }
                },
                _ = shutdown_rx.recv() => {
                    net_log!("🛑 Network received shutdown signal");
                    break;
                }
            }
        }
        net_log!("✅ Network shutdown complete");
    });
    Ok(net)
}

impl Network {
    pub async fn gossip_anchor(&self, a: &Anchor) { let _ = self.command_tx.send(NetworkCommand::GossipAnchor(a.clone())); }
    pub async fn gossip_coin(&self, c: &CoinCandidate) { let _ = self.command_tx.send(NetworkCommand::GossipCoin(c.clone())); }
    pub async fn gossip_transfer(&self, tx: &Transfer) { let _ = self.command_tx.send(NetworkCommand::GossipTransfer(tx.clone())); }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> { self.anchor_tx.subscribe() }
    pub fn proof_subscribe(&self) -> broadcast::Receiver<CoinProofResponse> { self.proof_tx.subscribe() }
    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> { self.anchor_tx.clone() }
    pub fn coin_id_subscribe(&self) -> broadcast::Receiver<[u8; 32]> { self.coin_id_tx.subscribe() }
    pub fn coin_id_sender(&self) -> broadcast::Sender<[u8; 32]> { self.coin_id_tx.clone() }
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    pub async fn request_coin(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoin(id)); }
    pub async fn request_latest_epoch(&self) { let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch); }
    pub async fn request_coin_proof(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoinProof(id)); }
    
    /// Gets the current number of connected peers
    pub fn peer_count(&self) -> usize {
        CONNECTED_PEER_COUNT.load(Ordering::Relaxed)
    }
}
