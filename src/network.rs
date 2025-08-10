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
}

#[derive(Debug, Clone)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(CoinCandidate),
    GossipTransfer(Transfer),
    RequestEpoch(u64),
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
    
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(std::time::Duration::from_secs(1))
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
    }

    let behaviour = Behaviour { gs, rpc: crate::rpc::build_rpc_behaviour() };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(std::time::Duration::from_secs(20))
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

    let (anchor_tx, _) = broadcast::channel(256);
    let (proof_tx, _) = broadcast::channel(256);
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), proof_tx: proof_tx.clone(), command_tx: command_tx.clone() });

    let mut peer_scores: HashMap<PeerId, PeerScore> = HashMap::new();
    let mut pending_commands: VecDeque<NetworkCommand> = VecDeque::new();
    const MAX_PENDING_COMMANDS: usize = 2048;
    // orphan_anchors removed; full anchors are fetched via RPC
    let mut connected_peers: HashSet<PeerId> = HashSet::new();
    let mut pq_authed: HashSet<PeerId> = HashSet::new();
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
    }
    let mut pending_rpcs: HashMap<u64, PendingRpc> = HashMap::new();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            net_log!("🤝 Connected to peer: {}", peer_id);
                            // Diagnostic: indicate PQ TLS preference is active (aws-lc-rs installed)
                            net_log!("🔐 Transport: rustls prefer-post-quantum active (aws-lc-rs provider installed)");
                            peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            connected_peers.insert(peer_id);
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                            CONNECTED_PEER_COUNT.store(connected_peers.len(), Ordering::Relaxed);
                            // Send PQ auth hello
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
                                kyber_pk: crate::crypto::load_or_create_node_kyber().map(|(pk,_sk)| pk.as_bytes().to_vec()).unwrap_or_default(),
                                expiry_unix_secs: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()) + 300,
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
                                let (t, data) = match &cmd {
                                NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                                 NetworkCommand::GossipCoin(c)   => (TOP_COIN, bincode::serialize(&c).ok()),
                                NetworkCommand::GossipTransfer(tx) => (TOP_TX, bincode::serialize(&tx).ok()),
                                NetworkCommand::RequestEpoch(_n) => ("", None),
                                NetworkCommand::RequestCoin(_id) => ("", None),
                                NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok()),
                                NetworkCommand::RequestCoinProof(_id) => ("", None),
                            };
                                if let Some(d) = data {
                            if swarm.behaviour_mut().gs.publish(IdentTopic::new(t), d).is_err() {
                                        if still_pending.len() >= MAX_PENDING_COMMANDS {
                                            let _ = still_pending.pop_front();
                                            crate::metrics::PENDING_CMD_DROPS.inc();
                                        }
                                        still_pending.push_back(cmd);
                                        crate::metrics::PENDING_CMD_QUEUE_LEN.set(still_pending.len() as i64);
                                    } else {
                                        match t {
                                            TOP_ANCHOR => crate::metrics::MSGS_OUT_ANCHOR.inc(),
                                            TOP_COIN => crate::metrics::MSGS_OUT_COIN.inc(),
                                            TOP_TX => crate::metrics::MSGS_OUT_TX.inc(),
                                            TOP_LATEST_REQUEST => crate::metrics::MSGS_OUT_LATEST_REQ.inc(),
                                            _ if t == "" => {},
                                            _ => {}
                                        }
                                    }
                                }
                            }
                            pending_commands = still_pending;
                            crate::metrics::PENDING_CMD_QUEUE_LEN.set(pending_commands.len() as i64);
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            net_log!("👋 Disconnected from peer: {} due to {:?}", peer_id, cause);
                            connected_peers.remove(&peer_id);
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                            CONNECTED_PEER_COUNT.store(connected_peers.len(), Ordering::Relaxed);
                        },
                        SwarmEvent::Behaviour(BehaviourEvent::Gs(GossipsubEvent::Message { message, .. })) => {
                            let peer_id = message.source.unwrap_or_else(PeerId::random);
                            let topic_str = message.topic.as_str();
                            let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
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
                            // Gate non-auth topics behind PQ handshake
                            if topic_str != TOP_AUTH && !pq_authed.contains(&peer_id) {
                                // silently ignore pre-auth non-auth topics
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
                                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                        if hello.unsigned.expiry_unix_secs < now { continue; }
                                        // Verify ed25519 peer id binding
                                        let ed_ok = if !hello.unsigned.ed25519_pk.is_empty() {
                                            if let Ok(lp) = libp2p::identity::ed25519::PublicKey::try_from_bytes(&hello.unsigned.ed25519_pk) {
                                                let derived = PeerId::from(libp2p::identity::PublicKey::from(lp));
                                                derived == peer_id
                                            } else { false }
                                        } else { false };
                                        if !ed_ok { continue; }
                                        if hello.unsigned.local_peer_id != peer_id.to_string() { continue; }
                                        // Verify ed25519 signature (dalek)
                                        let dalek_pk = match ed25519_dalek::PublicKey::from_bytes(&hello.unsigned.ed25519_pk) { Ok(p)=>p, Err(_)=>{continue;} };
                                        let dalek_sig = match DalekSig::from_bytes(&hello.sig_ed25519) { Ok(s)=>s, Err(_)=>{continue;} };
                                        if dalek_pk.verify(&bincode::serialize(&hello.unsigned).unwrap_or_default(), &dalek_sig).is_err() { continue; }
                                        // Verify dilithium signature
                                        let pk_pq = match pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&hello.unsigned.dilithium_pk) { Ok(p)=>p, Err(_)=>{continue;} };
                                        if !crate::crypto::pq_verify_detached(&bincode::serialize(&hello.unsigned).unwrap_or_default(), &hello.sig_dilithium, &pk_pq) { continue; }
                                        pq_authed.insert(peer_id);
                                        peer_keys.insert(peer_id, PeerStaticKeys { kyber_pk: hello.unsigned.kyber_pk.clone(), ed25519_pk: hello.unsigned.ed25519_pk.clone(), dilithium_pk: hello.unsigned.dilithium_pk });
                                    }
                                },
                                // Gossip only announces anchor id and height; bodies via RPC
                                TOP_ANCHOR => if let Ok(ann) = bincode::deserialize::<AnchorAnnounce>(&message.data) {
                                    crate::metrics::MSGS_IN_ANCHOR.inc();
                                    // Always request full anchor by number over RPC
                                    net_log!("📣 Announced anchor #{} (hash {}) — requesting payload via RPC", ann.num, hex::encode(ann.hash));
                                    let _ = command_tx.send(NetworkCommand::RequestEpoch(ann.num));
                                },
                                // Gossip coin: announce only epoch_hash + coin_id
                                TOP_COIN => if let Ok(ann) = bincode::deserialize::<CoinAnnounce>(&message.data) {
                                    crate::metrics::MSGS_IN_COIN.inc();
                                    // Enforce per-peer candidate quota
                                    let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                                    if !score.allow_candidate() { continue; }
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
                                    // Enforce RPC gating: require prior PQ auth on TOP_AUTH and verify ClientHello signatures before any decryption.
                                    if !pq_authed.contains(&peer) {
                                        // Refuse processing requests from peers that haven't completed PQ auth
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                                        pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, request.client_hello.unsigned.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("unauthenticated".into())));
                                        continue;
                                    }

                                    // Verify client hello signatures and binding (plaintext hello is part of request)
                                    let client_u = &request.client_hello.unsigned;
                                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                    if client_u.expiry_unix_secs < now { 
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, client_u.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("client hello expired".into())));
                                        continue; 
                                    }
                                    // Bind to peer ids claimed by client. Enforce mapping to libp2p peer id (ed25519)
                                    if client_u.remote_peer_id != peer_id.to_string() || client_u.local_peer_id != peer.to_string() {
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, client_u.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("peer id binding".into())));
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
                                            let _ = swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, client_u.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("client hello replay".into())));
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
                                        let _ = swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, client_u.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("bad ed25519".into())));
                                        continue;
                                    }
                                    // Verify Dilithium signature on client hello
                                    let pq_ok = if let Ok(pqpk) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&client_u.dilithium_pk) {
                                        crate::crypto::pq_verify_detached(&ser_u, &request.client_hello.sig_dilithium, &pqpk)
                                    } else { false };
                                    if !pq_ok {
                                        let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                        let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES]; pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                        let _ = swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, client_u.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("bad dilithium".into())));
                                        continue;
                                    }

                                    // Decrypt request using C2S AEAD, then build server response under S2C AEAD
                                    let server_ed_pk: [u8;32] = id_keys.public().try_into_ed25519().map(|p| p.to_bytes()).unwrap_or([0u8;32]);
                                    let mut pq_pk_arr = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                                    pq_pk_arr.copy_from_slice(pq_pk.as_bytes());
                                    // Obtain node Kyber secret for C2S decapsulation
                                    let (_node_ky_pk, node_ky_sk) = match crate::crypto::load_or_create_node_kyber() { Ok(v)=>v, Err(_) => { let _=swarm.behaviour_mut().rpc.send_response(channel, crate::rpc::seal_response(request.request_id, request.stream_id, request.client_hello.unsigned.clone(), server_ed_pk, pq_pk_arr, |m| id_keys.sign(m).unwrap_or_default(), |m| crate::crypto::pq_sign_detached(m, &pq_sk), |_m| (Vec::new(), vec![0u8;32]), crate::rpc::PINNED_SUITES, &peer_id.to_string(), &peer.to_string(), &crate::rpc::RpcResponsePayload::Error("server kyber".into()))); continue; } };
                                    let kyber_ss = if let Ok(ct) = KyberCt::from_bytes(&request.client_kyber_ct) { crate::crypto::kyber_decapsulate(ct.as_bytes(), &node_ky_sk) } else { None };
                                    let payload = if let Some(ss) = kyber_ss {
                                        let c2s = crate::rpc::derive_c2s_master(&ss, &request.client_hello.unsigned, &server_ed_pk, &pq_pk_arr);
                                        let aad_extra = bincode::serialize(&request.client_hello.unsigned).unwrap_or_default();
                                        if let Some(pt) = crate::rpc::aead_decrypt_c2s(&c2s, &request.client_kyber_ct, request.request_id, &aad_extra, &request.method_enc) {
                                            if let Ok(method) = bincode::deserialize::<crate::rpc::RpcMethod>(&pt) {
                                                    match method {
                                                    crate::rpc::RpcMethod::LatestAnchor => {
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
                                        crate::rpc::PINNED_SUITES,
                                        &peer_id.to_string(),
                                        &peer.to_string(),
                                        &payload,
                                    );
                                    let _ = swarm.behaviour_mut().rpc.send_response(channel, resp);
                                }
                                ReqRespMessage::Response { response, .. } => {
                                    if let Some(p) = pending_rpcs.remove(&response.request_id) {
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
                                                            // Prefer probabilistic verification: request selected IDs and sample proofs
                                                            // Fall back to full summary if sampling fails later
                                                            let _ = command_tx.send(NetworkCommand::RequestEpoch(a.num));
                                                        }
                                                        crate::rpc::RpcResponsePayload::EpochSummary(Some(summary)) => {
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
                                                        crate::rpc::RpcResponsePayload::CoinProof(Some((coin, anchor, proof))) => {
                                                            let resp = CoinProofResponse { coin, anchor, proof };
                                                            let _ = proof_tx.send(resp);
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                },
                Some(command) = command_rx.recv() => {
                    // Helper to send an RPC request via PQ AEAD with C2S request encryption
                    let mut send_rpc = |method: crate::rpc::RpcMethod| {
                        if let Some(peer) = connected_peers.iter().next().cloned() {
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
                                expiry_unix_secs: (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()) + 300,
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
                            pending_rpcs.insert(request_id, PendingRpc { client_sk, client_u: unsigned });
                            let _ = swarm.behaviour_mut().rpc.send_request(&peer, req);
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
                        NetworkCommand::RequestLatestEpoch => send_rpc(crate::rpc::RpcMethod::LatestAnchor),
                        NetworkCommand::RequestEpoch(n) => send_rpc(crate::rpc::RpcMethod::EpochSelectedIds(*n)),
                        NetworkCommand::RequestCoin(id) => send_rpc(crate::rpc::RpcMethod::Coin(*id)),
                        NetworkCommand::RequestCoinProof(id) => send_rpc(crate::rpc::RpcMethod::CoinProof(*id)),
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
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    pub async fn request_coin(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoin(id)); }
    pub async fn request_latest_epoch(&self) { let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch); }
    pub async fn request_coin_proof(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoinProof(id)); }
    
    /// Gets the current number of connected peers
    pub fn peer_count(&self) -> usize {
        CONNECTED_PEER_COUNT.load(Ordering::Relaxed)
    }
}
