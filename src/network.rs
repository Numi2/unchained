use crate::{
    storage::Store, epoch::Anchor, coin::{Coin, CoinCandidate}, transfer::Transfer, crypto, config, sync::SyncState,
};
use std::sync::{Arc, Mutex};
use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature as _};
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
use tokio::sync::{broadcast, mpsc};
use hex;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use serde::{Serialize, Deserialize};
use once_cell::sync::Lazy;

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

#[allow(dead_code)]
fn try_publish_gossip(
    swarm: &mut Swarm<Gossipsub<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &str,
    data: Vec<u8>,
    context: &str,
) {
    if let Err(e) = swarm.behaviour_mut().publish(IdentTopic::new(topic), data) {
        if !matches!(e, libp2p::gossipsub::PublishError::InsufficientPeers) {
            eprintln!("⚠️  Failed to publish {} ({}): {}", context, topic, e);
        }
    }
}

const TOP_ANCHOR: &str = "unchained/anchor/v1";
const TOP_COIN: &str = "unchained/coin/v1";
const TOP_COIN_PROOF_REQUEST: &str = "unchained/coin_proof_request/v1";
const TOP_COIN_PROOF_RESPONSE: &str = "unchained/coin_proof_response/v1";
const TOP_TX: &str = "unchained/tx/v1";
const TOP_EPOCH_REQUEST: &str = "unchained/epoch_request/v1";
const TOP_COIN_REQUEST: &str = "unchained/coin_request/v1";
const TOP_LATEST_REQUEST: &str = "unchained/latest_request/v1";

// PQ v2 topics (dual-publish during transition)
const TOP_ANCHOR_V2: &str = "unchained/anchor/v2";
const TOP_COIN_V2: &str = "unchained/coin/v2";
const TOP_TX_V2: &str = "unchained/tx/v2";
const TOP_HELLO_PQ: &str = "unchained/hello_pq/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[allow(dead_code)]
fn validate_coin_candidate(coin: &CoinCandidate, db: &Store) -> Result<(), String> {
    let anchor: Anchor = db.get("anchor", &coin.epoch_hash).unwrap_or(None)
        .ok_or_else(|| format!("Coin references non-existent epoch hash: {}", hex::encode(coin.epoch_hash)))?;

    if coin.creator_address == [0u8; 32] { return Err("Invalid creator address".into()); }
    
    let mem_kib = anchor.mem_kib;
    let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
    let calculated_pow = crypto::argon2id_pow(&header, mem_kib).map_err(|e| e.to_string())?;
    // Optional equality check with provided pow_hash for sanity
    if calculated_pow != coin.pow_hash { return Err("PoW validation failed".into()); }
    // Enforce network difficulty: first `difficulty` bytes of the PoW hash must be zero
    if !calculated_pow.iter().take(anchor.difficulty).all(|&b| b == 0) {
        return Err(format!(
            "PoW does not meet difficulty: requires {} leading zero bytes",
            anchor.difficulty
        ));
    }
    if Coin::calculate_id(&coin.epoch_hash, coin.nonce, &coin.creator_address) != coin.id { return Err("Coin ID mismatch".into()); }
    Ok(())
}

#[allow(dead_code)]
fn validate_transfer(tx: &Transfer, db: &Store) -> Result<(), String> {
    use pqcrypto_dilithium::dilithium3::{PublicKey, DetachedSignature, verify_detached_signature};
    let coin: Coin = db.get("coin", &tx.coin_id).unwrap().ok_or("Referenced coin does not exist")?;
    if db.get::<Transfer>("transfer", &tx.coin_id).unwrap().is_some() { return Err("Double-spend detected".into()); }
    let sender_pk = PublicKey::from_bytes(&tx.sender_pk).map_err(|_| "Invalid sender PK")?;
    let sender_addr = crypto::address_from_pk(&sender_pk);
    if sender_addr != coin.creator_address { return Err("Sender is not coin creator".into()); }
    let sig = DetachedSignature::from_bytes(&tx.sig).map_err(|_| "Invalid signature")?;
    if verify_detached_signature(&sig, &tx.signing_bytes(), &sender_pk).is_err() { return Err("Invalid signature".into()); }
    if tx.to == [0u8; 32] { return Err("Invalid recipient".into()); }
    Ok(())
}

fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    if anchor.hash == [0u8; 32] { return Err("Anchor hash cannot be zero".into()); }
    if anchor.difficulty == 0 { return Err("Difficulty cannot be zero".into()); }
    if anchor.mem_kib == 0 { return Err("Memory cannot be zero".into()); }
    if anchor.merkle_root == [0u8; 32] && anchor.coin_count > 0 { return Err("Merkle root cannot be zero when coins are present".into()); }
    if anchor.num == 0 {
        if anchor.cumulative_work != Anchor::expected_work_for_difficulty(anchor.difficulty) {
            return Err("Genesis cumulative work incorrect".into()); }
        // For genesis, hash should be BLAKE3(merkle_root)
        let mut h = blake3::Hasher::new();
        h.update(&anchor.merkle_root);
        let expected = *h.finalize().as_bytes();
        if anchor.hash != expected { return Err("Anchor hash mismatch".into()); }
        return Ok(());
    }
    let prev: Anchor = db.get("epoch", &(anchor.num - 1).to_le_bytes()).unwrap().ok_or(format!("Previous anchor #{} not found", anchor.num - 1))?;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinProofRequest { pub coin_id: [u8; 32] }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinProofResponse {
    pub coin: Coin,
    pub anchor: Anchor,
    pub proof: Vec<([u8; 32], bool)>,
}

// PQ-signed wrapper for v2 topics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqSigned<T> {
    pub msg: T,
    pub pq_pk: [u8; crypto::DILITHIUM3_PK_BYTES],
    pub pq_sig: [u8; crypto::DILITHIUM3_SIG_BYTES],
}

pub type NetHandle = Arc<Network>;

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
    for t in [TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_EPOCH_REQUEST, TOP_COIN_REQUEST, TOP_LATEST_REQUEST, TOP_COIN_PROOF_REQUEST, TOP_COIN_PROOF_RESPONSE, TOP_ANCHOR_V2, TOP_COIN_V2, TOP_TX_V2, TOP_HELLO_PQ] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    let mut swarm = Swarm::new(
        transport,
        gs,
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
    let mut orphan_anchors: HashMap<u64, Anchor> = HashMap::new();
    let mut connected_peers: HashSet<PeerId> = HashSet::new();

    // PQ peer identity
    let (pq_pk, pq_sk) = crypto::load_or_create_pq_peer_identity("peer_identity_pq.key")?;

    // Cache: peer_id -> PQ pk
    static PEER_PQ_KEYS: Lazy<Mutex<HashMap<PeerId, Vec<u8>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

    // Helper: wrap and sign a message into v2 container
    fn wrap_pq<T: Serialize + Clone>(msg: &T, pq_pk: &[u8], pq_sk: &pqcrypto_dilithium::dilithium3::SecretKey) -> Option<Vec<u8>> {
        let payload = bincode::serialize(msg).ok()?;
        let sig = crypto::pq_sign_payload(&payload, pq_sk);
        let mut pk_arr = [0u8; crypto::DILITHIUM3_PK_BYTES];
        pk_arr.copy_from_slice(pq_pk);
        let mut sig_arr = [0u8; crypto::DILITHIUM3_SIG_BYTES];
        sig_arr.copy_from_slice(&sig);
        let wrapper = PqSigned { msg: msg.clone(), pq_pk: pk_arr, pq_sig: sig_arr };
        bincode::serialize(&wrapper).ok()
    }

    // Helper: verify a v2 message container
    fn verify_pq<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8]) -> Option<T> {
        let wrapper: PqSigned<T> = bincode::deserialize(bytes).ok()?;
        let pk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&wrapper.pq_pk).ok()?;
        let payload = bincode::serialize(&wrapper.msg).ok()?;
        if crypto::pq_verify_payload(&payload, &wrapper.pq_sig, &pk) { Some(wrapper.msg) } else { None }
    }

    const MAX_ORPHAN_ANCHORS: usize = 1024;
    static RECENT_PROOF_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            net_log!("🤝 Connected to peer: {}", peer_id);
                            peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            connected_peers.insert(peer_id);
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                            // Send HELLO_PQ attestation once per connection
                            if let Ok(data) = bincode::serialize(&PqSigned { msg: (), pq_pk: *pq_pk.as_bytes(), pq_sig: crypto::pq_sign_payload(&[], &pq_sk) }) {
                                let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_HELLO_PQ), data);
                            }
                            let mut still_pending = VecDeque::new();
                            while let Some(cmd) = pending_commands.pop_front() {
                                let (t, data, data_v2): (&str, Option<Vec<u8>>, Option<(&str, Vec<u8>)>) = match &cmd {
                                    NetworkCommand::GossipAnchor(a) => {
                                        let v1 = bincode::serialize(&a).ok();
                                        let v2 = wrap_pq(a, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_ANCHOR_V2, d));
                                        (TOP_ANCHOR, v1, v2)
                                    },
                                     NetworkCommand::GossipCoin(c)   => {
                                        let v1 = bincode::serialize(&c).ok();
                                        let v2 = wrap_pq(c, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_COIN_V2, d));
                                        (TOP_COIN, v1, v2)
                                    },
                                    NetworkCommand::GossipTransfer(tx) => {
                                        let v1 = bincode::serialize(&tx).ok();
                                        let v2 = wrap_pq(tx, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_TX_V2, d));
                                        (TOP_TX, v1, v2)
                                    },
                                    NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok(), None),
                                    NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok(), None),
                                    NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok(), None),
                                    NetworkCommand::RequestCoinProof(id) => (TOP_COIN_PROOF_REQUEST, bincode::serialize(&CoinProofRequest{ coin_id: *id }).ok(), None),
                                };
                                if let Some(d) = data {
                                    if swarm.behaviour_mut().publish(IdentTopic::new(t), d).is_err() {
                                        still_pending.push_back(cmd.clone());
                                        continue;
                                    }
                                }
                                if let Some((t2, d2)) = data_v2 {
                                    let _ = swarm.behaviour_mut().publish(IdentTopic::new(t2), d2);
                                }
                            }
                            pending_commands = still_pending;
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            net_log!("👋 Disconnected from peer: {} due to {:?}", peer_id, cause);
                            connected_peers.remove(&peer_id);
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                        },
                        SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) => {
                            let peer_id = message.source.unwrap_or_else(PeerId::random);
                            let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            if score.is_banned() || !score.check_rate_limit() { continue; }
                            let require_pq = p2p_cfg.require_pq_signatures;
                            match message.topic.as_str() {
                                TOP_HELLO_PQ => {
                                    if let Ok(wrapper): Result<PqSigned<()>, _> = bincode::deserialize(&message.data) {
                                        // Cache peer's PQ pk if signature verifies
                                        let pk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&wrapper.pq_pk);
                                        if let Ok(pk) = pk {
                                            if crypto::pq_verify_payload(&[], &wrapper.pq_sig, &pk) {
                                                PEER_PQ_KEYS.lock().unwrap().insert(peer_id, wrapper.pq_pk.to_vec());
                                            }
                                        }
                                    }
                                }
                                TOP_ANCHOR_V2 => if let Some(a) = verify_pq::<Anchor>(&message.data) {
                                    process_anchor(a, &db, &anchor_tx, &mut orphan_anchors, &sync_state, &mut *score);
                                },
                                TOP_COIN_V2 => if let Some(c) = verify_pq::<CoinCandidate>(&message.data) {
                                    if validate_coin_candidate(&c, &db).is_ok() {
                                        let key = Store::candidate_key(&c.epoch_hash, &c.id);
                                        db.put("coin_candidate", &key, &c).ok();
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_COIN.inc();
                                        score.record_validation_failure();
                                    }
                                },
                                TOP_TX_V2 => if let Some(tx) = verify_pq::<Transfer>(&message.data) {
                                    if validate_transfer(&tx, &db).is_ok() {
                                        db.put("transfer", &tx.coin_id, &tx).ok();
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_TRANSFER.inc();
                                        score.record_validation_failure();
                                    }
                                },
                                TOP_ANCHOR => if !require_pq { if let Ok( a) = bincode::deserialize::<Anchor>(&message.data) {
                                    process_anchor(a, &db, &anchor_tx, &mut orphan_anchors, &sync_state, &mut *score);
                                }},
                                TOP_COIN => if !require_pq { if let Ok(c) = bincode::deserialize::<CoinCandidate>(&message.data) {
                                    if validate_coin_candidate(&c, &db).is_ok() {
                                        let key = Store::candidate_key(&c.epoch_hash, &c.id);
                                        db.put("coin_candidate", &key, &c).ok();
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_COIN.inc();
                                        score.record_validation_failure();
                                    }
                                }},
                                TOP_TX => if !require_pq { if let Ok(tx) = bincode::deserialize::<Transfer>(&message.data) {
                                    if validate_transfer(&tx, &db).is_ok() {
                                        db.put("transfer", &tx.coin_id, &tx).ok();
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_TRANSFER.inc();
                                        score.record_validation_failure();
                                    }
                                }},
                                TOP_LATEST_REQUEST => if let Ok(()) = bincode::deserialize::<()>(&message.data) {
                                    let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                                    if score.check_rate_limit() {
                                        net_log!("📨 Received latest epoch request from peer: {}", peer_id);
                                    }
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                        if score.check_rate_limit() {
                                            net_log!("📤 Sending latest epoch {} to peer", anchor.num);
                                        }
                                        if let Ok(data) = bincode::serialize(&anchor) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), data).ok();
                                            if let Some((t2, d2)) = wrap_pq(&anchor, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_ANCHOR_V2, d)) {
                                                swarm.behaviour_mut().publish(IdentTopic::new(t2), d2).ok();
                                            }
                                        }
                                    } else {
                                        net_log!("⚠️  No latest epoch found to send");
                                    }
                                },
                                TOP_EPOCH_REQUEST => if let Ok(n) = bincode::deserialize::<u64>(&message.data) {
                                    net_log!("📨 Received request for epoch {} from peer: {}", n, peer_id);
                                    if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &n.to_le_bytes()) {
                                        net_log!("📤 Sending epoch {} to peer", n);
                                        if let Ok(data) = bincode::serialize(&anchor) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), data).ok();
                                            if let Some((t2, d2)) = wrap_pq(&anchor, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_ANCHOR_V2, d)) {
                                                swarm.behaviour_mut().publish(IdentTopic::new(t2), d2).ok();
                                            }
                                        }
                                    } else {
                                        net_log!("⚠️  Epoch {} not found", n);
                                    }
                                },
                                TOP_COIN_REQUEST => if let Ok(id) = bincode::deserialize::<[u8; 32]>(&message.data) {
                                    if let Ok(Some(coin)) = db.get::<Coin>("coin", &id) {
                                        if let Ok(data) = bincode::serialize(&coin) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), data.clone()).ok();
                                            if let Some((t2, d2)) = wrap_pq(&coin, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_COIN_V2, d)) {
                                                swarm.behaviour_mut().publish(IdentTopic::new(t2), d2).ok();
                                            }
                                        }
                                    }
                                },
                                TOP_COIN_PROOF_REQUEST => if let Ok(req) = bincode::deserialize::<CoinProofRequest>(&message.data) {
                                    // Thread-safe dedupe by coin_id with 10s TTL
                                    let now = std::time::Instant::now();
                                    {
                                        let mut map = RECENT_PROOF_REQS.lock().unwrap();
                                        map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(10));
                                        if map.contains_key(&req.coin_id) { continue; }
                                        map.insert(req.coin_id, now);
                                    }
                                    if let Ok(Some(coin)) = db.get::<Coin>("coin", &req.coin_id) {
                                        // Look up anchor by epoch hash to get epoch number and root
                                        if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &coin.epoch_hash) {
                                            // Build proof from selected IDs for this epoch
                                            if let Ok(selected_ids) = db.get_selected_coin_ids_for_epoch(anchor.num) {
                                                let set: HashSet<[u8; 32]> = HashSet::from_iter(selected_ids.into_iter());
                                                if set.contains(&coin.id) {
                                                    if let Some(proof) = crate::epoch::MerkleTree::build_proof(&set, &coin.id) {
                                                        let resp = CoinProofResponse { coin, anchor: anchor.clone(), proof };
                                                        if let Ok(data) = bincode::serialize(&resp) {
                                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_PROOF_RESPONSE), data).ok();
                                                            crate::metrics::PROOFS_SERVED.inc();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                TOP_COIN_PROOF_RESPONSE => if let Ok(resp) = bincode::deserialize::<CoinProofResponse>(&message.data) {
                                    let _ = proof_tx.send(resp);
                                },
                                _ => {}
                            }
                        },
                        _ => {}
                    }
                },
                Some(command) = command_rx.recv() => {
                    let (topic, data, data_v2) = match &command {
                        NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok(), wrap_pq(a, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_ANCHOR_V2, d))),
                        NetworkCommand::GossipCoin(c) => (TOP_COIN, bincode::serialize(&c).ok(), wrap_pq(c, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_COIN_V2, d))),
                        NetworkCommand::GossipTransfer(tx) => (TOP_TX, bincode::serialize(&tx).ok(), wrap_pq(tx, pq_pk.as_bytes(), &pq_sk).map(|d| (TOP_TX_V2, d))),
                        NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok(), None),
                        NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok(), None),
                        NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok(), None),
                        NetworkCommand::RequestCoinProof(id) => (TOP_COIN_PROOF_REQUEST, bincode::serialize(&CoinProofRequest{ coin_id: *id }).ok(), None),
                    };
                    if let Some(d) = data {
                        if swarm.behaviour_mut().publish(IdentTopic::new(topic), d.clone()).is_err() {
                            pending_commands.push_back(command.clone());
                        }
                    }
                    if let Some((t2, d2)) = data_v2 {
                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(t2), d2);
                    }
                }
            }
        }
    });
    Ok(net)
}

fn process_anchor(
    a: Anchor,
    db: &Arc<Store>,
    anchor_tx: &broadcast::Sender<Anchor>,
    orphan_anchors: &mut HashMap<u64, Anchor>,
    sync_state: &Arc<Mutex<SyncState>>,
    score: &mut PeerScore,
) {
    // Ignore duplicate anchors we have already stored to reduce log and CPU spam
    if let Ok(Some(latest)) = db.get::<Anchor>("epoch", b"latest") {
        if a.num == latest.num && a.hash == latest.hash { return; }
    }
    net_log!("⚓ Received anchor for epoch {}", a.num);
    match validate_anchor(&a, db) {
        Ok(()) => {
            if a.is_better_chain(&db.get("epoch", b"latest").unwrap_or(None)) {
                net_log!("✅ Storing anchor for epoch {}", a.num);
                if db.put("epoch", &a.num.to_le_bytes(), &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                if db.put("anchor", &a.hash, &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                if db.put("epoch", b"latest", &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                {
                    let mut st = sync_state.lock().unwrap();
                    st.highest_seen_epoch = a.num;
                }
                let _ = anchor_tx.send(a.clone());

                // Process orphans following this anchor
                let mut next_num = a.num + 1;
                while let Some(orphan) = orphan_anchors.remove(&next_num) {
                    if validate_anchor(&orphan, db).is_ok() {
                        net_log!("✅ Processing buffered orphan anchor for epoch {}", orphan.num);
                        if db.put("epoch", &orphan.num.to_le_bytes(), &orphan).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                        if db.put("anchor", &orphan.hash, &orphan).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                        if db.put("epoch", b"latest", &orphan).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                        let _ = anchor_tx.send(orphan);
                        next_num += 1;
                    } else {
                        orphan_anchors.insert(orphan.num, orphan);
                        break;
                    }
                }
                crate::metrics::ORPHAN_BUFFER_LEN.set(orphan_anchors.len() as i64);
                if orphan_anchors.len() > MAX_ORPHAN_ANCHORS {
                    let oldest = *orphan_anchors.keys().min().unwrap();
                    orphan_anchors.remove(&oldest);
                    eprintln!("⚠️ Orphan buffer cap exceeded, dropping oldest epoch {}", oldest);
                }
            }
        }
        Err(e) if e.starts_with("Previous anchor") => {
            net_log!("⏳ Buffering orphan anchor for epoch {}", a.num);
            orphan_anchors.insert(a.num, a.clone());
            let mut state = sync_state.lock().unwrap();
            if a.num > state.highest_seen_epoch { state.highest_seen_epoch = a.num; }
        },
        Err(e) => {
            println!("❌ Anchor validation failed: {}", e);
            crate::metrics::VALIDATION_FAIL_ANCHOR.inc();
            score.record_validation_failure();
        }
    }
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
        0 // TODO: Implement actual peer counting
    }
}
