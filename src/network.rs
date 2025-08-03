use crate::{storage::Store, epoch::Anchor, coin::Coin, transfer::Transfer, crypto};
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
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use tokio::sync::{broadcast, mpsc};
use hex;

// Topics are versioned for future protocol upgrades.
const TOP_ANCHOR: &str = "anchor/1";
const TOP_COIN:   &str = "coin/1";
const TOP_TX:     &str = "tx/1";
const TOP_EPOCH_REQUEST: &str = "epoch_request/1";
const TOP_COIN_REQUEST: &str = "coin_request/1";

// Peer management constants
const MAX_VALIDATION_FAILURES_PER_PEER: u32 = 10;
const PEER_BAN_DURATION_SECS: u64 = 3600; // 1 hour
const RATE_LIMIT_WINDOW_SECS: u64 = 60; // 1 minute window
const MAX_MESSAGES_PER_WINDOW: u32 = 100; // messages per window per peer

#[derive(Debug, Clone)]
struct PeerScore {
    validation_failures: u32,
    last_failure: Option<Instant>,
    banned_until: Option<Instant>,
    message_count: u32,
    window_start: Instant,
}

/// Comprehensive coin validation to prevent forgery and ensure cryptographic integrity
//--------------------------------------------------------------------
// Coin validation
//--------------------------------------------------------------------
fn validate_coin(coin: &Coin, db: &Store) -> Result<(), String> {
    // 1. Check for double-spending: Ensure coin doesn't already exist
    if let Ok(Some(_)) = db.get::<Coin>("coin", &coin.id) {
        return Err(format!("Double-spend detected for coin ID: {}", hex::encode(coin.id)));
    }

    // 2. Validate coin ID integrity: Verify it's correctly computed from component fields
    let expected_id = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&coin.epoch_hash);
        hasher.update(&coin.nonce.to_le_bytes());
        hasher.update(&coin.creator_address);
        hasher.update(&coin.pow_hash);
        *hasher.finalize().as_bytes()
    };
    
    if coin.id != expected_id {
        return Err(format!(
            "Invalid coin ID. Expected: {}, Got: {}",
            hex::encode(expected_id),
            hex::encode(coin.id)
        ));
    }

    // 3. Validate epoch exists: Ensure epoch hash corresponds to a known anchor
    // Anchors are stored under column family "epoch" keyed by epoch number, **and**
    // under column family "anchor" keyed by their hash (added for fast lookup).
    let epoch_exists = match db.get::<Anchor>("anchor", &coin.epoch_hash) {
        Ok(Some(_)) => true,
        _ => false,
    };

    if !epoch_exists {
        return Err(format!(
            "Invalid or unknown epoch hash: {}",
            hex::encode(coin.epoch_hash)
        ));
    }

    // 4. Get difficulty and memory parameters for PoW validation
    let (difficulty, mem_kib) = match db.get::<Anchor>("epoch", b"latest") {
        Ok(Some(anchor)) => (anchor.difficulty, anchor.mem_kib),
        Ok(None) => (1, 1024), // Default safe values if no anchor exists
        Err(_) => (1, 1024),
    };

    // 5. Validate Proof-of-Work: Recalculate and verify PoW hash
    let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
    let calculated_pow = match crypto::argon2id_pow(&header, mem_kib, 1) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(format!("Failed to calculate PoW hash: {e}"));
        }
    };

    // 6. Verify PoW hash matches stored value
    if calculated_pow != coin.pow_hash {
        return Err(format!(
            "Invalid PoW hash. Expected: {}, Got: {}",
            hex::encode(calculated_pow),
            hex::encode(coin.pow_hash)
        ));
    }

    // 7. Verify PoW meets difficulty requirement (leading zero bytes)
    if !calculated_pow.iter().take(difficulty).all(|&b| b == 0) {
        return Err(format!(
            "PoW hash does not meet difficulty requirement of {} leading zero bytes. Hash: {}",
            difficulty,
            hex::encode(calculated_pow)
        ));
    }

    // 8. Validate coin value (should always be 1 for new coins)
    if coin.value != 1 {
        return Err(format!("Invalid coin value: {}. All new coins must have value 1", coin.value));
    }

    // 9. Verify creator address format (32 bytes)
    if coin.creator_address.len() != 32 {
        return Err(format!(
            "Invalid creator address length: {}. Must be 32 bytes",
            coin.creator_address.len()
        ));
    }

    Ok(())
}

//--------------------------------------------------------------------
// Transfer validation
//--------------------------------------------------------------------
fn validate_transfer(tx: &Transfer, db: &Store) -> Result<(), String> {
    use pqcrypto_dilithium::dilithium3::{PublicKey, DetachedSignature, verify_detached_signature};

    // 1. Coin must exist
    let coin: Coin = db
        .get("coin", &tx.coin_id)
        .map_err(|e| format!("DB error while fetching coin: {e}"))?
        .ok_or_else(|| format!("Referenced coin does not exist: {}", hex::encode(tx.coin_id)))?;

    // 2. Prevent double-spend – coin must not already have a recorded transfer
    if let Ok(Some(_)) = db.get::<Transfer>("transfer", &tx.coin_id) {
        return Err(format!(
            "Double-spend detected – coin {} already spent", hex::encode(tx.coin_id)
        ));
    }

    // 3. Verify Dilithium3 signature
    let sender_pk = PublicKey::from_bytes(&tx.sender_pk)
        .map_err(|_| "Invalid sender public key bytes".to_string())?;
    let sender_addr = crypto::address_from_pk(&sender_pk);

    // 4. Check ownership – sender must be current owner (creator of coin)
    if sender_addr != coin.creator_address {
        return Err("Sender does not own the coin".to_string());
    }

    // 5. prev_tx_hash must be zero for first spend
    if tx.prev_tx_hash != [0u8; 32] {
        return Err("prev_tx_hash must be zero for first transfer".to_string());
    }

    // 6. Verify signature over canonical signing bytes
    let content = tx.signing_bytes();
    let sig = DetachedSignature::from_bytes(&tx.sig)
        .map_err(|_| "Invalid signature bytes".to_string())?;
    verify_detached_signature(&sig, &content, &sender_pk)
        .map_err(|_| "Signature verification failed".to_string())?;

    Ok(())
}

//--------------------------------------------------------------------
// Anchor validation
//--------------------------------------------------------------------

//--------------------------------------------------------------------
// Anchor validation
//--------------------------------------------------------------------
fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    // Basic sanity checks
    if anchor.hash == [0u8; 32] {
        return Err("Anchor hash is zero".into());
    }

    // Genesis anchor (num == 0) special‐case
    if anchor.num == 0 {
        if anchor.cumulative_work != Anchor::expected_work_for_difficulty(anchor.difficulty) {
            return Err("Genesis cumulative work incorrect".into());
        }
        return Ok(());
    }

    // Must have previous anchor
    let prev: Anchor = db
        .get("epoch", &(anchor.num - 1).to_le_bytes())
        .map_err(|e| format!("DB error while fetching previous anchor: {e}"))?
        .ok_or_else(|| format!("Previous anchor #{} missing", anchor.num - 1))?;

    // Difficulty cannot change by more than ±1 between consecutive anchors
    let diff_change = anchor.difficulty.abs_diff(prev.difficulty);
    if diff_change > 1 {
        return Err("Difficulty adjustment too large".into());
    }

    // Memory parameter must stay within allowed bounds
    if anchor.mem_kib < 16_384 || anchor.mem_kib > 262_144 {
        return Err("mem_kib outside permissible range".into());
    }

    // Cumulative work must equal prev.cumulative_work + expected_work(difficulty)
    let expected_work = Anchor::expected_work_for_difficulty(anchor.difficulty);
    let expected_cum = prev.cumulative_work.saturating_add(expected_work);
    if anchor.cumulative_work != expected_cum {
        return Err("Cumulative work mismatch".into());
    }

    // Chain continuity: ensure anchor.hash differs from prev.hash to prevent duplication
    if anchor.hash == prev.hash {
        return Err("Anchor hash identical to previous".into());
    }

    Ok(())
}
#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
}

#[derive(Debug)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(Coin),
    RequestEpoch(u64),
    RequestCoin([u8; 32]),
}
pub type NetHandle = Arc<Network>;

// Peer management helper functions
impl PeerScore {
    fn new() -> Self {
        Self {
            validation_failures: 0,
            last_failure: None,
            banned_until: None,
            message_count: 0,
            window_start: Instant::now(),
        }
    }
    
    fn is_banned(&self) -> bool {
        if let Some(ban_time) = self.banned_until {
            Instant::now() < ban_time
        } else {
            false
        }
    }
    
    fn record_validation_failure(&mut self) {
        self.validation_failures += 1;
        self.last_failure = Some(Instant::now());
        
        if self.validation_failures >= MAX_VALIDATION_FAILURES_PER_PEER {
            self.banned_until = Some(Instant::now() + Duration::from_secs(PEER_BAN_DURATION_SECS));
            println!("🚫 Peer banned for {} validation failures", self.validation_failures);
        }
    }
    
    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > Duration::from_secs(RATE_LIMIT_WINDOW_SECS) {
            // Reset window
            self.window_start = now;
            self.message_count = 1;
            true
        } else {
            self.message_count += 1;
            self.message_count <= MAX_MESSAGES_PER_WINDOW
        }
    }
}

pub async fn spawn(cfg: crate::config::Net, db: Arc<Store>) -> anyhow::Result<NetHandle> {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("📡 Local peer-ID: {peer_id}");

    // NOTE: QUIC transport with post-quantum readiness
    // The rustls dependency now includes aws-lc-rs with prefer-post-quantum feature
    // which enables hybrid X25519+Kyber key exchange when both peers support it.
    // This provides post-quantum resistance while maintaining backwards compatibility.
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub::Config::default(),
    ).map_err(|e| anyhow::anyhow!("Failed to create Gossipsub: {}", e))?;
    for t in [TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_EPOCH_REQUEST, TOP_COIN_REQUEST] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    let mut swarm = Swarm::new(transport, gs, peer_id, libp2p::swarm::Config::with_tokio_executor());
    swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", cfg.listen_port).parse()?)?;
    for addr in &cfg.bootstrap {
        swarm.dial(addr.parse::<Multiaddr>()?)?;
    }

    let (anchor_tx, _) = broadcast::channel(256); // Increased from 32 to 256 for multi-node stability
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), command_tx });

    // Initialize peer management
    let mut peer_scores: HashMap<PeerId, PeerScore> = HashMap::new();
    let mut connected_peers = 0u32;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            connected_peers += 1;
                            if connected_peers > cfg.max_peers {
                                println!("⚠️  Max peers ({}) exceeded, disconnecting {}", cfg.max_peers, peer_id);
                                let _ = swarm.disconnect_peer_id(peer_id);
                                connected_peers -= 1;
                            } else {
                                peer_scores.entry(peer_id).or_insert_with(PeerScore::new);
                                println!("🤝 Connected to peer {} ({}/{} peers)", peer_id, connected_peers, cfg.max_peers);
                                
                                // Request latest state from new peer if we're starting fresh
                                if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                    if latest_anchor.num == 0 {
                                        println!("🔄 Requesting latest blockchain state from new peer {}", peer_id);
                                        // Request the latest epoch from this peer
                                        if let Ok(bytes) = bincode::serialize(&0u64) { // Request epoch 0 to get started
                                            let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                        }
                                    }
                                }
                                
                                // Broadcast our latest anchor to help new peers sync
                                if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                    if latest_anchor.num > 0 {
                                        println!("📡 Broadcasting latest anchor #{} to new peer {}", latest_anchor.num, peer_id);
                                        if let Ok(bytes) = bincode::serialize(&latest_anchor) {
                                            let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), bytes);
                                        }
                                    }
                                }
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            connected_peers = connected_peers.saturating_sub(1);
                            println!("👋 Disconnected from peer {} ({}/{} peers)", peer_id, connected_peers, cfg.max_peers);
                        },
                        SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) => {
                            let peer_id = message.source.unwrap_or_else(PeerId::random);
                            
                            // Check peer scoring and rate limiting
                            let should_process = {
                                let score = peer_scores.entry(peer_id).or_insert_with(PeerScore::new);
                                
                                if score.is_banned() {
                                    println!("🚫 Ignoring message from banned peer {peer_id}");
                                    false
                                } else if !score.check_rate_limit() {
                                    println!("🚨 Rate limit exceeded for peer {peer_id}, ignoring message");
                                    false
                                } else {
                                    true
                                }
                            };
                            
                            if !should_process {
                                continue;
                            }
                            
                            match message.topic.as_str() {
                                TOP_ANCHOR => if let Ok(a) = bincode::deserialize::<Anchor>(&message.data) {
                                match validate_anchor(&a, &db) {
                                    Ok(()) => {
                                        // Check for potential fork/reorg
                                        let current_best: Option<Anchor> = db.get("epoch", b"latest").unwrap_or(None);
                                        let should_reorg = a.is_better_chain(&current_best);
                                        
                                        if should_reorg {
                                            if let Some(current) = &current_best {
                                                if a.num < current.num {
                                                    println!("🔄 CHAIN REORGANIZATION: New chain with higher work at epoch {} (current: {})", a.num, current.num);
                                                    println!("   New cumulative work: {}", a.cumulative_work);
                                                    println!("   Old cumulative work: {}", current.cumulative_work);
                                                }
                                            }
                                            
                                            if db.put("epoch", &a.num.to_le_bytes(), &a).is_ok() {
                                                let _ = db.put("epoch", b"latest", &a);
                                                println!("✅ Accepted better chain anchor #{} from network", a.num);
                                                let _ = anchor_tx.send(a);
                                            }
                                        } else {
                                            // Still store the anchor but don't update latest
                                            if db.put("epoch", &a.num.to_le_bytes(), &a).is_ok() {
                                                println!("📥 Received anchor #{} from network (not better than current)", a.num);
                                            }
                                        }
                                    }
                                    Err(validation_error) => {
                                        eprintln!("🚫 REJECTED invalid anchor from {peer_id}: {validation_error}");
                                        eprintln!("   Epoch: {}", a.num);
                                        eprintln!("   Hash: {}", hex::encode(a.hash));
                                        eprintln!("   Difficulty: {}", a.difficulty);
                                        eprintln!("   Coin Count: {}", a.coin_count);
                                        eprintln!("   Cumulative Work: {}", a.cumulative_work);
                                        if let Some(score) = peer_scores.get_mut(&peer_id) {
                                            score.record_validation_failure();
                                        }
                                    }
                                }
                                },
                                TOP_COIN => if let Ok(c) = bincode::deserialize::<Coin>(&message.data) {
                                // 🔒 CRITICAL SECURITY: Validate coin before storing to prevent forgery
                                match validate_coin(&c, &db) {
                                    Ok(()) => {
                                        if let Err(e) = db.put("coin", &c.id, &c) {
                                            eprintln!("🚨 Failed to store validated coin {}: {e}", hex::encode(c.id));
                                        } else {
                                            println!("✅ Accepted valid coin from network: {}", hex::encode(c.id));
                                        }
                                    }
                                    Err(validation_error) => {
                                        eprintln!("🚫 REJECTED invalid coin from {peer_id}: {validation_error}");
                                        eprintln!("   Coin ID: {}", hex::encode(c.id));
                                        eprintln!("   Epoch Hash: {}", hex::encode(c.epoch_hash));
                                        eprintln!("   Creator: {}", hex::encode(c.creator_address));
                                        eprintln!("   Nonce: {}", c.nonce);
                                        eprintln!("   PoW Hash: {}", hex::encode(c.pow_hash));
                                        if let Some(score) = peer_scores.get_mut(&peer_id) {
                                            score.record_validation_failure();
                                        }
                                    }
                                }
                                },
                                TOP_TX => if let Ok(t) = bincode::deserialize::<Transfer>(&message.data) {
                                match validate_transfer(&t, &db) {
                                    Ok(()) => {
                                        if let Err(e) = db.put("transfer", &t.coin_id, &t) {
                                            eprintln!("🚨 Failed to store validated transfer for coin {}: {e}", hex::encode(t.coin_id));
                                        } else {
                                            println!("✅ Accepted valid transfer for coin {}", hex::encode(t.coin_id));
                                        }
                                    }
                                    Err(err) => {
                                        eprintln!("🚫 REJECTED invalid transfer from {peer_id}: {err}");
                                        eprintln!("   Coin ID: {}", hex::encode(t.coin_id));
                                        eprintln!("   To: {}", hex::encode(t.to));
                                        if let Some(score) = peer_scores.get_mut(&peer_id) {
                                            score.record_validation_failure();
                                        }
                                    }
                                }
                                },
                                TOP_COIN_REQUEST => if let Ok(id) = bincode::deserialize::<[u8; 32]>(&message.data) {
                                if let Ok(Some(coin)) = db.get::<Coin>("coin", &id) {
                                    if let Ok(bytes) = bincode::serialize(&coin) {
                                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), bytes);
                                    }
                                }
                                },
                                TOP_EPOCH_REQUEST => if let Ok(num) = bincode::deserialize::<u64>(&message.data) {
                                if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &num.to_le_bytes()) {
                                    if let Ok(bytes) = bincode::serialize(&anchor) {
                                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), bytes);
                                    }
                                }
                                },
                                _ => {}
                            }
                        },
                        _ => {} // Handle other swarm events as needed
                    }
                },
                Some(command) = command_rx.recv() => {
                    let (topic, data) = match command {
                        NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                        NetworkCommand::GossipCoin(c) => (TOP_COIN, bincode::serialize(&c).ok()),
                        NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                        NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                    };
                    if let Some(d) = data {
                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(topic), d);
                    }
                }
            }
        }
    });
    Ok(net)
}

impl Network {
    pub async fn gossip_anchor(&self, a: &Anchor) { let _ = self.command_tx.send(NetworkCommand::GossipAnchor(a.clone())); }
    pub async fn gossip_coin(&self, c: &Coin) { let _ = self.command_tx.send(NetworkCommand::GossipCoin(c.clone())); }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> { self.anchor_tx.subscribe() }
    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> { self.anchor_tx.clone() }
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    pub async fn request_coin(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoin(id)); }
    
    /// Request a specific epoch by number for recovery purposes
    pub async fn request_specific_epoch(&self, epoch_num: u64) {
        println!("🔄 Requesting specific epoch #{epoch_num} for recovery");
        self.request_epoch(epoch_num).await;
    }
    
    /// Request the latest epoch from the network for initial synchronization
    pub async fn request_latest_epoch(&self) {
        println!("🔄 Requesting latest epoch from network for synchronization");
        // Request epoch 0 to get started, then the sync module will handle requesting missing epochs
        self.request_epoch(0).await;
    }
}
