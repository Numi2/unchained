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
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};
use hex;
use std::fs;
use std::path::Path;

// Helper function for graceful gossipsub publishing
fn try_publish_gossip(
    swarm: &mut Swarm<Gossipsub<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &str,
    data: Vec<u8>,
    context: &str,
) {
    match swarm.behaviour_mut().publish(IdentTopic::new(topic), data) {
        Ok(_) => {
            // Successful publish - only log for important messages
            if topic == TOP_ANCHOR || topic == TOP_LATEST_REQUEST {
                println!("📤 Successfully published {} message", context);
            }
        }
        Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {
            // Expected in small networks - don't spam logs
            if topic == TOP_ANCHOR {
                println!("📡 Waiting for gossip mesh to establish for {}", context);
            }
        }
        Err(e) => {
            eprintln!("⚠️  Failed to publish {} ({}): {}", context, topic, e);
        }
    }
}

// Topics are versioned for future protocol upgrades.
const TOP_ANCHOR: &str = "unchained/anchor/v1";
const TOP_COIN: &str = "unchained/coin/v1";
const TOP_TX: &str = "unchained/tx/v1";
const TOP_EPOCH_REQUEST: &str = "unchained/epoch_request/v1";
const TOP_COIN_REQUEST: &str = "unchained/coin_request/v1";
const TOP_LATEST_REQUEST: &str = "unchained/latest_request/v1";

// Peer scoring and rate limiting constants
const MAX_VALIDATION_FAILURES_PER_PEER: u32 = 10;
const PEER_BAN_DURATION_SECS: u64 = 3600; // 1 hour
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const MAX_MESSAGES_PER_WINDOW: u32 = 100;

#[derive(Debug, Clone)]
struct PeerScore {
    validation_failures: u32,
    banned_until: Option<Instant>,
    message_count: u32,
    window_start: Instant,
}

impl PeerScore {
    fn new() -> Self {
        Self {
            validation_failures: 0,
            banned_until: None,
            message_count: 0,
            window_start: Instant::now(),
        }
    }

    fn record_validation_failure(&mut self) {
        self.validation_failures += 1;
        
        if self.validation_failures >= MAX_VALIDATION_FAILURES_PER_PEER {
            self.banned_until = Some(Instant::now() + std::time::Duration::from_secs(PEER_BAN_DURATION_SECS));
            println!("🚫 Peer banned for {} validation failures", self.validation_failures);
        }
    }

    fn is_banned(&mut self) -> bool {
        if let Some(banned_until) = self.banned_until {
            if Instant::now() < banned_until {
                return true;
            }
            // Ban expired, reset
            self.banned_until = None;
            self.validation_failures = 0;
        }
        false
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS) {
            // Reset window
            self.window_start = now;
            self.message_count = 0;
        }
        
        self.message_count += 1;
        
        self.message_count <= MAX_MESSAGES_PER_WINDOW
    }
}

// Coin validation
//--------------------------------------------------------------------
fn validate_coin(coin: &Coin, db: &Store) -> Result<(), String> {
    // 1. Check for double-spending: Ensure coin doesn't already exist
    if let Ok(Some(_)) = db.get::<Coin>("coin", &coin.id) {
        return Err(format!("Double-spend detected for coin ID: {}", hex::encode(coin.id)));
    }

    // 2. Validate epoch hash: Must reference a valid epoch
    // Anchors are stored under column family "epoch" keyed by epoch number, **and**
    // under column family "anchor" keyed by their hash (added for fast lookup).
    let epoch_exists = match db.get::<Anchor>("anchor", &coin.epoch_hash) {
        Ok(Some(_)) => true,
        _ => false,
    };

    if !epoch_exists {
        return Err(format!(
            "Coin references non-existent epoch hash: {}", hex::encode(coin.epoch_hash)
        ));
    }

    // 3. Validate creator address format
    if coin.creator_address == [0u8; 32] {
        return Err("Invalid creator address (all zeros)".into());
    }

    // 4. Get difficulty and memory parameters for PoW validation
    let (_difficulty, mem_kib) = match db.get::<Anchor>("epoch", b"latest") {
        Ok(Some(anchor)) => (anchor.difficulty, anchor.mem_kib),
        Ok(None) => (1, 1024), // Default safe values if no anchor exists
        Err(_) => (1, 1024),   // Default safe values on error
    };

    // 5. Validate Proof-of-Work: Recalculate and verify PoW hash
    let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
    let calculated_pow = match crypto::argon2id_pow(&header, mem_kib, 1) {
        Ok(hash) => hash,
        Err(e) => {
            return Err(format!("PoW calculation failed: {}", e));
        }
    };

    if calculated_pow != coin.pow_hash {
        return Err(format!(
            "PoW validation failed for coin ID: {}", hex::encode(coin.id)
        ));
    }

    // 6. Validate coin ID: Must match the hash of the coin data
    let calculated_id = Coin::calculate_id(&coin.epoch_hash, coin.nonce, &coin.creator_address);
    if calculated_id != coin.id {
        return Err(format!(
            "Coin ID mismatch for coin: {}", hex::encode(coin.id)
        ));
    }

    Ok(())
}

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

    // 3. Validate signature
    let sender_pk = PublicKey::from_bytes(&tx.sender_pk)
        .map_err(|_| "Invalid sender public key bytes".to_string())?;
    let sender_addr = crypto::address_from_pk(&sender_pk);

    // 4. Check ownership – sender must be current owner (creator of coin)
    if sender_addr != coin.creator_address {
        return Err(format!(
            "Transfer signature mismatch – sender {} is not coin creator {}",
            hex::encode(sender_addr),
            hex::encode(coin.creator_address)
        ));
    }

    // 5. Verify signature
    let sig = DetachedSignature::from_bytes(&tx.sig)
        .map_err(|_| "Invalid signature bytes".to_string())?;

    // Use the canonical signing bytes for signature verification
    let message = tx.signing_bytes();

    if verify_detached_signature(&sig, &message, &sender_pk).is_err() {
        return Err("Invalid transfer signature".into());
    }

    // 6. Validate recipient address
    if tx.to == [0u8; 32] {
        return Err("Invalid recipient address (all zeros)".into());
    }

    Ok(())
}

// Anchor validation
//--------------------------------------------------------------------
fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    // Basic sanity checks
    if anchor.hash == [0u8; 32] {
        return Err("Anchor hash cannot be zero".into());
    }

    if anchor.difficulty == 0 {
        return Err("Anchor difficulty cannot be zero".into());
    }

    if anchor.mem_kib == 0 {
        return Err("Anchor memory cannot be zero".into());
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
        .ok_or_else(|| format!("Previous anchor #{} not found", anchor.num - 1))?;

    // Cumulative work must equal prev.cumulative_work + expected_work(difficulty)
    let expected_work = Anchor::expected_work_for_difficulty(anchor.difficulty);
    let expected_cum = prev.cumulative_work.saturating_add(expected_work);
    if anchor.cumulative_work != expected_cum {
        return Err(format!(
            "Invalid cumulative work. Expected: {}, Got: {}",
            expected_cum, anchor.cumulative_work
        ));
    }

    Ok(())
}

pub type NetHandle = Arc<Network>;

#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
}

#[derive(Debug, Clone)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(Coin),
    RequestEpoch(u64),
    RequestCoin([u8; 32]),
    RequestLatestEpoch,
}

/// Load or create a persistent peer identity
fn load_or_create_peer_identity() -> anyhow::Result<identity::Keypair> {
    let identity_path = "peer_identity.key";
    
    // Try to load existing identity
    if Path::new(identity_path).exists() {
        match fs::read(identity_path) {
            Ok(key_data) => {
                match identity::Keypair::from_protobuf_encoding(&key_data) {
                    Ok(keypair) => {
                        println!("🔑 Loaded existing peer identity from {}", identity_path);
                        return Ok(keypair);
                    }
                    Err(e) => {
                        eprintln!("⚠️  Failed to load peer identity: {}. Creating new one.", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠️  Failed to read peer identity file: {}. Creating new one.", e);
            }
        }
    }
    
    // Create new identity
    let keypair = identity::Keypair::generate_ed25519();
    
    // Save the new identity
    match keypair.to_protobuf_encoding() {
        Ok(key_data) => {
            if let Err(e) = fs::write(identity_path, key_data) {
                eprintln!("⚠️  Failed to save peer identity: {}. Identity will not persist.", e);
            } else {
                println!("🔑 Created and saved new peer identity to {}", identity_path);
            }
        }
        Err(e) => {
            eprintln!("⚠️  Failed to encode peer identity: {}. Identity will not persist.", e);
        }
    }
    
    Ok(keypair)
}

pub async fn spawn(cfg: crate::config::Net, db: Arc<Store>) -> anyhow::Result<NetHandle> {
    // Load or create persistent peer identity
    let id_keys = load_or_create_peer_identity()?;
    let peer_id = PeerId::from(id_keys.public());
    println!("📡 Local peer-ID: {peer_id}");

    // NOTE: QUIC transport with post-quantum readiness
    // The rustls dependency now includes aws-lc-rs with prefer-post-quantum feature
    // which enables hybrid X25519+Kyber key exchange when both peers support it.
    // This provides post-quantum resistance while maintaining backwards compatibility.
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    // Tune mesh parameters so that publishing works even with very small networks (1-2 peers).
    // The defaults in libp2p assume at least 4 peers in the mesh; otherwise `publish` returns
    // `InsufficientPeers`. By lowering these thresholds, two nodes can immediately exchange
    // messages – e.g. the *latest epoch* request/response when a fresh node is bootstrapping.
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(std::time::Duration::from_secs(1))           // Faster heartbeat for small networks
        .validation_mode(gossipsub::ValidationMode::Permissive)          // Allow messages from any peer
        .mesh_n(2)                                                       // Target 2 peers in mesh
        .mesh_n_low(1)                                                   // Minimum 1 peer before publishing is allowed
        .mesh_n_high(3)                                                  // Upper bound keeps mesh small
        .mesh_outbound_min(0)                                              // Allow publishing even with only inbound peers
        .gossip_lazy(1)                                                  // Send gossip to 1 peer/heartbeat
        .flood_publish(true)                                             // Publish even if mesh thresholds not met
        .message_id_fn(|message| {                                       // Custom message ID to prevent duplicates
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            message.data.hash(&mut hasher);
            message.topic.hash(&mut hasher);
            gossipsub::MessageId::from(hasher.finish().to_string().into_bytes())
        })
        .duplicate_cache_time(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build gossipsub config: {}", e))?;
        
    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub_config,
    ).map_err(|e| anyhow::anyhow!("Failed to create Gossipsub: {}", e))?;
    for t in [TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_EPOCH_REQUEST, TOP_COIN_REQUEST, TOP_LATEST_REQUEST] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    let mut swarm = Swarm::new(transport, gs, peer_id, libp2p::swarm::Config::with_tokio_executor());
    
    // Bind the QUIC listener, automatically retrying the next port if the desired
    // port is already occupied. This improves UX when multiple nodes are started
    // on the same machine (e.g. during testing).
    let mut port = cfg.listen_port;
    let mut bound = false;
    for _ in 0..10 { // try up to 10 consecutive ports
        let listen_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port);
        println!("🔍 Attempting to listen on: {}", listen_addr);
        match swarm.listen_on(listen_addr.parse()?) {
            Ok(_) => { bound = true; break; },
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                if msg.contains("address already in use") {
                    println!("⚠️  Port {} already in use, trying {}", port, port + 1);
                    port = port.saturating_add(1);
                    continue;
                } else {
                    return Err(anyhow::anyhow!("Failed to bind listener: {}", e));
                }
            }
        }
    }
    if !bound {
        return Err(anyhow::anyhow!("Could not bind to any port starting from {}", cfg.listen_port));
    }
    
    // Debug: Show what we're trying to connect to
    println!("🔍 Local peer ID: {}", peer_id);
    println!("🔍 Local IP addresses:");
    for addr in &cfg.bootstrap {
        println!("   - {}", addr);
    }

    // Connect to bootstrap peers, but skip if it's our own peer ID
    for addr in &cfg.bootstrap {
        let parsed_addr = addr.parse::<Multiaddr>()?;
        // Extract peer ID from the multiaddr to check if it's our own
        if let Some(addr_peer_id) = parsed_addr.iter().last() {
            if let libp2p::multiaddr::Protocol::P2p(peer_id_bytes) = addr_peer_id {
                let addr_peer_id = PeerId::try_from(peer_id_bytes);
                if addr_peer_id.is_ok() {
                    let addr_peer_id = addr_peer_id.unwrap();
                    if addr_peer_id == peer_id {
                        println!("⚠️  Skipping bootstrap connection to self (peer ID: {})", peer_id);
                        continue;
                    }
                }
            }
        }
        println!("🔗 Attempting to connect to bootstrap peer: {}", addr);
        swarm.dial(parsed_addr)?;
    }

    let (anchor_tx, _) = broadcast::channel(256); // Increased from 32 to 256 for multi-node stability
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), command_tx: command_tx.clone() });

    // Initialize peer management
    let mut peer_scores: HashMap<PeerId, PeerScore> = HashMap::new();
    let mut connected_peers = 0u32;
    let mut recently_connected_peers: HashMap<PeerId, tokio::time::Instant> = HashMap::new();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            connected_peers += 1;
                            if connected_peers > cfg.max_peers {
                                println!("⚠️  Max peers ({}) exceeded, disconnecting {}", cfg.max_peers, peer_id);
                                let _ = swarm.disconnect_peer_id(peer_id);
                                connected_peers -= 1;
                            } else {
                                peer_scores.entry(peer_id).or_insert_with(PeerScore::new);
                                recently_connected_peers.insert(peer_id, tokio::time::Instant::now());
                                println!("🤝 Connected to peer {} ({}/{} peers) via {:?}", peer_id, connected_peers, cfg.max_peers, endpoint);
                                
                                // Wait a moment to stabilize the connection before sending data
                                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                                
                                // Request latest state from new peer if we're starting fresh
                                if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                    if latest_anchor.num == 0 {
                                        println!("🔄 Node has only genesis epoch, requesting latest anchor from new peer {}", peer_id);
                                        // Request the peer's latest anchor to discover the current chain state
                                        if let Ok(bytes) = bincode::serialize(&()) {
                                            match swarm.behaviour_mut().publish(IdentTopic::new(TOP_LATEST_REQUEST), bytes) {
                                                Ok(_) => println!("📤 Latest epoch request sent to peer {}", peer_id),
                                                Err(e) => println!("⚠️  Failed to publish latest request to peer {}: {}", peer_id, e),
                                            }
                                        } else {
                                            println!("⚠️  Failed to serialize latest epoch request");
                                        }
                                    }
                                }
                                
                                // Broadcast our latest anchor to help new peers sync
                                if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                    if latest_anchor.num > 0 {
                                        println!("📡 Broadcasting latest anchor #{} to new peer {}", latest_anchor.num, peer_id);
                                        // Wait a moment to ensure connection is stable before broadcasting
                                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                        if let Ok(bytes) = bincode::serialize(&latest_anchor) {
                                            try_publish_gossip(&mut swarm, TOP_ANCHOR, bytes, &format!("anchor #{} to peer {}", latest_anchor.num, peer_id));
                                            println!("📤 Anchor #{} broadcast sent to peer {}", latest_anchor.num, peer_id);
                                            // Give the message time to be sent before potential disconnection
                                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                        }
                                        
                                        // Send a keepalive message to maintain connection
                                        println!("💓 Sending keepalive message to peer {}", peer_id);
                                        if let Ok(keepalive_bytes) = bincode::serialize(&0u64) {
                                            try_publish_gossip(&mut swarm, TOP_EPOCH_REQUEST, keepalive_bytes, &format!("keepalive to peer {}", peer_id));
                                        }
                                    }
                                }
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, endpoint, .. } => {
                            // Check if this is a recently connected peer that we should protect
                            if let Some(connect_time) = recently_connected_peers.get(&peer_id) {
                                let connection_age = connect_time.elapsed();
                                if connection_age < std::time::Duration::from_secs(10) {
                                    println!("🛡️  Protecting recently connected peer {} (age: {:?})", peer_id, connection_age);
                                    // Don't count this as a disconnection for recently connected peers
                                    continue;
                                }
                            }
                            
                            connected_peers = connected_peers.saturating_sub(1);
                            recently_connected_peers.remove(&peer_id);
                            println!("👋 Disconnected from peer {} ({}/{} peers) via {:?}", peer_id, connected_peers, cfg.max_peers, endpoint);
                        },
                        SwarmEvent::OutgoingConnectionError { peer_id, error, connection_id: _ } => {
                            eprintln!("❌ Failed to connect to peer {:?}: {:?}", peer_id, error);
                            if peer_id.is_some() {
                                eprintln!("   This might be due to:");
                                eprintln!("   - Firewall blocking port 7777");
                                eprintln!("   - Target peer not running");
                                eprintln!("   - Network connectivity issues");
                                eprintln!("   - Wrong IP address in config.toml");
                            }
                        },
                        SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, connection_id: _ } => {
                            eprintln!("❌ Incoming connection failed from {} to {}: {:?}", send_back_addr, local_addr, error);
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
                                                if let Err(e) = db.put("epoch", b"latest", &a) {
                                                    eprintln!("❌ Critical: Failed to update latest anchor #{}: {}", a.num, e);
                                                }
                                                println!("✅ Accepted better chain anchor #{} from network", a.num);
                                                let anchor_num = a.num;
                                                if let Err(e) = anchor_tx.send(a) {
                                                    eprintln!("⚠️  Failed to broadcast anchor #{} internally: {}", anchor_num, e);
                                                }
                                            }
                                        } else {
                                            // Still store the anchor but don't update latest
                                            if db.put("epoch", &a.num.to_le_bytes(), &a).is_ok() {
                                                println!("📥 Received anchor #{} from network (not better than current)", a.num);
                                            }
                                        }
                                    }
                                    Err(validation_error) => {
                                        // Special handling when we are missing previous anchors in the chain.
                                        if validation_error.starts_with("Previous anchor") {
                                            // We don't yet have the prior anchor, so store this anchor for later
                                            // and request the missing predecessor instead of treating this as an
                                            // invalid message from the peer.
                                            println!("ℹ️  Received anchor #{} but missing previous. Storing and requesting previous epoch.", a.num);
                                            if db.put("epoch", &a.num.to_le_bytes(), &a).is_ok() {
                                                // Anchor stored for future validation – we will link it once the
                                                // missing predecessors arrive.
                                            }

                                            // Ask the network for the missing previous anchor so we can fully validate.
                                            if a.num > 0 {
                                                let prev_epoch = a.num - 1;
                                                if let Ok(bytes) = bincode::serialize(&prev_epoch) {
                                                    try_publish_gossip(&mut swarm, TOP_EPOCH_REQUEST, bytes, &format!("prev epoch #{} request", prev_epoch));
                                                }
                                            }
                                            // Intentionally do NOT penalise the peer – this is not their fault.
                                        } else {
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
                                        try_publish_gossip(&mut swarm, TOP_COIN, bytes, &format!("coin response {}", hex::encode(id)));
                                    }
                                }
                                },
                                TOP_EPOCH_REQUEST => if let Ok(num) = bincode::deserialize::<u64>(&message.data) {
                                if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &num.to_le_bytes()) {
                                    if let Ok(bytes) = bincode::serialize(&anchor) {
                                        try_publish_gossip(&mut swarm, TOP_ANCHOR, bytes, &format!("epoch {} response", num));
                                    }
                                }
                                },
                                TOP_LATEST_REQUEST => {
                                    // Respond with our latest anchor
                                    if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                                        if latest_anchor.num > 0 {
                                            println!("📤 Responding to latest epoch request with anchor #{}", latest_anchor.num);
                                            if let Ok(bytes) = bincode::serialize(&latest_anchor) {
                                                try_publish_gossip(&mut swarm, TOP_ANCHOR, bytes, &format!("latest epoch response #{}", latest_anchor.num));
                                            }
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
                    // Clone so we can retry later without reconstructing
                    let cmd_original = command.clone();
                    let (topic, data) = match &cmd_original {
                        NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                        NetworkCommand::GossipCoin(c) => (TOP_COIN, bincode::serialize(&c).ok()),
                        NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                        NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                        NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok()),
                    };
                    if let Some(d) = data {
                        match swarm.behaviour_mut().publish(IdentTopic::new(topic), d.clone()) {
                            Ok(_) => {
                                // Success - no need to log for every message
                            }
                            Err(libp2p::gossipsub::PublishError::InsufficientPeers) => {
                                // Common in small networks - retry after brief delay
                                println!("📡 Waiting for more peers to join topic {}, will retry...", topic);

                                // Clone variables needed inside async retry task
                                let topic_clone = topic.to_string();
                                let cmd_clone = cmd_original.clone();
                                let tx_clone = command_tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
                                    if tx_clone.send(cmd_clone).is_ok() {
                                        println!("🔄 Retrying publish for topic {}", topic_clone);
                                    } else {
                                        eprintln!("⚠️  Retry queue closed. Could not re-publish {}", topic_clone);
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("⚠️  Failed to publish {} message: {}", topic, e);
                            }
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
        println!("🔄 Requesting latest epoch info from network for synchronization");
        let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch);
    }
}