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
use tokio::sync::{broadcast, mpsc};
use hex;

// Topics are versioned for future protocol upgrades.
const TOP_ANCHOR: &str = "anchor/1";
const TOP_COIN:   &str = "coin/1";
const TOP_TX:     &str = "tx/1";
const TOP_EPOCH_REQUEST: &str = "epoch_request/1";
const TOP_COIN_REQUEST: &str = "coin_request/1";

/// Comprehensive coin validation to prevent forgery and ensure cryptographic integrity
//--------------------------------------------------------------------
// Coin validation
//--------------------------------------------------------------------
fn validate_coin(coin: &Coin, db: &Store) -> Result<(), String> {
    // 1. Check for double-spending: Ensure coin doesn't already exist
    if let Ok(Some(_)) = db.get::<Coin>("coin", &coin.id) {
        return Err(format!("Double-spend detected for coin ID: {}", hex::encode(&coin.id)));
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
            hex::encode(&expected_id),
            hex::encode(&coin.id)
        ));
    }

    // 3. Validate epoch exists: Ensure epoch hash corresponds to a known anchor
    let epoch_exists = match db.get::<Anchor>("epoch", b"latest") {
        Ok(Some(latest_anchor)) => {
            // Check if coin's epoch matches current or recent epochs
            coin.epoch_hash == latest_anchor.hash || 
            // Also check if this epoch hash exists in our database
            matches!(db.get::<Vec<u8>>("epoch", &coin.epoch_hash), Ok(Some(_)))
        }
        Ok(None) => {
            // If no latest anchor, check if epoch hash exists directly
            matches!(db.get::<Vec<u8>>("epoch", &coin.epoch_hash), Ok(Some(_)))
        }
        Err(_) => false,
    };

    if !epoch_exists {
        return Err(format!(
            "Invalid or unknown epoch hash: {}",
            hex::encode(&coin.epoch_hash)
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
            return Err(format!("Failed to calculate PoW hash: {}", e));
        }
    };

    // 6. Verify PoW hash matches stored value
    if calculated_pow != coin.pow_hash {
        return Err(format!(
            "Invalid PoW hash. Expected: {}, Got: {}",
            hex::encode(&calculated_pow),
            hex::encode(&coin.pow_hash)
        ));
    }

    // 7. Verify PoW meets difficulty requirement (leading zero bytes)
    if !calculated_pow.iter().take(difficulty).all(|&b| b == 0) {
        return Err(format!(
            "PoW hash does not meet difficulty requirement of {} leading zero bytes. Hash: {}",
            difficulty,
            hex::encode(&calculated_pow)
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
        .map_err(|e| format!("DB error while fetching coin: {}", e))?
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
        .map_err(|e| format!("DB error while fetching previous anchor: {}", e))?
        .ok_or_else(|| format!("Previous anchor #{} missing", anchor.num - 1))?;

    // Difficulty cannot change by more than ±1 between consecutive anchors
    let diff_change = if anchor.difficulty > prev.difficulty {
        anchor.difficulty - prev.difficulty
    } else {
        prev.difficulty - anchor.difficulty
    };
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

pub async fn spawn(cfg: crate::config::Net, db: Arc<Store>) -> anyhow::Result<NetHandle> {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());

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

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) = event {
                        match message.topic.as_str() {
                            TOP_ANCHOR => if let Ok(a) = bincode::deserialize::<Anchor>(&message.data) {
                                match validate_anchor(&a, &db) {
                                    Ok(()) => {
                                        if db.put("epoch", &a.num.to_le_bytes(), &a).is_ok() {
                                            let _ = db.put("epoch", b"latest", &a);
                                            let _ = anchor_tx.send(a);
                                        }
                                    }
                                    Err(err) => {
                                        eprintln!("🚫 REJECTED invalid anchor: {}", err);
                                    }
                                }
                            },
                            TOP_COIN => if let Ok(c) = bincode::deserialize::<Coin>(&message.data) {
                                // 🔒 CRITICAL SECURITY: Validate coin before storing to prevent forgery
                                match validate_coin(&c, &db) {
                                    Ok(()) => {
                                        if let Err(e) = db.put("coin", &c.id, &c) {
                                            eprintln!("🚨 Failed to store validated coin {}: {}", hex::encode(&c.id), e);
                                        } else {
                                            println!("✅ Accepted valid coin from network: {}", hex::encode(&c.id));
                                        }
                                    }
                                    Err(validation_error) => {
                                        eprintln!("🚫 REJECTED invalid coin from network: {}", validation_error);
                                        eprintln!("   Coin ID: {}", hex::encode(&c.id));
                                        eprintln!("   Epoch Hash: {}", hex::encode(&c.epoch_hash));
                                        eprintln!("   Creator: {}", hex::encode(&c.creator_address));
                                        eprintln!("   Nonce: {}", c.nonce);
                                        eprintln!("   PoW Hash: {}", hex::encode(&c.pow_hash));
                                        // Do not store invalid coins - this prevents forgery attacks
                                    }
                                }
                            },
                            TOP_TX => if let Ok(t) = bincode::deserialize::<Transfer>(&message.data) {
                                match validate_transfer(&t, &db) {
                                    Ok(()) => {
                                        if let Err(e) = db.put("transfer", &t.coin_id, &t) {
                                            eprintln!("🚨 Failed to store validated transfer for coin {}: {}", hex::encode(&t.coin_id), e);
                                        } else {
                                            println!("✅ Accepted valid transfer for coin {}", hex::encode(&t.coin_id));
                                        }
                                    }
                                    Err(err) => {
                                        eprintln!("🚫 REJECTED invalid transfer: {}", err);
                                        eprintln!("   Coin ID: {}", hex::encode(&t.coin_id));
                                        eprintln!("   To: {}", hex::encode(&t.to));
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
        println!("🔄 Requesting specific epoch #{} for recovery", epoch_num);
        self.request_epoch(epoch_num).await;
    }
}