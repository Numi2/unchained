use crate::{
    storage::Store, epoch::Anchor, coin::{Coin, CoinCandidate}, transfer::{Transfer, Spend}, crypto, config, sync::SyncState,
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

#[allow(dead_code)]
fn try_publish_gossip(
    swarm: &mut Swarm<Gossipsub<IdentityTransform, AllowAllSubscriptionFilter>>,
    topic: &str,
    data: Vec<u8>,
    context: &str,
) {
    if let Err(e) = swarm.behaviour_mut().publish(IdentTopic::new(topic), data) {
        // Some libp2p versions/forks use different variants for insufficient peers errors.
        // Fall back to string matching to avoid noisy logs while remaining compatible.
        let es = e.to_string();
        let is_insufficient = es.contains("InsufficientPeers") || es.contains("InsufficientPeersForTopic");
        if !is_insufficient {
            eprintln!("⚠️  Failed to publish {} ({}): {}", context, topic, es);
        }
    }
}

const TOP_ANCHOR: &str = "unchained/anchor/v1";
const TOP_COIN: &str = "unchained/coin/v1";
const TOP_COIN_PROOF_REQUEST: &str = "unchained/coin_proof_request/v1";
const TOP_COIN_PROOF_RESPONSE: &str = "unchained/coin_proof_response/v1";
const TOP_TX: &str = "unchained/tx/v1";
const TOP_SPEND: &str = "unchained/spend/v2";
const TOP_EPOCH_REQUEST: &str = "unchained/epoch_request/v1";
const TOP_COIN_REQUEST: &str = "unchained/coin_request/v1";
const TOP_LATEST_REQUEST: &str = "unchained/latest_request/v1";

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
    // Nullifier unseen check for uniqueness
    if db.get::<[u8; 1]>("nullifier", &tx.nullifier).unwrap().is_some() {
        return Err("Nullifier already seen (possible double spend)".into());
    }
    let sender_pk = PublicKey::from_bytes(&tx.sender_pk).map_err(|_| "Invalid sender PK")?;
    let sender_addr = crypto::address_from_pk(&sender_pk);
    if sender_addr != coin.creator_address { return Err("Sender is not coin creator".into()); }
    let sig = DetachedSignature::from_bytes(&tx.sig).map_err(|_| "Invalid signature")?;
    if verify_detached_signature(&sig, &tx.signing_bytes(), &sender_pk).is_err() { return Err("Invalid signature".into()); }
    // Basic stealth output sanity: ensure one-time pk decodes
    if pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&tx.to.one_time_pk).is_err() {
        return Err("Invalid one-time recipient public key".into());
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_spend(sp: &Spend, db: &Store) -> Result<(), String> {
    // no-op
    // Mirror Spend::validate but return String errors for network context
    let coin: Coin = db.get("coin", &sp.coin_id).unwrap().ok_or("Referenced coin does not exist")?;
    let anchor: Anchor = db.get("anchor", &coin.epoch_hash).unwrap().ok_or("Anchor not found for coin's epoch")?;
    if anchor.merkle_root != sp.root { return Err("Merkle root mismatch".into()); }
    let leaf = crate::coin::Coin::id_to_leaf_hash(&sp.coin_id);
    if !crate::epoch::MerkleTree::verify_proof(&leaf, &sp.proof, &sp.root) { return Err("Invalid Merkle proof".into()); }
    if db.get::<[u8;1]>("nullifier", &sp.nullifier).unwrap().is_some() { return Err("Nullifier already seen (double spend)".into()); }
    // Determine expected owner address
    let last_transfer: Option<Transfer> = db.get("transfer", &sp.coin_id).unwrap_or(None);
    let expected_owner_addr = match last_transfer {
        Some(ref t) => t.recipient(),
        None => coin.creator_address,
    };
    // Verify signature under last recipient one-time pk
    if let Some(t) = last_transfer {
        if let Ok(pk) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&t.to.one_time_pk) {
            if crate::crypto::address_from_pk(&pk) == expected_owner_addr {
                if let Ok(sig) = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(&sp.sig) {
                    if pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig, &sp.auth_bytes(), &pk).is_ok() {
                        return Ok(())
                    }
                }
            }
        }
        return Err("Invalid spend signature".into());
    } else {
        return Err("Cannot validate spend without previous owner pk (genesis spend requires legacy transfer)".into());
    }
}

fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    if anchor.hash == [0u8; 32] { return Err("Anchor hash cannot be zero".into()); }
    if anchor.difficulty == 0 { return Err("Difficulty cannot be zero".into()); }
    if anchor.mem_kib == 0 { return Err("Memory cannot be zero".into()); }
    if anchor.merkle_root == [0u8; 32] && anchor.coin_count > 0 { return Err("Merkle root cannot be zero when coins are present".into()); }
    if anchor.num == 0 {
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

pub type NetHandle = Arc<Network>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinProofRequest { pub coin_id: [u8; 32] }

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
    GossipSpend(Spend),
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
    for t in [TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_SPEND, TOP_EPOCH_REQUEST, TOP_COIN_REQUEST, TOP_LATEST_REQUEST, TOP_COIN_PROOF_REQUEST, TOP_COIN_PROOF_RESPONSE] {
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

    const MAX_ORPHAN_ANCHORS: usize = 1024;
    static RECENT_PROOF_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

    // Attempt to reorg to a better chain using buffered anchors.
    fn attempt_reorg(
        db: &Store,
        orphan_anchors: &mut HashMap<u64, Anchor>,
        anchor_tx: &broadcast::Sender<Anchor>,
        sync_state: &Arc<Mutex<SyncState>>,
        command_tx: &mpsc::UnboundedSender<NetworkCommand>,
    ) {
        let current_latest = match db.get::<Anchor>("epoch", b"latest") {
            Ok(Some(a)) => a,
            _ => return,
        };
        let Some(&max_buf_height) = orphan_anchors.keys().max() else { return };
        if max_buf_height <= current_latest.num { return; }

        // Build a contiguous segment ending at max_buf_height down to the first gap
        let mut segment: Vec<Anchor> = Vec::new();
        let mut h = max_buf_height;
        while let Some(a) = orphan_anchors.get(&h) {
            segment.push(a.clone());
            if h == 0 { break; }
            h -= 1;
        }
        if segment.is_empty() { return; }
        segment.reverse(); // ascending
        let fork_height = segment[0].num.saturating_sub(1);
        net_log!("🔎 Reorg: considering buffered segment {}..={} ({} epochs). Fork height candidate: {}",
            segment.first().map(|a| a.num).unwrap_or(0),
            segment.last().map(|a| a.num).unwrap_or(0),
            segment.len(),
            fork_height
        );

        // Need fork point present locally
        let Some(fork_anchor) = db.get::<Anchor>("epoch", &fork_height.to_le_bytes()).ok().flatten() else {
            net_log!("⛔ Reorg: missing local fork anchor at height {}", fork_height);
            // Proactively request the fork parent so we can validate and adopt the buffered segment
            let _ = command_tx.send(NetworkCommand::RequestEpoch(fork_height));
            return;
        };

        // Validate linkage and cumulative work across the segment
        let mut prev = fork_anchor.clone();
        for alt in &segment {
            let expected_work = Anchor::expected_work_for_difficulty(alt.difficulty);
            let expected_cum = prev.cumulative_work.saturating_add(expected_work);
            if alt.cumulative_work != expected_cum {
                net_log!("⛔ Reorg: cumulative work mismatch at {} (expected {}, got {})",
                    alt.num, expected_cum, alt.cumulative_work);
                return;
            }
            let mut hsh = blake3::Hasher::new();
            hsh.update(&alt.merkle_root);
            hsh.update(&prev.hash);
            let recomputed = *hsh.finalize().as_bytes();
            if alt.hash != recomputed {
                net_log!("⛔ Reorg: anchor hash mismatch at {} (recomputed {}, got {})",
                    alt.num, hex::encode(recomputed), hex::encode(alt.hash));
                return;
            }
            prev = alt.clone();
        }

        let seg_tip = segment.last().unwrap();
        if seg_tip.cumulative_work <= current_latest.cumulative_work {
            net_log!("ℹ️  Reorg: candidate tip #{} cum_work {} not better than current #{} cum_work {}",
                seg_tip.num, seg_tip.cumulative_work, current_latest.num, current_latest.cumulative_work);
            return;
        }

        // Adopt: overwrite epochs and latest pointer; reconcile per-epoch selected/leaves/coins to the new chain when possible
        let epoch_cf  = db.db.cf_handle("epoch").expect("epoch CF");
        let anchor_cf = db.db.cf_handle("anchor").expect("anchor CF");
        let sel_cf    = db.db.cf_handle("epoch_selected").expect("epoch_selected CF");
        let leaves_cf = db.db.cf_handle("epoch_leaves").expect("epoch_leaves CF");
        let coin_cf   = db.db.cf_handle("coin").expect("coin CF");
        let mut batch = WriteBatch::default();

        // Keep track of the parent as we walk the ascending segment so we can re-run deterministic selection
        let mut parent = fork_anchor.clone();
        for alt in &segment {
            // 1) Overwrite anchor mappings for this epoch and advance latest
            let ser = match bincode::serialize(alt) { Ok(v) => v, Err(_) => return };
            batch.put_cf(epoch_cf, alt.num.to_le_bytes(), &ser);
            batch.put_cf(epoch_cf, b"latest", &ser);
            batch.put_cf(anchor_cf, &alt.hash, &ser);

            // 2) Remove previously confirmed coins that belonged to the replaced chain at this epoch
            if let Ok(prev_selected_ids) = db.get_selected_coin_ids_for_epoch(alt.num) {
                for id in prev_selected_ids {
                    batch.delete_cf(coin_cf, &id);
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

            // 4) Attempt to reconstruct selected set using local candidates that reference the new parent
            //    Use the anchor-declared coin_count as the selection cap to match chain state.
            let mut candidates = match db.get_coin_candidates_by_epoch_hash(&parent.hash) {
                Ok(v) => v,
                Err(_) => Vec::new(),
            };
            if parent.difficulty > 0 {
                candidates.retain(|c| c.pow_hash.iter().take(parent.difficulty).all(|b| *b == 0));
            }
            // Select up to alt.coin_count by smallest pow_hash, tie-break by coin_id
            let cap = alt.coin_count as usize;
            if cap == 0 {
                // Nothing selected for this epoch; merkle_root must be zero to be valid (already validated earlier)
            } else if candidates.len() > cap {
                let _ = candidates.select_nth_unstable_by(cap - 1, |a, b| a
                    .pow_hash
                    .cmp(&b.pow_hash)
                    .then_with(|| a.id.cmp(&b.id))
                );
                candidates.truncate(cap);
                candidates.sort_by(|a, b| a.pow_hash.cmp(&b.pow_hash).then_with(|| a.id.cmp(&b.id)));
            } else {
                candidates.sort_by(|a, b| a.pow_hash.cmp(&b.pow_hash).then_with(|| a.id.cmp(&b.id)));
            }

            // Build leaves and root to verify against the adopted anchor
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
                // 5) Populate confirmed coins and per-epoch indexes to match the adopted anchor
                for cand in &candidates {
                    let coin = cand.clone().into_confirmed();
                    if let Ok(bytes) = bincode::serialize(&coin) {
                        batch.put_cf(coin_cf, &coin.id, &bytes);
                    }
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
                // Could not reconcile selected set locally; leave per-epoch indexes empty for this height
                // Proof serving will skip until coins are learned via normal gossip.
                net_log!(
                    "⚠️ Reorg: unable to reconstruct selected set for epoch {} (merkle {} vs computed {}, count {} vs {})",
                    alt.num,
                    hex::encode(alt.merkle_root),
                    hex::encode(computed_root),
                    alt.coin_count,
                    selected_ids.len()
                );
            }

            // Advance parent to this newly adopted anchor for the next height
            parent = alt.clone();
        }

        if let Err(e) = db.db.write(batch) {
            eprintln!("🔥 Reorg write failed: {}", e);
            return;
        }
        for alt in &segment { let _ = anchor_tx.send(alt.clone()); }
        {
            let mut st = sync_state.lock().unwrap();
            st.highest_seen_epoch = seg_tip.num;
        }
        for alt in &segment { orphan_anchors.remove(&alt.num); }
        net_log!("🔁 Reorg adopted up to epoch {} (better cumulative work)", seg_tip.num);
    }

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
                            let mut still_pending = VecDeque::new();
                            while let Some(cmd) = pending_commands.pop_front() {
                                let (t, data) = match &cmd {
                                NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                                 NetworkCommand::GossipCoin(c)   => (TOP_COIN, bincode::serialize(&c).ok()),
                                NetworkCommand::GossipTransfer(tx) => (TOP_TX, bincode::serialize(&tx).ok()),
                                NetworkCommand::GossipSpend(sp) => (TOP_SPEND, bincode::serialize(&sp).ok()),
                                NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                                NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                                NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok()),
                                NetworkCommand::RequestCoinProof(id) => (TOP_COIN_PROOF_REQUEST, bincode::serialize(&CoinProofRequest{ coin_id: *id }).ok()),
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
                            connected_peers.remove(&peer_id);
                            crate::metrics::PEERS.set(connected_peers.len() as i64);
                        },
                        SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) => {
                            let peer_id = message.source.unwrap_or_else(PeerId::random);
                            let topic_str = message.topic.as_str();
                            let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            // Do not rate-limit inbound anchors – they are essential for fast catch-up.
                            let rate_limit_exempt = topic_str == TOP_ANCHOR;
                            if score.is_banned() || (!rate_limit_exempt && !score.check_rate_limit()) { continue; }
                            
                            match topic_str {
                                TOP_ANCHOR => if let Ok( a) = bincode::deserialize::<Anchor>(&message.data) {
                                    // Ignore duplicate anchors we have already stored to reduce log and CPU spam
                                    if let Ok(Some(latest)) = db.get::<Anchor>("epoch", b"latest") {
                                        if a.num == latest.num && a.hash == latest.hash {
                                            // Silently drop duplicate
                                            continue;
                                        }
                                    }
                                    if score.check_rate_limit() {
                                        net_log!("⚓ Received anchor for epoch {} from peer: {}", a.num, peer_id);
                                    }
                                    // Attempt to process the received anchor.
                                    // If it fails because the parent is missing, buffer it.
                                    match validate_anchor(&a, &db) {
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
                                            }

                                             // Regardless of whether it was better, attempt to process any buffered fork anchors
                                            // that can now link from this height forward.
                                            let mut next_num = a.num + 1;
                                            while let Some(orphan) = orphan_anchors.remove(&next_num) {
                                                if validate_anchor(&orphan, &db).is_ok() {
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
                                             // After linking forward, attempt a reorg if a better buffered tip exists
                                             attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                            // Enforce orphan cap
                                            crate::metrics::ORPHAN_BUFFER_LEN.set(orphan_anchors.len() as i64);
                                            if orphan_anchors.len() > MAX_ORPHAN_ANCHORS {
                                                let oldest = *orphan_anchors.keys().min().unwrap();
                                                orphan_anchors.remove(&oldest);
                                                eprintln!("⚠️ Orphan buffer cap exceeded, dropping oldest epoch {}", oldest);
                                            }
                                        }
                                        Err(e) if e.starts_with("Previous anchor") => {
                                            net_log!("⏳ Buffering orphan anchor for epoch {}", a.num);
                                            orphan_anchors.insert(a.num, a.clone());
                                            
                                            let mut state = sync_state.lock().unwrap();
                                            if a.num > state.highest_seen_epoch {
                                                state.highest_seen_epoch = a.num;
                                            }
                                            // Proactively request the missing predecessor to accelerate linking the chain
                                            if a.num > 0 {
                                                let prev_epoch = a.num - 1;
                                                if let Ok(bytes) = bincode::serialize(&prev_epoch) {
                                                    let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                                }
                                            }
                                             // Try reorg as we may already have a contiguous buffered segment
                                             attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                        },
                                        Err(e) => {
                                            // Treat hash-mismatch as an alternate fork block at the same height.
                                            // This can legitimately occur if different miners produced different merkle roots.
                                            // We ignore it (not better chain) but do not penalize the peer, and we still
                                            // advance the highest_seen_epoch so heartbeat logic doesn’t flap.
                                            if e.contains("hash mismatch") {
                                                net_log!("🔀 Alternate fork anchor at height {} (hash mismatch) – buffering for reorg", a.num);
                                                // Buffer this anchor so once we obtain/confirm its predecessor we can advance this branch
                                                orphan_anchors.insert(a.num, a.clone());
                                                {
                                                    let mut st = sync_state.lock().unwrap();
                                                    if a.num > st.highest_seen_epoch {
                                                        st.highest_seen_epoch = a.num;
                                                    }
                                                }
                                                // Try to retrieve the predecessor to this fork height to see the competing chain
                                                if a.num > 0 {
                                                    let prev_epoch = a.num - 1;
                                                    if let Ok(bytes) = bincode::serialize(&prev_epoch) {
                                                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                                    }
                                                }
                                                // Attempt full reorg if alternate tip looks ahead
                                                attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                            } else {
                                                println!("❌ Anchor validation failed: {}", e);
                                                crate::metrics::VALIDATION_FAIL_ANCHOR.inc();
                                                score.record_validation_failure();
                                            }
                                        }
                                    }
                                },
                                TOP_COIN => if let Ok(c) = bincode::deserialize::<CoinCandidate>(&message.data) {
                                    if validate_coin_candidate(&c, &db).is_ok() {
                                        let key = Store::candidate_key(&c.epoch_hash, &c.id);
                                        db.put("coin_candidate", &key, &c).ok();
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_COIN.inc();
                                        score.record_validation_failure();
                                    }
                                },
                                TOP_TX => if let Ok(tx) = bincode::deserialize::<Transfer>(&message.data) {
                                    if validate_transfer(&tx, &db).is_ok() {
                                        db.put("transfer", &tx.coin_id, &tx).ok();
                                        let _ = db.put("nullifier", &tx.nullifier, &[1u8;1]);
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_TRANSFER.inc();
                                        score.record_validation_failure();
                                    }
                                },
                                TOP_SPEND => if let Ok(sp) = bincode::deserialize::<Spend>(&message.data) {
                                    if validate_spend(&sp, &db).is_ok() {
                                        db.put("spend", &sp.coin_id, &sp).ok();
                                        let _ = db.put("nullifier", &sp.nullifier, &[1u8;1]);
                                    } else {
                                        crate::metrics::VALIDATION_FAIL_TRANSFER.inc();
                                        score.record_validation_failure();
                                    }
                                },
                                TOP_LATEST_REQUEST => if let Ok(()) = bincode::deserialize::<()>(&message.data) {
                                    // Only log once every 5 seconds per peer to avoid spam
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
                                        }
                                    } else {
                                        net_log!("⚠️  Epoch {} not found", n);
                                    }
                                },
                                TOP_COIN_REQUEST => if let Ok(id) = bincode::deserialize::<[u8; 32]>(&message.data) {
                                    if let Ok(Some(coin)) = db.get::<Coin>("coin", &id) {
                                        if let Ok(data) = bincode::serialize(&coin) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), data).ok();
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
                    let (topic, data) = match &command {
                        NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                        NetworkCommand::GossipCoin(c) => (TOP_COIN, bincode::serialize(&c).ok()),
                        NetworkCommand::GossipTransfer(tx) => (TOP_TX, bincode::serialize(&tx).ok()),
                        NetworkCommand::GossipSpend(sp) => (TOP_SPEND, bincode::serialize(&sp).ok()),
                        NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                        NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                        NetworkCommand::RequestLatestEpoch => (TOP_LATEST_REQUEST, bincode::serialize(&()).ok()),
                        NetworkCommand::RequestCoinProof(id) => (TOP_COIN_PROOF_REQUEST, bincode::serialize(&CoinProofRequest{ coin_id: *id }).ok()),
                    };
                    if let Some(d) = data {
                        if swarm.behaviour_mut().publish(IdentTopic::new(topic), d.clone()).is_err() {
                            pending_commands.push_back(command);
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
    pub async fn gossip_coin(&self, c: &CoinCandidate) { let _ = self.command_tx.send(NetworkCommand::GossipCoin(c.clone())); }
    pub async fn gossip_transfer(&self, tx: &Transfer) { let _ = self.command_tx.send(NetworkCommand::GossipTransfer(tx.clone())); }
    pub async fn gossip_spend(&self, sp: &Spend) { let _ = self.command_tx.send(NetworkCommand::GossipSpend(sp.clone())); }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> { self.anchor_tx.subscribe() }
    pub fn proof_subscribe(&self) -> broadcast::Receiver<CoinProofResponse> { self.proof_tx.subscribe() }
    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> { self.anchor_tx.clone() }
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    pub async fn request_coin(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoin(id)); }
    pub async fn request_latest_epoch(&self) { let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch); }
    pub async fn request_coin_proof(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoinProof(id)); }
    
    /// Gets the current number of connected peers
    pub fn peer_count(&self) -> usize {
        // This would need to be implemented with a shared state between the network thread and this struct
        // For now, return a placeholder - in a full implementation, this would use Arc<Mutex<HashSet<PeerId>>>
        0 // TODO: Implement actual peer counting
    }
}
