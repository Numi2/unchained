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
const TOP_TX_REQUEST: &str = "unchained/tx_request/v1";          // payload: [u8;32] coin_id
const TOP_TX_RESPONSE: &str = "unchained/tx_response/v1";        // payload: Option<Transfer>
const TOP_SPEND_REQUEST: &str = "unchained/spend_request/v2";    // payload: [u8;32] coin_id
const TOP_SPEND_RESPONSE: &str = "unchained/spend_response/v2";  // payload: Option<Spend>
const TOP_EPOCH_REQUEST: &str = "unchained/epoch_request/v1";
const TOP_COIN_REQUEST: &str = "unchained/coin_request/v1";
const TOP_LATEST_REQUEST: &str = "unchained/latest_request/v1";
const TOP_PEER_ADDR: &str = "unchained/peer_addr/v1";         // payload: String multiaddr

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
    // Delegate to the canonical validator implemented in transfer.rs
    tx.validate(db).map_err(|e| e.to_string())
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
    connected_peers: Arc<Mutex<HashSet<PeerId>>>,
}

#[derive(Debug, Clone)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(CoinCandidate),
    GossipTransfer(Transfer),
    GossipSpend(Spend),
    RequestEpoch(u64),
    RequestTx([u8;32]),
    RequestSpend([u8;32]),
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
        .mesh_outbound_min(1)
        .mesh_n(6)
        .mesh_n_high(12)
        .flood_publish(false)
        .build()?;
        
    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub_config,
    ).map_err(|e| anyhow::anyhow!(e))?;
    for t in [
        TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_SPEND,
        TOP_EPOCH_REQUEST, TOP_COIN_REQUEST, TOP_LATEST_REQUEST,
        TOP_COIN_PROOF_REQUEST, TOP_COIN_PROOF_RESPONSE,
        TOP_TX_REQUEST, TOP_TX_RESPONSE, TOP_SPEND_REQUEST, TOP_SPEND_RESPONSE,
        TOP_PEER_ADDR,
    ] {
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

    let connected_peers: Arc<Mutex<HashSet<PeerId>>> = Arc::new(Mutex::new(HashSet::new()));

    // Also try dialing any previously stored peers
    if let Ok(addrs) = db.load_peer_addrs() {
        let mut dialed = 0usize;
        let cap = net_cfg.max_peers as usize;
        for addr in addrs {
            if dialed >= cap { break; }
            if net_cfg.bootstrap.contains(&addr) { continue; }
            // Basic filter: only dial /ip4/*/udp/*/quic-v1/p2p/<id>
            if !addr.starts_with("/ip4/") || !addr.contains("/udp/") || !addr.contains("/quic-v1/") || !addr.contains("/p2p/") { continue; }
            // Avoid dialing ourselves if persisted
            if let Some(id_str) = addr.split("/p2p/").last() { if id_str == swarm.local_peer_id().to_string() { continue; } }
            if let Some(ip_str) = addr.split('/').nth(3) {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() { if ip.is_private() || ip.is_loopback() { continue; } }
            }
            if let Ok(maddr) = addr.parse::<Multiaddr>() {
                if connected_peers.lock().unwrap().len() + dialed < cap {
                    net_log!("🔗 Dialing stored peer: {}", addr);
                    let _ = swarm.dial(maddr);
                    dialed += 1;
                } else { break; }
            }
        }
    }

    let (anchor_tx, _) = broadcast::channel(256);
    let (proof_tx, _) = broadcast::channel(256);
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), proof_tx: proof_tx.clone(), command_tx: command_tx.clone(), connected_peers: connected_peers.clone() });

    let mut peer_scores: HashMap<PeerId, PeerScore> = HashMap::new();
    let mut pending_commands: VecDeque<NetworkCommand> = VecDeque::new();
    let mut orphan_anchors: HashMap<u64, Vec<Anchor>> = HashMap::new();

    const MAX_ORPHAN_ANCHORS: usize = 1024;
    static RECENT_PROOF_REQS: Lazy<Mutex<std::collections::HashMap<[u8;32], std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    // Dedupe outgoing epoch requests to avoid spamming the network when we're blocked on a missing fork parent
    static RECENT_EPOCH_REQS: Lazy<Mutex<std::collections::HashMap<u64, std::time::Instant>>> = Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
    const EPOCH_REQ_DEDUP_SECS: u64 = 5;
    const REORG_BACKFILL: u64 = 16; // proactively backfill up to 16 predecessors on hash mismatch

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
        net_log!("🔎 Reorg: considering buffered segment {}..={} ({} epochs). Fork height candidate: {}",
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
            net_log!("⛔ Reorg: missing fork anchor at height {} (local and alternates)", fork_height);
            // Request a backfill window ending at fork_height to discover the competing parent
            let start = fork_height.saturating_sub(REORG_BACKFILL);
            for n in start..=fork_height { let _ = command_tx.send(NetworkCommand::RequestEpoch(n)); }
            return;
        }

        // Try to assemble a valid alternate branch from first_height..=max_buf_height by selecting, at each
        // height, the candidate whose hash links to the current parent. Start by trying all candidate parents.
        let mut chosen_chain: Vec<Anchor> = Vec::new();
        let mut resolved_parent: Option<Anchor> = None;
        let mut current_parents = parent_candidates;
        for height in first_height..=max_buf_height {
            let Some(cands) = orphan_anchors.get(&height) else { break; };
            if cands.is_empty() { break; }
            let mut linked: Option<(Anchor, Anchor)> = None; // (next, parent)
            'parent_loop: for p in &current_parents {
                for alt in cands {
                    let expected_work = Anchor::expected_work_for_difficulty(alt.difficulty);
                    let expected_cum = p.cumulative_work.saturating_add(expected_work);
                    if alt.cumulative_work != expected_cum { continue; }
                    let mut hsh = blake3::Hasher::new();
                    hsh.update(&alt.merkle_root);
                    hsh.update(&p.hash);
                    let recomputed = *hsh.finalize().as_bytes();
                    if alt.hash == recomputed {
                        linked = Some((alt.clone(), p.clone()));
                        break 'parent_loop;
                    }
                }
            }
            if let Some((next, p)) = linked {
                if resolved_parent.is_none() { resolved_parent = Some(p); }
                chosen_chain.push(next.clone());
                current_parents = vec![next];
            } else {
                net_log!("⛔ Reorg: anchor hash mismatch at {} (no candidate links to provided parents)", height);
                // Proactively request a window of predecessors up to the fork height to retrieve the missing parent chain
                if height > 0 {
                    let start = fork_height.saturating_sub(REORG_BACKFILL);
                    let end = height - 1;
                    for n in start..=end { let _ = command_tx.send(NetworkCommand::RequestEpoch(n)); }
                }
                let _ = command_tx.send(NetworkCommand::RequestEpoch(fork_height));
                return;
            }
        }
        if chosen_chain.is_empty() { return; }

        let seg_tip = chosen_chain.last().unwrap();
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
        let mut parent = resolved_parent.expect("parent must be set when chosen_chain is non-empty");
        for alt in &chosen_chain {
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
        for alt in &chosen_chain { let _ = anchor_tx.send(alt.clone()); }
        {
            let mut st = sync_state.lock().unwrap();
            st.highest_seen_epoch = seg_tip.num;
        }
        // Remove adopted anchors from buffer while keeping other alternates
        for alt in &chosen_chain {
            if let Some(vec) = orphan_anchors.get_mut(&alt.num) {
                vec.retain(|a| a.hash != alt.hash);
                if vec.is_empty() { orphan_anchors.remove(&alt.num); }
            }
        }
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
                            {
                                let mut set = connected_peers.lock().unwrap();
                                set.insert(peer_id);
                                crate::metrics::PEERS.set(set.len() as i64);
                            }
                            // After connecting, exchange our external address (if enabled) to help others connect
                            if net_cfg.peer_exchange {
                                let to_advertise = if let Some(public_ip) = net_cfg.public_ip.clone() {
                                    Some(format!("/ip4/{}/udp/{}/quic-v1/p2p/{}", public_ip, port, swarm.local_peer_id()))
                                } else {
                                    swarm.external_addresses().next().map(|a| format!("{}/p2p/{}", a, swarm.local_peer_id()))
                                };
                                if let Some(addr) = to_advertise {
                                    // Only advertise if it looks public and not loopback/private
                                    let ok_public = addr.starts_with("/ip4/") && addr.contains("/udp/") && addr.contains("/quic-v1/");
                                    if ok_public {
                                        if let Some(ip_str) = addr.split('/').nth(3) {
                                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                                if !ip.is_private() && !ip.is_loopback() {
                                                    if let Ok(data) = bincode::serialize(&addr) {
                                                        try_publish_gossip(&mut swarm, TOP_PEER_ADDR, data, "peer-addr");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
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
                                NetworkCommand::RequestTx(id) => (TOP_TX_REQUEST, bincode::serialize(&id).ok()),
                                NetworkCommand::RequestSpend(id) => (TOP_SPEND_REQUEST, bincode::serialize(&id).ok()),
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
                            {
                                let mut set = connected_peers.lock().unwrap();
                                set.remove(&peer_id);
                                crate::metrics::PEERS.set(set.len() as i64);
                            }
                        },
                        SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) => {
                            // Require authenticated source (we configure Signed authenticity). Skip if missing.
                            let Some(peer_id) = message.source else { continue };
                            let topic_str = message.topic.as_str();
                            let score = peer_scores.entry(peer_id).or_insert_with(|| PeerScore::new(&p2p_cfg));
                            // Do not rate-limit inbound anchors – they are essential for fast catch-up.
                            let rate_limit_exempt = topic_str == TOP_ANCHOR;
                            if score.is_banned() || (!rate_limit_exempt && !score.check_rate_limit()) { continue; }
                            
                            match topic_str {
                                TOP_PEER_ADDR => if net_cfg.peer_exchange {
                                    if let Ok(addr) = bincode::deserialize::<String>(&message.data) {
                                        // Only accept /ip4/*/udp/*/quic-v1/p2p/<peer_id>
                                        if !addr.starts_with("/ip4/") || !addr.contains("/udp/") || !addr.contains("/quic-v1/") { continue; }
                                        let Some(id_str) = addr.split("/p2p/").last() else { continue };
                                        // Skip our own address
                                        if id_str == swarm.local_peer_id().to_string() { continue; }
                                        // Skip private/loopback ip4
                                        if let Some(ip_str) = addr.split('/').nth(3) {
                                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() { if ip.is_private() || ip.is_loopback() { continue; } }
                                        }
                                        if addr.parse::<Multiaddr>().is_err() { continue; }
                                        // Persist and best-effort dial if under peer cap
                                        db.store_peer_addr(&addr).ok();
                                        if connected_peers.lock().unwrap().len() < net_cfg.max_peers as usize {
                                            if let Ok(m) = addr.parse::<Multiaddr>() { let _ = swarm.dial(m); }
                                        }
                                    }
                                },
                                TOP_ANCHOR => if let Ok( a) = bincode::deserialize::<Anchor>(&message.data) {
                                    // Ignore duplicate anchors we have already stored to reduce log and CPU spam
                                    if let Ok(Some(latest)) = db.get::<Anchor>("epoch", b"latest") {
                                        if a.num == latest.num && a.hash == latest.hash {
                                            // Treat duplicate as peer confirmation of our tip
                                            {
                                                let mut st = sync_state.lock().unwrap();
                                                if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                st.peer_confirmed_tip = true;
                                            }
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
                                            // Any valid anchor received implies we have a responsive peer
                                            {
                                                let mut st = sync_state.lock().unwrap();
                                                if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                st.peer_confirmed_tip = true;
                                            }
                                            if a.is_better_chain(&db.get("epoch", b"latest").unwrap_or(None)) {
                                                net_log!("✅ Storing anchor for epoch {}", a.num);
                                                if db.put("epoch", &a.num.to_le_bytes(), &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                if db.put("anchor", &a.hash, &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                if db.put("epoch", b"latest", &a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                                let _ = anchor_tx.send(a.clone());

                                                // Attempt to reconstruct and persist the selected set for this adopted anchor so
                                                // local services (wallet balance, proofs) have confirmed coins available.
                                                if a.num > 0 {
                                                    if let Ok(Some(parent)) = db.get::<Anchor>("epoch", &(a.num - 1).to_le_bytes()) {
                                                        // Gather candidates that reference the parent hash
                                                        let mut candidates = match db.get_coin_candidates_by_epoch_hash(&parent.hash) {
                                                            Ok(v) => v,
                                                            Err(_) => Vec::new(),
                                                        };
                                                        if parent.difficulty > 0 {
                                                            candidates.retain(|c| c.pow_hash.iter().take(parent.difficulty).all(|b| *b == 0));
                                                        }
                                                        // Select up to the anchor-declared coin_count by smallest pow_hash
                                                        let cap = a.coin_count as usize;
                                                        if cap == 0 {
                                                            // Nothing selected for this epoch
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

                                                        // Build leaves and verify against the adopted merkle_root
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

                                                        if computed_root == a.merkle_root && selected_ids.len() as u32 == a.coin_count {
                                                            // Persist confirmed coins and per-epoch indexes for this height
                                                            if let (Some(coin_cf), Some(sel_cf), Some(leaves_cf)) = (
                                                                db.db.cf_handle("coin"),
                                                                db.db.cf_handle("epoch_selected"),
                                                                db.db.cf_handle("epoch_leaves"),
                                                            ) {
                                                                let mut batch = rocksdb::WriteBatch::default();
                                                                for cand in &candidates {
                                                                    let coin = cand.clone().into_confirmed();
                                                                    if let Ok(bytes) = bincode::serialize(&coin) {
                                                                        batch.put_cf(coin_cf, &coin.id, &bytes);
                                                                    }
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
                                                                }
                                                            }
                                                        } else {
                                                            net_log!("ℹ️ Unable to reconstruct selected set for adopted epoch {} (root/count mismatch)", a.num);
                                                        }
                                                    }
                                                }
                                            }

                                            // If this valid anchor is not adopted (either equal to current or not better),
                                            // and it conflicts with the stored anchor at the same height, buffer it as an
                                            // alternate so reorg can consider it as a fork parent.
                                            if let Ok(Some(existing)) = db.get::<Anchor>("epoch", &a.num.to_le_bytes()) {
                                                if existing.hash != a.hash {
                                                    let entry = orphan_anchors.entry(a.num).or_default();
                                                    if !entry.iter().any(|x| x.hash == a.hash) {
                                                        net_log!("🔀 Buffered alternate anchor at height {} (valid but not adopted)", a.num);
                                                        entry.push(a.clone());
                                                    }
                                                }
                                            }

                                             // After adoption, rely on the reorg procedure to evaluate any buffered
                                             // alternate branches that can now link from this height forward.
                                             attempt_reorg(&db, &mut orphan_anchors, &anchor_tx, &sync_state, &command_tx);
                                            // Enforce orphan cap
                                             let orphan_len: usize = orphan_anchors.values().map(|v| v.len()).sum();
                                             crate::metrics::ORPHAN_BUFFER_LEN.set(orphan_len as i64);
                                             if orphan_len > MAX_ORPHAN_ANCHORS {
                                                 if let Some(&oldest) = orphan_anchors.keys().min() {
                                                     orphan_anchors.remove(&oldest);
                                                     eprintln!("⚠️ Orphan buffer cap exceeded, dropping oldest epoch {}", oldest);
                                                 }
                                             }
                                        }
                                        Err(e) if e.starts_with("Previous anchor") => {
                                            net_log!("⏳ Buffering orphan anchor for epoch {}", a.num);
                                             let entry = orphan_anchors.entry(a.num).or_default();
                                             if !entry.iter().any(|x| x.hash == a.hash) { entry.push(a.clone()); }
                                             
                                             let mut state = sync_state.lock().unwrap();
                                            if a.num > state.highest_seen_epoch {
                                                state.highest_seen_epoch = a.num;
                                            }
                                              state.peer_confirmed_tip = true;
                                            // Proactively request the missing predecessor to accelerate linking the chain
                                                 if a.num > 0 {
                                                 let now = std::time::Instant::now();
                                                 // Trim old entries
                                                 {
                                                     let mut map = RECENT_EPOCH_REQS.lock().unwrap();
                                                     map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                                                 }
                                                 // Request immediate predecessor if not recently requested
                                                 let prev_epoch = a.num - 1;
                                                 let mut map = RECENT_EPOCH_REQS.lock().unwrap();
                                                 if !map.contains_key(&prev_epoch) {
                                                     if let Ok(bytes) = bincode::serialize(&prev_epoch) {
                                                         let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                                         map.insert(prev_epoch, now);
                                                     }
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
                                                 let entry = orphan_anchors.entry(a.num).or_default();
                                                 if !entry.iter().any(|x| x.hash == a.hash) { entry.push(a.clone()); }
                                                 // Proactively request a backfill window of predecessors to locate the true fork point
                                                 if a.num > 0 {
                                                     let now = std::time::Instant::now();
                                                     {
                                                         // GC old dedupe entries
                                                         let mut map = RECENT_EPOCH_REQS.lock().unwrap();
                                                         map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                                                     }
                                                     let start = a.num.saturating_sub(REORG_BACKFILL);
                                                     let end = a.num - 1;
                                                     let mut map = RECENT_EPOCH_REQS.lock().unwrap();
                                                     for n in start..=end {
                                                         if !map.contains_key(&n) {
                                                             if let Ok(bytes) = bincode::serialize(&n) {
                                                                 let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_EPOCH_REQUEST), bytes);
                                                                 map.insert(n, now);
                                                             }
                                                         }
                                                     }
                                                 }
                                                  // Mark that we observed a peer tip even if not adopted
                                                  {
                                                      let mut st = sync_state.lock().unwrap();
                                                      if a.num > st.highest_seen_epoch { st.highest_seen_epoch = a.num; }
                                                      st.peer_confirmed_tip = true;
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
                                TOP_COIN => {
                                    // First, try to interpret as a confirmed Coin (responses to TOP_COIN_REQUEST)
                                    if let Ok(coin) = bincode::deserialize::<Coin>(&message.data) {
                                        // Persist confirmed coin so wallet balance and proofs work locally
                                        db.put("coin", &coin.id, &coin).ok();
                                        // Best-effort: index under epoch_selected using anchor lookup by epoch_hash
                                        if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &coin.epoch_hash) {
                                            if let Some(sel_cf) = db.db.cf_handle("epoch_selected") {
                                                let mut key = Vec::with_capacity(8 + 32);
                                                key.extend_from_slice(&anchor.num.to_le_bytes());
                                                key.extend_from_slice(&coin.id);
                                                let mut batch = rocksdb::WriteBatch::default();
                                                batch.put_cf(sel_cf, &key, &[]);
                                                let _ = db.db.write(batch);
                                            }
                                        }
                                    } else if let Ok(cand) = bincode::deserialize::<CoinCandidate>(&message.data) {
                                        // Else, treat as a coin candidate gossip
                                        if validate_coin_candidate(&cand, &db).is_ok() {
                                            let key = Store::candidate_key(&cand.epoch_hash, &cand.id);
                                            db.put("coin_candidate", &key, &cand).ok();
                                        } else {
                                            crate::metrics::VALIDATION_FAIL_COIN.inc();
                                            score.record_validation_failure();
                                        }
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
                                TOP_TX_REQUEST => if let Ok(coin_id) = bincode::deserialize::<[u8;32]>(&message.data) {
                                    if let Ok(Some(tx)) = db.get::<Transfer>("transfer", &coin_id) {
                                        if let Ok(data) = bincode::serialize(&Some(tx)) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_TX_RESPONSE), data).ok();
                                        }
                                    } else {
                                        // answer with None to let requester stop retrying
                                        if let Ok(data) = bincode::serialize(&Option::<Transfer>::None) {
                                            swarm.behaviour_mut().publish(IdentTopic::new(TOP_TX_RESPONSE), data).ok();
                                        }
                                    }
                                },
                                TOP_TX_RESPONSE => if let Ok(resp) = bincode::deserialize::<Option<Transfer>>(&message.data) {
                                    if let Some(tx) = resp {
                                        if validate_transfer(&tx, &db).is_ok() {
                                            db.put("transfer", &tx.coin_id, &tx).ok();
                                            let _ = db.put("nullifier", &tx.nullifier, &[1u8;1]);
                                        }
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
                                TOP_SPEND_REQUEST => if let Ok(coin_id) = bincode::deserialize::<[u8;32]>(&message.data) {
                                    if let Ok(Some(sp)) = db.get::<Spend>("spend", &coin_id) {
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
                                        if validate_spend(&sp, &db).is_ok() {
                                            db.put("spend", &sp.coin_id, &sp).ok();
                                            let _ = db.put("nullifier", &sp.nullifier, &[1u8;1]);
                                        }
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
                    match &command {
                        NetworkCommand::RequestEpoch(n) => {
                            // Dedupe request spam
                            let now = std::time::Instant::now();
                            {
                                let mut map = RECENT_EPOCH_REQS.lock().unwrap();
                                map.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_SECS));
                            }
                            let mut map = RECENT_EPOCH_REQS.lock().unwrap();
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
                        NetworkCommand::GossipTransfer(tx) => {
                            if let Ok(data) = bincode::serialize(tx) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_TX), data).is_err() {
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
                        NetworkCommand::RequestTx(id) => {
                            if let Ok(data) = bincode::serialize(id) {
                                if swarm.behaviour_mut().publish(IdentTopic::new(TOP_TX_REQUEST), data).is_err() {
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
    pub async fn request_tx(&self, id: [u8;32]) { let _ = self.command_tx.send(NetworkCommand::RequestTx(id)); }
    pub async fn request_spend(&self, id: [u8;32]) { let _ = self.command_tx.send(NetworkCommand::RequestSpend(id)); }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> { self.anchor_tx.subscribe() }
    pub fn proof_subscribe(&self) -> broadcast::Receiver<CoinProofResponse> { self.proof_tx.subscribe() }
    pub fn anchor_sender(&self) -> broadcast::Sender<Anchor> { self.anchor_tx.clone() }
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    pub async fn request_coin(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoin(id)); }
    pub async fn request_latest_epoch(&self) { let _ = self.command_tx.send(NetworkCommand::RequestLatestEpoch); }
    pub async fn request_coin_proof(&self, id: [u8; 32]) { let _ = self.command_tx.send(NetworkCommand::RequestCoinProof(id)); }
    
    /// Gets the current number of connected peers
    pub fn peer_count(&self) -> usize {
        self.connected_peers.lock().unwrap().len()
    }
}
