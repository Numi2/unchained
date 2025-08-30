use crate::{storage::Store, network::NetHandle, coin::{Coin, CoinCandidate}};
use crate::consensus::{
    calculate_retarget_consensus,
    TARGET_LEADING_ZEROS,
    DEFAULT_MEM_KIB,
    RETARGET_INTERVAL,
};
use tokio::{sync::{broadcast, mpsc}, time};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use crate::sync::SyncState;
use rocksdb::WriteBatch;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Anchor {
    pub num:          u64,
    pub hash:         [u8; 32],
    pub merkle_root:  [u8; 32],
    pub difficulty:   usize,
    pub coin_count:   u32,
    pub cumulative_work: u128,
    pub mem_kib:      u32,
}

impl Anchor {
    pub fn expected_work_for_difficulty(difficulty: usize) -> u128 {
        if difficulty == 0 { 1 } else { 1u128 << (difficulty * 8) }
    }
    
    pub fn is_better_chain(&self, current_best: &Option<Anchor>) -> bool {
        match current_best {
            None => true,
            Some(best) => {
                if self.cumulative_work > best.cumulative_work { return true; }
                if self.cumulative_work == best.cumulative_work && self.num > best.num { return true; }
                // Deterministic tie-break: at equal work and height, prefer lexicographically smaller hash
                if self.cumulative_work == best.cumulative_work && self.num == best.num && self.hash < best.hash { return true; }
                false
            }
        }
    }

}

    

pub struct MerkleTree;
impl MerkleTree {
    /// Build all Merkle levels from sorted leaves. levels[0] = sorted leaves, levels.last()[0] = root.
    pub fn build_levels_from_sorted_leaves(sorted_leaves: &[[u8; 32]]) -> Vec<Vec<[u8;32]>> {
        let mut levels: Vec<Vec<[u8;32]>> = Vec::new();
        if sorted_leaves.is_empty() { return levels; }
        let mut level: Vec<[u8;32]> = sorted_leaves.to_vec();
        levels.push(level.clone());
        while level.len() > 1 {
            let mut next_level: Vec<[u8;32]> = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            levels.push(next_level.clone());
            level = next_level;
        }
        levels
    }

    /// Build proof using precomputed levels and target leaf hash. levels[0] must contain target_leaf.
    pub fn build_proof_from_levels(levels: &Vec<Vec<[u8;32]>>, target_leaf: &[u8;32]) -> Option<Vec<([u8;32], bool)>> {
        if levels.is_empty() { return None; }
        let mut index = levels[0].iter().position(|h| h == target_leaf)?;
        let mut proof: Vec<([u8;32], bool)> = Vec::new();
        for level in &levels[..levels.len()-1] {
            if level.is_empty() { return None; }
            let (sibling_hash, sibling_is_left) = if index % 2 == 0 {
                let sib = *level.get(index + 1).unwrap_or(&level[index]);
                (sib, false)
            } else {
                let sib = level[index - 1];
                (sib, true)
            };
            proof.push((sibling_hash, sibling_is_left));
            index /= 2;
        }
        Some(proof)
    }
    /// Compute Merkle root from a set of coin IDs. This method:
    /// - Hashes each coin id into a leaf using `Coin::id_to_leaf_hash`
    /// - Sorts leaves ascending to obtain a canonical order
    /// - Reduces pairwise (duplicate last when odd) using BLAKE3
    pub fn build_root(coin_ids: &HashSet<[u8; 32]>) -> [u8; 32] {
        if coin_ids.is_empty() { return [0u8; 32]; }
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(Coin::id_to_leaf_hash).collect();
        leaves.sort();
        Self::compute_root_from_sorted_leaves(&leaves)
    }
}
impl MerkleTree {
    /// Compute Merkle root from a precomputed sorted leaf list.
    /// The `sorted_leaves` slice MUST be sorted ascending.
    pub fn compute_root_from_sorted_leaves(sorted_leaves: &[[u8; 32]]) -> [u8; 32] {
        if sorted_leaves.is_empty() { return [0u8; 32]; }
        let mut level: Vec<[u8; 32]> = sorted_leaves.to_vec();
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            level = next_level;
        }
        level[0]
    }
    pub fn build_proof(
        coin_ids: &HashSet<[u8; 32]>,
        target_id: &[u8; 32],
    ) -> Option<Vec<([u8; 32], bool)>> {
        if coin_ids.is_empty() { return None; }
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(Coin::id_to_leaf_hash).collect();
        leaves.sort();
        let leaf_hash = Coin::id_to_leaf_hash(target_id);
        let mut index = leaves.iter().position(|h| h == &leaf_hash)?;
        let mut level = leaves;
        let mut proof: Vec<([u8; 32], bool)> = Vec::new();
        while level.len() > 1 {
            let (sibling_hash, sibling_is_left) = if index % 2 == 0 {
                let sib = *level.get(index + 1).unwrap_or(&level[index]);
                (sib, false)
            } else {
                let sib = level[index - 1];
                (sib, true)
            };
            proof.push((sibling_hash, sibling_is_left));
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            index /= 2;
            level = next_level;
        }
        Some(proof)
    }

    /// Build a Merkle proof using a precomputed sorted leaf list.
    /// `sorted_leaves` must be sorted ascending and contain `target_leaf`.
    pub fn build_proof_from_leaves(
        sorted_leaves: &[[u8; 32]],
        target_leaf: &[u8; 32],
    ) -> Option<Vec<([u8; 32], bool)>> {
        if sorted_leaves.is_empty() { return None; }
        let mut index = sorted_leaves.iter().position(|h| h == target_leaf)?;
        let mut level: Vec<[u8;32]> = sorted_leaves.to_vec();
        let mut proof: Vec<([u8; 32], bool)> = Vec::new();
        while level.len() > 1 {
            let (sibling_hash, sibling_is_left) = if index % 2 == 0 {
                let sib = *level.get(index + 1).unwrap_or(&level[index]);
                (sib, false)
            } else {
                let sib = level[index - 1];
                (sib, true)
            };
            proof.push((sibling_hash, sibling_is_left));
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            index /= 2;
            level = next_level;
        }
        Some(proof)
    }

    /// Maximum accepted Merkle depth for proofs. Conservative upper bound to
    /// reject pathological inputs without affecting valid trees.
    pub const MAX_PROOF_DEPTH: usize = 64;

    pub fn verify_proof(
        leaf_hash: &[u8; 32],
        proof: &[( [u8; 32], bool )],
        root: &[u8; 32],
    ) -> bool {
        // Basic sanity bound: prevents absurdly large proofs from causing CPU burn.
        if proof.len() > Self::MAX_PROOF_DEPTH { return false; }
        let mut computed = *leaf_hash;
        for (sibling, sibling_is_left) in proof {
            let mut hasher = blake3::Hasher::new();
            if *sibling_is_left {
                hasher.update(sibling);
                hasher.update(&computed);
            } else {
                hasher.update(&computed);
                hasher.update(sibling);
            }
            computed = *hasher.finalize().as_bytes();
        }
        &computed == root
    }

    /// Expected proof length (tree height) for a Merkle tree with `coin_count` leaves,
    /// using the canonical odd-node duplication strategy. For example:
    /// - 1 -> 0, 2 -> 1, 3..4 -> 2, 5..8 -> 3, etc.
    #[inline]
    pub fn expected_proof_len(coin_count: u32) -> usize {
        if coin_count <= 1 { 0 } else { (32 - (coin_count - 1).leading_zeros()) as usize }
    }
}

pub struct Manager {
    db:   Arc<Store>,
    cfg:  crate::config::Epoch,
    net_cfg: crate::config::Net,
    net:  NetHandle,
    anchor_tx: broadcast::Sender<Anchor>,
    coin_rx: mpsc::UnboundedReceiver<[u8; 32]>,
    shutdown_rx: broadcast::Receiver<()>,
    sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>,
    compact_cfg: crate::config::Compact,
}
impl Manager {
    pub fn new(
        db: Arc<Store>, 
        cfg: crate::config::Epoch, 
        net_cfg: crate::config::Net,
        net: NetHandle, 
        coin_rx: mpsc::UnboundedReceiver<[u8; 32]>,
        shutdown_rx: broadcast::Receiver<()>,
        sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>,
        compact_cfg: crate::config::Compact,
    ) -> Self {
        let anchor_tx = net.anchor_sender();
        Self { db, cfg, net_cfg, net, anchor_tx, coin_rx, shutdown_rx, sync_state, compact_cfg }
    }

    pub fn spawn_loop(mut self) {
        tokio::spawn(async move {
            let mut current_epoch = match self.db.get::<Anchor>("epoch", b"latest") {
                Ok(Some(anchor)) => anchor.num + 1,
                Ok(None) => 0,
                Err(_) => 0,
            };

            if current_epoch == 0 {
                println!("🔄 Initial network synchronization phase...");
                self.net.request_latest_epoch().await;

                let sync_timeout = tokio::time::Duration::from_secs(self.net_cfg.sync_timeout_secs);
                let sync_start = tokio::time::Instant::now();
                
                while sync_start.elapsed() < sync_timeout {
                    if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                       if latest_anchor.num > 0 {
                           current_epoch = latest_anchor.num + 1;
                           println!("✅ Network synchronization complete! Starting from epoch {}", current_epoch);
                           break;
                       }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                }
                
                if current_epoch == 0 {
                    if self.net_cfg.bootstrap.is_empty() {
                        println!("⚠️  Network synchronization timeout or no peers found. Starting from genesis (no bootstrap configured).");
                    } else {
                        println!("⚠️  Network sync timed out but bootstrap peers are configured; not creating local genesis. Waiting for network.");
                    }
                }
            }

            let mut buffer: HashSet<[u8; 32]> = HashSet::new();
            // Tick immediately on startup for all cases; no restart grace period
            let mut ticker = time::interval_at(time::Instant::now(), time::Duration::from_secs(self.cfg.seconds));
            // Prevent bursty catch-up ticks from causing multiple seals in quick succession.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Periodic candidate pull during the entire epoch interval
            let mut candidate_pull_ticker = time::interval(time::Duration::from_millis(500));
            candidate_pull_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    biased;
                    _ = self.shutdown_rx.recv() => {
                        println!("🛑 Epoch manager received shutdown signal");
                        break;
                    }
                    Some(id) = self.coin_rx.recv() => { 
                        buffer.insert(id);
                        crate::metrics::CANDIDATE_COINS.set(buffer.len() as i64);
                    },
                    _ = ticker.tick() => {
                        // When bootstrap peers are configured, strictly avoid producing epochs until fully synced with peers.
                        if !self.net_cfg.bootstrap.is_empty() {
                            let (synced, highest_seen, peer_confirmed) = self
                                .sync_state
                                .lock()
                                .map(|s| (s.synced, s.highest_seen_epoch, s.peer_confirmed_tip))
                                .unwrap_or((false, 0, false));
                            let local_latest = self.db.get::<Anchor>("epoch", b"latest").unwrap_or(None).map(|a| a.num).unwrap_or(0);
                            let fully_caught_up = local_latest >= highest_seen && highest_seen > 0;
                            if !(synced && fully_caught_up && peer_confirmed) {
                                // Keep requesting latest and fast-forward our cursor to any newly stored tip
                                self.net.request_latest_epoch().await;
                                if current_epoch > 0 {
                                    if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                                        if latest_anchor.num >= current_epoch {
                                            current_epoch = latest_anchor.num + 1;
                                        }
                                    }
                                }
                                println!(
                                    "⏳ Waiting for full sync before producing: local={}, network={}, peer-confirmed={}",
                                    local_latest, highest_seen, peer_confirmed
                                );
                                continue;
                            }
                        }
                    

                        if current_epoch == 0 && buffer.is_empty() {
                            if self.net_cfg.bootstrap.is_empty() {
                                println!("🌱 No existing epochs found. Creating genesis anchor (no bootstrap configured)...");
                            } else {
                                // Avoid creating a forked genesis when we expect a network
                                println!("⏳ Waiting for network genesis (bootstrap configured), not creating local genesis.");
                                continue;
                            }
                        }
                        

                        // Determine previous anchor (for epoch linkage and candidate filtering)
                        let prev_anchor = self.db.get::<Anchor>("epoch", &(current_epoch.saturating_sub(1)).to_le_bytes()).unwrap_or_default();

                        // Use canonical fair selection that ensures diversity across creators
                        let mut selected: Vec<CoinCandidate> = Vec::new();
                        if let Some(prev) = &prev_anchor {
                            let cap = self.cfg.max_coins_per_epoch as usize;
                            let (list, _total) = crate::epoch::select_candidates_for_epoch(&self.db, prev, cap, Some(&buffer));
                            selected = list;
                        }
                        if let Some(last) = selected.last() {
                            // approximate selection threshold: interpret first 8 bytes of pow_hash as u64
                            let mut eight = [0u8;8];
                            eight.copy_from_slice(&last.pow_hash[..8]);
                            crate::metrics::SELECTION_THRESHOLD_U64.set(u64::from_le_bytes(eight) as i64);
                        }

                        // Build Merkle root from selected coin IDs and persist sorted leaves for fast proofs
                        let selected_ids: HashSet<[u8; 32]> = selected.iter().map(|c| c.id).collect();
                        let mut leaves: Vec<[u8;32]> = selected_ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
                        leaves.sort();
                        // Avoid emitting empty epochs on existing chains. This prevents height from
                        // advancing without any economic activity and reduces potential fork surface.
                        if prev_anchor.is_some() && selected_ids.is_empty() {
                            continue;
                        }
                        let levels = MerkleTree::build_levels_from_sorted_leaves(&leaves);
                        let merkle_root = if levels.is_empty() { [0u8;32] } else { *levels.last().unwrap().first().unwrap() };
                        // Anchor hash commits to merkle_root and previous anchor hash (if any)
                        let hash = {
                            let mut h = blake3::Hasher::new();
                            h.update(&merkle_root);
                            if let Some(prev) = &prev_anchor { h.update(&prev.hash); }
                            *h.finalize().as_bytes()
                        };
                        
                        let (difficulty, mem_kib) = if current_epoch > 0 && current_epoch % RETARGET_INTERVAL == 0 {
                            let mut recent_anchors = Vec::new();
                            for i in 0..RETARGET_INTERVAL {
                                let epoch_num = current_epoch.saturating_sub(RETARGET_INTERVAL - i);
                                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                    recent_anchors.push(anchor);
                                }
                            }
                            calculate_retarget_consensus(&recent_anchors)
                        } else {
                            prev_anchor.as_ref().map_or((TARGET_LEADING_ZEROS, DEFAULT_MEM_KIB), |p| (p.difficulty, p.mem_kib))
                        };
                        
                        let current_work = Anchor::expected_work_for_difficulty(difficulty);
                        let cumulative_work = prev_anchor.as_ref().map_or(current_work, |p| p.cumulative_work.saturating_add(current_work));
                        
                        let anchor = Anchor { 
                            num: current_epoch, 
                            hash,
                            merkle_root,
                            difficulty, 
                            coin_count: selected_ids.len() as u32, 
                            cumulative_work, 
                            mem_kib,
                        };
                        
                        let mut batch = WriteBatch::default();
                        let serialized_anchor = match bincode::serialize(&anchor) {
                            Ok(data) => data,
                            Err(e) => {
                                eprintln!("🔥 Failed to serialize anchor: {}", e);
                                continue;
                            }
                        };
                        
                        let epoch_cf = match self.db.db.cf_handle("epoch") {
                            Some(cf) => cf,
                            None => {
                                eprintln!("🔥 'epoch' column family missing");
                                continue;
                            }
                        };
                        
                        batch.put_cf(epoch_cf, current_epoch.to_le_bytes(), &serialized_anchor);
                        batch.put_cf(epoch_cf, b"latest", &serialized_anchor);

                        // Persist selected coins into confirmed coin CF and index selected IDs per-epoch
                        if let (Some(coin_cf), Some(coin_epoch_cf)) = (self.db.db.cf_handle("coin"), self.db.db.cf_handle("coin_epoch")) {
                            for cand in &selected {
                                // Include creator_pk and lock_hash for spends
                                let coin = cand.clone().into_confirmed();
                                if let Ok(bytes) = bincode::serialize(&coin) {
                                    batch.put_cf(coin_cf, &coin.id, &bytes);
                                }
                                // Record the epoch number that committed this coin
                                batch.put_cf(coin_epoch_cf, &coin.id, &current_epoch.to_le_bytes());
                            }
                        } else if let Some(coin_cf) = self.db.db.cf_handle("coin") {
                            // Fallback: write coins even if coin_epoch CF is missing (should not happen)
                            for cand in &selected {
                                let coin = cand.clone().into_confirmed();
                                if let Ok(bytes) = bincode::serialize(&coin) {
                                    batch.put_cf(coin_cf, &coin.id, &bytes);
                                }
                            }
                        }
                        if let Some(sel_cf) = self.db.db.cf_handle("epoch_selected") {
                            // Key: epoch number (little endian) || coin_id
                            for coin in &selected_ids {
                                let mut key = Vec::with_capacity(8 + 32);
                                key.extend_from_slice(&current_epoch.to_le_bytes());
                                key.extend_from_slice(coin);
                                batch.put_cf(sel_cf, &key, &[]);
                            }
                        }
                        if let Err(e) = self.db.store_epoch_leaves(current_epoch, &leaves) { eprintln!("⚠️ Failed to store epoch leaves: {}", e); }
                        if let Err(e) = self.db.store_epoch_levels(current_epoch, &levels) { eprintln!("⚠️ Failed to store epoch levels: {}", e); }
                        
                        if let Some(anchor_cf) = self.db.db.cf_handle("anchor") {
                            batch.put_cf(anchor_cf, &hash, &serialized_anchor);
                        }
                        
                        if let Err(e) = self.db.write_batch(batch) {
                            eprintln!("🔥 Failed to write new epoch to DB: {e}");
                            continue;
                        } else {
                            crate::metrics::EPOCH_HEIGHT.set(current_epoch as i64);
                            crate::metrics::SELECTED_COINS.set(selected_ids.len() as i64);
                            // Gossip legacy anchor
                            self.net.gossip_anchor(&anchor).await;
                            // Also gossip compact epoch if enabled
                            if self.compact_cfg.enable {
                                // Build a compact message opportunistically: prefill first entries
                                let prefill_n = self.compact_cfg.prefill_count.min(selected.len() as u32);
                                let mut prefilled: Vec<(u32, crate::coin::Coin)> = Vec::new();
                                for (i, cand) in selected.iter().take(prefill_n as usize).enumerate() {
                                    prefilled.push((i as u32, cand.clone().into_confirmed()));
                                }
                                // Short IDs: first 8 bytes of BLAKE3(coin_id). Low collision rate in practice.
                                let mut short_ids: Vec<[u8;8]> = Vec::with_capacity(selected.len());
                                for cand in &selected {
                                    let mut hasher = blake3::Hasher::new();
                                    hasher.update(&cand.id);
                                    let full = *hasher.finalize().as_bytes();
                                    let mut short = [0u8;8];
                                    short.copy_from_slice(&full[..8]);
                                    short_ids.push(short);
                                }
                                let compact = crate::network::CompactEpoch { anchor: anchor.clone(), short_ids, prefilled };
                                self.net.gossip_compact_epoch(compact).await;
                                crate::metrics::COMPACT_EPOCHS_SENT.inc();
                            }
                            // Also gossip sorted leaves to help peers serve proofs deterministically
                            let bundle = crate::network::EpochLeavesBundle { epoch_num: current_epoch, merkle_root, leaves: leaves.clone() };
                            self.net.gossip_epoch_leaves(bundle).await;
                            if let Err(e) = self.anchor_tx.send(anchor) {
                                eprintln!("⚠️  Failed to broadcast anchor: {}", e);
                            }
                            // Prune candidates but keep a safety window of recent epoch hashes to support reorgs
                            if let Some(latest) = self.db.get::<Anchor>("epoch", b"latest").ok().flatten() {
                                let mut keep: Vec<[u8;32]> = Vec::new();
                                // Keep the new parent (current hash) and recent window of parents
                                keep.push(hash);
                                // Walk back up to 127 previous anchors (total ~128 hashes kept)
                                let mut n = latest.num;
                                let mut walked: u64 = 0;
                                while walked < 127 {
                                    if n == 0 { break; }
                                    if let Ok(Some(a)) = self.db.get::<Anchor>("epoch", &n.to_le_bytes()) {
                                        keep.push(a.hash);
                                    } else { break; }
                                    if n == 0 { break; }
                                    n = n.saturating_sub(1);
                                    walked += 1;
                                }
                                let _ = self.db.prune_candidates_keep_hashes(&keep.iter().collect::<Vec<_>>().iter().map(|h| **h).collect::<Vec<[u8;32]>>());
                            }
                            buffer.clear();
                            current_epoch += 1;
                            // Align next tick to now + epoch.seconds
                            ticker = time::interval_at(
                                time::Instant::now() + time::Duration::from_secs(self.cfg.seconds),
                                time::Duration::from_secs(self.cfg.seconds)
                            );
                            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        }
                    }
                    _ = candidate_pull_ticker.tick() => {
                        // Continuously pull candidates for the upcoming epoch's parent hash
                        if let Some(prev) = &self.db.get::<Anchor>("epoch", &(current_epoch.saturating_sub(1)).to_le_bytes()).unwrap_or_default() {
                            self.net.request_epoch_candidates(prev.hash).await;
                        }
                    }
                }
            }
            println!("✅ Epoch manager shutdown complete");
        });
    }
}

/// Select candidates for a specific epoch based on parent anchor and capacity
/// This function is used during reorgs to reconstruct the selected set
pub fn select_candidates_for_epoch(
    db: &crate::storage::Store,
    parent: &Anchor,
    cap: usize,
    buffer: Option<&std::collections::HashSet<[u8; 32]>>,
) -> (Vec<crate::coin::CoinCandidate>, usize) {
    // Collect candidates for this epoch hash and optionally merge locally buffered ids
    let mut candidates = match db.get_coin_candidates_by_epoch_hash(&parent.hash) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    // Track existing candidate IDs to avoid O(n^2) scans during merge
    let mut candidate_ids: std::collections::HashSet<[u8;32]> =
        std::collections::HashSet::from_iter(candidates.iter().map(|c| c.id));
    if let Some(buf) = buffer {
        for id in buf.iter() {
            if candidate_ids.contains(id) { continue; }
            let key = crate::storage::Store::candidate_key(&parent.hash, id);
            if let Ok(Some(c)) = db.get::<crate::coin::CoinCandidate>("coin_candidate", &key) {
                candidate_ids.insert(c.id);
                candidates.push(c);
            }
        }
    }

    if cap == 0 {
        return (Vec::new(), 0);
    }

    // Filter by PoW difficulty
    let mut filtered: Vec<crate::coin::CoinCandidate> = Vec::new();
    let mut total_candidates = 0usize;
    for cand in candidates.into_iter() {
        if parent.difficulty > 0 && !cand.pow_hash.iter().take(parent.difficulty).all(|b| *b == 0) {
            continue;
        }
        total_candidates += 1;
        filtered.push(cand);
    }

    // Global order by pow_hash, then id (deterministic)
    filtered.sort_by(|a, b| a.pow_hash.cmp(&b.pow_hash).then_with(|| a.id.cmp(&b.id)));

    // Fair, round-based selection across creators while preserving global order.
    use std::collections::{HashMap, HashSet};
    let mut picked: Vec<crate::coin::CoinCandidate> = Vec::with_capacity(cap);
    let mut by_creator: HashMap<[u8;32], usize> = HashMap::new();
    let mut round: usize = 0;
    let mut picked_ids: HashSet<[u8;32]> = HashSet::new();

    while picked.len() < cap {
        let mut advanced = false;
        for c in filtered.iter() {
            if picked.len() >= cap { break; }
            let cnt = *by_creator.get(&c.creator_address).unwrap_or(&0);
            if cnt == round && !picked_ids.contains(&c.id) {
                picked.push(c.clone());
                picked_ids.insert(c.id);
                by_creator.insert(c.creator_address, cnt + 1);
                advanced = true;
                if picked.len() >= cap { break; }
            }
        }
        if !advanced { break; }
        round += 1;
    }

    // Ensure deterministic ordering of the selected set
    picked.sort_by(|a, b| a.pow_hash.cmp(&b.pow_hash).then_with(|| a.id.cmp(&b.id)));

    (picked, total_candidates)
}
