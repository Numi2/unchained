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
                false
            }
        }
    }

    /// Expose retargeting as an associated function for tests/backwards compat
    pub fn calculate_retarget(
        recent_anchors: &[Anchor],
        cfg: &crate::config::Epoch,
        mining_cfg: &crate::config::Mining,
    ) -> (usize, u32) {
        crate::epoch::calculate_retarget(recent_anchors, cfg, mining_cfg)
    }
}

pub fn calculate_retarget(
    recent_anchors: &[Anchor], 
    cfg: &crate::config::Epoch,
    mining_cfg: &crate::config::Mining
) -> (usize, u32) {
        if recent_anchors.is_empty() {
            return (cfg.target_leading_zeros, mining_cfg.mem_kib);
        }
        
        let last_anchor = recent_anchors.last().unwrap();
        let total_coins: u64 = recent_anchors.iter().map(|a| a.coin_count as u64).sum();
        let num_anchors = recent_anchors.len() as u64;

        const PRECISION: u64 = 1_000_000;

        let avg_coins_x_precision = (total_coins * PRECISION) / num_anchors;
        let target_coins_x_precision = cfg.target_coins_per_epoch as u64 * PRECISION;

         let new_difficulty = {
            let current_difficulty = last_anchor.difficulty as u64;
             let upper = (target_coins_x_precision * cfg.retarget_upper_pct / 100) as u64;
             let lower = (target_coins_x_precision * cfg.retarget_lower_pct / 100) as u64;
             let next = if avg_coins_x_precision > upper {
                 current_difficulty + 1
             } else if avg_coins_x_precision < lower {
                 current_difficulty.saturating_sub(1)
            } else {
                 current_difficulty
             } as usize;
             next.clamp(cfg.difficulty_min, cfg.difficulty_max)
        };
        
        let new_mem = {
            let current_mem = last_anchor.mem_kib as u64;
            let mem_adjustment_ratio_x_precision = if avg_coins_x_precision > 0 {
                (target_coins_x_precision * PRECISION) / avg_coins_x_precision
            } else {
                PRECISION
            };

            let max_adj = (mining_cfg.max_memory_adjustment * PRECISION as f64) as u64;
            let min_adj = (PRECISION as f64 / mining_cfg.max_memory_adjustment) as u64;
            let clamped_ratio_x_precision = mem_adjustment_ratio_x_precision.clamp(min_adj, max_adj);

            ((current_mem * clamped_ratio_x_precision) / PRECISION) as u32
        };
        
        (new_difficulty, new_mem.clamp(mining_cfg.min_mem_kib, mining_cfg.max_mem_kib))
    }

pub struct MerkleTree;
impl MerkleTree {
    pub fn build_root(coin_ids: &HashSet<[u8; 32]>) -> [u8; 32] {
        if coin_ids.is_empty() { return [0u8; 32]; }
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(Coin::id_to_leaf_hash).collect();
        leaves.sort();
        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            leaves = next_level;
        }
        leaves[0]
    }
}
impl MerkleTree {
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

    pub fn verify_proof(
        leaf_hash: &[u8; 32],
        proof: &[( [u8; 32], bool )],
        root: &[u8; 32],
    ) -> bool {
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
    ) -> Self {
        let anchor_tx = net.anchor_sender();
        Self { db, cfg, net_cfg, net, anchor_tx, coin_rx, shutdown_rx, sync_state }
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
            // Only tick immediately for genesis. For existing chains, wait a full interval to avoid
            // advancing the epoch immediately on node restarts, which can cause unnecessary height bumps.
            let mut ticker = if current_epoch == 0 {
                time::interval_at(time::Instant::now(), time::Duration::from_secs(self.cfg.seconds))
            } else {
                time::interval(time::Duration::from_secs(self.cfg.seconds))
            };

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
                        // When bootstrap peers are configured, avoid producing epochs until we have a peer-confirmed tip.
                        if !self.net_cfg.bootstrap.is_empty() {
                            let peer_confirmed = { self.sync_state.lock().unwrap().peer_confirmed_tip };
                            if !peer_confirmed {
                                self.net.request_latest_epoch().await;
                                // Also fast-forward our cursor to network-observed latest if we have it
                                if current_epoch > 0 {
                                    if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                                        if latest_anchor.num >= current_epoch {
                                            current_epoch = latest_anchor.num + 1;
                                        }
                                    }
                                }
                                println!("⏳ Waiting for peer confirmation before producing epoch {}", current_epoch);
                                continue;
                            }
                        }
                        if current_epoch > 0 {
                            if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                                if latest_anchor.num >= current_epoch {
                                    println!("⏭️  Chain has advanced. Skipping epoch creation and fast-forwarding from {} to {}.", current_epoch, latest_anchor.num + 1);
                                    current_epoch = latest_anchor.num + 1;
                                    continue;
                                }
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

                        // Collect all candidates for this epoch: include any from buffer and any seen from the network
                        let candidates: Vec<CoinCandidate> = if let Some(prev) = &prev_anchor {
                            // Fetch all candidates matching the prev anchor hash (current epoch is prev+1)
                            match self.db.get_coin_candidates_by_epoch_hash(&prev.hash) {
                                Ok(mut v) => {
                                    // Ensure locally buffered coins are included even if not yet persisted (best-effort)
                                    // Candidate CF key = epoch_hash || coin_id
                                    for id in buffer.iter() {
                                        if !v.iter().any(|c| &c.id == id) {
                                            let composite = crate::storage::Store::candidate_key(&prev.hash, id);
                                            if let Ok(Some(c)) = self.db.get::<CoinCandidate>("coin_candidate", &composite) {
                                                v.push(c);
                                            }
                                        }
                                    }
                                    v
                                }
                                Err(_) => Vec::new(),
                            }
                        } else {
                            // Genesis: no prev anchor, use only buffered coins (should be empty)
                            Vec::new()
                        };

                        // Enforce PoW difficulty from the previous anchor before selection
                        let mut selected: Vec<CoinCandidate> = if let Some(prev) = &prev_anchor {
                            let required_difficulty = prev.difficulty;
                            candidates
                                .into_iter()
                                .filter(|c| c.pow_hash.iter().take(required_difficulty).all(|b| *b == 0))
                                .collect()
                        } else {
                            // Genesis: nothing to filter
                            candidates
                        };

                        // Select up to max_coins_per_epoch by smallest pow_hash, tie-break by coin_id for determinism
                        let cap = self.cfg.max_coins_per_epoch as usize;
                        if selected.len() > cap {
                            if cap == 0 {
                                selected.clear();
                            } else {
                                // Partial select the k smallest to avoid full sort on large candidate sets
                                let _ = selected.select_nth_unstable_by(cap - 1, |a, b| a
                                    .pow_hash
                                    .cmp(&b.pow_hash)
                                    .then_with(|| a.id.cmp(&b.id))
                                );
                                selected.truncate(cap);
                                // Now stable-sort the top-k deterministically for reproducibility across nodes
                                selected.sort_by(|a, b| a
                                    .pow_hash
                                    .cmp(&b.pow_hash)
                                    .then_with(|| a.id.cmp(&b.id))
                                );
                            }
                        } else {
                            selected.sort_by(|a, b| a.pow_hash.cmp(&b.pow_hash).then_with(|| a.id.cmp(&b.id)));
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
                        let merkle_root = if leaves.is_empty() { [0u8;32] } else {
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
                        if let Some(coin_cf) = self.db.db.cf_handle("coin") {
                            for cand in &selected {
                                // Include creator_pk for genesis V2 spends
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
                        
                        if let Some(anchor_cf) = self.db.db.cf_handle("anchor") {
                            batch.put_cf(anchor_cf, &hash, &serialized_anchor);
                        }
                        
                        if let Err(e) = self.db.write_batch(batch) {
                            eprintln!("🔥 Failed to write new epoch to DB: {e}");
                            continue;
                        } else {
                            crate::metrics::EPOCH_HEIGHT.set(current_epoch as i64);
                            crate::metrics::SELECTED_COINS.set(selected_ids.len() as i64);
                            self.net.gossip_anchor(&anchor).await;
                            // Also gossip sorted leaves to help peers serve proofs deterministically
                            let bundle = crate::network::EpochLeavesBundle { epoch_num: current_epoch, merkle_root, leaves: leaves.clone() };
                            self.net.gossip_epoch_leaves(bundle).await;
                            if let Err(e) = self.anchor_tx.send(anchor) {
                                eprintln!("⚠️  Failed to broadcast anchor: {}", e);
                            }
                            // Prune old candidates (keep only those for the NEW parent, i.e., current anchor hash)
                            let _ = self.db.prune_old_candidates(&hash);
                            buffer.clear();
                            current_epoch += 1;
                        }
                    }
                }
            }
            println!("✅ Epoch manager shutdown complete");
        });
    }
}
