use crate::{storage::Store, network::NetHandle, coin::{Coin, CoinCandidate}};
use tokio::{sync::{broadcast, mpsc}, time};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use rocksdb::WriteBatch;
use bincode;
use crate::ring_transfer::RingTransfer;
use crate::ringsig::RingSignatureScheme;
#[cfg(feature = "llrs_ffi")]
use crate::ringsig::FfiLlrs as Llrs;
#[cfg(all(not(feature = "llrs_ffi"), feature = "ring_mock"))]
use crate::ringsig::MockLlrs as Llrs;
#[cfg(all(not(feature = "llrs_ffi"), not(feature = "ring_mock")))]
use crate::ringsig::NoLlrs as Llrs;
// anyhow not used in this module currently

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Anchor {
    pub num:          u64,
    pub hash:         [u8; 32],
    pub merkle_root:  [u8; 32],
    pub transfers_root: [u8; 32],
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
            if avg_coins_x_precision > target_coins_x_precision * 11 / 10 {
                (current_difficulty + 1).min(12) as usize
            } else if avg_coins_x_precision < target_coins_x_precision * 9 / 10 {
                current_difficulty.saturating_sub(1).max(1) as usize
            } else {
                last_anchor.difficulty
            }
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

/// Build a Merkle root from an ordered list of 32-byte hashes.
pub fn build_hash_list_root(mut items: Vec<[u8;32]>) -> [u8;32] {
    if items.is_empty() { return [0u8;32]; }
    items.sort();
    let mut level = items;
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
            next.push(*hasher.finalize().as_bytes());
        }
        level = next;
    }
    level[0]
}

/// Build a Merkle proof for a target hash within a sorted list of 32-byte hashes.
pub fn build_hash_list_proof(items: &[ [u8;32] ], target: &[u8;32]) -> Option<Vec<([u8;32], bool)>> {
    if items.is_empty() { return None; }
    let mut level: Vec<[u8;32]> = items.to_vec();
    let mut idx = level.iter().position(|h| h == target)?;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let (sib, sib_is_left) = if idx % 2 == 0 {
            (*level.get(idx + 1).unwrap_or(&level[idx]), false)
        } else {
            (level[idx - 1], true)
        };
        proof.push((sib, sib_is_left));
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
            next.push(*hasher.finalize().as_bytes());
        }
        idx /= 2;
        level = next;
    }
    Some(proof)
}

pub struct Manager {
    db:   Arc<Store>,
    cfg:  crate::config::Epoch,
    mining_cfg: crate::config::Mining,
    net_cfg: crate::config::Net,
    net:  NetHandle,
    anchor_tx: broadcast::Sender<Anchor>,
    coin_rx: mpsc::UnboundedReceiver<[u8; 32]>,
    shutdown_rx: broadcast::Receiver<()>,
}
impl Manager {
    pub fn new(
        db: Arc<Store>, 
        cfg: crate::config::Epoch, 
        mining_cfg: crate::config::Mining, 
        net_cfg: crate::config::Net,
        net: NetHandle, 
        coin_rx: mpsc::UnboundedReceiver<[u8; 32]>,
        shutdown_rx: broadcast::Receiver<()>
    ) -> Self {
        let anchor_tx = net.anchor_sender();
        Self { db, cfg, mining_cfg, net_cfg, net, anchor_tx, coin_rx, shutdown_rx }
    }

    pub fn spawn_loop(mut self) {
        tokio::spawn(async move {
            let mut current_epoch = match self.db.get::<Anchor>("epoch", b"latest") {
                Ok(Some(anchor)) => anchor.num + 1,
                Ok(None) => 0,
                Err(_) => 0,
            };

            // Read last anchor timestamp to align next tick and enforce minimum spacing across restarts
            let mut initial_delay = time::Duration::from_secs(0);
            if current_epoch > 0 {
                if let Some(head_cf) = self.db.db.cf_handle("head") {
                    if let Ok(Some(ts_bytes)) = self.db.db.get_cf(head_cf, b"last_anchor_ts") {
                        if ts_bytes.len() == 8 {
                            let mut arr = [0u8; 8];
                            arr.copy_from_slice(&ts_bytes);
                            let last_ts = u64::from_le_bytes(arr);
                            let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                            let target = last_ts.saturating_add(self.cfg.seconds);
                            if now_secs < target {
                                initial_delay = time::Duration::from_secs(target - now_secs);
                            }
                        }
                    }
                }
            }

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
            // Align first tick to previous anchor timestamp + cfg.seconds if available
            let start_instant = time::Instant::now() + initial_delay;
            let mut ticker = time::interval_at(start_instant, time::Duration::from_secs(self.cfg.seconds));

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
                        // Enforce minimum wall-clock spacing even if ticker fires early due to clock drift
                        if let Some(head_cf) = self.db.db.cf_handle("head") {
                            if let Ok(Some(ts_bytes)) = self.db.db.get_cf(head_cf, b"last_anchor_ts") {
                                if ts_bytes.len() == 8 {
                                    let mut arr = [0u8; 8];
                                    arr.copy_from_slice(&ts_bytes);
                                    let last_ts = u64::from_le_bytes(arr);
                                    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                    let target = last_ts.saturating_add(self.cfg.seconds);
                                    if now_secs < target {
                                        let sleep_for = target - now_secs;
                                        tokio::time::sleep(std::time::Duration::from_secs(sleep_for)).await;
                                    }
                                }
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

                        // Select up to max_coins_per_epoch by smallest pow_hash, tie-break by coin_id for determinism
                        let mut selected: Vec<CoinCandidate> = candidates;
                        selected.sort_by(|a, b| a
                            .pow_hash
                            .cmp(&b.pow_hash)
                            .then_with(|| a.id.cmp(&b.id))
                        );
                        let cap = self.cfg.max_coins_per_epoch as usize;
                        if selected.len() > cap { selected.truncate(cap); }
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
                        // transfers_root will be computed later; for now, placeholder zero included for forward compat
                        let hash = {
                            let mut h = blake3::Hasher::new();
                            h.update(&merkle_root);
                            if let Some(prev) = &prev_anchor { h.update(&prev.hash); }
                            h.update(&[0u8;32]); // placeholder transfers_root
                            *h.finalize().as_bytes()
                        };
                        
                        let (difficulty, mem_kib) = if current_epoch > 0 && current_epoch % self.cfg.retarget_interval == 0 {
                            let mut recent_anchors = Vec::new();
                            for i in 0..self.cfg.retarget_interval {
                                let epoch_num = current_epoch.saturating_sub(self.cfg.retarget_interval - i);
                                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                    recent_anchors.push(anchor);
                                }
                            }
                            calculate_retarget(&recent_anchors, &self.cfg, &self.mining_cfg)
                        } else {
                            prev_anchor.as_ref().map_or((self.cfg.target_leading_zeros, self.mining_cfg.mem_kib), |p| (p.difficulty, p.mem_kib))
                        };
                        
                        let current_work = Anchor::expected_work_for_difficulty(difficulty);
                        let cumulative_work = prev_anchor.as_ref().map_or(current_work, |p| p.cumulative_work.saturating_add(current_work));
                        
                        let anchor = Anchor { 
                            num: current_epoch, 
                            hash,
                            merkle_root,
                            transfers_root: [0u8;32],
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
                                let coin = cand.clone().into_confirmed();
                                if let Ok(bytes) = bincode::serialize(&coin) {
                                    batch.put_cf(coin_cf, &coin.id, &bytes);
                                }
                            }
                        }
                        // Accept transfers from mempool into this epoch (deterministic filter)
                        if let Some(mempool_cf) = self.db.db.cf_handle("tx_mempool") {
                            // Iterate mempool (small expected volume). For production, index by coin_id prefix.
                            let iter = self.db.db.iterator_cf(mempool_cf, rocksdb::IteratorMode::Start);
                            let mut accepted_ring_txs: Vec<[u8;32]> = Vec::new();
                            for item in iter {
                                if let Ok((_k, v)) = item {
                                    if let Ok(tx) = bincode::deserialize::<crate::transfer::Transfer>(&v) {
                                        // Validate against current tip using shared logic
                                        if tx.validate(&self.db).is_ok() {
                                            // Append to history immediately (atomic with tip)
                                            if let Ok(_) = self.db.append_transfer_if_tip_matches(&tx) {
                                                // Mark inclusion epoch for auditing
                                                let incl = crate::transfer::TransferInclusion { transfer: tx.clone(), epoch_num: current_epoch };
                                                if let Some(te_cf) = self.db.db.cf_handle("transfer_epoch") {
                                                    let key = tx.hash();
                                                    if let Ok(incl_bytes) = bincode::serialize(&incl) {
                                                        batch.put_cf(te_cf, &key, &incl_bytes);
                                                    }
                                                }
                                                // Remove from mempool (best-effort)
                                                batch.delete_cf(mempool_cf, &tx.hash());
                                            }
                                        }
                                    } else if let Ok(rtx) = bincode::deserialize::<RingTransfer>(&v) {
                                        // Re-verify ring signature at inclusion time and double-spend by tag
                                        let scheme = Llrs{};
                                        let msg = {
                                            let mut v = Vec::new();
                                            v.extend_from_slice(&rtx.to);
                                            let mut concat = Vec::new();
                                            for m in &rtx.ring_members { concat.extend_from_slice(&m.0); }
                                            let ring_root = crate::crypto::blake3_hash(&concat);
                                            v.extend_from_slice(b"ring_tx");
                                            v.extend_from_slice(&ring_root);
                                            v.extend_from_slice(&rtx.recipient_one_time.0);
                                            v
                                        };
                                        if scheme.verify(&msg, &rtx.ring_members, &rtx.signature, &rtx.link_tag).unwrap_or(false) {
                                            if self.db.get_raw_bytes("ring_tag", &rtx.link_tag.0).ok().flatten().is_none() {
                                                accepted_ring_txs.push(rtx.hash());
                                                if let Some(tag_cf) = self.db.db.cf_handle("ring_tag") {
                                                    batch.put_cf(tag_cf, &rtx.link_tag.0, &current_epoch.to_le_bytes());
                                                }
                                                batch.delete_cf(mempool_cf, &rtx.hash());
                                            }
                                        }
                                    }
                                }
                            }
                        // Persist accepted ring transfers list (sorted) and optional leaves cache, and update anchor.transfers_root
                            accepted_ring_txs.sort();
                            if let Ok(bytes) = bincode::serialize(&accepted_ring_txs) {
                                if let Some(er_cf) = self.db.db.cf_handle("epoch_ring_transfers") {
                                    batch.put_cf(er_cf, &current_epoch.to_le_bytes(), &bytes);
                                }
                            }
                        // Compute transfers_root and update anchor (rewrite epoch/latest entries)
                        let transfers_root = if accepted_ring_txs.is_empty() { [0u8;32] } else {
                            let mut h = blake3::Hasher::new();
                            for th in &accepted_ring_txs { h.update(th); }
                            *h.finalize().as_bytes()
                        };
                        let mut anchor = anchor.clone();
                        anchor.transfers_root = transfers_root;
                        // Recompute hash including transfers_root
                        let hash2 = if self.cfg.include_transfers_root_in_hash {
                            let mut h = blake3::Hasher::new();
                            h.update(&anchor.merkle_root);
                            if let Some(prev) = &prev_anchor { h.update(&prev.hash); }
                            h.update(&anchor.transfers_root);
                            *h.finalize().as_bytes()
                        } else {
                            let mut h = blake3::Hasher::new();
                            h.update(&anchor.merkle_root);
                            if let Some(prev) = &prev_anchor { h.update(&prev.hash); }
                            *h.finalize().as_bytes()
                        };
                        anchor.hash = hash2;
                        let serialized_anchor2 = match bincode::serialize(&anchor) {
                            Ok(d) => d,
                            Err(e) => { eprintln!("Failed to serialize anchor2: {}", e); continue; }
                        };
                        batch.put_cf(epoch_cf, current_epoch.to_le_bytes(), &serialized_anchor2);
                        batch.put_cf(epoch_cf, b"latest", &serialized_anchor2);
                        if let Some(anchor_cf) = self.db.db.cf_handle("anchor") { batch.put_cf(anchor_cf, &anchor.hash, &serialized_anchor2); }
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
                        // Persist last anchor timestamp for tick alignment across restarts
                        if let Some(head_cf) = self.db.db.cf_handle("head") {
                            let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                            batch.put_cf(head_cf, b"last_anchor_ts", &now_secs.to_le_bytes());
                        }
                        
                        if let Err(e) = self.db.write_batch(batch) {
                            eprintln!("🔥 Failed to write new epoch to DB: {e}");
                            continue;
                        } else {
                            crate::metrics::EPOCH_HEIGHT.set(current_epoch as i64);
                            crate::metrics::SELECTED_COINS.set(selected_ids.len() as i64);
                            self.net.gossip_anchor(&anchor).await;
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
