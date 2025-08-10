use crate::{storage::Store, network::NetHandle, coin::{Coin, CoinCandidate}};
use primitive_types::U256;
use tokio::{sync::{broadcast, mpsc}, time};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use rocksdb::WriteBatch;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Anchor {
    pub version:      u16,
    pub num:          u64,
    pub hash:         [u8; 32],
    pub merkle_root:  [u8; 32],
    pub transfers_root: [u8; 32],
    pub work_root:    [u8; 32],
    pub target_nbits: u32,
    pub mem_kib:      u32,
    pub t_cost:       u32,
    pub coin_count:   u32,
    pub cumulative_work: U256,
}

impl Anchor {
    #[inline]
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
}

/// Compute the anchor hash committing to all consensus-critical fields and prev hash
pub fn compute_anchor_hash(
    merkle_root: &[u8;32],
    transfers_root: &[u8;32],
    prev_hash: Option<&[u8;32]>,
    work_root: &[u8;32],
    target_nbits: u32,
    mem_kib: u32,
    t_cost: u32,
    coin_count: u32,
    cumulative_work: &U256,
) -> [u8;32] {
    let mut h = blake3::Hasher::new_derive_key("unchained/anchor/v4");
    h.update(merkle_root);
    h.update(transfers_root);
    if let Some(ph) = prev_hash { h.update(ph); }
    h.update(work_root);
    h.update(&target_nbits.to_le_bytes());
    h.update(&mem_kib.to_le_bytes());
    h.update(&t_cost.to_le_bytes());
    h.update(&coin_count.to_le_bytes());
    let mut cw = [0u8;32];
    cumulative_work.to_big_endian(&mut cw);
    h.update(&cw);
    *h.finalize().as_bytes()
}

#[inline]
fn fold_merkle(mut level: Vec<[u8;32]>, internal_label: &'static [u8]) -> [u8;32] {
    if level.is_empty() { return [0u8;32]; }
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len()+1)/2);
        for chunk in level.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(internal_label);
            hasher.update(&chunk[0]);
            hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
            next.push(*hasher.finalize().as_bytes());
        }
        level = next;
    }
    level[0]
}

#[inline]
fn leaf_hash_for_coin_id(coin_id: &[u8;32]) -> [u8;32] {
    let base = Coin::id_to_leaf_hash(coin_id);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"leaf");
    hasher.update(&base);
    *hasher.finalize().as_bytes()
}

#[inline]
fn leaf_hash_for_txid(txid: &[u8;32]) -> [u8;32] {
    let base = crate::crypto::blake3_hash(txid);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"leaf");
    hasher.update(&base);
    *hasher.finalize().as_bytes()
}

#[inline]
fn work_leaf_hash(coin_id: &[u8;32], work_value: &U256) -> [u8;32] {
    let mut work_value_bytes = [0u8;32];
    work_value.to_big_endian(&mut work_value_bytes);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"workleaf");
    hasher.update(coin_id);
    hasher.update(&work_value_bytes);
    *hasher.finalize().as_bytes()
}

/// Deterministically compute transfers root from sorted tx ids
pub fn compute_transfers_root(tx_ids: &[ [u8;32] ]) -> [u8;32] {
    if tx_ids.is_empty() { return [0u8;32]; }
    let mut leaf_hashes: Vec<[u8;32]> = tx_ids.iter().map(leaf_hash_for_txid).collect();
    leaf_hashes.sort();
    fold_merkle(leaf_hashes, b"node")
}

/// Validate an anchor against prev anchor and provided selection/coins
pub fn validate_anchor(
    db: &Store,
    cfg: &crate::config::Epoch,
    mining_cfg: &crate::config::Mining,
    anchor: &Anchor,
    prev_anchor: Option<&Anchor>,
    selected_coin_ids: &[[u8;32]],
    coins: &[Coin],
) -> Result<(), String> {
    // Enforce canonical compact target representation
    let normalized = crate::crypto::normalize_compact_target(anchor.target_nbits)
        .map_err(|_| "invalid compact target".to_string())?;
    if normalized != anchor.target_nbits { return Err("non-canonical compact target".into()); }
    // 1) Retarget consistency
    if let Some(prev) = prev_anchor {
        let (exp_nbits, mut exp_mem, exp_t) = if anchor.num > 0 && anchor.num % cfg.retarget_interval == 0 {
            // Collect last retarget_interval anchors ending at prev
            let mut recents: Vec<Anchor> = Vec::new();
            for i in (anchor.num.saturating_sub(cfg.retarget_interval))..anchor.num {
                if let Ok(Some(a)) = db.get::<Anchor>("epoch", &i.to_le_bytes()) { recents.push(a); }
            }
            calculate_retarget(&recents, cfg, mining_cfg)
        } else { (prev.target_nbits, prev.mem_kib, prev.t_cost) };
        // Deterministic post-adjustment of memory to steer selection within [λ_min, λ_max]
        let sel_len = selected_coin_ids.len() as u32;
        if sel_len > 0 {
            if sel_len < cfg.selected_min_per_epoch { exp_mem = exp_mem.saturating_sub(exp_mem / 50).max(mining_cfg.min_mem_kib); }
            if sel_len > cfg.selected_max_per_epoch { exp_mem = (exp_mem + exp_mem / 50).min(mining_cfg.max_mem_kib); }
        }
        if anchor.target_nbits != exp_nbits || anchor.mem_kib != exp_mem || anchor.t_cost != exp_t {
            return Err("retarget parameters mismatch".into());
        }
    } else {
        // Genesis must have zero cumulative work and zero coin count
        if anchor.num != 0 || anchor.cumulative_work != U256::zero() || anchor.coin_count != 0 { return Err("invalid genesis anchor fields".into()); }
    }

    // 2) Merkle root recompute from selected ids
    let id_set: HashSet<[u8;32]> = HashSet::from_iter(selected_coin_ids.iter().cloned());
    let mr = MerkleTree::build_root(&id_set);
    if mr != anchor.merkle_root { return Err("merkle_root mismatch".into()); }

    // 3) Transfers root
    if let Ok(Some(tx_ids)) = db.get_epoch_transfers(anchor.num) {
        let tr = compute_transfers_root(&tx_ids);
        if tr != anchor.transfers_root { return Err("transfers_root mismatch".into()); }
    } else {
        // If none stored, require empty root
        if anchor.transfers_root != [0u8;32] { return Err("unexpected non-empty transfers_root".into()); }
    }

    // 4) Epoch work recompute from coins
    // Ensure provided coins match selection and ids/epoch linkage
    let prev_h_opt = prev_anchor.map(|p| p.hash);
    let prev_h = if let Some(h) = prev_h_opt { h } else { [0u8;32] };
    let id_set_check: HashSet<[u8;32]> = coins.iter().map(|c| c.id).collect();
    if !selected_coin_ids.iter().all(|id| id_set_check.contains(id)) { return Err("coins list missing entries".into()); }
    let mut epoch_work = U256::zero();
    let mut work_leaves: Vec<[u8;32]> = Vec::with_capacity(coins.len());
    for coin in coins {
        // Verify ID reconstructs from components
        if Coin::calculate_id(&coin.epoch_hash, coin.nonce, &coin.creator_address) != coin.id { return Err("coin id mismatch".into()); }
        // Verify epoch hash linkage equals prev anchor
        if prev_anchor.is_some() && coin.epoch_hash != prev_h { return Err("coin epoch_hash mismatch prev".into()); }
        // Recompute PoW and work (salt = prev anchor hash = coin.epoch_hash, t_cost=1)
        let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
        let pow = crate::crypto::argon2id_pow(
            &header,
            &coin.epoch_hash,
            prev_anchor.map(|p| p.mem_kib).unwrap_or(mining_cfg.mem_kib),
            1,
        ).map_err(|e| format!("argon2id error: {e}"))?;
        // Enforce pow < target from prev anchor
        if let Some(prev) = prev_anchor {
            let target = crate::crypto::decode_compact_target(prev.target_nbits).map_err(|_| "target".to_string())?;
            if !crate::crypto::leq_hash_to_target(&pow, &target) { return Err("coin pow above target".into()); }
        }
        let work_value = crate::crypto::work_from_pow_hash(&pow);
        epoch_work = epoch_work.saturating_add(work_value);
        work_leaves.push(work_leaf_hash(&coin.id, &work_value));
    }
    let expected_cw = prev_anchor.map(|p| p.cumulative_work.saturating_add(epoch_work)).unwrap_or(epoch_work);
    if anchor.cumulative_work != expected_cw { return Err("cumulative_work mismatch".into()); }
    work_leaves.sort();
    let work_root = if work_leaves.is_empty() { [0u8;32] } else {
        let mut level = work_leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity((level.len()+1)/2);
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"worknode");
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next.push(*hasher.finalize().as_bytes());
            }
            level = next;
        }
        level[0]
    };
    if anchor.work_root != work_root { return Err("work_root mismatch".into()); }

    // 5) Hash commit check
    let prev_hash_ref = prev_anchor.map(|p| &p.hash);
    let computed = compute_anchor_hash(&anchor.merkle_root, &anchor.transfers_root, prev_hash_ref, &anchor.work_root, anchor.target_nbits, anchor.mem_kib, anchor.t_cost, anchor.coin_count, &anchor.cumulative_work);
    if anchor.hash != computed { return Err("anchor hash mismatch".into()); }

    Ok(())
}

pub fn calculate_retarget(
    recent_anchors: &[Anchor], 
    cfg: &crate::config::Epoch,
    mining_cfg: &crate::config::Mining
) -> (u32, u32, u32) {
    // If no history, return genesis defaults derived from config
    if recent_anchors.is_empty() {
        let initial_target = crate::crypto::decode_compact_target(0x1f00ffff).unwrap_or_else(|_| U256::from(u128::MAX));
        let nbits = crate::crypto::encode_compact_target(&initial_target);
        return (nbits, mining_cfg.mem_kib.max(crate::config::default_min_mem()), 3);
    }

    let last_anchor = recent_anchors.last().unwrap();
    let total_coins: u64 = recent_anchors.iter().map(|a| a.coin_count as u64).sum();
    let num_anchors = recent_anchors.len() as u64;
    let avg_coins = (total_coins.max(1)) / num_anchors.max(1);

    // ASERT-like controller on coin counts
    const SCALE: u64 = 1 << 20; // fixed-point
    let target_coins = cfg.target_coins_per_epoch as u64;
    let mut f_q = (target_coins * SCALE) / (avg_coins.max(1));
    let lower = (SCALE * 75) / 100; // -25%
    let upper = (SCALE * 125) / 100; // +25%
    if f_q < lower { f_q = lower; }
    if f_q > upper { f_q = upper; }

    let old_target = crate::crypto::decode_compact_target(last_anchor.target_nbits).unwrap_or_else(|_| U256::from(u128::MAX));
    // Proposed candidate: old_target * f_q >> 20
    let mut candidate = old_target.saturating_mul(U256::from(f_q)) >> 20;
    // EMA smoothing: new_target = (3*old + candidate)/4
    let ema_num = old_target.saturating_mul(U256::from(3)).saturating_add(candidate);
    candidate = ema_num / U256::from(4u8);
    // Clamp step size to ±10% per retarget to avoid oscillations
    let ten_percent = |v: U256| v / U256::from(10u8);
    let lower = old_target.saturating_sub(ten_percent(old_target));
    let upper = old_target.saturating_add(ten_percent(old_target));
    let clamped = if candidate < lower { lower } else if candidate > upper { upper } else { candidate };
    let new_nbits = crate::crypto::encode_compact_target(&clamped);

    // Memory small adjustment (±2%) and bounds enforcement; use memory to correct selection counts into [λ_min, λ_max]
    let current_mem = last_anchor.mem_kib as u64;
    let mut new_mem = current_mem;
    if avg_coins > target_coins { // too many coins → increase mem slightly
        new_mem = current_mem + (current_mem / 50);
    } else if avg_coins < target_coins { // too few → decrease mem slightly
        new_mem = current_mem.saturating_sub(current_mem / 50);
    }
    let new_mem = (new_mem as u32).clamp(mining_cfg.min_mem_kib, mining_cfg.max_mem_kib);

    // Enforce PoW t_cost=1 in consensus going forward
    let new_t_cost = 1u32;

    (new_nbits, new_mem, new_t_cost)
}

pub struct MerkleTree;
impl MerkleTree {
    pub fn build_root(coin_ids: &HashSet<[u8; 32]>) -> [u8; 32] {
        if coin_ids.is_empty() { return [0u8; 32]; }
        // Domain separation: leaf = BLAKE3("leaf" || coin_leaf_hash)
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(leaf_hash_for_coin_id).collect();
        leaves.sort();
        // Domain separation for internal nodes: node = BLAKE3("node" || left || right)
        fold_merkle(leaves, b"node")
    }
}
impl MerkleTree {
    pub fn build_proof(
        coin_ids: &HashSet<[u8; 32]>,
        target_id: &[u8; 32],
    ) -> Option<Vec<([u8; 32], bool)>> {
        if coin_ids.is_empty() { return None; }
        // Apply the same leaf-domain hashing as build_root: leaf = BLAKE3("leaf" || blake3(id))
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(|id| {
            let base = Coin::id_to_leaf_hash(id);
            let mut h = blake3::Hasher::new();
            h.update(b"leaf");
            h.update(&base);
            *h.finalize().as_bytes()
        }).collect();
        leaves.sort();
        // Compute the domain-separated leaf node for the target
        let base = Coin::id_to_leaf_hash(target_id);
        let mut h = blake3::Hasher::new();
        h.update(b"leaf");
        h.update(&base);
        let leaf_node = *h.finalize().as_bytes();
        let mut index = leaves.iter().position(|x| x == &leaf_node)?;
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
                hasher.update(b"node");
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
        // Verify with domain separation
        let mut h0 = blake3::Hasher::new();
        h0.update(b"leaf");
        h0.update(leaf_hash);
        let mut computed = *h0.finalize().as_bytes();
        for (sibling, sibling_is_left) in proof {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"node");
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

            // Deterministic genesis creation (prevents race) when no bootstrap peers are configured.
            if current_epoch == 0 && self.net_cfg.bootstrap.is_empty() {
                let merkle_root = [0u8;32];
                let transfers_root = [0u8;32];
                let work_root = [0u8;32];
                // Retarget params for genesis
        let target_nbits = crate::crypto::normalize_compact_target(0x1f00ffff).unwrap_or(0x1f00ffff);
                let mem_kib = self.mining_cfg.mem_kib;
                let t_cost = 1;
                let coin_count = 0u32;
                let cumulative_work = primitive_types::U256::zero();
                let hash = compute_anchor_hash(&merkle_root, &transfers_root, None, &work_root, target_nbits, mem_kib, t_cost, coin_count, &cumulative_work);
                let anchor = Anchor {
                    version: 4,
                    num: 0,
                    hash,
                    merkle_root,
                    transfers_root,
                    work_root,
                    target_nbits,
                    mem_kib,
                    t_cost,
                    coin_count,
                    cumulative_work,
                };
                if self.db.put("epoch", &anchor.num.to_le_bytes(), &anchor).is_ok()
                    && self.db.put("anchor", &anchor.hash, &anchor).is_ok()
                    && self.db.put("epoch", b"latest", &anchor).is_ok() {
                    crate::metrics::EPOCH_HEIGHT.set(0);
                    crate::metrics::SELECTED_COINS.set(0);
                    let _ = self.anchor_tx.send(anchor.clone());
                    self.net.gossip_anchor(&anchor).await;
                    println!("🌱 Created deterministic genesis anchor");
                    current_epoch = 1;
                }
            }

            let mut buffer: HashSet<[u8; 32]> = HashSet::new();
            // Tick immediately on startup so genesis or the first epoch can be processed without waiting a full period
            let mut ticker = time::interval_at(time::Instant::now(), time::Duration::from_secs(self.cfg.seconds));

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

                        // Threshold-only winners with DoS hardening:
                        // Recompute Argon2id for each candidate under prev anchor params and filter by target.
                        let mut selected_with_pow: Vec<(CoinCandidate, [u8;32])> = if let Some(prev) = &prev_anchor {
                            let target = crate::crypto::decode_compact_target(prev.target_nbits).unwrap_or_else(|_| U256::MAX);
                            let mem_kib = prev.mem_kib;
                            let t_cost = 1u32; // enforce t_cost=1 for PoW
                            candidates.into_iter()
                                .filter_map(|c| {
                                    // Validate coin id from components
                                    if Coin::calculate_id(&c.epoch_hash, c.nonce, &c.creator_address) != c.id { return None; }
                                    // Cheap prefilter: discard obviously invalid by claimed pow vs target to save CPU
                                    // (Recompute later for survivors)
                                    let claimed = U256::from_big_endian(&c.pow_hash);
                                    if claimed > target { return None; }
                                    let header = Coin::header_bytes(&c.epoch_hash, c.nonce, &c.creator_address);
                                    match crate::crypto::argon2id_pow(&header, &c.epoch_hash, mem_kib, t_cost) {
                                        Ok(pow) => {
                                            let h = U256::from_big_endian(&pow);
                                            if h <= target { Some((c, pow)) } else { None }
                                        }
                                        Err(_) => None,
                                    }
                                })
                                .collect()
                        } else { Vec::new() };
                        // Apply per-epoch cap (N_max) to protect downstream processing; keep smallest recomputed pow first
                        if !selected_with_pow.is_empty() {
                            selected_with_pow.sort_by(|a, b| U256::from_big_endian(&a.1).cmp(&U256::from_big_endian(&b.1)));
                            let cap: usize = (self.cfg.max_selected_per_epoch as usize).max(1);
                            if selected_with_pow.len() > cap { selected_with_pow.truncate(cap); }
                        }

                        // Build Merkle root from selected coin IDs and persist sorted leaves for fast proofs
                        let selected_ids: HashSet<[u8; 32]> = selected_with_pow.iter().map(|(c, _)| c.id).collect();
                        let mut leaves: Vec<[u8;32]> = selected_ids.iter().map(leaf_hash_for_coin_id).collect();
                        leaves.sort();
                        let merkle_root = fold_merkle(leaves.clone(), b"node");
                        // Build transfers_root from tx_pool (sorted blake3(tx_id))
                        let (transfers_root, applied_tx_ids) = {
                            if let Ok(txs) = self.db.iterate_tx_pool() {
                                if txs.is_empty() {
                                    ([0u8;32], Vec::new())
                                } else {
                                    let mut ids: Vec<[u8;32]> = Vec::with_capacity(txs.len());
                                    for tx in &txs { ids.push(tx.hash()); }
                                    ids.sort();
                                    (compute_transfers_root(&ids), ids)
                                }
                            } else { ([0u8;32], Vec::new()) }
                        };
                        // Retarget
                        let (mut target_nbits, mut mem_kib, t_cost) = if current_epoch > 0 && current_epoch % self.cfg.retarget_interval == 0 {
                            let mut recent_anchors = Vec::new();
                            for i in 0..self.cfg.retarget_interval {
                                let epoch_num = current_epoch.saturating_sub(self.cfg.retarget_interval - i);
                                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                    recent_anchors.push(anchor);
                                }
                            }
                            calculate_retarget(&recent_anchors, &self.cfg, &self.mining_cfg)
                        } else {
                            prev_anchor.as_ref().map_or((0x1f00ffff, self.mining_cfg.mem_kib, 1), |p| (p.target_nbits, p.mem_kib, p.t_cost))
                        };
                        // Deterministic post-adjustment: ensure selected count falls within [λ_min, λ_max] by tweaking mem_kib within bounds.
                        let sel_len = selected_with_pow.len() as u32;
                        if sel_len > 0 {
                            if sel_len < self.cfg.selected_min_per_epoch { mem_kib = mem_kib.saturating_sub(mem_kib / 50).max(self.mining_cfg.min_mem_kib); }
                            if sel_len > self.cfg.selected_max_per_epoch { mem_kib = (mem_kib + mem_kib / 50).min(self.mining_cfg.max_mem_kib); }
                        }
                        // Ensure canonical compact encoding
                        target_nbits = crate::crypto::normalize_compact_target(target_nbits).unwrap_or(target_nbits);
                        // Epoch work = sum over selected coins of work_from_pow_hash
                        let mut epoch_work = U256::zero();
                        let mut work_leaves: Vec<[u8;32]> = Vec::with_capacity(selected_with_pow.len());
                        for (c, pow) in &selected_with_pow {
                            let work_value = crate::crypto::work_from_pow_hash(pow);
                            epoch_work = epoch_work.saturating_add(work_value);
                            work_leaves.push(work_leaf_hash(&c.id, &work_value));
                        }
                        let cumulative_work = prev_anchor.as_ref().map_or(epoch_work, |p| p.cumulative_work.saturating_add(epoch_work));
                        let coin_count = selected_ids.len() as u32;
                        // Build work root and persist sorted leaves for proof serving
                        work_leaves.sort();
                        let work_root = fold_merkle(work_leaves.clone(), b"worknode");
                        // Anchor hash commits to all consensus-critical fields and previous hash
                        let prev_hash_ref = prev_anchor.as_ref().map(|p| &p.hash);
                        let hash = compute_anchor_hash(&merkle_root, &transfers_root, prev_hash_ref, &work_root, target_nbits, mem_kib, t_cost, coin_count, &cumulative_work);
                        let anchor = Anchor { 
                            version: 4,
                            num: current_epoch, 
                            hash,
                            merkle_root,
                            transfers_root,
                            work_root,
                            target_nbits,
                            mem_kib,
                            t_cost,
                            coin_count, 
                            cumulative_work,
                        };
                        // Pre-validate locally before persistence/broadcast
                        let confirmed: Vec<Coin> = selected_with_pow.iter().map(|(c, _)| c.clone().into_confirmed()).collect();
                        if let Err(e) = validate_anchor(&self.db, &self.cfg, &self.mining_cfg, &anchor, prev_anchor.as_ref(), &selected_ids.iter().cloned().collect::<Vec<_>>(), &confirmed) {
                            eprintln!("🔥 Local anchor validation failed: {}", e);
                            crate::metrics::VALIDATION_FAIL_ANCHOR.inc();
                            continue;
                        }
                        
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
                            for (cand, _pow) in &selected_with_pow {
                                let coin = cand.clone().into_confirmed();
                                if let Ok(bytes) = bincode::serialize(&coin) {
                                    batch.put_cf(coin_cf, &coin.id, &bytes);
                                }
                            }
                        }
                        // Apply transfers selected for this epoch: re-validate, move from tx_pool to transfer CF and index per-epoch ids
                        if let Some(tx_pool_cf) = self.db.db.cf_handle("tx_pool") {
                            let mut applied: Vec<[u8;32]> = Vec::new();
                            let iter = self.db.db.iterator_cf(tx_pool_cf, rocksdb::IteratorMode::Start);
                            if let Some(tx_cf) = self.db.db.cf_handle("transfer") {
                                for item in iter {
                                    if let Ok((_k, v)) = item {
                                        if let Ok(tx) = bincode::deserialize::<crate::transfer::Transfer>(&v) {
                                            if tx.validate(&self.db).is_ok() {
                                                // apply
                                                batch.put_cf(tx_cf, &tx.coin_id, &v);
                                                applied.push(tx.hash());
                                            }
                                        }
                                    }
                                }
                            }
                            // Remove applied from pool
                            for id in applied {
                                batch.delete_cf(tx_pool_cf, &id);
                            }
                            // Persist per-epoch transfer ids for validation and proofs
                            if let Err(e) = self.db.store_epoch_transfers(current_epoch, &applied_tx_ids) { eprintln!("⚠️ Failed to store epoch transfers: {}", e); }
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
                        if let Err(e) = self.db.store_epoch_work_leaves(current_epoch, &work_leaves) { eprintln!("⚠️ Failed to store epoch work leaves: {}", e); }
                        
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
