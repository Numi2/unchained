use crate::{storage::Store, network::NetHandle, coin::Coin};
use tokio::{sync::{broadcast, mpsc}, time};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use rocksdb::WriteBatch;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Anchor {
    pub num:          u64,
    pub hash:         [u8; 32],
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
                    println!("⚠️  Network synchronization timeout or no peers found. Starting from genesis.");
                }
            }

            let mut buffer: HashSet<[u8; 32]> = HashSet::new();
            let mut ticker = time::interval(time::Duration::from_secs(self.cfg.seconds));

            loop {
                tokio::select! {
                    biased;
                    _ = self.shutdown_rx.recv() => {
                        println!("🛑 Epoch manager received shutdown signal");
                        break;
                    }
                    Some(id) = self.coin_rx.recv() => { 
                        buffer.insert(id);
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
                            println!("🌱 No existing epochs found. Creating genesis anchor...");
                        }

                        let merkle_root = MerkleTree::build_root(&buffer);
                        let mut h = blake3::Hasher::new();
                        h.update(&merkle_root);
                        
                        let prev_anchor = self.db.get::<Anchor>("epoch", &(current_epoch.saturating_sub(1)).to_le_bytes()).unwrap_or_default();
                        if let Some(prev) = &prev_anchor { h.update(&prev.hash); }
                        let hash = *h.finalize().as_bytes();
                        
                        let (difficulty, mem_kib) = if current_epoch > 0 && current_epoch % self.cfg.retarget_interval == 0 {
                            let mut recent_anchors = Vec::new();
                            for i in 0..self.cfg.retarget_interval {
                                let epoch_num = current_epoch.saturating_sub(self.cfg.retarget_interval - i);
                                if let Ok(Some(anchor)) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                    recent_anchors.push(anchor);
                                }
                            }
                            Anchor::calculate_retarget(&recent_anchors, &self.cfg, &self.mining_cfg)
                        } else {
                            prev_anchor.as_ref().map_or((self.cfg.target_leading_zeros, self.mining_cfg.mem_kib), |p| (p.difficulty, p.mem_kib))
                        };
                        
                        let current_work = Anchor::expected_work_for_difficulty(difficulty);
                        let cumulative_work = prev_anchor.as_ref().map_or(current_work, |p| p.cumulative_work.saturating_add(current_work));
                        
                        let anchor = Anchor { num: current_epoch, hash, difficulty, coin_count: buffer.len() as u32, cumulative_work, mem_kib };
                        
                        let mut batch = WriteBatch::default();
                        let serialized_anchor = bincode::serialize(&anchor).unwrap();
                        let epoch_cf = self.db.db.cf_handle("epoch").unwrap();
                        batch.put_cf(epoch_cf, current_epoch.to_le_bytes(), &serialized_anchor);
                        batch.put_cf(epoch_cf, b"latest", &serialized_anchor);
                        if let Some(anchor_cf) = self.db.db.cf_handle("anchor") {
                            batch.put_cf(anchor_cf, &hash, &serialized_anchor);
                        }
                        
                        if let Err(e) = self.db.db.write(batch) {
                            eprintln!("🔥 Failed to write new epoch to DB: {e}");
                        } else {
                            self.net.gossip_anchor(&anchor).await;
                            let _ = self.anchor_tx.send(anchor);
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
