//! Epoch manager: collects freshly-mined coin IDs, rolls a new anchor
//! every `cfg.seconds` and gossips it to the network.

use crate::{storage::Store, network::NetHandle, coin::Coin};
use tokio::{sync::{broadcast, mpsc}, time};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub num:          u64,
    pub hash:         [u8; 32],
    pub difficulty:   usize,
    pub coin_count:   u32,
    pub cumulative_work: u128,  // Total Argon2id work in this chain up to this anchor
    pub mem_kib:      u32,      // Current memory requirement for mining
}

impl Anchor {
    /// Calculate expected work for a difficulty level
    /// Work = 2^(difficulty * 8) representing expected hashes to achieve this difficulty
    pub fn expected_work_for_difficulty(difficulty: usize) -> u128 {
        // Each leading zero byte means 256x more work
        // For difficulty=4: 2^32 expected hashes
        if difficulty == 0 {
            1
        } else {
            (1u128 << (difficulty * 8)).saturating_mul(1)
        }
    }
    
    /// Calculate retargeted difficulty and memory based on recent coin production
    pub fn calculate_retarget(
        recent_anchors: &[Anchor], 
        cfg: &crate::config::Epoch,
        mining_cfg: &crate::config::Mining
    ) -> (usize, u32) {
        if recent_anchors.is_empty() {
            return (cfg.target_leading_zeros, mining_cfg.mem_kib);
        }
        
        // Calculate average coins per epoch over the interval
        let total_coins: u32 = recent_anchors.iter().map(|a| a.coin_count).sum();
        let avg_coins_per_epoch = total_coins as f64 / recent_anchors.len() as f64;
        
        // Calculate difficulty adjustment
        let target_ratio = avg_coins_per_epoch / cfg.target_coins_per_epoch as f64;
        let difficulty_adjustment = (target_ratio).clamp(
            1.0 / cfg.max_difficulty_adjustment,
            cfg.max_difficulty_adjustment
        );
        
        let current_difficulty = recent_anchors.last().unwrap().difficulty;
        let new_difficulty = if difficulty_adjustment > 1.1 {
            // Too many coins, increase difficulty
            (current_difficulty + 1).min(10)  // Cap at 10 leading zeros
        } else if difficulty_adjustment < 0.9 {
            // Too few coins, decrease difficulty
            current_difficulty.saturating_sub(1).max(1) // Min 1 leading zero
        } else {
            current_difficulty // No change needed
        };
        
        // Calculate memory adjustment (inverse relationship - more coins = less memory needed)
        let memory_adjustment = (1.0 / target_ratio).clamp(
            1.0 / mining_cfg.max_memory_adjustment,
            mining_cfg.max_memory_adjustment
        );
        
        let current_mem = recent_anchors.last().unwrap().mem_kib;
        let new_mem = ((current_mem as f64 * memory_adjustment) as u32)
            .clamp(mining_cfg.min_mem_kib, mining_cfg.max_mem_kib);
        
        (new_difficulty, new_mem)
    }
}

/// Simple Merkle tree implementation for coin IDs
pub struct MerkleTree;

impl MerkleTree {
    /// Build Merkle tree root from a set of coin IDs
    pub fn build_root(coin_ids: &HashSet<[u8; 32]>) -> [u8; 32] {
        if coin_ids.is_empty() {
            return [0u8; 32]; // Empty tree root
        }

        // Convert coin IDs to leaf hashes
        let mut leaves: Vec<[u8; 32]> = coin_ids
            .iter()
            .map(|id| Coin::id_to_leaf_hash(id))
            .collect();
        
        // Sort for deterministic tree construction
        leaves.sort();

        // Build tree bottom-up
        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            
            // Process pairs
            for chunk in leaves.chunks(2) {
                let hash = if chunk.len() == 2 {
                    // Hash the pair
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[1]);
                    *hasher.finalize().as_bytes()
                } else {
                    // Odd number, hash single element with itself
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&chunk[0]);
                    hasher.update(&chunk[0]);
                    *hasher.finalize().as_bytes()
                };
                next_level.push(hash);
            }
            
            leaves = next_level;
        }

        leaves[0]
    }
}

pub struct Manager {
    db:   Arc<Store>,
    cfg:  crate::config::Epoch,
    mining_cfg: crate::config::Mining,
    net:  NetHandle,
    tx:   broadcast::Sender<Anchor>,
    coin_rx: mpsc::UnboundedReceiver<[u8; 32]>,
}
impl Manager {
    pub fn new(db: Arc<Store>,
               cfg: crate::config::Epoch,
               mining_cfg: crate::config::Mining,
               net: NetHandle,
               coin_rx: mpsc::UnboundedReceiver<[u8; 32]>) -> Self
    {
        let (tx, _) = broadcast::channel(32);
        Self { db, cfg, mining_cfg, net, tx, coin_rx }
    }
    /// Start the async task
    pub fn spawn(mut self) {
        tokio::spawn(async move {
            let mut current_epoch = self
                .db.get::<Anchor>("epoch", b"latest")
                .map_or(0, |a| a.num + 1);

            let mut buffer: HashSet<[u8; 32]> = HashSet::new();
            let mut ticker = time::interval(time::Duration::from_secs(self.cfg.seconds));

            loop {
                tokio::select! {
                    Some(id) = self.coin_rx.recv() => {
                        buffer.insert(id);
                    }
                    _ = ticker.tick() => {
                        // roll anchor
                        let merkle_root = MerkleTree::build_root(&buffer);
                        let mut h = blake3::Hasher::new();
                        h.update(&merkle_root);
                        if let Some(prev) = self.db.get::<Anchor>("epoch", &(current_epoch.saturating_sub(1)).to_le_bytes()) {
                            h.update(&prev.hash);
                        }
                        let hash = *h.finalize().as_bytes();
                        
                        // Check if retargeting is needed
                        let (difficulty, mem_kib) = if current_epoch % self.cfg.retarget_interval == 0 && current_epoch > 0 {
                            // Gather recent anchors for retargeting
                            let mut recent_anchors = Vec::new();
                            for i in 0..self.cfg.retarget_interval {
                                let epoch_num = current_epoch.saturating_sub(self.cfg.retarget_interval - i);
                                if let Some(anchor) = self.db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                                    recent_anchors.push(anchor);
                                }
                            }
                            Anchor::calculate_retarget(&recent_anchors, &self.cfg, &self.mining_cfg)
                        } else {
                            // Use previous values or defaults
                            if let Some(prev) = self.db.get::<Anchor>("epoch", &(current_epoch.saturating_sub(1)).to_le_bytes()) {
                                (prev.difficulty, prev.mem_kib)
                            } else {
                                (self.cfg.target_leading_zeros, self.mining_cfg.mem_kib)
                            }
                        };
                        
                        // Calculate cumulative work
                        let current_work = Anchor::expected_work_for_difficulty(difficulty);
                        let cumulative_work = if let Some(prev) = self.db.get::<Anchor>("epoch", &(current_epoch.saturating_sub(1)).to_le_bytes()) {
                            prev.cumulative_work.saturating_add(current_work)
                        } else {
                            current_work
                        };
                        
                        let anchor = Anchor {
                            num: current_epoch,
                            hash,
                            difficulty,
                            coin_count: buffer.len() as u32,
                            cumulative_work,
                            mem_kib,
                        };
                        // store
                        self.db.put("epoch", &current_epoch.to_le_bytes(), &anchor);
                        self.db.put("epoch", b"latest", &anchor);
                        // broadcast
                        self.net.gossip_anchor(&anchor).await;
                        let _ = self.tx.send(anchor.clone());
                        // prepare next epoch
                        buffer.clear();
                        current_epoch += 1;
                    }
                }
            }
        });
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Anchor> { self.tx.subscribe() }
}