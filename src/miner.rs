use crate::{storage::Store, crypto, epoch::Anchor, coin::{Coin, CoinCandidate}, network::NetHandle, wallet::Wallet};
// use rand::Rng; // no longer needed with sequential nonce
use std::sync::Arc;
use tokio::{sync::{mpsc, broadcast::Receiver}, task, time::{self, Duration}};
use tokio::sync::broadcast::error::RecvError;

use crate::sync::SyncState;

pub fn spawn(
    cfg: crate::config::Mining,
    db: Arc<Store>,
    net: NetHandle,
    wallet: Arc<Wallet>, // The miner needs a persistent identity
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
    shutdown_rx: Receiver<()>,
    sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>, // new
) {
    task::spawn(async move {
        let mut miner = Miner::new(cfg, db, net, wallet, coin_tx, shutdown_rx, sync_state);
        miner.run().await;
    });
}

struct Miner {
    #[allow(dead_code)]
    cfg: crate::config::Mining,
    db: Arc<Store>,
    net: NetHandle,
    wallet: Arc<Wallet>,
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
    shutdown_rx: Receiver<()>,
    sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>, // new
    current_epoch: Option<u64>,
    last_heartbeat: time::Instant,
    consecutive_failures: u32,
    max_consecutive_failures: u32,
}

impl Miner {
    fn new(
        cfg: crate::config::Mining,
        db: Arc<Store>,
        net: NetHandle,
        wallet: Arc<Wallet>,
        coin_tx: mpsc::UnboundedSender<[u8; 32]>,
        shutdown_rx: Receiver<()>,
        sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>,
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            db,
            net,
            wallet,
            coin_tx,
            shutdown_rx,
            sync_state,
            current_epoch: None,
            last_heartbeat: time::Instant::now(),
            consecutive_failures: 0,
            max_consecutive_failures: crate::config::default_max_consecutive_failures(),
        }
    }

    async fn run(&mut self) {
        // Wait until node is marked synced by main/sync services
        loop {
            let (synced, highest, local) = {
                let st = self.sync_state.lock().unwrap();
                let local = self.db.get::<Anchor>("epoch", b"latest").unwrap_or(None).map_or(0, |a| a.num);
                (st.synced, st.highest_seen_epoch, local)
            };

            if synced {
                println!("🚀 Node is synced – starting mining");
                break;
            }

            println!("⌛ Waiting to reach network tip… local {local} / net {highest}");
            tokio::select! {
                _ = self.shutdown_rx.recv() => { println!("🛑 Miner received shutdown while waiting for sync"); return; }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }

        println!("⛏️  Starting miner with reconnection and fallback capabilities");
        
        loop {
            match self.try_connect_and_mine().await {
                Ok(()) => {
                    // Successful mining session (found coin or epoch finished)
                    self.consecutive_failures = 0;
                    println!("✅ Mining session completed successfully");
                }
                Err(e) => {
                    self.consecutive_failures += 1;
                    if e.to_string() == "Shutdown" {
                        println!("🛑 Miner shut down gracefully");
                        break;
                    }
                    eprintln!("❌ Mining session failed (attempt {}/{}): {}", 
                             self.consecutive_failures, self.max_consecutive_failures, e);
                    
                    if self.consecutive_failures >= self.max_consecutive_failures {
                        eprintln!("🚨 Too many consecutive failures, restarting miner completely");
                        self.consecutive_failures = 0;
                        // Reset current epoch to force fresh start
                        self.current_epoch = None;
                    }
                    
                    // Exponential backoff: wait longer after each failure
                    let backoff_duration = Duration::from_secs(2u64.pow(self.consecutive_failures.min(6)));
                    println!("⏳ Waiting {} seconds before retry...", backoff_duration.as_secs());
                    time::sleep(backoff_duration).await;
                }
            }
        }
    }

    async fn try_connect_and_mine(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { /* actual code continues */
        let mut anchor_rx = self.net.anchor_subscribe();
        let mut heartbeat_interval = time::interval(Duration::from_secs(crate::config::default_heartbeat_interval()));
        
        println!("🔗 Connected to anchor broadcast channel");
        
        // doesn’t have to wait for the next anchor broadcast (which can be several minutes away).
        match self.db.get::<Anchor>("epoch", b"latest") {
            Ok(Some(latest_anchor)) => {
                println!("📥 Loaded latest epoch #{} from database", latest_anchor.num);
                self.current_epoch = Some(latest_anchor.num);
                self.last_heartbeat = time::Instant::now();
                if let Err(e) = self.mine_epoch(latest_anchor.clone()).await {
                    eprintln!("⚠️  Initial mining attempt failed: {e}");
                }
            },
            Ok(None) => {
                // No local epochs yet; request latest from network and wait for broadcasts.
                // In single-node genesis, proceed with anchor stream; epoch manager will create genesis immediately due to immediate ticker.
                println!("🌱 No existing epochs found locally. Waiting for epoch manager to create genesis…");
            },
            Err(e) => {
                eprintln!("🔥 Failed to read latest epoch from DB: {e}");
            }
        }
        
        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = self.shutdown_rx.recv() => {
                    println!("🛑 Miner received shutdown signal");
                    return Err("Shutdown".into());
                }
                
                // Handle incoming anchors
                anchor_result = anchor_rx.recv() => {
                    match anchor_result {
                        Ok(anchor) => {
                            self.last_heartbeat = time::Instant::now();
                            self.consecutive_failures = 0;
                            
                            // Update sync state to reflect the new epoch
                            {
                                let mut st = self.sync_state.lock().unwrap();
                                if anchor.num > st.highest_seen_epoch {
                                    st.highest_seen_epoch = anchor.num;
                                    println!("📊 Updated sync state: highest_seen_epoch = {}", st.highest_seen_epoch);
                                }
                            }
                            
                            println!(
                                "⛏️  New epoch #{}: target_nbits=0x{:08x}, mem_kib={}, t_cost={}. Mining...",
                                anchor.num, anchor.target_nbits, anchor.mem_kib, anchor.t_cost
                            );
                            
                            self.current_epoch = Some(anchor.num);
                            self.mine_epoch(anchor).await?;
                        }
                        Err(RecvError::Closed) => {
                            return Err("Anchor broadcast channel closed".into());
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            eprintln!("⚠️  Anchor channel lagged, skipped {skipped} messages");
                            
                            // Try to recover by requesting the latest epoch
                            if let Some(current_epoch) = self.current_epoch {
                                println!("🔄 Requesting latest epoch to recover from lag");
                                self.net.request_epoch(current_epoch).await;
                                
                                // Wait a bit for the request to be processed
                                time::sleep(Duration::from_millis(1000)).await;
                                
                                // Try to get the latest epoch from database as fallback
                                if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                                    if latest_anchor.num > current_epoch {
                                        println!("📥 Recovered latest epoch #{} from database", latest_anchor.num);
                                        self.current_epoch = Some(latest_anchor.num);
                                        self.mine_epoch(latest_anchor).await?;
                                        continue;
                                    }
                                }
                            }
                            
                            return Err("Failed to recover from anchor channel lag".into());
                        }
                    }
                }
                
                // Heartbeat monitoring
                _ = heartbeat_interval.tick() => {
                    let since_last_heartbeat = self.last_heartbeat.elapsed();
                    // Allow a generous timeout (6× heartbeat interval) so we don’t abort during a long epoch (default epoch length is 333 s).
                    // This also covers the case where we found a coin early and have to wait the full epoch duration for the next anchor.
                    let timeout_secs = crate::config::default_heartbeat_interval() * 6;
                    if since_last_heartbeat > Duration::from_secs(timeout_secs) {
                        eprintln!("💔 No anchor received for {} seconds, checking for missed epochs", 
                                 since_last_heartbeat.as_secs());
                        
                        // Try to recover by requesting the next expected epoch
                        if let Some(current_epoch) = self.current_epoch {
                            let next_epoch = current_epoch + 1;
                            println!("🔄 Requesting epoch #{next_epoch} due to heartbeat timeout");
                            self.net.request_epoch(next_epoch).await;
                            
                            // Also try to get from database
                            if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                                if latest_anchor.num >= next_epoch {
                                    println!("📥 Found missed epoch #{} in database", latest_anchor.num);
                                    self.current_epoch = Some(latest_anchor.num);
                                    self.mine_epoch(latest_anchor).await?;
                                    self.last_heartbeat = time::Instant::now();
                                    continue;
                                }
                            }
                        }
                        
                        return Err("Heartbeat timeout - no anchors received".into());
                    }
                }
            }
        }
    }

    async fn mine_epoch(&mut self, anchor: Anchor) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Subscribe to anchor broadcasts so we can abort immediately when a newer epoch arrives.
        let mut live_anchor_rx = self.net.anchor_subscribe();

        let creator_address = self.wallet.address();
        let mem_kib = anchor.mem_kib;
        // Consensus guidance: t_cost=1 for PoW; keep from anchor for compatibility if >1 but miner uses anchor value
        let t_cost = 1u32; // mining uses 1; validation will enforce whatever anchor encodes
        let target = crate::crypto::decode_compact_target(anchor.target_nbits).unwrap_or_else(|_| primitive_types::U256::MAX);
        let mut attempts = 0u64;
        let max_attempts = crate::config::default_max_mining_attempts();

        println!("🎯 Starting mining for epoch #{}", anchor.num);
        println!("⚙️  Mining parameters: target_nbits=0x{:08x}, mem_kib={}, t_cost={}, lanes=1 (consensus)", anchor.target_nbits, mem_kib, t_cost);

        loop {
            attempts += 1;
            if attempts > max_attempts {
                eprintln!("⚠️  Reached max attempts ({}) for epoch #{}, continuing to next epoch", max_attempts, anchor.num);
                return Ok(()); // Continue to next epoch
            }

            // Use sequential nonces for efficient coverage of the search space
            let nonce: u64 = attempts;
            let header = Coin::header_bytes(&anchor.hash, nonce, &creator_address);
            
            // Salt is bound to prev anchor hash (challenge); here header already includes epoch binding (prev hash), salt is prev hash
            if let Ok(pow_hash) = crypto::argon2id_pow(&header, &anchor.hash, mem_kib, t_cost) {
                if crate::crypto::leq_hash_to_target(&pow_hash, &target) {
                    // Reset heartbeat so we don't trigger timeout while waiting for the next epoch.
                    // Finding a coin proves the current epoch is still active.
                    self.last_heartbeat = time::Instant::now();

                    let candidate = CoinCandidate::new(anchor.hash, nonce, creator_address, pow_hash);
                    println!("✅ Found a new coin! ID: {} (attempts: {})", hex::encode(candidate.id), attempts);

                    // Candidate key: epoch_hash || coin_id for efficient prefix scans
                    let key = crate::storage::Store::candidate_key(&candidate.epoch_hash, &candidate.id);
                    if let Err(e) = self.db.put("coin_candidate", &key, &candidate) {
                        eprintln!("🔥 Failed to save coin to DB: {e}");
                    } else {
                        // Force immediate flush to ensure coin is persisted
                        if let Err(e) = self.db.flush() {
                            eprintln!("🔥 Failed to flush coin to disk: {e}");
                        }
                    }
                    
                    match self.coin_tx.send(candidate.id) {
                        Ok(_) => println!("📤 Coin {} sent to epoch manager", hex::encode(candidate.id)),
                        Err(e) => eprintln!("🔥 Failed to send coin ID to epoch manager: {e}"),
                    }
                    
                    self.net.gossip_coin(&candidate).await;
                    return Ok(());
                }
            }
            
            // Every 1 000 attempts yield to the scheduler and check if a newer epoch exists.
            if attempts % 10_000 == 0 {
                // Less noisy progress indicator
                println!("⏳ Mining progress: {} attempts for epoch #{}", attempts, anchor.num);

                // NEW: abort early if the chain has already advanced.
                // First, non-blocking check of the live anchor broadcast channel (fast-path).
                match live_anchor_rx.try_recv() {
                    Ok(new_anchor) => {
                        if new_anchor.num > anchor.num {
                            println!("🔄 Received newer epoch #{} while mining #{} – switching epochs", new_anchor.num, anchor.num);
                            return Ok(()); // Outer loop will handle the fresh anchor
                        }
                    },
                    Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                        // Channel closed: treat as abort signal
                        return Err("Anchor broadcast channel closed".into());
                    },
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) | Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
                }

                // Slow-path: also verify DB in case we missed the broadcast (unlikely but safe on multi-node).
                if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                    if latest_anchor.num > anchor.num {
                        println!("🔄 Detected newer epoch #{} in DB while mining #{}, stopping current mining", latest_anchor.num, anchor.num);
                        return Ok(());
                    }
                }

                // Let other tasks run so we don’t starve the runtime.
                tokio::task::yield_now().await;
            }
        }
    }
}