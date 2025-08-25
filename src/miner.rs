use crate::{storage::Store, crypto, epoch::Anchor, coin::{Coin, CoinCandidate}, network::NetHandle, wallet::Wallet};
use rand::Rng;
use pqcrypto_traits::sign::PublicKey as _;
use std::sync::Arc;
use std::collections::{VecDeque, HashSet};
use tokio::{sync::{mpsc, broadcast::Receiver}, task, time::{self, Duration}};
use tokio::sync::broadcast::error::RecvError;

use crate::sync::SyncState;
use std::sync::atomic::{AtomicBool, Ordering};

// Routine miner logs: gated to reduce console noise during normal operation.
static ALLOW_ROUTINE_MINER: AtomicBool = AtomicBool::new(false);
macro_rules! miner_routine { ($($arg:tt)*) => { if ALLOW_ROUTINE_MINER.load(Ordering::Relaxed) { println!($($arg)*); } } }
#[allow(unused_imports)]
use miner_routine;

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
    // Track our recently found coin candidates to report selection results next epoch
    recent_candidates: VecDeque<(u64, [u8; 32])>,
    reported_candidates: HashSet<[u8; 32]>,
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
            recent_candidates: VecDeque::new(),
            reported_candidates: HashSet::new(),
        }
    }

    async fn run(&mut self) {
        // Wait until node is marked synced by main/sync services and local tip >= network tip
        loop {
            let (synced, highest, peer_confirmed, local) = {
                let (synced, highest, peer_confirmed) = self
                    .sync_state
                    .lock()
                    .map(|st| (st.synced, st.highest_seen_epoch, st.peer_confirmed_tip))
                    .unwrap_or((false, 0, false));
                let local = self
                    .db
                    .get::<Anchor>("epoch", b"latest")
                    .unwrap_or(None)
                    .map_or(0, |a| a.num);
                (synced, highest, peer_confirmed, local)
            };

            if synced && highest > 0 && local >= highest && peer_confirmed {
                miner_routine!("🚀 Node is fully synced – starting mining");
                break;
            }

            miner_routine!("⌛ Waiting to reach network tip… local {} / net {} (peer-confirmed: {})", local, highest, peer_confirmed);
            tokio::select! {
                _ = self.shutdown_rx.recv() => { println!("🛑 Miner received shutdown while waiting for sync"); return; }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }

        miner_routine!("⛏️  Starting miner with reconnection and fallback capabilities");
        
        loop {
            match self.try_connect_and_mine().await {
                Ok(()) => {
                    // Successful mining session (found coin or epoch finished)
                    self.consecutive_failures = 0;
                    miner_routine!("✅ Mining session completed successfully");
                }
                Err(e) => {
                    self.consecutive_failures += 1;
                    if e.to_string() == "Shutdown" {
                        println!("🛑 Miner shut down gracefully");
                        break;
                    }
                    eprintln!("(attempt {}/{}) : {}", 
                             self.consecutive_failures, self.max_consecutive_failures, e);
                    
                    if self.consecutive_failures >= self.max_consecutive_failures {
                        eprintln!("🚨 Too many consecutive failures, restarting miner completely");
                        self.consecutive_failures = 0;
                        // Reset current epoch to force fresh start
                        self.current_epoch = None;
                    }
                    
                    // Exponential backoff: wait longer after each failure
                    let backoff_duration = Duration::from_secs(2u64.pow(self.consecutive_failures.min(6)));
                    miner_routine!("⏳ Waiting {} seconds before retry...", backoff_duration.as_secs());
                    time::sleep(backoff_duration).await;
                }
            }
        }
    }

    async fn try_connect_and_mine(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut anchor_rx = self.net.anchor_subscribe();
        let mut heartbeat_interval = time::interval(Duration::from_secs(self.cfg.heartbeat_interval_secs));
        
        miner_routine!("🔗 Connected to anchor broadcast channel");
        
        // doesn’t have to wait for the next anchor broadcast (which can be several minutes away).
        match self.db.get::<Anchor>("epoch", b"latest") {
            Ok(Some(latest_anchor)) => {
                miner_routine!("📥 Loaded latest epoch #{} from database", latest_anchor.num);
                self.current_epoch = Some(latest_anchor.num);
                self.last_heartbeat = time::Instant::now();
                // Guard: do not mine if this local anchor is behind observed network tip
                let behind_tip = self
                    .sync_state
                    .lock()
                    .map(|st| st.highest_seen_epoch > 0 && latest_anchor.num < st.highest_seen_epoch)
                    .unwrap_or(false);
                if behind_tip {
                    miner_routine!(
                        "⏭️  Skipping initial mining at local #{} (network observed >= {})",
                        latest_anchor.num,
                        self.sync_state.lock().map(|st| st.highest_seen_epoch).unwrap_or(0)
                    );
                } else if let Err(e) = self.mine_epoch(latest_anchor.clone()).await {
                    eprintln!("⚠️  Initial mining attempt failed: {e}");
                }
            },
            Ok(None) => {
                // No local epochs yet; request latest from network and wait for broadcasts.
                // In single-node genesis, proceed with anchor stream; epoch manager will create genesis immediately due to immediate ticker.
                miner_routine!("🌱 No existing epochs found locally. Waiting for epoch manager to create genesis…");
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
                            if let Ok(mut st) = self.sync_state.lock() {
                                if anchor.num > st.highest_seen_epoch {
                                    st.highest_seen_epoch = anchor.num;
                                    miner_routine!("📊 Updated sync state: highest_seen_epoch = {}", st.highest_seen_epoch);
                                }
                            }

                            // Report selection results for our candidates from the previous epoch, if any
                            let prev_epoch = anchor.num.saturating_sub(1);
                            let mut ours_prev: Vec<[u8;32]> = Vec::new();
                            for (e, id) in self.recent_candidates.iter() {
                                if *e == prev_epoch && !self.reported_candidates.contains(id) {
                                    ours_prev.push(*id);
                                }
                            }
                            if !ours_prev.is_empty() {
                                // Selection for candidates mined in prev_epoch is recorded under the current anchor number
                                match self.db.get_selected_coin_ids_for_epoch(anchor.num) {
                                    Ok(selected_ids) => {
                                        let selected_set: std::collections::HashSet<[u8;32]> = selected_ids.into_iter().collect();
                                        for id in ours_prev {
                                            if selected_set.contains(&id) {
                                                println!("🎉 Epoch #{} finalized: your coin {} was SELECTED", prev_epoch, hex::encode(id));
                                            }
                                            self.reported_candidates.insert(id);
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("⚠️  Could not read selection for epoch #{}: {}", prev_epoch, e);
                                    }
                                }
                                // Prune very old entries (keep ~2 epochs back)
                                while let Some((e, _)) = self.recent_candidates.front() {
                                    if *e + 2 < anchor.num { self.recent_candidates.pop_front(); } else { break; }
                                }
                            }
                            
                             // Ignore historical or non-adopted alternate anchors during reorg replay.
                             // Only mine the adopted tip or newer.
                             let db_latest_num = self
                                 .db
                                 .get::<Anchor>("epoch", b"latest")
                                 .unwrap_or(None)
                                 .map_or(0, |a| a.num);
                             if anchor.num < db_latest_num {
                                 miner_routine!("⤴️  Ignoring historical anchor #{} (< latest #{}) during reorg replay", anchor.num, db_latest_num);
                                 continue;
                             }
                             if let Ok(Some(existing_at_height)) =
                                 self.db.get::<Anchor>("epoch", &anchor.num.to_le_bytes())
                             {
                                 if existing_at_height.hash != anchor.hash {
                                     miner_routine!("⤴️  Ignoring alternate fork anchor at height {} (not adopted)", anchor.num);
                                     continue;
                                 }
                             }
                             if let Some(curr) = self.current_epoch {
                                 if anchor.num < curr {
                                     miner_routine!("⤴️  Ignoring out-of-order anchor #{} (< current #{})", anchor.num, curr);
                                     continue;
                                 }
                             }
                             
                            miner_routine!("⛏️  New epoch #{}: difficulty={}, mem_kib={}. Mining...", anchor.num, anchor.difficulty, anchor.mem_kib);
                            
                            // Always show wallet balance and address on new epoch
                            if let Ok(balance) = self.wallet.balance() {
                                println!("💰 Wallet balance: {} coins", balance);
                            }
                            println!("📍 Address: {}", hex::encode(self.wallet.address()));

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
                                // Also request a small window around it in case multiple were missed
                                let start = current_epoch.saturating_sub(4);
                                for n in start..current_epoch { self.net.request_epoch(n).await; }
                                
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
                    let timeout_secs = self.cfg.heartbeat_interval_secs * 6;
                    if since_last_heartbeat > Duration::from_secs(timeout_secs) {
                        eprintln!(" No anchor received for {} seconds, checking for missed epochs", 
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

        // Guard: if network tip is ahead of this anchor, skip mining this epoch
        let (net_tip, _peer_confirmed) = self
            .sync_state
            .lock()
            .map(|st| (st.highest_seen_epoch, st.peer_confirmed_tip))
            .unwrap_or((0, false));
        if net_tip > 0 && anchor.num < net_tip {
            miner_routine!(
                "⏭️  Skipping mining for stale epoch #{} (network tip {})",
                anchor.num,
                net_tip
            );
            return Ok(());
        }

        let creator_address = self.wallet.address();
        let mem_kib = anchor.mem_kib;
        let difficulty = anchor.difficulty;
        let mut attempts = 0u64;
        let max_attempts = self.cfg.max_attempts;

        miner_routine!("🎯 Starting mining for epoch #{}", anchor.num);
        miner_routine!("⚙️  Mining parameters: difficulty={}, mem_kib={}, lanes=1 (consensus)", difficulty, mem_kib);
        // Always print a concise start-of-epoch line for better feedback
        println!(
            "⛏️  Mining epoch #{} (difficulty={} zero-bytes, mem={} KiB)",
            anchor.num, difficulty, mem_kib
        );
        // Track progress window for attempts/sec feedback without being too chatty
        let mut last_progress_instant = std::time::Instant::now();
        let mut last_progress_attempts = 0u64;

        loop {
            attempts += 1;
            if attempts > max_attempts {
                eprintln!("⚠️  Reached max attempts ({}) for epoch #{}, continuing to next epoch", max_attempts, anchor.num);
                return Ok(()); // Continue to next epoch
            }

            let nonce: u64 = rand::thread_rng().gen();
            let header = Coin::header_bytes(&anchor.hash, nonce, &creator_address);

            // Measure hashing time and offload to blocking thread to avoid starving async runtime.
            let start = std::time::Instant::now();
            let pow_hash = if self.cfg.offload_blocking {
                tokio::task::spawn_blocking({
                    let header = header.clone();
                    move || crypto::argon2id_pow(&header, mem_kib)
                }).await.unwrap_or_else(|e| Err(anyhow::anyhow!(format!("join error: {}", e))))?
            } else {
                crypto::argon2id_pow(&header, mem_kib)?
            };
            crate::metrics::MINING_ATTEMPTS.inc();
            let elapsed = start.elapsed();
            crate::metrics::MINING_HASH_TIME_MS.observe(elapsed.as_secs_f64() * 1000.0);

            // Consensus requires Argon2 parameters to be deterministic (lanes=1 enforced in function).
            {
                if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
                    // Reset heartbeat so we don't trigger timeout while waiting for the next epoch.
                    // Finding a coin proves the current epoch is still active.
                    self.last_heartbeat = time::Instant::now();

                    let mut creator_pk = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                    creator_pk.copy_from_slice(self.wallet.public_key().as_bytes());
                    let candidate_id = Coin::calculate_id(&anchor.hash, nonce, &creator_address);
                    // Compute genesis lock for this coin deterministically from our Dilithium SK
                    let chain_id = self.db.get_chain_id()?;
                    let s0 = self.wallet.compute_genesis_lock_secret(&candidate_id, &chain_id);
                    let lock_hash = crate::crypto::lock_hash_from_preimage(&chain_id, &candidate_id, &s0);
                    let candidate = CoinCandidate::new(
                        anchor.hash,
                        nonce,
                        creator_address,
                        creator_pk,
                        lock_hash,
                        pow_hash,
                    );
                    println!("✅ Found a new coin! ID: {} (attempts: {})", hex::encode(candidate.id), attempts);
                    crate::metrics::MINING_FOUND.inc();
                    // Track this candidate to report selection result on next epoch
                    self.recent_candidates.push_back((anchor.num, candidate.id));
                    if self.recent_candidates.len() > 64 { self.recent_candidates.pop_front(); }

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
            
            // Periodically yield to the scheduler and check if a newer epoch exists.
            if attempts % self.cfg.check_interval_attempts == 0 {
                // Less noisy progress indicator
                miner_routine!("⏳ Mining progress: {} attempts for epoch #{}", attempts, anchor.num);
                // Print a concise human-facing progress update every ~3 seconds
                let elapsed = last_progress_instant.elapsed();
                if elapsed >= std::time::Duration::from_secs(2) {
                    let delta_attempts = attempts.saturating_sub(last_progress_attempts);
                    let rate = if elapsed.as_secs_f64() > 0.0 {
                        delta_attempts as f64 / elapsed.as_secs_f64()
                    } else { 0.0 };
                    println!(
                        "⏳ Mining epoch #{}: {} attempts (≈{:.1}/s)",
                        anchor.num, attempts, rate
                    );
                    last_progress_instant = std::time::Instant::now();
                    last_progress_attempts = attempts;
                }

                // NEW: abort early if the chain has already advanced.
                // First, non-blocking check of the live anchor broadcast channel (fast-path).
                match live_anchor_rx.try_recv() {
                    Ok(new_anchor) => {
                        if new_anchor.num > anchor.num {
                            // Always print an explicit switch notice; happens infrequently
                            println!(
                                "🔄 Newer epoch #{} detected while mining #{} – switching",
                                new_anchor.num, anchor.num
                            );
                            miner_routine!("🔄 Received newer epoch #{} while mining #{} – switching epochs", new_anchor.num, anchor.num);
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
                        miner_routine!("🔄 Detected newer epoch #{} in DB while mining #{}, stopping current mining", latest_anchor.num, anchor.num);
                        return Ok(());
                    }
                }

                // Let other tasks run so we don’t starve the runtime.
                tokio::task::yield_now().await;
            }
        }
    }
}