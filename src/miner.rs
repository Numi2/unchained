use crate::{
    coin::{Coin, CoinCandidate},
    crypto,
    epoch::Anchor,
    network::NetHandle,
    storage::Store,
    wallet::Wallet,
};
use pqcrypto_traits::sign::PublicKey as _;
use rand::Rng;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::{
    sync::{broadcast::Receiver, mpsc},
    task,
    time::{self, Duration},
};

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
    last_recovery_attempt: Option<time::Instant>,
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
            last_recovery_attempt: None,
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
                // Additional safety: ensure we've been peer-confirmed for a reasonable time
                // to avoid racing with potential fork detection after restart
                miner_routine!("🚀 Node is fully synced – starting mining");
                break;
            }

            miner_routine!(
                "⌛ Waiting to reach network tip… local {} / net {} (peer-confirmed: {})",
                local,
                highest,
                peer_confirmed
            );
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
                    eprintln!(
                        "(attempt {}/{}) : {}",
                        self.consecutive_failures, self.max_consecutive_failures, e
                    );

                    if self.consecutive_failures >= self.max_consecutive_failures {
                        eprintln!("🚨 Too many consecutive failures, restarting miner completely");
                        self.consecutive_failures = 0;
                        // Reset current epoch to force fresh start
                        self.current_epoch = None;
                        // Aggressive recovery: proactively redial bootstraps to regain mesh
                        self.net.redial_bootstraps().await;
                        // Also ask for latest and a small headers window to quickly resync
                        self.net.request_latest_epoch().await;
                        if let Ok(Some(lat)) = self.db.get::<Anchor>("epoch", b"latest") {
                            let start = lat.num.saturating_sub(16);
                            let count: u32 = 32;
                            self.net.request_epoch_headers_range(start, count).await;
                        }
                    }

                    // Exponential backoff: wait longer after each failure
                    let backoff_duration =
                        Duration::from_secs(2u64.pow(self.consecutive_failures.min(6)));
                    miner_routine!(
                        "⏳ Waiting {} seconds before retry...",
                        backoff_duration.as_secs()
                    );
                    time::sleep(backoff_duration).await;
                }
            }
        }
    }

    async fn try_connect_and_mine(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut anchor_rx = self.net.anchor_subscribe();
        let mut heartbeat_interval =
            time::interval(Duration::from_secs(self.cfg.heartbeat_interval_secs));

        miner_routine!("🔗 Connected to anchor broadcast channel");

        // doesn’t have to wait for the next anchor broadcast (which can be several minutes away).
        match self.db.get::<Anchor>("epoch", b"latest") {
            Ok(Some(latest_anchor)) => {
                miner_routine!(
                    "📥 Loaded latest epoch #{} from database",
                    latest_anchor.num
                );
                self.current_epoch = Some(latest_anchor.num);
                self.last_heartbeat = time::Instant::now();
                // Guard: do not mine if this local anchor is behind observed network tip
                let behind_tip = self
                    .sync_state
                    .lock()
                    .map(|st| {
                        st.highest_seen_epoch > 0 && latest_anchor.num < st.highest_seen_epoch
                    })
                    .unwrap_or(false);
                if behind_tip {
                    miner_routine!(
                        "⏭️  Skipping initial mining at local #{} (network observed >= {})",
                        latest_anchor.num,
                        self.sync_state
                            .lock()
                            .map(|st| st.highest_seen_epoch)
                            .unwrap_or(0)
                    );
                } else if let Err(e) = self.mine_epoch(latest_anchor.clone()).await {
                    eprintln!("⚠️  Initial mining attempt failed: {e}");
                }
            }
            Ok(None) => {
                // No local epochs yet; request latest from network and wait for broadcasts.
                // In single-node genesis, proceed with anchor stream; epoch manager will create genesis immediately due to immediate ticker.
                miner_routine!("🌱 No existing epochs found locally. Waiting for epoch manager to create genesis…");
            }
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
                            self.last_recovery_attempt = None;
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
                            self.request_recovery("anchor channel lag").await;
                            if let Some(latest_anchor) = self.latest_anchor_if_newer_than_current()? {
                                println!("📥 Recovered latest epoch #{} after lag", latest_anchor.num);
                                self.current_epoch = Some(latest_anchor.num);
                                self.last_heartbeat = time::Instant::now();
                                self.last_recovery_attempt = None;
                                self.mine_epoch(latest_anchor).await?;
                            }
                            continue;
                        }
                    }
                }

                // Heartbeat monitoring
                _ = heartbeat_interval.tick() => {
                    // Lightweight keepalive and cross-check of epoch candidates
                    // This helps keep QUIC/NAT bindings warm and asks peers' epoch managers
                    // for their current candidate sets for the latest known parent hash.
                    if self.net.peer_count() > 0 {
                        self.net.request_latest_epoch().await;
                        if let Ok(Some(latest)) = self.db.get::<Anchor>("epoch", b"latest") {
                            self.net.request_epoch_candidates(latest.hash).await;
                        }
                    }

                    let since_last_heartbeat = self.last_heartbeat.elapsed();
                    let timeout_secs = self.cfg.heartbeat_interval_secs * 5;
                    if since_last_heartbeat > Duration::from_secs(timeout_secs) {
                        eprintln!(
                                "⚠️  No anchor progress for {} seconds; requesting recovery",
                            since_last_heartbeat.as_secs()
                        );
                        self.request_recovery("heartbeat timeout").await;
                        if let Some(latest_anchor) = self.latest_anchor_if_newer_than_current()? {
                            println!("📥 Resuming mining from recovered epoch #{}", latest_anchor.num);
                            self.current_epoch = Some(latest_anchor.num);
                            self.last_heartbeat = time::Instant::now();
                            self.last_recovery_attempt = None;
                            self.mine_epoch(latest_anchor).await?;
                        }
                    }
                }
            }
        }
    }

    fn latest_anchor_if_newer_than_current(
        &self,
    ) -> Result<Option<Anchor>, Box<dyn std::error::Error + Send + Sync>> {
        let latest = self.db.get::<Anchor>("epoch", b"latest")?;
        Ok(match (self.current_epoch, latest) {
            (Some(current_epoch), Some(anchor)) if anchor.num > current_epoch => Some(anchor),
            (None, Some(anchor)) => Some(anchor),
            _ => None,
        })
    }

    async fn request_recovery(&mut self, reason: &str) {
        let now = time::Instant::now();
        let min_interval = Duration::from_secs(self.cfg.heartbeat_interval_secs.max(5));
        if let Some(last) = self.last_recovery_attempt {
            if now.duration_since(last) < min_interval {
                return;
            }
        }

        miner_routine!("🔄 Recovery requested: {}", reason);
        self.last_recovery_attempt = Some(now);
        self.net.request_latest_epoch().await;
        if let Some(current_epoch) = self.current_epoch {
            self.net.request_epoch(current_epoch).await;
            self.net
                .request_epoch(current_epoch.saturating_add(1))
                .await;
            let start = current_epoch.saturating_sub(8);
            let count: u32 = (current_epoch.saturating_add(1).saturating_sub(start)).min(64) as u32;
            self.net.request_epoch_headers_range(start, count).await;
        }
        if self.net.peer_count() == 0 {
            self.net.redial_bootstraps().await;
        }
    }

    async fn mine_epoch(
        &mut self,
        anchor: Anchor,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        // Safety: at retarget boundaries, only mine when our local retarget window is complete.
        // This avoids producing anchors with params that will be rejected once history arrives.
        if anchor.num > 0 && anchor.num % crate::consensus::RETARGET_INTERVAL == 0 {
            if let Ok(window_opt) = self.db.get_or_build_retarget_window(anchor.num) {
                let ready = window_opt
                    .as_ref()
                    .map(|w| w.len() as u64 == crate::consensus::RETARGET_INTERVAL)
                    .unwrap_or(false);
                if !ready {
                    println!(
                        "⏳ Retarget guard: delaying mining for epoch #{} until historical window [{}..{}] is complete",
                        anchor.num,
                        anchor.num.saturating_sub(crate::consensus::RETARGET_INTERVAL),
                        anchor.num.saturating_sub(1)
                    );
                    return Ok(());
                }
            } else {
                println!(
                    "⏳ Retarget guard: delaying mining for epoch #{} (window fetch error)",
                    anchor.num
                );
                return Ok(());
            }
        }
        let mut attempts = 0u64;
        let max_attempts = self.cfg.max_attempts;

        miner_routine!("🎯 Starting mining for epoch #{}", anchor.num);
        miner_routine!(
            "⚙️  Mining parameters: difficulty={}, mem_kib={}",
            difficulty,
            mem_kib
        );
        // Always print a concise start-of-epoch line for better feedback
        println!(
            "⛏️  Mining epoch #{} (difficulty={} zero-bytes, mem={} KiB)",
            anchor.num, difficulty, mem_kib
        );
        // Track progress window for attempts/sec feedback without being too chatty
        const PROGRESS_LOG_INTERVAL_ATTEMPTS: u64 = 10_000;
        let mut last_progress_instant = std::time::Instant::now();
        let mut last_progress_attempts = 0u64;

        // Batched hashing: eliminate per-attempt spawn_blocking overhead and allocations
        let check_every = self.cfg.check_interval_attempts.max(1);
        let mut next_nonce: u64 = rand::thread_rng().gen();
        let epoch_hash = anchor.hash;
        let creator_addr = creator_address;

        loop {
            if attempts >= max_attempts {
                eprintln!(
                    "⚠️  Reached max attempts ({}) for epoch #{}, continuing to next epoch",
                    max_attempts, anchor.num
                );
                return Ok(());
            }

            let batch_size = std::cmp::min(check_every, max_attempts - attempts);

            // Run up to 'batch_size' attempts in a single blocking worker to reduce spawn overhead
            let (found_opt, batch_attempts) = if self.cfg.offload_blocking {
                tokio::task::spawn_blocking({
                    let epoch_hash = epoch_hash;
                    let creator_addr = creator_addr;
                    let start_nonce = next_nonce;
                    move || -> Result<(Option<(u64, [u8; 32])>, u64), anyhow::Error> {
                        // Reuse fixed header buffer to avoid Vec allocations
                        let mut header = [0u8; 32 + 8 + 32]; // epoch_hash + nonce + creator_address
                        header[..32].copy_from_slice(&epoch_hash);
                        header[40..].copy_from_slice(&creator_addr);

                        let mut nonce = start_nonce;
                        let mut local_attempts = 0u64;

                        while local_attempts < batch_size {
                            // Update nonce in header buffer
                            header[32..40].copy_from_slice(&nonce.to_le_bytes());

                            let pow_hash = crate::crypto::argon2id_pow(&header, mem_kib)?;
                            local_attempts += 1;

                            // Check if we found a valid coin
                            if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
                                return Ok((Some((nonce, pow_hash)), local_attempts));
                            }

                            // Sequential nonce to avoid RNG overhead in tight loop
                            nonce = nonce.wrapping_add(1);
                        }
                        Ok((None, local_attempts))
                    }
                })
                .await
                .map_err(|e| anyhow::anyhow!("join error: {}", e))??
            } else {
                // Non-blocking version for when offload_blocking is disabled
                let mut found_opt = None;
                let mut header = [0u8; 32 + 8 + 32];
                header[..32].copy_from_slice(&epoch_hash);
                header[40..].copy_from_slice(&creator_addr);

                let mut nonce = next_nonce;
                let mut local_attempts = 0u64;

                while local_attempts < batch_size {
                    header[32..40].copy_from_slice(&nonce.to_le_bytes());
                    let pow_hash = crypto::argon2id_pow(&header, mem_kib)?;
                    local_attempts += 1;

                    if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
                        found_opt = Some((nonce, pow_hash));
                        break;
                    }

                    nonce = nonce.wrapping_add(1);
                }
                (found_opt, local_attempts)
            };

            attempts += batch_attempts;
            next_nonce = next_nonce.wrapping_add(batch_attempts);

            // Update metrics for the batch
            crate::metrics::MINING_ATTEMPTS.inc_by(batch_attempts);

            // Check if we found a valid coin
            if let Some((nonce, pow_hash)) = found_opt {
                // Reset heartbeat so we don't trigger timeout while waiting for the next epoch.
                // Finding a coin proves the current epoch is still active.
                self.last_heartbeat = time::Instant::now();

                let mut creator_pk = [0u8; crate::crypto::DILITHIUM3_PK_BYTES];
                creator_pk.copy_from_slice(self.wallet.public_key().as_bytes());
                let candidate_id = Coin::calculate_id(&anchor.hash, nonce, &creator_addr);
                // Compute genesis lock for this coin deterministically from our Dilithium SK
                let chain_id = self.db.get_chain_id()?;
                let s0 = self
                    .wallet
                    .compute_genesis_lock_secret(&candidate_id, &chain_id);
                let lock_hash =
                    crate::crypto::lock_hash_from_preimage(&chain_id, &candidate_id, &s0);
                let candidate = CoinCandidate::new(
                    anchor.hash,
                    nonce,
                    creator_addr,
                    creator_pk,
                    lock_hash,
                    pow_hash,
                );
                println!(
                    "✅ Found a new coin! ID: {} (attempts: {})",
                    hex::encode(candidate.id),
                    attempts
                );
                crate::metrics::MINING_FOUND.inc();
                // Track this candidate to report selection result on next epoch
                self.recent_candidates.push_back((anchor.num, candidate.id));
                if self.recent_candidates.len() > 64 {
                    self.recent_candidates.pop_front();
                }

                // Candidate key: epoch_hash || coin_id for efficient prefix scans
                let key =
                    crate::storage::Store::candidate_key(&candidate.epoch_hash, &candidate.id);
                if let Err(e) = self.db.put("coin_candidate", &key, &candidate) {
                    eprintln!("🔥 Failed to save coin to DB: {e}");
                } else {
                    // Force immediate flush to ensure coin is persisted
                    if let Err(e) = self.db.flush() {
                        eprintln!("🔥 Failed to flush coin to disk: {e}");
                    }
                }

                match self.coin_tx.send(candidate.id) {
                    Ok(_) => println!(
                        "📤 Coin {} sent to epoch manager",
                        hex::encode(candidate.id)
                    ),
                    Err(e) => eprintln!("🔥 Failed to send coin ID to epoch manager: {e}"),
                }

                self.net.gossip_coin(&candidate).await;
                return Ok(());
            }

            // Progress logging (runs once per batch instead of per attempt)
            miner_routine!(
                "⏳ Mining progress: {} attempts for epoch #{}",
                attempts,
                anchor.num
            );
            if attempts % PROGRESS_LOG_INTERVAL_ATTEMPTS == 0 {
                let elapsed = last_progress_instant.elapsed();
                if elapsed >= std::time::Duration::from_secs(2) {
                    let delta_attempts = attempts.saturating_sub(last_progress_attempts);
                    let rate = if elapsed.as_secs_f64() > 0.0 {
                        delta_attempts as f64 / elapsed.as_secs_f64()
                    } else {
                        0.0
                    };
                    println!(
                        "⏳ Mining epoch #{}: {} attempts (≈{:.1}/s)",
                        anchor.num, attempts, rate
                    );
                    last_progress_instant = std::time::Instant::now();
                    last_progress_attempts = attempts;
                }
            }

            // Check for newer epochs (same logic as before, but runs once per batch)
            match live_anchor_rx.try_recv() {
                Ok(new_anchor) => {
                    if new_anchor.num > anchor.num {
                        println!(
                            "🔄 Newer epoch #{} detected while mining #{} – switching",
                            new_anchor.num, anchor.num
                        );
                        miner_routine!(
                            "🔄 Received newer epoch #{} while mining #{} – switching epochs",
                            new_anchor.num,
                            anchor.num
                        );
                        return Ok(());
                    }
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    return Err("Anchor broadcast channel closed".into());
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_))
                | Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
            }

            // Slow-path DB check
            if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                if latest_anchor.num > anchor.num {
                    miner_routine!("🔄 Detected newer epoch #{} in DB while mining #{}, stopping current mining", latest_anchor.num, anchor.num);
                    return Ok(());
                }
            }

            // Let other tasks run
            tokio::task::yield_now().await;
        }
    }
}
