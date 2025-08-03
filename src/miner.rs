use crate::{storage::Store, crypto, epoch::Anchor, coin::Coin, network::NetHandle, wallet::Wallet};
use rand::Rng;
use std::sync::Arc;
use tokio::{sync::{mpsc, broadcast::Receiver}, task, time::{self, Duration}};
use tokio::sync::broadcast::error::RecvError;

pub fn spawn(
    cfg: crate::config::Mining,
    db: Arc<Store>,
    net: NetHandle,
    wallet: Arc<Wallet>, // The miner needs a persistent identity
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
    shutdown_rx: Receiver<()>,
) {
    task::spawn(async move {
        let mut miner = Miner::new(cfg, db, net, wallet, coin_tx, shutdown_rx);
        miner.run().await;
    });
}

struct Miner {
    cfg: crate::config::Mining,
    db: Arc<Store>,
    net: NetHandle,
    wallet: Arc<Wallet>,
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
    shutdown_rx: Receiver<()>,
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
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            db,
            net,
            wallet,
            coin_tx,
            shutdown_rx,
            current_epoch: None,
            last_heartbeat: time::Instant::now(),
            consecutive_failures: 0,
            max_consecutive_failures: cfg.max_consecutive_failures,
        }
    }

    async fn run(&mut self) {
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
        let mut heartbeat_interval = time::interval(Duration::from_secs(self.cfg.heartbeat_interval_secs));
        
        println!("🔗 Connected to anchor broadcast channel");
        
        // NEW: Immediately fetch the latest epoch from the database so that a miner started mid-epoch
        // doesn’t have to wait for the next anchor broadcast (which can be several minutes away).
        if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
            println!("📥 Loaded latest epoch #{} from database", latest_anchor.num);
            self.current_epoch = Some(latest_anchor.num);
            self.last_heartbeat = time::Instant::now();
            // Start mining straight away. If this fails (e.g., because the epoch already finished)
            // we’ll simply continue to the select! loop and await the next anchor.
            if let Err(e) = self.mine_epoch(latest_anchor.clone()).await {
                eprintln!("⚠️  Initial mining attempt failed: {e}");
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
                            
                            println!(
                                "⛏️  New epoch #{}: difficulty={}, mem_kib={}. Mining...",
                                anchor.num, anchor.difficulty, anchor.mem_kib
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
                    let timeout_secs = self.cfg.heartbeat_interval_secs * 6;
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
        let difficulty = anchor.difficulty;
        let mut attempts = 0u64;
        let max_attempts = self.cfg.max_mining_attempts;

        println!("🎯 Starting mining for epoch #{} with {} lanes", anchor.num, self.cfg.lanes);
        println!("⚙️  Mining parameters: difficulty={}, mem_kib={}", difficulty, mem_kib);

        loop {
            attempts += 1;
            if attempts > max_attempts {
                eprintln!("⚠️  Reached max attempts ({}) for epoch #{}, continuing to next epoch", max_attempts, anchor.num);
                return Ok(()); // Continue to next epoch
            }

            let nonce: u64 = rand::thread_rng().gen();
            let header = Coin::header_bytes(&anchor.hash, nonce, &creator_address);
            
            if let Ok(pow_hash) = crypto::argon2id_pow(&header, mem_kib, self.cfg.lanes) {
                                    if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
                    // Reset heartbeat so we don't trigger timeout while waiting for the next epoch.
                    // Finding a coin proves the current epoch is still active.
                    self.last_heartbeat = time::Instant::now();

                    let coin = Coin::new(anchor.hash, nonce, creator_address, pow_hash);
                    println!("✅ Found a new coin! ID: {} (attempts: {})", hex::encode(coin.id), attempts);

                    if let Err(e) = self.db.put("coin", &coin.id, &coin) {
                        eprintln!("🔥 Failed to save coin to DB: {e}");
                    } else {
                        // Force immediate flush to ensure coin is persisted
                        if let Err(e) = self.db.flush() {
                            eprintln!("🔥 Failed to flush coin to disk: {e}");
                        }
                    }
                    
                    match self.coin_tx.send(coin.id) {
                        Ok(_) => println!("📤 Coin {} sent to epoch manager", hex::encode(coin.id)),
                        Err(e) => eprintln!("🔥 Failed to send coin ID to epoch manager: {e}"),
                    }
                    
                    self.net.gossip_coin(&coin).await;
                    return Ok(());
                }
            }
            
            // Every 10 000 attempts yield to the scheduler and check if a newer epoch exists.
            if attempts % 10_000 == 0 {
                // Progress indicator
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