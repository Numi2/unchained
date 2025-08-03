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
                Ok(_) => {
                    // Successful mining session completed
                    self.consecutive_failures = 0;
                    println!("✅ Mining session completed successfully");
                }
                Err(e) => {
                    self.consecutive_failures += 1;
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

    async fn try_connect_and_mine(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut anchor_rx = self.net.anchor_subscribe();
        let mut heartbeat_interval = time::interval(Duration::from_secs(self.cfg.heartbeat_interval_secs));
        
        println!("🔗 Connected to anchor broadcast channel");
        
        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = self.shutdown_rx.recv() => {
                    println!("🛑 Miner received shutdown signal");
                    return Ok(());
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
                    // Allow a more generous timeout (4× heartbeat interval) to avoid premature failures when epoch length exceeds 2×heartbeat.
                    let timeout_secs = self.cfg.heartbeat_interval_secs * 4;
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

    async fn mine_epoch(&self, anchor: Anchor) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let creator_address = self.wallet.address();
        let mem_kib = anchor.mem_kib;
        let difficulty = anchor.difficulty;
        let mut attempts = 0u64;
        let max_attempts = self.cfg.max_mining_attempts;

        println!("🎯 Starting mining for epoch #{} with {} lanes", anchor.num, self.cfg.lanes);

        loop {
            attempts += 1;
            if attempts > max_attempts {
                eprintln!("⚠️  Reached max attempts for epoch #{}, continuing to next epoch", anchor.num);
                return Ok(()); // Continue to next epoch rather than failing completely
            }

            let nonce: u64 = rand::thread_rng().gen();
            let header = Coin::header_bytes(&anchor.hash, nonce, &creator_address);
            
            if let Ok(pow_hash) = crypto::argon2id_pow(&header, mem_kib, self.cfg.lanes) {
                if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
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
            
            // Progress indicator every 10000 attempts
            if attempts % 10000 == 0 {
                println!("⏳ Mining progress: {} attempts for epoch #{}", attempts, anchor.num);
            }
        }
    }
}