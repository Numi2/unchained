use crate::{storage::Store, epoch::Anchor, network::NetHandle};
use std::sync::Arc;
use tokio::{sync::{broadcast::Receiver, Semaphore}, task, time::{interval, Duration}};

const MAX_CONCURRENT_EPOCH_REQUESTS: usize = 10;
const SYNC_RETRY_INTERVAL_SECS: u64 = 30; // Retry sync every 30 seconds if stuck

pub fn spawn(db: Arc<Store>, net: NetHandle, mut shutdown_rx: Receiver<()>) {
    let mut anchor_rx: Receiver<Anchor> = net.anchor_subscribe();

    task::spawn(async move {
        let mut local_epoch = db.get::<Anchor>("epoch", b"latest").unwrap_or_default().map_or(0, |a| a.num);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_EPOCH_REQUESTS));
        let mut sync_retry_timer = interval(Duration::from_secs(SYNC_RETRY_INTERVAL_SECS));

        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    println!("🛑 Sync task received shutdown signal");
                    break;
                }
                
                // Periodic sync retry for nodes that might be stuck
                _ = sync_retry_timer.tick() => {
                    let current_best = db.get::<Anchor>("epoch", b"latest").unwrap_or_default();
                    if let Some(best) = current_best {
                        if best.num == 0 {
                            println!("🔄 Node still has only genesis epoch, requesting latest from network...");
                            net.request_latest_epoch().await;
                        }
                    }
                }
                
                // Handle anchor updates
                anchor_result = anchor_rx.recv() => {
                    match anchor_result {
                        Ok(anchor) => {
                            let current_best = db.get::<Anchor>("epoch", b"latest").unwrap_or_default();
                            
                            let should_accept = match current_best {
                                Some(best) => anchor.cumulative_work > best.cumulative_work ||
                                              (anchor.cumulative_work == best.cumulative_work && anchor.num > best.num),
                                None => true,
                            };

                            if should_accept {
                                if anchor.num > local_epoch + 1 {
                                    let missing_count = anchor.num.saturating_sub(local_epoch + 1);
                                    println!("⛓️  Syncing: behind by {} epochs. Requesting missing ones.", missing_count);
                                    
                                    // Request missing epochs in parallel with bounded concurrency
                                    let mut request_tasks = Vec::new();
                                    
                                    for missing in (local_epoch + 1)..anchor.num {
                                        let net_clone = net.clone();
                                        let sem_clone = semaphore.clone();
                                        
                                        let task = tokio::spawn(async move {
                                            // Acquire semaphore permit to limit concurrent requests
                                            let _permit = sem_clone.acquire().await.unwrap();
                                            net_clone.request_epoch(missing).await;
                                        });
                                        
                                        request_tasks.push(task);
                                    }
                                    
                                    // Wait for all requests to complete (but don't block on individual ones)
                                    for task in request_tasks {
                                        if let Err(e) = task.await {
                                            eprintln!("⚠️  Epoch request task failed: {e}");
                                        }
                                    }
                                }
                                local_epoch = anchor.num;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            eprintln!("⚠️  Sync lagged {n} anchors behind; re-checking latest from DB.");
                            local_epoch = db.get::<Anchor>("epoch", b"latest").unwrap_or_default().map_or(0, |a| a.num);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            println!("📡 Anchor broadcast channel closed");
                            break;
                        }
                    }
                }
            }
        }
        
        println!("✅ Sync task shutdown complete");
    });
}