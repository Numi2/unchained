use crate::{storage::Store, epoch::Anchor, network::NetHandle};
use std::sync::{Arc, Mutex};
use tokio::{sync::{broadcast::Receiver, Semaphore}, task, time::{interval, Duration}};

const MAX_CONCURRENT_EPOCH_REQUESTS: usize = 10;
const SYNC_CHECK_INTERVAL_SECS: u64 = 1;

#[derive(Default, Debug)]
pub struct SyncState {
    pub highest_seen_epoch: u64,
}

pub fn spawn(
    db: Arc<Store>,
    net: NetHandle,
    sync_state: Arc<Mutex<SyncState>>,
    mut shutdown_rx: Receiver<()>,
) {
    let mut anchor_rx: Receiver<Anchor> = net.anchor_subscribe();

    task::spawn(async move {
        let mut local_epoch = db.get::<Anchor>("epoch", b"latest").unwrap_or_default().map_or(0, |a| a.num);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_EPOCH_REQUESTS));
        let mut sync_check_timer = interval(Duration::from_secs(SYNC_CHECK_INTERVAL_SECS));

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    println!("🛑 Sync task received shutdown signal");
                    break;
                }

                _ = sync_check_timer.tick() => {
                    net.request_latest_epoch().await;
                    let highest_seen = { sync_state.lock().unwrap().highest_seen_epoch };
                    if highest_seen > local_epoch {
                        println!("⛓️  Sync state is ahead (local: {}, network: {}). Requesting missing epochs.", local_epoch, highest_seen);
                        request_missing_epochs(local_epoch, highest_seen, &net, &semaphore, &db).await;
                        if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                            local_epoch = latest_anchor.num;
                            println!("📊 Local epoch updated to: {}", local_epoch);
                        }
                    }
                }

                Ok(anchor) = anchor_rx.recv() => {
                    if anchor.num > local_epoch {
                        if anchor.is_better_chain(&db.get("epoch", b"latest").unwrap_or_default()) {
                            if anchor.num > local_epoch + 1 {
                                request_missing_epochs(local_epoch, anchor.num, &net, &semaphore, &db).await;
                            }
                            local_epoch = anchor.num;
                        }
                    }
                }
            }
        }
        println!("✅ Sync task shutdown complete");
    });
}

async fn request_missing_epochs(
    local_epoch: u64,
    target_epoch: u64,
    net: &NetHandle,
    semaphore: &Arc<Semaphore>,
    db: &Arc<Store>,
) {
    let start_epoch = if db.get::<Anchor>("epoch", b"latest").unwrap_or_default().is_none() {
        0
    } else {
        local_epoch + 1
    };

    if start_epoch > target_epoch {
        return;
    }

    println!("📥 Requesting epochs {} to {}", start_epoch, target_epoch);
    let mut request_tasks = Vec::new();
    for missing in start_epoch..=target_epoch {
        let net_clone = net.clone();
        let sem_clone = semaphore.clone();
        let task = tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            net_clone.request_epoch(missing).await;
        });
        request_tasks.push(task);
    }
    for task in request_tasks {
        task.await.ok();
    }
}
