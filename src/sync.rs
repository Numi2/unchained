use crate::{storage::Store, epoch::Anchor, network::NetHandle};
use crate::metrics;
use std::{collections::HashMap, sync::{Arc, Mutex}};
use tokio::{sync::{broadcast::Receiver, Semaphore}, task, time::{interval, Duration}};
use std::time::Instant;

const MAX_CONCURRENT_EPOCH_REQUESTS: usize = 10;
const SYNC_CHECK_INTERVAL_SECS: u64 = 1;
// When fully synced, only poll peers for the latest epoch every this many seconds
const SYNC_IDLE_POLL_INTERVAL_SECS: u64 = 30;
// Dedupe repeated requests for the same epoch within this TTL window to avoid network spam
const EPOCH_REQ_DEDUP_TTL_SECS: u64 = 10;

#[derive(Debug)]
pub struct SyncState {
    pub highest_seen_epoch: u64,
    pub synced: bool,
}

impl Default for SyncState {
    fn default() -> Self {
        Self { highest_seen_epoch: 0, synced: false }
    }
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
        let mut last_request_range: Option<(u64, u64)> = None;
        let mut idle_poll_timer = interval(Duration::from_secs(SYNC_IDLE_POLL_INTERVAL_SECS));
        let recent_epoch_reqs: Arc<Mutex<HashMap<u64, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

        // On startup, proactively reconcile our current tip with the network to detect any divergence early.
        if local_epoch > 0 {
            net.request_epoch(local_epoch).await;
        }

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    println!("🛑 Sync task received shutdown signal");
                    break;
                }

                _ = sync_check_timer.tick() => {
                    // Regular fast check while we are still catching up
                    let highest_seen = { sync_state.lock().unwrap().highest_seen_epoch };
                    if highest_seen > local_epoch {
                        // we are behind → mark unsynced
                        { let mut st = sync_state.lock().unwrap(); st.synced = false; }
                        // Ask peers for the latest epoch so we can catch up quickly
                        net.request_latest_epoch().await;
                        // Avoid repeatedly spamming identical request ranges every tick
                        // Compute the actual start_epoch exactly as request_missing_epochs will use
                        let start_epoch = if db.get::<Anchor>("epoch", b"latest").unwrap_or_default().is_none() { 0 } else { local_epoch + 1 };
                        // Only trigger a fetch pass if the bounds changed since last time
                        if last_request_range != Some((start_epoch, highest_seen)) {
                            println!("⛓️  Sync state is ahead (local: {}, network: {}). Requesting missing epochs.", local_epoch, highest_seen);
                            request_missing_epochs(local_epoch, highest_seen, &net, &semaphore, &db, &recent_epoch_reqs).await;
                            last_request_range = Some((start_epoch, highest_seen));
                        } else {
                            // Even if the range is unchanged, re-request only truly missing epochs (respecting dedupe TTL)
                            request_missing_epochs(local_epoch, highest_seen, &net, &semaphore, &db, &recent_epoch_reqs).await;
                        }
                        if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                            if latest_anchor.num != local_epoch {
                                local_epoch = latest_anchor.num;
                                println!("📊 Local epoch updated to: {}", local_epoch);
                                // Reset last_request_range so next gap requests are re-evaluated
                                last_request_range = None;
                            }
                        }
                    }
                }

                _ = idle_poll_timer.tick() => {
                    // Slower polling when fully synced to avoid spamming the network/logs
                    let highest_seen = { sync_state.lock().unwrap().highest_seen_epoch };
                    if highest_seen == local_epoch && highest_seen > 0 {
                        // we are at tip and have actually synced with network → mark synced once
                        {
                            let mut st = sync_state.lock().unwrap();
                            if !st.synced {
                                st.synced = true;
                                println!("✅ Node is fully synced at epoch {}", local_epoch);
                            }
                        } // Drop the mutex guard here
                        net.request_latest_epoch().await;
                    } else if highest_seen == 0 {
                        if local_epoch > 0 {
                            // No network view but we do have a local chain (e.g., single-node). Consider ourselves synced locally.
                            let mut st = sync_state.lock().unwrap();
                            if !st.synced {
                                st.synced = true;
                                if st.highest_seen_epoch == 0 { st.highest_seen_epoch = local_epoch; }
                                println!("✅ No peers visible; treating local epoch {} as tip.", local_epoch);
                            }
                        } else {
                            // We haven't heard from the network yet and have no local chain; keep requesting
                            net.request_latest_epoch().await;
                        }
                    }
                }

                Ok(anchor) = anchor_rx.recv() => {
                    if anchor.num > local_epoch {
                        if anchor.is_better_chain(&db.get("epoch", b"latest").unwrap_or_default()) {
                            if anchor.num > local_epoch + 1 {
                                request_missing_epochs(local_epoch, anchor.num, &net, &semaphore, &db, &recent_epoch_reqs).await;
                            }
                            local_epoch = anchor.num;
                            last_request_range = None; // new tip observed; clear dedupe so we can request next gaps
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
    recent_epoch_reqs: &Arc<Mutex<HashMap<u64, Instant>>>,
) {
    let start_epoch = if db.get::<Anchor>("epoch", b"latest").unwrap_or_default().is_none() {
        0
    } else {
        local_epoch + 1
    };

    if start_epoch > target_epoch {
        return;
    }

    // Compute the set of epochs that are actually missing in our local DB
    let mut to_request: Vec<u64> = Vec::new();
    for n in start_epoch..=target_epoch {
        if db.get::<Anchor>("epoch", &n.to_le_bytes()).unwrap_or_default().is_none() {
            to_request.push(n);
        }
    }
    if to_request.is_empty() {
        return;
    }

    // Dedupe and issue requests with bounded concurrency
    let now = Instant::now();
    let mut request_list: Vec<u64> = Vec::new();
    {
        let mut req_map = recent_epoch_reqs.lock().unwrap();
        // Purge old entries by TTL
        req_map.retain(|_, ts| now.saturating_duration_since(*ts) < std::time::Duration::from_secs(EPOCH_REQ_DEDUP_TTL_SECS));
        for missing in to_request {
            if !req_map.contains_key(&missing) {
                req_map.insert(missing, now);
                request_list.push(missing);
            }
        }
        metrics::EPOCH_REQ_DEDUP_SIZE.set(req_map.len() as i64);
    }

    let mut request_tasks = Vec::new();
    for epoch_num in request_list {
        let net_clone = net.clone();
        let sem_clone = semaphore.clone();
        let task = tokio::spawn(async move {
            // Hold a permit for the entire duration of the network request to enforce concurrency cap
            if let Ok(_permit) = sem_clone.acquire_owned().await {
                net_clone.request_epoch(epoch_num).await;
                // _permit drops here, releasing one slot
            }
        });
        request_tasks.push(task);
    }

    for task in request_tasks {
        task.await.ok();
    }
}
