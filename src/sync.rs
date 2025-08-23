use crate::{storage::Store, epoch::Anchor, network::NetHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::{sync::{broadcast::Receiver, Semaphore}, task, time::{interval, Duration}};
use tokio::sync::mpsc;

const MAX_CONCURRENT_EPOCH_REQUESTS: usize = 10;
// Back-off parameters to avoid spamming the same missing tip repeatedly when reorg
// cannot proceed due to unavailable fork parents.
const TIP_REQUEST_BACKOFF_MS: u64 = 1500;
const SYNC_CHECK_INTERVAL_SECS: u64 = 2;
// When fully synced, only poll peers for the latest epoch every this many seconds
const SYNC_IDLE_POLL_INTERVAL_SECS: u64 = 30;

// Routine sync logs are noisy; gate behind a static flag disabled by default.
static ALLOW_ROUTINE_SYNC: AtomicBool = AtomicBool::new(false);
macro_rules! sync_routine {
    ($($arg:tt)*) => {
        if ALLOW_ROUTINE_SYNC.load(Ordering::Relaxed) { println!($($arg)*); }
    };
}
#[allow(unused_imports)]
use sync_routine;

#[derive(Debug)]
pub struct SyncState {
    pub highest_seen_epoch: u64,
    pub synced: bool,
    // True once at least one peer has confirmed our tip (via receiving any valid anchor)
    pub peer_confirmed_tip: bool,
}

impl Default for SyncState {
    fn default() -> Self {
        Self { highest_seen_epoch: 0, synced: false, peer_confirmed_tip: false }
    }
}

pub fn spawn(
    db: Arc<Store>,
    net: NetHandle,
    sync_state: Arc<Mutex<SyncState>>,
    mut shutdown_rx: Receiver<()>,
    has_bootstrap: bool,
) {
    let mut anchor_rx: Receiver<Anchor> = net.anchor_subscribe();
    let mut spend_rx = net.spend_subscribe();

    task::spawn(async move {
        let mut local_epoch = db.get::<Anchor>("epoch", b"latest").unwrap_or_default().map_or(0, |a| a.num);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_EPOCH_REQUESTS));
        let mut sync_check_timer = interval(Duration::from_secs(SYNC_CHECK_INTERVAL_SECS));
        let mut idle_poll_timer = interval(Duration::from_secs(SYNC_IDLE_POLL_INTERVAL_SECS));
        let mut backfill_timer = interval(Duration::from_secs(10));

        let mut last_tip_request: Option<(u64, std::time::Instant)> = None;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    println!("🛑 Sync task received shutdown signal");
                    break;
                }

                _ = sync_check_timer.tick() => {
                    // Regular fast check while we are still catching up
                    let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                    if highest_seen > local_epoch {
                        // we are behind → mark unsynced
                        if let Ok(mut st) = sync_state.lock() { st.synced = false; }
                        // Avoid hammering the same tip if we've just requested it very recently
                        let now = std::time::Instant::now();
                        let should_request = match last_tip_request {
                            Some((h, t)) if h == highest_seen && now.duration_since(t).as_millis() < TIP_REQUEST_BACKOFF_MS as u128 => false,
                            _ => true,
                        };
                        if should_request {
                            // Ask peers for the latest epoch so we can catch up quickly
                            net.request_latest_epoch().await;
                            sync_routine!("⛓️  Sync state is ahead (local: {}, network: {}). Requesting missing epochs.", local_epoch, highest_seen);
                            request_missing_epochs(local_epoch, highest_seen, &net, &semaphore, &db).await;
                            last_tip_request = Some((highest_seen, now));
                        }
                        if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                            local_epoch = latest_anchor.num;
                            sync_routine!("📊 Local epoch updated to: {}", local_epoch);
                        }
                    }
                }

                _ = idle_poll_timer.tick() => {
                    // Slower polling when fully synced to avoid spamming the network/logs
                    let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                    if highest_seen == local_epoch && highest_seen > 0 {
                        // we are at tip and have actually synced with network → mark synced once
                        if let Ok(mut st) = sync_state.lock() { if !st.synced { st.synced = true; sync_routine!("✅ Node is fully synced at epoch {}", local_epoch); } }
                        net.request_latest_epoch().await;
                    } else if highest_seen == 0 {
                        if local_epoch > 0 {
                            if has_bootstrap {
                                // With bootstrap configured, do not self-declare synced; keep polling peers.
                                sync_routine!("⏳ No peer anchors observed yet; requesting latest epoch (local {}).", local_epoch);
                                net.request_latest_epoch().await;
                            } else {
                                // No network view but we do have a local chain (e.g., single-node). Consider ourselves synced locally.
                                if let Ok(mut st) = sync_state.lock() {
                                    if !st.synced {
                                        st.synced = true;
                                        if st.highest_seen_epoch == 0 { st.highest_seen_epoch = local_epoch; }
                                        sync_routine!("✅ No peers visible; treating local epoch {} as tip.", local_epoch);
                                    }
                                }
                            }
                        } else {
                            // We haven't heard from the network yet and have no local chain; keep requesting
                            net.request_latest_epoch().await;
                        }
                    }
                }

                _ = backfill_timer.tick() => {
                    // Background spend backfill to ensure offline receivers catch up
                    if let Ok(Some(latest)) = db.get::<Anchor>("epoch", b"latest") {
                        let window: u64 = 16; // scan recent epochs
                        let start = latest.num.saturating_sub(window);
                        for n in start..=latest.num {
                            // Preferred path: use per-epoch selected ids index
                            let mut ids: Vec<[u8;32]> = db.get_selected_coin_ids_for_epoch(n).unwrap_or_default();
                            // Fallback: if selected index missing/empty, derive ids from stored confirmed coins for that epoch
                            if ids.is_empty() {
                                if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &n.to_le_bytes()) {
                                    if let Ok(all_confirmed) = db.iterate_coins() {
                                        ids = all_confirmed
                                            .into_iter()
                                            .filter(|c| c.epoch_hash == anchor.hash)
                                            .map(|c| c.id)
                                            .collect();
                                    }
                                }
                            }
                            for id in ids {
                                // If we don't yet have a spend, request it
                                let have_spend: Option<crate::transfer::Spend> = db.get("spend", &id).unwrap_or(None);
                                if have_spend.is_some() { continue; }
                                net.request_spend(id).await;
                            }
                        }

                        // Additionally, heal orphaned spends (spend present without its coin)
                        if let Some(sp_cf) = db.db.cf_handle("spend") {
                            let iter = db.db.iterator_cf(sp_cf, rocksdb::IteratorMode::Start);
                            for item in iter {
                                if let Ok((_k, v)) = item {
                                    if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&v) {
                                        if db.get::<crate::coin::Coin>("coin", &sp.coin_id).unwrap_or(None).is_none() {
                                            net.request_coin(sp.coin_id).await;
                                        }
                                    }
                                }
                            }
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
                Ok(_sp) = spend_rx.recv() => {
                    // Wallet rescan hook point; wallet scans are dynamic via list_unspent/balance.
                }
            }
        }
        println!("✅ Sync task shutdown complete");
    });
}

// --- Headers-first skeleton sync: bounded pipeline scaffolding ---
#[derive(Debug, Clone)]
struct RangeTask { start: u64, count: u32 }

#[derive(Debug, Clone)]
struct HeaderSegment { headers: Vec<Anchor> }

pub async fn spawn_headers_skeleton(
    db: Arc<Store>,
    net: NetHandle,
    mut shutdown_rx: Receiver<()>,
) {
    let (range_tx, range_rx) = mpsc::channel::<RangeTask>(256);
    let (seg_tx, mut seg_rx) = mpsc::channel::<HeaderSegment>(64);
    let _workers = 3usize;

    // Fetch workers
    {
        let netc = net.clone();
        let mut range_rx_c = range_rx;
        let _seg_tx_c = seg_tx.clone();
        let db_for_req = db.clone();
        task::spawn(async move {
            loop {
                tokio::select! {
                    Some(task) = range_rx_c.recv() => {
                        netc.request_epoch_headers_range(task.start, task.count).await;
                        // Persist highest_requested cursor
                        if let Ok((mut highest_req, highest_stored)) = db_for_req.get_headers_cursor() {
                            if task.start.saturating_add(task.count as u64).saturating_sub(1) > highest_req {
                                highest_req = task.start.saturating_add(task.count as u64).saturating_sub(1);
                                let _ = db_for_req.put_headers_cursor(highest_req, highest_stored);
                            }
                        }
                    }
                    else => break,
                }
            }
        });
    }

    // Inbound header batches → enqueue segments (producer)
    let mut headers_rx = net.headers_subscribe();
    let seg_tx_producer = seg_tx.clone();
    task::spawn(async move {
        loop {
            tokio::select! {
                Ok(batch) = headers_rx.recv() => {
                    crate::metrics::HEADERS_BATCH_RECV.inc();
                    let _ = seg_tx_producer.send(HeaderSegment { headers: batch.headers }).await;
                },
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // Segment consumer: validate, fork-choice, store, update cursor
    let db_headers = db.clone();
    task::spawn(async move {
        loop {
            tokio::select! {
                Some(seg) = seg_rx.recv() => {
                    let mut ok = true;
                    for (idx, a) in seg.headers.iter().enumerate() {
                        if idx == 0 {
                            if a.num > 0 {
                                if let Ok(Some(prev)) = db_headers.get::<Anchor>("epoch", &(a.num - 1).to_le_bytes()) {
                                    let mut h = blake3::Hasher::new();
                                    h.update(&a.merkle_root); h.update(&prev.hash);
                                    let recomputed = *h.finalize().as_bytes();
                                    if recomputed != a.hash { ok = false; break; }
                                    let expected = Anchor::expected_work_for_difficulty(a.difficulty);
                                    if a.cumulative_work != prev.cumulative_work.saturating_add(expected) { ok = false; break; }
                                }
                            }
                        } else {
                            let prev = &seg.headers[idx-1];
                            if a.num != prev.num + 1 { ok = false; break; }
                            let mut h = blake3::Hasher::new();
                            h.update(&a.merkle_root); h.update(&prev.hash);
                            if *h.finalize().as_bytes() != a.hash { ok = false; break; }
                            let expected = Anchor::expected_work_for_difficulty(a.difficulty);
                            if a.cumulative_work != prev.cumulative_work.saturating_add(expected) { ok = false; break; }
                        }
                    }
                    if !ok { crate::metrics::HEADERS_INVALID.inc(); continue; }

                    let current_best = db_headers.get::<Anchor>("epoch", b"latest").ok().flatten();
                    if let Some(last) = seg.headers.last() {
                        if last.is_better_chain(&current_best) {
                            for a in &seg.headers {
                                if db_headers.put("epoch", &a.num.to_le_bytes(), a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                if db_headers.put("anchor", &a.hash, a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                crate::metrics::HEADERS_ANCHORS_STORED.inc();
                            }
                            if let Some(tip) = seg.headers.last() {
                                if db_headers.put("epoch", b"latest", tip).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                let (highest_req, mut highest_stored) = db_headers.get_headers_cursor().unwrap_or((0,0));
                                if tip.num > highest_stored { highest_stored = tip.num; let _ = db_headers.put_headers_cursor(highest_req, highest_stored); }
                            }
                        }
                    }
                },
                else => break,
            }
        }
    });

    // Seed ranges based on cursor
    let (_req, stored) = db.get_headers_cursor().unwrap_or((0,0));
    let start = if stored == 0 { 0 } else { stored + 1 };
    // Request a wider window to saturate network
    let mut s = start;
    for _ in 0..8u32 { // 8 ranges in flight
        let _ = range_tx.send(RangeTask{ start: s, count: 512 }).await;
        s = s.saturating_add(512);
    }
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

    sync_routine!("📥 Requesting epochs {} to {}", start_epoch, target_epoch);
    let mut request_tasks = Vec::new();
    for missing in start_epoch..=target_epoch {
        let net_clone = net.clone();
        let sem_clone = semaphore.clone();
        let task = tokio::spawn(async move {
            let Ok(_permit) = sem_clone.acquire().await else { return; };
            net_clone.request_epoch(missing).await;
        });
        request_tasks.push(task);
    }
    for task in request_tasks {
        let _ = task.await;
    }
}
