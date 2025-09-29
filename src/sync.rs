use crate::{storage::Store, epoch::Anchor, network::NetHandle, consensus::{RETARGET_INTERVAL, validate_header_params, Params}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::{sync::{broadcast::Receiver, Semaphore}, task, time::{interval, Duration}};
use tokio::sync::mpsc;

const MAX_CONCURRENT_EPOCH_REQUESTS: usize = 32;  // Increased for faster catch-up
// Back-off parameters to avoid spamming the same missing tip repeatedly when reorg
// cannot proceed due to unavailable fork parents.
const TIP_REQUEST_BACKOFF_MS: u64 = 500;  // Reduced for faster retry
const SYNC_CHECK_INTERVAL_SECS: u64 = 2;
// When fully synced, only poll peers for the latest epoch every this many seconds
const SYNC_IDLE_POLL_INTERVAL_SECS: u64 = 30;
// Maximum epochs to request in a single batch to avoid overwhelming the network
const MAX_EPOCH_BATCH_SIZE: u64 = 100;
// Track failed epoch requests for retry
const FAILED_EPOCH_RETRY_SECS: u64 = 5;


// Add new constants for better recovery
const RECOVERY_EPOCH_BATCH_SIZE: u64 = 20;  // Smaller batches during recovery
const RECOVERY_REQUEST_INTERVAL_MS: u64 = 100;  // Faster retry during recovery
const RECOVERY_MAX_STALL_COUNT: u32 = 5;  // Trigger recovery sooner (10 seconds)

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
        let mut failed_epochs: std::collections::HashMap<u64, std::time::Instant> = std::collections::HashMap::new();
        let mut sync_progress_stall_count = 0u32;
        let mut recovery_mode = false;  // Track if we're in recovery mode
        let mut recovery_requests: std::collections::HashMap<u64, std::time::Instant> = std::collections::HashMap::new();
        
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
                        
                        let now = std::time::Instant::now();
                        let should_request = match last_tip_request {
                            Some((h, t)) if h == highest_seen && now.duration_since(t).as_millis() < TIP_REQUEST_BACKOFF_MS as u128 => false,
                            _ => true,
                        };
                        
                        if should_request && !recovery_mode {
                            net.request_latest_epoch().await;
                            sync_routine!("⛓️  Sync state is ahead (local: {}, network: {}). Requesting missing epochs.", local_epoch, highest_seen);
                            
                            let gap = highest_seen.saturating_sub(local_epoch);
                            if gap > MAX_EPOCH_BATCH_SIZE * 2 {
                                let batch_end = local_epoch.saturating_add(MAX_EPOCH_BATCH_SIZE);
                                request_missing_epochs(local_epoch, batch_end, &net, &semaphore, &db).await;
                                let recent_start = highest_seen.saturating_sub(20);
                                if recent_start > batch_end {
                                    request_missing_epochs(recent_start, highest_seen, &net, &semaphore, &db).await;
                                }
                            } else {
                                request_missing_epochs(local_epoch, highest_seen, &net, &semaphore, &db).await;
                            }
                            last_tip_request = Some((highest_seen, now));
                        }
                        
                        // Enhanced recovery logic with bypass mechanism
                        let prev_local = local_epoch;
                        if let Ok(Some(latest_anchor)) = db.get::<Anchor>("epoch", b"latest") {
                            local_epoch = latest_anchor.num;
                            if local_epoch > prev_local {
                                sync_routine!("📊 Local epoch updated to: {}", local_epoch);
                                sync_progress_stall_count = 0;
                                recovery_mode = false;
                                recovery_requests.clear();
                            } else {
                                sync_progress_stall_count += 1;
                                
                                // Enter recovery mode sooner and with more aggressive tactics
                                if sync_progress_stall_count > RECOVERY_MAX_STALL_COUNT {
                                    if !recovery_mode {
                                        println!("⚠️  Sync appears stuck at epoch {}. Entering recovery mode...", local_epoch);
                                        recovery_mode = true;
                                    }
                                    
                                    // Clean up old recovery requests
                                    recovery_requests.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_millis(RECOVERY_REQUEST_INTERVAL_MS * 5));
                                    
                                    // 1) Pull the direct child of our local tip first (next expected epoch)
                                    let child = local_epoch.saturating_add(1);
                                    if !recovery_requests.contains_key(&child) {
                                        request_epoch_bypass(&net, child).await;
                                        recovery_requests.insert(child, now);
                                        failed_epochs.insert(child, now);
                                    }
                                    // 2) Also request a compact headers backfill around that area to seed validation
                                    // Use small window to avoid flooding
                                    let window: u64 = 32;
                                    let start = child.saturating_sub(window);
                                    let count = (child.saturating_sub(start)).saturating_add(1) as u32;
                                    net.request_epoch_headers_range(start, count).await;

                                    // 3) Request immediate next epochs with bypass mechanism to push forward
                                    let recovery_end = (local_epoch + RECOVERY_EPOCH_BATCH_SIZE).min(highest_seen);
                                    for n in (local_epoch + 1)..=recovery_end {
                                        if !recovery_requests.contains_key(&n) {
                                            request_epoch_bypass(&net, n).await;
                                            recovery_requests.insert(n, now);
                                            failed_epochs.insert(n, now);
                                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                                        }
                                    }
                                    
                                    // Also request a sample of recent epochs to detect potential forks
                                    let sample_start = highest_seen.saturating_sub(10);
                                    for n in sample_start..=highest_seen {
                                        if !recovery_requests.contains_key(&n) {
                                            request_epoch_bypass(&net, n).await;
                                            recovery_requests.insert(n, now);
                                        }
                                    }
                                    
                                    sync_progress_stall_count = 0; // Reset to allow multiple recovery attempts
                                }
                            }
                        }
                        
                        // Enhanced retry logic for failed epochs
                        if recovery_mode {
                            let epochs_to_retry: Vec<u64> = failed_epochs
                                .iter()
                                .filter_map(|(epoch, last_attempt)| {
                                    if now.duration_since(*last_attempt) > std::time::Duration::from_millis(RECOVERY_REQUEST_INTERVAL_MS) {
                                        Some(*epoch)
                                    } else {
                                        None
                                    }
                                })
                                .take(10) // Limit concurrent retries
                                .collect();
                            
                            for epoch in epochs_to_retry {
                                request_epoch_bypass(&net, epoch).await;
                                failed_epochs.insert(epoch, now);
                                recovery_requests.insert(epoch, now);
                            }
                        } else {
                            // Normal retry logic for non-recovery mode
                            let epochs_to_retry: Vec<u64> = failed_epochs
                                .iter()
                                .filter_map(|(epoch, last_attempt)| {
                                    if now.duration_since(*last_attempt) > std::time::Duration::from_secs(FAILED_EPOCH_RETRY_SECS) {
                                        Some(*epoch)
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            
                            for epoch in epochs_to_retry {
                                net.request_epoch(epoch).await;
                                failed_epochs.remove(&epoch);
                            }
                        }
                    } else {
                        sync_progress_stall_count = 0;
                        recovery_mode = false;
                        recovery_requests.clear();
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
                        } else if highest_seen < local_epoch {
                            // Network is behind us - this can happen after rollback if we have newer epochs
                            // Force request for latest to see if network has progressed
                            sync_routine!("🔄 Network appears behind (local: {}, network: {}). Requesting latest...", local_epoch, highest_seen);
                            net.request_latest_epoch().await;
                            
                            // Also sample some recent epochs to detect potential conflicts
                            let sample_start = local_epoch.saturating_sub(10);
                            for n in sample_start..local_epoch {
                                net.request_epoch(n).await;
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
                                        // If we could reconstruct a full set, persist it for future fast access
                                        if ids.len() == anchor.coin_count as usize && anchor.coin_count > 0 {
                                            let mut leaves: Vec<[u8;32]> = ids.iter().map(crate::coin::Coin::id_to_leaf_hash).collect();
                                            leaves.sort();
                                            let root = crate::epoch::MerkleTree::compute_root_from_sorted_leaves(&leaves);
                                            if root == anchor.merkle_root {
                                                if let Some(sel_cf) = db.db.cf_handle("epoch_selected") {
                                                    let mut batch = rocksdb::WriteBatch::default();
                                                    for coin_id in &ids {
                                                        let mut key = Vec::with_capacity(8 + 32);
                                                        key.extend_from_slice(&n.to_le_bytes());
                                                        key.extend_from_slice(coin_id);
                                                        batch.put_cf(sel_cf, &key, &[]);
                                                    }
                                                    let _ = db.db.write(batch);
                                                }
                                            } else {
                                                // If reconstruction fails, ask peers explicitly
                                                net.request_epoch_selected(n).await;
                                                net.request_epoch_leaves(n).await;
                                            }
                                        } else if anchor.coin_count > 0 {
                                            // Partial or empty reconstruction: ask peers
                                            net.request_epoch_selected(n).await;
                                            net.request_epoch_leaves(n).await;
                                        }
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
                                    if let Some(sp) = db.decode_spend_bytes_tolerant(&v) {
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
                            // Only fast-forward to anchor if it's strictly the next contiguous epoch and parent is present;
                            // otherwise request the missing range to enforce sequential adoption.
                            if anchor.num == local_epoch + 1 {
                                // Verify parent exists and links correctly before trusting this as progress
                                let mut ok = false;
                                if let Ok(Some(prev)) = db.get::<Anchor>("epoch", &local_epoch.to_le_bytes()) {
                                    let mut h = blake3::Hasher::new();
                                    h.update(&anchor.merkle_root); h.update(&prev.hash);
                                    ok = *h.finalize().as_bytes() == anchor.hash;
                                }
                                if ok { local_epoch = anchor.num; }
                                else { request_missing_epochs(local_epoch, anchor.num, &net, &semaphore, &db).await; }
                            } else if anchor.num > local_epoch + 1 {
                                request_missing_epochs(local_epoch, anchor.num, &net, &semaphore, &db).await;
                            }
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
    // Increase capacity to handle more concurrent header responses
    let (seg_tx, mut seg_rx) = mpsc::channel::<HeaderSegment>(512);
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

    // Segment consumer: validate, fork-choice, store, update cursor, keep window full
    let db_headers = db.clone();
    let range_tx_consumer = range_tx.clone();
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
                    // If we have no local epochs yet, allow genesis header to be accepted to seed tip.
                    if current_best.is_none() {
                        if let Some(first) = seg.headers.first() {
                            if first.num == 0 {
                                let _ = db_headers.put("epoch", &0u64.to_le_bytes(), first);
                                let _ = db_headers.put("anchor", &first.hash, first);
                                let _ = db_headers.put("epoch", b"latest", first);
                            }
                        }
                    }
                    if let Some(last) = seg.headers.last() {
                        if last.is_better_chain(&current_best) {
                            for a in &seg.headers {
                                // Store headers by hash only; do not write canonical epoch-by-height in skeleton sync
                                if db_headers.put("anchor", &a.hash, a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); }
                                crate::metrics::HEADERS_ANCHORS_STORED.inc();
                            }
                            if let Some(tip) = seg.headers.last() {
                                // Do NOT advance canonical latest here; headers are skeleton only.
                                // Track progress via headers cursors instead.
                                let (mut highest_req, mut highest_stored) = db_headers.get_headers_cursor().unwrap_or((0,0));
                                if tip.num > highest_stored { highest_stored = tip.num; let _ = db_headers.put_headers_cursor(highest_req, highest_stored); }
                                // Keep the headers window full by enqueueing additional ranges beyond highest_requested
                                // Target window parameters should mirror initial seeding
                                let desired_ranges_in_flight: u64 = 24;
                                let range_size: u64 = 2048;
                                let desired_gap = desired_ranges_in_flight.saturating_mul(range_size);
                                let mut outstanding = highest_req.saturating_sub(highest_stored);
                                while outstanding < desired_gap {
                                    let next_start = highest_req.saturating_add(1);
                                    // Send and optimistically advance highest_requested cursor
                                    let _ = range_tx_consumer.send(RangeTask{ start: next_start, count: range_size as u32 }).await;
                                    highest_req = highest_req.saturating_add(range_size);
                                    let _ = db_headers.put_headers_cursor(highest_req, highest_stored);
                                    outstanding = highest_req.saturating_sub(highest_stored);
                                }

                                // Fast-path: if this segment continues our canonical tip contiguously,
                                // adopt headers into canonical epoch heights and advance latest.
                                if let Ok(Some(mut latest)) = db_headers.get::<Anchor>("epoch", b"latest") {
                                    // Find the first header in this segment that is the immediate successor to latest
                                    if let Some(start_idx) = seg.headers.iter().position(|h| h.num == latest.num.saturating_add(1)) {
                                        for a in &seg.headers[start_idx..] {
                                            // Validate parent linkage (hash) and cumulative work step
                                            let mut h = blake3::Hasher::new();
                                            h.update(&a.merkle_root); h.update(&latest.hash);
                                            let linked = *h.finalize().as_bytes() == a.hash;
                                            if !linked { break; }

                                            let expected_work = Anchor::expected_work_for_difficulty(a.difficulty);
                                            if a.cumulative_work != latest.cumulative_work.saturating_add(expected_work) { break; }

                                            // Validate retarget parameters when required
                                            if a.num % RETARGET_INTERVAL == 0 {
                                                // Build window of last RETARGET_INTERVAL anchors ending at parent
                                                let start = a.num.saturating_sub(RETARGET_INTERVAL);
                                                let mut window: Vec<Anchor> = Vec::with_capacity(RETARGET_INTERVAL as usize);
                                                let mut missing = false;
                                                for n in start..a.num {
                                                    match db_headers.get::<Anchor>("epoch", &n.to_le_bytes()) {
                                                        Ok(Some(x)) => window.push(x),
                                                        _ => { missing = true; break; }
                                                    }
                                                }
                                                if missing { break; }
                                                let got = Params { difficulty: a.difficulty as u32, mem_kib: a.mem_kib };
                                                if validate_header_params(Some(&latest), a.num, &window, got).is_err() { break; }
                                            } else {
                                                // Between retargets, enforce params inheritance
                                                if a.difficulty as u32 != latest.difficulty as u32 || a.mem_kib != latest.mem_kib { break; }
                                            }

                                            // Commit to canonical height and advance latest
                                            if db_headers.put("epoch", &a.num.to_le_bytes(), a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); break; }
                                            if db_headers.put("anchor", &a.hash, a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); break; }
                                            if db_headers.put("epoch", b"latest", a).is_err() { crate::metrics::DB_WRITE_FAILS.inc(); break; }
                                            latest = a.clone();

                                            // Request leaves/selected for proofs/indexes (dedup handled in network layer)
                                            // Best-effort; ignore errors
                                            let _ = net.request_epoch_leaves(a.num).await;
                                            let _ = net.request_epoch_selected(a.num).await;
                                        }
                                    }
                                }
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
    // Request a much wider window and more ranges in flight to accelerate initial catch-up
    let mut s = start;
    let ranges_in_flight: u32 = 24; // previously 8
    let range_size: u32 = 2048;     // previously 512
    for _ in 0..ranges_in_flight {
        let _ = range_tx.send(RangeTask{ start: s, count: range_size }).await;
        s = s.saturating_add(range_size as u64);
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

    let count = target_epoch.saturating_sub(start_epoch) + 1;
    sync_routine!("📥 Requesting {} epochs: {} to {}", count, start_epoch, target_epoch);
    
    // Limit concurrent requests to avoid overwhelming the system
    let mut request_tasks = Vec::new();
    let batch_size = MAX_CONCURRENT_EPOCH_REQUESTS.min(count as usize);
    
    for missing in start_epoch..=target_epoch {
        let net_clone = net.clone();
        let sem_clone = semaphore.clone();
        let task = tokio::spawn(async move {
            if let Ok(_permit) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                sem_clone.acquire()
            ).await {
                net_clone.request_epoch(missing).await;
            }
        });
        request_tasks.push(task);
        
        // Process in batches to avoid too many concurrent tasks
        if request_tasks.len() >= batch_size || missing == target_epoch {
            for task in request_tasks.drain(..) {
                let _ = task.await;
            }
            // Small delay between batches to avoid network congestion
            if missing < target_epoch {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

// New bypass function that circumvents deduplication
async fn request_epoch_bypass(net: &NetHandle, epoch: u64) {
    // Create a direct network request that bypasses the normal deduplication
    // This is used only during recovery mode
    net.request_epoch_direct(epoch).await;
}
