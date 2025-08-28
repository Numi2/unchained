use anyhow::Result;
use bytes::Bytes;
use hyper::{Body, Request as HRequest, Response as HResponse, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::net::TcpListener as StdTcpListener;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Lightweight in-process metrics that emit log events ---

static LOG_BUS: Lazy<LogBus> = Lazy::new(LogBus::new);

const LOG_BUFFER_CAPACITY: usize = 200;
const INITIAL_SNAPSHOT_LINES: usize = 100;
const FLUSH_INTERVAL_SECS: u64 = 5;

struct LogBus {
    buffer: Mutex<VecDeque<String>>,
    tx: tokio::sync::broadcast::Sender<String>,
}

impl LogBus {
    fn new() -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel::<String>(2048);
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(LOG_BUFFER_CAPACITY)),
            tx,
        }
    }

    fn push(&self, line: String) {
        if let Ok(mut buf) = self.buffer.lock() {
            if buf.len() == LOG_BUFFER_CAPACITY { buf.pop_front(); }
            buf.push_back(line.clone());
        }
        let _ = self.tx.send(line);
    }

    fn snapshot(&self) -> Vec<String> {
        self.buffer.lock().map(|b| b.iter().cloned().collect()).unwrap_or_default()
    }
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn log_line(kind: &str, name: &str, msg: String) {
    LOG_BUS.push(format!("{} [{}] {}: {}", now_millis(), kind, name, msg));
}

#[derive(Clone, Copy, Default)]
struct HistAgg {
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
}

struct MetricsAggregator {
    hist: Mutex<HashMap<&'static str, HistAgg>>, // per-interval histogram stats
    counters_last: Mutex<HashMap<&'static str, u64>>, // last flushed absolute counter values
}

impl MetricsAggregator {
    fn new() -> Self {
        Self { hist: Mutex::new(HashMap::new()), counters_last: Mutex::new(HashMap::new()) }
    }

    fn record_hist(&self, name: &'static str, value: f64) {
        if let Ok(mut map) = self.hist.lock() {
            let entry = map.entry(name).or_insert_with(|| HistAgg { count: 0, sum: 0.0, min: f64::INFINITY, max: f64::NEG_INFINITY });
            entry.count = entry.count.saturating_add(1);
            entry.sum += value;
            if value < entry.min { entry.min = value; }
            if value > entry.max { entry.max = value; }
        }
    }

    fn build_snapshot_and_reset(&self) -> String {
        use std::sync::atomic::Ordering;

        // Gauges (absolute)
        let gauges: [(&'static str, i64); 7] = [
            ("unchained_peer_count", PEERS.value.load(Ordering::Relaxed)),
            ("unchained_epoch_height", EPOCH_HEIGHT.value.load(Ordering::Relaxed)),
            ("unchained_candidate_coins", CANDIDATE_COINS.value.load(Ordering::Relaxed)),
            ("unchained_selected_coins", SELECTED_COINS.value.load(Ordering::Relaxed)),
            ("unchained_orphan_buffer_len", ORPHAN_BUFFER_LEN.value.load(Ordering::Relaxed)),
            ("unchained_selection_threshold_u64", SELECTION_THRESHOLD_U64.value.load(Ordering::Relaxed)),
            ("unchained_bridge_pending_ops", BRIDGE_PENDING_OPS.value.load(Ordering::Relaxed)),
        ];

        // Counters (delta since last flush)
        let mut counters_last_guard = self.counters_last.lock().ok();
        let mut counters_delta: Vec<(&'static str, u64)> = Vec::new();
        macro_rules! counter_delta {
            ($name:expr, $static_counter:ident) => {{
                let current = $static_counter.value.load(Ordering::Relaxed);
                let last = counters_last_guard.as_ref().and_then(|m| m.get($name).copied()).unwrap_or(0);
                let delta = current.saturating_sub(last);
                if let Some(ref mut map) = counters_last_guard { map.insert($name, current); }
                if delta > 0 { counters_delta.push(($name, delta)); }
            }};
        }
        counter_delta!("unchained_coin_proofs_served_total", PROOFS_SERVED);
        counter_delta!("unchained_validation_failures_anchor_total", VALIDATION_FAIL_ANCHOR);
        counter_delta!("unchained_validation_failures_coin_total", VALIDATION_FAIL_COIN);
        counter_delta!("unchained_validation_failures_transfer_total", VALIDATION_FAIL_TRANSFER);
        counter_delta!("unchained_v3_sends_total", V3_SENDS);
        counter_delta!("unchained_legacy_upgrades_total", LEGACY_UPGRADES);
        counter_delta!("unchained_db_write_failures_total", DB_WRITE_FAILS);
        counter_delta!("unchained_pruned_candidates_total", PRUNED_CANDIDATES);
        counter_delta!("unchained_mining_attempts_total", MINING_ATTEMPTS);
        counter_delta!("unchained_mining_solutions_total", MINING_FOUND);
        counter_delta!("unchained_alt_fork_events_total", ALT_FORK_EVENTS);
        counter_delta!("unchained_compact_epochs_sent_total", COMPACT_EPOCHS_SENT);
        counter_delta!("unchained_compact_epochs_received_total", COMPACT_EPOCHS_RECV);
        counter_delta!("unchained_compact_tx_requests_total", COMPACT_TX_REQ);
        counter_delta!("unchained_compact_tx_responses_total", COMPACT_TX_RESP);
        counter_delta!("unchained_headers_batches_received_total", HEADERS_BATCH_RECV);
        counter_delta!("unchained_headers_anchors_stored_total", HEADERS_ANCHORS_STORED);
        counter_delta!("unchained_headers_invalid_total", HEADERS_INVALID);
        counter_delta!("unchained_compact_fallbacks_total", COMPACT_FALLBACKS);
        // Bridge counters
        counter_delta!("unchained_bridge_out_requests_total", BRIDGE_OUT_REQUESTS);
        counter_delta!("unchained_bridge_out_locked_coins_total", BRIDGE_OUT_LOCKED_COINS);
        counter_delta!("unchained_bridge_in_unlocked_coins_total", BRIDGE_IN_UNLOCKED_COINS);
        counter_delta!("unchained_bridge_errors_total", BRIDGE_ERRORS);
        counter_delta!("unchained_bridge_verify_ok_total", BRIDGE_VERIFY_OK);
        counter_delta!("unchained_bridge_verify_fail_total", BRIDGE_VERIFY_FAIL);
        counter_delta!("unchained_bridge_replay_attempts_total", BRIDGE_REPLAY_ATTEMPTS);
        counter_delta!("unchained_bridge_pending_expired_total", BRIDGE_PENDING_EXPIRED);
        counter_delta!("unchained_bridge_pending_confirmed_total", BRIDGE_PENDING_CONFIRMED);
        counter_delta!("unchained_bridge_pending_failed_total", BRIDGE_PENDING_FAILED);

        // Histograms (stats for the last interval)
        let hist = self.hist.lock().ok();
        let taken_hist = if let Some(mut guard) = hist { std::mem::take(&mut *guard) } else { HashMap::new() };

        // Build compact JSON string
        let mut out = String::new();
        out.push_str("{");
        out.push_str("\"ts\":");
        out.push_str(&now_millis().to_string());

        // Gauges
        out.push_str(",\"gauges\":{");
        for (idx, (name, val)) in gauges.iter().enumerate() {
            if idx > 0 { out.push(','); }
            out.push_str("\""); out.push_str(name); out.push_str("\":"); out.push_str(&val.to_string());
        }
        out.push('}');

        // Counters (only non-zero deltas)
        out.push_str(",\"counters_delta\":{");
        for (idx, (name, delta)) in counters_delta.iter().enumerate() {
            if idx > 0 { out.push(','); }
            out.push_str("\""); out.push_str(name); out.push_str("\":"); out.push_str(&delta.to_string());
        }
        out.push('}');

        // Histograms
        out.push_str(",\"histograms\":{");
        let mut wrote_any = false;
        for (name, agg) in taken_hist.iter() {
            if agg.count == 0 { continue; }
            if wrote_any { out.push(','); } else { wrote_any = true; }
            let avg = if agg.count > 0 { agg.sum / (agg.count as f64) } else { 0.0 };
            out.push_str("\""); out.push_str(name); out.push_str("\":{");
            out.push_str("\"count\":"); out.push_str(&agg.count.to_string()); out.push(',');
            out.push_str("\"avg\":"); out.push_str(&format!("{:.3}", avg)); out.push(',');
            out.push_str("\"min\":"); out.push_str(&format!("{:.3}", agg.min)); out.push(',');
            out.push_str("\"max\":"); out.push_str(&format!("{:.3}", agg.max));
            out.push('}');
        }
        out.push('}');

        out.push('}');
        out
    }
}

static AGGREGATOR: Lazy<MetricsAggregator> = Lazy::new(MetricsAggregator::new);

pub struct IntGauge {
    _name: &'static str,
    _description: &'static str,
    value: std::sync::atomic::AtomicI64,
}

impl IntGauge {
    pub fn new(name: &'static str, description: &'static str) -> std::result::Result<Self, ()> {
        Ok(Self { _name: name, _description: description, value: std::sync::atomic::AtomicI64::new(0) })
    }
    pub fn set(&self, val: i64) {
        self.value.store(val, std::sync::atomic::Ordering::Relaxed);
    }
}

pub struct IntCounter {
    _name: &'static str,
    _description: &'static str,
    value: std::sync::atomic::AtomicU64,
}

impl IntCounter {
    pub fn new(name: &'static str, description: &'static str) -> std::result::Result<Self, ()> {
        Ok(Self { _name: name, _description: description, value: std::sync::atomic::AtomicU64::new(0) })
    }
    pub fn inc(&self) {
        let _v = self.value.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    }
    pub fn inc_by(&self, by: u64) {
        let _v = self.value.fetch_add(by, std::sync::atomic::Ordering::Relaxed) + by;
    }
}

pub struct Histogram {
    name: &'static str,
    _description: &'static str,
}

impl Histogram {
    pub fn new(name: &'static str, description: &'static str) -> Self {
        Self { name, _description: description }
    }
    pub fn observe(&self, value: f64) {
        AGGREGATOR.record_hist(self.name, value);
    }
}

pub static PEERS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_peer_count", "Connected libp2p peers").unwrap());
pub static EPOCH_HEIGHT: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_epoch_height", "Current epoch height").unwrap());
pub static CANDIDATE_COINS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_candidate_coins", "Candidate coins observed for current epoch").unwrap());
pub static SELECTED_COINS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_selected_coins", "Selected coins in last finalized epoch").unwrap());
pub static PROOFS_SERVED: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_coin_proofs_served_total", "Number of coin proofs served").unwrap());
pub static PROOF_LATENCY_MS: Lazy<Histogram> = Lazy::new(|| Histogram::new("unchained_coin_proof_latency_ms", "Proof serving latency (ms)"));
pub static ORPHAN_BUFFER_LEN: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_orphan_buffer_len", "Number of buffered orphan anchors").unwrap());
pub static VALIDATION_FAIL_ANCHOR: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_validation_failures_anchor_total", "Count of invalid anchors received").unwrap());
pub static VALIDATION_FAIL_COIN: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_validation_failures_coin_total", "Count of invalid coin candidates received").unwrap());
pub static VALIDATION_FAIL_TRANSFER: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_validation_failures_transfer_total", "Count of invalid transfers received").unwrap());
pub static V3_SENDS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_v3_sends_total", "Count of V3 hashlock sends").unwrap());
pub static LEGACY_UPGRADES: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_legacy_upgrades_total", "Count of legacy coins auto-upgraded to V3").unwrap());
pub static DB_WRITE_FAILS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_db_write_failures_total", "Database write failures").unwrap());
pub static PRUNED_CANDIDATES: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_pruned_candidates_total", "Total candidate entries pruned").unwrap());
pub static SELECTION_THRESHOLD_U64: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_selection_threshold_u64", "Threshold (first 8 bytes of pow_hash) for last selected coin").unwrap());
pub static MINING_ATTEMPTS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_mining_attempts_total", "Total mining attempts (nonces tried)").unwrap());
pub static MINING_FOUND: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_mining_solutions_total", "Total found PoW solutions").unwrap());
pub static MINING_HASH_TIME_MS: Lazy<Histogram> = Lazy::new(|| Histogram::new("unchained_mining_hash_time_ms", "Argon2 PoW hashing time per attempt (ms)"));
pub static ALT_FORK_EVENTS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_alt_fork_events_total", "Count of alternate fork anchor events (hash mismatch) observed").unwrap());
pub static COMPACT_EPOCHS_SENT: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_compact_epochs_sent_total", "Compact epochs gossiped").unwrap());
pub static COMPACT_EPOCHS_RECV: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_compact_epochs_received_total", "Compact epochs received").unwrap());
pub static COMPACT_TX_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_compact_tx_requests_total", "GetTxn requests sent").unwrap());
pub static COMPACT_TX_RESP: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_compact_tx_responses_total", "Txn responses received").unwrap());
pub static HEADERS_BATCH_RECV: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_headers_batches_received_total", "Header batches received").unwrap());
pub static HEADERS_ANCHORS_STORED: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_headers_anchors_stored_total", "Anchors stored from header batches").unwrap());
pub static HEADERS_INVALID: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_headers_invalid_total", "Invalid anchors in header batches").unwrap());
pub static COMPACT_FALLBACKS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_compact_fallbacks_total", "Fallbacks to full bodies due to high missing %").unwrap());

// --- Bridge metrics ---
pub static BRIDGE_OUT_REQUESTS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_out_requests_total", "Bridge-out submissions received").unwrap());
pub static BRIDGE_OUT_LOCKED_COINS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_out_locked_coins_total", "Coins locked for bridge-out").unwrap());
pub static BRIDGE_IN_UNLOCKED_COINS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_in_unlocked_coins_total", "Coins unlocked via Sui burn proof").unwrap());
pub static BRIDGE_ERRORS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_errors_total", "Bridge errors").unwrap());
pub static BRIDGE_PENDING_OPS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_bridge_pending_ops", "Current pending bridge ops").unwrap());
pub static BRIDGE_VERIFY_OK: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_verify_ok_total", "Successful Sui burn proof verifications").unwrap());
pub static BRIDGE_VERIFY_FAIL: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_verify_fail_total", "Failed Sui burn proof verifications").unwrap());
pub static BRIDGE_REPLAY_ATTEMPTS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_replay_attempts_total", "Rejected replayed Sui digests").unwrap());
pub static BRIDGE_PENDING_EXPIRED: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_pending_expired_total", "Pending bridge ops expired by sweeper").unwrap());
pub static BRIDGE_PENDING_CONFIRMED: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_pending_confirmed_total", "Pending bridge ops marked confirmed").unwrap());
pub static BRIDGE_PENDING_FAILED: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_bridge_pending_failed_total", "Pending bridge ops marked failed").unwrap());

pub fn serve(cfg: crate::config::Metrics) -> Result<()> {
    // Initialize some defaults
    PEERS.set(0);

    // Start an HTTP server offering a single SSE endpoint at /logs.
    let bind_addr = cfg.bind.clone();
    tokio::spawn(async move {
        let mut addr = bind_addr.clone();
        let listener = loop {
            match StdTcpListener::bind(&addr) {
                Ok(l) => break l,
                Err(e) => {
                    let already = e.kind() == std::io::ErrorKind::AddrInUse || e.to_string().contains("in use");
                    if already {
                        if let Some((host, port_str)) = addr.rsplit_once(':') {
                            if let Ok(port) = port_str.parse::<u16>() {
                                let next = port.saturating_add(1);
                                addr = format!("{}:{}", host, next);
                                eprintln!("🔥 Logs API port in use, trying {}", addr);
                                continue;
                            }
                        }
                    }
                    eprintln!("🔥 Could not bind logs API on {addr}: {e}");
                    return;
                }
            }
        };
        listener.set_nonblocking(true).ok();
        // Periodic, compact metrics snapshot
        tokio::spawn(async move {
            use tokio::time::{sleep, Duration};
            loop {
                sleep(Duration::from_secs(FLUSH_INTERVAL_SECS)).await;
                let snapshot = AGGREGATOR.build_snapshot_and_reset();
                log_line("metrics", "snapshot", snapshot);
            }
        });

        let service = make_service_fn(|_conn| async move {
            Ok::<_, std::convert::Infallible>(service_fn(|req: HRequest<Body>| async move {
                if req.method() == hyper::Method::GET && req.uri().path() == "/logs" {
                    // Prepare SSE body
                    let (mut tx, body) = Body::channel();
                    let mut rx = LOG_BUS.tx.subscribe();
                    // Send current snapshot first
                    let mut snapshot = LOG_BUS.snapshot();
                    let start = snapshot.len().saturating_sub(INITIAL_SNAPSHOT_LINES);
                    let snapshot = snapshot.split_off(start);
                    // Send in a separate task to keep the response return non-blocking
                    tokio::spawn(async move {
                        // Helper to send one event line
                        async fn send_line(tx: &mut hyper::body::Sender, line: &str) -> Result<(), ()> {
                            let data = format!("data: {}\n\n", line);
                            tx.send_data(Bytes::from(data)).await.map_err(|_| ())
                        }
                        for line in snapshot {
                            if send_line(&mut tx, &line).await.is_err() { return; }
                        }
                        loop {
                            match rx.recv().await {
                                Ok(line) => {
                                    if send_line(&mut tx, &line).await.is_err() { break; }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            }
                        }
                    });

                    let mut resp = HResponse::new(body);
                    let headers = resp.headers_mut();
                    headers.insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/event-stream"));
                    headers.insert(hyper::header::CACHE_CONTROL, hyper::header::HeaderValue::from_static("no-cache"));
                    headers.insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("keep-alive"));
                    headers.insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, hyper::header::HeaderValue::from_static("*"));
                    Ok::<_, std::convert::Infallible>(resp)
                } else {
                    Ok::<_, std::convert::Infallible>(HResponse::builder().status(StatusCode::NOT_FOUND).body(Body::from("not found")).unwrap())
                }
            }))
        });

        match hyper::Server::from_tcp(listener).unwrap().serve(service).await {
            Ok(()) => {}
            Err(e) => eprintln!("🔥 Logs API error: {}", e),
        }
    });

    Ok(())
}