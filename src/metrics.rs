use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{LazyLock as Lazy, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
            if buf.len() == LOG_BUFFER_CAPACITY {
                buf.pop_front();
            }
            buf.push_back(line.clone());
        }
        let _ = self.tx.send(line);
    }

    fn snapshot(&self) -> Vec<String> {
        self.buffer
            .lock()
            .map(|b| b.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
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
        Self {
            hist: Mutex::new(HashMap::new()),
            counters_last: Mutex::new(HashMap::new()),
        }
    }

    fn record_hist(&self, name: &'static str, value: f64) {
        if let Ok(mut map) = self.hist.lock() {
            let entry = map.entry(name).or_insert_with(|| HistAgg {
                count: 0,
                sum: 0.0,
                min: f64::INFINITY,
                max: f64::NEG_INFINITY,
            });
            entry.count = entry.count.saturating_add(1);
            entry.sum += value;
            if value < entry.min {
                entry.min = value;
            }
            if value > entry.max {
                entry.max = value;
            }
        }
    }

    fn build_snapshot_and_reset(&self) -> String {
        use std::sync::atomic::Ordering;

        // Gauges (absolute)
        let gauges: [(&'static str, i64); 7] = [
            ("unchained_peer_count", PEERS.value.load(Ordering::Relaxed)),
            (
                "unchained_epoch_height",
                EPOCH_HEIGHT.value.load(Ordering::Relaxed),
            ),
            (
                "unchained_candidate_settlement_units",
                CANDIDATE_SETTLEMENT_UNITS.value.load(Ordering::Relaxed),
            ),
            (
                "unchained_committed_settlement_units",
                COMMITTED_SETTLEMENT_UNITS.value.load(Ordering::Relaxed),
            ),
            (
                "unchained_orphan_buffer_len",
                ORPHAN_BUFFER_LEN.value.load(Ordering::Relaxed),
            ),
            (
                "unchained_settlement_unit_admission_cutoff_u64",
                ADMISSION_CUTOFF_U64.value.load(Ordering::Relaxed),
            ),
            (
                "unchained_net_pending_cmds",
                NET_PENDING_COMMANDS.value.load(Ordering::Relaxed),
            ),
        ];

        // Counters (delta since last flush)
        let mut counters_last_guard = self.counters_last.lock().ok();
        let mut counters_delta: Vec<(&'static str, u64)> = Vec::new();
        macro_rules! counter_delta {
            ($name:expr, $static_counter:ident) => {{
                let current = $static_counter.value.load(Ordering::Relaxed);
                let last = counters_last_guard
                    .as_ref()
                    .and_then(|m| m.get($name).copied())
                    .unwrap_or(0);
                let delta = current.saturating_sub(last);
                if let Some(ref mut map) = counters_last_guard {
                    map.insert($name, current);
                }
                if delta > 0 {
                    counters_delta.push(($name, delta));
                }
            }};
        }
        counter_delta!(
            "unchained_settlement_unit_membership_proofs_served_total",
            MEMBERSHIP_PROOFS_SERVED
        );
        counter_delta!(
            "unchained_validation_failures_anchor_total",
            VALIDATION_FAIL_ANCHOR
        );
        counter_delta!(
            "unchained_validation_failures_settlement_unit_total",
            VALIDATION_FAIL_SETTLEMENT_UNIT
        );
        counter_delta!(
            "unchained_validation_failures_transfer_total",
            VALIDATION_FAIL_TRANSFER
        );
        counter_delta!("unchained_v3_sends_total", V3_SENDS);
        counter_delta!("unchained_db_write_failures_total", DB_WRITE_FAILS);
        counter_delta!(
            "unchained_pruned_settlement_unit_candidates_total",
            PRUNED_SETTLEMENT_UNIT_CANDIDATES
        );
        counter_delta!(
            "unchained_headers_batches_received_total",
            HEADERS_BATCH_RECV
        );
        counter_delta!(
            "unchained_headers_anchors_stored_total",
            HEADERS_ANCHORS_STORED
        );
        counter_delta!("unchained_headers_invalid_total", HEADERS_INVALID);
        // Network command counters
        counter_delta!("unchained_net_cmd_enqueued_total", NET_CMDS_ENQUEUED);
        counter_delta!("unchained_net_cmd_dropped_dup_total", NET_CMDS_DROPPED_DUP);
        counter_delta!("unchained_net_publish_fail_total", NET_PUBLISH_FAILS);
        counter_delta!("unchained_net_cmd_published_total", NET_CMDS_PUBLISHED_OK);

        // Histograms (stats for the last interval)
        let hist = self.hist.lock().ok();
        let taken_hist = if let Some(mut guard) = hist {
            std::mem::take(&mut *guard)
        } else {
            HashMap::new()
        };

        // Build compact JSON string
        let mut out = String::new();
        out.push_str("{");
        out.push_str("\"ts\":");
        out.push_str(&now_millis().to_string());

        // Gauges
        out.push_str(",\"gauges\":{");
        for (idx, (name, val)) in gauges.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str("\"");
            out.push_str(name);
            out.push_str("\":");
            out.push_str(&val.to_string());
        }
        out.push('}');

        // Counters (only non-zero deltas)
        out.push_str(",\"counters_delta\":{");
        for (idx, (name, delta)) in counters_delta.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str("\"");
            out.push_str(name);
            out.push_str("\":");
            out.push_str(&delta.to_string());
        }
        out.push('}');

        // Histograms
        out.push_str(",\"histograms\":{");
        let mut wrote_any = false;
        for (name, agg) in taken_hist.iter() {
            if agg.count == 0 {
                continue;
            }
            if wrote_any {
                out.push(',');
            } else {
                wrote_any = true;
            }
            let avg = if agg.count > 0 {
                agg.sum / (agg.count as f64)
            } else {
                0.0
            };
            out.push_str("\"");
            out.push_str(name);
            out.push_str("\":{");
            out.push_str("\"count\":");
            out.push_str(&agg.count.to_string());
            out.push(',');
            out.push_str("\"avg\":");
            out.push_str(&format!("{:.3}", avg));
            out.push(',');
            out.push_str("\"min\":");
            out.push_str(&format!("{:.3}", agg.min));
            out.push(',');
            out.push_str("\"max\":");
            out.push_str(&format!("{:.3}", agg.max));
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
        Ok(Self {
            _name: name,
            _description: description,
            value: std::sync::atomic::AtomicI64::new(0),
        })
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
        Ok(Self {
            _name: name,
            _description: description,
            value: std::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn inc(&self) {
        let _v = self
            .value
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
    }
    pub fn inc_by(&self, by: u64) {
        let _v = self
            .value
            .fetch_add(by, std::sync::atomic::Ordering::Relaxed)
            + by;
    }
}

pub struct Histogram {
    name: &'static str,
    _description: &'static str,
}

impl Histogram {
    pub fn new(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            _description: description,
        }
    }
    pub fn observe(&self, value: f64) {
        AGGREGATOR.record_hist(self.name, value);
    }
}

pub static PEERS: Lazy<IntGauge> =
    Lazy::new(|| IntGauge::new("unchained_peer_count", "Connected PQ transport peers").unwrap());
pub static EPOCH_HEIGHT: Lazy<IntGauge> =
    Lazy::new(|| IntGauge::new("unchained_epoch_height", "Current epoch height").unwrap());
pub static CANDIDATE_SETTLEMENT_UNITS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "unchained_candidate_settlement_units",
        "Pending bootstrap settlement units observed for current epoch",
    )
    .unwrap()
});
pub static COMMITTED_SETTLEMENT_UNITS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "unchained_committed_settlement_units",
        "Bootstrap settlement units committed in last finalized epoch",
    )
    .unwrap()
});
pub static MEMBERSHIP_PROOFS_SERVED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_settlement_unit_membership_proofs_served_total",
        "Number of checkpoint membership proofs served",
    )
    .unwrap()
});
pub static MEMBERSHIP_PROOF_LATENCY_MS: Lazy<Histogram> = Lazy::new(|| {
    Histogram::new(
        "unchained_settlement_unit_membership_proof_latency_ms",
        "Checkpoint membership proof serving latency (ms)",
    )
});
pub static ORPHAN_BUFFER_LEN: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "unchained_orphan_buffer_len",
        "Number of buffered orphan anchors",
    )
    .unwrap()
});
pub static VALIDATION_FAIL_ANCHOR: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_validation_failures_anchor_total",
        "Count of invalid anchors received",
    )
    .unwrap()
});
pub static VALIDATION_FAIL_SETTLEMENT_UNIT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_validation_failures_settlement_unit_total",
        "Count of invalid bootstrap settlement candidates received",
    )
    .unwrap()
});
pub static VALIDATION_FAIL_TRANSFER: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_validation_failures_transfer_total",
        "Count of invalid transfers received",
    )
    .unwrap()
});
pub static V3_SENDS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("unchained_v3_sends_total", "Count of V3 hashlock sends").unwrap()
});
pub static DB_WRITE_FAILS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_db_write_failures_total",
        "Database write failures",
    )
    .unwrap()
});
pub static PRUNED_SETTLEMENT_UNIT_CANDIDATES: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_pruned_settlement_unit_candidates_total",
        "Total candidate entries pruned",
    )
    .unwrap()
});
pub static ADMISSION_CUTOFF_U64: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "unchained_settlement_unit_admission_cutoff_u64",
        "Last checkpoint admission cutoff from the candidate digest order",
    )
    .unwrap()
});
pub static HEADERS_BATCH_RECV: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_headers_batches_received_total",
        "Header batches received",
    )
    .unwrap()
});
pub static HEADERS_ANCHORS_STORED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_headers_anchors_stored_total",
        "Anchors stored from header batches",
    )
    .unwrap()
});
pub static HEADERS_INVALID: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_headers_invalid_total",
        "Invalid anchors in header batches",
    )
    .unwrap()
});
// --- Network command metrics ---
pub static NET_PENDING_COMMANDS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "unchained_net_pending_cmds",
        "Pending network commands queued for publish",
    )
    .unwrap()
});
pub static NET_CMDS_ENQUEUED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_net_cmd_enqueued_total",
        "Network commands accepted/enqueued (post-dedup/backoff)",
    )
    .unwrap()
});
pub static NET_CMDS_DROPPED_DUP: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_net_cmd_dropped_dup_total",
        "Network commands dropped by dedup/backoff",
    )
    .unwrap()
});
pub static NET_PUBLISH_FAILS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_net_publish_fail_total",
        "Gossipsub publish failures for network commands",
    )
    .unwrap()
});
pub static NET_CMDS_PUBLISHED_OK: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "unchained_net_cmd_published_total",
        "Network commands published successfully",
    )
    .unwrap()
});

pub fn serve() -> Result<()> {
    // Initialize some defaults
    PEERS.set(0);

    // Observability is loopback-only so the shipped product has no non-PQ remote service surface.
    let bind_addr: SocketAddr = "127.0.0.1:9100"
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid fixed metrics socket address"))?;
    if !bind_addr.ip().is_loopback() {
        anyhow::bail!("fixed metrics socket address must use a loopback address");
    }
    let bind_addr = bind_addr.to_string();
    tokio::spawn(async move {
        let mut addr = bind_addr.clone();
        let listener = loop {
            match TcpListener::bind(&addr).await {
                Ok(l) => break l,
                Err(e) => {
                    let already = e.kind() == std::io::ErrorKind::AddrInUse
                        || e.to_string().contains("in use");
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
        // Periodic, compact metrics snapshot
        tokio::spawn(async move {
            use tokio::time::{sleep, Duration};
            loop {
                sleep(Duration::from_secs(FLUSH_INTERVAL_SECS)).await;
                let snapshot = AGGREGATOR.build_snapshot_and_reset();
                log_line("metrics", "snapshot", snapshot);
            }
        });

        loop {
            match listener.accept().await {
                Ok((socket, _peer)) => {
                    tokio::spawn(async move {
                        if let Err(err) = handle_logs_socket(socket).await {
                            eprintln!("🔥 Logs API connection error: {err}");
                        }
                    });
                }
                Err(err) => eprintln!("🔥 Logs API accept error: {err}"),
            }
        }
    });

    Ok(())
}

async fn handle_logs_socket(mut socket: TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), socket.read(&mut buf))
        .await
    {
        Ok(result) => result?,
        Err(_) => return Ok(()),
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or_default();
    if !first_line.starts_with("GET /logs ") {
        socket
            .write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found",
            )
            .await?;
        return Ok(());
    }

    socket
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
        )
        .await?;

    let mut snapshot = LOG_BUS.snapshot();
    let start = snapshot.len().saturating_sub(INITIAL_SNAPSHOT_LINES);
    let snapshot = snapshot.split_off(start);
    for line in snapshot {
        write_sse_line(&mut socket, &line).await?;
    }

    let mut rx = LOG_BUS.tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(line) => write_sse_line(&mut socket, &line).await?,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
    Ok(())
}

async fn write_sse_line(socket: &mut TcpStream, line: &str) -> std::io::Result<()> {
    socket.write_all(b"data: ").await?;
    socket
        .write_all(line.replace('\n', "\\n").as_bytes())
        .await?;
    socket.write_all(b"\n\n").await
}
