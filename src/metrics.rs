use anyhow::Result;
use bytes::Bytes;
use hyper::{Body, Request as HRequest, Response as HResponse, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::net::TcpListener as StdTcpListener;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// --- Lightweight in-process metrics that emit log events ---

static LOG_BUS: Lazy<LogBus> = Lazy::new(LogBus::new);

const LOG_BUFFER_CAPACITY: usize = 1000;

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
        let mut buf = self.buffer.lock().unwrap();
        if buf.len() == LOG_BUFFER_CAPACITY { buf.pop_front(); }
        buf.push_back(line.clone());
        let _ = self.tx.send(line);
    }

    fn snapshot(&self) -> Vec<String> {
        self.buffer.lock().unwrap().iter().cloned().collect()
    }
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn log_line(kind: &str, name: &str, msg: String) {
    LOG_BUS.push(format!("{} [{}] {}: {}", now_millis(), kind, name, msg));
}

pub struct IntGauge {
    name: &'static str,
    description: &'static str,
    value: std::sync::atomic::AtomicI64,
}

impl IntGauge {
    pub fn new(name: &'static str, description: &'static str) -> std::result::Result<Self, ()> {
        Ok(Self { name, description, value: std::sync::atomic::AtomicI64::new(0) })
    }
    pub fn set(&self, val: i64) {
        self.value.store(val, std::sync::atomic::Ordering::Relaxed);
        log_line("gauge", self.name, format!("set {} ({})", val, self.description));
    }
}

pub struct IntCounter {
    name: &'static str,
    description: &'static str,
    value: std::sync::atomic::AtomicU64,
}

impl IntCounter {
    pub fn new(name: &'static str, description: &'static str) -> std::result::Result<Self, ()> {
        Ok(Self { name, description, value: std::sync::atomic::AtomicU64::new(0) })
    }
    pub fn inc(&self) {
        let v = self.value.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        log_line("counter", self.name, format!("inc -> {} ({})", v, self.description));
    }
    pub fn inc_by(&self, by: u64) {
        let v = self.value.fetch_add(by, std::sync::atomic::Ordering::Relaxed) + by;
        log_line("counter", self.name, format!("inc_by {} -> {} ({})", by, v, self.description));
    }
}

pub struct Histogram {
    name: &'static str,
    description: &'static str,
}

impl Histogram {
    pub fn new(name: &'static str, description: &'static str) -> Self {
        Self { name, description }
    }
    pub fn observe(&self, value: f64) {
        log_line("histogram", self.name, format!("observe {:.3} ({})", value, self.description));
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
pub static DB_WRITE_FAILS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_db_write_failures_total", "Database write failures").unwrap());
pub static PRUNED_CANDIDATES: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_pruned_candidates_total", "Total candidate entries pruned").unwrap());
pub static SELECTION_THRESHOLD_U64: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_selection_threshold_u64", "Threshold (first 8 bytes of pow_hash) for last selected coin").unwrap());
pub static MINING_ATTEMPTS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_mining_attempts_total", "Total mining attempts (nonces tried)").unwrap());
pub static MINING_FOUND: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_mining_solutions_total", "Total found PoW solutions").unwrap());
pub static MINING_HASH_TIME_MS: Lazy<Histogram> = Lazy::new(|| Histogram::new("unchained_mining_hash_time_ms", "Argon2 PoW hashing time per attempt (ms)"));

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

        let service = make_service_fn(|_conn| async move {
            Ok::<_, std::convert::Infallible>(service_fn(|req: HRequest<Body>| async move {
                if req.method() == hyper::Method::GET && req.uri().path() == "/logs" {
                    // Prepare SSE body
                    let (mut tx, body) = Body::channel();
                    let mut rx = LOG_BUS.tx.subscribe();
                    // Send current snapshot first
                    let snapshot = LOG_BUS.snapshot();
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

    eprintln!("🖥  Real-time logs available via SSE at http://{}/logs", cfg.bind);
    Ok(())
}