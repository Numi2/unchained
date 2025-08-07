use anyhow::Result;
use once_cell::sync::Lazy;
use prometheus::{Registry, IntGauge, IntCounter, Encoder, TextEncoder};
use std::thread;

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);
pub static PEERS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_peer_count", "Connected libp2p peers").unwrap());
pub static EPOCH_HEIGHT: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_epoch_height", "Current epoch height").unwrap());
pub static CANDIDATE_COINS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_candidate_coins", "Candidate coins observed for current epoch").unwrap());
pub static SELECTED_COINS: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_selected_coins", "Selected coins in last finalized epoch").unwrap());
pub static PROOFS_SERVED: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_coin_proofs_served_total", "Number of coin proofs served").unwrap());
pub static PROOF_LATENCY_MS: Lazy<prometheus::Histogram> = Lazy::new(|| prometheus::Histogram::with_opts(prometheus::HistogramOpts::new("unchained_coin_proof_latency_ms", "Proof serving latency (ms)").buckets(vec![10.0,25.0,50.0,100.0,250.0,500.0,1000.0,2000.0,5000.0])).unwrap());
pub static ORPHAN_BUFFER_LEN: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_orphan_buffer_len", "Number of buffered orphan anchors").unwrap());
pub static VALIDATION_FAIL_ANCHOR: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_validation_failures_anchor_total", "Count of invalid anchors received").unwrap());
pub static VALIDATION_FAIL_COIN: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_validation_failures_coin_total", "Count of invalid coin candidates received").unwrap());
pub static VALIDATION_FAIL_TRANSFER: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_validation_failures_transfer_total", "Count of invalid transfers received").unwrap());
pub static DB_WRITE_FAILS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_db_write_failures_total", "Database write failures").unwrap());
pub static PRUNED_CANDIDATES: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_pruned_candidates_total", "Total candidate entries pruned").unwrap());
pub static SELECTION_THRESHOLD_U64: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_selection_threshold_u64", "Threshold (first 8 bytes of pow_hash) for last selected coin").unwrap());

pub fn serve(cfg: crate::config::Metrics) -> Result<()> {
    REGISTRY.register(Box::new(PEERS.clone()))?;
    REGISTRY.register(Box::new(EPOCH_HEIGHT.clone()))?;
    REGISTRY.register(Box::new(CANDIDATE_COINS.clone()))?;
    REGISTRY.register(Box::new(SELECTED_COINS.clone()))?;
    REGISTRY.register(Box::new(PROOFS_SERVED.clone()))?;
    REGISTRY.register(Box::new(PROOF_LATENCY_MS.clone()))?;
    REGISTRY.register(Box::new(ORPHAN_BUFFER_LEN.clone()))?;
    REGISTRY.register(Box::new(VALIDATION_FAIL_ANCHOR.clone()))?;
    REGISTRY.register(Box::new(VALIDATION_FAIL_COIN.clone()))?;
    REGISTRY.register(Box::new(VALIDATION_FAIL_TRANSFER.clone()))?;
    REGISTRY.register(Box::new(DB_WRITE_FAILS.clone()))?;
    REGISTRY.register(Box::new(PRUNED_CANDIDATES.clone()))?;
    REGISTRY.register(Box::new(SELECTION_THRESHOLD_U64.clone()))?;
    PEERS.set(0);

    // Start metrics server, retrying on port conflicts by incrementing port number.
    let bind_addr = cfg.bind.clone();
    thread::spawn(move || {
        let mut addr = bind_addr.clone();
        let server = loop {
            match tiny_http::Server::http(&addr) {
                Ok(s) => break s,
                Err(e) => {
                    if e.to_string().contains("Address already in use") {
                        // Try next port
                        if let Some((host, port_str)) = addr.rsplit_once(':') {
                            if let Ok(port) = port_str.parse::<u16>() {
                                let next_port = port.saturating_add(1);
                                addr = format!("{}:{}", host, next_port);
                                eprintln!("🔥 Metrics port in use, trying {}", addr);
                                continue;
                            }
                        }
                    }
                    eprintln!("🔥 Could not start metrics server on {addr}: {e}");
                    return;
                }
            }
        };
        eprintln!("📊 Prometheus metrics serving on http://{}", addr);

        for request in server.incoming_requests() {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            if encoder.encode(&metric_families, &mut buffer).is_err() {
                eprintln!("🔥 Could not encode metrics");
                continue;
            }

            let response = tiny_http::Response::from_data(buffer)
                .with_header("Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8".parse::<tiny_http::Header>().unwrap());
            
            let _ = request.respond(response);
        }
    });

    Ok(())
}