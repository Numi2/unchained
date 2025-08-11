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
pub static RATE_LIMIT_DROPS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_rate_limited_messages_total", "Inbound messages dropped due to per-peer rate limiting").unwrap());
pub static BANNED_DROPS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_banned_messages_total", "Inbound messages dropped due to peer being banned").unwrap());
pub static PENDING_CMD_DROPS: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_pending_command_drops_total", "Commands dropped due to pending queue capacity").unwrap());
pub static PENDING_CMD_QUEUE_LEN: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_pending_command_queue_len", "Length of the pending network command queue").unwrap());
pub static PROOF_DEDUP_SIZE: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_proof_dedup_size", "Number of entries in recent proof request dedup map").unwrap());
pub static EPOCH_REQ_DEDUP_SIZE: Lazy<IntGauge> = Lazy::new(|| IntGauge::new("unchained_epoch_req_dedup_size", "Number of entries in recent epoch request dedup map").unwrap());

// Inbound message counters per topic
pub static MSGS_IN_ANCHOR: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_anchor_total", "Inbound anchor messages").unwrap());
pub static MSGS_IN_COIN: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_coin_total", "Inbound coin candidate messages").unwrap());
pub static MSGS_IN_TX: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_tx_total", "Inbound transfer messages").unwrap());
pub static MSGS_IN_EPOCH_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_epoch_req_total", "Inbound epoch request messages").unwrap());
pub static MSGS_IN_COIN_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_coin_req_total", "Inbound coin request messages").unwrap());
pub static MSGS_IN_LATEST_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_latest_req_total", "Inbound latest epoch request messages").unwrap());
pub static MSGS_IN_PROOF_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_proof_req_total", "Inbound coin proof request messages").unwrap());
pub static MSGS_IN_PROOF_RESP: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_in_proof_resp_total", "Inbound coin proof response messages").unwrap());

// Outbound message counters per topic
pub static MSGS_OUT_ANCHOR: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_anchor_total", "Outbound anchor messages").unwrap());
pub static MSGS_OUT_COIN: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_coin_total", "Outbound coin candidate messages").unwrap());
pub static MSGS_OUT_TX: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_tx_total", "Outbound transfer messages").unwrap());
pub static MSGS_OUT_EPOCH_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_epoch_req_total", "Outbound epoch request messages").unwrap());
pub static MSGS_OUT_COIN_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_coin_req_total", "Outbound coin request messages").unwrap());
pub static MSGS_OUT_LATEST_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_latest_req_total", "Outbound latest epoch request messages").unwrap());
pub static MSGS_OUT_PROOF_REQ: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_proof_req_total", "Outbound coin proof request messages").unwrap());
pub static MSGS_OUT_PROOF_RESP: Lazy<IntCounter> = Lazy::new(|| IntCounter::new("unchained_msgs_out_proof_resp_total", "Outbound coin proof response messages").unwrap());

pub fn serve(cfg: crate::config::Metrics) -> Result<String> {
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
    REGISTRY.register(Box::new(RATE_LIMIT_DROPS.clone()))?;
    REGISTRY.register(Box::new(BANNED_DROPS.clone()))?;
    REGISTRY.register(Box::new(PENDING_CMD_DROPS.clone()))?;
    REGISTRY.register(Box::new(PENDING_CMD_QUEUE_LEN.clone()))?;
    REGISTRY.register(Box::new(PROOF_DEDUP_SIZE.clone()))?;
    REGISTRY.register(Box::new(EPOCH_REQ_DEDUP_SIZE.clone()))?;

    // Register per-topic message counters
    REGISTRY.register(Box::new(MSGS_IN_ANCHOR.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_COIN.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_TX.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_EPOCH_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_COIN_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_LATEST_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_PROOF_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_IN_PROOF_RESP.clone()))?;

    REGISTRY.register(Box::new(MSGS_OUT_ANCHOR.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_COIN.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_TX.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_EPOCH_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_COIN_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_LATEST_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_PROOF_REQ.clone()))?;
    REGISTRY.register(Box::new(MSGS_OUT_PROOF_RESP.clone()))?;
    PEERS.set(0);

    // Start metrics server, retrying on port conflicts by incrementing port number.
    let bind_addr = cfg.bind.clone();
    let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel::<String>(1);
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
        // Inform the caller which address we successfully bound to
        let _ = addr_tx.send(addr.clone());
        eprintln!("📊 Prometheus metrics serving on http://{}", addr);

        for request in server.incoming_requests() {
            // Pre-allocate a buffer proportional to current families to reduce reallocs
            let mut buffer = Vec::with_capacity(32 * 1024);
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            if encoder.encode(&metric_families, &mut buffer).is_err() {
                eprintln!("🔥 Could not encode metrics");
                continue;
            }
            let mut response = tiny_http::Response::from_data(buffer);
            // Prometheus text format content-type
            response.add_header(
                "Content-Type: text/plain; version=0.0.4; charset=utf-8"
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            let _ = request.respond(response);
        }
    });

    // Wait for the bound address so callers can display the correct endpoint
    let bound = addr_rx.recv().map_err(|e| anyhow::anyhow!("metrics server failed to report bound address: {}", e))?;
    Ok(bound)
}