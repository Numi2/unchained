use anyhow::Result;
use prometheus::{Registry, IntGauge, Encoder, TextEncoder};
use std::thread;

pub fn serve(cfg: crate::config::Metrics) -> Result<()> {
    let registry = Registry::new();
    // Prefix metrics with `unchained_` for better namespacing.
    let peers = IntGauge::new("unchained_peer_count", "Connected libp2p peers")?;
    registry.register(Box::new(peers.clone()))?;

    // In a real app, this gauge would be updated by the network module.
    peers.set(0);

    let bind_addr = cfg.bind.clone();
    thread::spawn(move || {
        let server = match tiny_http::Server::http(&bind_addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("🔥 Could not start metrics server on {}: {}", bind_addr, e);
                return;
            }
        };
        
        for request in server.incoming_requests() {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = registry.gather();
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