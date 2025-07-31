use prometheus::{Registry, IntGauge};

pub fn serve(cfg: crate::config::Metrics) -> anyhow::Result<()> {
    let reg = Registry::new();
    let peers = IntGauge::new("peer_count", "connected peers")?; reg.register(Box::new(peers))?;
    
    // For now, just print that metrics server would start
    println!("📊 metrics server would start on {}", cfg.bind);
    
    Ok(())
}