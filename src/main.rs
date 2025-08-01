use clap::{Parser, Subcommand};
use std::sync::Arc;

pub mod config;    pub mod crypto;   pub mod storage;  pub mod epoch;
pub mod coin;      pub mod transfer; pub mod miner;    pub mod network;
pub mod sync;      pub mod metrics;  pub mod wallet;

#[derive(Parser)]
#[command(author, version, about = "UnchainedCoin Node v0.3 (Post-Quantum Hardened)")]
struct Cli {
    /// Path to the TOML config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enable the local miner even if `mining.enabled = false`
    Mine,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- UnchainedCoin Node ---");

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    let db = storage::open(&cfg.storage);
    println!("🗄️  Database opened at '{}'", cfg.storage.path);

    let wallet = Arc::new(wallet::Wallet::load_or_create(db.clone())?);

    let net = network::spawn(cfg.net.clone(), db.clone()).await?;

    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();

    let epoch_mgr = epoch::Manager::new(
        db.clone(),
        cfg.epoch.clone(),
        cfg.mining.clone(),
        net.clone(),
        coin_rx,
    );
    epoch_mgr.spawn();

    sync::spawn(db.clone(), net.clone());

    let mining_enabled = matches!(cli.cmd, Some(Cmd::Mine)) || cfg.mining.enabled;
    if mining_enabled {
        miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx);
    }

    let metrics_bind = cfg.metrics.bind.clone();
    metrics::serve(cfg.metrics)?;

    println!("\n🚀 UnchainedCoin node is running!");
    println!("   📡 P2P listening on port {}", cfg.net.listen_port);
    println!("   📊 Metrics available on http://{}", metrics_bind);
    println!("   ⛏️  Mining: {}", if mining_enabled { "enabled" } else { "disabled" });
    println!("   Press Ctrl+C to stop");

    std::future::pending::<()>().await;
    Ok(())
}