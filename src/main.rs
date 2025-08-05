use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;

pub mod config;    pub mod crypto;   pub mod storage;  pub mod epoch;
pub mod coin;      pub mod transfer; pub mod miner;    pub mod network;
pub mod sync;      pub mod metrics;  pub mod wallet;

#[derive(Parser)]
#[command(author, version, about = "unchained Node v0.3 (Post-Quantum Hardened)")]
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
    println!("--- unchained Node ---");

    let cli = Cli::parse();
    let cfg_path = std::path::Path::new(&cli.config);
    let cfg_dir = cfg_path.parent().unwrap_or(std::path::Path::new("."));
    let mut cfg = config::load(&cli.config)?;

    // Resolve storage path relative to the config file location so that
    // running the binary from any working directory uses the **same** DB.
    if std::path::Path::new(&cfg.storage.path).is_relative() {
        let abs = cfg_dir.join(&cfg.storage.path);
        cfg.storage.path = abs.to_string_lossy().into_owned();
    }

    let db = storage::open(&cfg.storage);
    println!("🗄️  Database opened at '{}'", cfg.storage.path);

    // Create shutdown broadcast channel for coordinated shutdown
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    let wallet = Arc::new(wallet::Wallet::load_or_create(db.clone())?);

    let net = network::spawn(cfg.net.clone(), cfg.p2p.clone(), db.clone()).await?;

    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();

    let epoch_mgr = epoch::Manager::new(
        db.clone(),
        cfg.epoch.clone(),
        cfg.mining.clone(),
        cfg.net.clone(),
        net.clone(),
        coin_rx,
        shutdown_tx.subscribe(),
    );
    epoch_mgr.spawn();

    sync::spawn(db.clone(), net.clone(), shutdown_tx.subscribe());

    let mining_enabled = matches!(cli.cmd, Some(Cmd::Mine)) || cfg.mining.enabled;
    if mining_enabled {
        miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx, shutdown_tx.subscribe());
    }

    let metrics_bind = cfg.metrics.bind.clone();
    metrics::serve(cfg.metrics)?;

    println!("\n🚀 unchained node is running!");
    println!("   📡 P2P listening on port {}", cfg.net.listen_port);
    if let Some(public_ip) = cfg.net.public_ip {
        println!("   📢 Public IP announced as: {public_ip}");
    }
    println!("   📊 Metrics available on http://{metrics_bind}");
    println!("   ⛏️  Mining: {}", if mining_enabled { "enabled" } else { "disabled" });
    println!("   Press Ctrl+C to stop");

    // Wait for shutdown signal and perform clean shutdown
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("\n🛑 Shutdown signal received, cleaning up...");
            
            // Signal all background tasks to shutdown
            println!("📡 Signaling background tasks to shutdown...");
            let _ = shutdown_tx.send(());
            
            // Give tasks a reasonable time to shutdown gracefully
            println!("⏳ Waiting for tasks to shutdown gracefully...");
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            
            // Properly close database to prevent file conflicts
            if let Err(e) = db.close() {
                eprintln!("Warning: Database cleanup failed: {e}");
            } else {
                println!("✅ Database closed cleanly");
            }
            
            println!("👋 unchained node stopped");
            Ok(())
        }
        Err(err) => {
            eprintln!("Error waiting for shutdown signal: {err}");
            Err(err.into())
        }
    }
}
