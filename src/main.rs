use clap::{Parser, Subcommand};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;

pub mod config;    pub mod crypto;   pub mod storage;  pub mod epoch;
pub mod coin;      pub mod transfer; pub mod miner;    pub mod network;
pub mod sync;      pub mod metrics;  pub mod wallet;

#[derive(Parser)]
#[command(author, version, about = "unchained Node v0.3 (Post-Quantum Hardened)")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    Mine,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- unchained Node ---");

    let cli = Cli::parse();
    let cfg_path = std::path::Path::new(&cli.config);
    let cfg_dir = cfg_path.parent().unwrap_or(std::path::Path::new("."));
    let mut cfg = config::load(&cli.config)?;

    if std::path::Path::new(&cfg.storage.path).is_relative() {
        let abs = cfg_dir.join(&cfg.storage.path);
        cfg.storage.path = abs.to_string_lossy().into_owned();
    }

    let db = storage::open(&cfg.storage);
    println!("🗄️  Database opened at '{}'", cfg.storage.path);

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let wallet = Arc::new(wallet::Wallet::load_or_create(db.clone())?);
    
    let sync_state = Arc::new(Mutex::new(sync::SyncState::default()));

    let net = network::spawn(cfg.net.clone(), cfg.p2p.clone(), db.clone(), sync_state.clone()).await?;

    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();

    sync::spawn(db.clone(), net.clone(), sync_state.clone(), shutdown_tx.subscribe());

    let epoch_mgr = epoch::Manager::new(
        db.clone(),
        cfg.epoch.clone(),
        cfg.mining.clone(),
        cfg.net.clone(),
        net.clone(),
        coin_rx,
        shutdown_tx.subscribe(),
    );
    epoch_mgr.spawn_loop();

    // --- Active Synchronization Before Mining ---
    // A new node must sync with the network before it can mine. We explicitly
    // request the latest state and then enter a loop, waiting until our local
    // epoch number matches the highest epoch we've seen from the network.
    println!("🔄 Initiating synchronization with the network...");
    net.request_latest_epoch().await;
    
    let mut synced = false;
    for _ in 0..260 { // Up to 30 seconds to sync (160 * 500ms)
        let highest_seen = sync_state.lock().unwrap().highest_seen_epoch;
        let local_epoch = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None).map_or(0, |a| a.num);

        // Wait until we've heard from the network and our local chain matches the height.
        if highest_seen > 0 && local_epoch >= highest_seen {
            println!("✅ Synchronization complete. Local epoch is {}.", local_epoch);
            synced = true;
            break;
        }

        if highest_seen > 0 {
            println!("⏳ Syncing... local epoch: {}, network epoch: {}", local_epoch, highest_seen);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    if !synced {
        println!("⚠️  Could not sync with network after 160s. Starting as a new chain.");
    }
    
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

    match signal::ctrl_c().await {
        Ok(()) => {
            println!("\n🛑 Shutdown signal received, cleaning up...");
            let _ = shutdown_tx.send(());
            println!("⏳ Waiting for tasks to shutdown gracefully...");
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
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
