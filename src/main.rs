use clap::{Parser, Subcommand};
mod config;    mod crypto;   mod storage;  mod epoch;
mod coin;      mod transfer; mod miner;    mod network;
mod sync;      mod metrics;

#[derive(Parser)]
#[command(author, version, about = "UnchainedCoin node v0.2")]
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
    //---------------------------------- parse CLI & load config -----
    let cli   = Cli::parse();                                    // clap derive  [oai_citation:0‡Docs.rs](https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html?utm_source=chatgpt.com)
    let cfg   = config::load(&cli.config)?;                      // toml → struct  [oai_citation:1‡GitHub](https://github.com/pq-crystals/dilithium?utm_source=chatgpt.com)

    //---------------------------------- embed-DB --------------------
    let db    = storage::open(&cfg.storage);                     // RocksDB with CFs  [oai_citation:2‡Docs.rs](https://docs.rs/blake3/latest/blake3/?utm_source=chatgpt.com)

    //---------------------------------- p2p network -----------------
    let net   = network::spawn(cfg.net.clone(), db.clone()).await?; // libp2p SwarmBuilder  [oai_citation:3‡libp2p.github.io](https://libp2p.github.io/rust-libp2p/libp2p/struct.SwarmBuilder.html?utm_source=chatgpt.com)

    //---------------------------------- channels --------------------
    let (coin_tx,  coin_rx)  = tokio::sync::mpsc::unbounded_channel(); // mpsc unbounded  [oai_citation:4‡Docs.rs](https://docs.rs/tokio/latest/tokio/sync/mpsc/fn.unbounded_channel.html?utm_source=chatgpt.com)

    //---------------------------------- epoch roller ----------------
    let epoch_mgr = epoch::Manager::new(
        db.clone(),
        cfg.epoch.clone(),
        cfg.mining.clone(),
        net.clone(),
        coin_rx,            // receives coin IDs mined locally
    );
    epoch_mgr.spawn();                                           // ticker + broadcast

    //---------------------------------- historical sync -------------
    sync::spawn(db.clone(), net.clone());                        // catches gaps

    //---------------------------------- optional miner --------------
    if matches!(cli.cmd, Some(Cmd::Mine)) || cfg.mining.enabled {
        miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), coin_tx);
    }

    //---------------------------------- metrics server --------------
    let metrics_bind = cfg.metrics.bind.clone();
    metrics::serve(cfg.metrics)?;

    //---------------------------------- node is running -------------
    println!("🚀 UnchainedCoin node is running!");
    println!("   📡 P2P listening on port {}", cfg.net.listen_port);
    println!("   📊 Metrics available on {}", metrics_bind);
    println!("   ⛏️  Mining: {}", if cfg.mining.enabled || matches!(cli.cmd, Some(Cmd::Mine)) { "enabled" } else { "disabled" });
    println!("   Press Ctrl+C to stop");

    //---------------------------------- park forever ---------------
    std::future::pending::<()>().await;
    Ok(())
}