use clap::{Parser, Subcommand};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;
use anyhow;

pub mod config;    pub mod crypto;   pub mod storage;  pub mod epoch;
pub mod coin;      pub mod transfer; pub mod miner;    pub mod network;
pub mod sync;      pub mod metrics;  pub mod wallet;

#[derive(Parser)]
#[command(author, version, about = "unchained Node v0.3 (Post-Quantum Hardened)")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Suppress routine network gossip logs
    #[arg(long, default_value_t = false)]
    quiet_net: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    Mine,
    /// Print the local libp2p peer ID and exit
    PeerId,
    /// Export your stealth receiving address (base64-url)
    StealthAddress,
        /// Request a coin proof and verify it locally
        Proof {
            #[arg(long)]
            coin_id: String,
        },
        /// Serve a simple HTTP endpoint to fetch proofs by coin_id
        ProofServer {
            #[arg(long, default_value = "127.0.0.1:9090")]
            bind: String,
        },
    Send {
        /// Recipient stealth address (base64-url, from `wallet export-stealth-address`)
        #[arg(long)]
        stealth: String,
        #[arg(long)]
        amount: u64,
    },
    Balance,
    History,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- unchained Node ---");

    let cli = Cli::parse();
    if cli.quiet_net { network::set_quiet_logging(true); }

    // Try reading config from CLI path, then from the executable directory, else fallback to embedded default
    let mut cfg = match config::load(&cli.config) {
        Ok(c) => c,
        Err(e1) => {
            // Attempt exe-dir config.toml
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()));
            if let Some(dir) = exe_dir {
                let candidate = dir.join("config.toml");
                match config::load(&candidate) {
                    Ok(c) => c,
                    Err(e2) => {
                        eprintln!("⚠️  Could not read config from '{}' or exe dir: {} | {}", &cli.config, e1, e2);
                        // Embedded minimal default config ensures the Windows .exe can run standalone
                        const EMBEDDED_CONFIG: &str = include_str!("../config.toml");
                        match config::load_from_str(EMBEDDED_CONFIG) {
                            Ok(c) => c,
                            Err(e3) => return Err(anyhow::anyhow!("failed to load configuration: {} / {} / {}", e1, e2, e3)),
                        }
                    }
                }
            } else {
                const EMBEDDED_CONFIG: &str = include_str!("../config.toml");
                match config::load_from_str(EMBEDDED_CONFIG) {
                    Ok(c) => c,
                    Err(e3) => return Err(anyhow::anyhow!("failed to load configuration: {} / {}", e1, e3)),
                }
            }
        }
    };

    // Resolve storage path: if relative, place under user's home at ~/.unchained/unchained_data
    if std::path::Path::new(&cfg.storage.path).is_relative() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let abs = std::path::Path::new(&home)
            .join(".unchained")
            .join("unchained_data");
        cfg.storage.path = abs.to_string_lossy().into_owned();
    }

    let db = match std::panic::catch_unwind(|| storage::open(&cfg.storage)) {
        Ok(db) => db,
        Err(_) => return Err(anyhow::anyhow!("failed to open database")),
    };
    println!("🗄️  Database opened at '{}'", cfg.storage.path);

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let wallet = Arc::new(wallet::Wallet::load_or_create(db.clone())?);
    
    let sync_state = Arc::new(Mutex::new(sync::SyncState::default()));

    let net = network::spawn(cfg.net.clone(), cfg.p2p.clone(), db.clone(), sync_state.clone()).await?;

    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn background sync task (safe for read-only commands; does not advance epochs itself)
    sync::spawn(db.clone(), net.clone(), sync_state.clone(), shutdown_tx.subscribe(), !cfg.net.bootstrap.is_empty());
    
    // Handle CLI commands
    match &cli.cmd {
        Some(Cmd::Mine) => {
            // Start epoch manager only when actively mining or running as a block producer
            let epoch_mgr = epoch::Manager::new(
                db.clone(),
                cfg.epoch.clone(),
                cfg.mining.clone(),
                cfg.net.clone(),
                net.clone(),
                coin_rx,
                shutdown_tx.subscribe(),
                sync_state.clone(),
            );
            epoch_mgr.spawn_loop();

            // --- Active Synchronization Before Mining ---
            println!("🔄 Initiating synchronization with the network...");
            net.request_latest_epoch().await;

            let poll_interval_ms: u64 = 500;
            let max_attempts: u64 = ((cfg.net.sync_timeout_secs.saturating_mul(1000)) / poll_interval_ms).max(1);
            let mut synced = false;
            for attempt in 0..max_attempts {
                let highest_seen = sync_state.lock().unwrap().highest_seen_epoch;
                let peer_confirmed = sync_state.lock().unwrap().peer_confirmed_tip;
                let latest_opt = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None);
                let local_epoch = latest_opt.as_ref().map_or(0, |a| a.num);

                // When bootstrap peers are configured, require a peer-confirmed tip before declaring sync
                if highest_seen > 0 && local_epoch >= highest_seen && (cfg.net.bootstrap.is_empty() || peer_confirmed) {
                    println!("✅ Synchronization complete. Local epoch is {}.", local_epoch);
                    { let mut st = sync_state.lock().unwrap(); st.synced = true; }
                    synced = true;
                    break;
                }
                if highest_seen == 0 && latest_opt.is_some() && cfg.net.bootstrap.is_empty() {
                    println!("✅ No peers responded; proceeding with local chain at epoch {}.", local_epoch);
                    {
                        let mut st = sync_state.lock().unwrap();
                        st.synced = true;
                        if st.highest_seen_epoch == 0 { st.highest_seen_epoch = local_epoch; }
                    }
                    synced = true;
                    break;
                }
                if highest_seen > 0 {
                    if cfg.net.bootstrap.is_empty() {
                        println!("⏳ Syncing... local epoch: {}, network epoch: {}", local_epoch, highest_seen);
                    } else {
                        println!("⏳ Syncing... local {}, network {}, peer-confirmed: {}", local_epoch, highest_seen, peer_confirmed);
                    }
                } else {
                    println!("⏳ Waiting for network response... (attempt {})", attempt + 1);
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
            }
            if !synced {
                println!(
                    "⚠️  Could not sync with network after {}s. Starting as a new chain.",
                    cfg.net.sync_timeout_secs
                );
                if let Ok(Some(latest)) = db.get::<epoch::Anchor>("epoch", b"latest") {
                    let mut st = sync_state.lock().unwrap();
                    // Only auto-proceed without peer confirmation if no bootstrap peers are configured
                    if cfg.net.bootstrap.is_empty() || st.peer_confirmed_tip {
                        st.synced = true;
                    }
                    if st.highest_seen_epoch == 0 { st.highest_seen_epoch = latest.num; }
                    println!("✅ Proceeding with local chain at epoch {}.", latest.num);
                }
            }

            miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx, shutdown_tx.subscribe(), sync_state.clone());
            println!(
                "⛏️  Mining started (workers: {}, mem_kib: {}, heartbeat_secs: {})",
                cfg.mining.workers,
                cfg.mining.mem_kib,
                cfg.mining.heartbeat_interval_secs
            );
        }
        Some(Cmd::PeerId) => {
            let id = network::peer_id_string()?;
            println!("🆔 Peer ID: {}", id);
            if let Some(ip) = &cfg.net.public_ip {
                println!("📫 Multiaddr: /ip4/{}/udp/{}/quic-v1/p2p/{}", ip, cfg.net.listen_port, id);
            }
            return Ok(());
        }
        Some(Cmd::StealthAddress) => {
            let stealth = wallet.export_stealth_address();
            println!("{}", stealth);
            return Ok(());
        }
        Some(Cmd::Proof { coin_id }) => {
            // Parse coin id
            let id_vec = hex::decode(coin_id).map_err(|e| anyhow::anyhow!("Invalid coin_id hex: {}", e))?;
            if id_vec.len() != 32 { return Err(anyhow::anyhow!("coin_id must be 32 bytes")); }
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_vec);

            // Subscribe to proof responses and wait for matching coin_id
            let mut rx = net.proof_subscribe();
            net.request_coin_proof(id).await;
            println!("📨 Requested proof for coin {} (waiting up to 30s)", hex::encode(id));
            let _start = std::time::Instant::now();
            loop {
                tokio::select! {
                    Ok(resp) = rx.recv() => {
                        if resp.coin.id == id {
                            let leaf = crate::coin::Coin::id_to_leaf_hash(&resp.coin.id);
                            let ok = crate::epoch::MerkleTree::verify_proof(&leaf, &resp.proof, &resp.anchor.merkle_root);
                            println!("🔎 Proof verification for coin {}: {}", hex::encode(id), if ok {"OK"} else {"FAIL"});
                            return if ok { Ok(()) } else { Err(anyhow::anyhow!("invalid proof")) };
                        }
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        return Err(anyhow::anyhow!("timeout waiting for proof"));
                    }
                }
            }
        }
        Some(Cmd::ProofServer { bind }) => {
            // HTTPS server over rustls (aws-lc provider, PQ/hybrid TLS1.3)
            use hyper::{Body, Request as HRequest, Response as HResponse, Method, StatusCode};
            use hyper::service::service_fn;
            use std::net::SocketAddr;
            use tokio_rustls::TlsAcceptor;
            use tokio::net::TcpListener;
            use hyper::server::conn::Http;
            let addr: SocketAddr = bind.parse().map_err(|e| anyhow::anyhow!("invalid bind {}: {}", bind, e))?;
            let net_clone = net.clone();
            let auth_token = std::env::var("PROOF_SERVER_TOKEN").ok();
            let rate = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<String, (std::time::Instant, u32)>::new()));

            // Self-signed cert for local serving
            let (_cert_der, _key_der) = crypto::generate_self_signed_cert(&libp2p::identity::Keypair::generate_ed25519())?;
            let tls_cfg = crypto::create_pq_server_config(_cert_der, _key_der)?;
            let acceptor = TlsAcceptor::from(tls_cfg.clone());
            let listener = TcpListener::bind(addr).await?;
            println!("🔐 Proof server (TLS) listening on https://{}", bind);

            loop {
                let (stream, peer_addr) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let net = net_clone.clone();
                let auth = auth_token.clone();
                let rate = rate.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("TLS accept error: {}", e);
                            return;
                        }
                    };
                    let service = service_fn(move |req: HRequest<Body>| {
                        let net = net.clone();
                        let auth = auth.clone();
                        let rate = rate.clone();
                        let remote_ip = peer_addr.ip().to_string();
                        async move {
                            // Auth
                            if let Some(token) = &auth {
                                let ok = req.headers().get("x-auth-token").and_then(|v| v.to_str().ok()) == Some(token.as_str());
                                if !ok {
                                    return Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("unauthorized"))?);
                                }
                            }
                            // Simple per-IP rate limit: 5 req / 10s window.
                            {
                                let mut map = rate.lock().await;
                                let now = std::time::Instant::now();
                                let entry = map.entry(remote_ip.clone()).or_insert((now, 0));
                                if now.duration_since(entry.0) > std::time::Duration::from_secs(10) { *entry = (now, 0); }
                                entry.1 += 1;
                                if entry.1 > 5 { return Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::TOO_MANY_REQUESTS).body(Body::from("rate limit"))?); }
                            }

                            if req.method() == Method::GET && req.uri().path().starts_with("/proof/") {
                                let coin_hex = req.uri().path().trim_start_matches("/proof/");
                                let bytes = match hex::decode(coin_hex) { Ok(b) => b, Err(_) => vec![] };
                                if bytes.len() != 32 {
                                    return Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::BAD_REQUEST).body(Body::from("bad coin id"))?);
                                }
                                let mut id = [0u8; 32]; id.copy_from_slice(&bytes);

                                let mut sub = net.proof_subscribe();
                                let start = std::time::Instant::now();
                                net.request_coin_proof(id).await;
                                // Await response or timeout
                                let resp = tokio::time::timeout(std::time::Duration::from_secs(10), sub.recv()).await;
                                match resp {
                                    Ok(Ok(r)) if r.coin.id == id => {
                                        let leaf = crate::coin::Coin::id_to_leaf_hash(&r.coin.id);
                                        let ok = crate::epoch::MerkleTree::verify_proof(&leaf, &r.proof, &r.anchor.merkle_root);
                                        let ms = start.elapsed().as_millis() as f64;
                                        crate::metrics::PROOF_LATENCY_MS.observe(ms);
                                        let body = serde_json::to_vec(&serde_json::json!({
                                            "ok": ok, "response": {
                                                "coin": hex::encode(r.coin.id),
                                                "epoch": r.anchor.num,
                                                "merkle_root": hex::encode(r.anchor.merkle_root),
                                                "proof_len": r.proof.len()
                                            }
                                        }))?;
                                        Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::OK).header("Content-Type", "application/json").body(Body::from(body))?)
                                    }
                                    Ok(_) => Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::BAD_REQUEST).body(Body::from("mismatch"))?),
                                    Err(_) => Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::GATEWAY_TIMEOUT).body(Body::from("timeout"))?),
                                }
                            } else {
                                Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::NOT_FOUND).body(Body::from("not found"))?)
                            }
                        }
                    });
                    if let Err(e) = Http::new().serve_connection(tls_stream, service).await {
                        eprintln!("HTTP serve error: {}", e);
                    }
                });
            }
        }
        Some(Cmd::Send { stealth, amount }) => {
            println!("💰 Sending {} coins to stealth recipient", amount);
            match wallet.send_to_stealth_address(stealth, *amount, &net).await {
                Ok(outcome) => {
                    let total = outcome.transfers.len() + outcome.spends.len();
                    println!("✅ Sent {} records ({} legacy transfers, {} spends)", total, outcome.transfers.len(), outcome.spends.len());
                    for (i, t) in outcome.transfers.iter().enumerate() {
                        println!("  V1 transfer {}: coin {} -> {}", i + 1, hex::encode(t.coin_id), hex::encode(t.recipient()));
                    }
                    for (i, s) in outcome.spends.iter().enumerate() {
                        println!("  V2 spend {}: coin {} -> commitment {}", i + 1, hex::encode(s.coin_id), hex::encode(s.commitment));
                    }
                }
                Err(e) => {
                    eprintln!("❌ Send failed: {}", e);
                    return Err(e);
                }
            }
            return Ok(());
        }
        Some(Cmd::Balance) => {
            match wallet.balance() {
                Ok(balance) => {
                    println!("💰 Wallet balance: {} coins", balance);
                    println!("📍 Address: {}", hex::encode(wallet.address()));
                }
                Err(e) => {
                    eprintln!("❌ Failed to get balance: {}", e);
                    return Err(e);
                }
            }
            return Ok(());
        }
        Some(Cmd::History) => {
            match wallet.get_transaction_history() {
                Ok(history) => {
                    println!("📜 Transaction history:");
                    if history.is_empty() {
                        println!("  No transactions found");
                    } else {
                        for (i, record) in history.iter().enumerate() {
                            let direction = if record.is_sender { "→" } else { "←" };
                            println!("  {} {} {} {} (coin: {})", 
                                i + 1, 
                                direction, 
                                hex::encode(record.counterparty),
                                record.amount,
                                hex::encode(record.coin_id)
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to get history: {}", e);
                    return Err(e);
                }
            }
            return Ok(());
        }
        None => {
            // No command specified, start mining if enabled
            if cfg.mining.enabled {
                // Start epoch manager only when mining
                let epoch_mgr = epoch::Manager::new(
                    db.clone(),
                    cfg.epoch.clone(),
                    cfg.mining.clone(),
                    cfg.net.clone(),
                    net.clone(),
                    coin_rx,
                    shutdown_tx.subscribe(),
                    sync_state.clone(),
                );
                epoch_mgr.spawn_loop();

                // --- Active Synchronization Before Mining ---
                println!("🔄 Initiating synchronization with the network...");
                net.request_latest_epoch().await;

                let poll_interval_ms: u64 = 500;
                let max_attempts: u64 = ((cfg.net.sync_timeout_secs.saturating_mul(1000)) / poll_interval_ms).max(1);
                let mut synced = false;
                for attempt in 0..max_attempts {
                    let highest_seen = sync_state.lock().unwrap().highest_seen_epoch;
                    let peer_confirmed = sync_state.lock().unwrap().peer_confirmed_tip;
                    let latest_opt = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None);
                    let local_epoch = latest_opt.as_ref().map_or(0, |a| a.num);

                    if highest_seen > 0 && local_epoch >= highest_seen && (cfg.net.bootstrap.is_empty() || peer_confirmed) {
                        println!("✅ Synchronization complete. Local epoch is {}.", local_epoch);
                        { let mut st = sync_state.lock().unwrap(); st.synced = true; }
                        synced = true;
                        break;
                    }
                    if highest_seen == 0 && latest_opt.is_some() && cfg.net.bootstrap.is_empty() {
                        println!("✅ No peers responded; proceeding with local chain at epoch {}.", local_epoch);
                        {
                            let mut st = sync_state.lock().unwrap();
                            st.synced = true;
                            if st.highest_seen_epoch == 0 { st.highest_seen_epoch = local_epoch; }
                        }
                        synced = true;
                        break;
                    }
                    if highest_seen > 0 {
                        if cfg.net.bootstrap.is_empty() {
                            println!("⏳ Syncing... local epoch: {}, network epoch: {}", local_epoch, highest_seen);
                        } else {
                            println!("⏳ Syncing... local {}, network {}, peer-confirmed: {}", local_epoch, highest_seen, peer_confirmed);
                        }
                    } else {
                        println!("⏳ Waiting for network response... (attempt {})", attempt + 1);
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
                }
                if !synced {
                    println!(
                        "⚠️  Could not sync with network after {}s. Starting as a new chain.",
                        cfg.net.sync_timeout_secs
                    );
                    if let Ok(Some(latest)) = db.get::<epoch::Anchor>("epoch", b"latest") {
                        let mut st = sync_state.lock().unwrap();
                        if cfg.net.bootstrap.is_empty() || st.peer_confirmed_tip {
                            st.synced = true;
                        }
                        if st.highest_seen_epoch == 0 { st.highest_seen_epoch = latest.num; }
                        println!("✅ Proceeding with local chain at epoch {}.", latest.num);
                    }
                }

                miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx, shutdown_tx.subscribe(), sync_state.clone());
                println!(
                    "⛏️  Mining started (workers: {}, mem_kib: {}, heartbeat_secs: {})",
                    cfg.mining.workers,
                    cfg.mining.mem_kib,
                    cfg.mining.heartbeat_interval_secs
                );
            }
        }
    }

    let metrics_bind = cfg.metrics.bind.clone();
    metrics::serve(cfg.metrics)?;

    println!("\n🚀 unchained node is running!");
    println!("   📡 P2P listening on port {}", cfg.net.listen_port);
    if let Some(public_ip) = cfg.net.public_ip {
        println!("   📢 Public IP announced as: {public_ip}");
    }
    println!("   📊 Metrics available on http://{metrics_bind}");
    println!("   ⛏️  Mining: {}", if matches!(cli.cmd, Some(Cmd::Mine)) || cfg.mining.enabled { "enabled" } else { "disabled" });
    println!("   🎯 Epoch coin cap (max selected): {}", cfg.epoch.max_coins_per_epoch);
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
