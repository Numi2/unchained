use clap::{Parser, Subcommand};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;
use anyhow;

pub mod config;    pub mod crypto;   pub mod storage;  pub mod epoch;
pub mod coin;      pub mod transfer; pub mod miner;    pub mod network;
pub mod sync;      pub mod metrics;  pub mod wallet;   pub mod ringsig;  pub mod ring_transfer;

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
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
    },
    /// Send a private ring transfer for a specific owned output (demo)
    RingSend {
        #[arg(long)]
        to: String,
        /// Hex-encoded 32-byte output id to spend
        #[arg(long, value_name="output_id_hex")]
        output_id: String,
    },
    Balance,
    History,
    /// Rebuild ring state (outputs and spent set) from canonical chain after a reorg
    RebuildRing,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("--- unchained Node ---");

    let cli = Cli::parse();
    if cli.quiet_net { network::set_quiet_logging(true); }

    let mut cfg = config::load(&cli.config)?;

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

    if matches!(cli.cmd, Some(Cmd::Mine)) || cli.cmd.is_none() {
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
    }

    // --- Active Synchronization Before Mining ---
    // A new node must sync with the network before it can mine. We explicitly
    // request the latest state and then enter a loop, waiting until our local
    // epoch number matches the highest epoch we've seen from the network.
    if matches!(cli.cmd, Some(Cmd::Mine)) || cli.cmd.is_none() {
        println!("🔄 Initiating synchronization with the network...");
        net.request_latest_epoch().await;

        let poll_interval_ms: u64 = 500;
        let max_attempts: u64 = ((cfg.net.sync_timeout_secs.saturating_mul(1000)) / poll_interval_ms).max(1);
        let mut synced = false;
        for attempt in 0..max_attempts {
            let highest_seen = sync_state.lock().unwrap().highest_seen_epoch;
            let latest_opt = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None);
            let local_epoch = latest_opt.as_ref().map_or(0, |a| a.num);

            // Case 1: We have a network view and our local chain has caught up
            if highest_seen > 0 && local_epoch >= highest_seen {
                println!("✅ Synchronization complete. Local epoch is {}.", local_epoch);
                { let mut st = sync_state.lock().unwrap(); st.synced = true; }
                synced = true;
                break;
            }

            // Case 2: No peers responded, but we already have a local anchor (genesis) → proceed
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
                println!("⏳ Syncing... local epoch: {}, network epoch: {}", local_epoch, highest_seen);
            } else {
                println!("⏳ Waiting for network response... (attempt {})", attempt + 1);
            }

            // Proactively request latest anchor each iteration to coax peers
            net.request_latest_epoch().await;
            // Optionally, every 10th attempt, try fetching epoch 0 as a seed if we still have nothing
            if attempt % 10 == 0 && latest_opt.is_none() {
                net.request_epoch(0).await;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
        }

        if !synced {
            println!(
                "⚠️  Could not sync with network after {}s. Starting as a new chain.",
                cfg.net.sync_timeout_secs
            );
            // Fallback: if we have a local anchor (e.g., genesis created by epoch manager),
            // allow the node to proceed as a standalone chain even if bootstrap peers are configured.
            if let Ok(Some(latest)) = db.get::<epoch::Anchor>("epoch", b"latest") {
                let mut st = sync_state.lock().unwrap();
                st.synced = true;
                if st.highest_seen_epoch == 0 { st.highest_seen_epoch = latest.num; }
                println!("✅ Proceeding with local chain at epoch {}.", latest.num);
            }
        }
    }
    
    // Handle CLI commands
    match &cli.cmd {
        Some(Cmd::Mine) => {
            miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx, shutdown_tx.subscribe(), sync_state.clone());
        }
        Some(Cmd::PeerId) => {
            let id = network::peer_id_string()?;
            println!("🆔 Peer ID: {}", id);
            if let Some(ip) = &cfg.net.public_ip {
                println!("📫 Multiaddr: /ip4/{}/udp/{}/quic-v1/p2p/{}", ip, cfg.net.listen_port, id);
            }
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
            // Async Hyper server with simple auth and rate limit
            use hyper::{Body, Request as HRequest, Response as HResponse, Server, Method, StatusCode};
            use hyper::service::{make_service_fn, service_fn};
            use std::net::SocketAddr;
            let addr: SocketAddr = bind.parse().map_err(|e| anyhow::anyhow!("invalid bind {}: {}", bind, e))?;
            let net_clone = net.clone();
            let auth_token = std::env::var("PROOF_SERVER_TOKEN").ok();
            let rate = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<String, (std::time::Instant, u32)>::new()));

            let make_svc = make_service_fn(move |_| {
                let net = net_clone.clone();
                let auth = auth_token.clone();
                let rate = rate.clone();
                let db_clone = db.clone();
                async move {
                    Ok::<_, anyhow::Error>(service_fn(move |req: HRequest<Body>| {
                        let net = net.clone();
                        let auth = auth.clone();
                        let rate = rate.clone();
                        let db = db_clone.clone();
                        async move {
                            // Auth
                            if let Some(token) = &auth {
                                let ok = req.headers().get("x-auth-token").and_then(|v| v.to_str().ok()) == Some(token.as_str());
                                if !ok {
                                    return Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("unauthorized"))?);
                                }
                            }
                            // Simple per-IP rate limit: 5 req / 10s window. Prefer socket addr over XFF unless explicitly trusted.
                            let ip = req
                                .extensions()
                                .get::<SocketAddr>()
                                .map(|a| a.ip().to_string())
                                .or_else(|| req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
                                .unwrap_or_else(|| "unknown".to_string());
                            {
                                let mut map = rate.lock().await;
                                let now = std::time::Instant::now();
                                let entry = map.entry(ip.clone()).or_insert((now, 0));
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
                            } else if req.method() == Method::GET && req.uri().path().starts_with("/ring/") {
                                let tx_hex = req.uri().path().trim_start_matches("/ring/");
                                let bytes = match hex::decode(tx_hex) { Ok(b) => b, Err(_) => vec![] };
                                if bytes.len() != 32 {
                                    return Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::BAD_REQUEST).body(Body::from("bad tx hash"))?);
                                }
                                let mut h = [0u8;32]; h.copy_from_slice(&bytes);
                                // Serve proof locally from DB
                                if let Ok(Some(latest)) = db.get::<crate::epoch::Anchor>("epoch", b"latest") {
                                    for e in (0..=latest.num).rev() {
                                        if let Ok(list) = db.get_epoch_ring_transfers(e) {
                                            if list.contains(&h) {
                                                if let Ok(Some(anchor)) = db.get::<crate::epoch::Anchor>("epoch", &e.to_le_bytes()) {
                                                    let mut sorted = list.clone();
                                                    sorted.sort();
                                                    if let Some(proof) = crate::epoch::build_hash_list_proof(&sorted, &h) {
                                                        let body = serde_json::to_vec(&serde_json::json!({
                                                            "ok": true, "response": {
                                                                "tx_hash": tx_hex,
                                                                "epoch": e,
                                                                "transfers_root": hex::encode(anchor.transfers_root),
                                                                "proof_len": proof.len()
                                                            }
                                                        }))?;
                                                        return Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::OK).header("Content-Type", "application/json").body(Body::from(body))?);
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                                Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::NOT_FOUND).body(Body::from("ring tx not found"))?)
                            } else {
                                Ok::<_, anyhow::Error>(HResponse::builder().status(StatusCode::NOT_FOUND).body(Body::from("not found"))?)
                            }
                        }
                    }))
                }
            });
            println!("🌐 Proof server listening on http://{}", bind);
            // Run server in foreground and await shutdown via Ctrl+C
            if let Err(e) = Server::bind(&addr).serve(make_svc).await {
                eprintln!("proof server error: {}", e);
            }
            return Ok(());
        }
        Some(Cmd::Send { to, amount }) => {
            // Parse recipient address
            let recipient = hex::decode(to)
                .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?;
            if recipient.len() != 32 {
                return Err(anyhow::anyhow!("Recipient address must be 32 bytes"));
            }
            let mut recipient_addr = [0u8; 32];
            recipient_addr.copy_from_slice(&recipient);

            // Send transfer
            println!("💰 Sending {} coins to {}", amount, hex::encode(recipient_addr));
            match wallet.send_transfer(recipient_addr, *amount, &net).await {
                Ok(transfers) => {
                    println!("✅ Transfer successful! Sent {} transfers", transfers.len());
                    for (i, transfer) in transfers.iter().enumerate() {
                        println!("  Transfer {}: coin {} -> {}", i + 1, hex::encode(transfer.coin_id), hex::encode(transfer.recipient()));
                    }
                }
                Err(e) => {
                    eprintln!("❌ Transfer failed: {}", e);
                    return Err(e);
                }
            }
            return Ok(());
        }
        Some(Cmd::RingSend { to, output_id }) => {
            // Parse recipient address and output id
            let recipient = hex::decode(to).map_err(|e| anyhow::anyhow!("Invalid recipient: {}", e))?;
            if recipient.len() != 32 { return Err(anyhow::anyhow!("Recipient must be 32 bytes")); }
            let mut recipient_addr = [0u8;32]; recipient_addr.copy_from_slice(&recipient);
            let out_bytes = hex::decode(output_id).map_err(|e| anyhow::anyhow!("Invalid output id: {}", e))?;
            if out_bytes.len() != 32 { return Err(anyhow::anyhow!("Output id must be 32 bytes")); }
            let mut out_id = [0u8;32]; out_id.copy_from_slice(&out_bytes);

            // Load output
            let store = db.clone();
            let store_ref = store;
            if let Some(out) = store_ref.get_output(&out_id)? {
                // Build ring transfer (mock LLRS)
                #[cfg(feature = "ring_mock")]
                let scheme = crate::ringsig::MockLlrs{};
                #[cfg(not(feature = "ring_mock"))]
                let scheme = crate::ringsig::NoLlrs{};
                let rtx = wallet.build_ring_transfer(&store_ref, &scheme, &out, recipient_addr)?;
                // Add to mempool and gossip
                store_ref.put_ring_mempool_tx(&rtx)?;
                net.gossip_ring_transfer(&rtx).await;
                // Save for inclusion-proof servicing and reorg rebuilds
                store_ref.put_ring_tx(&rtx)?;
                println!("✅ Ring transfer submitted: {}", hex::encode(rtx.hash()));
                return Ok(());
            } else {
                return Err(anyhow::anyhow!("Output not found or not owned"));
            }
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
        Some(Cmd::RebuildRing) => {
            db.rebuild_ring_state()?;
            println!("🔄 Rebuilt ring state from canonical chain");
            return Ok(());
        }
        None => {
            // No command specified, start mining if enabled
            let mining_enabled = cfg.mining.enabled;
            if mining_enabled {
                miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx, shutdown_tx.subscribe(), sync_state.clone());
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
