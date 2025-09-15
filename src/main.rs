use clap::{Parser, Subcommand};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;
use anyhow;
use base64::Engine;
use std::io::{self, Write};

pub mod config;    pub mod crypto;   pub mod storage;  pub mod epoch;
pub mod coin;      pub mod transfer; pub mod miner;    pub mod network;
pub mod sync;      pub mod metrics;  pub mod wallet;   pub mod consensus;
pub mod bridge;    pub mod offers;   pub mod x402;
use qrcode::QrCode;
use qrcode::render::unicode;
use crate::network::RateLimitedMessage;
use pqcrypto_traits::kem::PublicKey as KyberPkTrait;
fn print_qr_to_terminal(data: &str) -> anyhow::Result<()> {
    let code = QrCode::new(data.as_bytes())?;
    let image = code.render::<unicode::Dense1x2>().dark_color(unicode::Dense1x2::Light).build();
    println!("{}", image);
    Ok(())
}
fn copy_to_clipboard(text: &str) -> anyhow::Result<()> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(text.to_string())?;
    Ok(())
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Unchained blockchain node and wallet CLI (Post‑Quantum Hardened)",
    long_about = "Run an Unchained node: mine, sync, and send hashlock transfers with Kyber stealth receiving.\n\
\nSending accepts a single receiver code (stealth address or batch token). Use flags for automation or run interactively for a guided flow.",
    help_template = "{name} {version}\n{about}\n\nUSAGE:\n  {usage}\n\nOPTIONS:\n{options}\n\nCOMMANDS:\n{subcommands}\n\n{after-help}",
    after_help = "Examples:\n  unchained stealth-address\n  unchained send --to <STEALTH_ADDR> --amount 100\n  unchained send  # guided flow\n  unchained make-commitment-request --stealth <STEALTH_ADDR> --amount 100\n  unchained serve-commitments\n"
)]
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
    /// Start mining and block production (runs epoch manager and miners)
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
    /// Send coins to a receiver paycode with an OOB spend note
    Send {
        /// Receiver paycode (base64-url): contains chain_id binding, receiver Kyber PK, and routing tag
        #[arg(long)]
        paycode: String,
        /// Amount to send
        #[arg(long)]
        amount: u64,
        /// OOB spend note secret `s` as hex or base64-url; if omitted, a random 32-byte secret is generated and printed
        #[arg(long)]
        note: Option<String>,
    },
    /// HTLC: Sender precomputes ch_refund (and optionally secrets) from plan
    HtlcRefundPrepare {
        /// Plan JSON from HtlcPlan
        #[arg(long)] plan: String,
        /// Optional hex/base64-url refund secret base; if omitted, random per-coin secrets are generated and saved
        #[arg(long)] refund_base: Option<String>,
        /// Output JSON for ch_refund mapping
        #[arg(long)] out: String,
        /// Optional output JSON to store refund secrets per coin (only used when refund_base is not provided)
        #[arg(long)] out_secrets: Option<String>,
    },
    Balance,
    History,
    /// x402: Pay a 402 challenge at a protected URL and print X-PAYMENT header
    X402Pay {
        /// URL to the protected resource (server will return 402 with challenge)
        #[arg(long)] url: String,
        /// Optional: auto-resubmit and print resource body after paying
        #[arg(long, default_value_t = true)] auto_resubmit: bool,
    },
    /// HTLC: Plan an offer (sender) and output a JSON plan
    HtlcPlan {
        #[arg(long)] paycode: String,
        #[arg(long)] amount: u64,
        /// Timeout epoch number T
        #[arg(long, value_parser = clap::value_parser!(u64))] timeout: u64,
        /// Output file to write the plan JSON
        #[arg(long)] out: String,
    },
    /// HTLC: Receiver computes claim CHs from claim secret and writes JSON
    HtlcClaimPrepare {
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)] claim_secret: String,
        /// Comma-separated coin ids (hex) to claim
        #[arg(long)] coins: String,
        /// Output JSON file to write claim CHs
        #[arg(long)] out: String,
    },
    /// HTLC: Execute sender offer (build spends with HTLC locks) using plan and receiver claim doc
    HtlcOfferExecute {
        #[arg(long)] plan: String,
        #[arg(long)] claims: String,
        /// Optional hex/base64-url refund secret base to derive per-coin refund secrets deterministically
        #[arg(long)] refund_base: Option<String>,
        /// Optional path to write per-coin refund secrets; required if refund_base is not provided
        #[arg(long)] refund_secrets_out: Option<String>,
    },
    /// HTLC: Execute claim spends before timeout with claim secret
    HtlcClaim {
        #[arg(long)] timeout: u64,
        #[arg(long)] claim_secret: String,
        /// JSON file mapping coin_id -> ch_refund (computed on sender during offer execute)
        #[arg(long)] refunds: String,
        /// Receiver paycode for the next hop
        #[arg(long)] paycode: String,
    },
    /// HTLC: Execute refund at/after timeout with refund secret
    HtlcRefund {
        #[arg(long)] timeout: u64,
        #[arg(long)] refund_secret: String,
        /// JSON file mapping coin_id -> ch_claim (from receiver)
        #[arg(long)] claims: String,
        /// Sender paycode (destination for refunded coins)
        #[arg(long)] paycode: String,
    },
    /// Offer: Create and sign an offer from an HTLC plan
    OfferCreate {
        /// Receiver paycode
        #[arg(long)] paycode: String,
        /// Amount to offer
        #[arg(long)] amount: u64,
        /// Timeout epoch number T
        #[arg(long, value_parser = clap::value_parser!(u64))] timeout: u64,
        /// Optional maker price in basis points (10000 = 100%)
        #[arg(long)] price_bps: Option<u64>,
        /// Optional note/label
        #[arg(long)] note: Option<String>,
        /// Output JSON path for the signed offer
        #[arg(long)] out: String,
    },
    /// Offer: Publish a signed offer to the network
    OfferPublish {
        /// Input offer JSON path
        #[arg(long)] input: String,
    },
    /// Offer: Watch incoming offers (prints JSON lines)
    OfferWatch {
        /// Exit after receiving N offers (optional)
        #[arg(long)] count: Option<u64>,
        /// Minimum amount filter
        #[arg(long)] min_amount: Option<u64>,
        /// Filter by maker address (hex)
        #[arg(long)] maker: Option<String>,
        /// Resume from millis cursor
        #[arg(long)] since: Option<u128>,
    },
    /// Offer: Verify a signed offer file
    OfferVerify {
        /// Input offer JSON path
        #[arg(long)] input: String,
    },
    /// Offer: Accept a signed offer file (deterministic secrets policy)
    OfferAccept {
        /// Input offer JSON path
        #[arg(long)] input: String,
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)] claim_secret: String,
        /// Refund base (deterministic per-coin), 32-byte hex/base64-url; if omitted, secrets are written to file
        #[arg(long)] refund_base: Option<String>,
        /// Path to write generated refund secrets per coin (required if --refund_base is absent)
        #[arg(long)] refund_secrets_out: Option<String>,
    },
    /// Offer: Prepare receiver claim CHs from an offer and claim secret
    OfferAcceptPrepare {
        /// Input offer JSON path
        #[arg(long)] input: String,
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)] claim_secret: String,
        /// Output JSON file to write claim CHs
        #[arg(long)] out: String,
    },
    /// Scan and repair malformed spend entries (backs up and deletes invalid rows)
    RepairSpends,
    // Commitment request/response tooling removed
    /// P2P: Send a short text message (topic limited to 2 msgs/24h)
    MsgSend {
        /// Message text to send; if omitted, you will be prompted
        #[arg(long)]
        text: Option<String>,
    },
    /// P2P: Listen for incoming messages on the 24h-limited topic
    MsgListen {
        /// Exit after receiving a single message
        #[arg(long, default_value_t = false)]
        once: bool,
        /// Exit after receiving this many messages
        #[arg(long)]
        count: Option<u64>,
    },
    /// Re-gossip all spends from local DB (sender-side recovery)
    ReplaySpends,
    /// Rescan local spends against this wallet (receiver-side recovery)
    RescanWallet,
    /// Export all anchors into a compressed snapshot file
    ExportAnchors {
        /// Output file path (e.g. anchors_snapshot.zst)
        #[arg(long)]
        out: String,
    },
    /// Import anchors from a compressed snapshot file
    ImportAnchors {
        /// Input snapshot file path
        #[arg(long)]
        input: String,
    },
    /// Bridge: Lock UNCH on Unchained for a Sui recipient
    BridgeOut {
        /// Sui recipient address (0x-prefixed lowercase hex)
        #[arg(long)]
        sui_recipient: String,
        /// Amount to lock
        #[arg(long)]
        amount: u64,
        /// Seconds to pre-warm coin proofs before submitting (0 to disable)
        #[arg(long, default_value_t = 12)]
        prewarm_secs: u64,
    },
    /// Meta: Create a signed authorization for facilitator to submit spends (EIP-3009-like)
    MetaAuthzCreate {
        /// Receiver paycode (base64-url)
        #[arg(long)] to: String,
        /// Total amount to authorize
        #[arg(long)] amount: u64,
        /// Valid after this epoch (inclusive)
        #[arg(long)] valid_after: u64,
        /// Valid before this epoch (exclusive)
        #[arg(long)] valid_before: u64,
        /// Facilitator Kyber768 public key (base64-url)
        #[arg(long)] facilitator_kyber_b64: String,
        /// Optional x402-style 32-byte binding (base64-url)
        #[arg(long)] binding_b64: Option<String>,
        /// Output file for the JSON document
        #[arg(long)] out: String,
    },
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

    // Auto-import anchors snapshot if DB is empty (no genesis) and a co-located snapshot file exists
    if db.get::<epoch::Anchor>("epoch", &0u64.to_le_bytes())?.is_none() {
        // Try well-known relative filenames next to config or working directory
        let candidates = [
            "anchors_snapshot.zst",
            "anchors_snapshot.bin",
        ];
        for cand in candidates.iter() {
            if std::path::Path::new(cand).exists() {
                match db.import_anchors_snapshot(cand) {
                    Ok(n) if n > 0 => {
                        println!("📥 Imported {} anchors from '{}'", n, cand);
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("⚠️  Snapshot import from '{}' failed: {}", cand, e),
                }
            }
        }
    }

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let wallet = Arc::new(wallet::Wallet::load_or_create(db.clone())?);
    
    let sync_state = Arc::new(Mutex::new(sync::SyncState::default()));

    let net = network::spawn(cfg.net.clone(), cfg.p2p.clone(), cfg.offers.clone(), db.clone(), sync_state.clone()).await?;
    // Kick off headers-first skeleton sync in the background (additive protocol, safe if peers don't support it)
    {
        let db_h = db.clone();
        let net_h = net.clone();
        let shutdown_rx_h = shutdown_tx.subscribe();
        tokio::spawn(async move {
            crate::sync::spawn_headers_skeleton(db_h, net_h, shutdown_rx_h).await;
        });
    }

    // Background: subscribe to spends and anchors to trigger deterministic rescans for this wallet
    {
        let net_clone = net.clone();
        let wallet_clone = wallet.clone();
        let db_clone = db.clone();
        tokio::spawn(async move {
            let mut spend_rx = net_clone.spend_subscribe();
            let mut anchor_rx = net_clone.anchor_subscribe();
            loop {
                tokio::select! {
                    Ok(sp) = spend_rx.recv() => {
                        let _ = wallet_clone.scan_spend_for_me(&sp);
                    },
                    Ok(_a) = anchor_rx.recv() => {
                        // On anchor adoption, rescan all spends idempotently (bounded by CF contents)
                        if let Some(cf) = db_clone.db.cf_handle("spend") {
                            let iter = db_clone.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
                            for item in iter {
                                if let Ok((_k, v)) = item {
                                    if let Some(sp) = db_clone.decode_spend_bytes_tolerant(&v) {
                                        let _ = wallet_clone.scan_spend_for_me(&sp);
                                    }
                                }
                            }
                        }
                        // FIXED: Process any pending spend scans that were waiting for coins
                        let _ = wallet_clone.process_pending_spend_scans();
                    }
                }
            }
        });
    }

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
                cfg.net.clone(),
                net.clone(),
                coin_rx,
                shutdown_tx.subscribe(),
                sync_state.clone(),
                cfg.compact.clone(),
            );
            epoch_mgr.spawn_loop();

            // --- Active Synchronization Before Mining ---
            println!("🔄 Initiating synchronization with the network...");
            net.request_latest_epoch().await;

            let mut anchor_rx = net.anchor_subscribe();
            let poll_interval_ms: u64 = 500;
            let max_attempts: u64 = ((cfg.net.sync_timeout_secs.saturating_mul(1000)) / poll_interval_ms).max(1);
            let mut synced = false;
            let mut attempt: u64 = 0;
            let mut last_local_displayed: u64 = u64::MAX; // force initial print once we have network view
            while attempt < max_attempts {
                let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                let peer_confirmed = sync_state.lock().map(|s| s.peer_confirmed_tip).unwrap_or(false);
                let latest_opt = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None);
                let local_epoch = latest_opt.as_ref().map_or(0, |a| a.num);

                // When bootstrap peers are configured, require a peer-confirmed tip before declaring sync
                if highest_seen > 0 && local_epoch >= highest_seen && (cfg.net.bootstrap.is_empty() || peer_confirmed) {
                    println!("✅ Synchronization complete. Local epoch is {}.", local_epoch);
                    if let Ok(mut st) = sync_state.lock() { st.synced = true; }
                    synced = true;
                    break;
                }
                if highest_seen == 0 && latest_opt.is_some() && cfg.net.bootstrap.is_empty() {
                    println!("✅ No peers responded; proceeding with local chain at epoch {}.", local_epoch);
                    if let Ok(mut st) = sync_state.lock() {
                        st.synced = true;
                        if st.highest_seen_epoch == 0 { st.highest_seen_epoch = local_epoch; }
                    }
                    synced = true;
                    break;
                }
                if highest_seen > 0 {
                    if last_local_displayed != local_epoch || attempt == 0 {
                        if cfg.net.bootstrap.is_empty() {
                            println!("⏳ Syncing... local epoch: {}, network epoch: {}", local_epoch, highest_seen);
                        } else {
                            println!("⏳ Syncing... local {}, network {}, peer-confirmed: {}", local_epoch, highest_seen, peer_confirmed);
                        }
                        last_local_displayed = local_epoch;
                    }
                } else {
                    println!("⏳ Waiting for network response... (attempt {})", attempt + 1);
                }

                tokio::select! {
                    Ok(_a) = anchor_rx.recv() => { continue; }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => { attempt += 1; }
                }
            }
            if !synced {
                println!(
                    "⚠️  Could not sync with network after {}s.",
                    cfg.net.sync_timeout_secs
                );
                // Only allow starting as a new chain when there are no bootstrap peers and no network view
                let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                if cfg.net.bootstrap.is_empty() && highest_seen == 0 {
                    if let Ok(Some(latest)) = db.get::<epoch::Anchor>("epoch", b"latest") {
                        if let Ok(mut st) = sync_state.lock() {
                            st.synced = true;
                            if st.highest_seen_epoch == 0 { st.highest_seen_epoch = latest.num; }
                        }
                        println!("✅ Proceeding with local chain at epoch {}.", latest.num);
                    }
                } else {
                    println!("⛔ Sync not achieved; mining remains disabled until local >= network tip.");
                }
            }

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
        Some(Cmd::Send { paycode, amount, note }) => {
            let net = net.clone();
            let (stealth, amount, _batch_token) = if true {
                // New non-interactive path handled below. Keep interactive flow for now but deprecated.
                (paycode.trim().to_string(), *amount, String::new())
            } else {
                // Fallback to interactive flow
                // Enable quiet network logging for interactive send
                network::set_quiet_logging(true);
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                println!("\n\n\n");
                println!("{}", "=".repeat(60));
                println!("💰 Guided Send (interactive)");
                println!("{}", "=".repeat(60));
                println!("This walkthrough has 3 short steps:");
                println!("  1) Paste the receiver code (stealth address or a batch token)");
                println!("  2) Enter the amount to send");
                println!("  3) Build and broadcast the spend(s) — commitments are fetched automatically");
                println!();
                println!("⏸️  Pausing network activity for clean input...");
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                // Prompt for stealth address (reuse existing interactive UI)
                println!("STEP 1/3 — Receiver code");
                println!("📤 Paste the receiver code and press Enter.");
                println!("   The receiver code can be either: \n   • a stealth address (base64‑url), or\n   • a batch token (base64‑url) they generated for this payment.");
                println!("   Tips:\n   • Paste in chunks if needed.\n   • Or type 'file:/path/to/code.txt' to load from file\n   • Or type 'test' to use 'test_stealth_address.txt'.");
                print!("   Address: ");
                io::stdout().flush()?;
                let mut stealth = String::new();
                let mut chunk_count = 0;
                loop {
                    chunk_count += 1;
                    print!("   Address chunk {} (leave empty to finish): ", chunk_count);
                    io::stdout().flush()?;
                    let mut chunk = String::new();
                    io::stdin().read_line(&mut chunk)?;
                    let chunk = chunk.trim();
                    if chunk.is_empty() {
                        if chunk_count == 1 { eprintln!("   ❌ Address cannot be empty"); return Ok(()); }
                        break;
                    }
                    stealth.push_str(chunk);
                    if chunk.ends_with("==") || chunk.ends_with("=") || chunk.len() < 100 {
                        print!("   ✅ Address appears complete. Press Enter to continue, or type 'more' to add more: ");
                        io::stdout().flush()?;
                        let mut c = String::new();
                        io::stdin().read_line(&mut c)?;
                        if c.trim() != "more" { break; }
                    }
                    println!("   📝 Added chunk {} ({} chars total)", chunk_count, stealth.len());
                }
                let stealth = stealth.trim().trim_matches('"').trim_matches('\'').trim_matches('`').to_string();
                let stealth = if stealth == "test" {
                    std::fs::read_to_string("test_stealth_address.txt").map(|s| s.trim().to_string()).unwrap_or_default()
                } else if stealth.starts_with("file:") {
                    let filename = stealth[5..].trim().trim_matches('"').trim_matches('\'').trim_matches('`').to_string();
                    std::fs::read_to_string(&filename).map(|s| s.trim().to_string()).unwrap_or_default()
                } else { stealth };
                if stealth.is_empty() { eprintln!("❌ Stealth address cannot be empty"); return Ok(()); }
                if !stealth.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=') {
                    eprintln!("❌ Invalid code format. Expected base64-url safe characters only.");
                    return Ok(());
                }
                println!("   ✅ Code accepted ({} characters)", stealth.len());
                println!();
                println!("STEP 2/3 — Amount");
                print!("💰 Enter amount to send: "); io::stdout().flush()?;
                let mut amount_str = String::new(); io::stdin().read_line(&mut amount_str)?;
                let amount: u64 = amount_str.trim().parse().map_err(|_| anyhow::anyhow!("invalid amount"))?;
                if amount == 0 { eprintln!("❌ Amount must be greater than 0"); return Ok(()); }
                // Build or request batch token interactively
                let mut token = String::new();
                {
                    println!("\nAuto‑obtaining receiver commitments (if needed)");
                    println!("   If your receiver code was a batch token, we will use it directly.\n   Otherwise, we'll request commitments over P2P for up to 12 seconds, with an offline QR fallback.");
                    let _coins = wallet.select_inputs(amount)?;
                    // commitment request/response flow removed
                    use rand::RngCore as _;
                    let mut rng_tag = [0u8;32]; rand::rngs::OsRng.fill_bytes(&mut rng_tag);
                    // Try interpret the code as a batch token first
                    let recipient_addr_opt: Option<crate::crypto::Address> = None;
                    if base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(stealth.as_str()).is_ok() || base64::engine::general_purpose::URL_SAFE.decode(stealth.as_str()).is_ok() {
                        let parsed_token = stealth.clone();
                        if let Ok(_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(parsed_token.as_str())
                            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(parsed_token.as_str())) {
                            // legacy batch token removed
                        }
                    }
                    let _recipient_addr = if let Some(a) = recipient_addr_opt { a } else {
                        let (a, _k) = wallet::Wallet::parse_stealth_address(&stealth)?; a
                    };
                    let used_network = false;
                    if net.peer_count() > 0 {
                        println!("   ⏳ Requesting commitments from peers (12s timeout)...");
                        // removed
                    }
                    if !used_network {
                        let req_b64 = "<commitment flow removed>".to_string();
                        println!("   📱 No P2P response yet — using offline exchange.");
                        println!("   Show this QR to the receiver so they can generate a batch token:");
                        if let Err(e) = print_qr_to_terminal(&req_b64) { eprintln!("(QR unavailable: {})", e); }
                        match copy_to_clipboard(&req_b64) { Ok(()) => println!("   📋 Copied request to clipboard"), Err(_) => eprintln!("   (clipboard unavailable)") }
                        println!("\n   Or share this code if QR is not convenient:\n   {}\n", req_b64);
                        print!("🔒 Paste the receiver's batch token here and press Enter: "); io::stdout().flush()?;
                        let mut tok = String::new(); io::stdin().read_line(&mut tok)?; token = tok.trim().to_string();
                    }
                }
                (stealth, amount, token)
            };

            // Non-interactive send execution (or interactive result)
            println!("\nSTEP 4/4 — Build and broadcast");
            println!("   Preparing spends and submitting to the network...");
            // Execute new send using paycode and OOB note
            use rand::RngCore;
            let s_bytes: Vec<u8> = if let Some(n) = note {
                let t = n.trim();
                if let Ok(b) = hex::decode(t.trim_start_matches("0x")) { b } else if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t) { b } else { anyhow::bail!("Invalid note encoding; use hex or base64-url") }
            } else {
                let mut s = [0u8;32]; rand::rngs::OsRng.fill_bytes(&mut s);
                println!("🔑 Generated random spend note s: {}", hex::encode(s));
                s.to_vec()
            };
            let outcome: anyhow::Result<wallet::SendOutcome> = wallet.send_with_paycode_and_note(&stealth, amount, &net, &s_bytes).await;
            match outcome {
                Ok(outcome) => {
                    let total = outcome.spends.len();
                    println!("✅ Done. Built and broadcast {} spend{}", total, if total == 1 { "" } else { "s" });
                    for (i, s) in outcome.spends.iter().enumerate() {
                        println!("   • Spend {}: coin {} → commitment {}", i + 1, hex::encode(s.coin_id), hex::encode(s.commitment));
                    }
                    println!("\nYou can watch for confirmations in the logs or with 'unchained history'.");
                }
                Err(e) => {
                    eprintln!("❌ Send failed: {}", e);
                    return Err(e);
                }
            }
            return Ok(());
        }
        Some(Cmd::HtlcPlan { paycode, amount, timeout, out }) => {
            let plan = wallet.plan_htlc_offer(*amount, paycode, *timeout)?;
            let json = serde_json::to_string_pretty(&plan)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote HTLC plan to {} (timeout epoch {})", out, timeout);
            return Ok(());
        }
        Some(Cmd::HtlcClaimPrepare { claim_secret, coins, out }) => {
            let claim_bytes = {
                let s = claim_secret.trim();
                if let Ok(b) = hex::decode(s.trim_start_matches("0x")) { b } else { base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)? }
            };
            if claim_bytes.is_empty() { return Err(anyhow::anyhow!("claim_secret empty")); }
            let mut entries = Vec::new();
            for hex_id in coins.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let id_vec = hex::decode(hex_id).map_err(|e| anyhow::anyhow!("Invalid coin id {}: {}", hex_id, e))?;
                if id_vec.len() != 32 { return Err(anyhow::anyhow!("coin id {} must be 32 bytes", hex_id)); }
                let mut coin_id = [0u8;32]; coin_id.copy_from_slice(&id_vec);
                let chain_id = db.get_chain_id()?;
                let ch = crypto::commitment_hash_from_preimage(&chain_id, &coin_id, &claim_bytes);
                entries.push(crate::wallet::HtlcClaimsDocEntry { coin_id, ch_claim: ch });
            }
            let doc = crate::wallet::HtlcClaimsDoc { claims: entries };
            let json = serde_json::to_string_pretty(&doc)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote HTLC claim CHs to {}", out);
            return Ok(());
        }
        Some(Cmd::HtlcOfferExecute { plan, claims, refund_base, refund_secrets_out }) => {
            let plan_doc: crate::wallet::HtlcPlanDoc = serde_json::from_slice(&std::fs::read(plan)?)?;
            let claims_doc: crate::wallet::HtlcClaimsDoc = serde_json::from_slice(&std::fs::read(claims)?)?;
            if refund_base.is_none() && refund_secrets_out.is_none() {
                return Err(anyhow::anyhow!("Provide either --refund_base (deterministic) or --refund_secrets_out to persist generated secrets"));
            }
            let refund_base_bytes: Option<Vec<u8>> = if let Some(b) = refund_base {
                let t = b.trim();
                if let Ok(h) = hex::decode(t.trim_start_matches("0x")) { Some(h) } else { Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t)?) }
            } else { None };
            let outcome = wallet.execute_htlc_offer(&plan_doc, &claims_doc, &net, refund_base_bytes.as_deref(), refund_secrets_out.as_deref(), None).await?;
            println!("✅ Built and broadcast {} HTLC offer spend(s)", outcome.spends.len());
            return Ok(());
        }
        Some(Cmd::HtlcRefundPrepare { plan, refund_base, out, out_secrets }) => {
            let plan_doc: crate::wallet::HtlcPlanDoc = serde_json::from_slice(&std::fs::read(plan)?)?;
            let chain_id = plan_doc.chain_id;
            let mut refunds = Vec::new();
            let mut secrets_dump: Vec<(String,String)> = Vec::new();
            use rand::RngCore;
            for c in &plan_doc.coins {
                let secret: [u8;32] = if let Some(b) = refund_base {
                    let base_bytes = if let Ok(h) = hex::decode(b.trim().trim_start_matches("0x")) { h } else { base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b.trim())? };
                    let mut h = blake3::Hasher::new_derive_key("unchained.htlc.refund.base");
                    h.update(&base_bytes); h.update(&c.coin_id);
                    let mut out = [0u8;32]; h.finalize_xof().fill(&mut out); out
                } else {
                    let mut s = [0u8;32]; rand::rngs::OsRng.fill_bytes(&mut s);
                    secrets_dump.push((hex::encode(c.coin_id), hex::encode(s)));
                    s
                };
                let ch = crypto::commitment_hash_from_preimage(&chain_id, &c.coin_id, &secret);
                refunds.push(crate::wallet::HtlcRefundsDocEntry { coin_id: c.coin_id, ch_refund: ch });
            }
            let doc = crate::wallet::HtlcRefundsDoc { refunds };
            std::fs::write(out, serde_json::to_string_pretty(&doc)?)?;
            if refund_base.is_none() {
                if let Some(path) = out_secrets {
                    let json = serde_json::to_string_pretty(&secrets_dump)?;
                    std::fs::write(path, json)?;
                    println!("✅ Wrote per-coin refund secrets (keep safe)");
                }
            }
            println!("✅ Wrote HTLC refund CHs to {}", out);
            return Ok(());
        }
        Some(Cmd::HtlcClaim { timeout, claim_secret, refunds, paycode }) => {
            // Guard: Claim only valid when current_epoch < T
            let current_epoch = db.get::<epoch::Anchor>("epoch", b"latest")?.map(|a| a.num).unwrap_or(0);
            if current_epoch >= *timeout {
                return Err(anyhow::anyhow!(
                    "Claim path not valid: current_epoch={} ≥ T={}. Use htlc-refund instead.",
                    current_epoch, timeout
                ));
            }
            let refunds_doc: crate::wallet::HtlcRefundsDoc = serde_json::from_slice(&std::fs::read(refunds)?)?;
            let mut map = std::collections::HashMap::new();
            for e in refunds_doc.refunds { map.insert(e.coin_id, e.ch_refund); }
            let s_bytes = {
                let s = claim_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) { h } else { base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)? }
            };
            let outcome = wallet.htlc_claim(*timeout, &s_bytes, &map, paycode, &net, None).await?;
            println!("✅ Built and broadcast {} HTLC claim spend(s)", outcome.spends.len());
            return Ok(());
        }
        Some(Cmd::HtlcRefund { timeout, refund_secret, claims, paycode }) => {
            // Guard: Refund only valid when current_epoch ≥ T
            let current_epoch = db.get::<epoch::Anchor>("epoch", b"latest")?.map(|a| a.num).unwrap_or(0);
            if current_epoch < *timeout {
                return Err(anyhow::anyhow!(
                    "Refund path not valid: current_epoch={} < T={}. Use htlc-claim instead.",
                    current_epoch, timeout
                ));
            }
            let claims_doc: crate::wallet::HtlcClaimsDoc = serde_json::from_slice(&std::fs::read(claims)?)?;
            let mut map = std::collections::HashMap::new();
            for e in claims_doc.claims { map.insert(e.coin_id, e.ch_claim); }
            let s_bytes = {
                let s = refund_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) { h } else { base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)? }
            };
            let outcome = wallet.htlc_refund(*timeout, &s_bytes, &map, paycode, &net, None).await?;
            println!("✅ Built and broadcast {} HTLC refund spend(s)", outcome.spends.len());
            return Ok(());
        }
        Some(Cmd::OfferCreate { paycode, amount, timeout, price_bps, note, out }) => {
            let plan = wallet.plan_htlc_offer(*amount, paycode, *timeout)?;
            let offer = wallet.create_offer_doc(plan, *price_bps, note.clone())?;
            let json = serde_json::to_string_pretty(&offer)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote signed offer to {}", out);
            return Ok(());
        }
        Some(Cmd::OfferVerify { input }) => {
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            println!("✅ Offer signature and maker address verified");
            return Ok(());
        }
        Some(Cmd::OfferAccept { input, claim_secret, refund_base, refund_secrets_out }) => {
            // 1) Verify offer
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            // 2) Build receiver claim doc deterministically from provided claim_secret
            let s_bytes = {
                let s = claim_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) { h } else { base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)? }
            };
            if s_bytes.len() != 32 { return Err(anyhow::anyhow!("claim_secret must be 32 bytes")); }
            let mut claims = Vec::new();
            for c in &offer.plan.coins {
                let ch = crypto::commitment_hash_from_preimage(&offer.plan.chain_id, &c.coin_id, &s_bytes);
                claims.push(crate::wallet::HtlcClaimsDocEntry { coin_id: c.coin_id, ch_claim: ch });
            }
            let claims_doc = crate::wallet::HtlcClaimsDoc { claims };
            // 3) Execute HTLC offer spends via wallet; never print secrets, only file output if requested
            if refund_base.is_none() && refund_secrets_out.is_none() {
                return Err(anyhow::anyhow!("Provide either --refund_base (deterministic) or --refund_secrets_out to persist generated secrets"));
            }
            let refund_base_bytes: Option<Vec<u8>> = if let Some(b) = refund_base {
                let t = b.trim();
                if let Ok(h) = hex::decode(t.trim_start_matches("0x")) { Some(h) } else { Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t)?) }
            } else { None };
            let outcome = wallet.execute_htlc_offer(&offer.plan, &claims_doc, &net, refund_base_bytes.as_deref(), refund_secrets_out.as_deref(), None).await?;
            println!("✅ Accepted offer. Built and broadcast {} spend(s)", outcome.spends.len());
            return Ok(());
        }
        Some(Cmd::OfferPublish { input }) => {
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            // Publish via network
            // Use binary bincode payload to match network path
            // Reuse GossipOffer command
            net.gossip_offer(&offer).await;
            println!("📢 Published offer to network");
            return Ok(());
        }
        Some(Cmd::OfferWatch { count, min_amount, maker, since: _ }) => {
            // Local subscribe; apply filters; since is not used in local mode
            let mut rx = net.offers_subscribe();
            let mut remaining = *count;
            loop {
                tokio::select! {
                    Ok(ofr) = rx.recv() => {
                        if let Some(min) = *min_amount { if ofr.plan.amount < min { continue; } }
                        if let Some(m) = maker.clone() {
                            let want = m.trim_start_matches("0x");
                            if hex::encode(ofr.maker_address) != want { continue; }
                        }
                        let json = serde_json::to_string(&ofr)?;
                        println!("{}", json);
                        if let Some(left) = remaining.as_mut() {
                            if *left > 0 { *left -= 1; }
                            if *left == 0 { break; }
                        }
                    }
                }
            }
            return Ok(());
        }
        Some(Cmd::OfferAcceptPrepare { input, claim_secret, out }) => {
            // Verify offer and emit receiver-side claim CHs for coins listed in maker plan
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            let s_bytes = {
                let s = claim_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) { h } else { base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)? }
            };
            if s_bytes.len() != 32 { return Err(anyhow::anyhow!("claim_secret must be 32 bytes")); }
            let mut entries = Vec::new();
            for c in &offer.plan.coins {
                let ch = crypto::commitment_hash_from_preimage(&offer.plan.chain_id, &c.coin_id, &s_bytes);
                entries.push(crate::wallet::HtlcClaimsDocEntry { coin_id: c.coin_id, ch_claim: ch });
            }
            let doc = crate::wallet::HtlcClaimsDoc { claims: entries };
            let json = serde_json::to_string_pretty(&doc)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote claim CHs for {} coins", doc.claims.len());
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
        Some(Cmd::X402Pay { url, auto_resubmit }) => {
            // Fetch challenge
            let client = reqwest::Client::new();
            let resp = client.get(url).send().await?;
            if resp.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
                eprintln!("Expected 402, got {}", resp.status());
                return Err(anyhow::anyhow!("not a 402"));
            }
            let challenge_json = resp.text().await?;
            // Pay using wallet and produce header
            let header = wallet.x402_pay_from_challenge(&challenge_json, &net).await?;
            println!("X-PAYMENT: {}", header);
            if *auto_resubmit {
                let resp2 = client.get(url).header(crate::x402::HEADER_X_PAYMENT, header).send().await?;
                if !resp2.status().is_success() {
                    eprintln!("Resubmit failed: {}", resp2.status());
                    return Err(anyhow::anyhow!("resubmit failed"));
                }
                let body = resp2.text().await.unwrap_or_default();
                println!("{}", body);
            }
            return Ok(());
        }
        Some(Cmd::RepairSpends) => {
            println!("🛠️  Scanning 'spend' CF for malformed entries...");
            let cf = db.db.cf_handle("spend").ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let backup_dir = format!("{}/backups_spend_repair/{}", cfg.storage.path, chrono::Utc::now().format("%Y%m%d_%H%M%S"));
            std::fs::create_dir_all(&backup_dir).ok();
            let mut batch = rocksdb::WriteBatch::default();
            let mut scanned: u64 = 0;
            let mut repaired: u64 = 0;
            for item in iter {
                if let Ok((k, v)) = item {
                    scanned += 1;
                    let valid = zstd::decode_all(&v[..])
                        .ok()
                        .and_then(|d| bincode::deserialize::<crate::transfer::Spend>(&d).ok())
                        .or_else(|| bincode::deserialize::<crate::transfer::Spend>(&v[..]).ok())
                        .is_some();
                    if !valid {
                        let key_hex = hex::encode(&k);
                        let mut path = std::path::PathBuf::from(&backup_dir);
                        path.push(format!("spend-{}.bin", key_hex));
                        let _ = std::fs::write(&path, &v);
                        batch.delete_cf(cf, &k);
                        repaired += 1;
                        println!("   - Deleted malformed spend key={} (backed up)", key_hex);
                    }
                }
            }
            if repaired > 0 {
                db.write_batch(batch)?;
            }
            println!("✅ Repair complete. Scanned: {}, deleted malformed: {}. Backup dir: {}", scanned, repaired, backup_dir);
            return Ok(());
        }
        Some(Cmd::ExportAnchors { out }) => {
            let written = db.export_anchors_snapshot(out)?;
            println!("✅ Exported {} anchors to {}", written, out);
            return Ok(());
        }
        Some(Cmd::ImportAnchors { input }) => {
            let added = db.import_anchors_snapshot(input)?;
            println!("✅ Imported {} anchors from {}", added, input);
            return Ok(());
        }
        Some(Cmd::BridgeOut { sui_recipient, amount, prewarm_secs }) => {
            // Optional: pre-warm proofs for inputs that will cover the amount
            if *prewarm_secs > 0 {
                match wallet.select_inputs(*amount) {
                    Ok(coins) => {
                        let mut rx = net.proof_subscribe();
                        for c in coins.iter() {
                            net.request_coin_proof(c.id).await;
                        }
                        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(*prewarm_secs);
                        loop {
                            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                            if remaining.is_zero() { break; }
                            if let Ok(Ok(resp)) = tokio::time::timeout(remaining, rx.recv()).await {
                                // Stop early if we have observed at least one proof for our set
                                if coins.iter().any(|c| c.id == resp.coin.id) {
                                    // best-effort: a single hit means peers are responsive
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  Could not pre-warm proofs: {}", e);
                    }
                }
            }
            // Submit directly via in-process bridge service to avoid HTTP dependency
            match bridge::submit_bridge_out_direct(
                cfg.bridge.clone(),
                db.clone(),
                wallet.clone(),
                net.clone(),
                *amount,
                sui_recipient.clone(),
            ).await {
                Ok(bridge::BridgeOutResult::Locked { tx_hash }) => {
                    println!("✅ Locked. tx_hash={}", tx_hash);
                }
                Ok(bridge::BridgeOutResult::Pending { op_id }) => {
                    println!("⏳ Submitted pending op. op_id={}", op_id);
                }
                Err(e) => {
                    eprintln!("❌ bridge_out failed: {}", e);
                }
            }
        }
        Some(Cmd::MetaAuthzCreate { to, amount, valid_after, valid_before, facilitator_kyber_b64, binding_b64, out }) => {
            // Parse facilitator Kyber PK
            let fac_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(facilitator_kyber_b64.trim())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(facilitator_kyber_b64.trim()))
                .map_err(|_| anyhow::anyhow!("invalid base64 for facilitator kyber pk"))?;
            let fac_pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&fac_bytes)
                .map_err(|_| anyhow::anyhow!("invalid facilitator kyber pk bytes"))?;
            // Optional binding
            let binding_opt: Option<[u8;32]> = if let Some(b) = binding_b64 {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(b.trim())
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b.trim()))
                    .map_err(|_| anyhow::anyhow!("invalid base64 for binding"))?;
                if raw.len() != 32 { return Err(anyhow::anyhow!("binding must be 32 bytes")); }
                let mut arr = [0u8;32]; arr.copy_from_slice(&raw); Some(arr)
            } else { None };
            let authz = wallet.authorize_meta_transfer(to, *amount, *valid_after, *valid_before, &fac_pk, binding_opt)?;
            let json = serde_json::to_string_pretty(&authz)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote meta authorization JSON");
            return Ok(());
        }
        // commitment commands removed
        Some(Cmd::MsgSend { text }) => {
            let message = if let Some(t) = text { t.clone() } else {
                print!("📝 Enter message to send (max a few KB): "); io::stdout().flush()?;
                let mut line = String::new(); io::stdin().read_line(&mut line)?; line.trim().to_string()
            };
            if message.is_empty() { println!("Nothing to send."); return Ok(()); }
            let msg = RateLimitedMessage { content: message };
            net.gossip_rate_limited(msg).await;
            println!("📤 Message submitted to P2P topic (subject to 2 msgs/24h outbound limit)");
            return Ok(());
        }
        Some(Cmd::MsgListen { once, count }) => {
            println!("👂 Listening for P2P messages (24h-limited topic). Press Ctrl+C to exit.");
            let mut rx = net.rate_limited_subscribe();
            let mut remaining = count.unwrap_or(u64::MAX);
            loop {
                tokio::select! {
                    Ok(m) = rx.recv() => {
                        println!("💬 {}", m.content);
                        if *once { break; }
                        if remaining != u64::MAX {
                            if remaining == 0 { break; }
                            remaining -= 1;
                            if remaining == 0 { break; }
                        }
                    }
                    else => { tokio::time::sleep(std::time::Duration::from_millis(50)).await; }
                }
            }
            return Ok(());
        }
        Some(Cmd::ReplaySpends) => {
            let cf = db.db.cf_handle("spend").ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let mut replayed = 0u64;
            for item in iter {
                let (_k, v) = item?;
                if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&v) {
                    net.gossip_spend(&sp).await;
                    replayed += 1;
                }
            }
            println!("✅ Re-gossiped {} spends", replayed);
            return Ok(());
        }
        Some(Cmd::RescanWallet) => {
            let cf = db.db.cf_handle("spend").ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let mut scanned = 0u64;
            for item in iter {
                let (_k, v) = item?;
                if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&v) {
                    let _ = wallet.scan_spend_for_me(&sp);
                    scanned += 1;
                }
            }
            println!("✅ Rescanned {} spends for this wallet", scanned);
            return Ok(());
        }
        // commitment request removed
        None => {
            // No command specified, start mining if enabled
            if cfg.mining.enabled {
                // Start epoch manager only when mining
                let epoch_mgr = epoch::Manager::new(
                    db.clone(),
                    cfg.epoch.clone(),
                    cfg.net.clone(),
                    net.clone(),
                    coin_rx,
                    shutdown_tx.subscribe(),
                    sync_state.clone(),
                    cfg.compact.clone(),
                );
                epoch_mgr.spawn_loop();

                // --- Active Synchronization Before Mining ---
                println!("🔄 Initiating synchronization with the network...");
                net.request_latest_epoch().await;

                let mut anchor_rx = net.anchor_subscribe();
                let poll_interval_ms: u64 = 500;
                let max_attempts: u64 = ((cfg.net.sync_timeout_secs.saturating_mul(1000)) / poll_interval_ms).max(1);
                let mut synced = false;
                let mut attempt: u64 = 0;
                let mut last_local_displayed: u64 = u64::MAX;
                while attempt < max_attempts {
                    let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                    let peer_confirmed = sync_state.lock().map(|s| s.peer_confirmed_tip).unwrap_or(false);
                    let latest_opt = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None);
                    let local_epoch = latest_opt.as_ref().map_or(0, |a| a.num);

                    if highest_seen > 0 && local_epoch >= highest_seen && (cfg.net.bootstrap.is_empty() || peer_confirmed) {
                        println!("✅ Synchronization complete. Local epoch is {}.", local_epoch);
                        if let Ok(mut st) = sync_state.lock() { st.synced = true; }
                        synced = true;
                        break;
                    }
                    if highest_seen == 0 && latest_opt.is_some() && cfg.net.bootstrap.is_empty() {
                        println!("✅ No peers responded; proceeding with local chain at epoch {}.", local_epoch);
                        if let Ok(mut st) = sync_state.lock() {
                            st.synced = true;
                            if st.highest_seen_epoch == 0 { st.highest_seen_epoch = local_epoch; }
                        }
                        synced = true;
                        break;
                    }

                    if highest_seen > 0 {
                        if last_local_displayed != local_epoch || attempt == 0 {
                            if cfg.net.bootstrap.is_empty() {
                                println!("⏳ Syncing... local epoch: {}, network epoch: {}", local_epoch, highest_seen);
                            } else {
                                println!("⏳ Syncing... local {}, network {}, peer-confirmed: {}", local_epoch, highest_seen, peer_confirmed);
                            }
                            last_local_displayed = local_epoch;
                        }
                    } else {
                        println!("⏳ Waiting for network response... (attempt {})", attempt + 1);
                    }

                    tokio::select! {
                        Ok(_a) = anchor_rx.recv() => { continue; }
                        _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => { attempt += 1; }
                    }
                }
                if !synced {
                    println!(
                        "⚠️  Could not sync with network after {}s.",
                        cfg.net.sync_timeout_secs
                    );
                    let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                    if cfg.net.bootstrap.is_empty() && highest_seen == 0 {
                        if let Ok(Some(latest)) = db.get::<epoch::Anchor>("epoch", b"latest") {
                            if let Ok(mut st) = sync_state.lock() {
                                st.synced = true;
                                if st.highest_seen_epoch == 0 { st.highest_seen_epoch = latest.num; }
                            }
                            println!("✅ Proceeding with local chain at epoch {}.", latest.num);
                        }
                    } else {
                        println!("⛔ Sync not achieved; mining remains disabled until local >= network tip.");
                    }
                }

                miner::spawn(cfg.mining.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx, shutdown_tx.subscribe(), sync_state.clone());
            }
        }
    }

    let _metrics_bind = cfg.metrics.bind.clone();
    metrics::serve(cfg.metrics)?;
    // Start offers HTTP API (SSE + GET)
    {
        let offers_cfg = cfg.offers.clone();
        let db_h = db.clone();
        let net_h = net.clone();
        tokio::spawn(async move {
            let _ = offers::serve(offers_cfg, db_h, net_h).await;
        });
    }
    // Start bridge RPC (lightweight JSON server)
    {
        let bridge_cfg = cfg.bridge.clone();
        let db_h = db.clone();
        let wallet_h = wallet.clone();
        let net_h = net.clone();
        tokio::spawn(async move {
            let _ = bridge::serve(bridge_cfg, db_h, wallet_h, net_h).await;
        });
    }

    println!("\n🚀 unchained node is running!");
    println!("   📡 unchained listening on port {}", cfg.net.listen_port);
    if let Some(public_ip) = cfg.net.public_ip {
        println!("   📢 Public IP announced as: {public_ip}");
    }
    println!("   📊 Epoch length: 222 seconds");
    println!("   ⛏️  Mining: {}", if matches!(cli.cmd, Some(Cmd::Mine)) || cfg.mining.enabled { "enabled" } else { "disabled" });
    println!("   🎯 Epoch coin cap: {}", cfg.epoch.max_coins_per_epoch);
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
