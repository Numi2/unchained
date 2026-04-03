use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, Subcommand};
use qrcode::render::unicode;
use qrcode::QrCode;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::time::Duration;

use crate::{
    canonical, config, epoch, metrics, miner, network, node_control, node_identity, protocol,
    storage, sync, wallet, wallet_control,
};
use crate::{
    network::NetHandle,
    storage::{Store, WalletStore},
    sync::SyncState,
};

#[derive(Args, Clone)]
struct CommonArgs {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Suppress routine network gossip logs
    #[arg(long, default_value_t = false)]
    quiet_net: bool,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Unchained node runtime",
    long_about = "Run the Unchained network node, bootstrap identity, manage network-facing maintenance tasks, own canonical chain state, and host the local node control plane for wallet and miner clients.",
    after_help = "Examples:\n  unchained_node init-root\n  unchained_node auth-prepare --out auth_request.txt\n  unchained_node auth-sign --request auth_request.txt --out node_record.txt\n  unchained_node auth-install --record node_record.txt\n  unchained_node start\n"
)]
struct NodeCli {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    cmd: NodeCmd,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Unchained wallet runtime",
    long_about = "Operate the Unchained shielded wallet service, mint single-use receive handles, send shielded transactions, and inspect wallet state through the capability-authenticated wallet control plane. Start `unchained_node start`, then `unchained_wallet serve`, and use the remaining wallet commands as clients of that running wallet service.",
    after_help = "Examples:\n  unchained_node start\n  unchained_wallet serve\n  unchained_wallet receive\n  unchained_wallet send --to <KEYDOC_JSON> --amount 100\n  unchained_wallet balance\n  unchained_wallet history\n"
)]
struct WalletCli {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    cmd: WalletCmd,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Unchained miner runtime",
    long_about = "Run the Unchained dedicated miner and block-production runtime. Requires `unchained_node start` for mining work and `unchained_wallet serve` for local wallet secrets."
)]
struct MinerCli {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Create or load the offline node root and print its compact root-info document
    InitRoot {
        #[arg(long)]
        out: Option<String>,
    },
    /// Prepare a runtime auth key and signed auth request for offline approval
    AuthPrepare {
        #[arg(long)]
        root_info: Option<String>,
        #[arg(long)]
        out: Option<String>,
    },
    /// Approve an auth request with the offline node root and produce a signed node record
    AuthSign {
        #[arg(long)]
        request: String,
        #[arg(long, default_value_t = 30)]
        lifetime_days: u64,
        #[arg(long)]
        out: Option<String>,
    },
    /// Install a signed node record for runtime use
    AuthInstall {
        #[arg(long)]
        record: String,
    },
    /// Create a compact trust-update revocation document
    TrustRevoke {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        out: Option<String>,
    },
    /// Create a compact trust-update replacement document
    TrustReplace {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        replacement: String,
        #[arg(long)]
        out: Option<String>,
    },
    /// Approve a compact trust-update document with the offline node root
    TrustApprove {
        #[arg(long)]
        update: String,
        #[arg(long)]
        out: Option<String>,
    },
    /// Print the local node ID and signed bootstrap record
    PeerId,
    /// Start the node runtime
    Start,
    /// Re-gossip all transactions from local DB
    ReplayTransactions,
    /// Export all anchors into a compressed snapshot file
    ExportAnchors {
        #[arg(long)]
        out: String,
    },
    /// Import anchors from a compressed snapshot file
    ImportAnchors {
        #[arg(long)]
        input: String,
    },
}

#[derive(Args, Clone)]
struct ReceiveArgs {
    #[arg(long, default_value_t = false)]
    plain: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
    #[arg(long, default_value_t = false)]
    copy: bool,
}

#[derive(Args, Clone)]
struct SendArgs {
    #[arg(long = "to")]
    to: Option<String>,
    #[arg(long)]
    amount: Option<u64>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone, Default)]
struct BalanceArgs {
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone, Default)]
struct HistoryArgs {
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Host the local wallet control socket used by other runtimes
    Serve,
    /// Show your shareable receiving address
    #[command(alias = "address")]
    Receive(ReceiveArgs),
    /// Send coins to a receiver, or run a guided send flow
    Send(SendArgs),
    /// Show wallet balance and owned shielded notes
    Balance(BalanceArgs),
    /// Show wallet transaction history
    History(HistoryArgs),
    /// Rescan local transactions against this wallet
    Rescan,
}

struct NetworkRuntime {
    db: Arc<Store>,
    net: NetHandle,
    sync_state: Arc<Mutex<SyncState>>,
    coin_tx: tokio::sync::mpsc::UnboundedSender<[u8; 32]>,
    shutdown_tx: broadcast::Sender<()>,
}

fn print_qr_to_terminal(data: &str) -> Result<()> {
    let code = QrCode::new(data.as_bytes())?;
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .build();
    println!("{image}");
    Ok(())
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(text.to_string())?;
    Ok(())
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn load_receiver_code(input: &str) -> Result<String> {
    let cleaned = input
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .to_string();
    if let Some(path) = cleaned.strip_prefix("file:") {
        return Ok(std::fs::read_to_string(
            path.trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches('`'),
        )?
        .trim()
        .to_string());
    }
    Ok(cleaned)
}

fn short_hex(bytes: &[u8]) -> String {
    let full = hex::encode(bytes);
    if full.len() <= 16 {
        full
    } else {
        format!("{}..{}", &full[..8], &full[full.len() - 8..])
    }
}

fn short_text(value: &str) -> String {
    if value.len() <= 18 {
        value.to_string()
    } else {
        format!("{}..{}", &value[..10], &value[value.len() - 8..])
    }
}

fn load_config(path: &str) -> Result<config::Config> {
    config::load_resolved(path)
}

fn apply_quiet_logging(common: &CommonArgs, cfg: &config::Config) {
    if common.quiet_net {
        network::set_quiet_logging(true);
    } else if cfg.net.quiet_by_default {
        network::set_quiet_logging(true);
    }
}

fn open_store(cfg: &config::Config) -> Result<Arc<Store>> {
    match std::panic::catch_unwind(|| storage::open(&cfg.storage)) {
        Ok(db) => Ok(db),
        Err(_) => Err(anyhow!("failed to open database")),
    }
}

fn open_wallet_store(cfg: &config::Config) -> Result<Arc<WalletStore>> {
    match std::panic::catch_unwind(|| WalletStore::open(&cfg.storage.path)) {
        Ok(Ok(db)) => Ok(Arc::new(db)),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(anyhow!("failed to open wallet database")),
    }
}

fn open_node_control_client(cfg: &config::Config) -> Result<node_control::NodeControlClient> {
    let client = node_control::NodeControlClient::new(&cfg.storage.path);
    client.ping()?;
    Ok(client)
}

async fn open_wallet_control_client(
    cfg: &config::Config,
) -> Result<wallet_control::WalletControlClient> {
    let client = wallet_control::WalletControlClient::new(&cfg.storage.path);
    client.ping().await?;
    Ok(client)
}

fn published_identity_addresses(cfg: &config::Config) -> Vec<String> {
    vec![std::net::SocketAddr::new(
        cfg.net
            .public_ip
            .as_ref()
            .and_then(|raw| raw.parse::<std::net::IpAddr>().ok())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        cfg.net.listen_port,
    )
    .to_string()]
}

fn load_identity_chain_id(storage_path: &str) -> Result<Option<[u8; 32]>> {
    let db = storage::Store::open(storage_path)?;
    Ok(Some(db.effective_chain_id()))
}

fn write_compact_output(path: Option<&str>, value: &str) -> Result<()> {
    if let Some(path) = path {
        std::fs::write(path, format!("{value}\n"))?;
        println!("Wrote {path}");
        println!();
    }
    Ok(())
}

fn print_compact_document(
    label: &str,
    node_id: Option<&str>,
    value: &str,
    out: Option<&str>,
) -> Result<()> {
    write_compact_output(out, value)?;
    if let Some(node_id) = node_id {
        println!("Node ID");
        println!();
        println!("{node_id}");
        println!();
    }
    println!("{label}");
    println!();
    println!("{value}");
    Ok(())
}

fn parse_node_id_hex(value: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(value.trim())?;
    if raw.len() != 32 {
        bail!("node id must be exactly 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn print_peer_id_output(cfg: &config::Config) -> Result<()> {
    let db = storage::Store::open(&cfg.storage.path)?;
    let chain_id = Some(db.effective_chain_id());
    let addresses = published_identity_addresses(cfg);
    let (id, bootstrap_record) = node_identity::load_local_identity_output_in_dir(
        &cfg.storage.path,
        protocol::CURRENT.version,
        chain_id,
        addresses,
    )?;
    println!("Node ID");
    println!();
    println!("{id}");
    println!();
    println!("Bootstrap Record");
    println!();
    println!("{bootstrap_record}");
    Ok(())
}

fn handle_node_operator_command(cmd: &NodeCmd, cfg: &config::Config) -> Result<bool> {
    match cmd {
        NodeCmd::InitRoot { out } => {
            let (node_id, root_info) = node_identity::init_root_in_dir(&cfg.storage.path)?;
            print_compact_document("Root Info", Some(&node_id), &root_info, out.as_deref())?;
            Ok(true)
        }
        NodeCmd::AuthPrepare { root_info, out } => {
            let chain_id = load_identity_chain_id(&cfg.storage.path)?;
            let addresses = published_identity_addresses(cfg);
            let (node_id, request) = node_identity::prepare_auth_request_in_dir(
                &cfg.storage.path,
                protocol::CURRENT.version,
                chain_id,
                addresses,
                root_info.as_deref(),
            )?;
            print_compact_document("Auth Request", Some(&node_id), &request, out.as_deref())?;
            Ok(true)
        }
        NodeCmd::AuthSign {
            request,
            lifetime_days,
            out,
        } => {
            let (node_id, record) = node_identity::sign_auth_request_in_dir(
                &cfg.storage.path,
                request,
                *lifetime_days,
            )?;
            print_compact_document("Node Record", Some(&node_id), &record, out.as_deref())?;
            Ok(true)
        }
        NodeCmd::AuthInstall { record } => {
            let (node_id, installed_record) =
                node_identity::install_node_record_in_dir(&cfg.storage.path, record)?;
            print_compact_document(
                "Installed Node Record",
                Some(&node_id),
                &installed_record,
                None,
            )?;
            Ok(true)
        }
        NodeCmd::TrustRevoke { node_id, out } => {
            let update = node_identity::create_trust_update_revoke(parse_node_id_hex(node_id)?)?;
            print_compact_document("Trust Update", None, &update, out.as_deref())?;
            Ok(true)
        }
        NodeCmd::TrustReplace {
            node_id,
            replacement,
            out,
        } => {
            let update = node_identity::create_trust_update_replace(
                parse_node_id_hex(node_id)?,
                replacement,
            )?;
            print_compact_document("Trust Update", None, &update, out.as_deref())?;
            Ok(true)
        }
        NodeCmd::TrustApprove { update, out } => {
            let approved = node_identity::approve_trust_update_in_dir(&cfg.storage.path, update)?;
            print_compact_document("Approved Trust Update", None, &approved, out.as_deref())?;
            Ok(true)
        }
        NodeCmd::PeerId => {
            print_peer_id_output(cfg)?;
            Ok(true)
        }
        NodeCmd::Start
        | NodeCmd::ReplayTransactions
        | NodeCmd::ExportAnchors { .. }
        | NodeCmd::ImportAnchors { .. } => Ok(false),
    }
}

async fn start_network_runtime(cfg: &config::Config) -> Result<NetworkRuntime> {
    let db = open_store(cfg)?;
    let sync_state = Arc::new(Mutex::new(sync::SyncState::default()));
    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let net = network::spawn(
        cfg.net.clone(),
        cfg.p2p.clone(),
        db.clone(),
        sync_state.clone(),
    )
    .await?;
    {
        let db_h = db.clone();
        let net_h = net.clone();
        let shutdown_rx_h = shutdown_tx.subscribe();
        tokio::spawn(async move {
            sync::spawn_headers_skeleton(db_h, net_h, shutdown_rx_h).await;
        });
    }
    sync::spawn(
        db.clone(),
        net.clone(),
        sync_state.clone(),
        shutdown_tx.subscribe(),
        !cfg.net.bootstrap.is_empty(),
    );
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
    Ok(NetworkRuntime {
        db,
        net,
        sync_state,
        coin_tx,
        shutdown_tx,
    })
}

async fn shutdown_network_runtime(runtime: NetworkRuntime) -> Result<()> {
    let _ = runtime.shutdown_tx.send(());
    runtime.net.shutdown().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    runtime.db.close()?;
    Ok(())
}

async fn wait_for_shutdown(signal_label: &str, runtime: NetworkRuntime) -> Result<()> {
    println!("Press Ctrl+C to stop.");
    match signal::ctrl_c().await {
        Ok(()) => {
            println!();
            println!("Shutdown signal received. Cleaning up {signal_label}...");
            shutdown_network_runtime(runtime).await?;
            println!("{signal_label} stopped.");
            Ok(())
        }
        Err(err) => {
            eprintln!("Error waiting for shutdown signal: {err}");
            Err(err.into())
        }
    }
}

async fn run_send_flow(
    client: &wallet_control::WalletControlClient,
    args: &SendArgs,
) -> Result<()> {
    let guided = args.to.is_none() || args.amount.is_none();
    if guided && !atty::is(atty::Stream::Stdin) {
        bail!("Interactive send requires a TTY. Pass --to and --amount in non-interactive mode.");
    }
    let to_raw = match &args.to {
        Some(to) => to.clone(),
        None => prompt_line("Single-use receive handle: ")?,
    };
    let to = load_receiver_code(&to_raw)?;
    if to.is_empty() {
        bail!("Address cannot be empty");
    }

    let amount = match args.amount {
        Some(amount) => amount,
        None => prompt_line("Amount: ")?
            .parse::<u64>()
            .map_err(|_| anyhow!("invalid amount"))?,
    };
    if amount == 0 {
        bail!("Amount must be greater than 0");
    }

    if guided {
        println!();
        println!(
            "Ready to send {amount} coin{}.",
            if amount == 1 { "" } else { "s" }
        );
        println!("Recipient: {}", short_text(&to));
        let confirm = prompt_line("Broadcast now? [Y/n]: ")?;
        if matches!(confirm.to_ascii_lowercase().as_str(), "n" | "no") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let outcome = client.send(&to, amount).await?;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "to": to,
                "amount": amount,
                "tx_id": hex::encode(outcome.tx_id),
                "input_count": outcome.input_count,
                "output_count": outcome.output_count,
            })
        );
        return Ok(());
    }

    println!("Sent");
    println!();
    println!(
        "Broadcast shielded transaction consuming {} note{} and creating {} note{} for {} coin{}.",
        outcome.input_count,
        if outcome.input_count == 1 { "" } else { "s" },
        outcome.output_count,
        if outcome.output_count == 1 { "" } else { "s" },
        amount,
        if amount == 1 { "" } else { "s" }
    );
    println!("Recipient: {}", short_text(&to));
    println!("Tx ID: {}", hex::encode(outcome.tx_id));
    println!();
    println!("Track confirmation with `unchained_wallet history`.");
    Ok(())
}

fn print_receive_output(handle: &str, args: &ReceiveArgs) -> Result<()> {
    let address = handle.to_string();
    let copied = if args.copy {
        copy_to_clipboard(&address).is_ok()
    } else {
        false
    };

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "address": address,
                "copied": copied,
            })
        );
        return Ok(());
    }

    if args.plain {
        println!("{address}");
        return Ok(());
    }

    println!("Receive");
    println!();
    println!("{address}");
    println!();
    if let Err(err) = print_qr_to_terminal(&address) {
        eprintln!("QR unavailable: {err}");
    }
    if args.copy {
        println!();
        println!(
            "{}",
            if copied {
                "Copied to clipboard."
            } else {
                "Clipboard unavailable."
            }
        );
    }
    Ok(())
}

fn print_balance_output(state: &wallet::WalletObservedState, args: &BalanceArgs) -> Result<()> {
    let balance = state.balance;
    let outputs = state.spendable_outputs;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "balance": balance,
                "spendable_outputs": outputs,
                "address": hex::encode(state.address),
            })
        );
        return Ok(());
    }

    println!("Wallet");
    println!();
    println!(
        "Spendable balance: {balance} coin{}",
        if balance == 1 { "" } else { "s" }
    );
    println!("Spendable outputs: {outputs}");
    println!("Receive: `unchained_wallet receive`");
    Ok(())
}

fn print_history_output(history: &[wallet::TransactionRecord], args: &HistoryArgs) -> Result<()> {
    let mut history = history.to_vec();
    if let Some(limit) = args.limit {
        history.truncate(limit);
    }

    if args.json {
        let rows: Vec<serde_json::Value> = history
            .iter()
            .map(|record| {
                serde_json::json!({
                    "coin_id": hex::encode(record.coin_id),
                    "transfer_hash": hex::encode(record.transfer_hash),
                    "epoch": record.commit_epoch,
                    "direction": if record.is_sender { "out" } else { "in" },
                    "amount": record.amount,
                    "counterparty": hex::encode(record.counterparty),
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(rows));
        return Ok(());
    }

    if history.is_empty() {
        println!("No wallet history yet.");
        return Ok(());
    }

    println!("History");
    println!();
    for record in history {
        let direction = if record.is_sender { "Sent" } else { "Received" };
        println!(
            "{} {} coin{} at epoch #{} with {}",
            direction,
            record.amount,
            if record.amount == 1 { "" } else { "s" },
            record.commit_epoch,
            short_hex(&record.counterparty)
        );
        println!("  coin {}", short_hex(&record.coin_id));
        println!("  tx   {}", short_hex(&record.transfer_hash));
    }
    Ok(())
}

async fn rescan_wallet_transactions(client: &wallet_control::WalletControlClient) -> Result<()> {
    client.force_sync().await?;
    println!("✅ Rescanned wallet state from the local node");
    Ok(())
}

pub async fn run_node_cli() -> Result<()> {
    let cli = NodeCli::parse();
    let cfg = load_config(&cli.common.config)?;
    apply_quiet_logging(&cli.common, &cfg);

    if handle_node_operator_command(&cli.cmd, &cfg)? {
        return Ok(());
    }

    match cli.cmd {
        NodeCmd::ExportAnchors { out } => {
            let db = open_store(&cfg)?;
            let written = db.export_anchors_snapshot(&out)?;
            db.close()?;
            println!("✅ Exported {written} anchors to {out}");
            Ok(())
        }
        NodeCmd::ImportAnchors { input } => {
            let db = open_store(&cfg)?;
            let added = db.import_anchors_snapshot(&input)?;
            db.close()?;
            println!("✅ Imported {added} anchors from {input}");
            Ok(())
        }
        NodeCmd::ReplayTransactions => {
            let runtime = start_network_runtime(&cfg).await?;
            let cf = runtime
                .db
                .db
                .cf_handle("tx")
                .ok_or_else(|| anyhow!("'tx' column family missing"))?;
            let iter = runtime.db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let mut replayed = 0u64;
            for item in iter {
                let (_k, v) = item?;
                if let Ok(tx) = canonical::decode_tx(&v) {
                    runtime.net.gossip_tx(&tx).await;
                    replayed += 1;
                }
            }
            shutdown_network_runtime(runtime).await?;
            println!("✅ Re-gossiped {replayed} transactions");
            Ok(())
        }
        NodeCmd::Start => {
            println!("Database: {}", cfg.storage.path);
            let runtime = start_network_runtime(&cfg).await?;
            let node_control_shutdown = runtime.shutdown_tx.subscribe();
            let node_control_server = node_control::NodeControlServer::bind(
                &cfg.storage.path,
                runtime.db.clone(),
                runtime.net.clone(),
                runtime.sync_state.clone(),
                runtime.coin_tx.clone(),
                !cfg.net.bootstrap.is_empty(),
            )
            .await?;
            let node_control_socket = node_control_server.socket_path().display().to_string();
            let node_control_capability =
                node_control::node_control_capability_path(&cfg.storage.path)
                    .display()
                    .to_string();
            let node_control_task =
                tokio::spawn(async move { node_control_server.serve(node_control_shutdown).await });
            metrics::serve(cfg.metrics.clone())?;
            println!();
            println!("Unchained node is running.");
            println!("Listening on port {}", cfg.net.listen_port);
            println!("Node control socket: {node_control_socket}");
            println!("Node control capability: {node_control_capability}");
            if let Some(public_ip) = cfg.net.public_ip.clone() {
                println!("Public IP: {public_ip}");
            }
            println!("Epoch length: {} seconds", cfg.epoch.seconds);
            println!("Mining: external clients only");
            println!("Epoch manager: enabled");
            println!("Epoch coin cap: {}", protocol::CURRENT.max_coins_per_epoch);
            let shutdown_result = wait_for_shutdown("Unchained node", runtime).await;
            let node_control_result = node_control_task.await.map_err(|err| anyhow!(err))?;
            shutdown_result?;
            node_control_result?;
            Ok(())
        }
        NodeCmd::InitRoot { .. }
        | NodeCmd::AuthPrepare { .. }
        | NodeCmd::AuthSign { .. }
        | NodeCmd::AuthInstall { .. }
        | NodeCmd::TrustRevoke { .. }
        | NodeCmd::TrustReplace { .. }
        | NodeCmd::TrustApprove { .. }
        | NodeCmd::PeerId => unreachable!("handled before runtime startup"),
    }
}

pub async fn run_wallet_cli() -> Result<()> {
    let cli = WalletCli::parse();
    let cfg = load_config(&cli.common.config)?;
    apply_quiet_logging(&cli.common, &cfg);

    match cli.cmd {
        WalletCmd::Serve => {
            let wallet_db = open_wallet_store(&cfg)?;
            let node_client = open_node_control_client(&cfg)?;
            let wallet = Arc::new(
                wallet::Wallet::load_or_create_private(wallet_db.clone())?
                    .with_node_client(node_client),
            );
            let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
            let server =
                wallet_control::WalletControlServer::bind(&cfg.storage.path, wallet.clone())
                    .await?;
            let socket_path = server.socket_path().display().to_string();
            let capability_path = wallet_control::wallet_control_capability_path(&cfg.storage.path)
                .display()
                .to_string();
            let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

            println!("Wallet control socket: {socket_path}");
            println!("Wallet control capability: {capability_path}");
            println!("Wallet control runtime is running.");
            println!("Press Ctrl+C to stop.");

            match signal::ctrl_c().await {
                Ok(()) => {
                    println!();
                    println!("Shutdown signal received. Cleaning up Unchained wallet...");
                    let _ = shutdown_tx.send(());
                    let server_result = server_task.await.map_err(|err| anyhow!(err))?;
                    drop(wallet);
                    let wallet_close_result = wallet_db.close();
                    server_result?;
                    wallet_close_result?;
                    println!("Unchained wallet stopped.");
                    Ok(())
                }
                Err(err) => {
                    let _ = shutdown_tx.send(());
                    let _ = server_task.await;
                    drop(wallet);
                    let _ = wallet_db.close();
                    Err(err.into())
                }
            }
        }
        WalletCmd::Receive(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let handle = client.mint_receive_handle().await?;
            print_receive_output(&handle, &args)?;
            Ok(())
        }
        WalletCmd::Balance(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let state = client.state().await?;
            print_balance_output(&state.state, &args)?;
            Ok(())
        }
        WalletCmd::History(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let state = client.state().await?;
            print_history_output(&state.state.history, &args)?;
            Ok(())
        }
        WalletCmd::Rescan => {
            let client = open_wallet_control_client(&cfg).await?;
            rescan_wallet_transactions(&client).await?;
            Ok(())
        }
        WalletCmd::Send(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            run_send_flow(&client, &args).await?;
            Ok(())
        }
    }
}

pub async fn run_miner_cli() -> Result<()> {
    let cli = MinerCli::parse();
    let mut cfg = load_config(&cli.common.config)?;
    cfg.mining.enabled = true;
    apply_quiet_logging(&cli.common, &cfg);

    let node_control = open_node_control_client(&cfg)?;
    let wallet_control = wallet_control::WalletControlClient::new(&cfg.storage.path);
    wallet_control.ping().await?;
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    println!("Database: {}", cfg.storage.path);
    let miner_task = miner::spawn(
        cfg.mining.clone(),
        node_control,
        wallet_control,
        shutdown_rx,
    );

    println!();
    println!("Unchained miner is running.");
    println!("Node runtime: external");
    println!("Wallet runtime: external");
    println!("Epoch length: {} seconds", cfg.epoch.seconds);
    println!("Mining: enabled");
    println!("Epoch coin cap: {}", protocol::CURRENT.max_coins_per_epoch);
    println!("Press Ctrl+C to stop.");
    match signal::ctrl_c().await {
        Ok(()) => {
            println!();
            println!("Shutdown signal received. Cleaning up Unchained miner...");
            let _ = shutdown_tx.send(());
            let _ = miner_task.await;
            println!("Unchained miner stopped.");
            Ok(())
        }
        Err(err) => {
            let _ = shutdown_tx.send(());
            let _ = miner_task.await;
            Err(err.into())
        }
    }
}
