use anyhow;
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;

pub mod canonical;
pub mod coin;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod epoch;
pub mod metrics;
pub mod miner;
pub mod network;
pub mod node_identity;
pub mod protocol;
pub mod shielded;
pub mod storage;
pub mod sync;
pub mod transaction;
pub mod wallet;
use crate::network::RateLimitedMessage;
use qrcode::render::unicode;
use qrcode::QrCode;
fn print_qr_to_terminal(data: &str) -> anyhow::Result<()> {
    let code = QrCode::new(data.as_bytes())?;
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .build();
    println!("{}", image);
    Ok(())
}
fn copy_to_clipboard(text: &str) -> anyhow::Result<()> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(text.to_string())?;
    Ok(())
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn load_receiver_code(input: &str) -> anyhow::Result<String> {
    let cleaned = input
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .to_string();
    if cleaned.eq_ignore_ascii_case("test") {
        return Ok(std::fs::read_to_string("test_stealth_address.txt")
            .map(|s| s.trim().to_string())
            .unwrap_or_default());
    }
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

#[derive(Parser)]
#[command(
    author,
    version,
    about = "Post-quantum shielded node and wallet CLI for Unchained",
    long_about = "Run an Unchained node, manage a PQ wallet, and send shielded note transactions.\n\
\nSending accepts a verified recipient document. Use flags for automation or run interactively for a guided flow.",
    help_template = "{name} {version}\n{about}\n\nUSAGE:\n  {usage}\n\nOPTIONS:\n{options}\n\nCOMMANDS:\n{subcommands}\n\n{after-help}",
    after_help = "Examples:\n  unchained node init-root\n  unchained node auth-prepare --out auth_request.txt\n  unchained node auth-sign --request auth_request.txt --out node_record.txt\n  unchained node auth-install --record node_record.txt\n  unchained node start\n  unchained wallet receive\n  unchained wallet send --to <KEYDOC_JSON> --amount 100\n  unchained wallet balance\n"
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
    /// Node lifecycle and identity commands
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Wallet commands
    Wallet {
        #[command(subcommand)]
        cmd: WalletCmd,
    },
    /// Messaging commands
    Message {
        #[command(subcommand)]
        cmd: MessageCmd,
    },
    /// Advanced protocol and maintenance commands
    Advanced {
        #[command(subcommand)]
        cmd: AdvancedCmd,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Create or load the offline node root and print its compact root-info document
    InitRoot {
        /// Optional file path for the compact root-info document
        #[arg(long)]
        out: Option<String>,
    },
    /// Prepare a runtime auth key and signed auth request for offline approval
    AuthPrepare {
        /// Optional compact root-info document or file path to pin the expected root
        #[arg(long)]
        root_info: Option<String>,
        /// Optional file path for the compact auth-request document
        #[arg(long)]
        out: Option<String>,
    },
    /// Approve an auth request with the offline node root and produce a signed node record
    AuthSign {
        /// Compact auth-request document or file path
        #[arg(long)]
        request: String,
        /// Signed node-record lifetime in days
        #[arg(long, default_value_t = 30)]
        lifetime_days: u64,
        /// Optional file path for the compact node-record document
        #[arg(long)]
        out: Option<String>,
    },
    /// Install a signed node record for runtime use
    AuthInstall {
        /// Compact node-record document or file path
        #[arg(long)]
        record: String,
    },
    /// Create a compact trust-update revocation document
    TrustRevoke {
        /// Subject node ID as 64 hex characters
        #[arg(long)]
        node_id: String,
        /// Optional file path for the compact trust-update document
        #[arg(long)]
        out: Option<String>,
    },
    /// Create a compact trust-update replacement document
    TrustReplace {
        /// Subject node ID as 64 hex characters
        #[arg(long)]
        node_id: String,
        /// Replacement compact node-record document or file path
        #[arg(long)]
        replacement: String,
        /// Optional file path for the compact trust-update document
        #[arg(long)]
        out: Option<String>,
    },
    /// Approve a compact trust-update document with the offline node root
    TrustApprove {
        /// Compact trust-update document or file path
        #[arg(long)]
        update: String,
        /// Optional file path for the compact trust-update document
        #[arg(long)]
        out: Option<String>,
    },
    /// Start the node runtime
    Start {
        /// Force mining on for this run
        #[arg(long, default_value_t = false)]
        mine: bool,
    },
    /// Print the local node ID and signed bootstrap record
    PeerId,
}

#[derive(Args, Clone)]
struct ReceiveArgs {
    /// Print only the address
    #[arg(long, default_value_t = false)]
    plain: bool,
    /// Output machine-readable JSON
    #[arg(long, default_value_t = false)]
    json: bool,
    /// Copy the address to the clipboard
    #[arg(long, default_value_t = false)]
    copy: bool,
}

#[derive(Args, Clone)]
struct SendArgs {
    /// Receiver address or verified recipient document; if omitted, you will be prompted
    #[arg(long = "to", alias = "paycode")]
    to: Option<String>,
    /// Amount to send; if omitted, you will be prompted
    #[arg(long)]
    amount: Option<u64>,
    /// Output machine-readable JSON
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone, Default)]
struct BalanceArgs {
    /// Output machine-readable JSON
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone, Default)]
struct HistoryArgs {
    /// Limit the number of rows shown
    #[arg(long)]
    limit: Option<usize>,
    /// Output machine-readable JSON
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone)]
struct MessageSendArgs {
    /// Message text to send; if omitted, you will be prompted
    #[arg(long)]
    text: Option<String>,
}

#[derive(Args, Clone)]
struct MessageListenArgs {
    /// Exit after receiving a single message
    #[arg(long, default_value_t = false)]
    once: bool,
    /// Exit after receiving this many messages
    #[arg(long)]
    count: Option<u64>,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Show your shareable receiving address
    #[command(alias = "address")]
    Receive(ReceiveArgs),
    /// Send coins to a receiver, or run a guided send flow
    Send(SendArgs),
    /// Show wallet balance and owned shielded notes
    Balance(BalanceArgs),
    /// Show wallet transaction history
    History(HistoryArgs),
}

#[derive(Subcommand)]
enum MessageCmd {
    /// Send a short text message on the bounded P2P topic
    Send(MessageSendArgs),
    /// Listen for incoming messages on the bounded P2P topic
    Listen(MessageListenArgs),
}

#[derive(Subcommand)]
enum AdvancedCmd {
    /// Re-gossip all transactions from local DB
    ReplayTransactions,
    /// Rescan local transactions against this wallet
    RescanWallet,
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

fn print_receive_output(wallet: &wallet::Wallet, args: &ReceiveArgs) -> anyhow::Result<()> {
    let address = wallet.export_address()?;
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
    if let Err(e) = print_qr_to_terminal(&address) {
        eprintln!("QR unavailable: {e}");
    }
    if args.copy {
        if copied {
            println!();
            println!("Copied to clipboard.");
        } else {
            println!();
            println!("Clipboard unavailable.");
        }
    }
    Ok(())
}

async fn run_send_flow(
    wallet: &Arc<wallet::Wallet>,
    net: &network::NetHandle,
    args: &SendArgs,
) -> anyhow::Result<()> {
    let guided = args.to.is_none() || args.amount.is_none();
    if guided && !atty::is(atty::Stream::Stdin) {
        anyhow::bail!(
            "Interactive send requires a TTY. Pass --to and --amount in non-interactive mode."
        );
    }
    let to_raw = match &args.to {
        Some(to) => to.clone(),
        None => prompt_line("Recipient document: ")?,
    };
    let to = load_receiver_code(&to_raw)?;
    if to.is_empty() {
        anyhow::bail!("Address cannot be empty");
    }
    wallet.validate_recipient_handle(&to)?;

    let amount = match args.amount {
        Some(amount) => amount,
        None => {
            let raw = prompt_line("Amount: ")?;
            raw.parse::<u64>()
                .map_err(|_| anyhow::anyhow!("invalid amount"))?
        }
    };
    if amount == 0 {
        anyhow::bail!("Amount must be greater than 0");
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

    let outcome = wallet.send_with_paycode_and_note(&to, amount, net).await?;

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
    println!("Track confirmation with `unchained wallet history`.");
    Ok(())
}

fn print_balance_output(wallet: &wallet::Wallet, args: &BalanceArgs) -> anyhow::Result<()> {
    let balance = wallet.balance()?;
    let outputs = wallet.list_owned_shielded_notes()?.len();
    let address = wallet.export_address()?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "balance": balance,
                "spendable_outputs": outputs,
                "address": address,
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
    println!("Receive: `unchained wallet receive`");
    Ok(())
}

fn print_history_output(wallet: &wallet::Wallet, args: &HistoryArgs) -> anyhow::Result<()> {
    let mut history = wallet.get_transaction_history()?;
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

fn print_peer_id_output(cfg: &config::Config) -> anyhow::Result<()> {
    let db = storage::Store::open(&cfg.storage.path)?;
    let chain_id = db.get_chain_id().ok();
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

fn load_identity_chain_id(storage_path: &str) -> anyhow::Result<Option<[u8; 32]>> {
    let db = storage::Store::open(storage_path)?;
    Ok(db.get_chain_id().ok())
}

fn write_compact_output(path: Option<&str>, value: &str) -> anyhow::Result<()> {
    if let Some(path) = path {
        std::fs::write(path, format!("{value}\n"))?;
        println!("Wrote {}", path);
        println!();
    }
    Ok(())
}

fn print_compact_document(
    label: &str,
    node_id: Option<&str>,
    value: &str,
    out: Option<&str>,
) -> anyhow::Result<()> {
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

fn parse_node_id_hex(value: &str) -> anyhow::Result<[u8; 32]> {
    let raw = hex::decode(value.trim())?;
    if raw.len() != 32 {
        return Err(anyhow::anyhow!("node id must be exactly 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn handle_node_operator_command(cmd: &Option<Cmd>, cfg: &config::Config) -> anyhow::Result<bool> {
    match cmd {
        Some(Cmd::Node {
            cmd: NodeCmd::InitRoot { out },
        }) => {
            let (node_id, root_info) = node_identity::init_root_in_dir(&cfg.storage.path)?;
            print_compact_document("Root Info", Some(&node_id), &root_info, out.as_deref())?;
            Ok(true)
        }
        Some(Cmd::Node {
            cmd: NodeCmd::AuthPrepare { root_info, out },
        }) => {
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
        Some(Cmd::Node {
            cmd:
                NodeCmd::AuthSign {
                    request,
                    lifetime_days,
                    out,
                },
        }) => {
            let (node_id, record) = node_identity::sign_auth_request_in_dir(
                &cfg.storage.path,
                request,
                *lifetime_days,
            )?;
            print_compact_document("Node Record", Some(&node_id), &record, out.as_deref())?;
            Ok(true)
        }
        Some(Cmd::Node {
            cmd: NodeCmd::AuthInstall { record },
        }) => {
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
        Some(Cmd::Node {
            cmd: NodeCmd::TrustRevoke { node_id, out },
        }) => {
            let update = node_identity::create_trust_update_revoke(parse_node_id_hex(node_id)?)?;
            print_compact_document("Trust Update", None, &update, out.as_deref())?;
            Ok(true)
        }
        Some(Cmd::Node {
            cmd:
                NodeCmd::TrustReplace {
                    node_id,
                    replacement,
                    out,
                },
        }) => {
            let update = node_identity::create_trust_update_replace(
                parse_node_id_hex(node_id)?,
                replacement,
            )?;
            print_compact_document("Trust Update", None, &update, out.as_deref())?;
            Ok(true)
        }
        Some(Cmd::Node {
            cmd: NodeCmd::TrustApprove { update, out },
        }) => {
            let approved = node_identity::approve_trust_update_in_dir(&cfg.storage.path, update)?;
            print_compact_document("Approved Trust Update", None, &approved, out.as_deref())?;
            Ok(true)
        }
        Some(Cmd::Node {
            cmd: NodeCmd::PeerId,
        }) => {
            print_peer_id_output(cfg)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.cmd.is_none() {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        println!();
        println!("Start with `unchained node start` or `unchained wallet receive`.");
        return Ok(());
    }

    let node_start_requested = matches!(
        &cli.cmd,
        Some(Cmd::Node {
            cmd: NodeCmd::Start { .. }
        })
    );
    let force_mine = matches!(
        &cli.cmd,
        Some(Cmd::Node {
            cmd: NodeCmd::Start { mine: true }
        })
    );

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
                        eprintln!(
                            "⚠️  Could not read config from '{}' or exe dir: {} | {}",
                            &cli.config, e1, e2
                        );
                        // Embedded minimal default config ensures the Windows .exe can run standalone
                        const EMBEDDED_CONFIG: &str = include_str!("../config.toml");
                        match config::load_from_str(EMBEDDED_CONFIG) {
                            Ok(c) => c,
                            Err(e3) => {
                                return Err(anyhow::anyhow!(
                                    "failed to load configuration: {} / {} / {}",
                                    e1,
                                    e2,
                                    e3
                                ))
                            }
                        }
                    }
                }
            } else {
                const EMBEDDED_CONFIG: &str = include_str!("../config.toml");
                match config::load_from_str(EMBEDDED_CONFIG) {
                    Ok(c) => c,
                    Err(e3) => {
                        return Err(anyhow::anyhow!(
                            "failed to load configuration: {} / {}",
                            e1,
                            e3
                        ))
                    }
                }
            }
        }
    };
    if force_mine {
        cfg.mining.enabled = true;
    }
    if std::path::Path::new(&cfg.storage.path).is_relative() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let abs = std::path::Path::new(&home)
            .join(".unchained")
            .join("unchained_data");
        cfg.storage.path = abs.to_string_lossy().into_owned();
    }

    if handle_node_operator_command(&cli.cmd, &cfg)? {
        return Ok(());
    }

    // Apply quiet logging preference: CLI flag overrides config
    if cli.quiet_net {
        network::set_quiet_logging(true);
    }

    // If no CLI quiet flag, honor config default
    if !cli.quiet_net && cfg.net.quiet_by_default {
        network::set_quiet_logging(true);
    }

    let db = match std::panic::catch_unwind(|| storage::open(&cfg.storage)) {
        Ok(db) => db,
        Err(_) => return Err(anyhow::anyhow!("failed to open database")),
    };

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let wallet = Arc::new(wallet::Wallet::load_or_create(db.clone())?);

    match &cli.cmd {
        Some(Cmd::Wallet {
            cmd: WalletCmd::Receive(args),
        }) => {
            print_receive_output(wallet.as_ref(), args)?;
            return Ok(());
        }
        Some(Cmd::Wallet {
            cmd: WalletCmd::Balance(args),
        }) => {
            print_balance_output(wallet.as_ref(), args)?;
            return Ok(());
        }
        Some(Cmd::Wallet {
            cmd: WalletCmd::History(args),
        }) => {
            print_history_output(wallet.as_ref(), args)?;
            return Ok(());
        }
        _ => {}
    }

    if node_start_requested {
        println!("Database: {}", cfg.storage.path);

        // Auto-import anchors snapshot if DB is empty (no genesis) and a co-located snapshot file exists
        if db
            .get::<epoch::Anchor>("epoch", &0u64.to_le_bytes())?
            .is_none()
        {
            // Try well-known relative filenames next to config or working directory
            let candidates = ["anchors_snapshot.zst", "anchors_snapshot.bin"];
            for cand in candidates.iter() {
                if std::path::Path::new(cand).exists() {
                    match db.import_anchors_snapshot(cand) {
                        Ok(n) if n > 0 => {
                            println!("Imported {} anchors from '{}'", n, cand);
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => eprintln!("Snapshot import from '{}' failed: {}", cand, e),
                    }
                }
            }
        }
    }

    let sync_state = Arc::new(Mutex::new(sync::SyncState::default()));

    let net = network::spawn(
        cfg.net.clone(),
        cfg.p2p.clone(),
        db.clone(),
        sync_state.clone(),
    )
    .await?;
    // Kick off headers-first skeleton sync in the background (additive protocol, safe if peers don't support it)
    {
        let db_h = db.clone();
        let net_h = net.clone();
        let shutdown_rx_h = shutdown_tx.subscribe();
        tokio::spawn(async move {
            crate::sync::spawn_headers_skeleton(db_h, net_h, shutdown_rx_h).await;
        });
    }

    // Background: subscribe to canonical transactions and anchors to trigger deterministic rescans.
    {
        let net_clone = net.clone();
        let wallet_clone = wallet.clone();
        let db_clone = db.clone();
        tokio::spawn(async move {
            let mut tx_rx = net_clone.tx_subscribe();
            let mut anchor_rx = net_clone.anchor_subscribe();
            loop {
                tokio::select! {
                    Ok(tx) = tx_rx.recv() => {
                        let _ = wallet_clone.scan_tx_for_me(&tx);
                    },
                    Ok(_a) = anchor_rx.recv() => {
                        // On anchor adoption, refresh owned shielded notes and replay stored tx outputs.
                        let _ = wallet_clone.sync_shielded_notes();
                        if let Some(cf) = db_clone.db.cf_handle("tx") {
                            let iter = db_clone.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
                            for item in iter {
                                if let Ok((_k, v)) = item {
                                    if let Ok(tx) = canonical::decode_tx(&v) {
                                        let _ = wallet_clone.scan_tx_for_me(&tx);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn background sync task (safe for read-only commands; does not advance epochs itself)
    sync::spawn(
        db.clone(),
        net.clone(),
        sync_state.clone(),
        shutdown_tx.subscribe(),
        !cfg.net.bootstrap.is_empty(),
    );

    // Handle CLI commands
    match &cli.cmd {
        Some(Cmd::Node {
            cmd: NodeCmd::Start { .. },
        }) => {
            if cfg.mining.enabled {
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
                println!("Syncing with the network before mining...");
                net.request_latest_epoch().await;

                let mut anchor_rx = net.anchor_subscribe();
                let poll_interval_ms: u64 = 500;
                let max_attempts: u64 =
                    ((cfg.net.sync_timeout_secs.saturating_mul(1000)) / poll_interval_ms).max(1);
                let mut synced = false;
                let mut attempt: u64 = 0;
                let mut last_local_displayed: u64 = u64::MAX; // force initial print once we have network view
                while attempt < max_attempts {
                    let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                    let peer_confirmed = sync_state
                        .lock()
                        .map(|s| s.peer_confirmed_tip)
                        .unwrap_or(false);
                    let latest_opt = db.get::<epoch::Anchor>("epoch", b"latest").unwrap_or(None);
                    let local_epoch = latest_opt.as_ref().map_or(0, |a| a.num);

                    // When bootstrap peers are configured, require a peer-confirmed tip before declaring sync
                    if highest_seen > 0
                        && local_epoch >= highest_seen
                        && (cfg.net.bootstrap.is_empty() || peer_confirmed)
                    {
                        println!("Synchronized at epoch {}.", local_epoch);
                        if let Ok(mut st) = sync_state.lock() {
                            st.synced = true;
                        }
                        synced = true;
                        break;
                    }
                    if highest_seen == 0 && latest_opt.is_some() && cfg.net.bootstrap.is_empty() {
                        println!(
                            "No peers responded; using local chain at epoch {}.",
                            local_epoch
                        );
                        if let Ok(mut st) = sync_state.lock() {
                            st.synced = true;
                            if st.highest_seen_epoch == 0 {
                                st.highest_seen_epoch = local_epoch;
                            }
                        }
                        synced = true;
                        break;
                    }
                    if highest_seen > 0 {
                        if last_local_displayed != local_epoch || attempt == 0 {
                            if cfg.net.bootstrap.is_empty() {
                                println!(
                                    "Syncing... local epoch {}, network epoch {}",
                                    local_epoch, highest_seen
                                );
                            } else {
                                println!(
                                    "Syncing... local {}, network {}, peer-confirmed {}",
                                    local_epoch, highest_seen, peer_confirmed
                                );
                            }
                            last_local_displayed = local_epoch;
                        }
                    } else {
                        println!("Waiting for network response... attempt {}", attempt + 1);
                    }

                    tokio::select! {
                        Ok(_a) = anchor_rx.recv() => { continue; }
                        _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => { attempt += 1; }
                    }
                }
                if !synced {
                    println!(
                        "Could not sync with the network after {}s.",
                        cfg.net.sync_timeout_secs
                    );
                    // Only allow starting as a new chain when there are no bootstrap peers and no network view
                    let highest_seen = sync_state.lock().map(|s| s.highest_seen_epoch).unwrap_or(0);
                    if cfg.net.bootstrap.is_empty() && highest_seen == 0 {
                        if let Ok(Some(latest)) = db.get::<epoch::Anchor>("epoch", b"latest") {
                            if let Ok(mut st) = sync_state.lock() {
                                st.synced = true;
                                if st.highest_seen_epoch == 0 {
                                    st.highest_seen_epoch = latest.num;
                                }
                            }
                            println!("Proceeding with local chain at epoch {}.", latest.num);
                        }
                    } else {
                        println!("Mining remains disabled until local state catches up to the network tip.");
                    }
                }

                miner::spawn(
                    cfg.mining.clone(),
                    db.clone(),
                    net.clone(),
                    wallet.clone(),
                    coin_tx,
                    shutdown_tx.subscribe(),
                    sync_state.clone(),
                );
            } else {
                println!("Starting node with mining disabled.");
            }
        }
        Some(Cmd::Wallet {
            cmd: WalletCmd::Send(args),
        }) => {
            run_send_flow(&wallet, &net, args).await?;
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::ExportAnchors { out },
        }) => {
            let written = db.export_anchors_snapshot(out)?;
            println!("✅ Exported {} anchors to {}", written, out);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::ImportAnchors { input },
        }) => {
            let added = db.import_anchors_snapshot(input)?;
            println!("✅ Imported {} anchors from {}", added, input);
            return Ok(());
        }
        // commitment commands removed
        Some(Cmd::Message {
            cmd: MessageCmd::Send(MessageSendArgs { text }),
        }) => {
            let message = if let Some(t) = text {
                t.clone()
            } else {
                if !atty::is(atty::Stream::Stdin) {
                    anyhow::bail!(
                        "Interactive message send requires a TTY. Pass --text in non-interactive mode."
                    );
                }
                prompt_line("Message: ")?
            };
            if message.is_empty() {
                println!("Nothing to send.");
                return Ok(());
            }
            let msg = RateLimitedMessage { content: message };
            net.gossip_rate_limited(msg).await;
            println!("Message submitted to the shared topic.");
            println!("Outbound rate limit: 2 messages per 24h.");
            return Ok(());
        }
        Some(Cmd::Message {
            cmd: MessageCmd::Listen(MessageListenArgs { once, count }),
        }) => {
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
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::ReplayTransactions,
        }) => {
            let cf = db
                .db
                .cf_handle("tx")
                .ok_or_else(|| anyhow::anyhow!("'tx' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let mut replayed = 0u64;
            for item in iter {
                let (_k, v) = item?;
                if let Ok(tx) = canonical::decode_tx(&v) {
                    net.gossip_tx(&tx).await;
                    replayed += 1;
                }
            }
            println!("✅ Re-gossiped {} transactions", replayed);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::RescanWallet,
        }) => {
            let cf = db
                .db
                .cf_handle("tx")
                .ok_or_else(|| anyhow::anyhow!("'tx' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let mut scanned = 0u64;
            for item in iter {
                let (_k, v) = item?;
                if let Ok(tx) = canonical::decode_tx(&v) {
                    let _ = wallet.scan_tx_for_me(&tx);
                    scanned += 1;
                }
            }
            let _ = wallet.sync_shielded_notes();
            println!("✅ Rescanned {} transactions for this wallet", scanned);
            return Ok(());
        }
        Some(Cmd::Node {
            cmd: NodeCmd::PeerId,
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::InitRoot { .. },
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::AuthPrepare { .. },
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::AuthSign { .. },
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::AuthInstall { .. },
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::TrustRevoke { .. },
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::TrustReplace { .. },
        })
        | Some(Cmd::Node {
            cmd: NodeCmd::TrustApprove { .. },
        })
        | Some(Cmd::Wallet {
            cmd: WalletCmd::Receive(_),
        })
        | Some(Cmd::Wallet {
            cmd: WalletCmd::Balance(_),
        })
        | Some(Cmd::Wallet {
            cmd: WalletCmd::History(_),
        }) => {
            unreachable!("handled before network startup")
        }
        None => return Ok(()),
        // commitment request removed
    }

    if !node_start_requested {
        return Ok(());
    }

    let _metrics_bind = cfg.metrics.bind.clone();
    metrics::serve(cfg.metrics)?;

    println!();
    println!("Unchained node is running.");
    println!("Listening on port {}", cfg.net.listen_port);
    if let Some(public_ip) = cfg.net.public_ip {
        println!("Public IP: {public_ip}");
    }
    println!("Epoch length: {} seconds", cfg.epoch.seconds);
    println!(
        "Mining: {}",
        if cfg.mining.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "Epoch coin cap: {}",
        crate::protocol::CURRENT.max_coins_per_epoch
    );
    println!("Press Ctrl+C to stop.");

    match signal::ctrl_c().await {
        Ok(()) => {
            println!();
            println!("Shutdown signal received. Cleaning up...");
            let _ = shutdown_tx.send(());
            net.shutdown().await;
            println!("Waiting for tasks to shut down gracefully...");
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            if let Err(e) = db.close() {
                eprintln!("Warning: Database cleanup failed: {e}");
            } else {
                println!("Database closed cleanly.");
            }
            println!("Unchained node stopped.");
            Ok(())
        }
        Err(err) => {
            eprintln!("Error waiting for shutdown signal: {err}");
            Err(err.into())
        }
    }
}
