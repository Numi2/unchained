use anyhow;
use base64::Engine;
use clap::{Args, CommandFactory, Parser, Subcommand};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;

pub mod bridge;
pub mod coin;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod epoch;
pub mod metrics;
pub mod miner;
pub mod network;
pub mod offers;
pub mod protocol;
pub mod storage;
pub mod sync;
pub mod transaction;
pub mod transfer;
pub mod wallet;
pub mod x402;
use crate::network::RateLimitedMessage;
use pqcrypto_traits::kem::PublicKey as KyberPkTrait;
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
    about = "Private node and wallet CLI for Unchained",
    long_about = "Run an Unchained node: start the runtime explicitly, manage a wallet, and send private hashlock transfers.\n\
\nSending accepts a single receiver address or verified recipient document. Use flags for automation or run interactively for a guided flow.",
    help_template = "{name} {version}\n{about}\n\nUSAGE:\n  {usage}\n\nOPTIONS:\n{options}\n\nCOMMANDS:\n{subcommands}\n\n{after-help}",
    after_help = "Examples:\n  unchained node start\n  unchained wallet receive\n  unchained wallet send --to <ADDRESS> --amount 100\n  unchained wallet balance\n  unchained offers watch\n  unchained x402 pay --url https://example.com/protected\n"
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
    /// Offer market commands
    Offers {
        #[command(subcommand)]
        cmd: OffersCmd,
    },
    /// Messaging commands
    Message {
        #[command(subcommand)]
        cmd: MessageCmd,
    },
    /// x402 payment commands
    X402 {
        #[command(subcommand)]
        cmd: X402Cmd,
    },
    /// Advanced protocol and maintenance commands
    Advanced {
        #[command(subcommand)]
        cmd: AdvancedCmd,
    },
    /// Start mining and block production (runs epoch manager and miners)
    #[command(hide = true)]
    Mine,
    /// Print the local libp2p peer ID and exit
    #[command(hide = true)]
    PeerId,
    /// Export your private receiving address (base64-url)
    #[command(alias = "stealth-address", hide = true)]
    Address(ReceiveArgs),
    /// Request a coin proof and verify it locally
    #[command(hide = true)]
    Proof(ProofArgs),
    /// Send coins to a receiver address with an out-of-band spend note
    #[command(hide = true)]
    Send(SendArgs),
    /// HTLC: Sender precomputes ch_refund (and optionally secrets) from plan
    #[command(hide = true)]
    HtlcRefundPrepare {
        /// Plan JSON from HtlcPlan
        #[arg(long)]
        plan: String,
        /// Optional hex/base64-url refund secret base; if omitted, random per-coin secrets are generated and saved
        #[arg(long)]
        refund_base: Option<String>,
        /// Output JSON for ch_refund mapping
        #[arg(long)]
        out: String,
        /// Optional output JSON to store refund secrets per coin (only used when refund_base is not provided)
        #[arg(long)]
        out_secrets: Option<String>,
    },
    /// Show the wallet balance
    #[command(hide = true)]
    Balance(BalanceArgs),
    /// Show wallet transaction history
    #[command(hide = true)]
    History(HistoryArgs),
    /// x402: Pay a 402 challenge at a protected URL and print X-PAYMENT header
    #[command(hide = true)]
    X402Pay(X402PayArgs),
    /// HTLC: Plan an offer (sender) and output a JSON plan
    #[command(hide = true)]
    HtlcPlan {
        #[arg(long)]
        paycode: String,
        #[arg(long)]
        amount: u64,
        /// Timeout epoch number T
        #[arg(long, value_parser = clap::value_parser!(u64))]
        timeout: u64,
        /// Output file to write the plan JSON
        #[arg(long)]
        out: String,
    },
    /// HTLC: Receiver computes claim CHs from claim secret and writes JSON
    #[command(hide = true)]
    HtlcClaimPrepare {
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)]
        claim_secret: String,
        /// Comma-separated coin ids (hex) to claim
        #[arg(long)]
        coins: String,
        /// Output JSON file to write claim CHs
        #[arg(long)]
        out: String,
    },
    /// HTLC: Execute sender offer (build spends with HTLC locks) using plan and receiver claim doc
    #[command(hide = true)]
    HtlcOfferExecute {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        claims: String,
        /// Optional hex/base64-url refund secret base to derive per-coin refund secrets deterministically
        #[arg(long)]
        refund_base: Option<String>,
        /// Optional path to write per-coin refund secrets; required if refund_base is not provided
        #[arg(long)]
        refund_secrets_out: Option<String>,
    },
    /// HTLC: Execute claim spends before timeout with claim secret
    #[command(hide = true)]
    HtlcClaim {
        #[arg(long)]
        timeout: u64,
        #[arg(long)]
        claim_secret: String,
        /// JSON file mapping coin_id -> ch_refund (computed on sender during offer execute)
        #[arg(long)]
        refunds: String,
        /// Receiver paycode for the next hop
        #[arg(long)]
        paycode: String,
    },
    /// HTLC: Execute refund at/after timeout with refund secret
    #[command(hide = true)]
    HtlcRefund {
        #[arg(long)]
        timeout: u64,
        #[arg(long)]
        refund_secret: String,
        /// JSON file mapping coin_id -> ch_claim (from receiver)
        #[arg(long)]
        claims: String,
        /// Sender paycode (destination for refunded coins)
        #[arg(long)]
        paycode: String,
    },
    /// Offer: Create and sign an offer from an HTLC plan
    #[command(hide = true)]
    OfferCreate {
        /// Receiver paycode
        #[arg(long)]
        paycode: String,
        /// Amount to offer
        #[arg(long)]
        amount: u64,
        /// Timeout epoch number T
        #[arg(long, value_parser = clap::value_parser!(u64))]
        timeout: u64,
        /// Optional maker price in basis points (10000 = 100%)
        #[arg(long)]
        price_bps: Option<u64>,
        /// Optional note/label
        #[arg(long)]
        note: Option<String>,
        /// Output JSON path for the signed offer
        #[arg(long)]
        out: String,
    },
    /// Offer: Publish a signed offer to the network
    #[command(hide = true)]
    OfferPublish {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
    },
    /// Offer: Watch incoming offers (prints JSON lines)
    #[command(hide = true)]
    OfferWatch(OfferWatchArgs),
    /// Offer: Verify a signed offer file
    #[command(hide = true)]
    OfferVerify {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
    },
    /// Offer: Accept a signed offer file (deterministic secrets policy)
    #[command(hide = true)]
    OfferAccept {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)]
        claim_secret: String,
        /// Refund base (deterministic per-coin), 32-byte hex/base64-url; if omitted, secrets are written to file
        #[arg(long)]
        refund_base: Option<String>,
        /// Path to write generated refund secrets per coin (required if --refund_base is absent)
        #[arg(long)]
        refund_secrets_out: Option<String>,
    },
    /// Offer: Prepare receiver claim CHs from an offer and claim secret
    #[command(hide = true)]
    OfferAcceptPrepare {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)]
        claim_secret: String,
        /// Output JSON file to write claim CHs
        #[arg(long)]
        out: String,
    },
    /// Scan and repair malformed spend entries (backs up and deletes invalid rows)
    #[command(hide = true)]
    RepairSpends,
    // Commitment request/response tooling removed
    /// P2P: Send a short text message (topic limited to 2 msgs/24h)
    #[command(hide = true)]
    MsgSend(MessageSendArgs),
    /// P2P: Listen for incoming messages on the 24h-limited topic
    #[command(hide = true)]
    MsgListen(MessageListenArgs),
    /// Re-gossip all spends from local DB (sender-side recovery)
    #[command(hide = true)]
    ReplaySpends,
    /// Rescan local spends against this wallet (receiver-side recovery)
    #[command(hide = true)]
    RescanWallet,
    /// Export all anchors into a compressed snapshot file
    #[command(hide = true)]
    ExportAnchors {
        /// Output file path (e.g. anchors_snapshot.zst)
        #[arg(long)]
        out: String,
    },
    /// Import anchors from a compressed snapshot file
    #[command(hide = true)]
    ImportAnchors {
        /// Input snapshot file path
        #[arg(long)]
        input: String,
    },
    /// Bridge: Lock UNCH on Unchained for a Sui recipient
    #[command(hide = true)]
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
    #[command(hide = true)]
    MetaAuthzCreate {
        /// Receiver paycode (base64-url)
        #[arg(long)]
        to: String,
        /// Total amount to authorize
        #[arg(long)]
        amount: u64,
        /// Valid after this epoch (inclusive)
        #[arg(long)]
        valid_after: u64,
        /// Valid before this epoch (exclusive)
        #[arg(long)]
        valid_before: u64,
        /// Facilitator Kyber768 public key (base64-url)
        #[arg(long)]
        facilitator_kyber_b64: String,
        /// Optional x402-style 32-byte binding (base64-url)
        #[arg(long)]
        binding_b64: Option<String>,
        /// Output file for the JSON document
        #[arg(long)]
        out: String,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Start the node runtime
    Start {
        /// Force mining on for this run
        #[arg(long, default_value_t = false)]
        mine: bool,
    },
    /// Print the local libp2p peer ID and shareable multiaddr
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
    /// Out-of-band spend note as hex or base64-url
    #[arg(long)]
    note: Option<String>,
    /// Write the shareable receiver note bundle to a file
    #[arg(long)]
    note_out: Option<String>,
    /// Copy the receiver note to the clipboard
    #[arg(long, default_value_t = false)]
    copy_note: bool,
    /// Render the receiver note as a terminal QR code
    #[arg(long, default_value_t = false)]
    show_note_qr: bool,
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
struct ProofArgs {
    #[arg(long)]
    coin_id: String,
}

#[derive(Args, Clone)]
struct OfferWatchArgs {
    /// Exit after receiving N offers (optional)
    #[arg(long)]
    count: Option<u64>,
    /// Minimum amount filter
    #[arg(long)]
    min_amount: Option<u64>,
    /// Filter by maker address (hex)
    #[arg(long)]
    maker: Option<String>,
    /// Resume from millis cursor
    #[arg(long)]
    since: Option<u128>,
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

#[derive(Args, Clone)]
struct X402PayArgs {
    /// URL to the protected resource (server will return 402 with challenge)
    #[arg(long)]
    url: String,
    /// Auto-resubmit and print the resource body after paying
    #[arg(long, default_value_t = true)]
    auto_resubmit: bool,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Show your shareable receiving address
    #[command(alias = "address")]
    Receive(ReceiveArgs),
    /// Send coins to a receiver, or run a guided send flow
    Send(SendArgs),
    /// Show wallet balance and spendable outputs
    Balance(BalanceArgs),
    /// Show wallet transaction history
    History(HistoryArgs),
}

#[derive(Subcommand)]
enum OffersCmd {
    /// Watch incoming offers (prints JSON lines)
    Watch(OfferWatchArgs),
    /// Create and sign an offer from an HTLC plan
    Create {
        /// Receiver paycode
        #[arg(long)]
        paycode: String,
        /// Amount to offer
        #[arg(long)]
        amount: u64,
        /// Timeout epoch number T
        #[arg(long, value_parser = clap::value_parser!(u64))]
        timeout: u64,
        /// Optional maker price in basis points (10000 = 100%)
        #[arg(long)]
        price_bps: Option<u64>,
        /// Optional note/label
        #[arg(long)]
        note: Option<String>,
        /// Output JSON path for the signed offer
        #[arg(long)]
        out: String,
    },
    /// Publish a signed offer to the network
    Publish {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
    },
    /// Verify a signed offer file
    Verify {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
    },
    /// Accept a signed offer file
    Accept {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)]
        claim_secret: String,
        /// Refund base (deterministic per-coin), 32-byte hex/base64-url
        #[arg(long)]
        refund_base: Option<String>,
        /// Path to write generated refund secrets per coin
        #[arg(long)]
        refund_secrets_out: Option<String>,
    },
    /// Prepare receiver claim CHs from an offer and claim secret
    AcceptPrepare {
        /// Input offer JSON path
        #[arg(long)]
        input: String,
        /// Claim secret s_claim (hex or base64-url)
        #[arg(long)]
        claim_secret: String,
        /// Output JSON file to write claim CHs
        #[arg(long)]
        out: String,
    },
}

#[derive(Subcommand)]
enum MessageCmd {
    /// Send a short text message on the bounded P2P topic
    Send(MessageSendArgs),
    /// Listen for incoming messages on the bounded P2P topic
    Listen(MessageListenArgs),
}

#[derive(Subcommand)]
enum X402Cmd {
    /// Pay a 402 challenge and optionally fetch the protected resource
    Pay(X402PayArgs),
}

#[derive(Subcommand)]
enum AdvancedCmd {
    /// Request a coin proof and verify it locally
    Proof(ProofArgs),
    /// HTLC: Sender precomputes refund commitments and secrets
    HtlcRefundPrepare {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        refund_base: Option<String>,
        #[arg(long)]
        out: String,
        #[arg(long)]
        out_secrets: Option<String>,
    },
    /// HTLC: Plan an offer (sender) and output a JSON plan
    HtlcPlan {
        #[arg(long)]
        paycode: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, value_parser = clap::value_parser!(u64))]
        timeout: u64,
        #[arg(long)]
        out: String,
    },
    /// HTLC: Receiver computes claim CHs from claim secret
    HtlcClaimPrepare {
        #[arg(long)]
        claim_secret: String,
        #[arg(long)]
        coins: String,
        #[arg(long)]
        out: String,
    },
    /// HTLC: Execute sender offer using a plan and receiver claim doc
    HtlcOfferExecute {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        claims: String,
        #[arg(long)]
        refund_base: Option<String>,
        #[arg(long)]
        refund_secrets_out: Option<String>,
    },
    /// HTLC: Execute claim spends before timeout
    HtlcClaim {
        #[arg(long)]
        timeout: u64,
        #[arg(long)]
        claim_secret: String,
        #[arg(long)]
        refunds: String,
        #[arg(long)]
        paycode: String,
    },
    /// HTLC: Execute refund at or after timeout
    HtlcRefund {
        #[arg(long)]
        timeout: u64,
        #[arg(long)]
        refund_secret: String,
        #[arg(long)]
        claims: String,
        #[arg(long)]
        paycode: String,
    },
    /// Scan and repair malformed spend entries
    RepairSpends,
    /// Re-gossip all spends from local DB
    ReplaySpends,
    /// Rescan local spends against this wallet
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
    /// Lock UNCH on Unchained for a Sui recipient
    BridgeOut {
        #[arg(long)]
        sui_recipient: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 12)]
        prewarm_secs: u64,
    },
    /// Create a signed authorization for facilitator submission
    MetaAuthzCreate {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        valid_after: u64,
        #[arg(long)]
        valid_before: u64,
        #[arg(long)]
        facilitator_kyber_b64: String,
        #[arg(long)]
        binding_b64: Option<String>,
        #[arg(long)]
        out: String,
    },
}

fn print_receive_output(wallet: &wallet::Wallet, args: &ReceiveArgs) -> anyhow::Result<()> {
    let address = wallet.export_address();
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

fn parse_note_bytes(note: Option<&str>) -> anyhow::Result<(Vec<u8>, bool, String)> {
    use rand::RngCore;

    let bytes = if let Some(note) = note {
        let t = note.trim();
        if let Ok(b) = hex::decode(t.trim_start_matches("0x")) {
            b
        } else if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t) {
            b
        } else {
            anyhow::bail!("Invalid note encoding; use hex or base64-url")
        }
    } else {
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        s.to_vec()
    };

    let note_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    Ok((bytes, note.is_none(), note_b64))
}

fn write_note_bundle(path: &str, note_b64: &str, to: &str, amount: u64) -> anyhow::Result<()> {
    let payload = serde_json::json!({
        "note": note_b64,
        "encoding": "base64url",
        "to": to,
        "amount": amount,
    });
    std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
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
        None => prompt_line("Receiver address: ")?,
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

    let (note_bytes, note_generated, note_b64) = parse_note_bytes(args.note.as_deref())?;
    if let Some(path) = &args.note_out {
        write_note_bundle(path, &note_b64, &to, amount)?;
    }
    if args.copy_note {
        let _ = copy_to_clipboard(&note_b64);
    }

    let outcome = wallet
        .send_with_paycode_and_note(&to, amount, net, &note_bytes)
        .await?;

    if args.json {
        let spends: Vec<serde_json::Value> = outcome
            .spends
            .iter()
            .map(|sp| {
                serde_json::json!({
                    "coin_id": hex::encode(sp.coin_id),
                    "commitment": hex::encode(sp.commitment),
                    "nullifier": hex::encode(sp.nullifier),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "to": to,
                "amount": amount,
                "spend_count": outcome.spends.len(),
                "note": note_b64,
                "note_generated": note_generated,
                "note_out": args.note_out,
                "spends": spends,
            })
        );
        return Ok(());
    }

    println!("Sent");
    println!();
    println!(
        "Broadcast {} spend{} for {} coin{}.",
        outcome.spends.len(),
        if outcome.spends.len() == 1 { "" } else { "s" },
        amount,
        if amount == 1 { "" } else { "s" }
    );
    println!("Recipient: {}", short_text(&to));
    println!();
    println!("Share this receiver note privately:");
    println!("{note_b64}");
    if args.copy_note {
        println!("Copied receiver note to clipboard.");
    }
    if args.show_note_qr || guided {
        println!();
        let _ = print_qr_to_terminal(&note_b64);
    }
    if let Some(path) = &args.note_out {
        println!();
        println!("Saved note bundle to {path}");
    }
    println!();
    println!("Track confirmation with `unchained wallet history`.");
    Ok(())
}

fn print_balance_output(wallet: &wallet::Wallet, args: &BalanceArgs) -> anyhow::Result<()> {
    let balance = wallet.balance()?;
    let outputs = wallet.list_unspent()?.len();
    let address = wallet.export_address();
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
    let id = network::peer_id_string()?;
    println!("Peer ID");
    println!();
    println!("{id}");
    if let Some(ip) = &cfg.net.public_ip {
        println!();
        println!(
            "Shareable multiaddr: /ip4/{}/udp/{}/quic-v1/p2p/{}",
            ip, cfg.net.listen_port, id
        );
    }
    Ok(())
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
        }) | Some(Cmd::Mine)
    );
    let force_mine = matches!(
        &cli.cmd,
        Some(Cmd::Mine)
            | Some(Cmd::Node {
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

    if matches!(
        &cli.cmd,
        Some(Cmd::Node {
            cmd: NodeCmd::PeerId
        }) | Some(Cmd::PeerId)
    ) {
        print_peer_id_output(&cfg)?;
        return Ok(());
    }

    // Apply quiet logging preference: CLI flag overrides config
    if cli.quiet_net {
        network::set_quiet_logging(true);
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
        })
        | Some(Cmd::Address(args)) => {
            print_receive_output(wallet.as_ref(), args)?;
            return Ok(());
        }
        Some(Cmd::Wallet {
            cmd: WalletCmd::Balance(args),
        })
        | Some(Cmd::Balance(args)) => {
            print_balance_output(wallet.as_ref(), args)?;
            return Ok(());
        }
        Some(Cmd::Wallet {
            cmd: WalletCmd::History(args),
        })
        | Some(Cmd::History(args)) => {
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
        cfg.offers.clone(),
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
                        for sp in tx.spends {
                            let _ = wallet_clone.scan_spend_for_me(&sp);
                        }
                    },
                    Ok(_a) = anchor_rx.recv() => {
                        // On anchor adoption, rescan all spends idempotently (bounded by CF contents)
                        if let Some(cf) = db_clone.db.cf_handle("spend") {
                            let iter = db_clone.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
                            for item in iter {
                                if let Ok((_k, v)) = item {
                                    if let Ok(sp) = db_clone.decode_spend_bytes(&v) {
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
        })
        | Some(Cmd::Mine) => {
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
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::Proof(ProofArgs { coin_id }),
        })
        | Some(Cmd::Proof(ProofArgs { coin_id })) => {
            // Parse coin id
            let id_vec =
                hex::decode(coin_id).map_err(|e| anyhow::anyhow!("Invalid coin_id hex: {}", e))?;
            if id_vec.len() != 32 {
                return Err(anyhow::anyhow!("coin_id must be 32 bytes"));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&id_vec);

            // Subscribe to proof responses and wait for matching coin_id
            let mut rx = net.proof_subscribe();
            net.request_coin_proof(id).await;
            println!(
                "📨 Requested proof for coin {} (waiting up to 30s)",
                hex::encode(id)
            );
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
        Some(Cmd::Wallet {
            cmd: WalletCmd::Send(args),
        })
        | Some(Cmd::Send(args)) => {
            run_send_flow(&wallet, &net, args).await?;
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::HtlcPlan {
                    paycode,
                    amount,
                    timeout,
                    out,
                },
        })
        | Some(Cmd::HtlcPlan {
            paycode,
            amount,
            timeout,
            out,
        }) => {
            let plan = wallet.plan_htlc_offer(*amount, paycode, *timeout)?;
            let json = serde_json::to_string_pretty(&plan)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote HTLC plan to {} (timeout epoch {})", out, timeout);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::HtlcClaimPrepare {
                    claim_secret,
                    coins,
                    out,
                },
        })
        | Some(Cmd::HtlcClaimPrepare {
            claim_secret,
            coins,
            out,
        }) => {
            let claim_bytes = {
                let s = claim_secret.trim();
                if let Ok(b) = hex::decode(s.trim_start_matches("0x")) {
                    b
                } else {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?
                }
            };
            if claim_bytes.is_empty() {
                return Err(anyhow::anyhow!("claim_secret empty"));
            }
            let mut entries = Vec::new();
            for hex_id in coins.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                let id_vec = hex::decode(hex_id)
                    .map_err(|e| anyhow::anyhow!("Invalid coin id {}: {}", hex_id, e))?;
                if id_vec.len() != 32 {
                    return Err(anyhow::anyhow!("coin id {} must be 32 bytes", hex_id));
                }
                let mut coin_id = [0u8; 32];
                coin_id.copy_from_slice(&id_vec);
                let chain_id = db.get_chain_id()?;
                let ch = crypto::commitment_hash_from_preimage(&chain_id, &coin_id, &claim_bytes);
                entries.push(crate::wallet::HtlcClaimsDocEntry {
                    coin_id,
                    ch_claim: ch,
                });
            }
            let doc = crate::wallet::HtlcClaimsDoc { claims: entries };
            let json = serde_json::to_string_pretty(&doc)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote HTLC claim CHs to {}", out);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::HtlcOfferExecute {
                    plan,
                    claims,
                    refund_base,
                    refund_secrets_out,
                },
        })
        | Some(Cmd::HtlcOfferExecute {
            plan,
            claims,
            refund_base,
            refund_secrets_out,
        }) => {
            let plan_doc: crate::wallet::HtlcPlanDoc =
                serde_json::from_slice(&std::fs::read(plan)?)?;
            let claims_doc: crate::wallet::HtlcClaimsDoc =
                serde_json::from_slice(&std::fs::read(claims)?)?;
            if refund_base.is_none() && refund_secrets_out.is_none() {
                return Err(anyhow::anyhow!("Provide either --refund_base (deterministic) or --refund_secrets_out to persist generated secrets"));
            }
            let refund_base_bytes: Option<Vec<u8>> = if let Some(b) = refund_base {
                let t = b.trim();
                if let Ok(h) = hex::decode(t.trim_start_matches("0x")) {
                    Some(h)
                } else {
                    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t)?)
                }
            } else {
                None
            };
            let outcome = wallet
                .execute_htlc_offer(
                    &plan_doc,
                    &claims_doc,
                    &net,
                    refund_base_bytes.as_deref(),
                    refund_secrets_out.as_deref(),
                    None,
                )
                .await?;
            println!(
                "✅ Built and broadcast {} HTLC offer spend(s)",
                outcome.spends.len()
            );
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::HtlcRefundPrepare {
                    plan,
                    refund_base,
                    out,
                    out_secrets,
                },
        })
        | Some(Cmd::HtlcRefundPrepare {
            plan,
            refund_base,
            out,
            out_secrets,
        }) => {
            let plan_doc: crate::wallet::HtlcPlanDoc =
                serde_json::from_slice(&std::fs::read(plan)?)?;
            let chain_id = plan_doc.chain_id;
            let mut refunds = Vec::new();
            let mut secrets_dump: Vec<(String, String)> = Vec::new();
            use rand::RngCore;
            for c in &plan_doc.coins {
                let secret: [u8; 32] = if let Some(b) = refund_base {
                    let base_bytes = if let Ok(h) = hex::decode(b.trim().trim_start_matches("0x")) {
                        h
                    } else {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b.trim())?
                    };
                    let mut h = blake3::Hasher::new_derive_key("unchained.htlc.refund.base");
                    h.update(&base_bytes);
                    h.update(&c.coin_id);
                    let mut out = [0u8; 32];
                    h.finalize_xof().fill(&mut out);
                    out
                } else {
                    let mut s = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut s);
                    secrets_dump.push((hex::encode(c.coin_id), hex::encode(s)));
                    s
                };
                let ch = crypto::commitment_hash_from_preimage(&chain_id, &c.coin_id, &secret);
                refunds.push(crate::wallet::HtlcRefundsDocEntry {
                    coin_id: c.coin_id,
                    ch_refund: ch,
                });
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
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::HtlcClaim {
                    timeout,
                    claim_secret,
                    refunds,
                    paycode,
                },
        })
        | Some(Cmd::HtlcClaim {
            timeout,
            claim_secret,
            refunds,
            paycode,
        }) => {
            // Guard: Claim only valid when current_epoch < T
            let current_epoch = db
                .get::<epoch::Anchor>("epoch", b"latest")?
                .map(|a| a.num)
                .unwrap_or(0);
            if current_epoch >= *timeout {
                return Err(anyhow::anyhow!(
                    "Claim path not valid: current_epoch={} ≥ T={}. Use htlc-refund instead.",
                    current_epoch,
                    timeout
                ));
            }
            let refunds_doc: crate::wallet::HtlcRefundsDoc =
                serde_json::from_slice(&std::fs::read(refunds)?)?;
            let mut map = std::collections::HashMap::new();
            for e in refunds_doc.refunds {
                map.insert(e.coin_id, e.ch_refund);
            }
            let s_bytes = {
                let s = claim_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) {
                    h
                } else {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?
                }
            };
            let outcome = wallet
                .htlc_claim(*timeout, &s_bytes, &map, paycode, &net, None)
                .await?;
            println!(
                "✅ Built and broadcast {} HTLC claim spend(s)",
                outcome.spends.len()
            );
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::HtlcRefund {
                    timeout,
                    refund_secret,
                    claims,
                    paycode,
                },
        })
        | Some(Cmd::HtlcRefund {
            timeout,
            refund_secret,
            claims,
            paycode,
        }) => {
            // Guard: Refund only valid when current_epoch ≥ T
            let current_epoch = db
                .get::<epoch::Anchor>("epoch", b"latest")?
                .map(|a| a.num)
                .unwrap_or(0);
            if current_epoch < *timeout {
                return Err(anyhow::anyhow!(
                    "Refund path not valid: current_epoch={} < T={}. Use htlc-claim instead.",
                    current_epoch,
                    timeout
                ));
            }
            let claims_doc: crate::wallet::HtlcClaimsDoc =
                serde_json::from_slice(&std::fs::read(claims)?)?;
            let mut map = std::collections::HashMap::new();
            for e in claims_doc.claims {
                map.insert(e.coin_id, e.ch_claim);
            }
            let s_bytes = {
                let s = refund_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) {
                    h
                } else {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?
                }
            };
            let outcome = wallet
                .htlc_refund(*timeout, &s_bytes, &map, paycode, &net, None)
                .await?;
            println!(
                "✅ Built and broadcast {} HTLC refund spend(s)",
                outcome.spends.len()
            );
            return Ok(());
        }
        Some(Cmd::Offers {
            cmd:
                OffersCmd::Create {
                    paycode,
                    amount,
                    timeout,
                    price_bps,
                    note,
                    out,
                },
        })
        | Some(Cmd::OfferCreate {
            paycode,
            amount,
            timeout,
            price_bps,
            note,
            out,
        }) => {
            let plan = wallet.plan_htlc_offer(*amount, paycode, *timeout)?;
            let offer = wallet.create_offer_doc(plan, *price_bps, note.clone())?;
            let json = serde_json::to_string_pretty(&offer)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote signed offer to {}", out);
            return Ok(());
        }
        Some(Cmd::Offers {
            cmd: OffersCmd::Verify { input },
        })
        | Some(Cmd::OfferVerify { input }) => {
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            println!("✅ Offer signature and maker address verified");
            return Ok(());
        }
        Some(Cmd::Offers {
            cmd:
                OffersCmd::Accept {
                    input,
                    claim_secret,
                    refund_base,
                    refund_secrets_out,
                },
        })
        | Some(Cmd::OfferAccept {
            input,
            claim_secret,
            refund_base,
            refund_secrets_out,
        }) => {
            // 1) Verify offer
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            // 2) Build receiver claim doc deterministically from provided claim_secret
            let s_bytes = {
                let s = claim_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) {
                    h
                } else {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?
                }
            };
            if s_bytes.len() != 32 {
                return Err(anyhow::anyhow!("claim_secret must be 32 bytes"));
            }
            let mut claims = Vec::new();
            for c in &offer.plan.coins {
                let ch = crypto::commitment_hash_from_preimage(
                    &offer.plan.chain_id,
                    &c.coin_id,
                    &s_bytes,
                );
                claims.push(crate::wallet::HtlcClaimsDocEntry {
                    coin_id: c.coin_id,
                    ch_claim: ch,
                });
            }
            let claims_doc = crate::wallet::HtlcClaimsDoc { claims };
            // 3) Execute HTLC offer spends via wallet; never print secrets, only file output if requested
            if refund_base.is_none() && refund_secrets_out.is_none() {
                return Err(anyhow::anyhow!("Provide either --refund_base (deterministic) or --refund_secrets_out to persist generated secrets"));
            }
            let refund_base_bytes: Option<Vec<u8>> = if let Some(b) = refund_base {
                let t = b.trim();
                if let Ok(h) = hex::decode(t.trim_start_matches("0x")) {
                    Some(h)
                } else {
                    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(t)?)
                }
            } else {
                None
            };
            let outcome = wallet
                .execute_htlc_offer(
                    &offer.plan,
                    &claims_doc,
                    &net,
                    refund_base_bytes.as_deref(),
                    refund_secrets_out.as_deref(),
                    None,
                )
                .await?;
            println!(
                "✅ Accepted offer. Built and broadcast {} spend(s)",
                outcome.spends.len()
            );
            return Ok(());
        }
        Some(Cmd::Offers {
            cmd: OffersCmd::Publish { input },
        })
        | Some(Cmd::OfferPublish { input }) => {
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            // Publish via network
            // Use binary bincode payload to match network path
            // Reuse GossipOffer command
            net.gossip_offer(&offer).await;
            println!("📢 Published offer to network");
            return Ok(());
        }
        Some(Cmd::Offers {
            cmd:
                OffersCmd::Watch(OfferWatchArgs {
                    count,
                    min_amount,
                    maker,
                    since: _,
                }),
        })
        | Some(Cmd::OfferWatch(OfferWatchArgs {
            count,
            min_amount,
            maker,
            since: _,
        })) => {
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
        Some(Cmd::Offers {
            cmd:
                OffersCmd::AcceptPrepare {
                    input,
                    claim_secret,
                    out,
                },
        })
        | Some(Cmd::OfferAcceptPrepare {
            input,
            claim_secret,
            out,
        }) => {
            // Verify offer and emit receiver-side claim CHs for coins listed in maker plan
            let offer: crate::wallet::OfferDocV1 = serde_json::from_slice(&std::fs::read(input)?)?;
            wallet::Wallet::verify_offer_doc(&offer)?;
            let s_bytes = {
                let s = claim_secret.trim();
                if let Ok(h) = hex::decode(s.trim_start_matches("0x")) {
                    h
                } else {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?
                }
            };
            if s_bytes.len() != 32 {
                return Err(anyhow::anyhow!("claim_secret must be 32 bytes"));
            }
            let mut entries = Vec::new();
            for c in &offer.plan.coins {
                let ch = crypto::commitment_hash_from_preimage(
                    &offer.plan.chain_id,
                    &c.coin_id,
                    &s_bytes,
                );
                entries.push(crate::wallet::HtlcClaimsDocEntry {
                    coin_id: c.coin_id,
                    ch_claim: ch,
                });
            }
            let doc = crate::wallet::HtlcClaimsDoc { claims: entries };
            let json = serde_json::to_string_pretty(&doc)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote claim CHs for {} coins", doc.claims.len());
            return Ok(());
        }
        Some(Cmd::X402 {
            cmd: X402Cmd::Pay(X402PayArgs { url, auto_resubmit }),
        })
        | Some(Cmd::X402Pay(X402PayArgs { url, auto_resubmit })) => {
            // Fetch challenge
            let client = reqwest::Client::new();
            let resp = client.get(url).send().await?;
            if resp.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
                eprintln!("Expected 402, got {}", resp.status());
                return Err(anyhow::anyhow!("not a 402"));
            }
            let challenge_json = resp.text().await?;
            // Pay using wallet and produce header
            let header = wallet
                .x402_pay_from_challenge(&challenge_json, &net)
                .await?;
            println!("X-PAYMENT: {}", header);
            if *auto_resubmit {
                let resp2 = client
                    .get(url)
                    .header(crate::x402::HEADER_X_PAYMENT, header)
                    .send()
                    .await?;
                if !resp2.status().is_success() {
                    eprintln!("Resubmit failed: {}", resp2.status());
                    return Err(anyhow::anyhow!("resubmit failed"));
                }
                let body = resp2.text().await.unwrap_or_default();
                println!("{}", body);
            }
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::RepairSpends,
        })
        | Some(Cmd::RepairSpends) => {
            println!("🛠️  Scanning 'spend' CF for malformed entries...");
            let cf = db
                .db
                .cf_handle("spend")
                .ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let backup_dir = format!(
                "{}/backups_spend_repair/{}",
                cfg.storage.path,
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            );
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
            println!(
                "✅ Repair complete. Scanned: {}, deleted malformed: {}. Backup dir: {}",
                scanned, repaired, backup_dir
            );
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::ExportAnchors { out },
        })
        | Some(Cmd::ExportAnchors { out }) => {
            let written = db.export_anchors_snapshot(out)?;
            println!("✅ Exported {} anchors to {}", written, out);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::ImportAnchors { input },
        })
        | Some(Cmd::ImportAnchors { input }) => {
            let added = db.import_anchors_snapshot(input)?;
            println!("✅ Imported {} anchors from {}", added, input);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::BridgeOut {
                    sui_recipient,
                    amount,
                    prewarm_secs,
                },
        })
        | Some(Cmd::BridgeOut {
            sui_recipient,
            amount,
            prewarm_secs,
        }) => {
            // Optional: pre-warm proofs for inputs that will cover the amount
            if *prewarm_secs > 0 {
                match wallet.select_inputs(*amount) {
                    Ok(coins) => {
                        let mut rx = net.proof_subscribe();
                        for c in coins.iter() {
                            net.request_coin_proof(c.id).await;
                        }
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(*prewarm_secs);
                        loop {
                            let remaining =
                                deadline.saturating_duration_since(std::time::Instant::now());
                            if remaining.is_zero() {
                                break;
                            }
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
            )
            .await
            {
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
        Some(Cmd::Advanced {
            cmd:
                AdvancedCmd::MetaAuthzCreate {
                    to,
                    amount,
                    valid_after,
                    valid_before,
                    facilitator_kyber_b64,
                    binding_b64,
                    out,
                },
        })
        | Some(Cmd::MetaAuthzCreate {
            to,
            amount,
            valid_after,
            valid_before,
            facilitator_kyber_b64,
            binding_b64,
            out,
        }) => {
            // Parse facilitator Kyber PK
            let fac_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(facilitator_kyber_b64.trim())
                .or_else(|_| {
                    base64::engine::general_purpose::URL_SAFE.decode(facilitator_kyber_b64.trim())
                })
                .map_err(|_| anyhow::anyhow!("invalid base64 for facilitator kyber pk"))?;
            let fac_pk = pqcrypto_kyber::kyber768::PublicKey::from_bytes(&fac_bytes)
                .map_err(|_| anyhow::anyhow!("invalid facilitator kyber pk bytes"))?;
            // Optional binding
            let binding_opt: Option<[u8; 32]> = if let Some(b) = binding_b64 {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(b.trim())
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b.trim()))
                    .map_err(|_| anyhow::anyhow!("invalid base64 for binding"))?;
                if raw.len() != 32 {
                    return Err(anyhow::anyhow!("binding must be 32 bytes"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                Some(arr)
            } else {
                None
            };
            let authz = wallet.authorize_meta_transfer(
                to,
                *amount,
                *valid_after,
                *valid_before,
                &fac_pk,
                binding_opt,
            )?;
            let json = serde_json::to_string_pretty(&authz)?;
            std::fs::write(out, json)?;
            println!("✅ Wrote meta authorization JSON");
            return Ok(());
        }
        // commitment commands removed
        Some(Cmd::Message {
            cmd: MessageCmd::Send(MessageSendArgs { text }),
        })
        | Some(Cmd::MsgSend(MessageSendArgs { text })) => {
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
        })
        | Some(Cmd::MsgListen(MessageListenArgs { once, count })) => {
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
            cmd: AdvancedCmd::ReplaySpends,
        })
        | Some(Cmd::ReplaySpends) => {
            let cf = db
                .db
                .cf_handle("spend")
                .ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
            let mut replayed = 0u64;
            for item in iter {
                let (_k, v) = item?;
                if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&v) {
                    let tx = crate::transaction::Tx::single_spend(sp);
                    net.gossip_tx(&tx).await;
                    replayed += 1;
                }
            }
            println!("✅ Re-gossiped {} transactions", replayed);
            return Ok(());
        }
        Some(Cmd::Advanced {
            cmd: AdvancedCmd::RescanWallet,
        })
        | Some(Cmd::RescanWallet) => {
            let cf = db
                .db
                .cf_handle("spend")
                .ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;
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
        Some(Cmd::Node {
            cmd: NodeCmd::PeerId,
        })
        | Some(Cmd::PeerId)
        | Some(Cmd::Wallet {
            cmd: WalletCmd::Receive(_),
        })
        | Some(Cmd::Wallet {
            cmd: WalletCmd::Balance(_),
        })
        | Some(Cmd::Wallet {
            cmd: WalletCmd::History(_),
        })
        | Some(Cmd::Address(_))
        | Some(Cmd::Balance(_))
        | Some(Cmd::History(_)) => {
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
    // Start offers HTTP API only when explicitly enabled.
    if cfg.offers.api_enabled {
        let offers_cfg = cfg.offers.clone();
        let db_h = db.clone();
        let net_h = net.clone();
        tokio::spawn(async move {
            let _ = offers::serve(offers_cfg, db_h, net_h).await;
        });
    }
    // Start bridge/x402 RPC only when explicitly enabled.
    if cfg.bridge.bridge_enabled || cfg.bridge.x402_enabled {
        let bridge_cfg = cfg.bridge.clone();
        let db_h = db.clone();
        let wallet_h = wallet.clone();
        let net_h = net.clone();
        tokio::spawn(async move {
            let _ = bridge::serve(bridge_cfg, db_h, wallet_h, net_h).await;
        });
    }

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
