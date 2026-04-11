use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{de::DeserializeOwned, Serialize};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;
use tokio::time::Duration;

use crate::{
    canonical, config, discovery, epoch, ingress, metrics, network, node_control, node_identity,
    proof_assistant, protocol, storage, sync, wallet, wallet_control,
};
use crate::{
    consensus::ValidatorId,
    evidence::SlashableEvidence,
    network::NetHandle,
    staking::{
        ValidatorMetadata, ValidatorPool, ValidatorProfileUpdate, ValidatorReactivation,
        ValidatorRegistration, ValidatorStatus,
    },
    storage::{Store, WalletStore},
    sync::SyncState,
    transaction::{PenaltyEvidenceAdmission, SharedStateAction, SharedStateControlDocument, Tx},
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
    long_about = "Run the Unchained network node, bootstrap identity, manage network-facing maintenance tasks, own canonical chain state, and host the local node control plane for wallet and validator-facing services.",
    after_help = "Examples:\n  unchained_node init-root\n  unchained_node auth-prepare --out auth_request.txt\n  unchained_node auth-sign --request auth_request.txt --out node_record.txt\n  unchained_node auth-install --record node_record.txt\n  unchained_node validator-register-doc --bonded-stake 100 --activation-epoch 2 --commission-bps 250 --display-name \"Validator\" --out validator_register.json\n  unchained_node discovery-status --json\n  unchained_node discovery-export-snapshot --out discovery.snapshot\n  unchained_node discovery-import-snapshot --input discovery.snapshot\n  unchained_node start\n"
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
    long_about = "Operate the Unchained shielded wallet service, publish a PIR-resolvable receive locator, mint one-time invoice capabilities for merchant-style flows, send shielded transactions, and inspect wallet state through the capability-authenticated wallet control plane. Start the required network services, then `unchained_wallet serve`, and use the remaining wallet commands as clients of that running wallet service.",
    after_help = "Examples:\n  unchained_node start\n  unchained_node start-discovery\n  unchained_wallet serve\n  unchained_wallet receive\n  unchained_wallet receive-rotate\n  unchained_wallet receive-compromise\n  unchained_wallet resolve --locator <LOCATOR>\n  unchained_wallet request-handle --locator <LOCATOR> --amount 100\n  unchained_wallet invoice --amount 100\n  unchained_wallet send --to <LOCATOR> --amount 100\n  unchained_wallet send --invoice <RECIPIENT_INVOICE_JSON> --amount 100\n  unchained_wallet submit-control --document validator_register.json\n  unchained_wallet balance\n  unchained_wallet history\n"
)]
struct WalletCli {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    cmd: WalletCmd,
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
    /// Build and cold-sign a validator registration control document
    ValidatorRegisterDoc(ValidatorRegisterDocArgs),
    /// Build and cold-sign a validator profile-update control document
    ValidatorProfileDoc(ValidatorProfileDocArgs),
    /// Build and cold-sign a validator reactivation control document
    ValidatorReactivateDoc(ValidatorReactivateDocArgs),
    /// Build a penalty-evidence admission control document
    PenaltyEvidenceDoc(PenaltyEvidenceDocArgs),
    /// Start the node runtime
    Start,
    /// Start the access relay role for ordinary-path wallet ingress
    StartAccessRelay,
    /// Start the submission gateway role for ordinary-path wallet ingress
    StartSubmissionGateway,
    /// Start the remote proof-assistant role for sender wallets
    StartProofAssistant,
    /// Start the PIR-backed discovery and mailbox service
    StartDiscovery,
    /// Query the live discovery service for manifest and queue status
    DiscoveryStatus(DiscoveryStatusArgs),
    /// Export a signed discovery snapshot bundle for mirror rollout or disaster recovery
    DiscoveryExportSnapshot {
        #[arg(long)]
        out: String,
    },
    /// Import a signed discovery snapshot bundle into the local discovery state
    DiscoveryImportSnapshot {
        #[arg(long)]
        input: String,
    },
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
    #[arg(long, conflicts_with = "to")]
    invoice: Option<String>,
    #[arg(long)]
    amount: Option<u64>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone, Default)]
struct DiscoveryStatusArgs {
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

#[derive(Args, Clone)]
struct SubmitControlArgs {
    #[arg(long)]
    document: String,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone)]
struct InvoiceArgs {
    #[arg(long)]
    amount: Option<u64>,
    #[command(flatten)]
    output: ReceiveArgs,
}

#[derive(Args, Clone)]
struct ResolveArgs {
    #[arg(long)]
    locator: String,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Clone)]
struct RequestHandleArgs {
    #[arg(long)]
    locator: String,
    #[arg(long)]
    amount: u64,
    #[arg(long, default_value_t = 15)]
    timeout_secs: u64,
    #[command(flatten)]
    output: ReceiveArgs,
}

#[derive(Args, Clone)]
struct ValidatorRegisterDocArgs {
    #[arg(long)]
    node_record: Option<String>,
    #[arg(long)]
    bonded_stake: u64,
    #[arg(long)]
    activation_epoch: u64,
    #[arg(long)]
    commission_bps: u16,
    #[arg(long)]
    display_name: String,
    #[arg(long)]
    website: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args, Clone)]
struct ValidatorProfileDocArgs {
    #[arg(long)]
    validator_id: Option<String>,
    #[arg(long)]
    commission_bps: u16,
    #[arg(long)]
    display_name: String,
    #[arg(long)]
    website: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args, Clone)]
struct ValidatorReactivateDocArgs {
    #[arg(long)]
    validator_id: Option<String>,
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args, Clone)]
struct PenaltyEvidenceDocArgs {
    #[arg(long)]
    evidence: String,
    #[arg(long)]
    out: Option<String>,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Host the local wallet control socket used by other runtimes
    Serve,
    /// Publish and print the PIR-resolvable receive locator
    Receive(ReceiveArgs),
    /// Force-rotate the ordinary offline receive capability and republish the locator
    ReceiveRotate(ReceiveArgs),
    /// Mark the current ordinary offline receive capability compromised, rotate it, and republish the locator
    ReceiveCompromise(ReceiveArgs),
    /// Resolve a locator through PIR and print the authenticated discovery record summary
    Resolve(ResolveArgs),
    /// Request a one-time negotiated recipient handle for a policy-bound receive flow
    RequestHandle(RequestHandleArgs),
    /// Mint and print a one-time invoice capability for merchant-style direct payment
    Invoice(InvoiceArgs),
    /// Send coins using a receive locator or an explicit invoice capability
    Send(SendArgs),
    /// Submit a signed fee-paid shared-state control document through the running wallet
    SubmitControl(SubmitControlArgs),
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

fn open_optional_node_control_client(
    cfg: &config::Config,
) -> Result<Option<node_control::NodeControlClient>> {
    let client = node_control::NodeControlClient::new(&cfg.storage.path);
    match client.ping() {
        Ok(()) => Ok(Some(client)),
        Err(_err)
            if normalized_config_item(cfg.ingress.wallet.relay.as_deref()).is_some()
                && normalized_config_item(cfg.ingress.wallet.gateway.as_deref()).is_some() =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

async fn open_wallet_control_client(
    cfg: &config::Config,
) -> Result<wallet_control::WalletControlClient> {
    let client = wallet_control::WalletControlClient::new(&cfg.storage.path);
    client.ping().await?;
    Ok(client)
}

async fn try_open_wallet_control_client(
    cfg: &config::Config,
) -> Option<wallet_control::WalletControlClient> {
    open_wallet_control_client(cfg).await.ok()
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

fn write_json_output<T: Serialize>(label: &str, value: &T, out: Option<&str>) -> Result<()> {
    let encoded = serde_json::to_string_pretty(value)?;
    if let Some(path) = out {
        std::fs::write(path, format!("{encoded}\n"))?;
        println!("Wrote {path}");
        println!();
    }
    println!("{label}");
    println!();
    println!("{encoded}");
    Ok(())
}

fn load_json_document<T: DeserializeOwned>(path: &str, label: &str) -> Result<T> {
    let bytes = std::fs::read(path)
        .map_err(|err| anyhow!("failed to read {label} document from {path}: {err}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| anyhow!("failed to parse {label} document at {path}: {err}"))
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

fn parse_validator_id_hex(value: &str) -> Result<ValidatorId> {
    Ok(ValidatorId(parse_node_id_hex(value)?))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn normalized_config_item(value: Option<&str>) -> Option<&str> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn validator_metadata(
    display_name: String,
    website: Option<String>,
    description: Option<String>,
) -> ValidatorMetadata {
    ValidatorMetadata {
        display_name,
        website,
        description,
    }
}

fn require_local_chain_id(cfg: &config::Config) -> Result<[u8; 32]> {
    load_identity_chain_id(&cfg.storage.path)?.ok_or_else(|| {
        anyhow!("local chain id is unavailable; initialize canonical chain state first")
    })
}

fn listen_addr(cfg: &config::Config) -> std::net::SocketAddr {
    std::net::SocketAddr::from(([0, 0, 0, 0], cfg.net.listen_port))
}

fn load_runtime_identity(cfg: &config::Config) -> Result<node_identity::NodeIdentity> {
    node_identity::NodeIdentity::load_runtime_in_dir(
        &cfg.storage.path,
        protocol::CURRENT.version,
        load_identity_chain_id(&cfg.storage.path)?,
        published_identity_addresses(cfg),
    )
}

fn load_validated_service_record(item: &str, label: &str) -> Result<node_identity::NodeRecordV3> {
    let record = node_identity::load_node_record(item)
        .map_err(|err| anyhow!("failed to load {label} node record: {err}"))?;
    record.validate(now_unix_ms())?;
    Ok(record)
}

fn load_ingress_record(
    item: &str,
    label: &str,
    expected_chain_id: [u8; 32],
) -> Result<node_identity::NodeRecordV3> {
    let record = load_validated_service_record(item, label)?;
    if record.chain_id != Some(expected_chain_id) {
        bail!(
            "{label} node record is bound to chain {}, expected {}",
            record
                .chain_id
                .map(hex::encode)
                .unwrap_or_else(|| "unbound".to_string()),
            hex::encode(expected_chain_id),
        );
    }
    Ok(record)
}

fn load_ingress_records(
    items: &[String],
    label: &str,
    expected_chain_id: [u8; 32],
) -> Result<Vec<node_identity::NodeRecordV3>> {
    items
        .iter()
        .map(|item| load_ingress_record(item, label, expected_chain_id))
        .collect()
}

fn build_wallet_ingress_client(
    cfg: &config::Config,
    expected_chain_id: Option<[u8; 32]>,
) -> Result<Option<ingress::IngressClient>> {
    let relay = normalized_config_item(cfg.ingress.wallet.relay.as_deref());
    let gateway = normalized_config_item(cfg.ingress.wallet.gateway.as_deref());
    match (relay, gateway) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => bail!(
            "wallet ingress requires both [ingress.wallet].relay and [ingress.wallet].gateway"
        ),
        (Some(relay), Some(gateway)) => {
            let relay_record = if let Some(chain_id) = expected_chain_id {
                load_ingress_record(relay, "access relay", chain_id)?
            } else {
                load_validated_service_record(relay, "access relay")?
            };
            let gateway_record = if let Some(chain_id) = expected_chain_id {
                load_ingress_record(gateway, "submission gateway", chain_id)?
            } else {
                load_validated_service_record(gateway, "submission gateway")?
            };
            Ok(Some(ingress::IngressClient::new(
                relay_record,
                gateway_record,
                cfg.ingress.wallet.envelope_size_bytes,
                Duration::from_secs(cfg.ingress.wallet.submit_timeout_secs),
            )?))
        }
    }
}

fn build_wallet_proof_assistant_client(
    cfg: &config::Config,
    expected_chain_id: Option<[u8; 32]>,
) -> Result<Option<proof_assistant::ProofAssistantClient>> {
    let server = normalized_config_item(cfg.proof_assistant.wallet.server.as_deref());
    let Some(server) = server else {
        return Ok(None);
    };
    let record = load_validated_service_record(server, "proof assistant")?;
    let chain_id = record
        .chain_id
        .ok_or_else(|| anyhow!("proof assistant node record must be bound to a chain"))?;
    if let Some(expected_chain_id) = expected_chain_id {
        if chain_id != expected_chain_id {
            bail!(
                "proof assistant node record is bound to chain {}, expected {}",
                hex::encode(chain_id),
                hex::encode(expected_chain_id),
            );
        }
    }
    Ok(Some(proof_assistant::ProofAssistantClient::new(
        record,
        cfg.proof_assistant.wallet.max_request_bytes,
        cfg.proof_assistant.wallet.max_response_bytes,
        Duration::from_secs(cfg.proof_assistant.wallet.submit_timeout_secs),
    )?))
}

fn build_wallet_discovery_client(
    cfg: &config::Config,
    expected_chain_id: Option<[u8; 32]>,
) -> Result<Option<discovery::DiscoveryClient>> {
    let server = normalized_config_item(cfg.discovery.wallet.server.as_deref());
    let Some(server) = server else {
        return Ok(None);
    };
    let record = load_validated_service_record(server, "discovery")?;
    let chain_id = record
        .chain_id
        .ok_or_else(|| anyhow!("discovery node record must be bound to a chain"))?;
    if let Some(expected_chain_id) = expected_chain_id {
        if chain_id != expected_chain_id {
            bail!(
                "discovery node record is bound to chain {}, expected {}",
                hex::encode(chain_id),
                hex::encode(expected_chain_id),
            );
        }
    }
    let mut mirrors = Vec::new();
    for mirror in &cfg.discovery.wallet.mirrors {
        let mirror = mirror.trim();
        if mirror.is_empty() {
            continue;
        }
        let mirror_record = load_validated_service_record(mirror, "discovery mirror")?;
        let mirror_chain_id = mirror_record
            .chain_id
            .ok_or_else(|| anyhow!("discovery mirror node record must be bound to a chain"))?;
        if mirror_chain_id != chain_id {
            bail!(
                "discovery mirror node record is bound to chain {}, expected {}",
                hex::encode(mirror_chain_id),
                hex::encode(chain_id),
            );
        }
        mirrors.push(mirror_record);
    }
    Ok(Some(discovery::DiscoveryClient::new(
        record,
        mirrors,
        cfg.discovery.wallet.max_request_bytes,
        cfg.discovery.wallet.max_response_bytes,
        Duration::from_secs(cfg.discovery.wallet.submit_timeout_secs),
    )?))
}

fn build_local_discovery_status_client(cfg: &config::Config) -> Result<discovery::DiscoveryClient> {
    let identity = load_runtime_identity(cfg)?;
    discovery::DiscoveryClient::new(
        identity.record().clone(),
        Vec::new(),
        cfg.discovery.server.max_request_bytes,
        cfg.discovery.server.max_response_bytes,
        Duration::from_secs(cfg.discovery.server.submit_timeout_secs),
    )
}

fn wallet_cover_traffic_enabled(cfg: &config::Config) -> bool {
    normalized_config_item(cfg.ingress.wallet.relay.as_deref()).is_some()
        && normalized_config_item(cfg.ingress.wallet.gateway.as_deref()).is_some()
        && cfg.ingress.wallet.cover_traffic_interval_secs > 0
}

fn access_relay_policy(cfg: &config::Config) -> ingress::AccessRelayPolicy {
    ingress::AccessRelayPolicy {
        rate_limit_window: Duration::from_secs(cfg.ingress.access_relay.rate_limit_window_secs),
        max_wallet_messages_per_window: cfg.ingress.access_relay.max_wallet_messages_per_window,
        envelope_size_bytes: cfg.ingress.access_relay.envelope_size_bytes,
        submit_timeout: Duration::from_secs(cfg.ingress.access_relay.submit_timeout_secs),
    }
}

fn submission_gateway_policy(cfg: &config::Config) -> ingress::SubmissionGatewayPolicy {
    ingress::SubmissionGatewayPolicy {
        release_window: Duration::from_millis(cfg.ingress.submission_gateway.release_window_ms),
        max_batch_txs: cfg.ingress.submission_gateway.max_batch_txs,
        max_queue_depth: cfg.ingress.submission_gateway.max_queue_depth,
        envelope_size_bytes: cfg.ingress.submission_gateway.envelope_size_bytes,
        submit_timeout: Duration::from_secs(cfg.ingress.submission_gateway.submit_timeout_secs),
    }
}

fn proof_assistant_policy(cfg: &config::Config) -> proof_assistant::ProofAssistantPolicy {
    proof_assistant::ProofAssistantPolicy {
        max_request_bytes: cfg.proof_assistant.server.max_request_bytes,
        max_response_bytes: cfg.proof_assistant.server.max_response_bytes,
        submit_timeout: Duration::from_secs(cfg.proof_assistant.server.submit_timeout_secs),
    }
}

fn discovery_policy(cfg: &config::Config) -> discovery::DiscoveryPolicy {
    discovery::DiscoveryPolicy {
        record_ttl: Duration::from_secs(cfg.discovery.server.record_ttl_secs),
        submit_timeout: Duration::from_secs(cfg.discovery.server.submit_timeout_secs),
        max_request_bytes: cfg.discovery.server.max_request_bytes,
        max_response_bytes: cfg.discovery.server.max_response_bytes,
        max_pending_requests: cfg.discovery.server.max_pending_requests,
        max_pending_responses: cfg.discovery.server.max_pending_responses,
        pir_arity: cfg.discovery.server.pir_arity,
        query_budget_difficulty_bits: cfg.discovery.server.query_budget_difficulty_bits,
        allow_mutations: !cfg.discovery.server.query_only_replica,
    }
}

fn load_operator_node_record(
    cfg: &config::Config,
    provided: Option<&str>,
) -> Result<node_identity::NodeRecordV3> {
    let record = if let Some(item) = provided {
        node_identity::load_node_record(item)?
    } else {
        node_identity::load_local_runtime_record_in_dir(
            &cfg.storage.path,
            protocol::CURRENT.version,
            Some(require_local_chain_id(cfg)?),
            published_identity_addresses(cfg),
        )?
    };
    record.validate(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0),
    )?;
    Ok(record)
}

fn sign_local_control_document(
    cfg: &config::Config,
    action: SharedStateAction,
) -> Result<SharedStateControlDocument> {
    let chain_id = require_local_chain_id(cfg)?;
    let signable = Tx::shared_state_signing_bytes(chain_id, &action)?;
    let signature = node_identity::sign_with_local_root_in_dir(&cfg.storage.path, &signable)?;
    Ok(SharedStateControlDocument::new(chain_id, action, signature))
}

fn build_validator_register_document(
    cfg: &config::Config,
    args: &ValidatorRegisterDocArgs,
) -> Result<SharedStateControlDocument> {
    let record = load_operator_node_record(cfg, args.node_record.as_deref())?;
    let chain_id = require_local_chain_id(cfg)?;
    if record.chain_id != Some(chain_id) {
        bail!("validator node record chain binding does not match the local chain");
    }
    let pool = ValidatorPool::from_node_record(
        &record,
        args.commission_bps,
        args.bonded_stake,
        args.activation_epoch,
        ValidatorStatus::PendingActivation,
        validator_metadata(
            args.display_name.clone(),
            args.website.clone(),
            args.description.clone(),
        ),
    )?;
    sign_local_control_document(
        cfg,
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool }),
    )
}

fn build_validator_profile_document(
    cfg: &config::Config,
    args: &ValidatorProfileDocArgs,
) -> Result<SharedStateControlDocument> {
    let validator_id = if let Some(value) = args.validator_id.as_deref() {
        parse_validator_id_hex(value)?
    } else {
        let record = load_operator_node_record(cfg, None)?;
        ValidatorId::from_hot_key(&record.auth_spki)
    };
    sign_local_control_document(
        cfg,
        SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
            validator_id,
            commission_bps: args.commission_bps,
            metadata: validator_metadata(
                args.display_name.clone(),
                args.website.clone(),
                args.description.clone(),
            ),
        }),
    )
}

fn build_validator_reactivate_document(
    cfg: &config::Config,
    args: &ValidatorReactivateDocArgs,
) -> Result<SharedStateControlDocument> {
    let validator_id = if let Some(value) = args.validator_id.as_deref() {
        parse_validator_id_hex(value)?
    } else {
        let record = load_operator_node_record(cfg, None)?;
        ValidatorId::from_hot_key(&record.auth_spki)
    };
    sign_local_control_document(
        cfg,
        SharedStateAction::ReactivateValidator(ValidatorReactivation { validator_id }),
    )
}

fn build_penalty_evidence_document(
    cfg: &config::Config,
    args: &PenaltyEvidenceDocArgs,
) -> Result<SharedStateControlDocument> {
    let evidence: SlashableEvidence = load_json_document(&args.evidence, "slashable evidence")?;
    Ok(SharedStateControlDocument::new(
        require_local_chain_id(cfg)?,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission { evidence }),
        Vec::new(),
    ))
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

async fn handle_node_operator_command(cmd: &NodeCmd, cfg: &config::Config) -> Result<bool> {
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
        NodeCmd::DiscoveryStatus(args) => {
            let client = build_local_discovery_status_client(cfg)?;
            let status = client.fetch_status().await.map_err(|err| {
                anyhow!(
                    "failed to query the local discovery service. Start `unchained_node start-discovery` first: {err}"
                )
            })?;
            let state_path = discovery::discovery_state_path(
                &cfg.storage.path,
                cfg.discovery.server.state_path.as_deref(),
            );
            print_discovery_status_output(&state_path, &status, args)?;
            Ok(true)
        }
        NodeCmd::DiscoveryExportSnapshot { out } => {
            let identity = load_runtime_identity(cfg)?;
            let state_path = discovery::discovery_state_path(
                &cfg.storage.path,
                cfg.discovery.server.state_path.as_deref(),
            );
            let bundle =
                discovery::export_snapshot_bundle(&identity, &state_path, &discovery_policy(cfg))?;
            std::fs::write(out, discovery::encode_snapshot_bundle(&bundle)?)
                .with_context(|| format!("failed to write discovery snapshot bundle to {out}"))?;
            println!("Discovery snapshot exported.");
            println!("State path: {state_path}");
            println!("Snapshot epoch: {}", bundle.snapshot_epoch);
            println!("Dataset ID: {}", hex::encode(bundle.dataset_id));
            println!("Record count: {}", bundle.record_count);
            println!("Output: {out}");
            Ok(true)
        }
        NodeCmd::DiscoveryImportSnapshot { input } => {
            let state_path = discovery::discovery_state_path(
                &cfg.storage.path,
                cfg.discovery.server.state_path.as_deref(),
            );
            let bytes = std::fs::read(input).with_context(|| {
                format!("failed to read discovery snapshot bundle from {input}")
            })?;
            let bundle = discovery::decode_snapshot_bundle(&bytes)?;
            discovery::import_snapshot_bundle(&state_path, &bundle)?;
            println!("Discovery snapshot imported.");
            println!("State path: {state_path}");
            println!("Snapshot epoch: {}", bundle.snapshot_epoch);
            println!("Dataset ID: {}", hex::encode(bundle.dataset_id));
            println!("Record count: {}", bundle.record_count);
            println!(
                "Source server node ID: {}",
                hex::encode(bundle.source_server_record.node_id)
            );
            Ok(true)
        }
        NodeCmd::ValidatorRegisterDoc(args) => {
            let document = build_validator_register_document(cfg, args)?;
            write_json_output(
                "Signed Shared-State Control Document",
                &document,
                args.out.as_deref(),
            )?;
            Ok(true)
        }
        NodeCmd::ValidatorProfileDoc(args) => {
            let document = build_validator_profile_document(cfg, args)?;
            write_json_output(
                "Signed Shared-State Control Document",
                &document,
                args.out.as_deref(),
            )?;
            Ok(true)
        }
        NodeCmd::ValidatorReactivateDoc(args) => {
            let document = build_validator_reactivate_document(cfg, args)?;
            write_json_output(
                "Signed Shared-State Control Document",
                &document,
                args.out.as_deref(),
            )?;
            Ok(true)
        }
        NodeCmd::PenaltyEvidenceDoc(args) => {
            let document = build_penalty_evidence_document(cfg, args)?;
            write_json_output(
                "Shared-State Control Document",
                &document,
                args.out.as_deref(),
            )?;
            Ok(true)
        }
        NodeCmd::Start
        | NodeCmd::StartAccessRelay
        | NodeCmd::StartSubmissionGateway
        | NodeCmd::StartProofAssistant
        | NodeCmd::StartDiscovery
        | NodeCmd::ReplayTransactions
        | NodeCmd::ExportAnchors { .. }
        | NodeCmd::ImportAnchors { .. } => Ok(false),
    }
}

async fn start_network_runtime(cfg: &config::Config) -> Result<NetworkRuntime> {
    let db = open_store(cfg)?;
    let sync_state = Arc::new(Mutex::new(sync::SyncState::default()));
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
        cfg.net.clone(),
        net.clone(),
        shutdown_tx.subscribe(),
        sync_state.clone(),
    );
    epoch_mgr.spawn_loop();
    Ok(NetworkRuntime {
        db,
        net,
        sync_state,
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

async fn wait_for_service_shutdown(
    signal_label: &str,
    shutdown_tx: broadcast::Sender<()>,
    service_task: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    println!("Press Ctrl+C to stop.");
    match signal::ctrl_c().await {
        Ok(()) => {
            println!();
            println!("Shutdown signal received. Cleaning up {signal_label}...");
            let _ = shutdown_tx.send(());
            service_task.await.map_err(|err| anyhow!(err))??;
            println!("{signal_label} stopped.");
            Ok(())
        }
        Err(err) => {
            let _ = shutdown_tx.send(());
            let _ = service_task.await;
            Err(err.into())
        }
    }
}

async fn run_send_flow(
    client: &wallet_control::WalletControlClient,
    args: &SendArgs,
) -> Result<()> {
    let guided = (args.to.is_none() && args.invoice.is_none()) || args.amount.is_none();
    if guided && !atty::is(atty::Stream::Stdin) {
        bail!(
            "Interactive send requires a TTY. Pass --to or --invoice together with --amount in non-interactive mode."
        );
    }
    let (target_kind, target_raw) = match (&args.to, &args.invoice) {
        (Some(locator), None) => ("locator", locator.clone()),
        (None, Some(invoice)) => ("invoice", invoice.clone()),
        (None, None) => {
            let locator = prompt_line("Recipient locator (leave blank to use an invoice): ")?;
            if locator.trim().is_empty() {
                ("invoice", prompt_line("Invoice: ")?)
            } else {
                ("locator", locator)
            }
        }
        (Some(_), Some(_)) => bail!("pass either --to or --invoice, not both"),
    };
    let target = load_receiver_code(&target_raw)?;
    if target.is_empty() {
        bail!("Recipient cannot be empty");
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
        println!(
            "{}: {}",
            if target_kind == "locator" {
                "Locator"
            } else {
                "Invoice"
            },
            short_text(&target)
        );
        let confirm = prompt_line("Broadcast now? [Y/n]: ")?;
        if matches!(confirm.to_ascii_lowercase().as_str(), "n" | "no") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let outcome = if target_kind == "locator" {
        client.send_to_locator(&target, amount).await?
    } else {
        client.send_to_invoice(&target, amount).await?
    };

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "target_kind": target_kind,
                "target": target,
                "amount": amount,
                "fee_amount": outcome.fee_amount,
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
        "Broadcast shielded transaction consuming {} note{}, creating {} note{}, sending {} coin{}, and paying {} coin{} in shielded fees.",
        outcome.input_count,
        if outcome.input_count == 1 { "" } else { "s" },
        outcome.output_count,
        if outcome.output_count == 1 { "" } else { "s" },
        amount,
        if amount == 1 { "" } else { "s" },
        outcome.fee_amount,
        if outcome.fee_amount == 1 { "" } else { "s" }
    );
    println!(
        "{}: {}",
        if target_kind == "locator" {
            "Locator"
        } else {
            "Invoice"
        },
        short_text(&target)
    );
    println!("Tx ID: {}", hex::encode(outcome.tx_id));
    println!();
    println!("Track confirmation with `unchained_wallet history`.");
    Ok(())
}

fn print_shareable_output(
    label: &str,
    json_key: &str,
    value: &str,
    args: &ReceiveArgs,
) -> Result<()> {
    let value = value.to_string();
    let copied = if args.copy {
        copy_to_clipboard(&value).is_ok()
    } else {
        false
    };

    if args.json {
        let mut obj = serde_json::Map::new();
        obj.insert(
            json_key.to_string(),
            serde_json::Value::String(value.clone()),
        );
        obj.insert("copied".to_string(), serde_json::Value::Bool(copied));
        println!("{}", serde_json::Value::Object(obj));
        return Ok(());
    }

    if args.plain {
        println!("{value}");
        return Ok(());
    }

    println!("{label}");
    println!();
    println!("{value}");
    println!();
    if let Err(err) = print_qr_to_terminal(&value) {
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

fn print_locator_resolution_output(
    locator: &str,
    record: &discovery::DiscoveryRecord,
    verified_servers: usize,
    args: &ResolveArgs,
) -> Result<()> {
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "locator": locator,
                "chain_id": hex::encode(record.chain_id),
                "locator_id": hex::encode(record.locator_id),
                "mailbox_id": hex::encode(record.mailbox_id),
                "owner_signing_pk": record.owner_signing_pk,
                "mailbox_kem_pk": record.mailbox_kem_pk,
                "offline_receive": {
                    "scan_kem_pk": record.offline_receive.scan_kem_pk,
                    "asset_policy": record.offline_receive.asset_policy,
                    "policy_flags": record.offline_receive.policy_flags,
                    "issued_unix_ms": record.offline_receive.issued_unix_ms,
                    "expires_unix_ms": record.offline_receive.expires_unix_ms,
                },
                "verified_servers": verified_servers,
            })
        );
        return Ok(());
    }

    println!("Resolved Locator");
    println!();
    println!("Locator: {locator}");
    println!("Verified servers: {verified_servers}");
    println!("Chain ID: {}", hex::encode(record.chain_id));
    println!("Mailbox ID: {}", hex::encode(record.mailbox_id));
    println!(
        "Offline receive expires: {}",
        record.offline_receive.expires_unix_ms
    );
    Ok(())
}

fn print_discovery_status_output(
    state_path: &str,
    status: &discovery::DiscoveryServerStatus,
    args: &DiscoveryStatusArgs,
) -> Result<()> {
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "state_path": state_path,
                "chain_id": hex::encode(status.chain_id),
                "server_node_id": hex::encode(status.server_node_id),
                "dataset_id": hex::encode(status.dataset_id),
                "snapshot_epoch": status.snapshot_epoch,
                "manifest_id": hex::encode(status.manifest_id),
                "manifest_issued_unix_ms": status.manifest_issued_unix_ms,
                "record_count": status.record_count,
                "record_bytes": status.record_bytes,
                "pir_arity": status.pir_arity,
                "query_budget_difficulty_bits": status.query_budget_difficulty_bits,
                "allow_mutations": status.allow_mutations,
                "record_ttl_secs": status.record_ttl_secs,
                "max_request_bytes": status.max_request_bytes,
                "max_response_bytes": status.max_response_bytes,
                "max_pending_requests": status.max_pending_requests,
                "max_pending_responses": status.max_pending_responses,
                "active_locator_count": status.active_locator_count,
                "next_locator_expiry_unix_ms": status.next_locator_expiry_unix_ms,
                "pending_mailbox_requests": status.pending_mailbox_requests,
                "pending_handle_responses": status.pending_handle_responses,
            })
        );
        return Ok(());
    }

    println!("Discovery Status");
    println!();
    println!("State path: {state_path}");
    println!("Server node ID: {}", hex::encode(status.server_node_id));
    println!("Chain ID: {}", hex::encode(status.chain_id));
    println!("Dataset ID: {}", hex::encode(status.dataset_id));
    println!("Snapshot epoch: {}", status.snapshot_epoch);
    println!("Manifest ID: {}", hex::encode(status.manifest_id));
    println!("Manifest issued: {}", status.manifest_issued_unix_ms);
    println!("Record count: {}", status.record_count);
    println!("Record bytes: {}", status.record_bytes);
    println!("PIR arity: {}", status.pir_arity);
    println!(
        "Query budget difficulty bits: {}",
        status.query_budget_difficulty_bits
    );
    println!(
        "Mutations enabled: {}",
        if status.allow_mutations { "yes" } else { "no" }
    );
    println!("Record TTL secs: {}", status.record_ttl_secs);
    println!("Active locators: {}", status.active_locator_count);
    println!(
        "Next locator expiry: {}",
        status
            .next_locator_expiry_unix_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "Pending mailbox requests: {} / {}",
        status.pending_mailbox_requests, status.max_pending_requests
    );
    println!(
        "Pending handle responses: {} / {}",
        status.pending_handle_responses, status.max_pending_responses
    );
    println!("Max request bytes: {}", status.max_request_bytes);
    println!("Max response bytes: {}", status.max_response_bytes);
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
    println!("Receive locator: `unchained_wallet receive`");
    println!("Mint invoice: `unchained_wallet invoice`");
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
                    "fee_amount": record.fee_amount,
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
        if record.fee_amount > 0 {
            println!(
                "  fee  {} coin{}",
                record.fee_amount,
                if record.fee_amount == 1 { "" } else { "s" }
            );
        }
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

    if handle_node_operator_command(&cli.cmd, &cfg).await? {
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
            println!(
                "Protocol checkpoint cadence: {} seconds",
                cfg.epoch.checkpoint_cadence_secs()
            );
            println!("Consensus foundation: validator/BFT runtime");
            println!("Settlement manager: enabled");
            println!("Epoch coin cap: {}", protocol::CURRENT.max_coins_per_epoch);
            let shutdown_result = wait_for_shutdown("Unchained node", runtime).await;
            let node_control_result = node_control_task.await.map_err(|err| anyhow!(err))?;
            shutdown_result?;
            node_control_result?;
            Ok(())
        }
        NodeCmd::StartAccessRelay => {
            let identity = load_runtime_identity(&cfg)?;
            let chain_id = require_local_chain_id(&cfg)?;
            let gateway_records = load_ingress_records(
                &cfg.ingress.access_relay.gateways,
                "submission gateway",
                chain_id,
            )?;
            let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
            let server = ingress::AccessRelayServer::bind(
                &identity,
                gateway_records,
                listen_addr(&cfg),
                access_relay_policy(&cfg),
            )?;
            let task = tokio::spawn(async move { server.serve(shutdown_rx).await });
            println!("Access relay is running.");
            println!("Listening on port {}", cfg.net.listen_port);
            wait_for_service_shutdown("Unchained access relay", shutdown_tx, task).await
        }
        NodeCmd::StartSubmissionGateway => {
            let identity = load_runtime_identity(&cfg)?;
            let chain_id = require_local_chain_id(&cfg)?;
            let allowed_relays = load_ingress_records(
                &cfg.ingress.submission_gateway.allowed_relays,
                "access relay",
                chain_id,
            )?;
            let validator_control_base_path = normalized_config_item(
                cfg.ingress
                    .submission_gateway
                    .validator_control_base_path
                    .as_deref(),
            )
            .unwrap_or(&cfg.storage.path);
            let validator_client =
                node_control::NodeControlClient::new(validator_control_base_path);
            validator_client.ping()?;
            let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
            let server = ingress::SubmissionGatewayServer::bind(
                &identity,
                allowed_relays,
                listen_addr(&cfg),
                validator_control_base_path,
                submission_gateway_policy(&cfg),
            )?;
            let task = tokio::spawn(async move { server.serve(shutdown_rx).await });
            println!("Submission gateway is running.");
            println!("Listening on port {}", cfg.net.listen_port);
            println!("Validator control base path: {validator_control_base_path}");
            wait_for_service_shutdown("Unchained submission gateway", shutdown_tx, task).await
        }
        NodeCmd::StartProofAssistant => {
            let identity = load_runtime_identity(&cfg)?;
            let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
            let server = proof_assistant::ProofAssistantServer::bind(
                &identity,
                listen_addr(&cfg),
                proof_assistant_policy(&cfg),
            )?;
            let task = tokio::spawn(async move { server.serve(shutdown_rx).await });
            println!("Proof assistant is running.");
            println!("Listening on port {}", cfg.net.listen_port);
            wait_for_service_shutdown("Unchained proof assistant", shutdown_tx, task).await
        }
        NodeCmd::StartDiscovery => {
            let identity = load_runtime_identity(&cfg)?;
            let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
            let state_path = discovery::discovery_state_path(
                &cfg.storage.path,
                cfg.discovery.server.state_path.as_deref(),
            );
            let server = discovery::DiscoveryServer::bind(
                &identity,
                listen_addr(&cfg),
                &state_path,
                discovery_policy(&cfg),
            )?;
            let task = tokio::spawn(async move { server.serve(shutdown_rx).await });
            println!("Discovery service is running.");
            println!("Listening on port {}", cfg.net.listen_port);
            println!("Discovery state path: {state_path}");
            wait_for_service_shutdown("Unchained discovery service", shutdown_tx, task).await
        }
        NodeCmd::InitRoot { .. }
        | NodeCmd::AuthPrepare { .. }
        | NodeCmd::AuthSign { .. }
        | NodeCmd::AuthInstall { .. }
        | NodeCmd::TrustRevoke { .. }
        | NodeCmd::TrustReplace { .. }
        | NodeCmd::TrustApprove { .. }
        | NodeCmd::PeerId
        | NodeCmd::DiscoveryStatus(..)
        | NodeCmd::DiscoveryExportSnapshot { .. }
        | NodeCmd::DiscoveryImportSnapshot { .. }
        | NodeCmd::ValidatorRegisterDoc(..)
        | NodeCmd::ValidatorProfileDoc(..)
        | NodeCmd::ValidatorReactivateDoc(..)
        | NodeCmd::PenaltyEvidenceDoc(..) => unreachable!("handled before runtime startup"),
    }
}

pub async fn run_wallet_cli() -> Result<()> {
    let cli = WalletCli::parse();
    let cfg = load_config(&cli.common.config)?;
    apply_quiet_logging(&cli.common, &cfg);

    match cli.cmd {
        WalletCmd::Serve => {
            let wallet_db = open_wallet_store(&cfg)?;
            let node_client = open_optional_node_control_client(&cfg)?;
            let mut wallet = wallet::Wallet::load_or_create_private(wallet_db.clone())?;
            if let Some(node_client) = node_client.clone() {
                wallet = wallet.with_node_client(node_client);
            }
            let expected_chain_id = node_client
                .as_ref()
                .map(node_control::NodeControlClient::chain_id)
                .transpose()?;
            let ingress_client = build_wallet_ingress_client(&cfg, expected_chain_id)?;
            if let Some(ingress_client) = ingress_client.clone() {
                wallet = wallet.with_ingress_client(ingress_client);
            }
            let proof_expected_chain_id = match (expected_chain_id, ingress_client.as_ref()) {
                (Some(chain_id), _) => Some(chain_id),
                (None, Some(ingress_client)) => Some(ingress_client.chain_id()?),
                (None, None) => None,
            };
            if let Some(proof_assistant_client) =
                build_wallet_proof_assistant_client(&cfg, proof_expected_chain_id)?
            {
                wallet = wallet.with_proof_assistant_client(proof_assistant_client);
            }
            if let Some(discovery_client) =
                build_wallet_discovery_client(&cfg, proof_expected_chain_id)?
            {
                wallet = wallet.with_discovery_client(discovery_client);
            }
            if !wallet.has_discovery_client() {
                bail!(
                    "wallet serve requires [discovery.wallet].server; PIR-native locator discovery is a canonical runtime dependency"
                );
            }
            if node_client.is_none() && !wallet.has_ingress_client() {
                bail!(
                    "wallet serve requires either a reachable local node control socket or configured [ingress.wallet] relay/gateway services"
                );
            }
            let wallet = Arc::new(wallet);
            let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
            let server =
                wallet_control::WalletControlServer::bind(&cfg.storage.path, wallet.clone())
                    .await?;
            let socket_path = server.socket_path().display().to_string();
            let capability_path = wallet_control::wallet_control_capability_path(&cfg.storage.path)
                .display()
                .to_string();
            let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });
            let cover_task = if wallet_cover_traffic_enabled(&cfg) && wallet.has_ingress_client() {
                let wallet = wallet.clone();
                let shutdown_rx = shutdown_tx.subscribe();
                let interval_secs = cfg.ingress.wallet.cover_traffic_interval_secs;
                Some(tokio::spawn(async move {
                    wallet
                        .run_cover_traffic_loop(interval_secs, shutdown_rx)
                        .await
                }))
            } else {
                None
            };
            let discovery_task = if wallet.has_discovery_client() {
                let wallet = wallet.clone();
                let shutdown_rx = shutdown_tx.subscribe();
                let publish_interval =
                    Duration::from_secs(cfg.discovery.wallet.publish_interval_secs.max(1));
                let poll_interval =
                    Duration::from_secs(cfg.discovery.wallet.poll_interval_secs.max(1));
                let record_ttl = publish_interval
                    .checked_mul(3)
                    .unwrap_or(publish_interval + publish_interval + publish_interval);
                Some(tokio::spawn(async move {
                    wallet
                        .run_discovery_loop(
                            publish_interval,
                            poll_interval,
                            record_ttl.max(Duration::from_secs(600)),
                            shutdown_rx,
                        )
                        .await
                }))
            } else {
                None
            };

            println!("Wallet control socket: {socket_path}");
            println!("Wallet control capability: {capability_path}");
            println!("Wallet control runtime is running.");
            if wallet_cover_traffic_enabled(&cfg) && wallet.has_ingress_client() {
                println!(
                    "Wallet ingress cover cadence: {} seconds",
                    cfg.ingress.wallet.cover_traffic_interval_secs
                );
            }
            if wallet.has_proof_assistant_client() {
                println!("Wallet remote proof assistant: enabled");
            }
            if wallet.has_discovery_client() {
                println!("Wallet discovery locator: {}", wallet.locator());
            }
            println!("Press Ctrl+C to stop.");

            match signal::ctrl_c().await {
                Ok(()) => {
                    println!();
                    println!("Shutdown signal received. Cleaning up Unchained wallet...");
                    let _ = shutdown_tx.send(());
                    let server_result = server_task.await.map_err(|err| anyhow!(err))?;
                    let cover_result = match cover_task {
                        Some(task) => Some(task.await.map_err(|err| anyhow!(err))?),
                        None => None,
                    };
                    let discovery_result = match discovery_task {
                        Some(task) => Some(task.await.map_err(|err| anyhow!(err))?),
                        None => None,
                    };
                    drop(wallet);
                    let wallet_close_result = wallet_db.close();
                    server_result?;
                    if let Some(result) = cover_result {
                        result?;
                    }
                    if let Some(result) = discovery_result {
                        result?;
                    }
                    wallet_close_result?;
                    println!("Unchained wallet stopped.");
                    Ok(())
                }
                Err(err) => {
                    let _ = shutdown_tx.send(());
                    let _ = server_task.await;
                    if let Some(task) = cover_task {
                        let _ = task.await;
                    }
                    if let Some(task) = discovery_task {
                        let _ = task.await;
                    }
                    drop(wallet);
                    let _ = wallet_db.close();
                    Err(err.into())
                }
            }
        }
        WalletCmd::Receive(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let locator = client.receive_locator().await?;
            print_shareable_output("Receive Locator", "locator", &locator, &args)?;
            Ok(())
        }
        WalletCmd::ReceiveRotate(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let locator = client.rotate_locator().await?;
            print_shareable_output("Rotated Receive Locator", "locator", &locator, &args)?;
            Ok(())
        }
        WalletCmd::ReceiveCompromise(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let locator = client.compromise_rotate_locator().await?;
            print_shareable_output(
                "Compromised Receive Locator Reissued",
                "locator",
                &locator,
                &args,
            )?;
            Ok(())
        }
        WalletCmd::Resolve(args) => {
            if let Some(client) = try_open_wallet_control_client(&cfg).await {
                match client.resolve_locator(&args.locator).await {
                    Ok((record, replica_count)) => {
                        print_locator_resolution_output(
                            &args.locator,
                            &record,
                            replica_count,
                            &args,
                        )?;
                        return Ok(());
                    }
                    Err(err)
                        if err
                            .to_string()
                            .contains("wallet discovery client is not configured") => {}
                    Err(err) => return Err(err),
                }
            }
            let discovery_client = build_wallet_discovery_client(&cfg, None)?
                .ok_or_else(|| anyhow!("resolve requires [discovery.wallet].server"))?;
            let record = discovery_client.resolve_locator(&args.locator).await?;
            print_locator_resolution_output(
                &args.locator,
                &record,
                discovery_client.mirror_count() + 1,
                &args,
            )?;
            Ok(())
        }
        WalletCmd::RequestHandle(args) => {
            let timeout = Duration::from_secs(args.timeout_secs.max(1));
            if let Some(client) = try_open_wallet_control_client(&cfg).await {
                match client
                    .request_handle(&args.locator, args.amount, timeout)
                    .await
                {
                    Ok(invoice) => {
                        print_shareable_output(
                            "Negotiated Handle",
                            "invoice",
                            &invoice,
                            &args.output,
                        )?;
                        return Ok(());
                    }
                    Err(err)
                        if err
                            .to_string()
                            .contains("wallet discovery client is not configured") => {}
                    Err(err) => return Err(err),
                }
            }
            let discovery_client = build_wallet_discovery_client(&cfg, None)?
                .ok_or_else(|| anyhow!("request-handle requires [discovery.wallet].server"))?;
            let invoice = discovery_client
                .request_handle(&args.locator, args.amount, timeout)
                .await?;
            print_shareable_output("Negotiated Handle", "invoice", &invoice, &args.output)?;
            Ok(())
        }
        WalletCmd::Invoice(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let invoice = client.mint_invoice(args.amount).await?;
            print_shareable_output("Invoice", "invoice", &invoice, &args.output)?;
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
        WalletCmd::SubmitControl(args) => {
            let client = open_wallet_control_client(&cfg).await?;
            let document: SharedStateControlDocument =
                load_json_document(&args.document, "shared-state control")?;
            let outcome = client.submit_shared_state_control(document).await?;
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "tx_id": hex::encode(outcome.tx_id),
                        "fee_amount": outcome.fee_amount,
                        "input_count": outcome.input_count,
                        "output_count": outcome.output_count,
                    })
                );
            } else {
                println!("Submitted Shared-State Control Transaction");
                println!();
                println!("Tx ID: {}", hex::encode(outcome.tx_id));
                println!(
                    "Shielded fee: {} coin{} via {} input note{} and {} output note{}.",
                    outcome.fee_amount,
                    if outcome.fee_amount == 1 { "" } else { "s" },
                    outcome.input_count,
                    if outcome.input_count == 1 { "" } else { "s" },
                    outcome.output_count,
                    if outcome.output_count == 1 { "" } else { "s" },
                );
            }
            Ok(())
        }
    }
}
