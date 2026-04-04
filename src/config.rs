use crate::protocol::CURRENT as PROTOCOL;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::Path};
use toml::Value as TomlValue;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub net: Net,
    pub p2p: P2p,
    pub storage: Storage,
    pub epoch: Epoch,
    pub metrics: Metrics,
    #[serde(default)]
    pub compact: Compact,
    #[serde(default)]
    pub ingress: Ingress,
    #[serde(default)]
    pub proof_assistant: ProofAssistant,
    #[serde(default)]
    pub discovery: Discovery,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Net {
    pub listen_port: u16,
    #[serde(default)]
    pub bootstrap: Vec<String>, // signed NodeRecordV2 strings or file paths
    #[serde(default)]
    pub trust_updates: Vec<String>, // signed TrustUpdateV1 strings or file paths
    #[serde(default = "default_strict_trust")]
    pub strict_trust: bool, // require peers to chain back to explicitly configured bootstrap roots
    #[serde(default)]
    pub peer_exchange: bool, // gossip known peers
    #[serde(default = "default_max_peers")]
    pub max_peers: u32, // maximum peer connections
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64, // connection timeout
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64, // QUIC idle timeout for established validator links
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval_secs: u64, // QUIC keep-alive interval for established validator links
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_sync_timeout")]
    pub sync_timeout_secs: u64,
    /// Optional static ban list of node IDs (hex). Connections and dials to these peers are blocked.
    #[serde(default)]
    pub banned_peer_ids: Vec<String>,
    /// Suppress routine network gossip logs by default (overridden by CLI --quiet-net)
    #[serde(default)]
    pub quiet_by_default: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct P2p {
    #[serde(default = "default_max_validation_failures_per_peer")]
    pub max_validation_failures_per_peer: u32,
    #[serde(default = "default_peer_ban_duration_secs")]
    pub peer_ban_duration_secs: u64,
    // Removed consensus_mismatch_ban_secs; hard-coded in network layer
    #[serde(default = "default_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
    #[serde(default = "default_max_messages_per_window")]
    pub max_messages_per_window: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Storage {
    pub path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Epoch {
    pub seconds: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Metrics {
    #[serde(default = "default_bind")]
    pub bind: String,

    /// How many recent epochs tools should display by default
    #[serde(default = "default_last_epochs_to_show")]
    pub last_epochs_to_show: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Compact {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_compact_prefill_count")]
    pub prefill_count: u32,
    /// Currently fixed at 8 in wire format; reserved for future tuning
    #[serde(default = "default_compact_short_id_len")]
    pub short_id_len: u8,
    /// If missing > max_missing_pct, request the full epoch data path instead
    #[serde(default = "default_compact_max_missing_pct")]
    pub max_missing_pct: u8,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Ingress {
    #[serde(default)]
    pub wallet: WalletIngress,
    #[serde(default)]
    pub access_relay: AccessRelay,
    #[serde(default)]
    pub submission_gateway: SubmissionGateway,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ProofAssistant {
    #[serde(default)]
    pub wallet: WalletProofAssistant,
    #[serde(default)]
    pub server: ProofAssistantServer,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Discovery {
    #[serde(default)]
    pub wallet: WalletDiscovery,
    #[serde(default)]
    pub server: DiscoveryServer,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WalletIngress {
    #[serde(default)]
    pub relay: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default = "default_wallet_cover_traffic_interval_secs")]
    pub cover_traffic_interval_secs: u64,
    #[serde(default = "default_ingress_envelope_size_bytes")]
    pub envelope_size_bytes: usize,
    #[serde(default = "default_ingress_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
}

impl Default for WalletIngress {
    fn default() -> Self {
        Self {
            relay: None,
            gateway: None,
            cover_traffic_interval_secs: default_wallet_cover_traffic_interval_secs(),
            envelope_size_bytes: default_ingress_envelope_size_bytes(),
            submit_timeout_secs: default_ingress_submit_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WalletProofAssistant {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default = "default_proof_assistant_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_proof_assistant_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_proof_assistant_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
}

impl Default for WalletProofAssistant {
    fn default() -> Self {
        Self {
            server: None,
            max_request_bytes: default_proof_assistant_max_request_bytes(),
            max_response_bytes: default_proof_assistant_max_response_bytes(),
            submit_timeout_secs: default_proof_assistant_submit_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct WalletDiscovery {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default = "default_discovery_publish_interval_secs")]
    pub publish_interval_secs: u64,
    #[serde(default = "default_discovery_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_discovery_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_discovery_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_discovery_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
}

impl Default for WalletDiscovery {
    fn default() -> Self {
        Self {
            server: None,
            publish_interval_secs: default_discovery_publish_interval_secs(),
            poll_interval_secs: default_discovery_poll_interval_secs(),
            max_request_bytes: default_discovery_max_request_bytes(),
            max_response_bytes: default_discovery_max_response_bytes(),
            submit_timeout_secs: default_discovery_submit_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccessRelay {
    #[serde(default)]
    pub gateways: Vec<String>,
    #[serde(default = "default_ingress_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
    #[serde(default = "default_ingress_max_wallet_messages_per_window")]
    pub max_wallet_messages_per_window: u32,
    #[serde(default = "default_ingress_envelope_size_bytes")]
    pub envelope_size_bytes: usize,
    #[serde(default = "default_ingress_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
}

impl Default for AccessRelay {
    fn default() -> Self {
        Self {
            gateways: Vec::new(),
            rate_limit_window_secs: default_ingress_rate_limit_window_secs(),
            max_wallet_messages_per_window: default_ingress_max_wallet_messages_per_window(),
            envelope_size_bytes: default_ingress_envelope_size_bytes(),
            submit_timeout_secs: default_ingress_submit_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubmissionGateway {
    #[serde(default)]
    pub allowed_relays: Vec<String>,
    #[serde(default)]
    pub validator_control_base_path: Option<String>,
    #[serde(default = "default_ingress_release_window_ms")]
    pub release_window_ms: u64,
    #[serde(default = "default_ingress_max_batch_txs")]
    pub max_batch_txs: usize,
    #[serde(default = "default_ingress_max_queue_depth")]
    pub max_queue_depth: usize,
    #[serde(default = "default_ingress_envelope_size_bytes")]
    pub envelope_size_bytes: usize,
    #[serde(default = "default_ingress_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
}

impl Default for SubmissionGateway {
    fn default() -> Self {
        Self {
            allowed_relays: Vec::new(),
            validator_control_base_path: None,
            release_window_ms: default_ingress_release_window_ms(),
            max_batch_txs: default_ingress_max_batch_txs(),
            max_queue_depth: default_ingress_max_queue_depth(),
            envelope_size_bytes: default_ingress_envelope_size_bytes(),
            submit_timeout_secs: default_ingress_submit_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProofAssistantServer {
    #[serde(default = "default_proof_assistant_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_proof_assistant_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_proof_assistant_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
}

impl Default for ProofAssistantServer {
    fn default() -> Self {
        Self {
            max_request_bytes: default_proof_assistant_max_request_bytes(),
            max_response_bytes: default_proof_assistant_max_response_bytes(),
            submit_timeout_secs: default_proof_assistant_submit_timeout_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct DiscoveryServer {
    #[serde(default)]
    pub state_path: Option<String>,
    #[serde(default = "default_discovery_record_ttl_secs")]
    pub record_ttl_secs: u64,
    #[serde(default = "default_discovery_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_discovery_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_discovery_submit_timeout_secs")]
    pub submit_timeout_secs: u64,
    #[serde(default = "default_discovery_max_pending_requests")]
    pub max_pending_requests: usize,
    #[serde(default = "default_discovery_max_pending_responses")]
    pub max_pending_responses: usize,
    #[serde(default = "default_discovery_pir_arity")]
    pub pir_arity: u32,
}

impl Default for DiscoveryServer {
    fn default() -> Self {
        Self {
            state_path: None,
            record_ttl_secs: default_discovery_record_ttl_secs(),
            max_request_bytes: default_discovery_max_request_bytes(),
            max_response_bytes: default_discovery_max_response_bytes(),
            submit_timeout_secs: default_discovery_submit_timeout_secs(),
            max_pending_requests: default_discovery_max_pending_requests(),
            max_pending_responses: default_discovery_max_pending_responses(),
            pir_arity: default_discovery_pir_arity(),
        }
    }
}

impl Default for Compact {
    fn default() -> Self {
        Self {
            enable: false,
            prefill_count: default_compact_prefill_count(),
            short_id_len: default_compact_short_id_len(),
            max_missing_pct: default_compact_max_missing_pct(),
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1:9100".into()
}
fn default_last_epochs_to_show() -> u64 {
    10
}
// Network defaults for production deployment
fn default_max_peers() -> u32 {
    100
}
fn default_connection_timeout() -> u64 {
    30
}
fn default_idle_timeout() -> u64 {
    120
}
fn default_keep_alive_interval() -> u64 {
    10
}
fn default_sync_timeout() -> u64 {
    180
}
fn default_proof_assistant_max_request_bytes() -> usize {
    32 * 1024 * 1024
}
fn default_proof_assistant_max_response_bytes() -> usize {
    16 * 1024 * 1024
}
fn default_proof_assistant_submit_timeout_secs() -> u64 {
    30
}
fn default_discovery_publish_interval_secs() -> u64 {
    300
}
fn default_discovery_poll_interval_secs() -> u64 {
    5
}
fn default_discovery_record_ttl_secs() -> u64 {
    3600
}
fn default_discovery_max_request_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_discovery_max_response_bytes() -> usize {
    32 * 1024 * 1024
}
fn default_discovery_submit_timeout_secs() -> u64 {
    10
}
fn default_discovery_max_pending_requests() -> usize {
    4096
}
fn default_discovery_max_pending_responses() -> usize {
    4096
}
fn default_discovery_pir_arity() -> u32 {
    4
}
fn default_strict_trust() -> bool {
    true
}

// P2P defaults
fn default_max_validation_failures_per_peer() -> u32 {
    10
}
fn default_peer_ban_duration_secs() -> u64 {
    3600
}
fn default_rate_limit_window_secs() -> u64 {
    60
}
fn default_max_messages_per_window() -> u32 {
    100
}

// Compact defaults
fn default_compact_prefill_count() -> u32 {
    4
}
fn default_compact_short_id_len() -> u8 {
    8
}
fn default_compact_max_missing_pct() -> u8 {
    20
}

fn default_ingress_envelope_size_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_ingress_submit_timeout_secs() -> u64 {
    10
}

fn default_ingress_rate_limit_window_secs() -> u64 {
    60
}

fn default_ingress_max_wallet_messages_per_window() -> u32 {
    128
}

fn default_ingress_release_window_ms() -> u64 {
    50
}

fn default_wallet_cover_traffic_interval_secs() -> u64 {
    30
}

fn default_ingress_max_batch_txs() -> usize {
    32
}

fn default_ingress_max_queue_depth() -> usize {
    2048
}

/// Read the TOML file at `p` and deserialize into `Config`.
/// *Adds context* so user errors print a friendlier message.
///
/// # Errors
/// * Returns an anyhow::Error if the file cannot be read or parsed.
pub fn load<P: AsRef<Path>>(p: P) -> Result<Config> {
    let text = fs::read_to_string(&p)
        .with_context(|| format!("🗂️  couldn’t read config file {}", p.as_ref().display()))?;
    // Parse to TOML to detect unknown keys for diagnostics
    let val: TomlValue =
        toml::from_str(&text).with_context(|| "📝  invalid TOML in config file".to_string())?;
    warn_unknown_keys(&val);
    let mut cfg: Config = val
        .try_into()
        .with_context(|| "📝  invalid config schema".to_string())?;
    apply_protocol_overrides(&mut cfg);
    Ok(cfg)
}

pub fn resolve_storage_path(path: &str) -> String {
    if Path::new(path).is_relative() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        Path::new(&home)
            .join(".unchained")
            .join("unchained_data")
            .to_string_lossy()
            .into_owned()
    } else {
        path.to_string()
    }
}

pub fn load_resolved<P: AsRef<Path>>(p: P) -> Result<Config> {
    let mut cfg = load(p)?;
    cfg.storage.path = resolve_storage_path(&cfg.storage.path);
    Ok(cfg)
}

/// Parse configuration from a TOML string and apply the same validations as `load`.
pub fn load_from_str(text: &str) -> Result<Config> {
    let val: TomlValue = toml::from_str(text)
        .with_context(|| "📝  invalid TOML in embedded/default config".to_string())?;
    warn_unknown_keys(&val);
    let mut cfg: Config = val
        .try_into()
        .with_context(|| "📝  invalid config schema".to_string())?;
    apply_protocol_overrides(&mut cfg);
    Ok(cfg)
}

fn warn_unknown_keys(val: &TomlValue) {
    // Known sections and keys
    use std::collections::HashSet;
    let top_allowed: HashSet<&str> = [
        "net",
        "p2p",
        "storage",
        "epoch",
        "metrics",
        "compact",
        "ingress",
        "proof_assistant",
        "discovery",
    ]
    .into_iter()
    .collect();
    if let Some(table) = val.as_table() {
        for (k, v) in table.iter() {
            if !top_allowed.contains(k.as_str()) {
                eprintln!("⚠️  Unknown top-level config section '{}' (ignored)", k);
                continue;
            }
            match (k.as_str(), v) {
                ("net", TomlValue::Table(t)) => warn_unknown_keys_in(
                    t,
                    &[
                        "listen_port",
                        "bootstrap",
                        "trust_updates",
                        "strict_trust",
                        "peer_exchange",
                        "max_peers",
                        "connection_timeout_secs",
                        "public_ip",
                        "sync_timeout_secs",
                        "banned_peer_ids",
                        "quiet_by_default",
                    ],
                ),
                ("p2p", TomlValue::Table(t)) => warn_unknown_keys_in(
                    t,
                    &[
                        "max_validation_failures_per_peer",
                        "peer_ban_duration_secs",
                        "rate_limit_window_secs",
                        "max_messages_per_window",
                    ],
                ),
                ("storage", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["path"]),
                ("epoch", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["seconds"]),
                ("metrics", TomlValue::Table(t)) => {
                    warn_unknown_keys_in(t, &["bind", "last_epochs_to_show"])
                }
                ("compact", TomlValue::Table(t)) => warn_unknown_keys_in(
                    t,
                    &["enable", "prefill_count", "short_id_len", "max_missing_pct"],
                ),
                ("ingress", TomlValue::Table(t)) => {
                    warn_unknown_keys_in(t, &["wallet", "access_relay", "submission_gateway"]);
                    if let Some(wallet) = t.get("wallet").and_then(TomlValue::as_table) {
                        warn_unknown_keys_in(
                            wallet,
                            &[
                                "relay",
                                "gateway",
                                "cover_traffic_interval_secs",
                                "envelope_size_bytes",
                                "submit_timeout_secs",
                            ],
                        );
                    }
                    if let Some(relay) = t.get("access_relay").and_then(TomlValue::as_table) {
                        warn_unknown_keys_in(
                            relay,
                            &[
                                "gateways",
                                "rate_limit_window_secs",
                                "max_wallet_messages_per_window",
                                "envelope_size_bytes",
                                "submit_timeout_secs",
                            ],
                        );
                    }
                    if let Some(gateway) = t.get("submission_gateway").and_then(TomlValue::as_table)
                    {
                        warn_unknown_keys_in(
                            gateway,
                            &[
                                "allowed_relays",
                                "validator_control_base_path",
                                "release_window_ms",
                                "max_batch_txs",
                                "max_queue_depth",
                                "envelope_size_bytes",
                                "submit_timeout_secs",
                            ],
                        );
                    }
                }
                ("proof_assistant", TomlValue::Table(t)) => {
                    warn_unknown_keys_in(t, &["wallet", "server"]);
                    if let Some(wallet) = t.get("wallet").and_then(TomlValue::as_table) {
                        warn_unknown_keys_in(
                            wallet,
                            &[
                                "server",
                                "max_request_bytes",
                                "max_response_bytes",
                                "submit_timeout_secs",
                            ],
                        );
                    }
                    if let Some(server) = t.get("server").and_then(TomlValue::as_table) {
                        warn_unknown_keys_in(
                            server,
                            &[
                                "max_request_bytes",
                                "max_response_bytes",
                                "submit_timeout_secs",
                            ],
                        );
                    }
                }
                ("discovery", TomlValue::Table(t)) => {
                    warn_unknown_keys_in(t, &["wallet", "server"]);
                    if let Some(wallet) = t.get("wallet").and_then(TomlValue::as_table) {
                        warn_unknown_keys_in(
                            wallet,
                            &[
                                "server",
                                "publish_interval_secs",
                                "poll_interval_secs",
                                "max_request_bytes",
                                "max_response_bytes",
                                "submit_timeout_secs",
                            ],
                        );
                    }
                    if let Some(server) = t.get("server").and_then(TomlValue::as_table) {
                        warn_unknown_keys_in(
                            server,
                            &[
                                "state_path",
                                "record_ttl_secs",
                                "max_request_bytes",
                                "max_response_bytes",
                                "submit_timeout_secs",
                                "max_pending_requests",
                                "max_pending_responses",
                                "pir_arity",
                            ],
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

fn warn_unknown_keys_in(table: &toml::map::Map<String, TomlValue>, allowed: &[&str]) {
    let set: std::collections::HashSet<&str> = allowed.iter().cloned().collect();
    for key in table.keys() {
        if !set.contains(key.as_str()) {
            eprintln!("⚠️  Unknown config key '{}' (ignored)", key);
        }
    }
}

fn apply_protocol_overrides(cfg: &mut Config) {
    let _ = PROTOCOL.version;
    let _ = cfg;
}
