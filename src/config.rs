use serde::Deserialize;
use std::{fs, path::Path};
use anyhow::{Context, Result};
use toml::Value as TomlValue;



#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub net: Net,
    pub p2p: P2p,
    pub storage: Storage,
    pub epoch: Epoch,
    pub mining: Mining,
    pub metrics: Metrics,
    #[serde(default)]
    pub compact: Compact,
    #[serde(default)]
    pub wallet: WalletCfg,
    #[serde(default)]
    pub offers: Offers,
    #[serde(default)]
    pub bridge: BridgeConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Net {
    pub listen_port: u16,
    #[serde(default)]
    pub bootstrap: Vec<String>,          // multiaddrs
    #[serde(default)]
    pub peer_exchange: bool,             // gossip known peers
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,                  // maximum peer connections
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,    // connection timeout
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_sync_timeout")]
    pub sync_timeout_secs: u64,
    /// Optional static ban list of libp2p PeerIds. Connections and dials to these peers are blocked.
    #[serde(default)]
    pub banned_peer_ids: Vec<String>,
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
    #[serde(default = "default_target_leading_zeros")]
    pub target_leading_zeros: usize,
    #[serde(default = "default_target_coins")]
    pub target_coins_per_epoch: u32,
    /// Hard cap of selected coins per epoch (consensus). If not specified,
    /// defaults to the same as target_coins_per_epoch.
    #[serde(default = "default_max_coins")]
    pub max_coins_per_epoch: u32,
    #[serde(default = "default_retarget_interval")]
    pub retarget_interval: u64,
    /// Minimum/maximum difficulty clamp for retargeting
    #[serde(default = "default_difficulty_min")]
    pub difficulty_min: usize,
    #[serde(default = "default_difficulty_max")]
    pub difficulty_max: usize,



    #[serde(default = "default_retarget_upper_pct")]
    pub retarget_upper_pct: u64,
    #[serde(default = "default_retarget_lower_pct")]
    pub retarget_lower_pct: u64,
}



#[derive(Debug, Deserialize, Clone)]
pub struct Mining {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mem")]
    pub mem_kib: u32,
    #[serde(default = "default_min_mem")]

    pub min_mem_kib: u32,
    #[serde(default = "default_max_mem")]

    pub max_mem_kib: u32,
    #[serde(default = "default_max_memory_adjustment")]
    pub max_memory_adjustment: f64,
    /// Miner heartbeat timeout interval (seconds)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    /// Maximum attempts per epoch before giving up
    #[serde(default = "default_max_mining_attempts", alias = "max_mining_attempts")]
    pub max_attempts: u64,
    /// Attempts between runtime yield/anchor checks
    #[serde(default = "default_check_interval_attempts")]
    pub check_interval_attempts: u64,


    #[serde(default = "default_workers")]
    pub workers: u32,
    /// Offload Argon2 hashing to blocking threads
    #[serde(default = "default_offload_blocking")]
    pub offload_blocking: bool,
}



#[inline(never)]
#[allow(non_snake_case)]
fn lO0OIO0l() -> u64 {
    (0b1010_1110u64 | 0x10u64) + 0x20u64

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
    /// If missing > max_missing_pct, fall back to legacy requests
    #[serde(default = "default_compact_max_missing_pct")]
    pub max_missing_pct: u8,
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

#[derive(Debug, Deserialize, Clone)]
pub struct Offers {
    /// Bind address for the offers HTTP API (SSE + GET). Defaults to 127.0.0.1:9120
    #[serde(default = "default_offers_bind")]
    pub bind: String,
    /// TTL for offers durability window (seconds)
    #[serde(default = "default_offers_ttl_secs")]
    pub ttl_secs: u64,
    /// Maximum number of offers retained in the store
    #[serde(default = "default_offers_max_entries")]
    pub max_entries: u64,
    /// Maximum allowed size for offer payloads (bytes)
    #[serde(default = "default_offers_max_size_bytes")]
    pub max_size_bytes: u64,
    /// Per-peer daily cap on accepted offers (count)
    #[serde(default = "default_offers_per_peer_daily")]
    pub per_peer_daily: u64,
    /// Minimum allowed amount in offers (coins)
    #[serde(default = "default_offers_min_amount")]
    pub min_amount: u64,
    /// Default fee basis points to expect/advertise if not present
    #[serde(default = "default_offers_fee_bps_default")]
    pub fee_bps_default: u64,
}

impl Default for Offers {
    fn default() -> Self {
        Self {
            bind: default_offers_bind(),
            ttl_secs: default_offers_ttl_secs(),
            max_entries: default_offers_max_entries(),
            max_size_bytes: default_offers_max_size_bytes(),
            per_peer_daily: default_offers_per_peer_daily(),
            min_amount: default_offers_min_amount(),
            fee_bps_default: default_offers_fee_bps_default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct WalletCfg {
    #[serde(default = "default_auto_serve_commitments")]
    pub auto_serve_commitments: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BridgeConfig {
    #[serde(default = "default_sui_rpc_url")]
    pub sui_rpc_url: String,
    #[serde(default = "default_sui_package_id")]
    pub sui_package_id: String,
    #[serde(default = "default_sui_config_object")]
    pub sui_config_object: String,
    /// Stealth paycode where Unchained coins are locked during bridge_out
    #[serde(default)]
    pub vault_paycode: Option<String>,
    /// Optional admin token required for admin endpoints. If None, admin endpoints are open on localhost.
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default = "default_bridge_enabled")]
    pub bridge_enabled: bool,
    #[serde(default = "default_bridge_min_amount")]
    pub min_amount: u64,
    #[serde(default = "default_bridge_max_amount")]
    pub max_amount: u64,
    #[serde(default = "default_bridge_fee_bps")]
    pub fee_basis_points: u64,
    /// Bind for the lightweight bridge HTTP RPC (JSON). Defaults to 127.0.0.1:9110
    #[serde(default = "default_bridge_rpc_bind")]
    pub rpc_bind: String,
    /// Rolling window for rate limits (seconds)
    #[serde(default = "default_bridge_rate_window_secs")]
    pub rate_window_secs: u64,
    /// Per-Unchained-sender daily cap (in coins)
    #[serde(default = "default_bridge_per_address_daily_cap")]
    pub per_address_daily_cap: u64,
    /// Global daily cap (in coins)
    #[serde(default = "default_bridge_global_daily_cap")]
    pub global_daily_cap: u64,
    /// Sui bridge module name containing the burn/mint events
    #[serde(default = "default_sui_bridge_module")]
    pub sui_bridge_module: String,
    /// Sui burn event type name emitted on bridge burn
    #[serde(default = "default_sui_burn_event")]
    pub sui_burn_event: String,
    /// Optional Sui coin type that must match in the burn event (e.g. 0x..::unch::UNCH)
    #[serde(default)]
    pub sui_coin_type: Option<String>,
    // --- x402 payment integration (served via bridge RPC bind) ---
    #[serde(default = "default_x402_enabled")]
    pub x402_enabled: bool,
    /// Minimum confirmations required for x402 receipts (currently only 0 is supported)
    #[serde(default = "default_x402_min_confs")]
    pub x402_min_confs: u32,
    /// Invoice TTL in milliseconds
    #[serde(default = "default_x402_invoice_ttl_ms")]
    pub x402_invoice_ttl_ms: u64,
    /// Recipient handle (stealth address or KeyDoc). If None, server wallet address is used.
    #[serde(default)]
    pub x402_recipient_handle: Option<String>,
    /// Path prefixes that will be protected and require x402 payment if accessed via HTTP
    #[serde(default = "default_x402_protected_prefixes")]
    pub x402_protected_prefixes: Vec<String>,
    /// Optional EVM x402 facilitator (e.g., Base Sepolia/Testnet or Mainnet URL)
    #[serde(default)]
    pub x402_facilitator_url: Option<String>,
    /// EVM network name (e.g., "base-sepolia", "base") for informational display
    #[serde(default)]
    pub x402_evm_network: Option<String>,
    /// EVM recipient address for facilitator-based payments
    #[serde(default)]
    pub x402_evm_recipient: Option<String>,
    /// Static price in USD micros for protected resources when offering EVM method
    #[serde(default)]
    pub x402_price_usd_micros: Option<u64>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            sui_rpc_url: default_sui_rpc_url(),
            sui_package_id: default_sui_package_id(),
            sui_config_object: default_sui_config_object(),
            vault_paycode: None,
            admin_token: None,
            bridge_enabled: default_bridge_enabled(),
            min_amount: default_bridge_min_amount(),
            max_amount: default_bridge_max_amount(),
            fee_basis_points: default_bridge_fee_bps(),
            rpc_bind: default_bridge_rpc_bind(),
            rate_window_secs: default_bridge_rate_window_secs(),
            per_address_daily_cap: default_bridge_per_address_daily_cap(),
            global_daily_cap: default_bridge_global_daily_cap(),
            sui_bridge_module: default_sui_bridge_module(),
            sui_burn_event: default_sui_burn_event(),
            sui_coin_type: default_sui_coin_type(),
            x402_enabled: default_x402_enabled(),
            x402_min_confs: default_x402_min_confs(),
            x402_invoice_ttl_ms: default_x402_invoice_ttl_ms(),
            x402_recipient_handle: None,
            x402_protected_prefixes: default_x402_protected_prefixes(),
            x402_facilitator_url: None,
            x402_evm_network: None,
            x402_evm_recipient: None,
            x402_price_usd_micros: None,
        }
    }
}

fn default_mem() -> u32   { 65_536 }          // 64 MiB
fn default_bind() -> String { "127.0.0.1:9100".into() }
fn default_last_epochs_to_show() -> u64 { 10 }
fn default_auto_serve_commitments() -> bool { true }

// Epoch retargeting defaults
fn default_target_coins() -> u32 { 11 }
fn default_max_coins() -> u32 { 111 }
fn default_retarget_interval() -> u64 { 2000 }
fn default_difficulty_min() -> usize { 1 }
fn default_difficulty_max() -> usize { 12 }
fn default_retarget_upper_pct() -> u64 { 110 }
fn default_retarget_lower_pct() -> u64 { 90 }
fn default_target_leading_zeros() -> usize { 2 }



// Mining memory retargeting defaults
pub fn default_min_mem() -> u32 { 16_192 }        // 16 MiB
pub fn default_max_mem() -> u32 { 262_144 }       // 256 MiB
pub fn default_max_memory_adjustment() -> f64 { 1.5 }

// Miner stability defaults
pub fn default_heartbeat_interval() -> u64 { 30 }  // 30 seconds
pub fn default_max_consecutive_failures() -> u32 { 5 }
pub fn default_max_mining_attempts() -> u64 { 1_000_000 }
fn default_check_interval_attempts() -> u64 { 1_000 }
fn default_workers() -> u32 { 1 }
fn default_offload_blocking() -> bool { true }

// Network defaults for production deployment
fn default_max_peers() -> u32 { 100 }
fn default_connection_timeout() -> u64 { 30 }
fn default_sync_timeout() -> u64 { 180 }

// P2P defaults
fn default_max_validation_failures_per_peer() -> u32 { 10 }
fn default_peer_ban_duration_secs() -> u64 { 3600 }
fn default_rate_limit_window_secs() -> u64 { 60 }
fn default_max_messages_per_window() -> u32 { 100 }

// Compact defaults
fn default_compact_prefill_count() -> u32 { 4 }
fn default_compact_short_id_len() -> u8 { 8 }
fn default_compact_max_missing_pct() -> u8 { 20 }


// Bridge defaults (Sui Testnet deployment provided by user)
fn default_sui_rpc_url() -> String { "https://fullnode.testnet.sui.io:443".into() }
fn default_sui_package_id() -> String { "0xbf27e02789a91a48ac1356c3416fe44638d9a477a616fa74d6317403e4116089".into() }
fn default_sui_config_object() -> String { "0x37f9f48977d272674bae2d4d217e842398dac2073868ff638a8ff019c0bdc50e".into() }
fn default_bridge_enabled() -> bool { true }
fn default_bridge_min_amount() -> u64 { 1 }
fn default_bridge_max_amount() -> u64 { 1_000_000 }
fn default_bridge_fee_bps() -> u64 { 10 }
fn default_bridge_rpc_bind() -> String { "127.0.0.1:9110".into() }
fn default_bridge_rate_window_secs() -> u64 { 24 * 60 * 60 }
fn default_bridge_per_address_daily_cap() -> u64 { 1_000_000_000 }
fn default_bridge_global_daily_cap() -> u64 { 10_000_000_000 }
fn default_sui_bridge_module() -> String { "simple_bridge".into() }
fn default_sui_burn_event() -> String { "Burn".into() }
fn default_sui_coin_type() -> Option<String> { Some("0xbf27e02789a91a48ac1356c3416fe44638d9a477a616fa74d6317403e4116089::unch::UNCH".into()) }

// x402 defaults
fn default_x402_enabled() -> bool { false }
fn default_x402_min_confs() -> u32 { 0 }
fn default_x402_invoice_ttl_ms() -> u64 { 5 * 60 * 1000 }
fn default_x402_protected_prefixes() -> Vec<String> { vec!["/paid".into()] }

// Offers defaults
fn default_offers_bind() -> String { "127.0.0.1:9120".into() }
fn default_offers_ttl_secs() -> u64 { 60 * 60 } // 1 hour
fn default_offers_max_entries() -> u64 { 50_000 }
fn default_offers_max_size_bytes() -> u64 { 512 * 1024 } // 512 KiB
fn default_offers_per_peer_daily() -> u64 { 10_000 }
fn default_offers_min_amount() -> u64 { 1 }
fn default_offers_fee_bps_default() -> u64 { 0 }


/// Read the TOML file at `p` and deserialize into `Config`.
/// *Adds context* so user errors print a friendlier message.
///
/// # Errors
/// * Returns an anyhow::Error if the file cannot be read or parsed.
pub fn load<P: AsRef<Path>>(p: P) -> Result<Config> {
    let text = fs::read_to_string(&p)
        .with_context(|| format!("🗂️  couldn’t read config file {}", p.as_ref().display()))?;
    // Parse to TOML to detect unknown keys for diagnostics
    let val: TomlValue = toml::from_str(&text)
        .with_context(|| "📝  invalid TOML in config file".to_string())?;
    warn_unknown_keys(&val);
    let mut cfg: Config = val.try_into().with_context(|| "📝  invalid config schema".to_string())?;
    // Harden epoch duration regardless of file contents (obfuscated)
    cfg.epoch.seconds = lO0OIO0l();
    // Sanity clamps
    if cfg.mining.mem_kib < cfg.mining.min_mem_kib { cfg.mining.mem_kib = cfg.mining.min_mem_kib; }
    if cfg.mining.mem_kib > cfg.mining.max_mem_kib { cfg.mining.mem_kib = cfg.mining.max_mem_kib; }
    Ok(cfg)
}

/// Parse configuration from a TOML string and apply the same validations as `load`.
pub fn load_from_str(text: &str) -> Result<Config> {
    let val: TomlValue = toml::from_str(text)
        .with_context(|| "📝  invalid TOML in embedded/default config".to_string())?;
    warn_unknown_keys(&val);
    let mut cfg: Config = val.try_into().with_context(|| "📝  invalid config schema".to_string())?;
    // Harden epoch duration regardless of embedded/default contents (obfuscated)
    cfg.epoch.seconds = lO0OIO0l();
    // Sanity clamps
    if cfg.mining.mem_kib < cfg.mining.min_mem_kib { cfg.mining.mem_kib = cfg.mining.min_mem_kib; }
    if cfg.mining.mem_kib > cfg.mining.max_mem_kib { cfg.mining.mem_kib = cfg.mining.max_mem_kib; }
    Ok(cfg)
}

fn warn_unknown_keys(val: &TomlValue) {
    // Known sections and keys
    use std::collections::HashSet;
    let top_allowed: HashSet<&str> = ["net","p2p","storage","epoch","mining","metrics","wallet","offers","bridge"].into_iter().collect();
    if let Some(table) = val.as_table() {
        for (k, v) in table.iter() {
            if !top_allowed.contains(k.as_str()) {
                eprintln!("⚠️  Unknown top-level config section '{}' (ignored)", k);
                continue;
            }
            match (k.as_str(), v) {
                ("net", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "listen_port","bootstrap","peer_exchange","max_peers","connection_timeout_secs","public_ip","sync_timeout_secs","banned_peer_ids"
                ]),
                ("p2p", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "max_validation_failures_per_peer","peer_ban_duration_secs","rate_limit_window_secs","max_messages_per_window"
                ]),
                ("storage", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["path"]),
                ("epoch", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "seconds","target_leading_zeros","target_coins_per_epoch","max_coins_per_epoch","_interval","difficulty_min","difficulty_max","retarget_upper_pct","retarget_lower_pct"
                ]),
                ("mining", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "enabled","mem_kib","min_mem_kib","max_mem_kib","max_memory_adjustment","heartbeat_interval_secs","max_attempts","max_mining_attempts","check_interval_attempts","workers","offload_blocking"
                ]),
                ("metrics", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["bind","last_epochs_to_show"]),
                ("wallet", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["auto_serve_commitments"]),
                ("offers", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "bind","ttl_secs","max_entries","max_size_bytes","per_peer_daily","min_amount","fee_bps_default"
                ]),
                ("bridge", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "sui_rpc_url","sui_package_id","sui_config_object","vault_paycode","admin_token","bridge_enabled","min_amount","max_amount","fee_basis_points","rpc_bind","rate_window_secs","per_address_daily_cap","global_daily_cap","sui_bridge_module","sui_burn_event","sui_coin_type","x402_enabled","x402_min_confs","x402_invoice_ttl_ms","x402_recipient_handle","x402_protected_prefixes","x402_facilitator_url","x402_evm_network","x402_evm_recipient","x402_price_usd_micros"
                ]),
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



