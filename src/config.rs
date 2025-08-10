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
}

#[derive(Debug, Deserialize, Clone)]
pub struct Net {
    pub listen_port: u16,
    // Removed unused iroh_key_path to avoid confusion
    #[serde(default)]
    pub bootstrap: Vec<String>,          // multiaddrs
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,                  // maximum peer connections
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,    // connection timeout
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_sync_timeout")]
    pub sync_timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct P2p {
    #[serde(default = "default_max_validation_failures_per_peer")]
    pub max_validation_failures_per_peer: u32,
    #[serde(default = "default_peer_ban_duration_secs")]
    pub peer_ban_duration_secs: u64,
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
    #[serde(default = "default_target_coins")]
    pub target_coins_per_epoch: u32,
    // Removed max_coins_per_epoch under threshold-only winners
    #[serde(default = "default_retarget_interval")]
    pub retarget_interval: u64,
    // Selection rules
    #[serde(default = "default_max_selected")] 
    pub max_selected_per_epoch: u32, // N_max
    #[serde(default = "default_selected_min")] 
    pub selected_min_per_epoch: u32, // λ_min
    #[serde(default = "default_selected_max")] 
    pub selected_max_per_epoch: u32, // λ_max
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
}

#[derive(Debug, Deserialize, Clone)]
pub struct Metrics {
    #[serde(default = "default_bind")]
    pub bind: String,
}

fn default_mem() -> u32   { 65_536 }          // 64 MiB
fn default_bind() -> String { "127.0.0.1:9100".into() }

// Epoch retargeting defaults
fn default_target_coins() -> u32 { 100 }
fn default_retarget_interval() -> u64 { 10 }
fn default_max_selected() -> u32 { 64 }
fn default_selected_min() -> u32 { 8 }
fn default_selected_max() -> u32 { 32 }


// Mining memory retargeting defaults
pub fn default_min_mem() -> u32 { 16_384 }        // 16 MiB
pub fn default_max_mem() -> u32 { 262_144 }       // 256 MiB
pub fn default_max_memory_adjustment() -> f64 { 1.5 }

// Miner stability defaults
pub fn default_heartbeat_interval() -> u64 { 30 }  // 30 seconds
pub fn default_max_consecutive_failures() -> u32 { 5 }
pub fn default_max_mining_attempts() -> u64 { 1_000_000 }

// Network defaults for production deployment
fn default_max_peers() -> u32 { 100 }
fn default_connection_timeout() -> u64 { 30 }
fn default_sync_timeout() -> u64 { 180 }

// P2P defaults
fn default_max_validation_failures_per_peer() -> u32 { 10 }
fn default_peer_ban_duration_secs() -> u64 { 3600 }
fn default_rate_limit_window_secs() -> u64 { 60 }
fn default_max_messages_per_window() -> u32 { 100 }


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
    // Sanity clamps
    if cfg.mining.mem_kib < cfg.mining.min_mem_kib { cfg.mining.mem_kib = cfg.mining.min_mem_kib; }
    if cfg.mining.mem_kib > cfg.mining.max_mem_kib { cfg.mining.mem_kib = cfg.mining.max_mem_kib; }
    Ok(cfg)
}

fn warn_unknown_keys(val: &TomlValue) {
    // Known sections and keys
    use std::collections::HashSet;
    let top_allowed: HashSet<&str> = ["net","p2p","storage","epoch","mining","metrics"].into_iter().collect();
    if let Some(table) = val.as_table() {
        for (k, v) in table.iter() {
            if !top_allowed.contains(k.as_str()) {
                eprintln!("⚠️  Unknown top-level config section '{}' (ignored)", k);
                continue;
            }
            match (k.as_str(), v) {
                ("net", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "listen_port","bootstrap","max_peers","connection_timeout_secs","public_ip","sync_timeout_secs"
                ]),
                ("p2p", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "max_validation_failures_per_peer","peer_ban_duration_secs","rate_limit_window_secs","max_messages_per_window"
                ]),
                ("storage", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["path"]),
                ("epoch", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "seconds","target_coins_per_epoch","retarget_interval","max_selected_per_epoch","selected_min_per_epoch","selected_max_per_epoch"
                ]),
                ("mining", TomlValue::Table(t)) => warn_unknown_keys_in(t, &[
                    "enabled","mem_kib","min_mem_kib","max_mem_kib","max_memory_adjustment"
                ]),
                ("metrics", TomlValue::Table(t)) => warn_unknown_keys_in(t, &["bind"]),
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
