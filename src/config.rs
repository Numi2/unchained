use serde::Deserialize;
use std::{fs, path::Path};
use anyhow::{Context, Result};

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
    pub iroh_key_path: String,
    #[serde(default)]
    pub bootstrap: Vec<String>,          // multiaddrs
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,                  // maximum peer connections
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,    // connection timeout
    #[serde(default)]
    pub public_ip: Option<String>,
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
    pub target_leading_zeros: usize,
    #[serde(default = "default_target_coins")]
    pub target_coins_per_epoch: u32,
    #[serde(default = "default_retarget_interval")]
    pub retarget_interval: u64,
    pub max_difficulty_adjustment: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Mining {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mem")]
    pub mem_kib: u32,
    #[serde(default = "default_lanes")]
    pub lanes: u32,
    #[serde(default = "default_min_mem")]
    pub min_mem_kib: u32,
    #[serde(default = "default_max_mem")]
    pub max_mem_kib: u32,
    #[serde(default = "default_max_memory_adjustment")]
    pub max_memory_adjustment: f64,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,
    #[serde(default = "default_max_mining_attempts")]
    pub max_mining_attempts: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Metrics {
    #[serde(default = "default_bind")]
    pub bind: String,
}

fn default_mem() -> u32   { 65_536 }          // 64 MiB
fn default_lanes() -> u32 { 4 }
fn default_bind() -> String { "0.0.0.0:9100".into() }

// Epoch retargeting defaults
fn default_target_coins() -> u32 { 100 }
fn default_retarget_interval() -> u64 { 10 }


// Mining memory retargeting defaults
fn default_min_mem() -> u32 { 16_384 }        // 16 MiB
fn default_max_mem() -> u32 { 262_144 }       // 256 MiB
fn default_max_memory_adjustment() -> f64 { 1.5 }

// Miner stability defaults
fn default_heartbeat_interval() -> u64 { 30 }  // 30 seconds
fn default_max_consecutive_failures() -> u32 { 5 }
fn default_max_mining_attempts() -> u64 { 1_000_000 }

// Network defaults for production deployment
fn default_max_peers() -> u32 { 100 }
fn default_connection_timeout() -> u64 { 30 }

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
    toml::from_str(&text)
        .with_context(|| "📝  invalid TOML in config file".to_string())
}
