use serde::Deserialize;
use std::{fs, path::Path};
use anyhow::{Context, Result};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub net: Net,
    pub storage: Storage,
    pub epoch: Epoch,
    pub mining: Mining,
    pub metrics: Metrics,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Net {
    pub listen_port: u16,
    #[serde(default)]
    pub bootstrap: Vec<String>,          // multiaddrs
}

#[derive(Debug, Deserialize, Clone)]
pub struct Storage {
    pub path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Epoch {
    pub seconds: u64,
    pub target_leading_zeros: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Mining {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_mem")]
    pub mem_kib: u32,
    #[serde(default = "default_lanes")]
    pub lanes: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Metrics {
    #[serde(default = "default_bind")]
    pub bind: String,
}

fn default_mem() -> u32   { 65_536 }          // 64 MiB
fn default_lanes() -> u32 { 4 }
fn default_bind() -> String { "0.0.0.0:9100".into() }

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