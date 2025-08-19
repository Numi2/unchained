use clap::{Parser, Subcommand};
use std::fs;
use unchained::{config, storage};

const WALLET_CF: &str = "wallet";
const WALLET_KEY: &[u8] = b"default_keypair";

#[derive(Parser)]
#[command(about = "Wallet CF helper: backup/restore/delete the wallet record in RocksDB", version)]
struct Cli {
    /// Config file path (defaults to devnet.toml for convenience)
    #[arg(short, long, default_value = "devnet.toml")]
    config: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Backup the wallet record to a file
    Backup {
        /// Output path
        #[arg(long)]
        out: String,
    },
    /// Restore the wallet record from a file
    Restore {
        /// Input path
        #[arg(long)]
        r#in: String,
    },
    /// Delete the wallet record
    Delete,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut cfg = config::load(&cli.config)?;
    // Resolve storage path to absolute like main.rs
    if std::path::Path::new(&cfg.storage.path).is_relative() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let abs = std::path::Path::new(&home).join(".unchained").join("unchained_data");
        cfg.storage.path = abs.to_string_lossy().into_owned();
    }

    let db = storage::open(&cfg.storage);
    let handle = db.db.cf_handle(WALLET_CF).ok_or_else(|| anyhow::anyhow!("'wallet' CF missing"))?;

    match cli.cmd {
        Cmd::Backup { out } => {
            match db.db.get_cf(handle, WALLET_KEY)? {
                Some(bytes) => {
                    fs::write(&out, &bytes)?;
                    println!("✅ Backed up wallet to {} ({} bytes)", out, bytes.len());
                }
                None => {
                    println!("⚠️  No wallet record found to backup");
                }
            }
        }
        Cmd::Restore { r#in } => {
            let bytes = fs::read(&r#in)?;
            db.db.put_cf(handle, WALLET_KEY, &bytes)?;
            println!("✅ Restored wallet from {} ({} bytes)", r#in, bytes.len());
        }
        Cmd::Delete => {
            db.db.delete_cf(handle, WALLET_KEY)?;
            println!("✅ Deleted wallet record (if existed)");
        }
    }

    Ok(())
}


