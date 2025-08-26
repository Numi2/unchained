use unchained::{storage, epoch::Anchor, config};

fn main() -> anyhow::Result<()> {
    // Parse optional N from CLI: default to config.metrics.last_epochs_to_show (or 10)
    let args: Vec<String> = std::env::args().collect();
    let n_arg: Option<u64> = if args.len() > 1 { args[1].parse::<u64>().ok() } else { None };

    // Load configuration (same fallback behavior as other tools)
    let mut cfg = match config::load("config.toml") {
        Ok(c) => c,
        Err(_) => {
            let embedded = include_str!("../../config.toml");
            config::load_from_str(embedded)?
        }
    };
    // Resolve storage path to absolute under home if relative
    if std::path::Path::new(&cfg.storage.path).is_relative() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let abs = std::path::Path::new(&home)
            .join(".unchained")
            .join("unchained_data");
        cfg.storage.path = abs.to_string_lossy().into_owned();
    }

    let db = storage::open(&cfg.storage);

    let default_n = cfg.metrics.last_epochs_to_show;
    let show_n = n_arg.unwrap_or(default_n.max(1));

    println!("📚 Listing last {} epoch(s)", show_n);

    // Determine latest epoch
    let latest = match db.get::<Anchor>("epoch", b"latest")? {
        Some(a) => a,
        None => {
            println!("❌ No epochs found in database at '{}'", cfg.storage.path);
            return Ok(());
        }
    };

    // Walk backwards from latest.num, up to show_n epochs or until genesis
    let mut count: u64 = 0;
    let mut current = latest.num;
    while count < show_n {
        if let Some(anchor) = db.get::<Anchor>("epoch", &current.to_le_bytes())? {
            // Basic anchor info
            println!("\n# Epoch {}", anchor.num);
            println!("   hash: {}", hex::encode(anchor.hash));
            println!("   merkle_root: {}", hex::encode(anchor.merkle_root));
            println!("   difficulty: {}", anchor.difficulty);
            println!("   coin_count: {}", anchor.coin_count);
            println!("   cumulative_work: {}", anchor.cumulative_work);
            println!("   mem_kib: {}", anchor.mem_kib);

            // Selected coin IDs recorded for this epoch (if any)
            match db.get_selected_coin_ids_for_epoch(anchor.num) {
                Ok(ids) => {
                    let len = ids.len();
                    println!("   selected_ids: {}", len);
                    if len > 0 {
                        let preview = len.min(5);
                        for (i, id) in ids.iter().take(preview).enumerate() {
                            println!("     - [{}] {}", i, hex::encode(id));
                        }
                        if len > preview { println!("     … {} more", len - preview); }
                        
                        // Show creator distribution for this epoch
                        let mut creators = std::collections::HashSet::new();
                        for id in &ids {
                            if let Ok(Some(coin)) = db.get::<unchained::coin::Coin>("coin", id) {
                                creators.insert(coin.creator_address);
                            }
                        }
                        println!("   unique_creators: {} ({}% of selected)", 
                                creators.len(), 
                                if len > 0 { (creators.len() * 100) / len } else { 0 });
                    }
                }
                Err(e) => {
                    println!("   selected_ids: n/a ({})", e);
                }
            }

            // Stored sorted leaves for this epoch (if present)
            match db.get_epoch_leaves(anchor.num) {
                Ok(Some(leaves)) => {
                    println!("   leaves: {} ({} bytes each)", leaves.len(), 32);
                    if leaves.len() as u32 != anchor.coin_count {
                        println!("   ⚠️  leaves/coin_count mismatch: {} vs {}", leaves.len(), anchor.coin_count);
                    }
                }
                Ok(None) => println!("   leaves: none"),
                Err(e) => println!("   leaves: n/a ({})", e),
            }
        } else {
            // Stop if the epoch record is missing
            break;
        }

        if current == 0 { break; }
        current = current.saturating_sub(1);
        count += 1;
    }

    if count == 0 {
        println!("❌ No epoch records found to list");
    }

    Ok(())
}


