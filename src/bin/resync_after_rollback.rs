use unchained::{storage, epoch::Anchor, config};
use rocksdb::WriteBatch;

fn main() -> anyhow::Result<()> {
    println!("🔄 Post-Rollback Resync Tool");
    println!("============================");
    println!("This tool forces a clean resync after using fix_fork");
    println!("⚠️  WARNING: This will clear all epochs after the rollback point");
    println!();
    
    // Parse command line args
    let args: Vec<String> = std::env::args().collect();
    let keep_up_to = if args.len() > 1 {
        args[1].parse::<u64>()?
    } else {
        println!("Usage: {} <epoch_to_keep_up_to>", args[0]);
        println!("Example: {} 7000", args[0]);
        return Ok(());
    };
    
    // Load config
    let mut cfg = match config::load("config.toml") {
        Ok(c) => c,
        Err(_) => {
            let embedded = include_str!("../../config.toml");
            config::load_from_str(embedded)?
        }
    };
    
    // Resolve path
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
    
    // Step 1: Analyze current state
    println!("📊 Analyzing database state...");
    
    let current_latest = match db.get::<Anchor>("epoch", b"latest")? {
        Some(a) => {
            println!("   Current latest: epoch {}", a.num);
            println!("   Hash: {}", hex::encode(&a.hash[..8]));
            a
        }
        None => {
            eprintln!("❌ No latest epoch found");
            return Ok(());
        }
    };

    let keep_anchor = match db.get::<Anchor>("epoch", &keep_up_to.to_le_bytes())? {
        Some(a) => {
            println!("   Keep up to: epoch {}", a.num);
            println!("   Hash: {}", hex::encode(&a.hash[..8]));
            a
        }
        None => {
            eprintln!("❌ Target epoch {} not found", keep_up_to);
            return Ok(());
        }
    };

    if current_latest.num <= keep_up_to {
        println!("✅ No cleanup needed - current latest {} <= target {}", current_latest.num, keep_up_to);
        return Ok(());
    }

    println!();
    println!("🎯 This will:");
    println!("   • Keep epochs 0 through {}", keep_up_to);
    println!("   • Remove epochs {} through {}", keep_up_to + 1, current_latest.num);
    println!("   • Clear all associated coins, spends, and indices");
    println!("   • Reset sync state to force full resync from network");
    println!();
    
    print!("Continue? (y/N): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "y" {
        println!("Aborted.");
        return Ok(());
    }

    println!();
    println!("🧹 Starting cleanup...");

    // Get all column family handles
    let epoch_cf = db.db.cf_handle("epoch").expect("epoch CF missing");
    let anchor_cf = db.db.cf_handle("anchor").expect("anchor CF missing");
    let coin_cf = db.db.cf_handle("coin").expect("coin CF missing");
    let coin_epoch_cf = db.db.cf_handle("coin_epoch").expect("coin_epoch CF missing");
    let spend_cf = db.db.cf_handle("spend").expect("spend CF missing");
    let nullifier_cf = db.db.cf_handle("nullifier").expect("nullifier CF missing");
    let commitment_used_cf = db.db.cf_handle("commitment_used").expect("commitment_used CF missing");
    let epoch_selected_cf = db.db.cf_handle("epoch_selected").expect("epoch_selected CF missing");
    let epoch_leaves_cf = db.db.cf_handle("epoch_leaves").expect("epoch_leaves CF missing");
    let coin_candidate_cf = db.db.cf_handle("coin_candidate").expect("coin_candidate CF missing");

    let mut batch = WriteBatch::default();
    let mut epochs_removed = 0;
    let mut coins_removed = 0;
    let mut spends_removed = 0;

    // Step 1: Remove epochs after keep_up_to
    for epoch_num in (keep_up_to + 1)..=current_latest.num {
        if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
            println!("   Removing epoch {} (hash: {})", epoch_num, hex::encode(&anchor.hash[..8]));
            
            // Remove epoch entry
            batch.delete_cf(epoch_cf, &epoch_num.to_le_bytes());
            batch.delete_cf(anchor_cf, &anchor.hash);
            epochs_removed += 1;

            // Remove associated coins and spends
            if let Ok(selected_ids) = db.get_selected_coin_ids_for_epoch(epoch_num) {
                for coin_id in selected_ids {
                    // Remove coin
                    batch.delete_cf(coin_cf, &coin_id);
                    batch.delete_cf(coin_epoch_cf, &coin_id);
                    coins_removed += 1;

                    // Remove spend if exists
                    if let Ok(Some(spend)) = db.get::<unchained::transfer::Spend>("spend", &coin_id) {
                        batch.delete_cf(spend_cf, &coin_id);
                        batch.delete_cf(nullifier_cf, &spend.nullifier);
                        spends_removed += 1;

                        // Remove commitment if V3 spend
                        if spend.unlock_preimage.is_some() {
                            if let Some(next_lock) = spend.next_lock_hash {
                                if let Ok(chain_id) = db.get_chain_id() {
                                    let cid = unchained::crypto::commitment_id_v1(
                                        &spend.to.one_time_pk, 
                                        &spend.to.kyber_ct, 
                                        &next_lock, 
                                        &spend.coin_id, 
                                        spend.to.amount_le, 
                                        &chain_id
                                    );
                                    batch.delete_cf(commitment_used_cf, &cid);
                                }
                            }
                        }
                    }
                }
            }

            // Remove epoch indices
            let prefix = epoch_num.to_le_bytes();
            
            // Remove selected index entries
            let iter = db.db.iterator_cf(epoch_selected_cf, rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
            for item in iter {
                if let Ok((k, _)) = item {
                    if k.len() >= 8 && &k[0..8] == prefix {
                        batch.delete_cf(epoch_selected_cf, k);
                        continue;
                    }
                }
                break;
            }

            // Remove leaves
            batch.delete_cf(epoch_leaves_cf, &prefix);
        }
    }

    // Step 2: Clean up coin candidates that reference removed epochs
    let iter = db.db.iterator_cf(coin_candidate_cf, rocksdb::IteratorMode::Start);
    let mut candidates_to_remove = Vec::new();
    
    for item in iter {
        if let Ok((k, v)) = item {
            if let Ok(candidate) = bincode::deserialize::<unchained::coin::CoinCandidate>(&v) {
                // Check if candidate references a removed epoch
                if let Ok(Some(anchor)) = db.get::<Anchor>("anchor", &candidate.epoch_hash) {
                    if anchor.num > keep_up_to {
                        candidates_to_remove.push(k.to_vec());
                    }
                }
            }
        }
    }
    
    for key in candidates_to_remove {
        batch.delete_cf(coin_candidate_cf, &key);
    }

    // Step 3: Update latest pointer to the keep_up_to epoch
    if let Ok(bytes) = bincode::serialize(&keep_anchor) {
        batch.put_cf(epoch_cf, b"latest", &bytes);
    }

    // Step 4: Clear sync cursors to force full resync
    if let Some(headers_cf) = db.db.cf_handle("headers") {
        batch.delete_cf(headers_cf, b"cursor");
    }

    println!("   Writing changes to database...");
    db.db.write(batch)?;

    println!();
    println!("✅ Cleanup completed:");
    println!("   • Removed {} epochs", epochs_removed);
    println!("   • Removed {} coins", coins_removed);
    println!("   • Removed {} spends", spends_removed);
    println!("   • Reset latest to epoch {}", keep_up_to);
    println!();
    println!("🚀 Next steps:");
    println!("   1. Restart your node");
    println!("   2. The node will automatically sync from epoch {} onwards", keep_up_to + 1);
    println!("   3. Monitor sync progress in the logs");
    println!();
    println!("💡 The node will now accept the network's version of epochs after {}", keep_up_to);

    Ok(())
}
