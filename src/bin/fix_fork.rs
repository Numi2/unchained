use unchained::{storage, epoch::Anchor, transfer::Spend, config};
use rocksdb::WriteBatch;
use std::collections::HashSet;

fn main() -> anyhow::Result<()> {
    println!("🔧 Fork Fix Tool - Surgical Rollback");
    println!("=====================================");
    
    // Parse command line args
    let args: Vec<String> = std::env::args().collect();
    let rollback_to = if args.len() > 1 {
        args[1].parse::<u64>().unwrap_or(6229)
    } else {
        6229
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
    println!("\n📊 Analyzing database state...");
    
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
    
    if current_latest.num <= rollback_to {
        println!("✅ Already at or below epoch {}. Nothing to do.", rollback_to);
        return Ok(());
    }
    
    // Check the rollback target exists
    let rollback_anchor = match db.get::<Anchor>("epoch", &rollback_to.to_le_bytes())? {
        Some(a) => {
            println!("\n🎯 Rollback target: epoch {}", a.num);
            println!("   Hash: {}", hex::encode(&a.hash[..8]));
            println!("   Cumulative work: {}", a.cumulative_work);
            a
        }
        None => {
            eprintln!("❌ Epoch {} not found", rollback_to);
            return Ok(());
        }
    };
    
    // Step 2: Check for fork at the problematic epoch
    let problem_epoch = rollback_to + 1;
    if let Ok(Some(bad_epoch)) = db.get::<Anchor>("epoch", &problem_epoch.to_le_bytes()) {
        println!("\n⚠️  Found epoch {} with hash: {}", problem_epoch, hex::encode(&bad_epoch.hash[..8]));
        
        // Compute what the hash should be
        let mut h = blake3::Hasher::new();
        h.update(&bad_epoch.merkle_root);
        h.update(&rollback_anchor.hash);
        let expected = *h.finalize().as_bytes();
        
        if expected != bad_epoch.hash {
            println!("❌ Hash mismatch detected!");
            println!("   Expected parent: {}", hex::encode(&rollback_anchor.hash[..8]));
            println!("   Computed hash should be: {}", hex::encode(&expected[..8]));
            println!("   But stored hash is: {}", hex::encode(&bad_epoch.hash[..8]));
            println!("   This confirms a fork at epoch {}", problem_epoch);
        }
    }
    
    println!("\n⚠️  This will remove epochs {} through {}", rollback_to + 1, current_latest.num);
    println!("   Continue? (y/N)");
    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Aborted.");
        return Ok(());
    }
    
    // Step 3: Collect coins to remove (from epochs being rolled back)
    println!("\n🔍 Collecting data to remove...");
    let mut coins_to_remove = HashSet::new();
    let mut spends_to_remove = HashSet::new();
    let mut epochs_processed = 0;
    
    for epoch_num in (rollback_to + 1)..=current_latest.num {
        // Get selected coin IDs for this epoch
        if let Ok(coin_ids) = db.get_selected_coin_ids_for_epoch(epoch_num) {
            for id in coin_ids {
                coins_to_remove.insert(id);
                // Also check for spends of these coins
                if let Ok(Some(spend)) = db.get::<Spend>("spend", &id) {
                    spends_to_remove.insert(spend.coin_id);
                }
            }
        }
        epochs_processed += 1;
    }
    
    println!("   Epochs to remove: {}", epochs_processed);
    println!("   Coins to remove: {}", coins_to_remove.len());
    println!("   Spends to remove: {}", spends_to_remove.len());
    
    // Step 4: Create rollback batch
    println!("\n📝 Creating rollback transaction...");
    let mut batch = WriteBatch::default();
    
    // Get column families
    let epoch_cf = db.db.cf_handle("epoch").ok_or_else(|| anyhow::anyhow!("'epoch' CF not found"))?;
    let anchor_cf = db.db.cf_handle("anchor").ok_or_else(|| anyhow::anyhow!("'anchor' CF not found"))?;
    let coin_cf = db.db.cf_handle("coin").ok_or_else(|| anyhow::anyhow!("'coin' CF not found"))?;
    let coin_epoch_cf = db.db.cf_handle("coin_epoch").ok_or_else(|| anyhow::anyhow!("'coin_epoch' CF not found"))?;
    let selected_cf = db.db.cf_handle("epoch_selected").ok_or_else(|| anyhow::anyhow!("'epoch_selected' CF not found"))?;
    let leaves_cf = db.db.cf_handle("epoch_leaves").ok_or_else(|| anyhow::anyhow!("'epoch_leaves' CF not found"))?;
    let spend_cf = db.db.cf_handle("spend").ok_or_else(|| anyhow::anyhow!("'spend' CF not found"))?;
    let nullifier_cf = db.db.cf_handle("nullifier").ok_or_else(|| anyhow::anyhow!("'nullifier' CF not found"))?;
    
    // Remove epochs
    for epoch_num in (rollback_to + 1)..=current_latest.num {
        batch.delete_cf(epoch_cf, epoch_num.to_le_bytes());
        
        // Remove anchor by hash if we have it
        if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
            batch.delete_cf(anchor_cf, anchor.hash);
        }
        
        // Remove epoch_selected entries
        let prefix = epoch_num.to_le_bytes();
        let iter = db.db.iterator_cf(selected_cf, rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        for item in iter {
            if let Ok((k, _)) = item {
                if k.len() >= 8 && &k[0..8] == prefix {
                    batch.delete_cf(selected_cf, k);
                } else {
                    break; // Past this epoch's entries
                }
            }
        }
        
        // Remove epoch leaves
        batch.delete_cf(leaves_cf, &prefix);
    }
    
    // Remove coins
    for coin_id in &coins_to_remove {
        batch.delete_cf(coin_cf, coin_id);
        batch.delete_cf(coin_epoch_cf, coin_id);
    }
    
    // Remove spends and nullifiers
    for coin_id in &spends_to_remove {
        if let Ok(Some(spend)) = db.get::<Spend>("spend", coin_id) {
            batch.delete_cf(spend_cf, coin_id);
            batch.delete_cf(nullifier_cf, spend.nullifier);
        }
    }
    
    // Set the rollback epoch as latest
    if let Ok(bytes) = bincode::serialize(&rollback_anchor) {
        batch.put_cf(epoch_cf, b"latest", &bytes);
    }
    
    // Step 5: Apply the rollback
    println!("\n⚙️  Applying rollback...");
    match db.db.write(batch) {
        Ok(()) => {
            println!("✅ Successfully rolled back to epoch {}", rollback_to);
            println!("   Database is now clean at epoch {}", rollback_to);
            println!("   Hash: {}", hex::encode(&rollback_anchor.hash[..8]));
        }
        Err(e) => {
            eprintln!("❌ Rollback failed: {}", e);
            return Err(e.into());
        }
    }
    
    // Step 6: Verify the rollback
    println!("\n🔍 Verifying rollback...");
    
    if let Ok(Some(new_latest)) = db.get::<Anchor>("epoch", b"latest") {
        if new_latest.num == rollback_to {
            println!("✅ Latest epoch is now: {}", new_latest.num);
            
            // Check that bad epochs are gone
            if db.get::<Anchor>("epoch", &problem_epoch.to_le_bytes())?.is_none() {
                println!("✅ Epoch {} has been removed", problem_epoch);
            } else {
                println!("⚠️  Warning: Epoch {} still exists", problem_epoch);
            }
        } else {
            println!("⚠️  Latest epoch is {} (expected {})", new_latest.num, rollback_to);
        }
    }
    
    println!("\n✅ Fork fix complete!");
    println!("🚀 You can now restart your node with:");
    println!("   cargo run --release --bin unchained mine");
    println!("\nThe node will request and validate the correct epoch {} from the network.", problem_epoch);
    
    Ok(())
}
