use unchained::config;
use unchained::{epoch::Anchor, storage};

fn main() -> anyhow::Result<()> {
    println!("🔍 Inspecting unchained Database...");

    let cfg = config::load();

    let db = storage::open(&cfg.storage)?;

    // Check for latest epoch
    if let Ok(Some(latest_epoch)) = db.get::<Anchor>("epoch", b"latest") {
        println!("📊 Latest Epoch: #{}", latest_epoch.num);
        println!(
            "   Position: epoch {} slot {}",
            latest_epoch.position.epoch, latest_epoch.position.slot
        );
        println!(
            "   Parent: {}",
            latest_epoch
                .parent_hash
                .map(hex::encode)
                .unwrap_or_else(|| "none".to_string())
        );
        println!("   Ordering path: {:?}", latest_epoch.ordering_path);
        println!(
            "   Bootstrap settlement units: {}",
            latest_epoch.settlement_unit_count
        );
        println!(
            "   Validator set hash: {}",
            hex::encode(latest_epoch.validator_set.committee_hash())
        );
        println!("   QC votes: {}", latest_epoch.qc.votes.len());
        println!("   Merkle root: {}", hex::encode(latest_epoch.merkle_root));
        println!("   Hash: {}", hex::encode(latest_epoch.hash));
    } else {
        println!("❌ No epochs found in database");
    }

    // Print genesis anchor for cross-node comparison
    if let Ok(Some(genesis)) = db.get::<Anchor>("epoch", &0u64.to_le_bytes()) {
        println!("\n🌱 Genesis:");
        println!(
            "   Position: epoch {} slot {}",
            genesis.position.epoch, genesis.position.slot
        );
        println!(
            "   Validator set hash: {}",
            hex::encode(genesis.validator_set.committee_hash())
        );
        println!("   Merkle root: {}", hex::encode(genesis.merkle_root));
        println!("   Hash: {}", hex::encode(genesis.hash));
    } else {
        println!("\n🌱 Genesis anchor not present in this DB");
    }

    // Count total bootstrap settlement units from epoch metadata.
    let mut bootstrap_units_from_epochs = 0;
    let mut total_epochs = 0;

    println!("\n💰 Scanning epochs for bootstrap settlement units...");

    // Try to get some recent epochs to see settlement unit counts
    for epoch_num in 0u64..=20 {
        if let Ok(Some(epoch)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
            total_epochs += 1;
            bootstrap_units_from_epochs += epoch.settlement_unit_count as usize;
            println!(
                "   Epoch #{}: {} bootstrap settlement units (from epoch metadata)",
                epoch.num, epoch.settlement_unit_count
            );
        }
    }

    // Scan recent epochs and inspect their committed bootstrap unit indexes.
    for epoch_num in 0u64..=20 {
        if let Ok(Some(_epoch)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
            // Per-epoch IDs live in the settlement-unit index store.
        }
    }

    println!("\n📈 Summary:");
    println!("   Total epochs: {total_epochs}");
    println!("   Total bootstrap settlement units: {bootstrap_units_from_epochs}");
    println!("   ⚠️  WARNING: This only counts units recorded in epoch metadata!");
    println!("   ⚠️  Some committed units may not yet be indexed for per-epoch inspection.");

    // Show database storage info
    println!("\n🗄️ Database Storage Info:");
    if let Ok(entries) = std::fs::read_dir(&cfg.storage.path) {
        let mut sst_files = 0;
        let mut log_files = 0;
        let mut total_size = 0u64;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "sst" {
                    sst_files += 1;
                } else if ext == "log" {
                    log_files += 1;
                }
            }
            if let Ok(metadata) = std::fs::metadata(&path) {
                total_size += metadata.len();
            }
        }

        println!("   SST files: {sst_files}");
        println!("   Log files: {log_files}");
        println!("   Total size: {total_size} bytes");
    }

    Ok(())
}
