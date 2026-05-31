use unchained::{config, epoch::Anchor, storage};

fn main() -> anyhow::Result<()> {
    // Parse optional N from CLI: default to config.metrics.last_epochs_to_show (or 10)
    let args: Vec<String> = std::env::args().collect();
    let n_arg: Option<u64> = if args.len() > 1 {
        args[1].parse::<u64>().ok()
    } else {
        None
    };

    let cfg = config::load_resolved("config.toml")?;

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
            println!(
                "   position: epoch {} slot {}",
                anchor.position.epoch, anchor.position.slot
            );
            println!(
                "   parent_hash: {}",
                anchor
                    .parent_hash
                    .map(hex::encode)
                    .unwrap_or_else(|| "none".to_string())
            );
            println!("   ordering_path: {:?}", anchor.ordering_path);
            println!("   settlement_unit_root: {}", hex::encode(anchor.merkle_root));
            println!("   bootstrap_units: {}", anchor.settlement_unit_count);
            println!(
                "   validator_set_hash: {}",
                hex::encode(anchor.validator_set.committee_hash())
            );
            println!("   qc_votes: {}", anchor.qc.votes.len());
            println!("   qc_signed_power: {}", anchor.qc.signed_voting_power);

            // Bootstrap settlement unit IDs selected for this checkpoint (if any).
            match db.get_selected_settlement_unit_ids_for_checkpoint(anchor.num) {
                Ok(ids) => {
                    let len = ids.len();
                    println!("   selected_bootstrap_unit_ids: {}", len);
                    if len > 0 {
                        let preview = len.min(5);
                        for (i, id) in ids.iter().take(preview).enumerate() {
                            println!("     - [{}] {}", i, hex::encode(id));
                        }
                        if len > preview {
                            println!("     … {} more", len - preview);
                        }

                        // Show creator distribution for this checkpoint
                        let mut creators = std::collections::HashSet::new();
                        for id in &ids {
                            if let Ok(Some(settlement_unit)) =
                                db.get::<unchained::settlement_unit::SettlementUnit>(
                                    "settlement_unit",
                                    id,
                                )
                            {
                                creators.insert(settlement_unit.creator_address);
                            }
                        }
                        println!(
                            "   unique_bootstrap_creators: {} ({}% of committed units)",
                            creators.len(),
                            if len > 0 {
                                (creators.len() * 100) / len
                            } else {
                                0
                            }
                        );
                    }
                }
                Err(e) => {
                    println!("   selected_bootstrap_unit_ids: n/a ({})", e);
                }
            }

            // Stored sorted leaves for this checkpoint (if present)
            match db.get_checkpoint_leaves(anchor.num) {
                Ok(Some(leaves)) => {
                    println!("   leaves: {} ({} bytes each)", leaves.len(), 32);
                    if leaves.len() as u32 != anchor.settlement_unit_count {
                        println!(
                            "   ⚠️  leaves/bootstrap_units mismatch: {} vs {}",
                            leaves.len(),
                            anchor.settlement_unit_count
                        );
                    }
                }
                Ok(None) => println!("   leaves: none"),
                Err(e) => println!("   leaves: n/a ({})", e),
            }
        } else {
            // Stop if the epoch record is missing
            break;
        }

        if current == 0 {
            break;
        }
        current = current.saturating_sub(1);
        count += 1;
    }

    if count == 0 {
        println!("❌ No epoch records found to list");
    }

    Ok(())
}
