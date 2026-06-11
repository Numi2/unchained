use anyhow::{anyhow, bail, Context, Result};
use hex;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, WriteOptions, DB};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use std::io::Write;
// use std::process; // removed unused

// Using bincode for fast, compact binary serialization instead of JSON.
// Using zstd for a better compression ratio and speed than lz4.
// These are significant performance and storage efficiency improvements.

pub struct WalletStore {
    pub db: DB,
    path: String,
}

pub struct Store {
    pub db: DB,
    path: String,
}

const STORE_COLUMN_FAMILIES: &[&str] = &[
    "default",
    "epoch",
    "settlement_unit",
    "settlement_unit_candidate",
    "checkpoint_settlement_units",
    "checkpoint_leaves",
    "checkpoint_levels",
    "settlement_unit_checkpoint",
    "settlement_unit_checkpoint_index",
    "checkpoint_header",
    "head",
    "anchor",
    "validator_pool",
    "validator_committee",
    "tx",
    "consensus_evidence",
    "liveness_fault",
    "validator_penalty_event",
    "validator_reward_event",
    "anchor_proposal_observation",
    "validator_vote_observation",
    "shared_state_dag_observation",
    "fast_path_pending_tx",
    "fast_path_batch",
    "shared_state_pending_tx",
    "shared_state_batch",
    "shared_state_dag_batch",
    "shared_state_dag_round",
    "shared_state_finalized_batch",
    "peers",
    "meta",
    "shielded_note_tree",
    "shielded_nullifier_epoch",
    "shielded_root_ledger",
    "shielded_output",
    "shielded_active_nullifier",
    "shielded_spent_note",
    "external_stake_nullifier",
    "external_asset_anchor",
    "shielded_archive_provider",
    "shielded_archive_replica",
    "shielded_archive_accounting",
    "shielded_archive_custody",
];

fn build_cf_options() -> Options {
    let mut cf_opts = Options::default();
    {
        let mut block = rocksdb::BlockBasedOptions::default();
        block.set_bloom_filter(10.0, false);
        block.set_cache_index_and_filter_blocks(true);
        block.set_partition_filters(true);
        block.set_pin_l0_filter_and_index_blocks_in_cache(true);
        cf_opts.set_block_based_table_factory(&block);
    }
    cf_opts.set_write_buffer_size(64 * 1024 * 1024);
    cf_opts.set_max_write_buffer_number(2);
    cf_opts.set_target_file_size_base(64 * 1024 * 1024);
    cf_opts
}

fn build_db_options(db_path: &str) -> Options {
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    let wal_dir = format!("{db_path}/logs");
    let backup_dir = format!("{db_path}/backups");
    std::fs::create_dir_all(db_path).ok();
    std::fs::create_dir_all(&wal_dir).ok();
    std::fs::create_dir_all(&backup_dir).ok();

    db_opts.set_wal_dir(&wal_dir);
    db_opts.set_use_fsync(false);
    db_opts.set_bytes_per_sync(8 * 1024 * 1024);
    db_opts.set_wal_bytes_per_sync(8 * 1024 * 1024);
    db_opts.set_db_write_buffer_size(256 * 1024 * 1024);
    db_opts.set_max_background_jobs(8);
    db_opts.set_level_zero_slowdown_writes_trigger(20);
    db_opts.set_level_zero_stop_writes_trigger(36);
    db_opts.set_max_open_files(512);
    db_opts.set_recycle_log_file_num(4);
    db_opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::TolerateCorruptedTailRecords);
    db_opts.set_manual_wal_flush(false);
    db_opts.set_wal_size_limit_mb(64);
    db_opts.set_max_total_wal_size(512 * 1024 * 1024);
    db_opts.set_keep_log_file_num(10);
    db_opts.set_wal_ttl_seconds(24 * 60 * 60);
    db_opts.set_delete_obsolete_files_period_micros(10 * 1_000_000);
    db_opts.set_max_subcompactions(4);
    db_opts
}

fn open_db_with_families(db_path: &str, cf_names: &[&str]) -> Result<DB> {
    let cf_opts = build_cf_options();
    let db_opts = build_db_options(db_path);

    let existing_cfs: Vec<String> = match DB::list_cf(&db_opts, db_path) {
        Ok(names) => names,
        Err(_) => Vec::new(),
    };

    let mut cf_name_set: HashSet<String> = existing_cfs.into_iter().collect();
    for name in cf_names {
        cf_name_set.insert((*name).to_string());
    }
    cf_name_set.insert("default".to_string());

    let mut final_cf_names: Vec<String> = cf_name_set.into_iter().collect();
    final_cf_names.sort();
    if let Some(pos) = final_cf_names.iter().position(|n| n == "default") {
        let default = final_cf_names.remove(pos);
        final_cf_names.insert(0, default);
    }
    let cf_descriptors: Vec<ColumnFamilyDescriptor> = final_cf_names
        .iter()
        .map(|name| {
            let mut opts = cf_opts.clone();
            if name == "settlement_unit_candidate" {
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                opts.set_optimize_filters_for_hits(true);
            } else if name == "checkpoint_settlement_units"
                || name == "settlement_unit_checkpoint_index"
            {
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                opts.set_optimize_filters_for_hits(true);
            }
            ColumnFamilyDescriptor::new(name.clone(), opts)
        })
        .collect();

    DB::open_cf_descriptors(&db_opts, db_path, cf_descriptors)
        .with_context(|| format!("Failed to open database at '{db_path}'"))
}

pub fn wallet_store_path(base_path: &str) -> String {
    std::path::Path::new(base_path)
        .join("wallet_private")
        .to_string_lossy()
        .into_owned()
}

impl WalletStore {
    pub fn base_path(&self) -> &str {
        &self.path
    }

    pub fn health_check(&self) -> Result<()> {
        let test_key = b"wallet_health_check";
        self.db
            .put(test_key, b"ok")
            .with_context(|| "Wallet database write test failed")?;
        let value = self
            .db
            .get(test_key)
            .with_context(|| "Wallet database read test failed")?;
        if value.as_deref() != Some(b"ok") {
            anyhow::bail!("Wallet database read/write consistency check failed");
        }
        self.db
            .delete(test_key)
            .with_context(|| "Wallet database delete test failed")?;
        Ok(())
    }

    pub fn open(base_path: &str) -> Result<Self> {
        let db_path = wallet_store_path(base_path);
        let mut db = open_db_with_families(
            &db_path,
            &[
                "default",
                "meta",
                "wallet_secret",
                "wallet_receive_key",
                "wallet_sent_tx",
                "wallet_spent_note",
                "shielded_checkpoint",
                "shielded_owned_note",
            ],
        )?;
        if db.cf_handle("wallet").is_some() {
            db.drop_cf("wallet")
                .with_context(|| "Failed to drop obsolete wallet column family")?;
        }
        let store = Self { db, path: db_path };
        store
            .health_check()
            .with_context(|| "Wallet database health check failed during initialization")?;
        Ok(store)
    }

    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], value: &T) -> Result<()> {
        let data_to_store = bincode::serialize(value).with_context(|| {
            format!("Failed to serialize wallet value for key '{key:?}' in CF '{cf}'")
        })?;
        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Wallet column family '{}' not found", cf))?;
        self.db
            .put_cf(handle, key, &data_to_store)
            .with_context(|| {
                format!("Failed to PUT to wallet database for key '{key:?}' in CF '{cf}'")
            })
    }

    pub fn get<T: DeserializeOwned + 'static>(&self, cf: &str, key: &[u8]) -> Result<Option<T>> {
        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Wallet column family '{}' not found", cf))?;
        match self.db.get_cf(handle, key)? {
            Some(value) => match bincode::deserialize(&value[..]) {
                Ok(deser) => Ok(Some(deser)),
                Err(_) => Err(anyhow::anyhow!(
                    "Failed to deserialize wallet value for key '{:?}' in CF '{}'",
                    key,
                    cf
                )),
            },
            None => Ok(None),
        }
    }

    pub fn get_raw_bytes(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Wallet column family '{}' not found", cf))?;
        Ok(self.db.get_cf(handle, key)?.map(|v| v.to_vec()))
    }

    pub fn put_raw_bytes(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Wallet column family '{}' not found", cf))?;
        self.db.put_cf(handle, key, value).with_context(|| {
            format!("Failed to PUT raw bytes to wallet database for key '{key:?}' in CF '{cf}'")
        })
    }

    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .with_context(|| "Failed to flush wallet database")?;
        if let Err(err) = self.db.flush_wal(true) {
            eprintln!("Warning: Wallet WAL flush failed (non-critical): {err}");
        }
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        self.flush()?;
        self.db.cancel_all_background_work(true);
        Ok(())
    }
}

impl Store {
    pub fn base_path(&self) -> &str {
        &self.path
    }

    /// Perform database health check and recovery
    pub fn health_check(&self) -> Result<()> {
        // Check basic connectivity
        let test_key = b"health_check";
        self.db
            .put(test_key, b"ok")
            .with_context(|| "Database write test failed")?;
        let value = self
            .db
            .get(test_key)
            .with_context(|| "Database read test failed")?;
        if value.as_deref() != Some(b"ok") {
            anyhow::bail!("Database read/write consistency check failed");
        }
        self.db
            .delete(test_key)
            .with_context(|| "Database delete test failed")?;
        Ok(())
    }

    /// Create backup of critical blockchain data
    pub fn create_backup(&self) -> Result<String> {
        let unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let backup_dir = format!("{}/backups/{}", self.path, unix_secs);
        std::fs::create_dir_all(&backup_dir)
            .with_context(|| "Failed to create backup directory")?;

        std::fs::write(
            format!("{backup_dir}/MANIFEST"),
            "unchained rocksdb column-family backup v1\nentry: key_len_le_u32 || key || value_len_le_u32 || value\n",
        )?;

        for &cf_name in STORE_COLUMN_FAMILIES {
            if let Some(cf_handle) = self.db.cf_handle(cf_name) {
                let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
                let cf_backup_file = format!("{backup_dir}/{cf_name}.kv");
                let mut file = std::fs::File::create(&cf_backup_file)?;

                for item in iter {
                    let (key, value) = item?;
                    if key.len() > u32::MAX as usize || value.len() > u32::MAX as usize {
                        bail!("column family entry too large to back up from '{cf_name}'");
                    }
                    file.write_all(&(key.len() as u32).to_le_bytes())?;
                    file.write_all(&key)?;
                    file.write_all(&(value.len() as u32).to_le_bytes())?;
                    file.write_all(&value)?;
                }
            }
        }

        println!("Backup created at: {backup_dir}");
        Ok(backup_dir)
    }

    pub fn open(base_path: &str) -> Result<Self> {
        // Use base path directly for production, but ensure clean state
        let db_path = base_path.to_string();

        // Do not delete RocksDB LOCK file; if present and DB open fails, surface error to caller

        let mut db = open_db_with_families(&db_path, STORE_COLUMN_FAMILIES)?;
        for obsolete_cf in [
            "wallet",
            "coin",
            "coin_candidate",
            "epoch_selected",
            "coin_epoch",
            "coin_epoch_by_epoch",
            "epoch_settlement_units",
            "epoch_leaves",
            "epoch_levels",
            "settlement_unit_epoch",
            "settlement_unit_epoch_by_epoch",
            "shielded_checkpoint",
            "shielded_owned_note",
            "shielded_archive_operator",
            "shielded_archive_receipt",
            "delegation_share",
            "retarget_cache",
        ] {
            if db.cf_handle(obsolete_cf).is_some() {
                db.drop_cf(obsolete_cf).with_context(|| {
                    format!("Failed to drop obsolete chain column family '{obsolete_cf}'")
                })?;
            }
        }

        let store = Store { db, path: db_path };

        // Perform initial health check
        store
            .health_check()
            .with_context(|| "Database health check failed during initialization")?;
        Ok(store)
    }

    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], value: &T) -> Result<()> {
        // Serialize value once
        let data_to_store = bincode::serialize(value)
            .with_context(|| format!("Failed to serialize value for key '{key:?}' in CF '{cf}'"))?;

        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;

        // Use default write options; rely on WAL fsync policy
        let write_opts = WriteOptions::default();

        // Write to RocksDB first (primary store)
        self.db
            .put_cf_opt(handle, key, &data_to_store, &write_opts)
            .with_context(|| format!("Failed to PUT to database for key '{key:?}' in CF '{cf}'"))?;

        Ok(())
    }

    pub fn get<T: DeserializeOwned + 'static>(&self, cf: &str, key: &[u8]) -> Result<Option<T>> {
        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;

        match self.db.get_cf(handle, key)? {
            Some(value) => bincode::deserialize(&value[..]).map(Some).map_err(|_| {
                anyhow::anyhow!(
                    "Failed to deserialize value for key '{:?}' in CF '{}'",
                    key,
                    cf
                )
            }),
            None => Ok(None),
        }
    }

    /// Fetch raw bytes without attempting to deserialize
    pub fn get_raw_bytes(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;
        Ok(self.db.get_cf(handle, key)?.map(|v| v.to_vec()))
    }

    /// Atomically applies a set of writes.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true); // Force sync for batch writes too
                                   // Keep WAL enabled but rely on aggressive cleanup settings

        self.db
            .write_opt(batch, &write_opts)
            .with_context(|| "Failed to write batch to database")
    }

    /// Force flush all memtables to disk (useful for ensuring durability)
    pub fn flush(&self) -> Result<()> {
        // Use a simpler, more reliable flush approach
        self.db
            .flush()
            .with_context(|| "Failed to flush database")?;

        // Flush WAL to ensure data is persisted
        if let Err(e) = self.db.flush_wal(true) {
            eprintln!("Warning: WAL flush failed (non-critical): {e}");
        }

        Ok(())
    }

    /// Proper cleanup when dropping the database
    pub fn close(&self) -> Result<()> {
        // Perform final flush before closing
        self.flush()?;

        // Cancel all background work to prevent file conflicts
        self.db.cancel_all_background_work(true);

        Ok(())
    }

    /// Gets all settlement units owned by a specific address.
    pub fn get_settlement_units_by_owner(
        &self,
        owner_address: &[u8; 32],
    ) -> Result<Vec<crate::settlement_unit::SettlementUnit>> {
        let cf = self
            .db
            .cf_handle("settlement_unit")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut settlement_units = Vec::new();

        for item in iter {
            let (_key, value) = item?;
            if let Ok(settlement_unit) = crate::settlement_unit::decode_settlement_unit(&value) {
                if settlement_unit.creator_address == *owner_address {
                    settlement_units.push(settlement_unit);
                }
            }
        }

        Ok(settlement_units)
    }

    /// Iterates over all settlement units in the database.
    pub fn iterate_settlement_units(&self) -> Result<Vec<crate::settlement_unit::SettlementUnit>> {
        let cf = self
            .db
            .cf_handle("settlement_unit")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut settlement_units = Vec::new();

        for item in iter {
            let (_key, value) = item?;
            if let Ok(settlement_unit) = crate::settlement_unit::decode_settlement_unit(&value) {
                settlement_units.push(settlement_unit);
            }
        }

        Ok(settlement_units)
    }

    /// Iterates over canonically committed settlement units in deterministic checkpoint/id order.
    pub fn iterate_committed_settlement_units(
        &self,
    ) -> Result<Vec<(u64, crate::settlement_unit::SettlementUnit)>> {
        let Some(latest) = self.get::<crate::epoch::Anchor>("epoch", b"latest")? else {
            return Ok(Vec::new());
        };
        let mut committed = Vec::new();
        for checkpoint_num in 0..=latest.num {
            for settlement_unit_id in
                self.get_committed_settlement_unit_ids_for_checkpoint(checkpoint_num)?
            {
                let settlement_unit = self
                    .get::<crate::settlement_unit::SettlementUnit>(
                        "settlement_unit",
                        &settlement_unit_id,
                    )?
                    .ok_or_else(|| {
                        anyhow!(
                            "missing committed settlement unit {}",
                            hex::encode(settlement_unit_id)
                        )
                    })?;
                committed.push((checkpoint_num, settlement_unit));
            }
        }
        committed.sort_by(
            |(checkpoint_a, settlement_unit_a), (checkpoint_b, settlement_unit_b)| {
                checkpoint_a
                    .cmp(checkpoint_b)
                    .then(settlement_unit_a.id.cmp(&settlement_unit_b.id))
            },
        );
        Ok(committed)
    }

    pub fn count_committed_settlement_units(&self) -> Result<u64> {
        let Some(latest) = self.get::<crate::epoch::Anchor>("epoch", b"latest")? else {
            return Ok(0);
        };
        let mut total = 0u64;
        for checkpoint_num in 0..=latest.num {
            total = total.saturating_add(
                self.get_committed_settlement_unit_ids_for_checkpoint(checkpoint_num)?
                    .len() as u64,
            );
        }
        Ok(total)
    }

    pub fn load_committed_settlement_unit_slice(
        &self,
        start_index: u64,
        limit: usize,
    ) -> Result<Vec<(u64, crate::settlement_unit::SettlementUnit)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let Some(latest) = self.get::<crate::epoch::Anchor>("epoch", b"latest")? else {
            return Ok(Vec::new());
        };
        let mut next_index = 0u64;
        let mut committed = Vec::with_capacity(limit);
        for checkpoint_num in 0..=latest.num {
            let mut settlement_unit_ids =
                self.get_committed_settlement_unit_ids_for_checkpoint(checkpoint_num)?;
            settlement_unit_ids.sort();
            for settlement_unit_id in settlement_unit_ids {
                if next_index < start_index {
                    next_index = next_index.saturating_add(1);
                    continue;
                }
                let settlement_unit = self
                    .get::<crate::settlement_unit::SettlementUnit>(
                        "settlement_unit",
                        &settlement_unit_id,
                    )?
                    .ok_or_else(|| {
                        anyhow!(
                            "missing committed settlement unit {}",
                            hex::encode(settlement_unit_id)
                        )
                    })?;
                committed.push((checkpoint_num, settlement_unit));
                next_index = next_index.saturating_add(1);
                if committed.len() >= limit {
                    return Ok(committed);
                }
            }
        }
        Ok(committed)
    }

    /// Iterates over all settlement unit candidates in the database
    pub fn iterate_settlement_unit_candidates(
        &self,
    ) -> Result<Vec<crate::settlement_unit::SettlementUnitCandidate>> {
        let cf = self
            .db
            .cf_handle("settlement_unit_candidate")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_candidate' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut settlement_units = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            if let Ok(settlement_unit) =
                crate::settlement_unit::decode_settlement_unit_candidate(&value)
            {
                settlement_units.push(settlement_unit);
            }
        }
        Ok(settlement_units)
    }

    /// Build the composite key for settlement unit candidates:
    /// parent_checkpoint_hash || settlement_unit_id.
    pub fn candidate_key(
        parent_checkpoint_hash: &[u8; 32],
        settlement_unit_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(parent_checkpoint_hash);
        key.extend_from_slice(settlement_unit_id);
        key
    }

    /// Iterate settlement unit candidates by parent checkpoint hash using bounded prefix iteration.
    pub fn get_settlement_unit_candidates_by_parent_checkpoint_hash(
        &self,
        parent_checkpoint_hash: &[u8; 32],
    ) -> Result<Vec<crate::settlement_unit::SettlementUnitCandidate>> {
        let cf = self
            .db
            .cf_handle("settlement_unit_candidate")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_candidate' column family missing"))?;
        let mut settlement_units = Vec::new();
        let mut upper = Vec::with_capacity(64);
        upper.extend_from_slice(parent_checkpoint_hash);
        upper.extend_from_slice(&[0xFF; 32]);
        let mut ro = rocksdb::ReadOptions::default();
        ro.set_iterate_lower_bound(parent_checkpoint_hash.to_vec());
        ro.set_iterate_upper_bound(upper);
        let iter = self.db.iterator_cf_opt(
            cf,
            ro,
            rocksdb::IteratorMode::From(parent_checkpoint_hash, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (k, v) = item?;
            if k.len() < 64 {
                continue;
            }
            // within bounds due to iterate_upper_bound; keep prefix guard for safety
            if &k[0..32] != &parent_checkpoint_hash[..] {
                break;
            }
            if let Ok(settlement_unit) =
                crate::settlement_unit::decode_settlement_unit_candidate(&v)
            {
                settlement_units.push(settlement_unit);
            }
        }
        Ok(settlement_units)
    }

    /// Fetch a confirmed settlement unit by id.
    pub fn get_settlement_unit(
        &self,
        settlement_unit_id: &[u8; 32],
    ) -> Result<Option<crate::settlement_unit::SettlementUnit>> {
        let cf = self
            .db
            .cf_handle("settlement_unit")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit' column family missing"))?;
        match self.db.get_cf(cf, settlement_unit_id)? {
            Some(value) => match crate::settlement_unit::decode_settlement_unit(&value) {
                Ok(c) => Ok(Some(c)),
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Deletes settlement unit candidates outside the kept parent-checkpoint hashes.
    /// Keeps recent candidates to support reorgs.
    pub fn prune_old_candidates(&self, keep_parent_checkpoint_hash: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("settlement_unit_candidate")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_candidate' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();
        let mut pruned: u64 = 0;

        let mut parent_checkpoint_hashes = std::collections::HashSet::new();
        parent_checkpoint_hashes.insert(keep_parent_checkpoint_hash.to_vec());

        // Keep candidates for the current parent checkpoint to support reorgs.
        // For now, be very conservative and don't prune aggressively
        // This can be made more aggressive later once reorg stability is confirmed
        for item in iter {
            let (key, _) = item?;
            if key.len() >= 32 {
                let parent_checkpoint_hash = &key[0..32];
                if !parent_checkpoint_hashes.contains(parent_checkpoint_hash) {
                    // For now, be very conservative and only prune very old candidates
                    // This can be made more aggressive later once reorg stability is confirmed
                    batch.delete_cf(cf, key);
                    pruned += 1;
                }
            }
        }

        self.write_batch(batch)?;
        if pruned > 0 {
            crate::metrics::PRUNED_SETTLEMENT_UNIT_CANDIDATES.inc_by(pruned as u64);
        }
        Ok(())
    }

    /// Store sorted leaf hashes for a checkpoint for faster proof construction.
    pub fn store_checkpoint_leaves(
        &self,
        checkpoint_num: u64,
        leaves: &Vec<[u8; 32]>,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("checkpoint_leaves")
            .ok_or_else(|| anyhow::anyhow!("'checkpoint_leaves' column family missing"))?;
        let key = checkpoint_num.to_le_bytes();
        let data = bincode::serialize(leaves)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Load sorted leaf hashes for a checkpoint if present.
    pub fn get_checkpoint_leaves(&self, checkpoint_num: u64) -> Result<Option<Vec<[u8; 32]>>> {
        let cf = self
            .db
            .cf_handle("checkpoint_leaves")
            .ok_or_else(|| anyhow::anyhow!("'checkpoint_leaves' column family missing"))?;
        let key = checkpoint_num.to_le_bytes();
        match self.db.get_cf(cf, &key)? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Store full Merkle levels for a checkpoint for O(log N) proof generation without recomputation.
    pub fn store_checkpoint_levels(
        &self,
        checkpoint_num: u64,
        levels: &Vec<Vec<[u8; 32]>>,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("checkpoint_levels")
            .ok_or_else(|| anyhow::anyhow!("'checkpoint_levels' column family missing"))?;
        let key = checkpoint_num.to_le_bytes();
        let data = bincode::serialize(levels)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Load Merkle levels for a checkpoint if present. Level 0 must be sorted leaves.
    pub fn get_checkpoint_levels(&self, checkpoint_num: u64) -> Result<Option<Vec<Vec<[u8; 32]>>>> {
        let cf = self
            .db
            .cf_handle("checkpoint_levels")
            .ok_or_else(|| anyhow::anyhow!("'checkpoint_levels' column family missing"))?;
        let key = checkpoint_num.to_le_bytes();
        match self.db.get_cf(cf, &key)? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Returns the chain id (32 bytes) derived from the genesis anchor hash (epoch 0).
    /// Errors if the genesis anchor is not yet available.
    pub fn get_chain_id(&self) -> Result<[u8; 32]> {
        let genesis: Option<crate::epoch::Anchor> = self.get("epoch", &0u64.to_le_bytes())?;
        match genesis {
            Some(a) => Ok(a.hash),
            None => anyhow::bail!("Genesis anchor not found; chain id unavailable"),
        }
    }

    /// Return the canonical chain id even before the genesis anchor is materialized locally.
    pub fn effective_chain_id(&self) -> [u8; 32] {
        self.get_chain_id().unwrap_or_else(|_| protocol_chain_id())
    }

    // (moved to module scope below)

    /// Persist a signed node record into the peers CF keyed by node_id.
    pub fn store_node_record(&self, node_id: &[u8; 32], record_bytes: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("peers")
            .ok_or_else(|| anyhow::anyhow!("'peers' column family missing"))?;
        self.db.put_cf(cf, node_id, record_bytes)?;
        Ok(())
    }

    /// Load all known signed node records as raw bytes.
    pub fn load_node_records(&self) -> Result<Vec<Vec<u8>>> {
        let cf = self
            .db
            .cf_handle("peers")
            .ok_or_else(|| anyhow::anyhow!("'peers' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut records = Vec::new();
        for item in iter {
            let (_k, v) = item?;
            records.push(v.to_vec());
        }
        Ok(records)
    }

    pub fn store_validator_pool(&self, pool: &crate::staking::ValidatorPool) -> Result<()> {
        self.put("validator_pool", &pool.validator.id.0, pool)
    }

    pub fn load_validator_pool(
        &self,
        validator_id: &crate::consensus::ValidatorId,
    ) -> Result<Option<crate::staking::ValidatorPool>> {
        self.get("validator_pool", &validator_id.0)
    }

    pub fn load_validator_pools(&self) -> Result<Vec<crate::staking::ValidatorPool>> {
        let cf = self
            .db
            .cf_handle("validator_pool")
            .ok_or_else(|| anyhow::anyhow!("'validator_pool' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut pools = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            pools.push(bincode::deserialize(&value)?);
        }
        Ok(pools)
    }

    pub fn store_validator_committee(
        &self,
        validator_set: &crate::consensus::ValidatorSet,
    ) -> Result<()> {
        self.put(
            "validator_committee",
            &validator_set.epoch.to_le_bytes(),
            validator_set,
        )
    }

    pub fn load_validator_committee(
        &self,
        epoch: u64,
    ) -> Result<Option<crate::consensus::ValidatorSet>> {
        self.get("validator_committee", &epoch.to_le_bytes())
    }

    pub fn invalidate_future_validator_committees(
        &self,
        batch: &mut rocksdb::WriteBatch,
        current_epoch: u64,
    ) -> Result<()> {
        let validator_committee_cf = self
            .db
            .cf_handle("validator_committee")
            .ok_or_else(|| anyhow::anyhow!("'validator_committee' column family missing"))?;
        let iter = self
            .db
            .iterator_cf(validator_committee_cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item?;
            let epoch_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid validator committee key"))?;
            let epoch = u64::from_le_bytes(epoch_bytes);
            if epoch > current_epoch {
                batch.delete_cf(validator_committee_cf, key);
            }
        }
        Ok(())
    }

    pub fn store_shared_state_pending_tx(
        &self,
        tx_id: &[u8; 32],
        tx: &crate::transaction::Tx,
    ) -> Result<()> {
        self.put("shared_state_pending_tx", tx_id, tx)
    }

    pub fn load_shared_state_pending_tx(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<crate::transaction::Tx>> {
        self.get("shared_state_pending_tx", tx_id)
    }

    pub fn load_shared_state_pending_txs(&self) -> Result<Vec<([u8; 32], crate::transaction::Tx)>> {
        let cf = self
            .db
            .cf_handle("shared_state_pending_tx")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_pending_tx' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut txs = Vec::new();
        for item in iter {
            let (key, value) = item?;
            let key: [u8; 32] = key
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("invalid shared-state pending tx key length"))?;
            txs.push((key, bincode::deserialize(&value)?));
        }
        Ok(txs)
    }

    pub fn delete_shared_state_pending_tx(&self, tx_id: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shared_state_pending_tx")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_pending_tx' column family missing"))?;
        self.db.delete_cf(cf, tx_id)?;
        Ok(())
    }

    pub fn store_fast_path_pending_tx(
        &self,
        tx_id: &[u8; 32],
        tx: &crate::transaction::Tx,
    ) -> Result<()> {
        self.put("fast_path_pending_tx", tx_id, tx)
    }

    pub fn load_fast_path_pending_tx(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<crate::transaction::Tx>> {
        self.get("fast_path_pending_tx", tx_id)
    }

    pub fn load_fast_path_pending_txs(&self) -> Result<Vec<([u8; 32], crate::transaction::Tx)>> {
        let cf = self
            .db
            .cf_handle("fast_path_pending_tx")
            .ok_or_else(|| anyhow::anyhow!("'fast_path_pending_tx' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut txs = Vec::new();
        for item in iter {
            let (key, value) = item?;
            let key: [u8; 32] = key
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("invalid fast-path pending tx key length"))?;
            txs.push((key, bincode::deserialize(&value)?));
        }
        Ok(txs)
    }

    pub fn delete_fast_path_pending_tx(&self, tx_id: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("fast_path_pending_tx")
            .ok_or_else(|| anyhow::anyhow!("'fast_path_pending_tx' column family missing"))?;
        self.db.delete_cf(cf, tx_id)?;
        Ok(())
    }

    pub fn store_fast_path_batch(&self, batch: &crate::transaction::FastPathBatch) -> Result<()> {
        self.put("fast_path_batch", &batch.ordered_tx_root, batch)
    }

    pub fn load_fast_path_batch(
        &self,
        ordered_tx_root: &[u8; 32],
    ) -> Result<Option<crate::transaction::FastPathBatch>> {
        self.get("fast_path_batch", ordered_tx_root)
    }

    pub fn store_shared_state_batch(
        &self,
        batch: &crate::transaction::SharedStateBatch,
    ) -> Result<()> {
        self.put("shared_state_batch", &batch.ordered_tx_root, batch)
    }

    pub fn load_shared_state_batch(
        &self,
        ordered_tx_root: &[u8; 32],
    ) -> Result<Option<crate::transaction::SharedStateBatch>> {
        self.get("shared_state_batch", ordered_tx_root)
    }

    pub fn anchor_proposal_observation_key(
        proposer: crate::consensus::ValidatorId,
        position: crate::consensus::ConsensusPosition,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(32 + 8 + 4);
        key.extend_from_slice(&proposer.0);
        key.extend_from_slice(&position.epoch.to_le_bytes());
        key.extend_from_slice(&position.slot.to_le_bytes());
        key
    }

    pub fn validator_vote_observation_key(
        voter: crate::consensus::ValidatorId,
        position: crate::consensus::ConsensusPosition,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(32 + 8 + 4);
        key.extend_from_slice(&voter.0);
        key.extend_from_slice(&position.epoch.to_le_bytes());
        key.extend_from_slice(&position.slot.to_le_bytes());
        key
    }

    pub fn shared_state_dag_observation_key(
        epoch: u64,
        round: u64,
        author: crate::consensus::ValidatorId,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + 8 + 32);
        key.extend_from_slice(&epoch.to_le_bytes());
        key.extend_from_slice(&round.to_le_bytes());
        key.extend_from_slice(&author.0);
        key
    }

    pub fn store_anchor_proposal_observation(
        &self,
        key: &[u8],
        observation: &crate::evidence::StoredAnchorProposalObservation,
    ) -> Result<()> {
        self.put("anchor_proposal_observation", key, observation)
    }

    pub fn load_anchor_proposal_observation(
        &self,
        key: &[u8],
    ) -> Result<Option<crate::evidence::StoredAnchorProposalObservation>> {
        self.get("anchor_proposal_observation", key)
    }

    pub fn store_validator_vote_observation(
        &self,
        key: &[u8],
        observation: &crate::evidence::StoredValidatorVoteObservation,
    ) -> Result<()> {
        self.put("validator_vote_observation", key, observation)
    }

    pub fn load_validator_vote_observation(
        &self,
        key: &[u8],
    ) -> Result<Option<crate::evidence::StoredValidatorVoteObservation>> {
        self.get("validator_vote_observation", key)
    }

    pub fn store_shared_state_dag_observation(
        &self,
        key: &[u8],
        observation: &crate::evidence::StoredSharedStateDagObservation,
    ) -> Result<()> {
        self.put("shared_state_dag_observation", key, observation)
    }

    pub fn load_shared_state_dag_observation(
        &self,
        key: &[u8],
    ) -> Result<Option<crate::evidence::StoredSharedStateDagObservation>> {
        self.get("shared_state_dag_observation", key)
    }

    pub fn store_consensus_evidence(
        &self,
        record: &crate::evidence::ConsensusEvidenceRecord,
    ) -> Result<()> {
        let existing = self.get_raw_bytes("consensus_evidence", &record.evidence_id)?;
        if existing.is_none() {
            self.put("consensus_evidence", &record.evidence_id, record)?;
        }
        Ok(())
    }

    pub fn load_consensus_evidence(&self) -> Result<Vec<crate::evidence::ConsensusEvidenceRecord>> {
        let cf = self
            .db
            .cf_handle("consensus_evidence")
            .ok_or_else(|| anyhow::anyhow!("'consensus_evidence' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut records: Vec<crate::evidence::ConsensusEvidenceRecord> = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            records.push(
                bincode::deserialize(&value)
                    .context("deserialize consensus evidence from storage")?,
            );
        }
        records.sort_by(|left, right| {
            right
                .recorded_unix_ms
                .cmp(&left.recorded_unix_ms)
                .then(left.evidence_id.cmp(&right.evidence_id))
        });
        Ok(records)
    }

    pub fn store_liveness_fault_record(
        &self,
        record: &crate::evidence::LivenessFaultRecord,
    ) -> Result<()> {
        let existing = self.get_raw_bytes("liveness_fault", &record.evidence_id)?;
        if existing.is_none() {
            self.put("liveness_fault", &record.evidence_id, record)?;
        }
        Ok(())
    }

    pub fn load_liveness_fault_record(
        &self,
        evidence_id: &[u8; 32],
    ) -> Result<Option<crate::evidence::LivenessFaultRecord>> {
        self.get("liveness_fault", evidence_id)
    }

    pub fn load_liveness_fault_records(&self) -> Result<Vec<crate::evidence::LivenessFaultRecord>> {
        let cf = self
            .db
            .cf_handle("liveness_fault")
            .ok_or_else(|| anyhow::anyhow!("'liveness_fault' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut records: Vec<crate::evidence::LivenessFaultRecord> = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            records.push(
                bincode::deserialize(&value)
                    .context("deserialize liveness fault record from storage")?,
            );
        }
        records.sort_by(|left, right| {
            right
                .recorded_unix_ms
                .cmp(&left.recorded_unix_ms)
                .then(left.evidence_id.cmp(&right.evidence_id))
        });
        Ok(records)
    }

    pub fn store_validator_penalty_event(
        &self,
        event: &crate::staking::ValidatorPenaltyEvent,
    ) -> Result<()> {
        let existing = self.get_raw_bytes("validator_penalty_event", &event.evidence_id)?;
        if existing.is_none() {
            self.put("validator_penalty_event", &event.evidence_id, event)?;
        }
        Ok(())
    }

    pub fn load_validator_penalty_event(
        &self,
        evidence_id: &[u8; 32],
    ) -> Result<Option<crate::staking::ValidatorPenaltyEvent>> {
        self.get("validator_penalty_event", evidence_id)
    }

    pub fn load_validator_penalty_events(
        &self,
    ) -> Result<Vec<crate::staking::ValidatorPenaltyEvent>> {
        let cf = self
            .db
            .cf_handle("validator_penalty_event")
            .ok_or_else(|| anyhow::anyhow!("'validator_penalty_event' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut events: Vec<crate::staking::ValidatorPenaltyEvent> = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            events.push(
                bincode::deserialize(&value)
                    .context("deserialize validator penalty event from storage")?,
            );
        }
        events.sort_by(|left, right| {
            right
                .applied_in_epoch
                .cmp(&left.applied_in_epoch)
                .then(left.evidence_id.cmp(&right.evidence_id))
        });
        Ok(events)
    }

    pub(crate) fn validator_reward_event_key(
        anchor_num: u64,
        validator_id: &crate::consensus::ValidatorId,
    ) -> [u8; 40] {
        let mut key = [0u8; 40];
        key[..8].copy_from_slice(&anchor_num.to_le_bytes());
        key[8..].copy_from_slice(&validator_id.0);
        key
    }

    pub fn store_validator_reward_event(
        &self,
        event: &crate::staking::ValidatorRewardEvent,
    ) -> Result<()> {
        self.put(
            "validator_reward_event",
            &Self::validator_reward_event_key(event.anchor_num, &event.validator_id),
            event,
        )
    }

    pub fn load_validator_reward_events(
        &self,
    ) -> Result<Vec<crate::staking::ValidatorRewardEvent>> {
        let cf = self
            .db
            .cf_handle("validator_reward_event")
            .ok_or_else(|| anyhow::anyhow!("'validator_reward_event' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut events: Vec<crate::staking::ValidatorRewardEvent> = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            events.push(
                bincode::deserialize(&value)
                    .context("deserialize validator reward event from storage")?,
            );
        }
        events.sort_by(|left, right| {
            right
                .anchor_num
                .cmp(&left.anchor_num)
                .then(left.validator_id.cmp(&right.validator_id))
        });
        Ok(events)
    }

    pub fn load_validator_reward_events_for_anchor(
        &self,
        anchor_num: u64,
    ) -> Result<Vec<crate::staking::ValidatorRewardEvent>> {
        let cf = self
            .db
            .cf_handle("validator_reward_event")
            .ok_or_else(|| anyhow::anyhow!("'validator_reward_event' column family missing"))?;
        let prefix = anchor_num.to_le_bytes();
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        let mut events: Vec<crate::staking::ValidatorRewardEvent> = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(&prefix) {
                break;
            }
            events.push(
                bincode::deserialize(&value)
                    .context("deserialize validator reward event from storage")?,
            );
        }
        events.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        Ok(events)
    }

    fn shared_state_dag_round_key(epoch: u64, round: u64, author: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + 8 + 32);
        key.extend_from_slice(&epoch.to_le_bytes());
        key.extend_from_slice(&round.to_le_bytes());
        key.extend_from_slice(author);
        key
    }

    fn shared_state_dag_round_prefix(epoch: u64, round: u64) -> [u8; 16] {
        let mut prefix = [0u8; 16];
        prefix[..8].copy_from_slice(&epoch.to_le_bytes());
        prefix[8..].copy_from_slice(&round.to_le_bytes());
        prefix
    }

    fn shared_state_dag_epoch_prefix(epoch: u64) -> [u8; 8] {
        epoch.to_le_bytes()
    }

    pub fn store_shared_state_dag_batch(
        &self,
        batch: &crate::transaction::SharedStateDagBatch,
    ) -> Result<()> {
        let dag_cf = self
            .db
            .cf_handle("shared_state_dag_batch")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_dag_batch' column family missing"))?;
        let round_cf = self
            .db
            .cf_handle("shared_state_dag_round")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_dag_round' column family missing"))?;
        let mut write_batch = rocksdb::WriteBatch::default();
        write_batch.put_cf(
            dag_cf,
            &batch.batch_id,
            bincode::serialize(batch).context("serialize shared-state DAG batch")?,
        );
        write_batch.put_cf(
            round_cf,
            Self::shared_state_dag_round_key(batch.epoch, batch.round, &batch.author.0),
            batch.batch_id,
        );
        self.write_batch(write_batch)
    }

    pub fn load_shared_state_dag_batch(
        &self,
        batch_id: &[u8; 32],
    ) -> Result<Option<crate::transaction::SharedStateDagBatch>> {
        self.get("shared_state_dag_batch", batch_id)
    }

    pub fn load_shared_state_dag_round(
        &self,
        epoch: u64,
        round: u64,
    ) -> Result<Vec<crate::transaction::SharedStateDagBatch>> {
        let cf = self
            .db
            .cf_handle("shared_state_dag_round")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_dag_round' column family missing"))?;
        let dag_cf = self
            .db
            .cf_handle("shared_state_dag_batch")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_dag_batch' column family missing"))?;
        let prefix = Self::shared_state_dag_round_prefix(epoch, round);
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        let mut out = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if !key.as_ref().starts_with(&prefix) {
                break;
            }
            let batch_id: [u8; 32] = value
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("invalid shared-state DAG round index value"))?;
            let bytes = self
                .db
                .get_cf(dag_cf, batch_id)?
                .ok_or_else(|| anyhow!("shared-state DAG batch is missing from storage"))?;
            out.push(
                bincode::deserialize(&bytes)
                    .context("deserialize shared-state DAG batch from storage")?,
            );
        }
        Ok(out)
    }

    pub fn load_highest_shared_state_dag_round(&self, epoch: u64) -> Result<Option<u64>> {
        let cf = self
            .db
            .cf_handle("shared_state_dag_round")
            .ok_or_else(|| anyhow::anyhow!("'shared_state_dag_round' column family missing"))?;
        let prefix = Self::shared_state_dag_epoch_prefix(epoch);
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
        );
        let mut highest = None;
        for item in iter {
            let (key, _) = item?;
            if !key.as_ref().starts_with(&prefix) {
                break;
            }
            let round = u64::from_le_bytes(
                key.as_ref()[8..16]
                    .try_into()
                    .map_err(|_| anyhow!("invalid shared-state DAG round key"))?,
            );
            highest = Some(highest.map_or(round, |current: u64| current.max(round)));
        }
        Ok(highest)
    }

    pub fn has_shared_state_dag_batch_author(
        &self,
        epoch: u64,
        round: u64,
        author: &crate::consensus::ValidatorId,
    ) -> Result<bool> {
        let key = Self::shared_state_dag_round_key(epoch, round, &author.0);
        Ok(self
            .get_raw_bytes("shared_state_dag_round", &key)?
            .is_some())
    }

    pub fn mark_shared_state_dag_batch_finalized(
        &self,
        batch_id: &[u8; 32],
        anchor_num: u64,
    ) -> Result<()> {
        self.put(
            "shared_state_finalized_batch",
            batch_id,
            &anchor_num.to_le_bytes().to_vec(),
        )
    }

    pub fn load_shared_state_dag_batch_finalization(
        &self,
        batch_id: &[u8; 32],
    ) -> Result<Option<u64>> {
        match self.get::<Vec<u8>>("shared_state_finalized_batch", batch_id)? {
            Some(bytes) => {
                let array: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("invalid shared-state finalized batch marker"))?;
                Ok(Some(u64::from_le_bytes(array)))
            }
            None => Ok(None),
        }
    }

    pub fn store_shielded_note_tree(
        &self,
        tree: &crate::shielded::NoteCommitmentTree,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_note_tree")
            .ok_or_else(|| anyhow::anyhow!("'shielded_note_tree' column family missing"))?;
        let bytes = crate::canonical::encode_note_commitment_tree(tree)?;
        self.db.put_cf(cf, b"global", bytes)?;
        Ok(())
    }

    pub fn load_shielded_note_tree(&self) -> Result<Option<crate::shielded::NoteCommitmentTree>> {
        let cf = self
            .db
            .cf_handle("shielded_note_tree")
            .ok_or_else(|| anyhow::anyhow!("'shielded_note_tree' column family missing"))?;
        match self.db.get_cf(cf, b"global")? {
            Some(bytes) => Ok(Some(crate::canonical::decode_note_commitment_tree(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn store_shielded_nullifier_epoch(
        &self,
        epoch: &crate::shielded::ArchivedNullifierEpoch,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_nullifier_epoch")
            .ok_or_else(|| anyhow::anyhow!("'shielded_nullifier_epoch' column family missing"))?;
        let bytes = crate::canonical::encode_archived_nullifier_epoch(epoch)?;
        self.db.put_cf(cf, &epoch.epoch.to_le_bytes(), bytes)?;
        Ok(())
    }

    pub fn load_shielded_nullifier_epoch(
        &self,
        epoch: u64,
    ) -> Result<Option<crate::shielded::ArchivedNullifierEpoch>> {
        let cf = self
            .db
            .cf_handle("shielded_nullifier_epoch")
            .ok_or_else(|| anyhow::anyhow!("'shielded_nullifier_epoch' column family missing"))?;
        match self.db.get_cf(cf, &epoch.to_le_bytes())? {
            Some(bytes) => Ok(Some(crate::canonical::decode_archived_nullifier_epoch(
                &bytes,
            )?)),
            None => Ok(None),
        }
    }

    pub fn iterate_shielded_nullifier_epochs(
        &self,
    ) -> Result<Vec<crate::shielded::ArchivedNullifierEpoch>> {
        let cf = self
            .db
            .cf_handle("shielded_nullifier_epoch")
            .ok_or_else(|| anyhow::anyhow!("'shielded_nullifier_epoch' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut archived = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            archived.push(crate::canonical::decode_archived_nullifier_epoch(&value)?);
        }
        Ok(archived)
    }

    pub fn store_shielded_root_ledger(
        &self,
        ledger: &crate::shielded::NullifierRootLedger,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_root_ledger")
            .ok_or_else(|| anyhow::anyhow!("'shielded_root_ledger' column family missing"))?;
        let bytes = crate::canonical::encode_nullifier_root_ledger(ledger)?;
        self.db.put_cf(cf, b"ledger", bytes)?;
        Ok(())
    }

    pub fn load_shielded_root_ledger(
        &self,
    ) -> Result<Option<crate::shielded::NullifierRootLedger>> {
        let cf = self
            .db
            .cf_handle("shielded_root_ledger")
            .ok_or_else(|| anyhow::anyhow!("'shielded_root_ledger' column family missing"))?;
        match self.db.get_cf(cf, b"ledger")? {
            Some(bytes) => Ok(Some(crate::canonical::decode_nullifier_root_ledger(
                &bytes,
            )?)),
            None => Ok(None),
        }
    }

    pub fn store_shielded_archive_provider(
        &self,
        manifest: &crate::shielded::ArchiveProviderManifest,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_archive_provider")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_provider' column family missing"))?;
        let bytes = crate::canonical::encode_archive_provider_manifest(manifest)?;
        self.db.put_cf(cf, &manifest.provider_id, bytes)?;
        Ok(())
    }

    pub fn load_shielded_archive_provider(
        &self,
        provider_id: &[u8; 32],
    ) -> Result<Option<crate::shielded::ArchiveProviderManifest>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_provider")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_provider' column family missing"))?;
        match self.db.get_cf(cf, provider_id)? {
            Some(bytes) => Ok(Some(crate::canonical::decode_archive_provider_manifest(
                &bytes,
            )?)),
            None => Ok(None),
        }
    }

    pub fn load_shielded_archive_providers(
        &self,
    ) -> Result<Vec<crate::shielded::ArchiveProviderManifest>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_provider")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_provider' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut manifests = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            manifests.push(crate::canonical::decode_archive_provider_manifest(&value)?);
        }
        Ok(manifests)
    }

    pub fn store_shielded_archive_replica(
        &self,
        replica: &crate::shielded::ArchiveReplicaAttestation,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_archive_replica")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_replica' column family missing"))?;
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&replica.provider_id);
        key.extend_from_slice(&replica.shard_id.to_le_bytes());
        let bytes = crate::canonical::encode_archive_replica_attestation(replica)?;
        self.db.put_cf(cf, key, bytes)?;
        Ok(())
    }

    pub fn load_shielded_archive_replicas(
        &self,
    ) -> Result<Vec<crate::shielded::ArchiveReplicaAttestation>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_replica")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_replica' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut replicas = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            replicas.push(crate::canonical::decode_archive_replica_attestation(
                &value,
            )?);
        }
        Ok(replicas)
    }

    pub fn store_shielded_archive_service_ledger(
        &self,
        ledger: &crate::shielded::ArchiveServiceLedger,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_archive_accounting")
            .ok_or_else(|| {
                anyhow::anyhow!("'shielded_archive_accounting' column family missing")
            })?;
        let bytes = crate::canonical::encode_archive_service_ledger(ledger)?;
        self.db.put_cf(cf, &ledger.provider_id, bytes)?;
        Ok(())
    }

    pub fn load_shielded_archive_service_ledger(
        &self,
        provider_id: &[u8; 32],
    ) -> Result<Option<crate::shielded::ArchiveServiceLedger>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_accounting")
            .ok_or_else(|| {
                anyhow::anyhow!("'shielded_archive_accounting' column family missing")
            })?;
        match self.db.get_cf(cf, provider_id)? {
            Some(bytes) => Ok(Some(crate::canonical::decode_archive_service_ledger(
                &bytes,
            )?)),
            None => Ok(None),
        }
    }

    pub fn load_shielded_archive_service_ledgers(
        &self,
    ) -> Result<Vec<crate::shielded::ArchiveServiceLedger>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_accounting")
            .ok_or_else(|| {
                anyhow::anyhow!("'shielded_archive_accounting' column family missing")
            })?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut ledgers = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            ledgers.push(crate::canonical::decode_archive_service_ledger(&value)?);
        }
        Ok(ledgers)
    }

    pub fn store_shielded_archive_custody_commitment(
        &self,
        commitment: &crate::shielded::ArchiveCustodyCommitment,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_archive_custody")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_custody' column family missing"))?;
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&commitment.provider_id);
        key.extend_from_slice(&commitment.shard_id.to_le_bytes());
        let bytes = crate::canonical::encode_archive_custody_commitment(commitment)?;
        self.db.put_cf(cf, key, bytes)?;
        Ok(())
    }

    pub fn load_shielded_archive_custody_commitments(
        &self,
    ) -> Result<Vec<crate::shielded::ArchiveCustodyCommitment>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_custody")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_custody' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut commitments = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            commitments.push(crate::canonical::decode_archive_custody_commitment(&value)?);
        }
        Ok(commitments)
    }

    pub fn store_shielded_output(
        &self,
        tx_id: &[u8; 32],
        output_index: u32,
        output: &crate::transaction::ShieldedOutput,
    ) -> Result<()> {
        let mut key = Vec::with_capacity(36);
        key.extend_from_slice(tx_id);
        key.extend_from_slice(&output_index.to_le_bytes());
        self.put("shielded_output", &key, output)
    }

    pub fn iterate_shielded_outputs(
        &self,
    ) -> Result<Vec<([u8; 32], u32, crate::transaction::ShieldedOutput)>> {
        let cf = self
            .db
            .cf_handle("shielded_output")
            .ok_or_else(|| anyhow::anyhow!("'shielded_output' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut outputs = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if key.len() != 36 {
                continue;
            }
            let mut tx_id = [0u8; 32];
            tx_id.copy_from_slice(&key[..32]);
            let mut index_bytes = [0u8; 4];
            index_bytes.copy_from_slice(&key[32..]);
            let output = bincode::deserialize::<crate::transaction::ShieldedOutput>(&value)?;
            outputs.push((tx_id, u32::from_le_bytes(index_bytes), output));
        }
        Ok(outputs)
    }

    pub fn count_shielded_outputs(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle("shielded_output")
            .ok_or_else(|| anyhow::anyhow!("'shielded_output' column family missing"))?;
        Ok(self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .count() as u64)
    }

    pub fn load_shielded_output_slice(
        &self,
        start_index: u64,
        limit: usize,
    ) -> Result<Vec<([u8; 32], u32, crate::transaction::ShieldedOutput)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let cf = self
            .db
            .cf_handle("shielded_output")
            .ok_or_else(|| anyhow::anyhow!("'shielded_output' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut outputs = Vec::with_capacity(limit);
        for (position, item) in iter.enumerate() {
            let position = position as u64;
            if position < start_index {
                continue;
            }
            let (key, value) = item?;
            if key.len() != 36 {
                continue;
            }
            let mut tx_id = [0u8; 32];
            tx_id.copy_from_slice(&key[..32]);
            let mut index_bytes = [0u8; 4];
            index_bytes.copy_from_slice(&key[32..]);
            let output = bincode::deserialize::<crate::transaction::ShieldedOutput>(&value)?;
            outputs.push((tx_id, u32::from_le_bytes(index_bytes), output));
            if outputs.len() >= limit {
                break;
            }
        }
        Ok(outputs)
    }

    pub fn external_stake_nullifier_exists(
        &self,
        asset_id: &[u8; 32],
        external_nullifier: &[u8; 32],
    ) -> Result<bool> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(asset_id);
        key.extend_from_slice(external_nullifier);
        Ok(self
            .get_raw_bytes("external_stake_nullifier", &key)?
            .is_some())
    }

    pub fn store_external_stake_nullifier(
        &self,
        asset_id: &[u8; 32],
        external_nullifier: &[u8; 32],
        stake_position_commitment: &[u8; 32],
    ) -> Result<()> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(asset_id);
        key.extend_from_slice(external_nullifier);
        self.put("external_stake_nullifier", &key, stake_position_commitment)
    }

    pub fn external_asset_anchor_exists(
        &self,
        asset: crate::external_asset::ExternalAsset,
        anchor_hash: &[u8; 32],
    ) -> Result<bool> {
        let key = crate::zcash::external_anchor_storage_key(asset, anchor_hash);
        Ok(self.get_raw_bytes("external_asset_anchor", &key)?.is_some())
    }

    pub fn store_zcash_stake_anchor(
        &self,
        asset: crate::external_asset::ExternalAsset,
        anchor: &crate::zcash::ZcashStakeAnchor,
    ) -> Result<[u8; 32]> {
        anchor.validate_for_asset(asset)?;
        let anchor_hash = anchor.anchor_hash();
        let key = crate::zcash::external_anchor_storage_key(asset, &anchor_hash);
        self.put("external_asset_anchor", &key, anchor)?;
        Ok(anchor_hash)
    }

    pub fn store_shielded_active_nullifier_epoch(
        &self,
        active: &crate::shielded::ActiveNullifierEpoch,
    ) -> Result<()> {
        self.put("shielded_active_nullifier", b"active", active)
    }

    pub fn load_shielded_active_nullifier_epoch(
        &self,
    ) -> Result<Option<crate::shielded::ActiveNullifierEpoch>> {
        self.get("shielded_active_nullifier", b"active")
    }

    pub fn mark_shielded_note_spent(
        &self,
        note_commitment: &[u8; 32],
        current_nullifier: &[u8; 32],
    ) -> Result<()> {
        self.put("shielded_spent_note", note_commitment, current_nullifier)
    }

    pub fn is_shielded_note_spent(&self, note_commitment: &[u8; 32]) -> Result<bool> {
        Ok(self
            .get_raw_bytes("shielded_spent_note", note_commitment)?
            .is_some())
    }

    /// Gets settlement unit IDs selected by a checkpoint commitment.
    pub fn get_selected_settlement_unit_ids_for_checkpoint(
        &self,
        checkpoint_num: u64,
    ) -> Result<Vec<[u8; 32]>> {
        let sel_cf = self
            .db
            .cf_handle("checkpoint_settlement_units")
            .ok_or_else(|| {
                anyhow::anyhow!("'checkpoint_settlement_units' column family missing")
            })?;
        let mut ids = Vec::new();
        let start_key = checkpoint_num.to_le_bytes();
        let iter = self.db.iterator_cf(
            sel_cf,
            rocksdb::IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (k, _v) = item?;
            if k.len() < 8 + 32 {
                continue;
            }
            if &k[0..8] != start_key {
                break;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&k[8..8 + 32]);
            ids.push(id);
        }
        Ok(ids)
    }

    /// Records a fully recovered settlement unit in checkpoint/id scan order.
    pub fn put_committed_settlement_unit_checkpoint_index(
        &self,
        checkpoint_num: u64,
        settlement_unit_id: &[u8; 32],
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("settlement_unit_checkpoint_index")
            .ok_or_else(|| {
                anyhow::anyhow!("'settlement_unit_checkpoint_index' column family missing")
            })?;
        let mut key = Vec::with_capacity(8 + 32);
        key.extend_from_slice(&checkpoint_num.to_le_bytes());
        key.extend_from_slice(settlement_unit_id);
        self.db.put_cf(cf, &key, &[])?;
        Ok(())
    }

    /// Gets fully recovered settlement unit IDs in checkpoint/id scan order.
    pub fn get_committed_settlement_unit_ids_for_checkpoint(
        &self,
        checkpoint_num: u64,
    ) -> Result<Vec<[u8; 32]>> {
        let cf = self
            .db
            .cf_handle("settlement_unit_checkpoint_index")
            .ok_or_else(|| {
                anyhow::anyhow!("'settlement_unit_checkpoint_index' column family missing")
            })?;
        let start_key = checkpoint_num.to_le_bytes();
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );
        let mut ids: Vec<[u8; 32]> = Vec::new();
        for item in iter {
            let (k, _v) = item?;
            if k.len() < 8 + 32 {
                continue;
            }
            if &k[0..8] != start_key {
                break;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&k[8..8 + 32]);
            ids.push(id);
        }
        Ok(ids)
    }

    /// Persist a mapping settlement_unit_id -> checkpoint number that committed it.
    pub fn put_settlement_unit_checkpoint(
        &self,
        settlement_unit_id: &[u8; 32],
        checkpoint_num: u64,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("settlement_unit_checkpoint")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_checkpoint' column family missing"))?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&checkpoint_num.to_le_bytes());
        self.db.put_cf(cf, settlement_unit_id, &bytes)?;
        Ok(())
    }

    /// Delete a mapping settlement_unit_id -> checkpoint number (used during reorgs).
    pub fn delete_settlement_unit_checkpoint(&self, settlement_unit_id: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("settlement_unit_checkpoint")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_checkpoint' column family missing"))?;
        self.db.delete_cf(cf, settlement_unit_id)?;
        Ok(())
    }

    /// Retrieve the checkpoint number that committed the given settlement unit, if known.
    pub fn get_settlement_unit_checkpoint(
        &self,
        settlement_unit_id: &[u8; 32],
    ) -> Result<Option<u64>> {
        let cf = self
            .db
            .cf_handle("settlement_unit_checkpoint")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_checkpoint' column family missing"))?;
        match self.db.get_cf(cf, settlement_unit_id)? {
            Some(v) => {
                if v.len() != 8 {
                    return Ok(None);
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&v);
                Ok(Some(u64::from_le_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Retrieve the checkpoint number for a settlement unit from the committed index.
    pub fn get_checkpoint_for_settlement_unit(
        &self,
        settlement_unit_id: &[u8; 32],
    ) -> Result<Option<u64>> {
        self.get_settlement_unit_checkpoint(settlement_unit_id)
    }

    /// Persist headers sync cursor (highest requested and highest stored header heights)
    pub fn put_headers_cursor(&self, highest_requested: u64, highest_stored: u64) -> Result<()> {
        let cf = self
            .db
            .cf_handle("meta")
            .ok_or_else(|| anyhow::anyhow!("'meta' column family missing"))?;
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&highest_requested.to_le_bytes());
        buf[8..].copy_from_slice(&highest_stored.to_le_bytes());
        self.db.put_cf(cf, b"headers_cursor", &buf)?;
        Ok(())
    }

    /// Load headers sync cursor; returns (highest_requested, highest_stored)
    pub fn get_headers_cursor(&self) -> Result<(u64, u64)> {
        let cf = self
            .db
            .cf_handle("meta")
            .ok_or_else(|| anyhow::anyhow!("'meta' column family missing"))?;
        if let Some(v) = self.db.get_cf(cf, b"headers_cursor")? {
            if v.len() == 16 {
                let mut a = [0u8; 8];
                a.copy_from_slice(&v[..8]);
                let mut b = [0u8; 8];
                b.copy_from_slice(&v[8..]);
                return Ok((u64::from_le_bytes(a), u64::from_le_bytes(b)));
            }
        }
        Ok((0, 0))
    }

    /// Persist a header-only checkpoint fetched by the headers pipeline.
    pub fn put_checkpoint_header(&self, header: &crate::epoch::Anchor) -> Result<()> {
        self.put("checkpoint_header", &header.num.to_le_bytes(), header)
    }

    /// Fetch a header-only checkpoint by height.
    pub fn get_checkpoint_header(
        &self,
        checkpoint_num: u64,
    ) -> Result<Option<crate::epoch::Anchor>> {
        self.get("checkpoint_header", &checkpoint_num.to_le_bytes())
    }

    /// Convenience: fetch anchor by checkpoint number.
    pub fn get_anchor_by_checkpoint_num(
        &self,
        checkpoint_num: u64,
    ) -> Result<Option<crate::epoch::Anchor>> {
        self.get("epoch", &checkpoint_num.to_le_bytes())
    }

    /// Gets the total number of settlement units in the database.
    pub fn settlement_unit_count(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle("settlement_unit")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }

    /// Export all known anchors (by checkpoint number) into a compressed snapshot file.
    /// Returns the number of anchors written.
    pub fn export_anchors_snapshot(&self, out_path: &str) -> Result<usize> {
        use std::io::Write as _;

        let epoch_cf = self
            .db
            .cf_handle("epoch")
            .ok_or_else(|| anyhow::anyhow!("'epoch' column family missing"))?;
        let iter = self.db.iterator_cf(epoch_cf, rocksdb::IteratorMode::Start);

        let mut anchors: Vec<crate::epoch::Anchor> = Vec::new();
        for item in iter {
            let (k, v) = item?;
            // Only include keys that are exactly 8 bytes. Skip the "latest" marker and others.
            if k.len() != 8 {
                continue;
            }
            let anchor: crate::epoch::Anchor = match bincode::deserialize(&v[..]) {
                Ok(a) => a,
                Err(_) => continue,
            };
            anchors.push(anchor);
        }
        // Sort by checkpoint number to make snapshot deterministic.
        anchors.sort_by_key(|a| a.num);
        if anchors.is_empty() {
            anyhow::bail!("No anchors found to export");
        }

        #[derive(Serialize, Deserialize)]
        struct AnchorsSnapshotV1 {
            chain_id: [u8; 32],
            anchors: Vec<crate::epoch::Anchor>,
        }

        let chain_id = anchors
            .first()
            .map(|a| a.hash)
            .ok_or_else(|| anyhow::anyhow!("Missing genesis anchor in snapshot export"))?;
        let snapshot = AnchorsSnapshotV1 { chain_id, anchors };

        let raw = bincode::serialize(&snapshot).context("Failed to serialize anchors snapshot")?;
        let mut encoder =
            zstd::Encoder::new(Vec::new(), 10).context("Failed to create zstd encoder")?;
        encoder
            .write_all(&raw)
            .context("Failed to write snapshot to encoder")?;
        let compressed = encoder
            .finish()
            .context("Failed to finalize zstd compression")?;
        std::fs::write(out_path, compressed)
            .with_context(|| format!("Failed to write snapshot file to '{}'", out_path))?;

        Ok(snapshot.anchors.len())
    }

    /// Import anchors from a compressed snapshot file. Missing anchors are inserted;
    /// existing anchors are left untouched. Returns the number of anchors inserted.
    pub fn import_anchors_snapshot(&self, path: &str) -> Result<u64> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct AnchorsSnapshotV1 {
            chain_id: [u8; 32],
            anchors: Vec<crate::epoch::Anchor>,
        }

        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read snapshot file '{}'", path))?;
        let data = zstd::decode_all(&bytes[..]).context("Failed to decompress anchors snapshot")?;
        let snapshot: AnchorsSnapshotV1 = bincode::deserialize(&data)
            .context("Failed to deserialize anchors snapshot (expected AnchorsSnapshotV1)")?;

        if self
            .get::<crate::epoch::Anchor>("epoch", b"latest")?
            .is_some()
        {
            bail!("anchor snapshot import requires an empty database");
        }

        if snapshot.anchors.is_empty() {
            bail!("anchor snapshot is empty");
        }

        let mut anchors = snapshot.anchors;
        anchors.sort_by_key(|anchor| anchor.num);
        validate_anchor_snapshot(&anchors, snapshot.chain_id)?;

        let mut inserted: u64 = 0;
        let mut batch = WriteBatch::default();

        let epoch_cf = self
            .db
            .cf_handle("epoch")
            .ok_or_else(|| anyhow::anyhow!("'epoch' column family missing"))?;
        let anchor_cf = self
            .db
            .cf_handle("anchor")
            .ok_or_else(|| anyhow::anyhow!("'anchor' column family missing"))?;

        let mut highest_num: Option<u64> = None;
        for a in anchors.iter() {
            let key = a.num.to_le_bytes();
            let exists = match self.db.get_cf(epoch_cf, &key) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => return Err(e.into()),
            };
            if !exists {
                let ser = bincode::serialize(a).context("Failed to serialize anchor for import")?;
                batch.put_cf(epoch_cf, key, &ser);
                batch.put_cf(anchor_cf, &a.hash, &ser);
                inserted += 1;
            }
            highest_num = Some(highest_num.map_or(a.num, |h| h.max(a.num)));
        }

        // Update latest pointer if we imported any anchors
        if inserted > 0 {
            if let Some(h) = highest_num {
                if let Some(v) = self.get_raw_bytes("epoch", &h.to_le_bytes())? {
                    batch.put_cf(epoch_cf, b"latest", &v);
                }
            }
            self.write_batch(batch)?;
        }

        Ok(inserted)
    }

    /// Gets statistics about the database
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let settlement_unit_count = self.settlement_unit_count()?;
        let tx_count = self.tx_count()?;
        let epoch_count = self.epoch_count()?;

        Ok(DatabaseStats {
            settlement_unit_count,
            tx_count,
            epoch_count,
        })
    }

    /// Gets the total number of canonical transactions in the database.
    pub fn tx_count(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow::anyhow!("'tx' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }

    /// Gets the total number of epochs in the database
    pub fn epoch_count(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle("epoch")
            .ok_or_else(|| anyhow::anyhow!("'epoch' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }

    /// Deletes settlement unit candidates older than those referenced by the provided parent checkpoints.
    /// Keeps candidate entries whose key prefix is in `keep_hashes`.
    pub fn prune_candidates_keep_hashes(&self, keep_hashes: &[[u8; 32]]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("settlement_unit_candidate")
            .ok_or_else(|| anyhow::anyhow!("'settlement_unit_candidate' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();
        let mut pruned: u64 = 0;

        let keep: std::collections::HashSet<&[u8; 32]> = keep_hashes.iter().collect();
        for item in iter {
            let (key, _) = item?;
            if key.len() >= 32 {
                let mut prefix = [0u8; 32];
                prefix.copy_from_slice(&key[0..32]);
                if !keep.contains(&prefix) {
                    batch.delete_cf(cf, key);
                    pruned += 1;
                }
            }
        }
        self.write_batch(batch)?;
        if pruned > 0 {
            crate::metrics::PRUNED_SETTLEMENT_UNIT_CANDIDATES.inc_by(pruned as u64);
        }
        Ok(())
    }
}

pub fn protocol_chain_id() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0u8; 32]);
    *hasher.finalize().as_bytes()
}

fn validate_anchor_snapshot(anchors: &[crate::epoch::Anchor], chain_id: [u8; 32]) -> Result<()> {
    let Some(genesis) = anchors.first() else {
        bail!("anchor snapshot is empty");
    };
    if genesis.num != 0 {
        bail!("anchor snapshot must start at genesis");
    }
    if genesis.hash != chain_id {
        bail!("snapshot chain_id does not match the genesis anchor hash");
    }
    genesis
        .validate_against_parent(None)
        .map_err(|err| anyhow!("invalid snapshot genesis checkpoint: {err}"))?;

    let mut validated = Vec::with_capacity(anchors.len());
    validated.push(genesis.clone());

    for anchor in anchors.iter().skip(1) {
        let prev = validated
            .last()
            .ok_or_else(|| anyhow!("validated snapshot unexpectedly missing parent"))?;
        anchor
            .validate_against_parent(Some(prev))
            .map_err(|err| anyhow!("invalid snapshot checkpoint {}: {err}", anchor.num))?;
        validated.push(anchor.clone());
    }

    Ok(())
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub settlement_unit_count: u64,
    pub tx_count: u64,
    pub epoch_count: u64,
}
