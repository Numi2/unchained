use anyhow::{anyhow, bail, Context, Result};
use hex;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, WriteOptions, DB};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
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
    mirror_tx: Option<std::sync::mpsc::Sender<(String, Vec<u8>)>>, // background mirroring
}

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
            if name == "coin_candidate" {
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                opts.set_optimize_filters_for_hits(true);
            } else if name == "epoch_selected" || name == "coin_epoch_by_epoch" {
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
        let backup_dir = format!(
            "{}/backups/{}",
            self.path,
            chrono::Utc::now().format("%Y%m%d_%H%M%S")
        );
        std::fs::create_dir_all(&backup_dir)
            .with_context(|| "Failed to create backup directory")?;

        // Backup critical chain-state column families.
        for cf_name in [
            "epoch",
            "anchor",
            "validator_pool",
            "validator_committee",
            "tx",
            "consensus_evidence",
            "anchor_proposal_observation",
            "validator_vote_observation",
            "shared_state_dag_observation",
            "shared_state_pending_tx",
            "shared_state_batch",
            "meta",
            "shielded_note_tree",
            "shielded_nullifier_epoch",
            "shielded_root_ledger",
            "shielded_output",
            "shielded_active_nullifier",
            "shielded_spent_note",
        ] {
            if let Some(cf_handle) = self.db.cf_handle(cf_name) {
                let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
                let cf_backup_dir = format!("{backup_dir}/{cf_name}");
                std::fs::create_dir_all(&cf_backup_dir)?;

                for (i, item) in iter.enumerate() {
                    let (key, value) = item?;
                    let backup_file = format!("{cf_backup_dir}/{i:05}.dat");
                    let backup_data = format!("{key:?}:{value:?}");
                    std::fs::write(backup_file, backup_data)?;
                }
            }
        }

        // Also backup coins directory using cross-platform approach
        let coins_backup = format!("{backup_dir}/coins");
        if let Err(e) = copy_dir_all(&self.coins_dir(), &coins_backup) {
            eprintln!("Warning: Coins backup failed: {e}");
        }

        println!("✅ Backup created at: {backup_dir}");
        Ok(backup_dir)
    }

    pub fn open(base_path: &str) -> Result<Self> {
        // Use base path directly for production, but ensure clean state
        let db_path = base_path.to_string();

        // Do not delete RocksDB LOCK file; if present and DB open fails, surface error to caller

        let cf_names = [
            "default",
            "epoch",
            "coin",
            "coin_candidate",
            "epoch_selected",      // per-epoch selected coin IDs
            "epoch_leaves",        // per-epoch sorted leaf hashes for proofs
            "epoch_levels",        // per-epoch merkle levels for fast proofs
            "coin_epoch", // coin_id -> epoch number mapping (child epoch that committed the coin)
            "coin_epoch_by_epoch", // epoch_num||coin_id -> 1 (reverse index for range scans)
            "head",
            "anchor",
            "validator_pool",      // validator_id -> ValidatorPool
            "validator_committee", // epoch -> ValidatorSet
            "tx",
            "consensus_evidence", // evidence_id -> ConsensusEvidenceRecord
            "anchor_proposal_observation", // proposer||epoch||slot -> StoredAnchorProposalObservation
            "validator_vote_observation",  // voter||epoch||slot -> StoredValidatorVoteObservation
            "shared_state_dag_observation", // epoch||round||author -> StoredSharedStateDagObservation
            "fast_path_pending_tx",         // tx_id -> pending ordinary fast-path Tx
            "fast_path_batch",              // ordered_tx_root -> FastPathBatch
            "shared_state_pending_tx",      // tx_id -> pending shared-state Tx
            "shared_state_batch",           // ordered_tx_root -> SharedStateBatch
            "shared_state_dag_batch",       // batch_id -> SharedStateDagBatch
            "shared_state_dag_round",       // epoch||round||author -> batch_id
            "shared_state_finalized_batch", // batch_id -> anchor_num
            "peers",
            "meta", // miscellaneous metadata (e.g., cursors)
            // Shielded pool state
            "shielded_note_tree", // singleton canonical note commitment tree
            "shielded_nullifier_epoch", // epoch -> ArchivedNullifierEpoch
            "shielded_root_ledger", // singleton historical nullifier root ledger
            "shielded_output",    // tx_id||output_index -> ShieldedOutput
            "shielded_active_nullifier", // singleton current ActiveNullifierEpoch
            "shielded_spent_note", // note_commitment -> spent marker
            "shielded_archive_provider", // provider_id -> ArchiveProviderManifest
            "shielded_archive_replica", // provider_id||shard_id -> ArchiveReplicaAttestation
            "shielded_archive_operator", // provider_id -> ArchiveOperatorScorecard
            "shielded_archive_accounting", // provider_id -> ArchiveServiceLedger
            "shielded_archive_custody", // provider_id||shard_id -> ArchiveCustodyCommitment
            "shielded_archive_receipt", // receipt_digest -> ArchiveRetrievalReceipt
        ];

        let mut db = open_db_with_families(&db_path, &cf_names)?;
        for obsolete_cf in [
            "wallet",
            "shielded_checkpoint",
            "shielded_owned_note",
            "delegation_share",
            "retarget_cache",
        ] {
            if db.cf_handle(obsolete_cf).is_some() {
                db.drop_cf(obsolete_cf).with_context(|| {
                    format!("Failed to drop obsolete chain column family '{obsolete_cf}'")
                })?;
            }
        }

        // Create coins directory for individual coin files
        let coins_dir = format!("{db_path}/coins");
        fs::create_dir_all(&coins_dir).ok();

        // ----------------------------------------------------
        // Optional background coin mirroring for explicit operator opt-in.
        // Disabled by default because it leaks canonical coin data to loose files.
        // ----------------------------------------------------
        let mirror_enabled = std::env::var("COIN_MIRRORING")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mirror_tx = if mirror_enabled {
            let (tx, rx) = std::sync::mpsc::channel::<(String, Vec<u8>)>();
            std::thread::Builder::new()
                .name("coin-mirror".into())
                .spawn(move || {
                    for (path, bytes) in rx {
                        if let Some(parent) = std::path::Path::new(&path).parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let _ = std::fs::write(&path, &bytes);
                    }
                })
                .expect("Failed to spawn coin mirror thread");
            Some(tx)
        } else {
            None
        };

        let store = Store {
            db,
            path: db_path,
            mirror_tx,
        };

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

        // Queue coin mirroring in background thread (feature-guarded via env); off by default
        if cf == "coin" {
            if let Some(tx) = &self.mirror_tx {
                let mirror_path = format!("{}/coins/coin-{}.bin", self.path, hex::encode(key));
                let _ = tx.send((mirror_path, data_to_store.clone()));
            }
        }
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

    /// Absolute path to the directory where individual coin files are stored.
    pub fn coins_dir(&self) -> String {
        format!("{}/coins", self.path)
    }

    /// Gets all coins owned by a specific address
    pub fn get_coins_by_owner(&self, owner_address: &[u8; 32]) -> Result<Vec<crate::coin::Coin>> {
        let cf = self
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow::anyhow!("'coin' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut coins = Vec::new();

        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_coin(&value) {
                if coin.creator_address == *owner_address {
                    coins.push(coin);
                }
            }
        }

        Ok(coins)
    }

    /// Iterates over all coins in the database
    pub fn iterate_coins(&self) -> Result<Vec<crate::coin::Coin>> {
        let cf = self
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow::anyhow!("'coin' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut coins = Vec::new();

        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_coin(&value) {
                coins.push(coin);
            }
        }

        Ok(coins)
    }

    /// Iterates over canonically committed coins in deterministic epoch/id order.
    pub fn iterate_committed_coins(&self) -> Result<Vec<(u64, crate::coin::Coin)>> {
        let Some(latest) = self.get::<crate::epoch::Anchor>("epoch", b"latest")? else {
            return Ok(Vec::new());
        };
        let mut committed = Vec::new();
        for epoch_num in 0..=latest.num {
            for coin_id in self.get_coin_ids_for_epoch_committed(epoch_num)? {
                let coin = self
                    .get::<crate::coin::Coin>("coin", &coin_id)?
                    .ok_or_else(|| anyhow!("missing committed coin {}", hex::encode(coin_id)))?;
                committed.push((epoch_num, coin));
            }
        }
        committed.sort_by(|(epoch_a, coin_a), (epoch_b, coin_b)| {
            epoch_a.cmp(epoch_b).then(coin_a.id.cmp(&coin_b.id))
        });
        Ok(committed)
    }

    /// Iterates over all coin candidates in the database
    pub fn iterate_coin_candidates(&self) -> Result<Vec<crate::coin::CoinCandidate>> {
        let cf = self
            .db
            .cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut coins = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_candidate(&value) {
                coins.push(coin);
            }
        }
        Ok(coins)
    }

    /// Build the composite key for coin candidates: epoch_hash || coin_id
    pub fn candidate_key(epoch_hash: &[u8; 32], coin_id: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(epoch_hash);
        key.extend_from_slice(coin_id);
        key
    }

    /// Iterate coin candidates by epoch hash using bounded prefix iteration
    pub fn get_coin_candidates_by_epoch_hash(
        &self,
        epoch_hash: &[u8; 32],
    ) -> Result<Vec<crate::coin::CoinCandidate>> {
        let cf = self
            .db
            .cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;
        let mut coins = Vec::new();
        let mut upper = Vec::with_capacity(64);
        upper.extend_from_slice(epoch_hash);
        upper.extend_from_slice(&[0xFF; 32]);
        let mut ro = rocksdb::ReadOptions::default();
        ro.set_iterate_lower_bound(epoch_hash.to_vec());
        ro.set_iterate_upper_bound(upper);
        let iter = self.db.iterator_cf_opt(
            cf,
            ro,
            rocksdb::IteratorMode::From(epoch_hash, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (k, v) = item?;
            if k.len() < 64 {
                continue;
            }
            // within bounds due to iterate_upper_bound; keep prefix guard for safety
            if &k[0..32] != &epoch_hash[..] {
                break;
            }
            if let Ok(coin) = crate::coin::decode_candidate(&v) {
                coins.push(coin);
            }
        }
        Ok(coins)
    }

    /// Fetch a confirmed coin by id.
    pub fn get_coin(&self, coin_id: &[u8; 32]) -> Result<Option<crate::coin::Coin>> {
        let cf = self
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow::anyhow!("'coin' column family missing"))?;
        match self.db.get_cf(cf, coin_id)? {
            Some(value) => match crate::coin::decode_coin(&value) {
                Ok(c) => Ok(Some(c)),
                Err(_) => Ok(None),
            },
            None => Ok(None),
        }
    }

    /// Deletes coin candidates older than or equal to a specific epoch hash (best-effort GC)
    /// Keeps candidates for recent epochs to support reorgs
    pub fn prune_old_candidates(&self, keep_epoch_hash: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();
        let mut pruned: u64 = 0;

        // Collect all epoch hashes to determine which ones to keep
        let mut epoch_hashes = std::collections::HashSet::new();
        epoch_hashes.insert(keep_epoch_hash.to_vec());

        // Keep candidates for the current epoch hash and recent epochs to support reorgs
        // For now, be very conservative and don't prune aggressively
        // This can be made more aggressive later once reorg stability is confirmed
        for item in iter {
            let (key, _) = item?;
            if key.len() >= 32 {
                let epoch_hash = &key[0..32];
                // Only prune if the candidate is for a significantly older epoch
                // Keep candidates for recent epochs to support reorgs
                if !epoch_hashes.contains(epoch_hash) {
                    // For now, be very conservative and only prune very old candidates
                    // This can be made more aggressive later once reorg stability is confirmed
                    batch.delete_cf(cf, key);
                    pruned += 1;
                }
            }
        }

        self.write_batch(batch)?;
        if pruned > 0 {
            crate::metrics::PRUNED_CANDIDATES.inc_by(pruned as u64);
        }
        Ok(())
    }

    /// Store sorted leaf hashes for an epoch for faster proof construction
    pub fn store_epoch_leaves(&self, epoch_num: u64, leaves: &Vec<[u8; 32]>) -> Result<()> {
        let cf = self
            .db
            .cf_handle("epoch_leaves")
            .ok_or_else(|| anyhow::anyhow!("'epoch_leaves' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        let data = bincode::serialize(leaves)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Load sorted leaf hashes for an epoch if present
    pub fn get_epoch_leaves(&self, epoch_num: u64) -> Result<Option<Vec<[u8; 32]>>> {
        let cf = self
            .db
            .cf_handle("epoch_leaves")
            .ok_or_else(|| anyhow::anyhow!("'epoch_leaves' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        match self.db.get_cf(cf, &key)? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Store full Merkle levels for an epoch for O(log N) proof generation without recomputation
    pub fn store_epoch_levels(&self, epoch_num: u64, levels: &Vec<Vec<[u8; 32]>>) -> Result<()> {
        let cf = self
            .db
            .cf_handle("epoch_levels")
            .ok_or_else(|| anyhow::anyhow!("'epoch_levels' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        let data = bincode::serialize(levels)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Load Merkle levels for an epoch if present. Level 0 must be sorted leaves.
    pub fn get_epoch_levels(&self, epoch_num: u64) -> Result<Option<Vec<Vec<[u8; 32]>>>> {
        let cf = self
            .db
            .cf_handle("epoch_levels")
            .ok_or_else(|| anyhow::anyhow!("'epoch_levels' column family missing"))?;
        let key = epoch_num.to_le_bytes();
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

    pub fn store_shielded_archive_operator_scorecard(
        &self,
        scorecard: &crate::shielded::ArchiveOperatorScorecard,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_archive_operator")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_operator' column family missing"))?;
        let bytes = crate::canonical::encode_archive_operator_scorecard(scorecard)?;
        self.db.put_cf(cf, &scorecard.provider_id, bytes)?;
        Ok(())
    }

    pub fn load_shielded_archive_operator_scorecards(
        &self,
    ) -> Result<Vec<crate::shielded::ArchiveOperatorScorecard>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_operator")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_operator' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut scorecards = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            scorecards.push(crate::canonical::decode_archive_operator_scorecard(&value)?);
        }
        Ok(scorecards)
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

    pub fn store_shielded_archive_retrieval_receipt(
        &self,
        receipt: &crate::shielded::ArchiveRetrievalReceipt,
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle("shielded_archive_receipt")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_receipt' column family missing"))?;
        let bytes = crate::canonical::encode_archive_retrieval_receipt(receipt)?;
        self.db.put_cf(cf, &receipt.receipt_digest, bytes)?;
        Ok(())
    }

    pub fn load_shielded_archive_retrieval_receipts(
        &self,
    ) -> Result<Vec<crate::shielded::ArchiveRetrievalReceipt>> {
        let cf = self
            .db
            .cf_handle("shielded_archive_receipt")
            .ok_or_else(|| anyhow::anyhow!("'shielded_archive_receipt' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut receipts = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            receipts.push(crate::canonical::decode_archive_retrieval_receipt(&value)?);
        }
        Ok(receipts)
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

    /// Gets selected coin IDs for an epoch
    pub fn get_selected_coin_ids_for_epoch(&self, epoch_num: u64) -> Result<Vec<[u8; 32]>> {
        let sel_cf = self
            .db
            .cf_handle("epoch_selected")
            .ok_or_else(|| anyhow::anyhow!("'epoch_selected' column family missing"))?;
        let mut ids = Vec::new();
        let start_key = epoch_num.to_le_bytes();
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

    pub fn put_coin_epoch_rev(&self, epoch_num: u64, coin_id: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("coin_epoch_by_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch_by_epoch' column family missing"))?;
        let mut key = Vec::with_capacity(8 + 32);
        key.extend_from_slice(&epoch_num.to_le_bytes());
        key.extend_from_slice(coin_id);
        self.db.put_cf(cf, &key, &[])?;
        Ok(())
    }

    pub fn get_coin_ids_for_epoch_committed(&self, epoch_num: u64) -> Result<Vec<[u8; 32]>> {
        let cf = self
            .db
            .cf_handle("coin_epoch_by_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch_by_epoch' column family missing"))?;
        let start_key = epoch_num.to_le_bytes();
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
            id.copy_from_slice(&k[8..]);
            ids.push(id);
        }
        Ok(ids)
    }

    /// Persist a mapping coin_id -> epoch number that committed it
    pub fn put_coin_epoch(&self, coin_id: &[u8; 32], epoch_num: u64) -> Result<()> {
        let cf = self
            .db
            .cf_handle("coin_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch' column family missing"))?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&epoch_num.to_le_bytes());
        self.db.put_cf(cf, coin_id, &bytes)?;
        Ok(())
    }

    /// Delete a mapping coin_id -> epoch number (used during reorgs)
    pub fn delete_coin_epoch(&self, coin_id: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("coin_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch' column family missing"))?;
        self.db.delete_cf(cf, coin_id)?;
        Ok(())
    }

    /// Retrieve epoch number that committed the given coin, if known
    pub fn get_coin_epoch(&self, coin_id: &[u8; 32]) -> Result<Option<u64>> {
        let cf = self
            .db
            .cf_handle("coin_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch' column family missing"))?;
        match self.db.get_cf(cf, coin_id)? {
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

    /// Retrieve the epoch number for a coin from the committed reverse index.
    pub fn get_epoch_for_coin(&self, coin_id: &[u8; 32]) -> Result<Option<u64>> {
        self.get_coin_epoch(coin_id)
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

    /// Convenience: fetch anchor by epoch number
    pub fn get_anchor_by_epoch_num(&self, epoch_num: u64) -> Result<Option<crate::epoch::Anchor>> {
        self.get("epoch", &epoch_num.to_le_bytes())
    }

    /// Gets the total number of coins in the database
    pub fn coin_count(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow::anyhow!("'coin' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }

    /// Export all known anchors (by epoch number) into a compressed snapshot file.
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
            // Only include keys that are exactly 8 bytes (epoch number). Skip the "latest" marker and others.
            if k.len() != 8 {
                continue;
            }
            let anchor: crate::epoch::Anchor = match bincode::deserialize(&v[..]) {
                Ok(a) => a,
                Err(_) => continue,
            };
            anchors.push(anchor);
        }
        // Sort by epoch number to make snapshot deterministic
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
        let coin_count = self.coin_count()?;
        let tx_count = self.tx_count()?;
        let epoch_count = self.epoch_count()?;

        Ok(DatabaseStats {
            coin_count,
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

    /// Deletes coin candidates older than those referenced by the provided epoch hashes.
    /// Keeps candidate entries whose key prefix (epoch_hash) is in `keep_hashes`.
    pub fn prune_candidates_keep_hashes(&self, keep_hashes: &[[u8; 32]]) -> Result<()> {
        let cf = self
            .db
            .cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;
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
            crate::metrics::PRUNED_CANDIDATES.inc_by(pruned as u64);
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
    pub coin_count: u64,
    pub tx_count: u64,
    pub epoch_count: u64,
}

/// Cross-platform directory copy function for backups
fn copy_dir_all(src: &str, dst: &str) -> Result<()> {
    use std::path::Path;

    let src_path = Path::new(src);
    let dst_path = Path::new(dst);

    if !src_path.exists() {
        return Ok(()); // Source doesn't exist, nothing to copy
    }

    std::fs::create_dir_all(dst_path)?;

    for entry in std::fs::read_dir(src_path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_file = entry.path();
        let dst_file = dst_path.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_all(&src_file.to_string_lossy(), &dst_file.to_string_lossy())?;
        } else {
            std::fs::copy(src_file, dst_file)?;
        }
    }
    Ok(())
}

pub fn open(cfg: &crate::config::Storage) -> Arc<Store> {
    match Store::open(&cfg.path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!(
                "❌ Critical: Database failed to open at '{}': {}",
                cfg.path, e
            );
            eprintln!("💡 Possible solutions:");
            eprintln!("   - Check if directory exists and is writable");
            eprintln!("   - Verify no other instances are running");
            eprintln!(
                "   - If previous crash, try removing stale lock: rm {}/LOCK",
                cfg.path
            );
            // For genesis deployment, propagate error instead of exiting in library
            panic!("Database open failed: {}", e);
        }
    }
}
