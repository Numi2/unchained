use rocksdb::{Options, DB, ColumnFamilyDescriptor, WriteBatch, WriteOptions};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs;
use serde::{Serialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use hex;
use std::sync::Arc;
use std::collections::HashSet;
// use std::process; // removed unused

// Using bincode for fast, compact binary serialization instead of JSON.
// Using zstd for a better compression ratio and speed than lz4.
// These are significant performance and storage efficiency improvements.

pub struct Store {
    pub db: DB,
    path: String,
    mirror_tx: Option<std::sync::mpsc::Sender<(String, Vec<u8>)>>, // background mirroring
}

// Global counter to ensure unique database paths
static DB_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Store {
    /// Perform database health check and recovery
    pub fn health_check(&self) -> Result<()> {
        // Check basic connectivity
        let test_key = b"health_check";
        self.db.put(test_key, b"ok").with_context(|| "Database write test failed")?;
        let value = self.db.get(test_key).with_context(|| "Database read test failed")?;
        if value.as_deref() != Some(b"ok") {
            anyhow::bail!("Database read/write consistency check failed");
        }
        self.db.delete(test_key).with_context(|| "Database delete test failed")?;
        Ok(())
    }
    
    /// Create backup of critical blockchain data
    pub fn create_backup(&self) -> Result<String> {
        let backup_dir = format!("{}/backups/{}", self.path, chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        std::fs::create_dir_all(&backup_dir).with_context(|| "Failed to create backup directory")?;
        
        // Backup critical column families
        for cf_name in ["epoch", "wallet"] {
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
        // Increment counter for tracking (helps with debugging)
        let _instance_id = DB_INSTANCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        
        // Use base path directly for production, but ensure clean state
        let db_path = base_path.to_string();
        
        // Do not delete RocksDB LOCK file; if present and DB open fails, surface error to caller
        
        let cf_names = [
            "default",
            "epoch",
            "coin",
            "coin_candidate",
            "epoch_selected", // per-epoch selected coin IDs
            "epoch_leaves",   // per-epoch sorted leaf hashes for proofs
            "coin_epoch",     // coin_id -> epoch number mapping (child epoch that committed the coin)
            "head",
            "wallet",
            "anchor",
            "transfer",
            "spend",
            "nullifier",
            "peers",
        ];
        
        // Configure column family options with sane production defaults
        let mut cf_opts = Options::default();
        // Larger memtable for throughput; multiple write buffers
        cf_opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        cf_opts.set_max_write_buffer_number(2);
        // Target file size for compaction levels
        cf_opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB SSTs
        // Let RocksDB manage compaction triggers; avoid over-aggressive small thresholds

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        
        // Organize files into meaningful subdirectories under the chosen db_path
        let wal_dir = format!("{db_path}/logs");
        let backup_dir = format!("{db_path}/backups");
        std::fs::create_dir_all(&db_path).ok();
        std::fs::create_dir_all(&wal_dir).ok();
        std::fs::create_dir_all(&backup_dir).ok();
        
        // Custom file organization
        db_opts.set_wal_dir(&wal_dir); // Put WAL files in /logs subdirectory
        
        // Production-leaning durability settings: rely on WAL + periodic fsync
        db_opts.set_use_fsync(false);
        db_opts.set_bytes_per_sync(8 * 1024 * 1024);
        db_opts.set_wal_bytes_per_sync(8 * 1024 * 1024);
        db_opts.set_db_write_buffer_size(256 * 1024 * 1024);
        db_opts.set_max_background_jobs(8);
        
        // More forgiving compaction thresholds
        db_opts.set_level_zero_slowdown_writes_trigger(20);
        db_opts.set_level_zero_stop_writes_trigger(36);
        db_opts.set_max_open_files(512);
        
        // Additional file management settings
        db_opts.set_recycle_log_file_num(4);
        
        // WAL and cleanup tuned for throughput
        db_opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::TolerateCorruptedTailRecords);
        db_opts.set_manual_wal_flush(false);
        db_opts.set_wal_size_limit_mb(64);
        db_opts.set_max_total_wal_size(512 * 1024 * 1024);
        db_opts.set_keep_log_file_num(10);
        db_opts.set_wal_ttl_seconds(24 * 60 * 60);
        db_opts.set_delete_obsolete_files_period_micros(10 * 1_000_000);
        db_opts.set_max_subcompactions(4);
        
        // Discover any existing column families to ensure compatibility with older DBs
        let existing_cfs: Vec<String> = match DB::list_cf(&db_opts, &db_path) {
            Ok(names) => names,
            Err(_)
                // New database paths may not have any CF metadata yet; default to an empty list
                => Vec::new(),
        };

        // Union of existing CFs and required CFs
        let mut cf_name_set: HashSet<String> = existing_cfs.into_iter().collect();
        for name in cf_names.iter() {
            cf_name_set.insert((*name).to_string());
        }
        // Ensure 'default' is always present
        cf_name_set.insert("default".to_string());

        // Build descriptors from the unified list. Keep a stable order: 'default' first, then others sorted.
        let mut final_cf_names: Vec<String> = cf_name_set.into_iter().collect();
        final_cf_names.sort();
        if let Some(pos) = final_cf_names.iter().position(|n| n == "default") {
            let default = final_cf_names.remove(pos);
            final_cf_names.insert(0, default);
        }
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = final_cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(name.clone(), cf_opts.clone()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors)
            .with_context(|| format!("Failed to open database at '{db_path}'"))?;

        // Create coins directory for individual coin files
        let coins_dir = format!("{db_path}/coins");
        fs::create_dir_all(&coins_dir).ok();

        // ----------------------------------------------------
        // Background coin mirroring (enabled by default)
        // Can be disabled by setting env VAR COIN_MIRRORING=0
        // ----------------------------------------------------
        let mirror_enabled = std::env::var("COIN_MIRRORING")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);
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
        store.health_check().with_context(|| "Database health check failed during initialization")?;
        
        println!("✅ Database opened successfully ");
        Ok(store)
    }

    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], value: &T) -> Result<()> {
        // Serialize value once
        let data_to_store = bincode::serialize(value)
            .with_context(|| format!("Failed to serialize value for key '{key:?}' in CF '{cf}'"))?;

        let handle = self.db.cf_handle(cf)
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
        let handle = self.db.cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;

        match self.db.get_cf(handle, key)? {
            Some(value) => {
                // First attempt: assume data is compressed
                if let Ok(decompressed) = zstd::decode_all(&value[..]) {
                    if let Ok(deser) = bincode::deserialize(&decompressed) {
                        return Ok(Some(deser));
                    }
                }

                // Fallback: treat data as uncompressed bincode
                match bincode::deserialize(&value[..]) {
                    Ok(deser) => Ok(Some(deser)),
                    Err(_) => Err(anyhow::anyhow!(
                        "Failed to deserialize value for key '{:?}' in CF '{}'",
                        key, cf
                    )),
                }
            }
            None => Ok(None),
        }
    }

    /// Fetch raw bytes without attempting to deserialize
    pub fn get_raw_bytes(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let handle = self.db.cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;
        Ok(self.db.get_cf(handle, key)? .map(|v| v.to_vec()))
    }

    /// Atomically applies a set of writes.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true); // Force sync for batch writes too
        // Keep WAL enabled but rely on aggressive cleanup settings
        
        self.db.write_opt(batch, &write_opts).with_context(|| "Failed to write batch to database")
    }
    
    /// Force flush all memtables to disk (useful for ensuring durability)
    pub fn flush(&self) -> Result<()> {
        // Use a simpler, more reliable flush approach
        self.db.flush()
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
        let cf = self.db.cf_handle("coin")
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

    /// Gets all unspent coins owned by a specific address
    pub fn get_unspent_coins_by_owner(&self, owner_address: &[u8; 32]) -> Result<Vec<crate::coin::Coin>> {
        let coins = self.get_coins_by_owner(owner_address)?;
        let mut unspent_coins = Vec::new();
        
        for coin in coins {
            // Check if coin is spent
            let legacy_spent: Option<crate::transfer::Transfer> = self.get("transfer", &coin.id)?;
            let v2_spent: Option<crate::transfer::Spend> = self.get("spend", &coin.id)?;
            if legacy_spent.is_none() && v2_spent.is_none() { unspent_coins.push(coin); }
        }
        
        Ok(unspent_coins)
    }

    /// Iterates over all coins in the database
    pub fn iterate_coins(&self) -> Result<Vec<crate::coin::Coin>> {
        let cf = self.db.cf_handle("coin")
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

    /// Iterates over all coin candidates in the database
    pub fn iterate_coin_candidates(&self) -> Result<Vec<crate::coin::CoinCandidate>> {
        let cf = self.db.cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut coins = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = bincode::deserialize::<crate::coin::CoinCandidate>(&value) {
                coins.push(coin);
            }
        }
        Ok(coins)
    }

    /// Build the composite key for coin candidates: epoch_hash || coin_id
    pub fn candidate_key(epoch_hash: &[u8;32], coin_id: &[u8;32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(epoch_hash);
        key.extend_from_slice(coin_id);
        key
    }

    /// Iterate coin candidates by epoch hash using prefix iteration
    pub fn get_coin_candidates_by_epoch_hash(&self, epoch_hash: &[u8; 32]) -> Result<Vec<crate::coin::CoinCandidate>> {
        let cf = self.db.cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;
        let mut coins = Vec::new();
        let prefix = epoch_hash;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::From(prefix, rocksdb::Direction::Forward));
        for item in iter {
            let (k, v) = item?;
            if k.len() < 64 { continue; }
            if &k[0..32] != prefix { break; }
            if let Ok(coin) = bincode::deserialize::<crate::coin::CoinCandidate>(&v) {
                coins.push(coin);
            }
        }
        Ok(coins)
    }

    /// Backward-compatible fetch of a confirmed coin by id
    pub fn get_coin(&self, coin_id: &[u8; 32]) -> Result<Option<crate::coin::Coin>> {
        let cf = self.db.cf_handle("coin")
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
    pub fn prune_old_candidates(&self, keep_epoch_hash: &[u8; 32]) -> Result<()> {
        let cf = self.db.cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();
        let mut pruned: u64 = 0;
        for item in iter {
            let (key, _) = item?;
            if key.len() >= 32 && &key[0..32] != keep_epoch_hash {
                batch.delete_cf(cf, key);
                pruned += 1;
            }
        }
        self.write_batch(batch)?;
        if pruned > 0 { crate::metrics::PRUNED_CANDIDATES.inc_by(pruned as u64); }
        Ok(())
    }

    /// Store sorted leaf hashes for an epoch for faster proof construction
    pub fn store_epoch_leaves(&self, epoch_num: u64, leaves: &Vec<[u8;32]>) -> Result<()> {
        let cf = self.db.cf_handle("epoch_leaves")
            .ok_or_else(|| anyhow::anyhow!("'epoch_leaves' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        let data = bincode::serialize(leaves)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Load sorted leaf hashes for an epoch if present
    pub fn get_epoch_leaves(&self, epoch_num: u64) -> Result<Option<Vec<[u8;32]>>> {
        let cf = self.db.cf_handle("epoch_leaves")
            .ok_or_else(|| anyhow::anyhow!("'epoch_leaves' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        match self.db.get_cf(cf, &key)? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Persist a peer multiaddr string into the peers CF (deduped by key)
    pub fn store_peer_addr(&self, addr: &str) -> Result<()> {
        let cf = self.db.cf_handle("peers")
            .ok_or_else(|| anyhow::anyhow!("'peers' column family missing"))?;
        // Key is the multiaddr string bytes; value empty
        self.db.put_cf(cf, addr.as_bytes(), &[])?;
        Ok(())
    }

    /// Load all known peer multiaddr strings
    pub fn load_peer_addrs(&self) -> Result<Vec<String>> {
        let cf = self.db.cf_handle("peers")
            .ok_or_else(|| anyhow::anyhow!("'peers' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut addrs = Vec::new();
        for item in iter {
            let (k, _v) = item?;
            if let Ok(s) = std::str::from_utf8(&k) {
                addrs.push(s.to_string());
            }
        }
        Ok(addrs)
    }

    /// Gets selected coin IDs for an epoch
    pub fn get_selected_coin_ids_for_epoch(&self, epoch_num: u64) -> Result<Vec<[u8; 32]>> {
        let sel_cf = self.db.cf_handle("epoch_selected")
            .ok_or_else(|| anyhow::anyhow!("'epoch_selected' column family missing"))?;
        let mut ids = Vec::new();
        let start_key = epoch_num.to_le_bytes();
        let iter = self.db.iterator_cf(sel_cf, rocksdb::IteratorMode::From(&start_key, rocksdb::Direction::Forward));
        for item in iter {
            let (k, _v) = item?;
            if k.len() < 8 + 32 { continue; }
            if &k[0..8] != start_key { break; }
            let mut id = [0u8; 32];
            id.copy_from_slice(&k[8..8+32]);
            ids.push(id);
        }
        Ok(ids)
    }

    /// Persist a mapping coin_id -> epoch number that committed it
    pub fn put_coin_epoch(&self, coin_id: &[u8;32], epoch_num: u64) -> Result<()> {
        let cf = self.db.cf_handle("coin_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch' column family missing"))?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&epoch_num.to_le_bytes());
        self.db.put_cf(cf, coin_id, &bytes)?;
        Ok(())
    }

    /// Delete a mapping coin_id -> epoch number (used during reorgs)
    pub fn delete_coin_epoch(&self, coin_id: &[u8;32]) -> Result<()> {
        let cf = self.db.cf_handle("coin_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch' column family missing"))?;
        self.db.delete_cf(cf, coin_id)?;
        Ok(())
    }

    /// Retrieve epoch number that committed the given coin, if known
    pub fn get_coin_epoch(&self, coin_id: &[u8;32]) -> Result<Option<u64>> {
        let cf = self.db.cf_handle("coin_epoch")
            .ok_or_else(|| anyhow::anyhow!("'coin_epoch' column family missing"))?;
        match self.db.get_cf(cf, coin_id)? {
            Some(v) => {
                if v.len() != 8 { return Ok(None); }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&v);
                Ok(Some(u64::from_le_bytes(arr)))
            },
            None => Ok(None),
        }
    }

    /// Fallback: scan `epoch_selected` to find the epoch that selected this coin
    pub fn find_coin_epoch_via_scan(&self, coin_id: &[u8;32]) -> Result<Option<u64>> {
        let sel_cf = self.db.cf_handle("epoch_selected")
            .ok_or_else(|| anyhow::anyhow!("'epoch_selected' column family missing"))?;
        // Iterate all entries; stop on first matching suffix
        let iter = self.db.iterator_cf(sel_cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (k, _v) = item?;
            if k.len() == 8 + 32 && &k[8..] == coin_id {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&k[0..8]);
                return Ok(Some(u64::from_le_bytes(arr)));
            }
        }
        Ok(None)
    }

    /// Retrieve the epoch number for a coin using the index or fallback scan
    pub fn get_epoch_for_coin(&self, coin_id: &[u8;32]) -> Result<Option<u64>> {
        if let Some(n) = self.get_coin_epoch(coin_id)? { return Ok(Some(n)); }
        self.find_coin_epoch_via_scan(coin_id)
    }

    /// Convenience: fetch anchor by epoch number
    pub fn get_anchor_by_epoch_num(&self, epoch_num: u64) -> Result<Option<crate::epoch::Anchor>> {
        self.get("epoch", &epoch_num.to_le_bytes())
    }

    /// Gets the total number of coins in the database
    pub fn coin_count(&self) -> Result<u64> {
        let cf = self.db.cf_handle("coin")
            .ok_or_else(|| anyhow::anyhow!("'coin' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }

    /// Gets statistics about the database
    pub fn get_stats(&self) -> Result<DatabaseStats> {
        let coin_count = self.coin_count()?;
        let transfer_count = self.transfer_count()?;
        let epoch_count = self.epoch_count()?;
        
        Ok(DatabaseStats {
            coin_count,
            transfer_count,
            epoch_count,
        })
    }

    /// Gets the total number of transfers in the database
    pub fn transfer_count(&self) -> Result<u64> {
        let cf = self.db.cf_handle("transfer")
            .ok_or_else(|| anyhow::anyhow!("'transfer' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }

    /// Gets the total number of epochs in the database
    pub fn epoch_count(&self) -> Result<u64> {
        let cf = self.db.cf_handle("epoch")
            .ok_or_else(|| anyhow::anyhow!("'epoch' column family missing"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let count = iter.count() as u64;
        Ok(count)
    }
}



/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub coin_count: u64,
    pub transfer_count: u64,
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
            eprintln!("❌ Critical: Database failed to open at '{}': {}", cfg.path, e);
            eprintln!("💡 Possible solutions:");
            eprintln!("   - Check if directory exists and is writable");
            eprintln!("   - Verify no other instances are running");
            eprintln!("   - If previous crash, try removing stale lock: rm {}/LOCK", cfg.path);
            // For genesis deployment, propagate error instead of exiting in library
            panic!("Database open failed: {}", e);
        }
    }
}