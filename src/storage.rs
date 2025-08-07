use rocksdb::{Options, DB, ColumnFamilyDescriptor, WriteBatch, WriteOptions};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs;
use serde::{Serialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use hex;
use std::sync::Arc;
use std::process;

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
        
        // Clean up any existing lock files that might cause conflicts
        let lock_file = format!("{}/LOCK", &db_path);
        if std::path::Path::new(&lock_file).exists() {
            let _ = std::fs::remove_file(&lock_file); // Remove stale lock
        }
        
        let cf_names = ["default", "epoch", "coin", "head", "wallet", "anchor", "transfer"];
        
        // Configure column family options for stability and uniqueness
        let mut cf_opts = Options::default();
        cf_opts.set_write_buffer_size(256 * 1024); // 256KB buffer (very small)
        cf_opts.set_max_write_buffer_number(1); // Only 1 write buffer
        cf_opts.set_target_file_size_base(512 * 1024); // 512KB SST files (very small)
        cf_opts.set_level_zero_file_num_compaction_trigger(1); // Compact immediately with 1 file
        cf_opts.set_max_bytes_for_level_base(1024 * 1024); // 1MB base level
        cf_opts.set_level_zero_slowdown_writes_trigger(1); // Slowdown at 1 file
        cf_opts.set_level_zero_stop_writes_trigger(2); // Stop at 2 files
        // (removed duplicate settings that conflict with extreme single-file config)
        
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, cf_opts.clone()))
            .collect();

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        
        // Organize files into meaningful subdirectories
        let wal_dir = format!("{db_path}/logs");
        let backup_dir = format!("{db_path}/backups");
        std::fs::create_dir_all(&wal_dir).ok();
        std::fs::create_dir_all(&backup_dir).ok();
        
        // Custom file organization
        db_opts.set_wal_dir(&wal_dir); // Put WAL files in /logs subdirectory
        
        // Balanced durability settings - prioritize stability over extreme speed
        db_opts.set_use_fsync(true); // Force fsync for durability
        db_opts.set_bytes_per_sync(1024 * 1024); // Sync every 1MB (more stable)
        db_opts.set_wal_bytes_per_sync(1024 * 1024); // Sync WAL every 1MB
        db_opts.set_writable_file_max_buffer_size(0); // No OS buffering
        db_opts.set_db_write_buffer_size(16 * 1024 * 1024); // 16MB total (more stable)
        db_opts.set_max_background_jobs(4); // Reasonable background jobs
        
        // Prevent file naming conflicts with stable settings
        db_opts.set_level_zero_slowdown_writes_trigger(8); // More stable thresholds
        db_opts.set_level_zero_stop_writes_trigger(12);
        db_opts.set_max_open_files(100); // Strict limit on open files
        
        // Additional file management settings
        db_opts.set_recycle_log_file_num(0); // Don't recycle log files - delete them
        
        // EXTREME single-file configuration
        db_opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::AbsoluteConsistency);
        db_opts.set_manual_wal_flush(false);
        
        // Force absolute minimum files
        db_opts.set_wal_size_limit_mb(1); // Smallest possible WAL
        db_opts.set_max_total_wal_size(512 * 1024); // 512KB max total WAL
        db_opts.set_keep_log_file_num(1); // Minimum allowed (can't be 0)
        
        // Instant cleanup - delete files immediately
        db_opts.set_wal_ttl_seconds(1); // Delete after 1 second
        db_opts.set_delete_obsolete_files_period_micros(100 * 1000); // Check every 100ms
        
        // Minimize compaction files  
        db_opts.set_max_background_jobs(1); // Single background job
        db_opts.set_max_subcompactions(1); // Single subcompaction
        
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

        // Use sync write options for critical data persistence
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true); // Force sync to disk immediately

        // Write to RocksDB first (primary store)
        self.db
            .put_cf_opt(handle, key, &data_to_store, &write_opts)
            .with_context(|| format!("Failed to PUT to database for key '{key:?}' in CF '{cf}'"))?;

        // Queue numicoin mirroring in background thread
        if cf == "coin" {
            if let Some(tx) = &self.mirror_tx {
                let mirror_path = format!("{}/coins/numicoin{}.dat", self.path, hex::encode(key));
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
                    Err(_) => {
                        // Special case: caller expects Vec<u8> but value is raw bytes
                        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<Vec<u8>>() {
                            // Safe conversion for Vec<u8> case
                            let vec_bytes: Vec<u8> = value.to_vec();
                            // SAFETY: We've verified T is Vec<u8> via TypeId comparison
                            let result = unsafe {
                                let ptr = Box::into_raw(Box::new(vec_bytes)) as *mut T;
                                *Box::from_raw(ptr)
                            };
                            Ok(Some(result))
                        } else {
                            Err(anyhow::anyhow!(
                                "Failed to deserialize value for key '{:?}' in CF '{}'", key, cf
                            ))
                        }
                    }
                }
            }
            None => Ok(None),
        }
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
            if let Ok(coin) = bincode::deserialize::<crate::coin::Coin>(&value) {
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
            if let Ok(None) = self.get::<crate::transfer::Transfer>("transfer", &coin.id) {
                unspent_coins.push(coin);
            }
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
            if let Ok(coin) = bincode::deserialize::<crate::coin::Coin>(&value) {
                coins.push(coin);
            }
        }
        
        Ok(coins)
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
    Arc::new(Store::open(&cfg.path).unwrap_or_else(|e| {
        eprintln!("❌ Critical: Database failed to open at '{}': {}", cfg.path, e);
        eprintln!("💡 Possible solutions:");
        eprintln!("   - Check if directory exists and is writable");
        eprintln!("   - Verify no other instances are running");
        eprintln!("   - Try removing lock files: rm {}/LOCK", cfg.path);
        process::exit(1);
    }))
}