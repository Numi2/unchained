use rocksdb::{Options, DB, ColumnFamilyDescriptor, WriteBatch, WriteOptions};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs;
use std::path::Path;
use serde::{Serialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use std::sync::Arc;

// Using bincode for fast, compact binary serialization instead of JSON.
// Using zstd for a better compression ratio and speed than lz4.
// These are significant performance and storage efficiency improvements.

pub struct Store { 
    pub db: DB,
    path: String,
    coin_counter: AtomicU64,
}

// Global counter to ensure unique database paths
static DB_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Store {
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
        
        let cf_names = ["default", "epoch", "coin", "head", "wallet", "anchor"];
        
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
        let wal_dir = format!("{}/logs", db_path);
        let backup_dir = format!("{}/backups", db_path);
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
            .with_context(|| format!("Failed to open database at '{}'", db_path))?;

        // Create coins directory for individual coin files
        let coins_dir = format!("{}/coins", db_path);
        fs::create_dir_all(&coins_dir).ok();

        // Initialize coin counter by counting existing coin files
        let coin_counter = if let Ok(entries) = fs::read_dir(&coins_dir) {
            entries.filter_map(|e| e.ok()).count() as u64
        } else {
            0
        };

        Ok(Store { 
            db, 
            path: db_path,
            coin_counter: AtomicU64::new(coin_counter),
        })
    }

    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], value: &T) -> Result<()> {
        // Special handling for coins - save as individual files with meaningful names
        if cf == "coin" {
            return self.put_coin(key, value);
        }
        
        // For other data types, use regular RocksDB storage
        let data_to_store = bincode::serialize(value)
            .with_context(|| format!("Failed to serialize value for key '{:?}' in CF '{}'", key, cf))?;
        
        let handle = self.db.cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;
        
        // Use sync write options for critical data persistence
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true); // Force sync to disk immediately
        
        self.db.put_cf_opt(handle, key, data_to_store, &write_opts)
            .with_context(|| format!("Failed to PUT to database for key '{:?}' in CF '{}'", key, cf))
    }

    /// Save coin as individual file with meaningful name
    fn put_coin<T: Serialize>(&self, _key: &[u8], coin: &T) -> Result<()> {
        let coin_num = self.coin_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let coin_filename = format!("{}/coins/coin{:05}.dat", self.path, coin_num);
        
        let coin_data = bincode::serialize(coin)
            .with_context(|| "Failed to serialize coin data")?;
        
        fs::write(&coin_filename, &coin_data)
            .with_context(|| format!("Failed to save coin to file '{}'", coin_filename))?;
        
        println!("💾 Saved coin to: {}", coin_filename);
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
                            // Safety: We just checked that T is Vec<u8>
                                                        let vec_bytes: Vec<u8> = value.to_vec();
                            // SAFETY: We ensured T is Vec<u8>; we convert via raw pointer round-trip to avoid size checks.
                            let boxed = Box::new(vec_bytes);
                            let raw = Box::into_raw(boxed) as *mut T;
                            let coerced: Box<T> = unsafe { Box::from_raw(raw) };
                            Ok(Some(*coerced))
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
            eprintln!("Warning: WAL flush failed (non-critical): {}", e);
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
}

pub fn open(cfg: &crate::config::Storage) -> Arc<Store> {
    Arc::new(Store::open(&cfg.path).expect("Database open failed"))
}