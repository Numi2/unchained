use rocksdb::{Options, DB, ColumnFamilyDescriptor, WriteBatch, WriteOptions};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs;
use serde::{Serialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use hex;
use std::sync::Arc;
use serde::Deserialize;
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

/// Encrypted OTP secret key record (version 1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpSkRecordV1 {
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

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
            "epoch_levels",   // per-epoch merkle levels for fast proofs
            "coin_epoch",     // coin_id -> epoch number mapping (child epoch that committed the coin)
            "head",
            "wallet",
            "anchor",
            "spend",
            "nullifier",
            "commitment_used",
            "otp_sk",
            "otp_index",
            "peers",
            "wallet_scan_pending", // FIXED: pending wallet scans waiting for coin synchronization
            "meta",                 // miscellaneous metadata (e.g., cursors)
            // Offer discovery CFs
            "offers",               // id -> OfferStored
            "offers_quota",         // day||peer_hash -> u64 count
            // Bridge-related CFs
            "bridge_state",           // serialized BridgeState summary
            "bridge_pending",         // op_id -> PendingBridgeOp
            "bridge_processed_sui",   // sui_tx_hash -> 1
            "bridge_locked",          // coin_id -> op_id
            "bridge_op_coins",        // op_id -> Vec<coin_id>
            "bridge_events",          // append-only event log (key: millis||rand)
        ];
        
        // Configure column family options with sane production defaults
        let mut cf_opts = Options::default();
        // Enable Bloom filters and prefix extractor for better prefix seeks (coin_candidate: 32-byte epoch_hash)
        {
            let mut block = rocksdb::BlockBasedOptions::default();
            // Bloom filter ~10 bits/key; enable index/filter caching
            block.set_bloom_filter(10.0, false);
            block.set_cache_index_and_filter_blocks(true);
            // Partitioned bloom filters improve prefix-iteration performance
            block.set_partition_filters(true);
            // Keep L0 index/filter pinned in cache to reduce thrash during bursts
            block.set_pin_l0_filter_and_index_blocks_in_cache(true);
            cf_opts.set_block_based_table_factory(&block);
        }
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
            .map(|name| {
                let mut opts = cf_opts.clone();
                // Apply a fixed-length 32-byte prefix extractor on coin_candidate CF to optimize per-epoch scans
                if name == "coin_candidate" {
                    opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                    opts.set_optimize_filters_for_hits(true);
                }
                ColumnFamilyDescriptor::new(name.clone(), opts)
            })
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

    /// Specialized tolerant getter for `spend` CF that never errors on deserialization issues.
    /// Returns Ok(None) when bytes are malformed instead of bailing.
    pub fn get_spend_tolerant(&self, key: &[u8]) -> Result<Option<crate::transfer::Spend>> {
        let handle = self.db.cf_handle("spend")
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", "spend"))?;

        match self.db.get_cf(handle, key)? {
            Some(value) => {
                // Try compressed then plain
                if let Ok(decompressed) = zstd::decode_all(&value[..]) {
                    if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&decompressed) {
                        return Ok(Some(sp));
                    }
                }
                if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&value[..]) {
                    return Ok(Some(sp));
                }
                // Malformed spend bytes: be tolerant and return None without logging to avoid spam in hot paths.
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Tolerant decode for arbitrary CF values into Spend (used when iterating CF directly)
    pub fn decode_spend_bytes_tolerant(&self, bytes: &[u8]) -> Option<crate::transfer::Spend> {
        if let Ok(decompressed) = zstd::decode_all(bytes) {
            if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(&decompressed) {
                return Some(sp);
            }
        }
        if let Ok(sp) = bincode::deserialize::<crate::transfer::Spend>(bytes) {
            return Some(sp);
        }
        None
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
            // Check if coin is spent (V3 chain)
            let recorded_spend: Option<crate::transfer::Spend> = self.get_spend_tolerant(&coin.id)?;
            if recorded_spend.is_none() { unspent_coins.push(coin); }
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
            if let Ok(coin) = crate::coin::decode_candidate(&value) {
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

    /// Iterate coin candidates by epoch hash using bounded prefix iteration
    pub fn get_coin_candidates_by_epoch_hash(&self, epoch_hash: &[u8; 32]) -> Result<Vec<crate::coin::CoinCandidate>> {
        let cf = self.db.cf_handle("coin_candidate")
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
            if k.len() < 64 { continue; }
            // within bounds due to iterate_upper_bound; keep prefix guard for safety
            if &k[0..32] != &epoch_hash[..] { break; }
            if let Ok(coin) = crate::coin::decode_candidate(&v) {
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
    /// Keeps candidates for recent epochs to support reorgs
    pub fn prune_old_candidates(&self, keep_epoch_hash: &[u8; 32]) -> Result<()> {
        let cf = self.db.cf_handle("coin_candidate")
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

    /// Store full Merkle levels for an epoch for O(log N) proof generation without recomputation
    pub fn store_epoch_levels(&self, epoch_num: u64, levels: &Vec<Vec<[u8;32]>>) -> Result<()> {
        let cf = self.db.cf_handle("epoch_levels")
            .ok_or_else(|| anyhow::anyhow!("'epoch_levels' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        let data = bincode::serialize(levels)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Load Merkle levels for an epoch if present. Level 0 must be sorted leaves.
    pub fn get_epoch_levels(&self, epoch_num: u64) -> Result<Option<Vec<Vec<[u8;32]>>>> {
        let cf = self.db.cf_handle("epoch_levels")
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

    // (moved to module scope below)

    /// Store a one-time secret key under pk_hash if absent. Returns Ok(()) even if already present.
    pub fn put_otp_sk_if_absent(&self, pk_hash: &[u8;32], sk_bytes: &[u8]) -> Result<()> {
        use rand::RngCore;
        use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, NewAead}, XNonce, Key};
        use rand::rngs::OsRng;
        use argon2::{Argon2, Params};

        let cf = self.db.cf_handle("otp_sk").ok_or_else(|| anyhow::anyhow!("'otp_sk' column family missing"))?;
        if self.db.get_cf(cf, pk_hash)?.is_some() { return Ok(()); }

        // Derive encryption key for OTP SKs from unified passphrase
        let pass = crate::crypto::unified_passphrase(Some("Enter pass-phrase to protect OTP keys:"))?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let params = Params::new(256 * 1024, 3, 1, None).map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?; // 256 MiB, 3 iters, lanes=1
        let mut key_bytes = [0u8; 32];
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let mut nonce = [0u8; 24]; OsRng.fill_bytes(&mut nonce);
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), sk_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to encrypt OTP SK: {}", e))?;
        key_bytes.iter_mut().for_each(|b| *b = 0);

        let rec = OtpSkRecordV1 { salt, nonce, ct };
        let ser = bincode::serialize(&rec)?;
        self.db.put_cf(cf, pk_hash, &ser)?;
        Ok(())
    }

    /// Retrieve and decrypt a one-time secret key by pk_hash
    pub fn get_otp_sk(&self, pk_hash: &[u8;32]) -> Result<Option<Vec<u8>>> {
        use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, NewAead}, XNonce, Key};
        use argon2::{Argon2, Params};

        let cf = self.db.cf_handle("otp_sk").ok_or_else(|| anyhow::anyhow!("'otp_sk' column family missing"))?;
        let Some(v) = self.db.get_cf(cf, pk_hash)? else { return Ok(None) };
        let rec: OtpSkRecordV1 = bincode::deserialize(&v)?;
        let pass = crate::crypto::unified_passphrase(Some("Enter pass-phrase to unlock OTP keys:"))?;
        let params = Params::new(256 * 1024, 3, 1, None).map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
        let mut key_bytes = [0u8; 32];
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), &rec.salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let pt = cipher.decrypt(XNonce::from_slice(&rec.nonce), rec.ct.as_ref())
            .map_err(|_| anyhow::anyhow!("Failed to decrypt OTP SK (wrong passphrase?)"))?;
        key_bytes.iter_mut().for_each(|b| *b = 0);
        Ok(Some(pt))
    }

    /// Index coin_id -> pk_hash to locate OTP SK for spends later
    pub fn put_otp_index(&self, coin_id: &[u8;32], pk_hash: &[u8;32]) -> Result<()> {
        let cf = self.db.cf_handle("otp_index").ok_or_else(|| anyhow::anyhow!("'otp_index' column family missing"))?;
        self.db.put_cf(cf, coin_id, pk_hash)?;
        Ok(())
    }

    pub fn get_otp_pk_hash_for_coin(&self, coin_id: &[u8;32]) -> Result<Option<[u8;32]>> {
        let cf = self.db.cf_handle("otp_index").ok_or_else(|| anyhow::anyhow!("'otp_index' column family missing"))?;
        if let Some(v) = self.db.get_cf(cf, coin_id)? {
            if v.len() == 32 { let mut h=[0u8;32]; h.copy_from_slice(&v); return Ok(Some(h)); }
        }
        Ok(None)
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

    /// Persist headers sync cursor (highest requested and highest stored header heights)
    pub fn put_headers_cursor(&self, highest_requested: u64, highest_stored: u64) -> Result<()> {
        let cf = self.db.cf_handle("meta").ok_or_else(|| anyhow::anyhow!("'meta' column family missing"))?;
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&highest_requested.to_le_bytes());
        buf[8..].copy_from_slice(&highest_stored.to_le_bytes());
        self.db.put_cf(cf, b"headers_cursor", &buf)?;
        Ok(())
    }

    /// Load headers sync cursor; returns (highest_requested, highest_stored)
    pub fn get_headers_cursor(&self) -> Result<(u64, u64)> {
        let cf = self.db.cf_handle("meta").ok_or_else(|| anyhow::anyhow!("'meta' column family missing"))?;
        if let Some(v) = self.db.get_cf(cf, b"headers_cursor")? {
            if v.len() == 16 {
                let mut a=[0u8;8]; a.copy_from_slice(&v[..8]);
                let mut b=[0u8;8]; b.copy_from_slice(&v[8..]);
                return Ok((u64::from_le_bytes(a), u64::from_le_bytes(b)));
            }
        }
        Ok((0,0))
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

    /// Export all known anchors (by epoch number) into a compressed snapshot file.
    /// Returns the number of anchors written.
    pub fn export_anchors_snapshot(&self, out_path: &str) -> Result<usize> {
        use std::io::Write as _;

        let epoch_cf = self.db.cf_handle("epoch")
            .ok_or_else(|| anyhow::anyhow!("'epoch' column family missing"))?;
        let iter = self.db.iterator_cf(epoch_cf, rocksdb::IteratorMode::Start);

        let mut anchors: Vec<crate::epoch::Anchor> = Vec::new();
        for item in iter {
            let (k, v) = item?;
            // Only include keys that are exactly 8 bytes (epoch number). Skip the "latest" marker and others.
            if k.len() != 8 { continue; }
            // Tolerant decode: try zstd first, then plain bincode
            let anchor: crate::epoch::Anchor = if let Ok(decompressed) = zstd::decode_all(&v[..]) {
                match bincode::deserialize(&decompressed) {
                    Ok(a) => a,
                    Err(_) => match bincode::deserialize(&v[..]) {
                        Ok(a) => a,
                        Err(_) => continue,
                    },
                }
            } else {
                match bincode::deserialize(&v[..]) {
                    Ok(a) => a,
                    Err(_) => continue,
                }
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

        let chain_id = anchors.first().map(|a| a.hash)
            .ok_or_else(|| anyhow::anyhow!("Missing genesis anchor in snapshot export"))?;
        let snapshot = AnchorsSnapshotV1 { chain_id, anchors };

        let raw = bincode::serialize(&snapshot)
            .context("Failed to serialize anchors snapshot")?;
        let mut encoder = zstd::Encoder::new(Vec::new(), 10)
            .context("Failed to create zstd encoder")?;
        encoder.write_all(&raw).context("Failed to write snapshot to encoder")?;
        let compressed = encoder.finish().context("Failed to finalize zstd compression")?;
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
        // Try zstd then plain
        let data = match zstd::decode_all(&bytes[..]) {
            Ok(d) => d,
            Err(_) => bytes,
        };
        let snapshot: AnchorsSnapshotV1 = bincode::deserialize(&data)
            .context("Failed to deserialize anchors snapshot (expected AnchorsSnapshotV1)")?;

        // If DB already has a genesis, ensure chain id matches
        if let Ok(Some(existing_genesis)) = self.get::<crate::epoch::Anchor>("epoch", &0u64.to_le_bytes()) {
            if existing_genesis.hash != snapshot.chain_id {
                anyhow::bail!("Snapshot chain_id does not match existing database genesis");
            }
        }

        let mut inserted: u64 = 0;
        let mut batch = WriteBatch::default();

        let epoch_cf = self.db.cf_handle("epoch").ok_or_else(|| anyhow::anyhow!("'epoch' column family missing"))?;
        let anchor_cf = self.db.cf_handle("anchor").ok_or_else(|| anyhow::anyhow!("'anchor' column family missing"))?;

        let mut highest_num: Option<u64> = None;
        for a in snapshot.anchors.iter() {
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
        let transfer_count = self.spend_count()?;
        let epoch_count = self.epoch_count()?;
        
        Ok(DatabaseStats {
            coin_count,
            transfer_count,
            epoch_count,
        })
    }

    /// Gets the total number of spends in the database
    pub fn spend_count(&self) -> Result<u64> {
        let cf = self.db.cf_handle("spend")
            .ok_or_else(|| anyhow::anyhow!("'spend' column family missing"))?;

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

    /// Deletes coin candidates older than those referenced by the provided epoch hashes.
    /// Keeps candidate entries whose key prefix (epoch_hash) is in `keep_hashes`.
    pub fn prune_candidates_keep_hashes(&self, keep_hashes: &[[u8;32]]) -> Result<()> {
        let cf = self.db.cf_handle("coin_candidate")
            .ok_or_else(|| anyhow::anyhow!("'coin_candidate' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();
        let mut pruned: u64 = 0;

        let keep: std::collections::HashSet<&[u8;32]> = keep_hashes.iter().collect();
        for item in iter {
            let (key, _) = item?;
            if key.len() >= 32 {
                let mut prefix = [0u8;32];
                prefix.copy_from_slice(&key[0..32]);
                if !keep.contains(&prefix) {
                    batch.delete_cf(cf, key);
                    pruned += 1;
                }
            }
        }
        self.write_batch(batch)?;
        if pruned > 0 { crate::metrics::PRUNED_CANDIDATES.inc_by(pruned as u64); }
        Ok(())
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