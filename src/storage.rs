use rocksdb::{Options, DB, ColumnFamilyDescriptor, WriteBatch, WriteOptions};
use rocksdb::{SliceTransform, BlockBasedOptions, DBCompressionType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use std::sync::Arc;
use rand::RngCore;
use chacha20poly1305::aead::NewAead;
// Removed direct Aead/NewAead imports to avoid warnings; using fully qualified paths below
// use std::process; // removed unused

// Using bincode for fast, compact binary serialization instead of JSON.
// Using zstd for a better compression ratio and speed than lz4.
// These are significant performance and storage efficiency improvements.

pub struct Store {
    pub db: DB,
    path: String,
    mirror_tx: Option<std::sync::mpsc::Sender<(String, Vec<u8>)>>, // background mirroring
    enc_key: Option<[u8;32]>,
}

// Replay state persistence value
#[derive(Serialize, Deserialize)]
pub struct ReplayVal { pub ts: u64, pub seq: u64 }

// Global counter to ensure unique database paths
static DB_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Store {
    // Compress values larger than this many bytes using zstd before optional encryption
    const COMPRESS_THRESHOLD_BYTES: usize = 512;
    const ZSTD_LEVEL: i32 = 3;
    fn load_or_derive_enc_key(base_path: &str) -> Option<[u8;32]> {
        // Prefer a raw key via DB_ENC_KEY_HEX (64 hex chars for 32 bytes)
        if let Ok(hexkey) = std::env::var("DB_ENC_KEY_HEX") {
            if let Ok(bytes) = hex::decode(hexkey.trim()) {
                if bytes.len() == 32 {
                    let mut k = [0u8;32];
                    k.copy_from_slice(&bytes);
                    return Some(k);
                }
            }
        }
        // Else derive from unified passphrase only
        let pass = match crate::crypto::unified_passphrase(Some("Enter quantum pass-phrase: ")) {
            Ok(p) => p,
            Err(_) => return None,
        };
        let salt_path = format!("{}/db.keysalt", base_path);
        let mut salt: [u8;16] = [0u8;16];
        if std::path::Path::new(&salt_path).exists() {
            if let Ok(bytes) = std::fs::read(&salt_path) {
                if bytes.len() == 16 { salt.copy_from_slice(&bytes); }
            }
        } else {
            let mut tmp = [0u8;16];
            rand::rngs::OsRng.fill_bytes(&mut tmp);
            let _ = std::fs::write(&salt_path, &tmp);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&salt_path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&salt_path, perms);
                }
            }
            salt = tmp;
        }
        let mem_mib = std::env::var("DB_ENC_MEM_MIB").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(1024);
        let time_cost = std::env::var("DB_ENC_TIME").ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(3);
        let params = argon2::Params::new(mem_mib.saturating_mul(1024), time_cost, 1, None).ok()?;
        let mut key = [0u8;32];
        let _ = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), &salt, &mut key);
        Some(key)
    }

    fn maybe_encrypt(&self, cf: &str, value: Vec<u8>) -> Vec<u8> {
        // Do not double-encrypt wallet because it is encrypted separately
        if let Some(key) = self.enc_key {
            if cf != "wallet" {
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
                let mut nonce = [0u8;24]; rand::rngs::OsRng.fill_bytes(&mut nonce);
                let ct = chacha20poly1305::aead::Aead::encrypt(&cipher, chacha20poly1305::XNonce::from_slice(&nonce), &value[..]).unwrap_or_default();
                let mut out = b"UCED1".to_vec();
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                return out;
            }
        }
        value
    }

    fn maybe_decrypt(&self, value: Vec<u8>) -> Vec<u8> {
        if value.starts_with(b"UCED1") {
            if let Some(key) = self.enc_key {
                if value.len() >= 5+24 {
                    let nonce = &value[5..29];
                    let ct = &value[29..];
                    let cipher = chacha20poly1305::XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
                    if let Ok(pt) = chacha20poly1305::aead::Aead::decrypt(&cipher, chacha20poly1305::XNonce::from_slice(nonce), ct) { return pt; }
                }
            }
            // If decryption fails, fall through to return original for erroring upstream on deserialize
        }
        value
    }
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
        
        // Backup critical column families with bincode serialization plus integrity tag (blake3)
        for cf_name in ["epoch", "wallet"] {
            if let Some(cf_handle) = self.db.cf_handle(cf_name) {
                let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
                let cf_backup_dir = format!("{backup_dir}/{cf_name}");
                std::fs::create_dir_all(&cf_backup_dir)?;
                
                for (i, item) in iter.enumerate() {
                    let (key, value) = item?;
                    let backup_file = format!("{cf_backup_dir}/{i:08}.bin");
                    let mut blob = Vec::new();
                    // Structure: len(key)||key||len(val)||val||tag
                    let key_len = (key.len() as u32).to_le_bytes();
                    let val_len = (value.len() as u32).to_le_bytes();
                    blob.extend_from_slice(&key_len);
                    blob.extend_from_slice(&key);
                    blob.extend_from_slice(&val_len);
                    blob.extend_from_slice(&value);
                    let tag = blake3::hash(&blob);
                    blob.extend_from_slice(tag.as_bytes());
                    std::fs::write(backup_file, blob)?;
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
            "epoch_work_leaves", // per-epoch sorted work leaf hashes
            "epoch_transfers",// per-epoch selected transfer IDs
            "head",
            "wallet",
            "anchor",
            "transfer",
            "tx_pool",
            "replay",
        ];

        // Base CF options
        let mut base_cf_opts = Options::default();
        base_cf_opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        base_cf_opts.set_max_write_buffer_number(2);
        base_cf_opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB SSTs

        // Global block-based options with bloom filter
        let mut blk_opts = BlockBasedOptions::default();
        // Bloom filter: 10 bits per key, no block-based whole key filtering
        blk_opts.set_bloom_filter(10.0, false);

        // Build per-CF options, enabling prefix extractors for hot prefix scans
        let mut cf_descriptors: Vec<ColumnFamilyDescriptor> = Vec::new();
        for name in cf_names.iter() {
            let mut opts = base_cf_opts.clone();
            opts.set_block_based_table_factory(&blk_opts);
            match *name {
                // Prefix: epoch_hash (32 bytes) || coin_id (32 bytes)
                "coin_candidate" => {
                    // Safe prefix extractor: clamp to available length to avoid panics on short/internal keys.
                    // RocksDB expects a stable prefix; for short keys we return the whole key (including empty).
                    let st = SliceTransform::create(
                        "coin_candidate_prefix",
                        |key: &[u8]| {
                            let n = 32.min(key.len());
                            &key[..n]
                        },
                        None,
                    );
                    opts.set_prefix_extractor(st);
                    // Enable memtable prefix bloom to speed up prefix seeks
                    opts.set_memtable_prefix_bloom_ratio(0.1);
                }
                // Prefix: epoch number (8 bytes) || coin_id
                "epoch_selected" => {
                    // Safe prefix extractor: clamp to available length to avoid panics on short/internal keys.
                    let st = SliceTransform::create(
                        "epoch_selected_prefix",
                        |key: &[u8]| {
                            let n = 8.min(key.len());
                            &key[..n]
                        },
                        None,
                    );
                    opts.set_prefix_extractor(st);
                    opts.set_memtable_prefix_bloom_ratio(0.1);
                }
                _ => { /* default */ }
            }
            cf_descriptors.push(ColumnFamilyDescriptor::new(*name, opts));
        }

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // Prefer Zstd compression for better read amplification vs. size
        db_opts.set_compression_type(DBCompressionType::Zstd);
        db_opts.set_bottommost_compression_type(DBCompressionType::Zstd);
        
        // Organize files into meaningful subdirectories under the chosen db_path
        let wal_dir = format!("{db_path}/logs");
        let backup_dir = format!("{db_path}/backups");
        std::fs::create_dir_all(&db_path).ok();
        std::fs::create_dir_all(&wal_dir).ok();
        std::fs::create_dir_all(&backup_dir).ok();
        
        // Custom file organization
        db_opts.set_wal_dir(&wal_dir); // Put WAL files in /logs subdirectory
        
        // Durability: default to fsync ON (safer). Can be tuned via env ROCKSDB_USE_FSYNC=0
        let use_fsync = std::env::var("ROCKSDB_USE_FSYNC").map(|v| v != "0").unwrap_or(true);
        db_opts.set_use_fsync(use_fsync);
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
        
        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors)
            .with_context(|| format!("Failed to open database at '{db_path}'"))?;

        // Create coins directory for individual coin files
        let coins_dir = format!("{db_path}/coins");
        fs::create_dir_all(&coins_dir).ok();

        // ----------------------------------------------------
        // Background coin mirroring (disabled by default)
        // Enable by setting env VAR COIN_MIRRORING=1 (writes plaintext files!)
        // ----------------------------------------------------
        let mirror_enabled = std::env::var("COIN_MIRRORING")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);
        let mirror_tx = if mirror_enabled {
            eprintln!("⚠️ COIN_MIRRORING is ENABLED: coin data will be written as PLAINTEXT files under {}/coins. Do NOT use in production!", db_path);
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
            enc_key: Store::load_or_derive_enc_key(base_path),
        };
        
        // Perform initial health check
        store.health_check().with_context(|| "Database health check failed during initialization")?;
        
        println!("✅ Database opened successfully ");
        Ok(store)
    }

    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], value: &T) -> Result<()> {
        // Serialize value once
        let mut data_to_store = bincode::serialize(value)
            .with_context(|| format!("Failed to serialize value for key '{key:?}' in CF '{cf}'"))?;
        // Compress large values before optional encryption
        if data_to_store.len() >= Self::COMPRESS_THRESHOLD_BYTES {
            if let Ok(comp) = zstd::encode_all(&data_to_store[..], Self::ZSTD_LEVEL) {
                data_to_store = comp;
            }
        }
        let data_to_store = self.maybe_encrypt(cf, data_to_store);

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
                // Try decrypt (no-op if plaintext), then attempt zstd fallback
                let maybe_plain = self.maybe_decrypt(value.to_vec());
                // First attempt: assume data is compressed
                if let Ok(decompressed) = zstd::decode_all(&maybe_plain[..]) {
                    if let Ok(deser) = bincode::deserialize(&decompressed) {
                        return Ok(Some(deser));
                    }
                }

                // Fallback: treat data as uncompressed bincode
                match bincode::deserialize(&maybe_plain[..]) {
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

    /// Iterate all pending transfers in the tx_pool CF
    pub fn iterate_tx_pool(&self) -> Result<Vec<crate::transfer::Transfer>> {
        let cf = self.db.cf_handle("tx_pool")
            .ok_or_else(|| anyhow::anyhow!("'tx_pool' column family missing"))?;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut txs = Vec::new();
        for item in iter {
            let (_k, v) = item?;
            if let Ok(tx) = bincode::deserialize::<crate::transfer::Transfer>(&v) {
                txs.push(tx);
            }
        }
        Ok(txs)
    }

    /// Backward-compatible fetch of a confirmed coin by id
    pub fn get_coin(&self, coin_id: &[u8; 32]) -> Result<Option<crate::coin::Coin>> {
        let cf = self.db.cf_handle("coin")
            .ok_or_else(|| anyhow::anyhow!("'coin' column family missing"))?;
        if let Some(value) = self.db.get_cf(cf, coin_id)? {
            return Ok(crate::coin::decode_coin(&value).ok());
        }
        Ok(None)
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

    /// Store sorted work leaf hashes for an epoch
    pub fn store_epoch_work_leaves(&self, epoch_num: u64, leaves: &Vec<[u8;32]>) -> Result<()> {
        let cf = self.db.cf_handle("epoch_work_leaves")
            .ok_or_else(|| anyhow::anyhow!("'epoch_work_leaves' column family missing"))?;
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

    /// Load sorted work leaf hashes for an epoch if present
    pub fn get_epoch_work_leaves(&self, epoch_num: u64) -> Result<Option<Vec<[u8;32]>>> {
        let cf = self.db.cf_handle("epoch_work_leaves")
            .ok_or_else(|| anyhow::anyhow!("'epoch_work_leaves' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        match self.db.get_cf(cf, &key)? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Store per-epoch transfer IDs (tx_id = transfer.hash())
    pub fn store_epoch_transfers(&self, epoch_num: u64, tx_ids: &Vec<[u8;32]>) -> Result<()> {
        let cf = self.db.cf_handle("epoch_transfers")
            .ok_or_else(|| anyhow::anyhow!("'epoch_transfers' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        let data = bincode::serialize(tx_ids)?;
        self.db.put_cf(cf, &key, &data)?;
        Ok(())
    }

    /// Get per-epoch transfer IDs if present
    pub fn get_epoch_transfers(&self, epoch_num: u64) -> Result<Option<Vec<[u8;32]>>> {
        let cf = self.db.cf_handle("epoch_transfers")
            .ok_or_else(|| anyhow::anyhow!("'epoch_transfers' column family missing"))?;
        let key = epoch_num.to_le_bytes();
        match self.db.get_cf(cf, &key)? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
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

    // ------------------------------
    // Replay state persistence (per-sender pk -> last (timestamp, seq))
    // ------------------------------
    pub fn get_replay_state(&self, sender_pk: &[u8]) -> Result<Option<(u64, u64)>> {
        let cf = self.db.cf_handle("replay")
            .ok_or_else(|| anyhow::anyhow!("'replay' column family missing"))?;
        match self.db.get_cf(cf, sender_pk)? {
            Some(v) => {
                let rv: ReplayVal = bincode::deserialize(&v)?;
                Ok(Some((rv.ts, rv.seq)))
            }
            None => Ok(None),
        }
    }

    pub fn put_replay_state(&self, sender_pk: &[u8], ts: u64, seq: u64) -> Result<()> {
        let cf = self.db.cf_handle("replay")
            .ok_or_else(|| anyhow::anyhow!("'replay' column family missing"))?;
        let rv = ReplayVal { ts, seq };
        let enc = bincode::serialize(&rv)?;
        self.db.put_cf(cf, sender_pk, &enc)?;
        Ok(())
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