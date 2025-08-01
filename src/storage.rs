use rocksdb::{Options, DB, ColumnFamilyDescriptor, WriteBatch};
use serde::{Serialize, de::DeserializeOwned};
use anyhow::{Result, Context};
use std::sync::Arc;

// Using bincode for fast, compact binary serialization instead of JSON.
// Using zstd for a better compression ratio and speed than lz4.
// These are significant performance and storage efficiency improvements.

pub struct Store { pub db: DB }

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let cf_names = ["default", "epoch", "coin", "head", "wallet", "anchor"];
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)
            .with_context(|| format!("Failed to open database at '{}'", path))?;

        Ok(Store { db })
    }

    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], value: &T) -> Result<()> {
        const COMPRESSION_THRESHOLD: usize = 64; // bytes

        let serialized = bincode::serialize(value)
            .with_context(|| format!("Failed to serialize value for key '{:?}' in CF '{}'", key, cf))?;

        // Only compress larger payloads to avoid overhead on tiny records (like simple test data)
        let data_to_store: Vec<u8> = if serialized.len() > COMPRESSION_THRESHOLD {
            zstd::encode_all(&serialized[..], 0)
                .with_context(|| "Failed to compress data")?
        } else {
            serialized.clone()
        };
        
        let handle = self.db.cf_handle(cf)
            .ok_or_else(|| anyhow::anyhow!("Column family '{}' not found", cf))?;
        
        self.db.put_cf(handle, key, data_to_store)
            .with_context(|| format!("Failed to PUT to database for key '{:?}' in CF '{}'", key, cf))
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
        self.db.write(batch).with_context(|| "Failed to write batch to database")
    }
}

pub fn open(cfg: &crate::config::Storage) -> Arc<Store> {
    Arc::new(Store::open(&cfg.path).expect("Database open failed"))
}