use rocksdb::{Options, DB, ColumnFamilyDescriptor};
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use serde::{Serialize, de::DeserializeOwned};
use serde_json;

pub struct Store { db: DB }
impl Store {
    pub fn open(path: &str) -> Self {
        let cf = |name| ColumnFamilyDescriptor::new(name, Options::default());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open_cf_descriptors(&opts, path,
                 vec![cf("epoch"), cf("coin"), cf("head")]).unwrap();
        Store{db}
    }
    pub fn put<T: Serialize>(&self, cf: &str, key: &[u8], v: &T) {
        let b = compress_prepend_size(&serde_json::to_vec(v).unwrap());
        let _ = self.db.cf_handle(cf).map(|h| self.db.put_cf(h, key, b)).unwrap();
    }
    pub fn get<T: DeserializeOwned>(&self, cf: &str, key: &[u8]) -> Option<T> {
        let h = self.db.cf_handle(cf)?;
        self.db.get_cf(h, key).unwrap().map(|v| {
            let decompressed = decompress_size_prepended(&v).unwrap();
            serde_json::from_slice(&decompressed).unwrap()
        })
    }
}
pub fn open(cfg: &crate::config::Storage) -> std::sync::Arc<Store> {
    std::sync::Arc::new(Store::open(&cfg.path))
}