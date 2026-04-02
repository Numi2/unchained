use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{canonical, storage::Store, transfer::Spend};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    pub version: u8,
    pub spends: Vec<Spend>,
}

impl Tx {
    pub const VERSION: u8 = 1;

    pub fn single_spend(spend: Spend) -> Self {
        Self {
            version: Self::VERSION,
            spends: vec![spend],
        }
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        let bytes = canonical::encode_tx(self).context("serialize tx")?;
        Ok(crate::crypto::blake3_hash(&bytes))
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        if self.version != Self::VERSION {
            return Err(anyhow!("unsupported tx version"));
        }
        if self.spends.is_empty() {
            return Err(anyhow!("tx must contain at least one spend"));
        }

        let mut nullifiers = HashSet::new();
        let mut coin_ids = HashSet::new();
        for spend in &self.spends {
            if !nullifiers.insert(spend.nullifier) {
                return Err(anyhow!("duplicate nullifier inside tx"));
            }
            if !coin_ids.insert(spend.coin_id) {
                return Err(anyhow!("duplicate coin input inside tx"));
            }
            spend.validate(db)?;
        }
        Ok(())
    }

    pub fn apply(&self, db: &Store) -> Result<[u8; 32]> {
        self.validate(db)?;

        let tx_id = self.id()?;
        let tx_cf = db
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow!("tx CF missing"))?;
        let mut batch = rocksdb::WriteBatch::default();
        let tx_bytes = canonical::encode_tx(self).context("serialize tx")?;
        batch.put_cf(tx_cf, &tx_id, &tx_bytes);
        for spend in &self.spends {
            spend.apply_to_batch(db, &mut batch)?;
        }
        db.write_batch(batch).context("write tx batch")?;
        Ok(tx_id)
    }
}
