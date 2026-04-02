use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::HashSet;

use crate::{
    canonical,
    crypto::ML_KEM_768_CT_BYTES,
    epoch::Anchor,
    proof,
    protocol::CURRENT as PROTOCOL,
    shielded::{
        deterministic_genesis_note, ActiveNullifierEpoch, ArchivedNullifierEpoch,
        HistoricalUnspentCheckpoint, HistoricalUnspentExtension, NoteCommitmentTree,
        NullifierRootLedger, ShieldedNote,
    },
    storage::Store,
};

const SHIELDED_OUTPUT_NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutput {
    pub note_commitment: [u8; 32],
    #[serde(with = "BigArray")]
    pub kem_ct: [u8; ML_KEM_768_CT_BYTES],
    #[serde(with = "BigArray")]
    pub nonce: [u8; SHIELDED_OUTPUT_NONCE_LEN],
    pub view_tag: u8,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutputPlaintext {
    pub note: ShieldedNote,
    pub note_key: [u8; 32],
    pub checkpoint: HistoricalUnspentCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    pub nullifiers: Vec<[u8; 32]>,
    pub outputs: Vec<ShieldedOutput>,
    pub proof: Vec<u8>,
}

impl Tx {
    pub fn new(nullifiers: Vec<[u8; 32]>, outputs: Vec<ShieldedOutput>, proof: Vec<u8>) -> Self {
        Self {
            nullifiers,
            outputs,
            proof,
        }
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        let bytes = canonical::encode_tx(self).context("serialize tx")?;
        Ok(crate::crypto::blake3_hash(&bytes))
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        self.validate_shielded(db)
    }

    pub fn apply(&self, db: &Store) -> Result<[u8; 32]> {
        self.apply_shielded(db)
    }

    fn validate_shielded(&self, db: &Store) -> Result<()> {
        ensure_shielded_runtime_state(db)?;

        if self.nullifiers.is_empty() {
            bail!("shielded tx must contain at least one nullifier");
        }
        if self.outputs.is_empty() {
            bail!("shielded tx must contain at least one output");
        }

        let current_epoch = current_nullifier_epoch(db)?;
        let chain_id = db.get_chain_id()?;
        let tree = db.load_shielded_note_tree()?.unwrap_or_default();
        let tree_root = tree.root();
        let ledger = db.load_shielded_root_ledger()?.unwrap_or_default();
        let active = db
            .load_shielded_active_nullifier_epoch()?
            .unwrap_or_else(|| ActiveNullifierEpoch::new(current_epoch));
        if active.epoch != current_epoch {
            bail!("active nullifier epoch is out of sync with the chain tip");
        }
        active.validate()?;

        let journal = proof::verify_shielded_receipt_bytes(&self.proof)?;
        if journal.chain_id != chain_id {
            bail!("shielded receipt chain id mismatch");
        }
        if journal.current_epoch != current_epoch {
            bail!("shielded receipt epoch mismatch");
        }
        if journal.note_tree_root != tree_root {
            bail!("shielded receipt note tree root mismatch");
        }
        if journal.inputs.len() != self.nullifiers.len() {
            bail!("shielded receipt input count mismatch");
        }
        if journal.outputs.len() != self.outputs.len() {
            bail!("shielded receipt output count mismatch");
        }

        let existing_commitments = tree.commitments.iter().copied().collect::<HashSet<_>>();
        let mut seen_nullifiers = HashSet::new();
        for (index, binding) in journal.inputs.iter().enumerate() {
            if binding.current_nullifier != self.nullifiers[index] {
                bail!("shielded receipt nullifier mismatch");
            }
            if !seen_nullifiers.insert(binding.current_nullifier) {
                bail!("duplicate current nullifier inside tx");
            }
            if active.contains(&binding.current_nullifier) {
                bail!("current nullifier already exists in the active epoch");
            }
            if current_epoch > 0 && binding.historical_through_epoch != current_epoch - 1 {
                bail!("historical range does not end at the prior epoch");
            }
            let expected_digest = historical_root_digest_for_range(
                &ledger,
                binding.historical_from_epoch,
                binding.historical_through_epoch,
            )?;
            if expected_digest != binding.historical_root_digest {
                bail!("historical nullifier root digest mismatch");
            }
        }

        let mut new_commitments = HashSet::new();
        for (binding, output) in journal.outputs.iter().zip(&self.outputs) {
            if binding.note_commitment != output.note_commitment {
                bail!("shielded receipt output commitment mismatch");
            }
            if binding != &proof::output_binding(output) {
                bail!("shielded receipt output binding mismatch");
            }
            if existing_commitments.contains(&output.note_commitment)
                || !new_commitments.insert(output.note_commitment)
            {
                bail!("duplicate shielded output note commitment");
            }
        }

        Ok(())
    }

    fn apply_shielded(&self, db: &Store) -> Result<[u8; 32]> {
        self.validate_shielded(db)?;

        let tx_id = self.id()?;
        let tx_cf = db
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow!("tx CF missing"))?;
        let mut batch = rocksdb::WriteBatch::default();
        let tx_bytes = canonical::encode_tx(self).context("serialize tx")?;
        batch.put_cf(tx_cf, &tx_id, &tx_bytes);

        let mut tree = db.load_shielded_note_tree()?.unwrap_or_default();
        let mut active = db
            .load_shielded_active_nullifier_epoch()?
            .ok_or_else(|| anyhow!("missing active shielded nullifier epoch"))?;

        for nullifier in &self.nullifiers {
            active.insert(*nullifier)?;
        }

        for (index, output) in self.outputs.iter().enumerate() {
            tree.append(output.note_commitment);
            let mut output_key = Vec::with_capacity(36);
            output_key.extend_from_slice(&tx_id);
            output_key.extend_from_slice(&(index as u32).to_le_bytes());
            let output_cf = db
                .db
                .cf_handle("shielded_output")
                .ok_or_else(|| anyhow!("'shielded_output' column family missing"))?;
            batch.put_cf(
                output_cf,
                &output_key,
                bincode::serialize(output).context("serialize shielded output")?,
            );
        }

        let tree_cf = db
            .db
            .cf_handle("shielded_note_tree")
            .ok_or_else(|| anyhow!("'shielded_note_tree' column family missing"))?;
        batch.put_cf(
            tree_cf,
            b"global",
            canonical::encode_note_commitment_tree(&tree)?,
        );

        let active_cf = db
            .db
            .cf_handle("shielded_active_nullifier")
            .ok_or_else(|| anyhow!("'shielded_active_nullifier' column family missing"))?;
        batch.put_cf(
            active_cf,
            b"active",
            bincode::serialize(&active).context("serialize active nullifier epoch")?,
        );

        db.write_batch(batch)
            .context("write shielded tx batch to the database")?;
        Ok(tx_id)
    }
}

pub fn current_nullifier_epoch_from_height(anchor_height: u64) -> u64 {
    let epoch_len = PROTOCOL.nullifier_epoch_length.max(1);
    anchor_height / epoch_len
}

pub fn current_nullifier_epoch(db: &Store) -> Result<u64> {
    let anchor = db.get::<Anchor>("epoch", b"latest")?.unwrap_or(Anchor {
        num: 0,
        hash: [0u8; 32],
        merkle_root: [0u8; 32],
        difficulty: 0,
        coin_count: 0,
        cumulative_work: 0,
        mem_kib: 0,
    });
    Ok(current_nullifier_epoch_from_height(anchor.num))
}

pub fn ensure_shielded_runtime_state(db: &Store) -> Result<()> {
    materialize_genesis_note_commitments(db)?;
    rollover_active_nullifier_epoch(db)
}

pub fn build_local_historical_extension(
    db: &Store,
    note: &ShieldedNote,
    note_key: &[u8; 32],
    checkpoint: &HistoricalUnspentCheckpoint,
    through_epoch: Option<u64>,
) -> Result<HistoricalUnspentExtension> {
    ensure_shielded_runtime_state(db)?;
    let expected_from = checkpoint.covered_through_epoch.saturating_add(1);
    let Some(through_epoch) = through_epoch else {
        let server = crate::shielded::ShieldedSyncServer::new();
        return server.extend_checkpoint(checkpoint, &[]);
    };
    if through_epoch < expected_from {
        let server = crate::shielded::ShieldedSyncServer::new();
        return server.extend_checkpoint(checkpoint, &[]);
    }

    let chain_id = db.get_chain_id()?;
    let mut server = crate::shielded::ShieldedSyncServer::new();
    let mut queries = Vec::new();
    for epoch in expected_from..=through_epoch {
        let archived = db
            .load_shielded_nullifier_epoch(epoch)?
            .unwrap_or_else(|| ArchivedNullifierEpoch::new(epoch, std::iter::empty()));
        server.archive_epoch(epoch, archived.nullifiers.clone())?;
        queries.push(crate::shielded::EvolvingNullifierQuery {
            epoch,
            nullifier: note.derive_evolving_nullifier(note_key, &chain_id, epoch)?,
        });
    }
    server.extend_checkpoint(checkpoint, &queries)
}

pub fn materialize_genesis_note_commitments(db: &Store) -> Result<()> {
    let chain_id = db.get_chain_id()?;
    let coins = db.iterate_coins()?;
    let mut tree = db
        .load_shielded_note_tree()?
        .unwrap_or_else(NoteCommitmentTree::new);
    let mut changed = false;
    let mut known = tree.commitments.iter().copied().collect::<HashSet<_>>();
    for coin in coins {
        let birth_epoch = db.get_epoch_for_coin(&coin.id)?.unwrap_or(0);
        let (note, _, _) = deterministic_genesis_note(&coin, birth_epoch, &chain_id);
        if known.insert(note.commitment) {
            tree.append(note.commitment);
            changed = true;
        }
    }
    if changed {
        db.store_shielded_note_tree(&tree)?;
    }
    Ok(())
}

fn rollover_active_nullifier_epoch(db: &Store) -> Result<()> {
    let current_epoch = current_nullifier_epoch(db)?;
    let mut active = db
        .load_shielded_active_nullifier_epoch()?
        .unwrap_or_else(|| ActiveNullifierEpoch::new(0));
    active.validate()?;
    if active.epoch > current_epoch {
        bail!("active nullifier epoch is ahead of the local chain tip");
    }

    let mut ledger = db
        .load_shielded_root_ledger()?
        .unwrap_or_else(NullifierRootLedger::default);
    let mut changed = false;
    while active.epoch < current_epoch {
        let archived = active.archive()?;
        db.store_shielded_nullifier_epoch(&archived)?;
        ledger.remember_epoch(&archived);
        active = ActiveNullifierEpoch::new(active.epoch.saturating_add(1));
        changed = true;
    }

    if changed || db.load_shielded_root_ledger()?.is_none() {
        db.store_shielded_root_ledger(&ledger)?;
    }
    if changed || db.load_shielded_active_nullifier_epoch()?.is_none() {
        db.store_shielded_active_nullifier_epoch(&active)?;
    }
    Ok(())
}

fn historical_root_digest_for_range(
    ledger: &NullifierRootLedger,
    from_epoch: u64,
    through_epoch: u64,
) -> Result<[u8; 32]> {
    if from_epoch > through_epoch {
        return Ok(proof_core::historical_root_digest_from_pairs(&[]));
    }
    let mut pairs = Vec::new();
    for epoch in from_epoch..=through_epoch {
        pairs.push((epoch, ledger.root_for_epoch(epoch)?));
    }
    Ok(proof_core::historical_root_digest_from_pairs(&pairs))
}
