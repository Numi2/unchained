use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::HashSet;

use crate::{
    canonical::{self, CanonicalWriter},
    crypto::{self, ML_KEM_768_CT_BYTES},
    epoch::Anchor,
    protocol::CURRENT as PROTOCOL,
    shielded::{
        deterministic_genesis_note, note_key_commitment, ActiveNullifierEpoch,
        ArchivedNullifierEpoch, HistoricalUnspentCheckpoint, HistoricalUnspentExtension,
        NoteCommitmentTree, NoteMembershipProof, NullifierRootLedger, ShieldedNote,
    },
    storage::Store,
};

const SHIELDED_OUTPUT_NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedInput {
    pub note: ShieldedNote,
    pub note_key: [u8; 32],
    pub membership_proof: NoteMembershipProof,
    pub historical_checkpoint: HistoricalUnspentCheckpoint,
    pub historical_extension: HistoricalUnspentExtension,
    pub current_nullifier: [u8; 32],
    pub authorization_sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutput {
    pub note: ShieldedNote,
    #[serde(with = "BigArray")]
    pub kem_ct: [u8; ML_KEM_768_CT_BYTES],
    #[serde(with = "BigArray")]
    pub nonce: [u8; SHIELDED_OUTPUT_NONCE_LEN],
    pub view_tag: u8,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutputPlaintext {
    pub note_commitment: [u8; 32],
    pub note_key: [u8; 32],
    pub checkpoint: HistoricalUnspentCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    pub inputs: Vec<ShieldedInput>,
    pub outputs: Vec<ShieldedOutput>,
}

impl Tx {
    pub fn new(inputs: Vec<ShieldedInput>, outputs: Vec<ShieldedOutput>) -> Self {
        Self { inputs, outputs }
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        let bytes = canonical::encode_tx(self).context("serialize tx")?;
        Ok(crypto::blake3_hash(&bytes))
    }

    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let mut writer = CanonicalWriter::new();
        writer.write_bytes(b"unchained.shielded_tx.signing.v1")?;
        writer.write_vec(&self.inputs, |writer, input| {
            writer.write_fixed(&input.note.commitment);
            writer.write_fixed(&input.current_nullifier);
            Ok(())
        })?;
        writer.write_vec(&self.outputs, |writer, output| {
            writer.write_bytes(&canonical::encode_shielded_note(&output.note)?)?;
            writer.write_fixed(&output.kem_ct);
            writer.write_fixed(&output.nonce);
            writer.write_u8(output.view_tag);
            writer.write_bytes(&output.ciphertext)?;
            Ok(())
        })?;
        Ok(crypto::blake3_hash(&writer.into_vec()))
    }

    pub fn authorization_message(&self, input_index: usize) -> Result<Vec<u8>> {
        let digest = self.signing_digest()?;
        let input = self
            .inputs
            .get(input_index)
            .ok_or_else(|| anyhow!("shielded input index out of range"))?;
        let mut writer = CanonicalWriter::new();
        writer.write_fixed(&digest);
        writer.write_u32(
            u32::try_from(input_index).map_err(|_| anyhow!("too many shielded inputs"))?,
        );
        writer.write_fixed(&input.note.commitment);
        writer.write_fixed(&input.current_nullifier);
        Ok(writer.into_vec())
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        self.validate_shielded(db)
    }

    pub fn apply(&self, db: &Store) -> Result<[u8; 32]> {
        self.apply_shielded(db)
    }

    fn validate_shielded(&self, db: &Store) -> Result<()> {
        ensure_shielded_runtime_state(db)?;

        if self.inputs.is_empty() {
            bail!("shielded tx must contain at least one input");
        }
        if self.outputs.is_empty() {
            bail!("shielded tx must contain at least one output");
        }

        let chain_id = db.get_chain_id()?;
        let current_epoch = current_nullifier_epoch(db)?;
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

        let mut seen_note_commitments = HashSet::new();
        let mut seen_nullifiers = HashSet::new();
        let mut total_in = 0u128;
        let mut total_out = 0u128;

        for (index, input) in self.inputs.iter().enumerate() {
            input.note.validate()?;
            if note_key_commitment(&input.note_key) != input.note.note_key_commitment {
                bail!("shielded input note key does not match its commitment");
            }
            if db.is_shielded_note_spent(&input.note.commitment)? {
                bail!("shielded note has already been spent");
            }
            if !seen_note_commitments.insert(input.note.commitment) {
                bail!("duplicate shielded note input inside tx");
            }
            if !seen_nullifiers.insert(input.current_nullifier) {
                bail!("duplicate current-epoch nullifier inside tx");
            }
            if active.contains(&input.current_nullifier) {
                bail!("current-epoch nullifier already exists");
            }

            if input.membership_proof.note_commitment != input.note.commitment {
                bail!("shielded membership proof does not match the note commitment");
            }
            if input.membership_proof.root != tree_root || !input.membership_proof.verify() {
                bail!("invalid shielded note membership proof");
            }

            if input.historical_checkpoint.note_commitment != input.note.commitment {
                bail!("historical checkpoint does not match the note commitment");
            }
            let updated_checkpoint = input
                .historical_checkpoint
                .apply_extension(&input.historical_extension, &ledger)?;
            let required_historical_epoch = current_epoch.saturating_sub(1);
            if updated_checkpoint.covered_through_epoch != required_historical_epoch {
                bail!("historical checkpoint is stale for the current nullifier epoch");
            }

            let expected_nullifier =
                input
                    .note
                    .derive_evolving_nullifier(&input.note_key, &chain_id, current_epoch)?;
            if expected_nullifier != input.current_nullifier {
                bail!("shielded input current nullifier mismatch");
            }

            let auth_message = self.authorization_message(index)?;
            input
                .note
                .owner_signing_pk
                .verify(&auth_message, &input.authorization_sig)
                .context("invalid shielded input authorization signature")?;

            total_in = total_in.saturating_add(input.note.value as u128);
        }

        let existing_commitments = tree.commitments.iter().copied().collect::<HashSet<_>>();
        let mut new_commitments = HashSet::new();
        for output in &self.outputs {
            output.note.validate()?;
            if output.note.birth_epoch != current_epoch {
                bail!("shielded output birth epoch must equal the current nullifier epoch");
            }
            if existing_commitments.contains(&output.note.commitment)
                || !new_commitments.insert(output.note.commitment)
            {
                bail!("duplicate shielded output note commitment");
            }
            total_out = total_out.saturating_add(output.note.value as u128);
        }

        if total_in != total_out {
            bail!("shielded tx balance mismatch");
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

        for input in &self.inputs {
            batch.put_cf(
                db.db
                    .cf_handle("shielded_spent_note")
                    .ok_or_else(|| anyhow!("'shielded_spent_note' column family missing"))?,
                &input.note.commitment,
                &input.current_nullifier,
            );
            active.insert(input.current_nullifier)?;
        }

        for (index, output) in self.outputs.iter().enumerate() {
            tree.append(output.note.commitment);
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
    through_epoch: u64,
) -> Result<HistoricalUnspentExtension> {
    ensure_shielded_runtime_state(db)?;
    let expected_from = checkpoint.covered_through_epoch.saturating_add(1);
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
