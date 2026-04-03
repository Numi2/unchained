use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::ML_DSA_65;
use methods::CHECKPOINT_ACCUMULATOR_METHOD_ID;
use proof_core::{ProofShieldedInputBinding, ProofShieldedOutputBinding};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{
    canonical,
    consensus::ValidatorId,
    crypto::ML_KEM_768_CT_BYTES,
    epoch::Anchor,
    proof,
    protocol::CURRENT as PROTOCOL,
    shielded::{
        deterministic_genesis_note, ActiveNullifierEpoch, HistoricalUnspentCheckpoint,
        NoteCommitmentTree, NullifierRootLedger, ShieldedNote,
    },
    staking::{ValidatorPool, ValidatorProfileUpdate, ValidatorRegistration},
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionClass {
    OrdinaryPrivateTransfer,
    SharedState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrdinaryPrivateTransfer {
    pub nullifiers: Vec<[u8; 32]>,
    pub outputs: Vec<ShieldedOutput>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedStateAuthorization {
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateDelegation {
    pub validator_id: ValidatorId,
    pub transfer: OrdinaryPrivateTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateUndelegation {
    pub validator_id: ValidatorId,
    pub transfer: OrdinaryPrivateTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimUnbonding {
    pub transfer: OrdinaryPrivateTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedStateBatch {
    pub ordered_tx_root: [u8; 32],
    pub txs: Vec<Tx>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FastPathBatch {
    pub ordered_tx_root: [u8; 32],
    pub txs: Vec<Tx>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedStateDagBatch {
    pub epoch: u64,
    pub round: u64,
    pub author: ValidatorId,
    pub parents: Vec<[u8; 32]>,
    pub batch_id: [u8; 32],
    pub batch: SharedStateBatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SharedStateAction {
    RegisterValidator(ValidatorRegistration),
    UpdateValidatorProfile(ValidatorProfileUpdate),
    PrivateDelegation(PrivateDelegation),
    PrivateUndelegation(PrivateUndelegation),
    ClaimUnbonding(ClaimUnbonding),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedStateTx {
    pub action: SharedStateAction,
    pub authorization: SharedStateAuthorization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Tx {
    OrdinaryPrivateTransfer(OrdinaryPrivateTransfer),
    SharedState(SharedStateTx),
}

impl SharedStateBatch {
    pub fn ordered_tx_root_for_ids(tx_ids: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("unchained.shared-state-batch.ordered-root.v1");
        hasher.update(&(tx_ids.len() as u64).to_le_bytes());
        for tx_id in tx_ids {
            hasher.update(tx_id);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn new(txs: Vec<Tx>) -> Result<Self> {
        let tx_ids = txs.iter().map(|tx| tx.id()).collect::<Result<Vec<_>>>()?;
        let ordered_tx_root = Self::ordered_tx_root_for_ids(&tx_ids);
        Ok(Self {
            ordered_tx_root,
            txs,
        })
    }

    pub fn tx_ids(&self) -> Result<Vec<[u8; 32]>> {
        self.txs.iter().map(Tx::id).collect()
    }

    pub fn ordered_tx_count(&self) -> Result<u32> {
        u32::try_from(self.txs.len()).context("shared-state batch size exceeds u32")
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        let tx_ids = self.tx_ids()?;
        let mut seen_tx_ids = HashSet::new();
        for (_tx, tx_id) in self.txs.iter().zip(tx_ids.iter()) {
            if !seen_tx_ids.insert(*tx_id) {
                bail!("shared-state batch contains duplicate transaction ids");
            }
        }
        let expected_root = Self::ordered_tx_root_for_ids(&tx_ids);
        if self.ordered_tx_root != expected_root {
            bail!("shared-state batch ordered tx root mismatch");
        }
        Ok(())
    }

    pub fn from_dag_batches(dag_batches: &[SharedStateDagBatch]) -> Result<Self> {
        let mut txs = Vec::new();
        let mut seen_tx_ids = HashSet::new();
        let mut seen_nullifiers = HashSet::new();
        let mut seen_conflicts = HashSet::new();
        for dag_batch in dag_batches {
            for tx in &dag_batch.batch.txs {
                let tx_id = tx.id()?;
                if !seen_tx_ids.insert(tx_id) {
                    continue;
                }
                let conflict_keys = tx.shared_state_conflict_keys()?;
                if tx
                    .nullifiers()
                    .iter()
                    .any(|nullifier| seen_nullifiers.contains(nullifier))
                    || conflict_keys.iter().any(|key| seen_conflicts.contains(key))
                {
                    continue;
                }
                for nullifier in tx.nullifiers() {
                    seen_nullifiers.insert(*nullifier);
                }
                for conflict_key in conflict_keys {
                    seen_conflicts.insert(conflict_key);
                }
                txs.push(tx.clone());
            }
        }
        Self::new(txs)
    }

    pub fn validate_against_store(&self, db: &Store) -> Result<()> {
        self.validate()?;
        let mut seen_nullifiers = HashSet::new();
        let mut seen_conflicts = HashSet::new();
        for tx in &self.txs {
            let tx_id = tx.id()?;
            if db.get_raw_bytes("tx", &tx_id)?.is_some() {
                bail!("shared-state batch contains an already finalized transaction");
            }
            tx.validate(db)?;
            for nullifier in tx.nullifiers() {
                if !seen_nullifiers.insert(*nullifier) {
                    bail!("shared-state batch contains duplicate nullifiers");
                }
            }
            for conflict_key in tx.shared_state_conflict_keys()? {
                if !seen_conflicts.insert(conflict_key) {
                    bail!("shared-state batch contains conflicting shared-state actions");
                }
            }
        }
        Ok(())
    }

    pub fn apply_finalized(&self, db: &Store) -> Result<Vec<[u8; 32]>> {
        self.validate_against_store(db)?;
        ensure_shielded_runtime_state(db)?;

        let mut note_tree = db.load_shielded_note_tree()?.unwrap_or_default();
        let mut active = db
            .load_shielded_active_nullifier_epoch()?
            .ok_or_else(|| anyhow!("missing active shielded nullifier epoch"))?;
        let mut pool_overlay = HashMap::<[u8; 32], ValidatorPool>::new();
        let tx_cf = db
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow!("tx CF missing"))?;
        let validator_pool_cf = db
            .db
            .cf_handle("validator_pool")
            .ok_or_else(|| anyhow!("'validator_pool' column family missing"))?;
        let pending_cf = db
            .db
            .cf_handle("shared_state_pending_tx")
            .ok_or_else(|| anyhow!("'shared_state_pending_tx' column family missing"))?;

        let mut write_batch = rocksdb::WriteBatch::default();
        let mut finalized_tx_ids = Vec::with_capacity(self.txs.len());
        for tx in &self.txs {
            let tx_id = tx.id()?;
            finalized_tx_ids.push(tx_id);
            let tx_bytes =
                canonical::encode_tx(tx).context("serialize finalized shared-state tx")?;
            write_batch.put_cf(tx_cf, &tx_id, &tx_bytes);
            write_batch.delete_cf(pending_cf, &tx_id);
            match tx {
                Tx::OrdinaryPrivateTransfer(transfer) => {
                    append_shielded_transfer_to_overlay(
                        db,
                        &mut write_batch,
                        &tx_id,
                        transfer,
                        &mut note_tree,
                        &mut active,
                    )?;
                    let fast_path_pending_cf = db
                        .db
                        .cf_handle("fast_path_pending_tx")
                        .ok_or_else(|| anyhow!("'fast_path_pending_tx' column family missing"))?;
                    write_batch.delete_cf(fast_path_pending_cf, &tx_id);
                }
                Tx::SharedState(shared) => match &shared.action {
                    SharedStateAction::RegisterValidator(registration) => {
                        pool_overlay
                            .insert(registration.pool.validator.id.0, registration.pool.clone());
                    }
                    SharedStateAction::UpdateValidatorProfile(update) => {
                        let existing = pool_overlay
                            .get(&update.validator_id.0)
                            .cloned()
                            .or_else(|| db.load_validator_pool(&update.validator_id).ok().flatten())
                            .ok_or_else(|| anyhow!("validator pool not found"))?;
                        let updated = update.apply_to(&existing)?;
                        pool_overlay.insert(updated.validator.id.0, updated);
                    }
                    SharedStateAction::PrivateDelegation(delegation) => {
                        let journal = proof::verify_private_delegation_receipt_bytes(
                            &delegation.transfer.proof,
                        )?;
                        let pool = pool_overlay
                            .get(&delegation.validator_id.0)
                            .cloned()
                            .or_else(|| {
                                db.load_validator_pool(&delegation.validator_id)
                                    .ok()
                                    .flatten()
                            })
                            .ok_or_else(|| anyhow!("validator pool not found"))?;
                        let updated_pool = pool.apply_delegation(
                            journal.delegated_amount,
                            journal.delegation_share_value,
                        )?;
                        append_shielded_transfer_to_overlay(
                            db,
                            &mut write_batch,
                            &tx_id,
                            &delegation.transfer,
                            &mut note_tree,
                            &mut active,
                        )?;
                        pool_overlay.insert(updated_pool.validator.id.0, updated_pool);
                    }
                    SharedStateAction::PrivateUndelegation(undelegation) => {
                        let journal = proof::verify_private_undelegation_receipt_bytes(
                            &undelegation.transfer.proof,
                        )?;
                        let pool = pool_overlay
                            .get(&undelegation.validator_id.0)
                            .cloned()
                            .or_else(|| {
                                db.load_validator_pool(&undelegation.validator_id)
                                    .ok()
                                    .flatten()
                            })
                            .ok_or_else(|| anyhow!("validator pool not found"))?;
                        let updated_pool = pool.apply_undelegation(
                            journal.burned_share_value,
                            journal.claim_value,
                            journal.current_epoch,
                            journal.release_epoch,
                            PROTOCOL.stake_unbonding_epochs,
                        )?;
                        append_shielded_transfer_to_overlay(
                            db,
                            &mut write_batch,
                            &tx_id,
                            &undelegation.transfer,
                            &mut note_tree,
                            &mut active,
                        )?;
                        pool_overlay.insert(updated_pool.validator.id.0, updated_pool);
                    }
                    SharedStateAction::ClaimUnbonding(claim) => {
                        append_shielded_transfer_to_overlay(
                            db,
                            &mut write_batch,
                            &tx_id,
                            &claim.transfer,
                            &mut note_tree,
                            &mut active,
                        )?;
                    }
                },
            }
        }

        persist_shielded_runtime_overlay(db, &mut write_batch, &note_tree, &active)?;
        for updated_pool in pool_overlay.into_values() {
            write_batch.put_cf(
                validator_pool_cf,
                &updated_pool.validator.id.0,
                bincode::serialize(&updated_pool)
                    .context("serialize finalized shared-state validator pool")?,
            );
        }
        db.write_batch(write_batch)
            .context("write finalized shared-state batch to the database")?;
        Ok(finalized_tx_ids)
    }
}

impl FastPathBatch {
    pub fn ordered_tx_root_for_ids(tx_ids: &[[u8; 32]]) -> [u8; 32] {
        SharedStateBatch::ordered_tx_root_for_ids(tx_ids)
    }

    pub fn new(txs: Vec<Tx>) -> Result<Self> {
        let tx_ids = txs
            .iter()
            .map(|tx| {
                if !matches!(tx, Tx::OrdinaryPrivateTransfer(_)) {
                    bail!("fast-path batches may only carry ordinary private transfers");
                }
                tx.id()
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            ordered_tx_root: Self::ordered_tx_root_for_ids(&tx_ids),
            txs,
        })
    }

    pub fn tx_ids(&self) -> Result<Vec<[u8; 32]>> {
        self.txs.iter().map(Tx::id).collect()
    }

    pub fn ordered_tx_count(&self) -> Result<u32> {
        u32::try_from(self.txs.len()).context("fast-path batch size exceeds u32")
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        let tx_ids = self.tx_ids()?;
        let mut seen_tx_ids = HashSet::new();
        let mut seen_nullifiers = HashSet::new();
        for (tx, tx_id) in self.txs.iter().zip(tx_ids.iter()) {
            let Tx::OrdinaryPrivateTransfer(_) = tx else {
                bail!("fast-path batches may only carry ordinary private transfers");
            };
            if !seen_tx_ids.insert(*tx_id) {
                bail!("fast-path batch contains duplicate transaction ids");
            }
            for nullifier in tx.nullifiers() {
                if !seen_nullifiers.insert(*nullifier) {
                    bail!("fast-path batch contains duplicate nullifiers");
                }
            }
        }
        let expected_root = Self::ordered_tx_root_for_ids(&tx_ids);
        if self.ordered_tx_root != expected_root {
            bail!("fast-path batch ordered tx root mismatch");
        }
        Ok(())
    }

    pub fn validate_against_store(&self, db: &Store) -> Result<()> {
        self.validate()?;
        for tx in &self.txs {
            let tx_id = tx.id()?;
            if db.get_raw_bytes("tx", &tx_id)?.is_some() {
                bail!("fast-path batch contains an already finalized transaction");
            }
            match tx {
                Tx::OrdinaryPrivateTransfer(transfer) => {
                    tx.validate(db)?;
                    let journal = proof::verify_shielded_receipt_bytes(&transfer.proof)?;
                    if journal.inputs.len() != transfer.nullifiers.len() {
                        bail!("fast-path transaction proof input count mismatch");
                    }
                    if journal.outputs.len() != transfer.outputs.len() {
                        bail!("fast-path transaction proof output count mismatch");
                    }
                }
                Tx::SharedState(_) => {
                    bail!("fast-path batches cannot carry shared-state transactions")
                }
            }
        }
        Ok(())
    }

    pub fn apply_finalized(&self, db: &Store) -> Result<Vec<[u8; 32]>> {
        self.validate_against_store(db)?;
        ensure_shielded_runtime_state(db)?;

        let mut note_tree = db.load_shielded_note_tree()?.unwrap_or_default();
        let mut active = db
            .load_shielded_active_nullifier_epoch()?
            .ok_or_else(|| anyhow!("missing active shielded nullifier epoch"))?;
        let tx_cf = db
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow!("tx CF missing"))?;
        let pending_cf = db
            .db
            .cf_handle("fast_path_pending_tx")
            .ok_or_else(|| anyhow!("'fast_path_pending_tx' column family missing"))?;

        let mut write_batch = rocksdb::WriteBatch::default();
        let mut finalized_tx_ids = Vec::with_capacity(self.txs.len());
        for tx in &self.txs {
            let tx_id = tx.id()?;
            finalized_tx_ids.push(tx_id);
            let tx_bytes = canonical::encode_tx(tx).context("serialize finalized fast-path tx")?;
            write_batch.put_cf(tx_cf, &tx_id, &tx_bytes);
            write_batch.delete_cf(pending_cf, &tx_id);
            let Tx::OrdinaryPrivateTransfer(transfer) = tx else {
                bail!("fast-path batch contains a non-ordinary transaction");
            };
            append_shielded_transfer_to_overlay(
                db,
                &mut write_batch,
                &tx_id,
                transfer,
                &mut note_tree,
                &mut active,
            )?;
        }

        persist_shielded_runtime_overlay(db, &mut write_batch, &note_tree, &active)?;
        db.write_batch(write_batch)
            .context("write finalized fast-path batch to the database")?;
        Ok(finalized_tx_ids)
    }
}

impl SharedStateDagBatch {
    pub fn compute_batch_id(
        epoch: u64,
        round: u64,
        author: ValidatorId,
        parents: &[[u8; 32]],
        batch: &SharedStateBatch,
    ) -> Result<[u8; 32]> {
        batch.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key("unchained.shared-state-dag-batch.id.v1");
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(&author.0);
        hasher.update(&(parents.len() as u64).to_le_bytes());
        for parent in parents {
            hasher.update(parent);
        }
        hasher.update(&batch.ordered_tx_root);
        hasher.update(&batch.ordered_tx_count()?.to_le_bytes());
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn new(
        epoch: u64,
        round: u64,
        author: ValidatorId,
        mut parents: Vec<[u8; 32]>,
        batch: SharedStateBatch,
    ) -> Result<Self> {
        parents.sort();
        let batch_id = Self::compute_batch_id(epoch, round, author, &parents, &batch)?;
        let dag_batch = Self {
            epoch,
            round,
            author,
            parents,
            batch_id,
            batch,
        };
        dag_batch.validate()?;
        Ok(dag_batch)
    }

    pub fn validate(&self) -> Result<()> {
        self.batch.validate()?;
        if self.round == 0 {
            bail!("shared-state DAG batch round must be non-zero");
        }
        if self.round == 1 && !self.parents.is_empty() {
            bail!("round-1 DAG batches must not reference parents");
        }
        if self.round > 1 && self.parents.is_empty() {
            bail!("non-genesis DAG batches must reference a parent frontier");
        }
        let mut last_parent = None;
        for parent in &self.parents {
            if *parent == [0u8; 32] {
                bail!("shared-state DAG batch parent id cannot be zero");
            }
            if last_parent == Some(*parent) {
                bail!("shared-state DAG batch contains duplicate parents");
            }
            last_parent = Some(*parent);
        }
        let expected = Self::compute_batch_id(
            self.epoch,
            self.round,
            self.author,
            &self.parents,
            &self.batch,
        )?;
        if self.batch_id != expected {
            bail!("shared-state DAG batch id mismatch");
        }
        Ok(())
    }

    pub fn ordered_tx_count(&self) -> Result<u32> {
        self.batch.ordered_tx_count()
    }

    pub fn tx_ids(&self) -> Result<Vec<[u8; 32]>> {
        self.batch.tx_ids()
    }

    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}

impl Tx {
    pub fn new(nullifiers: Vec<[u8; 32]>, outputs: Vec<ShieldedOutput>, proof: Vec<u8>) -> Self {
        Self::OrdinaryPrivateTransfer(OrdinaryPrivateTransfer {
            nullifiers,
            outputs,
            proof,
        })
    }

    pub fn new_shared_state(action: SharedStateAction, authorization_signature: Vec<u8>) -> Self {
        Self::SharedState(SharedStateTx {
            action,
            authorization: SharedStateAuthorization {
                signature: authorization_signature,
            },
        })
    }

    pub fn class(&self) -> TransactionClass {
        match self {
            Self::OrdinaryPrivateTransfer(_) => TransactionClass::OrdinaryPrivateTransfer,
            Self::SharedState(_) => TransactionClass::SharedState,
        }
    }

    pub fn ordinary_transfer(&self) -> Option<&OrdinaryPrivateTransfer> {
        match self {
            Self::OrdinaryPrivateTransfer(transfer) => Some(transfer),
            Self::SharedState(_) => None,
        }
    }

    pub fn shielded_transfer(&self) -> Option<&OrdinaryPrivateTransfer> {
        match self {
            Self::OrdinaryPrivateTransfer(transfer) => Some(transfer),
            Self::SharedState(shared) => match &shared.action {
                SharedStateAction::PrivateDelegation(delegation) => Some(&delegation.transfer),
                SharedStateAction::PrivateUndelegation(undelegation) => {
                    Some(&undelegation.transfer)
                }
                SharedStateAction::ClaimUnbonding(claim) => Some(&claim.transfer),
                SharedStateAction::RegisterValidator(_)
                | SharedStateAction::UpdateValidatorProfile(_) => None,
            },
        }
    }

    pub fn shared_state(&self) -> Option<&SharedStateTx> {
        match self {
            Self::OrdinaryPrivateTransfer(_) => None,
            Self::SharedState(shared) => Some(shared),
        }
    }

    pub fn nullifiers(&self) -> &[[u8; 32]] {
        self.shielded_transfer()
            .map(|transfer| transfer.nullifiers.as_slice())
            .unwrap_or(&[])
    }

    pub fn outputs(&self) -> &[ShieldedOutput] {
        self.shielded_transfer()
            .map(|transfer| transfer.outputs.as_slice())
            .unwrap_or(&[])
    }

    pub fn proof(&self) -> Option<&[u8]> {
        self.shielded_transfer()
            .map(|transfer| transfer.proof.as_slice())
    }

    pub fn input_count(&self) -> usize {
        self.nullifiers().len()
    }

    pub fn output_count(&self) -> usize {
        self.outputs().len()
    }

    pub fn shared_state_signing_bytes(
        chain_id: [u8; 32],
        action: &SharedStateAction,
    ) -> Result<Vec<u8>> {
        if matches!(
            action,
            SharedStateAction::PrivateDelegation(_)
                | SharedStateAction::PrivateUndelegation(_)
                | SharedStateAction::ClaimUnbonding(_)
        ) {
            bail!("private staking actions are authorized by native proofs, not governance signatures");
        }
        canonical::encode_shared_state_action_signing_message(&chain_id, action)
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        let bytes = canonical::encode_tx(self).context("serialize tx")?;
        Ok(crate::crypto::blake3_hash(&bytes))
    }

    pub fn is_fast_path_eligible(&self) -> bool {
        matches!(self, Self::OrdinaryPrivateTransfer(_))
    }

    pub fn validate(&self, db: &Store) -> Result<()> {
        self.ensure_not_finalized(db)?;
        match self {
            Self::OrdinaryPrivateTransfer(transfer) => self.validate_shielded(transfer, db),
            Self::SharedState(shared) => self.validate_shared_state(shared, db),
        }
    }

    pub fn apply(&self, db: &Store) -> Result<[u8; 32]> {
        self.ensure_not_finalized(db)?;
        match self {
            Self::OrdinaryPrivateTransfer(transfer) => self.apply_shielded(transfer, db),
            Self::SharedState(shared) => self.apply_shared_state(shared, db),
        }
    }

    pub fn shared_state_conflict_keys(&self) -> Result<Vec<Vec<u8>>> {
        let Some(shared) = self.shared_state() else {
            return Ok(Vec::new());
        };
        match &shared.action {
            SharedStateAction::RegisterValidator(registration) => Ok(vec![
                conflict_key(b"validator-id", &registration.pool.validator.id.0),
                conflict_key(b"validator-node", &registration.pool.node_id),
            ]),
            SharedStateAction::UpdateValidatorProfile(update) => {
                Ok(vec![conflict_key(b"validator-id", &update.validator_id.0)])
            }
            SharedStateAction::PrivateDelegation(delegation) => Ok(vec![conflict_key(
                b"validator-id",
                &delegation.validator_id.0,
            )]),
            SharedStateAction::PrivateUndelegation(undelegation) => Ok(vec![conflict_key(
                b"validator-id",
                &undelegation.validator_id.0,
            )]),
            SharedStateAction::ClaimUnbonding(_) => Ok(Vec::new()),
        }
    }

    fn ensure_not_finalized(&self, db: &Store) -> Result<()> {
        let tx_id = self.id()?;
        if db.get_raw_bytes("tx", &tx_id)?.is_some() {
            bail!("transaction is already finalized");
        }
        Ok(())
    }

    fn validate_shielded(&self, transfer: &OrdinaryPrivateTransfer, db: &Store) -> Result<()> {
        ensure_shielded_runtime_state(db)?;

        if transfer.nullifiers.is_empty() {
            bail!("shielded tx must contain at least one nullifier");
        }
        if transfer.outputs.is_empty() {
            bail!("shielded tx must contain at least one output");
        }

        let current_epoch = current_nullifier_epoch(db)?;
        let chain_id = db.effective_chain_id();
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

        let journal = proof::verify_shielded_receipt_bytes(&transfer.proof)?;
        if journal.chain_id != chain_id {
            bail!("shielded receipt chain id mismatch");
        }
        if journal.current_epoch != current_epoch {
            bail!("shielded receipt epoch mismatch");
        }
        if journal.note_tree_root != tree_root {
            bail!("shielded receipt note tree root mismatch");
        }
        validate_transfer_against_journal(
            transfer,
            current_epoch,
            &tree,
            &ledger,
            &active,
            &journal.inputs,
            &journal.outputs,
        )
    }

    fn apply_shielded(&self, transfer: &OrdinaryPrivateTransfer, db: &Store) -> Result<[u8; 32]> {
        self.validate_shielded(transfer, db)?;

        let tx_id = self.id()?;
        let tx_cf = db
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow!("tx CF missing"))?;
        let mut batch = rocksdb::WriteBatch::default();
        let tx_bytes = canonical::encode_tx(self).context("serialize tx")?;
        batch.put_cf(tx_cf, &tx_id, &tx_bytes);
        append_shielded_transfer_to_batch(db, &mut batch, &tx_id, transfer)?;

        db.write_batch(batch)
            .context("write shielded tx batch to the database")?;
        Ok(tx_id)
    }

    fn validate_shared_state(&self, shared: &SharedStateTx, db: &Store) -> Result<()> {
        let latest_anchor = db
            .get::<Anchor>("epoch", b"latest")?
            .ok_or_else(|| anyhow!("shared-state transactions require a finalized anchor"))?;
        let current_epoch = latest_anchor.position.epoch;
        let chain_id = db.effective_chain_id();

        match &shared.action {
            SharedStateAction::RegisterValidator(registration) => {
                let signable = Self::shared_state_signing_bytes(
                    chain_id,
                    &SharedStateAction::RegisterValidator(registration.clone()),
                )?;
                registration.validate()?;
                verify_shared_state_signature(
                    &registration.pool.validator.keys.cold_governance_key,
                    &signable,
                    &shared.authorization.signature,
                )?;
                if registration.pool.activation_epoch <= current_epoch {
                    bail!(
                        "validator registrations must activate in a future epoch; current epoch is {}",
                        current_epoch
                    );
                }
                if db
                    .load_validator_committee(registration.pool.activation_epoch)?
                    .is_some()
                {
                    bail!(
                        "validator committee for activation epoch {} is already fixed",
                        registration.pool.activation_epoch
                    );
                }
                if db
                    .load_validator_pool(&registration.pool.validator_id())?
                    .is_some()
                {
                    bail!("validator pool already exists");
                }
                for existing in db.load_validator_pools()? {
                    if existing.node_id == registration.pool.node_id {
                        bail!("validator node id is already registered");
                    }
                }
            }
            SharedStateAction::UpdateValidatorProfile(update) => {
                let signable = Self::shared_state_signing_bytes(
                    chain_id,
                    &SharedStateAction::UpdateValidatorProfile(update.clone()),
                )?;
                update.validate()?;
                let existing = db
                    .load_validator_pool(&update.validator_id)?
                    .ok_or_else(|| anyhow!("validator pool not found"))?;
                existing.validate()?;
                verify_shared_state_signature(
                    &existing.validator.keys.cold_governance_key,
                    &signable,
                    &shared.authorization.signature,
                )?;
            }
            SharedStateAction::PrivateDelegation(delegation) => {
                if !shared.authorization.signature.is_empty() {
                    bail!("private delegation does not accept an external authorization signature");
                }
                let pool = db
                    .load_validator_pool(&delegation.validator_id)?
                    .ok_or_else(|| anyhow!("validator pool not found"))?;
                pool.validate()?;
                let tree = db.load_shielded_note_tree()?.unwrap_or_default();
                let ledger = db.load_shielded_root_ledger()?.unwrap_or_default();
                let active = db
                    .load_shielded_active_nullifier_epoch()?
                    .unwrap_or_else(|| ActiveNullifierEpoch::new(current_epoch));
                if active.epoch != current_epoch {
                    bail!("active nullifier epoch is out of sync with the chain tip");
                }
                active.validate()?;

                let journal =
                    proof::verify_private_delegation_receipt_bytes(&delegation.transfer.proof)?;
                if journal.chain_id != chain_id {
                    bail!("private delegation receipt chain id mismatch");
                }
                if journal.current_epoch != current_epoch {
                    bail!("private delegation receipt epoch mismatch");
                }
                if journal.note_tree_root != tree.root() {
                    bail!("private delegation receipt note tree root mismatch");
                }
                if ValidatorId(journal.validator_id) != delegation.validator_id {
                    bail!("private delegation receipt validator id mismatch");
                }

                validate_transfer_against_journal(
                    &delegation.transfer,
                    current_epoch,
                    &tree,
                    &ledger,
                    &active,
                    &journal.inputs,
                    &journal.outputs,
                )?;

                let delegated_output = delegation
                    .transfer
                    .outputs
                    .get(journal.delegated_output_index as usize)
                    .ok_or_else(|| anyhow!("delegated output index is out of range"))?;
                if delegated_output.note_commitment != journal.delegated_note_commitment {
                    bail!("delegated output commitment mismatch");
                }
                let preview = pool.preview_delegation(journal.delegated_amount)?;
                if preview.minted_shares != journal.delegation_share_value {
                    bail!(
                        "delegation share note value does not match the canonical pool mint result"
                    );
                }
            }
            SharedStateAction::PrivateUndelegation(undelegation) => {
                if !shared.authorization.signature.is_empty() {
                    bail!(
                        "private undelegation does not accept an external authorization signature"
                    );
                }
                let pool = db
                    .load_validator_pool(&undelegation.validator_id)?
                    .ok_or_else(|| anyhow!("validator pool not found"))?;
                pool.validate()?;
                let tree = db.load_shielded_note_tree()?.unwrap_or_default();
                let ledger = db.load_shielded_root_ledger()?.unwrap_or_default();
                let active = db
                    .load_shielded_active_nullifier_epoch()?
                    .unwrap_or_else(|| ActiveNullifierEpoch::new(current_epoch));
                if active.epoch != current_epoch {
                    bail!("active nullifier epoch is out of sync with the chain tip");
                }
                active.validate()?;

                let journal =
                    proof::verify_private_undelegation_receipt_bytes(&undelegation.transfer.proof)?;
                if journal.chain_id != chain_id {
                    bail!("private undelegation receipt chain id mismatch");
                }
                if journal.current_epoch != current_epoch {
                    bail!("private undelegation receipt epoch mismatch");
                }
                if journal.note_tree_root != tree.root() {
                    bail!("private undelegation receipt note tree root mismatch");
                }
                if ValidatorId(journal.validator_id) != undelegation.validator_id {
                    bail!("private undelegation receipt validator id mismatch");
                }

                validate_transfer_against_journal(
                    &undelegation.transfer,
                    current_epoch,
                    &tree,
                    &ledger,
                    &active,
                    &journal.inputs,
                    &journal.outputs,
                )?;

                let claim_output = undelegation
                    .transfer
                    .outputs
                    .get(journal.claim_output_index as usize)
                    .ok_or_else(|| anyhow!("claim output index is out of range"))?;
                if claim_output.note_commitment != journal.claim_note_commitment {
                    bail!("unbonding claim output commitment mismatch");
                }
                let _ = pool.apply_undelegation(
                    journal.burned_share_value,
                    journal.claim_value,
                    current_epoch,
                    journal.release_epoch,
                    PROTOCOL.stake_unbonding_epochs,
                )?;
            }
            SharedStateAction::ClaimUnbonding(claim) => {
                if !shared.authorization.signature.is_empty() {
                    bail!("unbonding claim does not accept an external authorization signature");
                }
                let tree = db.load_shielded_note_tree()?.unwrap_or_default();
                let ledger = db.load_shielded_root_ledger()?.unwrap_or_default();
                let active = db
                    .load_shielded_active_nullifier_epoch()?
                    .unwrap_or_else(|| ActiveNullifierEpoch::new(current_epoch));
                if active.epoch != current_epoch {
                    bail!("active nullifier epoch is out of sync with the chain tip");
                }
                active.validate()?;

                let journal = proof::verify_unbonding_claim_receipt_bytes(&claim.transfer.proof)?;
                if journal.chain_id != chain_id {
                    bail!("unbonding claim receipt chain id mismatch");
                }
                if journal.current_epoch != current_epoch {
                    bail!("unbonding claim receipt epoch mismatch");
                }
                if journal.note_tree_root != tree.root() {
                    bail!("unbonding claim receipt note tree root mismatch");
                }

                validate_transfer_against_journal(
                    &claim.transfer,
                    current_epoch,
                    &tree,
                    &ledger,
                    &active,
                    &journal.inputs,
                    &journal.outputs,
                )?;
            }
        }
        Ok(())
    }

    fn apply_shared_state(&self, shared: &SharedStateTx, db: &Store) -> Result<[u8; 32]> {
        self.validate_shared_state(shared, db)?;

        let tx_id = self.id()?;
        let tx_bytes = canonical::encode_tx(self).context("serialize tx")?;
        let tx_cf = db
            .db
            .cf_handle("tx")
            .ok_or_else(|| anyhow!("tx CF missing"))?;
        let validator_pool_cf = db
            .db
            .cf_handle("validator_pool")
            .ok_or_else(|| anyhow!("'validator_pool' column family missing"))?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(tx_cf, &tx_id, &tx_bytes);

        match &shared.action {
            SharedStateAction::RegisterValidator(registration) => {
                batch.put_cf(
                    validator_pool_cf,
                    &registration.pool.validator.id.0,
                    bincode::serialize(&registration.pool)
                        .context("serialize validator registration")?,
                );
            }
            SharedStateAction::UpdateValidatorProfile(update) => {
                let existing = db
                    .load_validator_pool(&update.validator_id)?
                    .ok_or_else(|| anyhow!("validator pool not found"))?;
                let updated = update.apply_to(&existing)?;
                batch.put_cf(
                    validator_pool_cf,
                    &updated.validator.id.0,
                    bincode::serialize(&updated).context("serialize validator profile update")?,
                );
            }
            SharedStateAction::PrivateDelegation(delegation) => {
                let journal =
                    proof::verify_private_delegation_receipt_bytes(&delegation.transfer.proof)?;
                let pool = db
                    .load_validator_pool(&delegation.validator_id)?
                    .ok_or_else(|| anyhow!("validator pool not found"))?;
                let updated_pool = pool
                    .apply_delegation(journal.delegated_amount, journal.delegation_share_value)?;
                append_shielded_transfer_to_batch(db, &mut batch, &tx_id, &delegation.transfer)?;
                batch.put_cf(
                    validator_pool_cf,
                    &updated_pool.validator.id.0,
                    bincode::serialize(&updated_pool)
                        .context("serialize delegated validator pool")?,
                );
            }
            SharedStateAction::PrivateUndelegation(undelegation) => {
                let journal =
                    proof::verify_private_undelegation_receipt_bytes(&undelegation.transfer.proof)?;
                let pool = db
                    .load_validator_pool(&undelegation.validator_id)?
                    .ok_or_else(|| anyhow!("validator pool not found"))?;
                let updated_pool = pool.apply_undelegation(
                    journal.burned_share_value,
                    journal.claim_value,
                    journal.current_epoch,
                    journal.release_epoch,
                    PROTOCOL.stake_unbonding_epochs,
                )?;
                append_shielded_transfer_to_batch(db, &mut batch, &tx_id, &undelegation.transfer)?;
                batch.put_cf(
                    validator_pool_cf,
                    &updated_pool.validator.id.0,
                    bincode::serialize(&updated_pool)
                        .context("serialize undelegated validator pool")?,
                );
            }
            SharedStateAction::ClaimUnbonding(claim) => {
                append_shielded_transfer_to_batch(db, &mut batch, &tx_id, &claim.transfer)?;
            }
        }

        db.write_batch(batch)
            .context("write shared-state tx batch to the database")?;
        Ok(tx_id)
    }
}

fn validate_transfer_against_journal(
    transfer: &OrdinaryPrivateTransfer,
    current_epoch: u64,
    tree: &NoteCommitmentTree,
    ledger: &NullifierRootLedger,
    active: &ActiveNullifierEpoch,
    input_bindings: &[ProofShieldedInputBinding],
    output_bindings: &[ProofShieldedOutputBinding],
) -> Result<()> {
    if input_bindings.len() != transfer.nullifiers.len() {
        bail!("shielded receipt input count mismatch");
    }
    if output_bindings.len() != transfer.outputs.len() {
        bail!("shielded receipt output count mismatch");
    }

    let mut seen_nullifiers = HashSet::new();
    for (index, binding) in input_bindings.iter().enumerate() {
        if binding.current_nullifier != transfer.nullifiers[index] {
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
        if binding.historical_from_epoch <= binding.historical_through_epoch
            && binding.historical_accumulator_image_id != CHECKPOINT_ACCUMULATOR_METHOD_ID
        {
            bail!("historical accumulator method mismatch");
        }
        if binding.historical_from_epoch > binding.historical_through_epoch
            && binding.historical_accumulator_image_id != [0u32; 8]
        {
            bail!("empty historical range must not reference an accumulator method");
        }
        let expected_digest = historical_root_digest_for_range(
            ledger,
            binding.historical_from_epoch,
            binding.historical_through_epoch,
        )?;
        if expected_digest != binding.historical_root_digest {
            bail!("historical nullifier root digest mismatch");
        }
    }

    let mut new_commitments = HashSet::new();
    for (binding, output) in output_bindings.iter().zip(&transfer.outputs) {
        if binding.note_commitment != output.note_commitment {
            bail!("shielded receipt output commitment mismatch");
        }
        if binding != &proof::output_binding(output) {
            bail!("shielded receipt output binding mismatch");
        }
        if tree.contains_commitment(&output.note_commitment)
            || !new_commitments.insert(output.note_commitment)
        {
            bail!("duplicate shielded output note commitment");
        }
    }

    Ok(())
}

fn append_shielded_transfer_to_batch(
    db: &Store,
    batch: &mut rocksdb::WriteBatch,
    tx_id: &[u8; 32],
    transfer: &OrdinaryPrivateTransfer,
) -> Result<()> {
    let mut tree = db.load_shielded_note_tree()?.unwrap_or_default();
    let mut active = db
        .load_shielded_active_nullifier_epoch()?
        .ok_or_else(|| anyhow!("missing active shielded nullifier epoch"))?;
    append_shielded_transfer_to_overlay(db, batch, tx_id, transfer, &mut tree, &mut active)?;
    persist_shielded_runtime_overlay(db, batch, &tree, &active)?;
    Ok(())
}

fn append_shielded_transfer_to_overlay(
    db: &Store,
    batch: &mut rocksdb::WriteBatch,
    tx_id: &[u8; 32],
    transfer: &OrdinaryPrivateTransfer,
    tree: &mut NoteCommitmentTree,
    active: &mut ActiveNullifierEpoch,
) -> Result<()> {
    for nullifier in &transfer.nullifiers {
        active.insert(*nullifier)?;
    }

    let output_cf = db
        .db
        .cf_handle("shielded_output")
        .ok_or_else(|| anyhow!("'shielded_output' column family missing"))?;
    for (index, output) in transfer.outputs.iter().enumerate() {
        tree.append(output.note_commitment)?;
        let mut output_key = Vec::with_capacity(36);
        output_key.extend_from_slice(tx_id);
        output_key.extend_from_slice(&(index as u32).to_le_bytes());
        batch.put_cf(
            output_cf,
            &output_key,
            bincode::serialize(output).context("serialize shielded output")?,
        );
    }
    Ok(())
}

fn persist_shielded_runtime_overlay(
    db: &Store,
    batch: &mut rocksdb::WriteBatch,
    tree: &NoteCommitmentTree,
    active: &ActiveNullifierEpoch,
) -> Result<()> {
    let tree_cf = db
        .db
        .cf_handle("shielded_note_tree")
        .ok_or_else(|| anyhow!("'shielded_note_tree' column family missing"))?;
    batch.put_cf(
        tree_cf,
        b"global",
        canonical::encode_note_commitment_tree(tree)?,
    );

    let active_cf = db
        .db
        .cf_handle("shielded_active_nullifier")
        .ok_or_else(|| anyhow!("'shielded_active_nullifier' column family missing"))?;
    batch.put_cf(
        active_cf,
        b"active",
        bincode::serialize(active).context("serialize active nullifier epoch")?,
    );
    Ok(())
}

fn conflict_key(prefix: &[u8], value: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + value.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(value);
    key
}

fn verify_shared_state_signature(
    cold_governance_key: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> Result<()> {
    UnparsedPublicKey::new(&ML_DSA_65, cold_governance_key)
        .verify(msg, signature)
        .map_err(|_| anyhow!("shared-state authorization signature verification failed"))
}

pub fn current_nullifier_epoch_from_height(anchor_height: u64) -> u64 {
    let epoch_len = PROTOCOL.nullifier_epoch_length.max(1);
    anchor_height / epoch_len
}

pub fn current_nullifier_epoch(db: &Store) -> Result<u64> {
    let anchor_height = db
        .get::<Anchor>("epoch", b"latest")?
        .map(|anchor| anchor.num)
        .unwrap_or(0);
    Ok(current_nullifier_epoch_from_height(anchor_height))
}

pub fn ensure_shielded_runtime_state(db: &Store) -> Result<()> {
    materialize_genesis_note_commitments(db)?;
    rollover_active_nullifier_epoch(db)
}

pub fn materialize_genesis_note_commitments(db: &Store) -> Result<()> {
    let chain_id = db.effective_chain_id();
    let mut tree = db
        .load_shielded_note_tree()?
        .unwrap_or_else(NoteCommitmentTree::new);
    let mut changed = false;
    for (birth_epoch, coin) in db.iterate_committed_coins()? {
        let (note, _, _) = deterministic_genesis_note(&coin, birth_epoch, &chain_id);
        if !tree.contains_commitment(&note.commitment) {
            tree.append(note.commitment)?;
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
        return Ok(proof_core::checkpoint_accumulator_historical_digest_from_pairs(&[]));
    }
    let mut pairs = Vec::new();
    for epoch in from_epoch..=through_epoch {
        pairs.push((epoch, ledger.root_for_epoch(epoch)?));
    }
    Ok(proof_core::checkpoint_accumulator_historical_digest_from_pairs(&pairs))
}

pub fn local_available_archive_epochs(
    db: &Store,
    ledger: &NullifierRootLedger,
) -> Result<BTreeSet<u64>> {
    let mut epochs = BTreeSet::new();
    for epoch in ledger.roots.keys() {
        if db.load_shielded_nullifier_epoch(*epoch)?.is_some() {
            epochs.insert(*epoch);
        }
    }
    Ok(epochs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{Validator, ValidatorKeys},
        crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki},
        staking::{ValidatorMetadata, ValidatorPool, ValidatorStatus},
    };

    fn registration_action() -> SharedStateAction {
        let hot_key = ml_dsa_65_generate().unwrap();
        let cold_key = ml_dsa_65_generate().unwrap();
        let pool = ValidatorPool::new(
            Validator::new(
                9,
                ValidatorKeys {
                    hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key).unwrap(),
                    cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                },
            )
            .unwrap(),
            [7u8; 32],
            250,
            9,
            3,
            ValidatorStatus::PendingActivation,
            ValidatorMetadata {
                display_name: "validator".to_string(),
                website: Some("https://validator.example".to_string()),
                description: Some("canonical validator".to_string()),
            },
        )
        .unwrap();
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool })
    }

    fn shielded_output(seed: u8) -> ShieldedOutput {
        ShieldedOutput {
            note_commitment: [seed; 32],
            kem_ct: [seed.wrapping_add(1); crate::crypto::ML_KEM_768_CT_BYTES],
            nonce: [seed.wrapping_add(2); SHIELDED_OUTPUT_NONCE_LEN],
            view_tag: seed.wrapping_add(3),
            ciphertext: vec![seed.wrapping_add(4), seed.wrapping_add(5)],
        }
    }

    fn ordinary_tx(nullifier_seed: u8, output_seed: u8, proof_seed: u8) -> Tx {
        Tx::new(
            vec![[nullifier_seed; 32]],
            vec![shielded_output(output_seed)],
            vec![proof_seed],
        )
    }

    #[test]
    fn ordinary_private_transfers_default_to_fast_path_class() {
        let tx = Tx::new(vec![[1u8; 32]], Vec::new(), vec![7u8; 4]);
        assert_eq!(tx.class(), TransactionClass::OrdinaryPrivateTransfer);
        assert!(tx.is_fast_path_eligible());
    }

    #[test]
    fn shared_state_operations_are_not_fast_path_eligible() {
        let tx = Tx::new_shared_state(registration_action(), vec![9u8; 4]);
        assert_eq!(tx.class(), TransactionClass::SharedState);
        assert!(!tx.is_fast_path_eligible());
    }

    #[test]
    fn ordinary_transaction_round_trips_through_canonical_encoding() {
        let tx = Tx::new(vec![[3u8; 32]], Vec::new(), vec![1, 2, 3, 4]);
        let encoded = crate::canonical::encode_tx(&tx).unwrap();
        let decoded = crate::canonical::decode_tx(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn shared_state_transaction_round_trips_through_canonical_encoding() {
        let tx = Tx::new_shared_state(registration_action(), vec![1, 2, 3, 4]);
        let encoded = crate::canonical::encode_tx(&tx).unwrap();
        let decoded = crate::canonical::decode_tx(&encoded).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn private_delegation_exposes_embedded_shielded_transfer() {
        let transfer = OrdinaryPrivateTransfer {
            nullifiers: vec![[3u8; 32]],
            outputs: vec![ShieldedOutput {
                note_commitment: [7u8; 32],
                kem_ct: [9u8; crate::crypto::ML_KEM_768_CT_BYTES],
                nonce: [5u8; SHIELDED_OUTPUT_NONCE_LEN],
                view_tag: 11,
                ciphertext: vec![1, 2, 3],
            }],
            proof: vec![4, 5, 6],
        };
        let tx = Tx::new_shared_state(
            SharedStateAction::PrivateDelegation(PrivateDelegation {
                validator_id: ValidatorId([8u8; 32]),
                transfer: transfer.clone(),
            }),
            Vec::new(),
        );

        assert_eq!(tx.nullifiers(), transfer.nullifiers.as_slice());
        assert_eq!(tx.outputs(), transfer.outputs.as_slice());
        assert_eq!(tx.proof(), Some(transfer.proof.as_slice()));
        assert_eq!(tx.input_count(), 1);
        assert_eq!(tx.output_count(), 1);
    }

    #[test]
    fn fast_path_batch_rejects_shared_state_transactions() {
        let err = FastPathBatch::new(vec![Tx::new_shared_state(
            registration_action(),
            vec![9u8; 4],
        )])
        .expect_err("shared-state tx must not be accepted into fast path");
        assert!(err
            .to_string()
            .contains("fast-path batches may only carry ordinary private transfers"));
    }

    #[test]
    fn fast_path_batch_rejects_duplicate_nullifiers() {
        let tx_a = ordinary_tx(3, 7, 11);
        let tx_b = ordinary_tx(3, 8, 12);
        let batch = FastPathBatch::new(vec![tx_a, tx_b]).expect("construct fast-path batch");
        let err = batch
            .validate()
            .expect_err("duplicate nullifiers must not survive fast-path selection");
        assert!(err
            .to_string()
            .contains("fast-path batch contains duplicate nullifiers"));
    }

    #[test]
    fn shared_state_dag_aggregation_filters_contended_ordinary_transfers() {
        let ordinary_a = ordinary_tx(4, 20, 30);
        let ordinary_b = ordinary_tx(4, 21, 31);
        let shared = Tx::new_shared_state(registration_action(), vec![12u8; 4]);

        let dag_a = SharedStateDagBatch::new(
            0,
            1,
            ValidatorId([1u8; 32]),
            Vec::new(),
            SharedStateBatch::new(vec![ordinary_a.clone()]).expect("dag batch A"),
        )
        .expect("round-1 DAG batch A");
        let dag_b = SharedStateDagBatch::new(
            0,
            1,
            ValidatorId([2u8; 32]),
            Vec::new(),
            SharedStateBatch::new(vec![ordinary_b, shared.clone()]).expect("dag batch B"),
        )
        .expect("round-1 DAG batch B");

        let aggregate =
            SharedStateBatch::from_dag_batches(&[dag_a, dag_b]).expect("aggregate DAG batches");
        let aggregate_ids = aggregate.tx_ids().expect("aggregate tx ids");
        assert_eq!(aggregate_ids.len(), 2);
        assert_eq!(aggregate_ids[0], ordinary_a.id().expect("ordinary tx id"));
        assert_eq!(aggregate_ids[1], shared.id().expect("shared-state tx id"));
    }
}
