use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::signature::UnparsedPublicKey;
use aws_lc_rs::unstable::signature::ML_DSA_65;
use methods::CHECKPOINT_ACCUMULATOR_METHOD_ID;
use proof_core::{ProofShieldedInputBinding, ProofShieldedOutputBinding};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::{BTreeSet, HashSet};

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
    staking::{ValidatorProfileUpdate, ValidatorRegistration},
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
pub enum SharedStateAction {
    RegisterValidator(ValidatorRegistration),
    UpdateValidatorProfile(ValidatorProfileUpdate),
    PrivateDelegation(PrivateDelegation),
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

    pub fn shared_state(&self) -> Option<&SharedStateTx> {
        match self {
            Self::OrdinaryPrivateTransfer(_) => None,
            Self::SharedState(shared) => Some(shared),
        }
    }

    pub fn nullifiers(&self) -> &[[u8; 32]] {
        self.ordinary_transfer()
            .map(|transfer| transfer.nullifiers.as_slice())
            .unwrap_or(&[])
    }

    pub fn outputs(&self) -> &[ShieldedOutput] {
        self.ordinary_transfer()
            .map(|transfer| transfer.outputs.as_slice())
            .unwrap_or(&[])
    }

    pub fn proof(&self) -> Option<&[u8]> {
        self.ordinary_transfer()
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
        if matches!(action, SharedStateAction::PrivateDelegation(_)) {
            bail!("private delegation is authorized by its delegation proof, not a governance signature");
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
        match self {
            Self::OrdinaryPrivateTransfer(transfer) => self.validate_shielded(transfer, db),
            Self::SharedState(shared) => self.validate_shared_state(shared, db),
        }
    }

    pub fn apply(&self, db: &Store) -> Result<[u8; 32]> {
        match self {
            Self::OrdinaryPrivateTransfer(transfer) => self.apply_shielded(transfer, db),
            Self::SharedState(shared) => self.apply_shared_state(shared, db),
        }
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
                if db
                    .load_delegation_share(&journal.delegated_note_commitment)?
                    .is_some()
                {
                    bail!("delegation note commitment already exists in delegation state");
                }
                let _ = pool.mint_delegation(
                    journal.delegated_value,
                    current_epoch,
                    journal.delegated_note_commitment,
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
                let (updated_pool, delegation_record) = pool.mint_delegation(
                    journal.delegated_value,
                    journal.current_epoch,
                    journal.delegated_note_commitment,
                )?;
                append_shielded_transfer_to_batch(db, &mut batch, &tx_id, &delegation.transfer)?;
                batch.put_cf(
                    validator_pool_cf,
                    &updated_pool.validator.id.0,
                    bincode::serialize(&updated_pool)
                        .context("serialize delegated validator pool")?,
                );
                let delegation_cf = db
                    .db
                    .cf_handle("delegation_share")
                    .ok_or_else(|| anyhow!("'delegation_share' column family missing"))?;
                batch.put_cf(
                    delegation_cf,
                    &delegation_record.note_commitment,
                    bincode::serialize(&delegation_record)
                        .context("serialize delegation share record")?,
                );
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

    for nullifier in &transfer.nullifiers {
        active.insert(*nullifier)?;
    }

    for (index, output) in transfer.outputs.iter().enumerate() {
        tree.append(output.note_commitment)?;
        let mut output_key = Vec::with_capacity(36);
        output_key.extend_from_slice(tx_id);
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
    Ok(())
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
}
