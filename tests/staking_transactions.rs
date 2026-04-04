mod finality_support;

use anyhow::Result;
use aws_lc_rs::{signature::UnparsedPublicKey, unstable::signature::ML_DSA_65};
use rocksdb::WriteBatch;
use std::sync::Arc;
use tempfile::TempDir;
use unchained::{
    consensus::{
        ConsensusPosition, OrderingPath, QuorumCertificate, Validator, ValidatorKeys, ValidatorSet,
        ValidatorVote, VoteTarget,
    },
    crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    evidence::{self, ConsensusEvidence, SlashableEvidence, VoteEquivocationEvidence},
    protocol::CURRENT as PROTOCOL,
    staking::{
        expected_validator_set_for_epoch, load_or_compute_active_validator_set, PenaltyCause,
        PenaltyFaultClass, PenaltyPolicy, ValidatorAccountability, ValidatorMetadata,
        ValidatorPenaltyEvent, ValidatorPool, ValidatorProfileUpdate, ValidatorReactivation,
        ValidatorRegistration, ValidatorStatus,
    },
    storage::WalletStore,
    transaction::{PenaltyEvidenceAdmission, SharedStateAction, Tx},
    wallet::Wallet,
    Store,
};

fn seed_genesis(store: &Store, committee: &finality_support::TestCommittee) -> Result<Anchor> {
    let genesis = committee.genesis_anchor();
    committee.seed_validator_state(store, genesis.position.epoch)?;
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
}

fn build_active_validator_pool(
    voting_power: u64,
    activation_epoch: u64,
    node_id: [u8; 32],
) -> Result<(
    ValidatorPool,
    aws_lc_rs::unstable::signature::PqdsaKeyPair,
    aws_lc_rs::unstable::signature::PqdsaKeyPair,
)> {
    let hot_key = ml_dsa_65_generate()?;
    let cold_key = ml_dsa_65_generate()?;
    let validator = Validator::new(
        voting_power,
        ValidatorKeys {
            hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key)?,
            cold_governance_key: ml_dsa_65_public_key_spki(&cold_key)?,
        },
    )?;
    let pool = ValidatorPool::new(
        validator,
        node_id,
        0,
        voting_power,
        activation_epoch,
        ValidatorStatus::Active,
        ValidatorMetadata {
            display_name: format!("validator-{}", hex::encode(&node_id[..4])),
            website: None,
            description: Some("accountability test validator".to_string()),
        },
    )?;
    Ok((pool, hot_key, cold_key))
}

fn signed_shared_state_tx(
    store: &Store,
    wallet: &Wallet,
    action: SharedStateAction,
    cold_key: &aws_lc_rs::unstable::signature::PqdsaKeyPair,
) -> Result<Tx> {
    let signable = Tx::shared_state_signing_bytes(store.effective_chain_id(), &action)
        .expect("encode shared-state signing message");
    let signature = ml_dsa_65_sign(cold_key, &signable).expect("sign shared-state action");
    finality_support::fee_paid_shared_state_tx(store, wallet, action, signature)
}

fn sign_shared_state_action(
    store: &Store,
    action: &SharedStateAction,
    cold_key: &aws_lc_rs::unstable::signature::PqdsaKeyPair,
) -> Result<Vec<u8>> {
    let signable = Tx::shared_state_signing_bytes(store.effective_chain_id(), action)
        .expect("encode shared-state signing message");
    Ok(ml_dsa_65_sign(cold_key, &signable).expect("sign shared-state action"))
}

fn penalty_policy_for_evidence(evidence: &SlashableEvidence) -> (PenaltyFaultClass, PenaltyPolicy) {
    match evidence {
        SlashableEvidence::Consensus(_) => (
            PenaltyFaultClass::Safety,
            PenaltyPolicy {
                slash_bps: PROTOCOL.equivocation_slash_bps,
                jail_after_faults: 1,
                jail_epochs: PROTOCOL.equivocation_jail_epochs,
                retire_after_faults: PROTOCOL.equivocation_retirement_faults,
            },
        ),
        SlashableEvidence::Liveness(_) => (
            PenaltyFaultClass::Liveness,
            PenaltyPolicy {
                slash_bps: PROTOCOL.liveness_fault_slash_bps,
                jail_after_faults: PROTOCOL.liveness_fault_jail_threshold,
                jail_epochs: PROTOCOL.liveness_fault_jail_epochs,
                retire_after_faults: PROTOCOL.liveness_fault_retirement_faults,
            },
        ),
    }
}

fn penalty_cause_for_evidence(evidence: &SlashableEvidence) -> PenaltyCause {
    match evidence {
        SlashableEvidence::Consensus(consensus) => match consensus {
            ConsensusEvidence::ProposalEquivocation(proposal) => {
                PenaltyCause::ProposalEquivocation {
                    position: proposal.position,
                }
            }
            ConsensusEvidence::VoteEquivocation(vote) => PenaltyCause::VoteEquivocation {
                position: vote.position,
            },
            ConsensusEvidence::DagBatchEquivocation(batch) => PenaltyCause::DagBatchEquivocation {
                epoch: batch.epoch,
                round: batch.round,
            },
        },
        SlashableEvidence::Liveness(fault) => PenaltyCause::MissedConsensusVote {
            position: fault.position,
            anchor_hash: fault.anchor_hash,
        },
    }
}

fn apply_control_action_without_fee(
    store: &Store,
    action: SharedStateAction,
    authorization_signature: Vec<u8>,
) -> Result<()> {
    let chain_id = store.effective_chain_id();
    let current_epoch = store
        .get::<Anchor>("epoch", b"latest")?
        .map(|anchor| anchor.position.epoch)
        .unwrap_or(0);
    let mut committee_state_changed = false;

    match &action {
        SharedStateAction::RegisterValidator(registration) => {
            let signable = Tx::shared_state_signing_bytes(
                chain_id,
                &SharedStateAction::RegisterValidator(registration.clone()),
            )?;
            registration.validate()?;
            UnparsedPublicKey::new(
                &ML_DSA_65,
                &registration.pool.validator.keys.cold_governance_key,
            )
            .verify(&signable, &authorization_signature)
            .map_err(|_| {
                anyhow::anyhow!("shared-state authorization signature verification failed")
            })?;
            if registration.pool.activation_epoch <= current_epoch {
                anyhow::bail!(
                    "validator registrations must activate in a future epoch; current epoch is {}",
                    current_epoch
                );
            }
            if store
                .load_validator_pool(&registration.pool.validator_id())?
                .is_some()
            {
                anyhow::bail!("validator pool already exists");
            }
            for existing in store.load_validator_pools()? {
                if existing.node_id == registration.pool.node_id {
                    anyhow::bail!("validator node id is already registered");
                }
            }
            committee_state_changed = true;
            store.store_validator_pool(&registration.pool)?;
        }
        SharedStateAction::UpdateValidatorProfile(update) => {
            let signable = Tx::shared_state_signing_bytes(
                chain_id,
                &SharedStateAction::UpdateValidatorProfile(update.clone()),
            )?;
            update.validate()?;
            let existing = store
                .load_validator_pool(&update.validator_id)?
                .ok_or_else(|| anyhow::anyhow!("validator pool not found"))?;
            existing.validate()?;
            UnparsedPublicKey::new(&ML_DSA_65, &existing.validator.keys.cold_governance_key)
                .verify(&signable, &authorization_signature)
                .map_err(|_| {
                    anyhow::anyhow!("shared-state authorization signature verification failed")
                })?;
            store.store_validator_pool(&update.apply_to(&existing)?)?;
        }
        SharedStateAction::AdmitPenaltyEvidence(admission) => {
            if !authorization_signature.is_empty() {
                anyhow::bail!(
                    "penalty evidence admission is authorized by deterministic evidence, not an external governance signature"
                );
            }
            admission.evidence.validate(store)?;
            let evidence_id = admission.evidence.evidence_id()?;
            if store.load_validator_penalty_event(&evidence_id)?.is_some() {
                anyhow::bail!("validator penalty for this evidence is already finalized");
            }
            let pool = store
                .load_validator_pool(&admission.evidence.validator_id())?
                .ok_or_else(|| anyhow::anyhow!("validator pool not found"))?;
            let (fault_class, policy) = penalty_policy_for_evidence(&admission.evidence);
            let application = pool.apply_penalty(fault_class, current_epoch, policy)?;
            let event = ValidatorPenaltyEvent {
                evidence_id,
                validator_id: pool.validator_id(),
                cause: penalty_cause_for_evidence(&admission.evidence),
                slash_bps: policy.slash_bps,
                slashed_amount: application.slashed_amount,
                bonded_stake_before: pool.total_bonded_stake,
                bonded_stake_after: application.updated_pool.total_bonded_stake,
                applied_in_epoch: current_epoch,
                resulting_status: application.updated_pool.status,
                resulting_activation_epoch: application.updated_pool.activation_epoch,
                resulting_accountability: application.updated_pool.accountability.clone(),
            };
            event.validate()?;
            committee_state_changed = true;
            store.store_validator_pool(&application.updated_pool)?;
            store.store_validator_penalty_event(&event)?;
        }
        SharedStateAction::ReactivateValidator(reactivation) => {
            let signable = Tx::shared_state_signing_bytes(
                chain_id,
                &SharedStateAction::ReactivateValidator(reactivation.clone()),
            )?;
            reactivation.validate()?;
            let existing = store
                .load_validator_pool(&reactivation.validator_id)?
                .ok_or_else(|| anyhow::anyhow!("validator pool not found"))?;
            existing.validate()?;
            UnparsedPublicKey::new(&ML_DSA_65, &existing.validator.keys.cold_governance_key)
                .verify(&signable, &authorization_signature)
                .map_err(|_| {
                    anyhow::anyhow!("shared-state authorization signature verification failed")
                })?;
            committee_state_changed = true;
            store.store_validator_pool(&existing.request_reactivation(current_epoch)?)?;
        }
        SharedStateAction::PrivateDelegation(_)
        | SharedStateAction::PrivateUndelegation(_)
        | SharedStateAction::ClaimUnbonding(_) => {
            anyhow::bail!("test helper only supports fee-less control actions");
        }
    }

    if committee_state_changed {
        let mut batch = WriteBatch::default();
        store.invalidate_future_validator_committees(&mut batch, current_epoch)?;
        store.db.write(batch)?;
    }
    Ok(())
}

fn build_single_action_fee_wallet(
    dir: &TempDir,
    store: &Store,
    genesis: &Anchor,
) -> Result<Wallet> {
    std::env::set_var("WALLET_PASSPHRASE", "staking-transactions-passphrase");
    std::env::set_var(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        finality_support::proof_fixture_dir(),
    );
    let wallet_store = Arc::new(WalletStore::open(&dir.path().to_string_lossy())?);
    let wallet = finality_support::deterministic_wallet(wallet_store)?;
    let _ = finality_support::seed_wallet_with_coin_values(store, &wallet, genesis, &[2])?;
    Ok(wallet)
}

fn build_pending_validator_pool(
    voting_power: u64,
    activation_epoch: u64,
) -> Result<(ValidatorPool, aws_lc_rs::unstable::signature::PqdsaKeyPair)> {
    let hot_key = ml_dsa_65_generate()?;
    let cold_key = ml_dsa_65_generate()?;
    let validator = Validator::new(
        voting_power,
        ValidatorKeys {
            hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key)?,
            cold_governance_key: ml_dsa_65_public_key_spki(&cold_key)?,
        },
    )?;
    let pool = ValidatorPool::new(
        validator,
        [9u8; 32],
        175,
        voting_power,
        activation_epoch,
        ValidatorStatus::PendingActivation,
        ValidatorMetadata {
            display_name: "new validator".to_string(),
            website: Some("https://validator.example".to_string()),
            description: Some("canonical pending validator".to_string()),
        },
    )?;
    Ok((pool, cold_key))
}

fn store_pool_with_share_supply(
    store: &Store,
    pool: &ValidatorPool,
    total_delegation_shares: u128,
) -> Result<ValidatorPool> {
    let mut updated = pool.clone();
    updated.total_delegation_shares = total_delegation_shares;
    updated.validate()?;
    store.store_validator_pool(&updated)?;
    Ok(updated)
}

fn epoch_anchor_num(epoch: u64) -> u64 {
    epoch * (PROTOCOL.slots_per_epoch as u64)
}

fn store_latest_anchor(store: &Store, anchor: &Anchor) -> Result<()> {
    store.store_validator_committee(&anchor.validator_set)?;
    store.put("epoch", &anchor.num.to_le_bytes(), anchor)?;
    store.put("epoch", b"latest", anchor)?;
    store.put("anchor", &anchor.hash, anchor)?;
    Ok(())
}

fn finalized_fast_path_anchor(
    num: u64,
    validator_set: &ValidatorSet,
    signers: Vec<(
        unchained::consensus::ValidatorId,
        &aws_lc_rs::unstable::signature::PqdsaKeyPair,
    )>,
) -> Result<Anchor> {
    let position = Anchor::position_for_num(num);
    let parent_hash = if num == 0 {
        None
    } else {
        Some([num as u8; 32])
    };
    let target = VoteTarget {
        position,
        ordering_path: OrderingPath::FastPathPrivateTransfer,
        block_digest: Anchor::compute_hash(
            num,
            parent_hash,
            position,
            OrderingPath::FastPathPrivateTransfer,
            [num as u8; 32],
            0,
            0,
            &[],
            &[],
            [0u8; 32],
            0,
            validator_set,
        ),
    };
    let target_bytes = target.signing_bytes();
    let qc = QuorumCertificate::from_votes(
        validator_set,
        target.clone(),
        signers
            .into_iter()
            .map(|(validator_id, hot_key)| ValidatorVote {
                voter: validator_id,
                target: target.clone(),
                signature: ml_dsa_65_sign(hot_key, &target_bytes).expect("sign anchor vote"),
            })
            .collect(),
    )?;
    Ok(Anchor::new(
        num,
        parent_hash,
        OrderingPath::FastPathPrivateTransfer,
        [num as u8; 32],
        0,
        0,
        Vec::new(),
        Vec::new(),
        [0u8; 32],
        0,
        validator_set.clone(),
        qc,
    )?)
}

#[test]
fn validator_registration_transaction_updates_pools_and_future_committee() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let wallet = build_single_action_fee_wallet(&dir, &store, &genesis)?;
    let (pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;

    let action = SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() });
    let tx = signed_shared_state_tx(&store, &wallet, action, &cold_key)?;
    let tx_id = tx.apply(&store)?;

    assert!(store.get_raw_bytes("tx", &tx_id)?.is_some());
    assert_eq!(
        store.load_validator_pool(&pool.validator.id)?.as_ref(),
        Some(&pool)
    );

    let next_epoch = genesis.position.epoch + 1;
    let next_committee =
        expected_validator_set_for_epoch(&store, next_epoch)?.expect("next epoch committee");
    assert!(next_committee.validator(&pool.validator.id).is_some());
    assert_eq!(
        store
            .load_validator_committee(genesis.position.epoch)?
            .unwrap()
            .epoch,
        0
    );

    store.close()?;
    Ok(())
}

#[test]
fn validator_profile_update_transaction_applies_from_fresh_fee_paid_control_submission(
) -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let wallet = build_single_action_fee_wallet(&dir, &store, &genesis)?;
    let (pool, cold_key) = build_pending_validator_pool(5, genesis.position.epoch + 1)?;
    store.store_validator_pool(&pool)?;

    let update = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: pool.validator.id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "updated validator".to_string(),
            website: Some("https://updated.example".to_string()),
            description: Some("updated canonical profile".to_string()),
        },
    });
    let tx = signed_shared_state_tx(&store, &wallet, update, &cold_key)?;
    tx.apply(&store)?;

    let stored = store
        .load_validator_pool(&pool.validator.id)?
        .expect("updated validator pool");
    assert_eq!(stored.commission_bps, 325);
    assert_eq!(stored.metadata.display_name, "updated validator");
    assert_eq!(
        stored.metadata.website.as_deref(),
        Some("https://updated.example")
    );

    store.close()?;
    Ok(())
}

#[test]
fn validator_profile_update_requires_cold_governance_signature() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let (pool, cold_key) = build_pending_validator_pool(5, genesis.position.epoch + 1)?;
    store.store_validator_pool(&pool)?;

    let update = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: pool.validator.id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "updated validator".to_string(),
            website: Some("https://updated.example".to_string()),
            description: Some("updated canonical profile".to_string()),
        },
    });

    let wrong_key = ml_dsa_65_generate()?;
    let invalid_signature = sign_shared_state_action(&store, &update, &wrong_key)?;
    assert!(apply_control_action_without_fee(&store, update.clone(), invalid_signature).is_err());

    let valid_signature = sign_shared_state_action(&store, &update, &cold_key)?;
    apply_control_action_without_fee(&store, update, valid_signature)?;
    let stored = store
        .load_validator_pool(&pool.validator.id)?
        .expect("updated validator pool");
    assert_eq!(stored.commission_bps, 325);
    assert_eq!(stored.metadata.display_name, "updated validator");
    assert_eq!(
        stored.metadata.website.as_deref(),
        Some("https://updated.example")
    );

    store.close()?;
    Ok(())
}

#[test]
fn liveness_fault_admission_slashes_pool_without_changing_share_ownership() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;

    let (pool_a, hot_a, _) = build_active_validator_pool(101, 0, [0x11; 32])?;
    let (pool_b, hot_b, _) = build_active_validator_pool(101, 0, [0x22; 32])?;
    let (pool_c, _hot_c, _) = build_active_validator_pool(100, 0, [0x33; 32])?;
    let slashed_pool = store_pool_with_share_supply(&store, &pool_c, 250)?;
    store.store_validator_pool(&pool_a)?;
    store.store_validator_pool(&pool_b)?;

    let validator_set = ValidatorSet::new(
        0,
        vec![
            pool_a.validator.clone(),
            pool_b.validator.clone(),
            slashed_pool.validator.clone(),
        ],
    )?;
    store.store_validator_committee(&validator_set)?;

    let position = Anchor::position_for_num(0);
    let target = VoteTarget {
        position,
        ordering_path: OrderingPath::FastPathPrivateTransfer,
        block_digest: Anchor::compute_hash(
            0,
            None,
            position,
            OrderingPath::FastPathPrivateTransfer,
            [0u8; 32],
            0,
            0,
            &[],
            &[],
            [0u8; 32],
            0,
            &validator_set,
        ),
    };
    let target_bytes = target.signing_bytes();
    let qc = QuorumCertificate::from_votes(
        &validator_set,
        target.clone(),
        vec![
            ValidatorVote {
                voter: pool_a.validator.id,
                target: target.clone(),
                signature: ml_dsa_65_sign(&hot_a, &target_bytes)?,
            },
            ValidatorVote {
                voter: pool_b.validator.id,
                target: target.clone(),
                signature: ml_dsa_65_sign(&hot_b, &target_bytes)?,
            },
        ],
    )?;
    let anchor = Anchor::new(
        0,
        None,
        OrderingPath::FastPathPrivateTransfer,
        [0u8; 32],
        0,
        0,
        Vec::new(),
        Vec::new(),
        [0u8; 32],
        0,
        validator_set.clone(),
        qc,
    )?;
    store.put("epoch", &0u64.to_le_bytes(), &anchor)?;
    store.put("epoch", b"latest", &anchor)?;
    store.put("anchor", &anchor.hash, &anchor)?;

    let liveness_records = evidence::record_anchor_liveness_faults(&store, &anchor)?;
    assert_eq!(liveness_records.len(), 1);
    assert_eq!(
        liveness_records[0].validator_id(),
        slashed_pool.validator.id
    );

    apply_control_action_without_fee(
        &store,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: SlashableEvidence::Liveness(liveness_records[0].fault.clone()),
        }),
        Vec::new(),
    )?;

    let event = store
        .load_validator_penalty_event(&liveness_records[0].evidence_id)?
        .expect("stored validator penalty event");
    let updated_pool = store
        .load_validator_pool(&slashed_pool.validator.id)?
        .expect("slashed validator pool");

    assert_eq!(event.validator_id, slashed_pool.validator.id);
    assert_eq!(event.slash_bps, PROTOCOL.liveness_fault_slash_bps);
    assert_eq!(event.bonded_stake_before, slashed_pool.total_bonded_stake);
    assert_eq!(
        event.bonded_stake_after,
        slashed_pool.total_bonded_stake - 1
    );
    assert_eq!(event.resulting_status, ValidatorStatus::Active);
    assert_eq!(
        event.resulting_activation_epoch,
        slashed_pool.activation_epoch
    );
    assert_eq!(event.resulting_accountability.liveness_faults, 1);
    assert_eq!(event.resulting_accountability.safety_faults, 0);
    assert_eq!(event.resulting_accountability.jailed_until_epoch, None);
    assert_eq!(
        updated_pool.total_delegation_shares,
        slashed_pool.total_delegation_shares
    );
    assert_eq!(updated_pool.status, ValidatorStatus::Active);
    assert_eq!(updated_pool.accountability.liveness_faults, 1);
    assert_eq!(updated_pool.accountability.jailed_until_epoch, None);
    assert_eq!(
        store.load_liveness_fault_record(&liveness_records[0].evidence_id)?,
        Some(liveness_records[0].clone())
    );

    store.close()?;
    Ok(())
}

#[test]
fn validator_reactivation_transaction_applies_from_fresh_fee_paid_control_submission() -> Result<()>
{
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let wallet = build_single_action_fee_wallet(&dir, &store, &genesis)?;
    let (pool, _hot_key, cold_key) =
        build_active_validator_pool(9, genesis.position.epoch, [0x44; 32])?;
    let jailed_pool = ValidatorPool {
        status: ValidatorStatus::Jailed,
        accountability: ValidatorAccountability {
            liveness_faults: PROTOCOL.liveness_fault_jail_threshold,
            safety_faults: 0,
            jailed_until_epoch: Some(genesis.position.epoch),
        },
        ..pool
    };
    jailed_pool.validate()?;
    store.store_validator_pool(&jailed_pool)?;

    let tx = signed_shared_state_tx(
        &store,
        &wallet,
        SharedStateAction::ReactivateValidator(ValidatorReactivation {
            validator_id: jailed_pool.validator.id,
        }),
        &cold_key,
    )?;
    tx.apply(&store)?;

    let reactivated = store
        .load_validator_pool(&jailed_pool.validator.id)?
        .expect("reactivated validator pool");
    assert_eq!(reactivated.status, ValidatorStatus::PendingActivation);
    assert_eq!(reactivated.activation_epoch, genesis.position.epoch + 1);
    assert_eq!(
        reactivated.accountability.liveness_faults,
        jailed_pool.accountability.liveness_faults
    );
    assert_eq!(reactivated.accountability.jailed_until_epoch, None);

    store.close()?;
    Ok(())
}

#[test]
fn repeated_liveness_faults_jail_then_reactivate_future_committee() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;

    let (pool_a, hot_a, _) = build_active_validator_pool(101, 0, [0x11; 32])?;
    let (pool_b, hot_b, _) = build_active_validator_pool(101, 0, [0x22; 32])?;
    let (pool_c, _hot_c, cold_c) = build_active_validator_pool(100, 0, [0x33; 32])?;
    let mut pool_c = store_pool_with_share_supply(&store, &pool_c, 250)?;
    store.store_validator_pool(&pool_a)?;
    store.store_validator_pool(&pool_b)?;
    let _genesis_anchor = finalized_fast_path_anchor(
        epoch_anchor_num(0),
        &ValidatorSet::new(
            0,
            vec![
                pool_a.validator.clone(),
                pool_b.validator.clone(),
                pool_c.validator.clone(),
            ],
        )?,
        vec![(pool_a.validator.id, &hot_a), (pool_b.validator.id, &hot_b)],
    )?;

    for epoch in 0..=2 {
        let validator_set = ValidatorSet::new(
            epoch,
            vec![
                pool_a.validator.clone(),
                pool_b.validator.clone(),
                pool_c.validator.clone(),
            ],
        )?;
        let anchor = finalized_fast_path_anchor(
            epoch_anchor_num(epoch),
            &validator_set,
            vec![(pool_a.validator.id, &hot_a), (pool_b.validator.id, &hot_b)],
        )?;
        store_latest_anchor(&store, &anchor)?;
        let fault = evidence::record_anchor_liveness_faults(&store, &anchor)?
            .into_iter()
            .find(|record| record.validator_id() == pool_c.validator.id)
            .expect("liveness fault for validator C");
        if epoch == 2 {
            let cached_epoch3 = load_or_compute_active_validator_set(&store, 3)?;
            assert!(cached_epoch3.validator(&pool_c.validator.id).is_some());
            store.store_validator_committee(&cached_epoch3)?;
        }
        apply_control_action_without_fee(
            &store,
            SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
                evidence: SlashableEvidence::Liveness(fault.fault.clone()),
            }),
            Vec::new(),
        )?;
        pool_c = store
            .load_validator_pool(&pool_c.validator.id)?
            .expect("validator pool after liveness penalty");
    }

    assert_eq!(pool_c.status, ValidatorStatus::Jailed);
    assert_eq!(pool_c.accountability.liveness_faults, 3);
    assert_eq!(
        pool_c.accountability.jailed_until_epoch,
        Some(2 + PROTOCOL.liveness_fault_jail_epochs)
    );
    assert!(store.load_validator_committee(3)?.is_none());
    let epoch3 = expected_validator_set_for_epoch(&store, 3)?.expect("epoch 3 committee");
    assert!(epoch3.validator(&pool_c.validator.id).is_none());

    let cached_epoch5 = load_or_compute_active_validator_set(&store, 5)?;
    assert!(cached_epoch5.validator(&pool_c.validator.id).is_none());
    store.store_validator_committee(&cached_epoch5)?;
    let anchor4 = finalized_fast_path_anchor(
        epoch_anchor_num(4),
        &ValidatorSet::new(4, vec![pool_a.validator.clone(), pool_b.validator.clone()])?,
        vec![(pool_a.validator.id, &hot_a), (pool_b.validator.id, &hot_b)],
    )?;
    store_latest_anchor(&store, &anchor4)?;

    let reactivation_action = SharedStateAction::ReactivateValidator(ValidatorReactivation {
        validator_id: pool_c.validator.id,
    });
    let reactivation_signature = sign_shared_state_action(&store, &reactivation_action, &cold_c)?;
    apply_control_action_without_fee(&store, reactivation_action, reactivation_signature)?;

    pool_c = store
        .load_validator_pool(&pool_c.validator.id)?
        .expect("reactivated validator pool");
    assert_eq!(pool_c.status, ValidatorStatus::PendingActivation);
    assert_eq!(pool_c.activation_epoch, 5);
    assert_eq!(pool_c.accountability.liveness_faults, 3);
    assert_eq!(pool_c.accountability.jailed_until_epoch, None);
    assert!(store.load_validator_committee(5)?.is_none());
    let epoch5 = expected_validator_set_for_epoch(&store, 5)?.expect("epoch 5 committee");
    assert!(epoch5.validator(&pool_c.validator.id).is_some());

    store.close()?;
    Ok(())
}

#[test]
fn repeated_safety_faults_retire_validator_permanently() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;

    let (pool_a, hot_a, _) = build_active_validator_pool(101, 0, [0x11; 32])?;
    let (pool_b, hot_b, _) = build_active_validator_pool(101, 0, [0x22; 32])?;
    let (pool_c, hot_c, _) = build_active_validator_pool(100, 0, [0x33; 32])?;
    let pool_c = store_pool_with_share_supply(&store, &pool_c, 250)?;
    store.store_validator_pool(&pool_a)?;
    store.store_validator_pool(&pool_b)?;

    let validator_set = ValidatorSet::new(
        0,
        vec![
            pool_a.validator.clone(),
            pool_b.validator.clone(),
            pool_c.validator.clone(),
        ],
    )?;
    let anchor0 = finalized_fast_path_anchor(
        epoch_anchor_num(0),
        &validator_set,
        vec![
            (pool_a.validator.id, &hot_a),
            (pool_b.validator.id, &hot_b),
            (pool_c.validator.id, &hot_c),
        ],
    )?;
    store_latest_anchor(&store, &anchor0)?;
    let cached_epoch1 = load_or_compute_active_validator_set(&store, 1)?;
    assert!(cached_epoch1.validator(&pool_c.validator.id).is_some());
    store.store_validator_committee(&cached_epoch1)?;

    let build_evidence = |slot: u32| -> Result<SlashableEvidence> {
        let first_target = VoteTarget {
            position: ConsensusPosition { epoch: 0, slot },
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: [slot as u8 + 1; 32],
        };
        let second_target = VoteTarget {
            block_digest: [slot as u8 + 2; 32],
            ..first_target.clone()
        };
        Ok(SlashableEvidence::Consensus(
            ConsensusEvidence::VoteEquivocation(VoteEquivocationEvidence::new(
                ValidatorVote {
                    voter: pool_c.validator.id,
                    target: first_target.clone(),
                    signature: ml_dsa_65_sign(&hot_c, &first_target.signing_bytes())?,
                },
                ValidatorVote {
                    voter: pool_c.validator.id,
                    target: second_target.clone(),
                    signature: ml_dsa_65_sign(&hot_c, &second_target.signing_bytes())?,
                },
            )?),
        ))
    };

    let first_evidence = build_evidence(1)?;
    let first_event_id = first_evidence.evidence_id()?;
    apply_control_action_without_fee(
        &store,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: first_evidence,
        }),
        Vec::new(),
    )?;
    let first_penalty = store
        .load_validator_penalty_event(&first_event_id)?
        .expect("first safety penalty");
    let after_first = store
        .load_validator_pool(&pool_c.validator.id)?
        .expect("validator after first safety fault");
    assert_eq!(first_penalty.resulting_status, ValidatorStatus::Jailed);
    assert_eq!(after_first.status, ValidatorStatus::Jailed);
    assert_eq!(after_first.accountability.safety_faults, 1);
    assert_eq!(
        after_first.accountability.jailed_until_epoch,
        Some(PROTOCOL.equivocation_jail_epochs)
    );
    assert!(store.load_validator_committee(1)?.is_none());
    let epoch1 = expected_validator_set_for_epoch(&store, 1)?.expect("epoch 1 committee");
    assert!(epoch1.validator(&pool_c.validator.id).is_none());

    let second_evidence = build_evidence(2)?;
    let second_event_id = second_evidence.evidence_id()?;
    apply_control_action_without_fee(
        &store,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: second_evidence,
        }),
        Vec::new(),
    )?;
    let second_penalty = store
        .load_validator_penalty_event(&second_event_id)?
        .expect("second safety penalty");
    let after_second = store
        .load_validator_pool(&pool_c.validator.id)?
        .expect("validator after second safety fault");
    assert_eq!(second_penalty.resulting_status, ValidatorStatus::Retired);
    assert_eq!(after_second.status, ValidatorStatus::Retired);
    assert_eq!(after_second.accountability.safety_faults, 2);
    assert_eq!(after_second.accountability.jailed_until_epoch, None);

    store.close()?;
    Ok(())
}
