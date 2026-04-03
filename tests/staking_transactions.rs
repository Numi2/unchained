mod finality_support;

use anyhow::Result;
use tempfile::TempDir;
use unchained::{
    consensus::{Validator, ValidatorKeys},
    crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    staking::{
        expected_validator_set_for_epoch, ValidatorMetadata, ValidatorPool, ValidatorProfileUpdate,
        ValidatorRegistration, ValidatorStatus,
    },
    transaction::{SharedStateAction, Tx},
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

fn signed_shared_state_tx(
    store: &Store,
    action: SharedStateAction,
    cold_key: &aws_lc_rs::unstable::signature::PqdsaKeyPair,
) -> Tx {
    let signable = Tx::shared_state_signing_bytes(store.effective_chain_id(), &action)
        .expect("encode shared-state signing message");
    let signature = ml_dsa_65_sign(cold_key, &signable).expect("sign shared-state action");
    Tx::new_shared_state(action, signature)
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

#[test]
fn validator_registration_transaction_updates_pools_and_future_committee() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let (pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;

    let action = SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() });
    let tx = signed_shared_state_tx(&store, action, &cold_key);
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
fn validator_profile_update_requires_cold_governance_signature() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let (pool, cold_key) = build_pending_validator_pool(5, genesis.position.epoch + 1)?;
    let registration = signed_shared_state_tx(
        &store,
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() }),
        &cold_key,
    );
    registration.apply(&store)?;

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
    let invalid_tx = signed_shared_state_tx(&store, update.clone(), &wrong_key);
    assert!(invalid_tx.apply(&store).is_err());

    let valid_tx = signed_shared_state_tx(&store, update, &cold_key);
    valid_tx.apply(&store)?;
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
