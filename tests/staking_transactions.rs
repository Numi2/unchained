mod finality_support;

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use unchained::{
    config::{Net, P2p},
    consensus::{
        ConsensusPosition, OrderingPath, QuorumCertificate, Validator, ValidatorKeys, ValidatorSet,
        ValidatorVote, VoteTarget,
    },
    crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    evidence::{self, ConsensusEvidence, SlashableEvidence, VoteEquivocationEvidence},
    network, node_identity,
    protocol::CURRENT as PROTOCOL,
    staking::{
        expected_validator_set_for_epoch, load_or_compute_active_validator_set, ValidatorMetadata,
        ValidatorPool, ValidatorProfileUpdate, ValidatorReactivation, ValidatorRegistration,
        ValidatorStatus,
    },
    storage::WalletStore,
    sync::SyncState,
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

fn pick_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind udp socket")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn build_net(port: u16) -> Net {
    Net {
        listen_port: port,
        bootstrap: Vec::new(),
        trust_updates: Vec::new(),
        strict_trust: false,
        peer_exchange: true,
        max_peers: 8,
        connection_timeout_secs: 5,
        public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()),
        sync_timeout_secs: 3,
        banned_peer_ids: Vec::new(),
        quiet_by_default: true,
    }
}

fn build_p2p() -> P2p {
    P2p {
        max_validation_failures_per_peer: 8,
        peer_ban_duration_secs: 60,
        rate_limit_window_secs: 60,
        max_messages_per_window: 10_000,
    }
}

fn provision_runtime_identity(
    tempdir: &TempDir,
    chain_id: [u8; 32],
    address: String,
) -> Result<()> {
    let _ = node_identity::init_root_in_dir(tempdir.path())?;
    let (_, request) = node_identity::prepare_auth_request_in_dir(
        tempdir.path(),
        unchained::protocol::CURRENT.version,
        Some(chain_id),
        vec![address],
        None,
    )?;
    let (_, record) = node_identity::sign_auth_request_in_dir(tempdir.path(), &request, 30)?;
    let _ = node_identity::install_node_record_in_dir(tempdir.path(), &record)?;
    Ok(())
}

async fn spawn_network(db: Arc<Store>, port: u16) -> Result<unchained::network::NetHandle> {
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    network::spawn(build_net(port), build_p2p(), db, sync_state).await
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

fn build_fee_payer_wallet(
    dir: &TempDir,
    store: &Store,
    genesis: &Anchor,
    coin_count: u64,
) -> Result<Wallet> {
    std::env::set_var("WALLET_PASSPHRASE", "staking-transactions-passphrase");
    let wallet_store = Arc::new(WalletStore::open(&dir.path().to_string_lossy())?);
    let wallet = Wallet::load_or_create_private(wallet_store)?;
    let _ = finality_support::seed_wallet_with_coins(store, &wallet, genesis, coin_count)?;
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
    let wallet = build_fee_payer_wallet(&dir, &store, &genesis, 2)?;
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
fn validator_profile_update_requires_cold_governance_signature() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&store, &committee)?;
    let wallet = build_fee_payer_wallet(&dir, &store, &genesis, 4)?;
    let (pool, cold_key) = build_pending_validator_pool(5, genesis.position.epoch + 1)?;
    let registration = signed_shared_state_tx(
        &store,
        &wallet,
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() }),
        &cold_key,
    )?;
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
    let invalid_tx = signed_shared_state_tx(&store, &wallet, update.clone(), &wrong_key)?;
    assert!(invalid_tx.apply(&store).is_err());

    let valid_tx = signed_shared_state_tx(&store, &wallet, update, &cold_key)?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordered_shared_state_batches_finalize_validator_lifecycle_updates() -> Result<()> {
    network::set_quiet_logging(true);

    let dir = TempDir::new()?;
    let store = Arc::new(Store::open(&dir.path().to_string_lossy())?);
    let port = pick_udp_port();
    let address = format!("127.0.0.1:{port}");
    provision_runtime_identity(&dir, store.effective_chain_id(), address.clone())?;
    let identity = node_identity::NodeIdentity::load_runtime_in_dir(
        dir.path(),
        unchained::protocol::CURRENT.version,
        Some(store.effective_chain_id()),
        vec![address],
    )?;
    let committee = finality_support::TestCommittee::from_identities(vec![identity]);
    let net = spawn_network(store.clone(), port).await?;
    let genesis = seed_genesis(store.as_ref(), &committee)?;
    let wallet = build_fee_payer_wallet(&dir, store.as_ref(), &genesis, 4)?;
    let (pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;

    let registration = signed_shared_state_tx(
        store.as_ref(),
        &wallet,
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() }),
        &cold_key,
    )?;
    let registration_id = net.submit_tx(&registration).await?;
    assert!(store.get_raw_bytes("tx", &registration_id)?.is_none());
    assert!(store
        .load_shared_state_pending_tx(&registration_id)?
        .is_some());

    let registration_batch = net
        .select_pending_shared_state_batch()?
        .expect("registration batch");
    let registration_anchor = net
        .finalize_local_shared_state_batch(&registration_batch)
        .await?;
    assert_eq!(
        registration_anchor.ordering_path,
        unchained::consensus::OrderingPath::DagBftSharedState
    );
    assert_eq!(
        registration_anchor.ordered_tx_count,
        registration_batch.ordered_tx_count()?
    );
    assert!(store.get_raw_bytes("tx", &registration_id)?.is_some());
    assert!(store
        .load_shared_state_pending_tx(&registration_id)?
        .is_none());
    assert_eq!(
        store.load_validator_pool(&pool.validator.id)?.as_ref(),
        Some(&pool)
    );

    let update = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: pool.validator.id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "ordered validator".to_string(),
            website: Some("https://ordered.example".to_string()),
            description: Some("ordered canonical profile".to_string()),
        },
    });
    let update_tx = signed_shared_state_tx(store.as_ref(), &wallet, update, &cold_key)?;
    let update_id = net.submit_tx(&update_tx).await?;
    assert!(store.get_raw_bytes("tx", &update_id)?.is_none());
    assert!(store.load_shared_state_pending_tx(&update_id)?.is_some());

    let update_batch = net
        .select_pending_shared_state_batch()?
        .expect("profile update batch");
    let update_anchor = net.finalize_local_shared_state_batch(&update_batch).await?;
    assert_eq!(
        update_anchor.ordering_path,
        unchained::consensus::OrderingPath::DagBftSharedState
    );
    assert!(store.get_raw_bytes("tx", &update_id)?.is_some());
    assert!(store.load_shared_state_pending_tx(&update_id)?.is_none());

    let stored = store
        .load_validator_pool(&pool.validator.id)?
        .expect("updated validator pool");
    assert_eq!(stored.commission_bps, 325);
    assert_eq!(stored.metadata.display_name, "ordered validator");
    assert_eq!(
        stored.metadata.website.as_deref(),
        Some("https://ordered.example")
    );

    net.shutdown().await;
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

    let wallet = build_fee_payer_wallet(&dir, &store, &anchor, 2)?;
    let tx = finality_support::fee_paid_shared_state_tx(
        &store,
        &wallet,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: SlashableEvidence::Liveness(liveness_records[0].fault.clone()),
        }),
        Vec::new(),
    )?;
    tx.apply(&store)?;

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
fn repeated_liveness_faults_jail_then_reactivate_future_committee() -> Result<()> {
    let dir = TempDir::new()?;
    let store = Store::open(&dir.path().to_string_lossy())?;

    let (pool_a, hot_a, _) = build_active_validator_pool(101, 0, [0x11; 32])?;
    let (pool_b, hot_b, _) = build_active_validator_pool(101, 0, [0x22; 32])?;
    let (pool_c, _hot_c, cold_c) = build_active_validator_pool(100, 0, [0x33; 32])?;
    let mut pool_c = store_pool_with_share_supply(&store, &pool_c, 250)?;
    store.store_validator_pool(&pool_a)?;
    store.store_validator_pool(&pool_b)?;
    let genesis_anchor = finalized_fast_path_anchor(
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
    let wallet = build_fee_payer_wallet(&dir, &store, &genesis_anchor, 5)?;

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
        finality_support::fee_paid_shared_state_tx(
            &store,
            &wallet,
            SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
                evidence: SlashableEvidence::Liveness(fault.fault.clone()),
            }),
            Vec::new(),
        )?
        .apply(&store)?;
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
    let reactivation = signed_shared_state_tx(&store, &wallet, reactivation_action, &cold_c)?;
    reactivation.apply(&store)?;

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
    let wallet = build_fee_payer_wallet(&dir, &store, &anchor0, 4)?;
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
    finality_support::fee_paid_shared_state_tx(
        &store,
        &wallet,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: first_evidence,
        }),
        Vec::new(),
    )?
    .apply(&store)?;
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
    finality_support::fee_paid_shared_state_tx(
        &store,
        &wallet,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: second_evidence,
        }),
        Vec::new(),
    )?
    .apply(&store)?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordered_penalty_evidence_batches_finalize_validator_slashing() -> Result<()> {
    network::set_quiet_logging(true);

    let dir = TempDir::new()?;
    let store = Arc::new(Store::open(&dir.path().to_string_lossy())?);
    let port = pick_udp_port();
    let address = format!("127.0.0.1:{port}");
    provision_runtime_identity(&dir, store.effective_chain_id(), address.clone())?;
    let identity = node_identity::NodeIdentity::load_runtime_in_dir(
        dir.path(),
        unchained::protocol::CURRENT.version,
        Some(store.effective_chain_id()),
        vec![address],
    )?;
    let committee =
        finality_support::TestCommittee::from_weighted_identities(vec![(identity.clone(), 100)]);
    let net = spawn_network(store.clone(), port).await?;
    let genesis = seed_genesis(store.as_ref(), &committee)?;
    let wallet = build_fee_payer_wallet(&dir, store.as_ref(), &genesis, 2)?;
    let validator = committee
        .validator_set_for_epoch(genesis.position.epoch)
        .validators[0]
        .clone();
    let slashed_pool = store_pool_with_share_supply(
        store.as_ref(),
        &store
            .load_validator_pool(&validator.id)?
            .expect("local validator pool"),
        250,
    )?;

    let first_target = VoteTarget {
        position: ConsensusPosition {
            epoch: genesis.position.epoch,
            slot: genesis.position.slot.saturating_add(1),
        },
        ordering_path: OrderingPath::FastPathPrivateTransfer,
        block_digest: [0x41; 32],
    };
    let second_target = VoteTarget {
        block_digest: [0x52; 32],
        ..first_target.clone()
    };
    let evidence = SlashableEvidence::Consensus(ConsensusEvidence::VoteEquivocation(
        VoteEquivocationEvidence::new(
            ValidatorVote {
                voter: validator.id,
                target: first_target.clone(),
                signature: identity.sign_consensus_message(&first_target.signing_bytes())?,
            },
            ValidatorVote {
                voter: validator.id,
                target: second_target.clone(),
                signature: identity.sign_consensus_message(&second_target.signing_bytes())?,
            },
        )?,
    ));
    let evidence_id = evidence.evidence_id()?;
    let tx = finality_support::fee_paid_shared_state_tx(
        store.as_ref(),
        &wallet,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission { evidence }),
        Vec::new(),
    )?;

    let tx_id = net.submit_tx(&tx).await?;
    assert!(store.get_raw_bytes("tx", &tx_id)?.is_none());
    assert!(store.load_shared_state_pending_tx(&tx_id)?.is_some());
    let cached_epoch1 = load_or_compute_active_validator_set(store.as_ref(), 1)?;
    assert!(cached_epoch1.validator(&validator.id).is_some());
    store.store_validator_committee(&cached_epoch1)?;

    let batch = net
        .select_pending_shared_state_batch()?
        .expect("penalty evidence batch");
    let anchor = net.finalize_local_shared_state_batch(&batch).await?;
    assert_eq!(anchor.ordering_path, OrderingPath::DagBftSharedState);
    assert_eq!(anchor.ordered_tx_count, 1);
    assert!(store.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(store.load_shared_state_pending_tx(&tx_id)?.is_none());

    let event = store
        .load_validator_penalty_event(&evidence_id)?
        .expect("stored ordered validator penalty");
    let updated_pool = store
        .load_validator_pool(&validator.id)?
        .expect("ordered slashed validator pool");

    assert_eq!(event.validator_id, validator.id);
    assert_eq!(event.slash_bps, PROTOCOL.equivocation_slash_bps);
    assert_eq!(event.bonded_stake_before, slashed_pool.total_bonded_stake);
    assert_eq!(event.bonded_stake_after, 75);
    assert_eq!(event.resulting_status, ValidatorStatus::Jailed);
    assert_eq!(event.resulting_accountability.safety_faults, 1);
    assert_eq!(
        event.resulting_accountability.jailed_until_epoch,
        Some(PROTOCOL.equivocation_jail_epochs)
    );
    assert_eq!(
        updated_pool.total_delegation_shares,
        slashed_pool.total_delegation_shares
    );
    assert_eq!(updated_pool.status, ValidatorStatus::Jailed);
    assert_eq!(updated_pool.total_bonded_stake, 75);
    assert!(store.load_validator_committee(1)?.is_none());
    assert!(expected_validator_set_for_epoch(store.as_ref(), 1).is_err());

    net.shutdown().await;
    Ok(())
}
