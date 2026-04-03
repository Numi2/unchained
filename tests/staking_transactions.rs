mod finality_support;

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use unchained::{
    config::{Net, P2p},
    consensus::{Validator, ValidatorKeys},
    crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign},
    epoch::Anchor,
    network, node_identity,
    staking::{
        expected_validator_set_for_epoch, ValidatorMetadata, ValidatorPool, ValidatorProfileUpdate,
        ValidatorRegistration, ValidatorStatus,
    },
    sync::SyncState,
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
    let (pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;

    let registration = signed_shared_state_tx(
        store.as_ref(),
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() }),
        &cold_key,
    );
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
    let update_tx = signed_shared_state_tx(store.as_ref(), update, &cold_key);
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
