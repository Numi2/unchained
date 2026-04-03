mod finality_support;

use once_cell::sync::Lazy;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::Endpoint;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::broadcast;
use tokio::time::{sleep, Instant};
use unchained::coin::Coin;
use unchained::config::{Net, P2p};
use unchained::consensus::{OrderingPath, Validator, ValidatorKeys};
use unchained::crypto::{
    ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign, TaggedSigningPublicKey,
};
use unchained::epoch::{Anchor, MerkleTree};
use unchained::network::{self, NetHandle};
use unchained::node_identity::{self, validator_from_record, NodeIdentity};
use unchained::protocol::CURRENT as PROTOCOL;
use unchained::shielded::{
    local_archive_provider_manifest, local_archive_replica_attestations, route_checkpoint_requests,
    ArchiveDirectory, ArchivedNullifierEpoch, CheckpointExtensionRequest, EvolvingNullifierQuery,
    HistoricalUnspentCheckpoint, NullifierRootLedger,
};
use unchained::staking::{
    ValidatorMetadata, ValidatorPool, ValidatorRegistration, ValidatorStatus,
};
use unchained::storage::{protocol_chain_id, Store};
use unchained::sync::SyncState;
use unchained::transaction::{self, SharedStateAction, Tx};

static TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn pick_udp_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind udp socket")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn next_anchor(
    committee: &finality_support::TestCommittee,
    prev: &Anchor,
    merkle_root: [u8; 32],
    coin_count: u32,
) -> Anchor {
    committee.child_anchor(prev, merkle_root, coin_count)
}

fn seed_genesis(
    store: &Store,
    committee: &finality_support::TestCommittee,
) -> anyhow::Result<Anchor> {
    let genesis = committee.genesis_anchor();
    committee.seed_validator_state(store, genesis.position.epoch)?;
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
}

fn store_anchor(store: &Store, anchor: &Anchor) -> anyhow::Result<()> {
    store.store_validator_committee(&anchor.validator_set)?;
    store.put("epoch", &anchor.num.to_le_bytes(), anchor)?;
    store.put("epoch", b"latest", anchor)?;
    store.put("anchor", &anchor.hash, anchor)?;
    Ok(())
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
) -> anyhow::Result<(ValidatorPool, aws_lc_rs::unstable::signature::PqdsaKeyPair)> {
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
        [7u8; 32],
        175,
        voting_power,
        activation_epoch,
        ValidatorStatus::PendingActivation,
        ValidatorMetadata {
            display_name: "dag validator".to_string(),
            website: Some("https://dag.example".to_string()),
            description: Some("dag-ordered validator".to_string()),
        },
    )?;
    Ok((pool, cold_key))
}

fn store_coin_epoch(
    store: &Store,
    anchor: &Anchor,
    coin: &Coin,
    leaves: &Vec<[u8; 32]>,
) -> anyhow::Result<()> {
    let levels = MerkleTree::build_levels_from_sorted_leaves(leaves);
    store.put("coin", &coin.id, coin)?;
    store.put_coin_epoch(&coin.id, anchor.num)?;
    store.put_coin_epoch_rev(anchor.num, &coin.id)?;
    store.store_epoch_leaves(anchor.num, leaves)?;
    store.store_epoch_levels(anchor.num, &levels)?;
    let sel_cf = store
        .db
        .cf_handle("epoch_selected")
        .expect("epoch_selected CF");
    let mut key = Vec::with_capacity(8 + 32);
    key.extend_from_slice(&anchor.num.to_le_bytes());
    key.extend_from_slice(&coin.id);
    store.db.put_cf(sel_cf, &key, &[])?;
    Ok(())
}

fn build_net(port: u16, bootstrap: Vec<String>) -> Net {
    Net {
        listen_port: port,
        bootstrap,
        trust_updates: Vec::new(),
        strict_trust: false,
        peer_exchange: true,
        max_peers: 16,
        connection_timeout_secs: 5,
        public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()),
        sync_timeout_secs: 5,
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
    chain_id: Option<[u8; 32]>,
    addresses: Vec<String>,
) -> anyhow::Result<(String, String)> {
    let (node_id, _) = node_identity::init_root_in_dir(tempdir.path())?;
    let (_, request) = node_identity::prepare_auth_request_in_dir(
        tempdir.path(),
        PROTOCOL.version,
        chain_id,
        addresses,
        None,
    )?;
    let (_, record) = node_identity::sign_auth_request_in_dir(tempdir.path(), &request, 30)?;
    let (installed_node_id, installed_record) =
        node_identity::install_node_record_in_dir(tempdir.path(), &record)?;
    assert_eq!(installed_node_id, node_id);
    Ok((installed_node_id, installed_record))
}

async fn spawn_test_node(
    tempdir: &TempDir,
    net_cfg: Net,
) -> anyhow::Result<(Arc<Store>, NetHandle, Arc<Mutex<SyncState>>)> {
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let net = network::spawn(net_cfg, build_p2p(), db.clone(), sync_state.clone()).await?;
    Ok((db, net, sync_state))
}

async fn wait_for_peers(net: &NetHandle, expected: usize, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if net.peer_count() >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for peers on {label}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_anchor(rx: &mut broadcast::Receiver<Anchor>, expected_hash: [u8; 32]) -> Anchor {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for anchor");
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(anchor)) if anchor.hash == expected_hash => return anchor,
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => continue,
            Err(_) => panic!("timed out waiting for anchor"),
        }
    }
}

async fn wait_for_condition(label: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_collects_multivalidator_qc_for_deterministic_leader() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let dir_c = TempDir::new()?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let port_c = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");
    let addr_c = format!("127.0.0.1:{port_c}");
    let chain_id = protocol_chain_id();

    let (_, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()])?;
    provision_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()])?;
    provision_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()])?;

    let identity_a = NodeIdentity::load_runtime_in_dir(
        dir_a.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_a.clone()],
    )?;
    let identity_b = NodeIdentity::load_runtime_in_dir(
        dir_b.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_b.clone()],
    )?;
    let identity_c = NodeIdentity::load_runtime_in_dir(
        dir_c.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_c.clone()],
    )?;

    let committee = finality_support::TestCommittee::from_identities(vec![
        identity_a.clone(),
        identity_b.clone(),
        identity_c.clone(),
    ]);
    let genesis = committee.genesis_anchor();

    let (db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;
    let (db_c, net_c, _) = spawn_test_node(&dir_c, build_net(port_c, vec![bootstrap_a])).await?;

    wait_for_peers(&net_a, 2, "node A").await;
    wait_for_peers(&net_b, 1, "node B").await;
    wait_for_peers(&net_c, 1, "node C").await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;

    let leader_id = committee.leader_for(1);
    let leader_a = validator_from_record(identity_a.record(), 1)?.id == leader_id;
    let leader_b = validator_from_record(identity_b.record(), 1)?.id == leader_id;
    let (leader_db, leader_net) = if leader_a {
        (db_a.clone(), net_a.clone())
    } else if leader_b {
        (db_b.clone(), net_b.clone())
    } else {
        (db_c.clone(), net_c.clone())
    };

    let anchor = leader_net
        .certify_local_anchor(
            1,
            Some(&genesis),
            [9u8; 32],
            0,
            0,
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            0,
            OrderingPath::FastPathPrivateTransfer,
        )
        .await?;
    anchor.validate_against_parent(Some(&genesis))?;
    assert_eq!(anchor.qc.votes.len(), 3);
    assert_eq!(
        anchor.qc.signed_voting_power,
        genesis.validator_set.quorum_threshold
    );

    store_anchor(leader_db.as_ref(), &anchor)?;
    leader_net.gossip_anchor(&anchor).await;

    wait_for_condition(
        "checkpoint adoption on node A",
        Duration::from_secs(10),
        || {
            db_a.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|latest| latest.hash == anchor.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "checkpoint adoption on node B",
        Duration::from_secs(10),
        || {
            db_b.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|latest| latest.hash == anchor.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "checkpoint adoption on node C",
        Duration::from_secs(10),
        || {
            db_c.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|latest| latest.hash == anchor.hash)
                .unwrap_or(false)
        },
    )
    .await;

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_orders_shared_state_from_multivalidator_dag_frontier() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let dir_c = TempDir::new()?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let port_c = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");
    let addr_c = format!("127.0.0.1:{port_c}");
    let chain_id = protocol_chain_id();

    let (_, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()])?;
    provision_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()])?;
    provision_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()])?;

    let identity_a = NodeIdentity::load_runtime_in_dir(
        dir_a.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_a.clone()],
    )?;
    let identity_b = NodeIdentity::load_runtime_in_dir(
        dir_b.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_b.clone()],
    )?;
    let identity_c = NodeIdentity::load_runtime_in_dir(
        dir_c.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_c.clone()],
    )?;

    let committee = finality_support::TestCommittee::from_identities(vec![
        identity_a.clone(),
        identity_b.clone(),
        identity_c.clone(),
    ]);
    let genesis = committee.genesis_anchor();
    let (pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;

    let (db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;
    let (db_c, net_c, _) = spawn_test_node(&dir_c, build_net(port_c, vec![bootstrap_a])).await?;

    wait_for_peers(&net_a, 2, "node A").await;
    wait_for_peers(&net_b, 1, "node B").await;
    wait_for_peers(&net_c, 1, "node C").await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;

    let tx = signed_shared_state_tx(
        db_a.as_ref(),
        SharedStateAction::RegisterValidator(ValidatorRegistration { pool: pool.clone() }),
        &cold_key,
    );
    let tx_id = net_a.submit_tx(&tx).await?;
    wait_for_condition(
        "shared-state tx propagation to node B",
        Duration::from_secs(10),
        || {
            db_b.load_shared_state_pending_tx(&tx_id)
                .ok()
                .flatten()
                .is_some()
        },
    )
    .await;
    wait_for_condition(
        "shared-state tx propagation to node C",
        Duration::from_secs(10),
        || {
            db_c.load_shared_state_pending_tx(&tx_id)
                .ok()
                .flatten()
                .is_some()
        },
    )
    .await;

    let batch_a = net_a
        .select_pending_shared_state_batch()?
        .expect("pending shared-state batch on node A");
    let batch_b = net_b
        .select_pending_shared_state_batch()?
        .expect("pending shared-state batch on node B");
    let batch_c = net_c
        .select_pending_shared_state_batch()?
        .expect("pending shared-state batch on node C");
    assert_eq!(batch_a.ordered_tx_count()?, 1);
    assert_eq!(batch_b.ordered_tx_count()?, 1);
    assert_eq!(batch_c.ordered_tx_count()?, 1);

    let dag_a = net_a.author_local_shared_state_batch(&batch_a).await?;
    let dag_b = net_b.author_local_shared_state_batch(&batch_b).await?;
    let dag_c = net_c.author_local_shared_state_batch(&batch_c).await?;
    assert_eq!(dag_a.round, 1);
    assert_eq!(dag_b.round, 1);
    assert_eq!(dag_c.round, 1);
    assert!(dag_a.parents.is_empty());
    assert!(dag_b.parents.is_empty());
    assert!(dag_c.parents.is_empty());

    wait_for_condition(
        "round-1 DAG batch availability on node A",
        Duration::from_secs(10),
        || {
            db_a.load_shared_state_dag_round(genesis.position.epoch, 1)
                .map(|batches| batches.len() == 3)
                .unwrap_or(false)
        },
    )
    .await;

    let leader_id = committee.leader_for(1);
    let leader_net = if validator_from_record(identity_a.record(), 1)?.id == leader_id {
        net_a.clone()
    } else if validator_from_record(identity_b.record(), 1)?.id == leader_id {
        net_b.clone()
    } else {
        net_c.clone()
    };

    let anchor = leader_net
        .finalize_available_shared_state_anchor()
        .await?
        .expect("finalized shared-state anchor");
    assert_eq!(anchor.ordering_path, OrderingPath::DagBftSharedState);
    assert_eq!(anchor.dag_round, 1);
    assert_eq!(anchor.dag_frontier.len(), 3);
    assert_eq!(anchor.ordered_batch_ids.len(), 3);
    assert_eq!(anchor.ordered_tx_count, 1);

    wait_for_condition(
        "shared-state anchor adoption on node A",
        Duration::from_secs(10),
        || {
            db_a.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|latest| latest.hash == anchor.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "shared-state anchor adoption on node B",
        Duration::from_secs(10),
        || {
            db_b.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|latest| latest.hash == anchor.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "shared-state anchor adoption on node C",
        Duration::from_secs(10),
        || {
            db_c.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|latest| latest.hash == anchor.hash)
                .unwrap_or(false)
        },
    )
    .await;

    assert!(db_a.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_b.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_c.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_a.load_validator_pool(&pool.validator.id)?.is_some());
    assert!(db_b.load_validator_pool(&pool.validator.id)?.is_some());
    assert!(db_c.load_validator_pool(&pool.validator.id)?.is_some());

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_bootstrap_anchor_recovery_and_proof_roundtrip() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let dir_c = TempDir::new()?;

    let db_a_seed = Store::open(&dir_a.path().to_string_lossy())?;
    let db_b_seed = Store::open(&dir_b.path().to_string_lossy())?;
    let db_c_seed = Store::open(&dir_c.path().to_string_lossy())?;

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&db_a_seed, &committee)?;
    seed_genesis(&db_b_seed, &committee)?;
    seed_genesis(&db_c_seed, &committee)?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let port_c = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");
    let addr_c = format!("127.0.0.1:{port_c}");

    let (_, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(genesis.hash), vec![addr_a.clone()])?;
    provision_runtime_identity(&dir_b, Some(genesis.hash), vec![addr_b])?;
    provision_runtime_identity(&dir_c, Some(genesis.hash), vec![addr_c])?;

    drop(db_a_seed);
    drop(db_b_seed);
    drop(db_c_seed);

    let (db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;
    let (db_c, net_c, _) = spawn_test_node(&dir_c, build_net(port_c, vec![bootstrap_a])).await?;

    wait_for_peers(&net_a, 2, "node A").await;
    wait_for_peers(&net_b, 1, "node B").await;
    wait_for_peers(&net_c, 1, "node C").await;

    let mut anchor_rx_b = net_b.anchor_subscribe();
    let mut anchor_rx_c = net_c.anchor_subscribe();

    let anchor1 = next_anchor(&committee, &genesis, [0u8; 32], 0);
    store_anchor(&db_a, &anchor1)?;
    net_a.gossip_anchor(&anchor1).await;

    let seen_b_1 = wait_for_anchor(&mut anchor_rx_b, anchor1.hash).await;
    let seen_c_1 = wait_for_anchor(&mut anchor_rx_c, anchor1.hash).await;
    assert_eq!(seen_b_1.hash, anchor1.hash);
    assert_eq!(seen_c_1.hash, anchor1.hash);

    wait_for_condition(
        "anchor1 adoption on node B",
        Duration::from_secs(10),
        || {
            db_b.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|anchor| anchor.hash == anchor1.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "anchor1 adoption on node C",
        Duration::from_secs(10),
        || {
            db_c.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|anchor| anchor.hash == anchor1.hash)
                .unwrap_or(false)
        },
    )
    .await;

    let coin = Coin::new_with_creator_pk_and_lock(
        anchor1.hash,
        42,
        [7u8; 32],
        TaggedSigningPublicKey::zero_ml_dsa_65(),
        [0u8; 32],
    );
    let leaf = Coin::id_to_leaf_hash(&coin.id);
    let leaves = vec![leaf];
    let anchor2 = next_anchor(
        &committee,
        &anchor1,
        MerkleTree::compute_root_from_sorted_leaves(&leaves),
        1,
    );
    store_anchor(&db_a, &anchor2)?;
    store_coin_epoch(&db_a, &anchor2, &coin, &leaves)?;

    net_a.gossip_anchor(&anchor2).await;
    let seen_b_2 = wait_for_anchor(&mut anchor_rx_b, anchor2.hash).await;
    let seen_c_2 = wait_for_anchor(&mut anchor_rx_c, anchor2.hash).await;
    assert_eq!(seen_b_2.hash, anchor2.hash);
    assert_eq!(seen_c_2.hash, anchor2.hash);

    wait_for_condition(
        "anchor2 adoption on node B",
        Duration::from_secs(10),
        || {
            db_b.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|anchor| anchor.hash == anchor2.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "anchor2 adoption on node C",
        Duration::from_secs(10),
        || {
            db_c.get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|anchor| anchor.hash == anchor2.hash)
                .unwrap_or(false)
        },
    )
    .await;

    wait_for_condition(
        "recovered epoch leaves on node C",
        Duration::from_secs(10),
        || {
            db_c.get_epoch_leaves(anchor2.num)
                .ok()
                .flatten()
                .map(|stored| stored == leaves)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "recovered selected ids on node C",
        Duration::from_secs(10),
        || {
            db_c.get_selected_coin_ids_for_epoch(anchor2.num)
                .ok()
                .map(|ids| ids.contains(&coin.id))
                .unwrap_or(false)
        },
    )
    .await;

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_restart_preserves_identity_and_reloads_persisted_peers() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let db_a_seed = Store::open(&dir_a.path().to_string_lossy())?;
    let db_b_seed = Store::open(&dir_b.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&db_a_seed, &committee)?;
    seed_genesis(&db_b_seed, &committee)?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let (node_id_a, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(genesis.hash), vec![addr_a.clone()])?;
    let (node_id_b_before, _) =
        provision_runtime_identity(&dir_b, Some(genesis.hash), vec![addr_b.clone()])?;
    let bootstrap_record_a = node_identity::NodeRecordV2::decode_compact(&bootstrap_a)?;

    drop(db_a_seed);
    drop(db_b_seed);

    let (_db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;

    wait_for_peers(&net_a, 1, "node A first boot").await;
    wait_for_peers(&net_b, 1, "node B first boot").await;

    let remembered_a = db_b
        .load_node_records()?
        .into_iter()
        .filter_map(|bytes| unchained::canonical::decode_node_record(&bytes).ok())
        .any(|record| record.node_id == bootstrap_record_a.node_id);
    assert!(remembered_a, "node B did not persist node A record");

    net_b.shutdown().await;
    db_b.close()?;
    drop(db_b);
    drop(net_b);

    let (node_id_b_after, _) = node_identity::load_local_identity_output_in_dir(
        dir_b.path(),
        PROTOCOL.version,
        Some(genesis.hash),
        vec![addr_b.clone()],
    )?;
    assert_eq!(node_id_b_after, node_id_b_before);
    assert_ne!(node_id_a, node_id_b_after);

    let (_db_b_restart, net_b_restart, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![])).await?;

    wait_for_peers(&net_a, 1, "node A after B restart").await;
    wait_for_peers(&net_b_restart, 1, "node B after restart").await;

    net_b_restart.shutdown().await;
    net_a.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_rejoin_recovers_full_epoch_state_after_gap() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let db_a_seed = Store::open(&dir_a.path().to_string_lossy())?;
    let db_b_seed = Store::open(&dir_b.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&db_a_seed, &committee)?;
    seed_genesis(&db_b_seed, &committee)?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let (_, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(genesis.hash), vec![addr_a.clone()])?;
    provision_runtime_identity(&dir_b, Some(genesis.hash), vec![addr_b])?;

    drop(db_a_seed);
    drop(db_b_seed);

    let (db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;

    wait_for_peers(&net_a, 1, "node A before partition").await;
    wait_for_peers(&net_b, 1, "node B before partition").await;

    net_b.shutdown().await;
    db_b.close()?;
    drop(db_b);
    drop(net_b);

    let anchor1 = next_anchor(&committee, &genesis, [0u8; 32], 0);
    store_anchor(&db_a, &anchor1)?;

    let coin = Coin::new_with_creator_pk_and_lock(
        anchor1.hash,
        99,
        [5u8; 32],
        TaggedSigningPublicKey::zero_ml_dsa_65(),
        [1u8; 32],
    );
    let leaf = Coin::id_to_leaf_hash(&coin.id);
    let leaves = vec![leaf];
    let anchor2 = next_anchor(
        &committee,
        &anchor1,
        MerkleTree::compute_root_from_sorted_leaves(&leaves),
        1,
    );
    store_anchor(&db_a, &anchor2)?;
    store_coin_epoch(&db_a, &anchor2, &coin, &leaves)?;

    let (db_b_rejoin, net_b_rejoin, _) = spawn_test_node(&dir_b, build_net(port_b, vec![])).await?;

    wait_for_peers(&net_a, 1, "node A after rejoin").await;
    wait_for_peers(&net_b_rejoin, 1, "node B after rejoin").await;

    let mut anchor_rx = net_b_rejoin.anchor_subscribe();
    net_b_rejoin.request_latest_epoch().await;
    let adopted_tip = wait_for_anchor(&mut anchor_rx, anchor2.hash).await;
    assert_eq!(adopted_tip.hash, anchor2.hash);

    wait_for_condition(
        "rejoined latest anchor adoption",
        Duration::from_secs(10),
        || {
            db_b_rejoin
                .get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|anchor| anchor.hash == anchor2.hash)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "rejoined epoch leaves recovery",
        Duration::from_secs(10),
        || {
            db_b_rejoin
                .get_epoch_leaves(anchor2.num)
                .ok()
                .flatten()
                .map(|stored| stored == leaves)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "rejoined selected ids recovery",
        Duration::from_secs(10),
        || {
            db_b_rejoin
                .get_selected_coin_ids_for_epoch(anchor2.num)
                .ok()
                .map(|ids| ids.contains(&coin.id))
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "rejoined confirmed coin recovery",
        Duration::from_secs(10),
        || {
            db_b_rejoin
                .get::<Coin>("coin", &coin.id)
                .ok()
                .flatten()
                .map(|stored| stored.id == coin.id && stored.epoch_hash == coin.epoch_hash)
                .unwrap_or(false)
        },
    )
    .await;

    let levels = db_b_rejoin
        .get_epoch_levels(anchor2.num)?
        .expect("epoch levels present after recovery");
    let proof =
        MerkleTree::build_proof_from_levels(&levels, &leaf).expect("proof rebuild after recovery");
    assert!(MerkleTree::verify_proof(
        &leaf,
        &proof,
        &anchor2.merkle_root,
    ));

    net_b_rejoin.shutdown().await;
    net_a.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_disconnects_peer_that_sends_invalid_envelope() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_victim = TempDir::new()?;
    let dir_attacker = TempDir::new()?;

    let db_seed = Store::open(&dir_victim.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&db_seed, &committee)?;
    drop(db_seed);

    let port_victim = pick_udp_port();
    let addr_victim = format!("127.0.0.1:{port_victim}");
    let (_, bootstrap_victim) =
        provision_runtime_identity(&dir_victim, Some(genesis.hash), vec![addr_victim.clone()])?;
    let victim_record = node_identity::NodeRecordV2::decode_compact(&bootstrap_victim)?;

    let (db_victim, net_victim, _) =
        spawn_test_node(&dir_victim, build_net(port_victim, vec![])).await?;

    provision_runtime_identity(
        &dir_attacker,
        Some(genesis.hash),
        vec!["127.0.0.1:0".to_string()],
    )?;
    let attacker_identity = node_identity::NodeIdentity::load_runtime_in_dir(
        dir_attacker.path(),
        PROTOCOL.version,
        Some(genesis.hash),
        vec!["127.0.0.1:0".to_string()],
    )?;
    let expected_peers = node_identity::ExpectedPeerStore::new();
    expected_peers.remember(&victim_record);
    let rustls_client = node_identity::build_client_config(&attacker_identity, expected_peers)?;
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_client)?));
    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(client_config.clone());

    let connection = endpoint
        .connect_with(
            client_config,
            victim_record.primary_address()?,
            &victim_record.server_name(),
        )?
        .await?;

    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&network::encode_wire_hello(
        attacker_identity.record().clone(),
        Vec::new(),
    )?)
    .await?;
    send.finish()?;
    let _ = recv.read_to_end(8 * 1024 * 1024).await?;

    wait_for_condition("victim peer admission", Duration::from_secs(10), || {
        net_victim.peer_count() == 1
    })
    .await;

    let mut forged = node_identity::SignedEnvelope::new(
        &attacker_identity,
        PROTOCOL.version,
        Some(genesis.hash),
        vec![0xde, 0xad, 0xbe, 0xef],
    )?;
    forged.sig[0] ^= 0x01;

    let mut stream = connection.open_uni().await?;
    stream
        .write_all(&network::encode_wire_envelope(&forged)?)
        .await?;
    stream.finish()?;

    wait_for_condition("victim peer eviction", Duration::from_secs(10), || {
        net_victim.peer_count() == 0
    })
    .await;
    assert_eq!(
        db_victim
            .get::<Anchor>("epoch", b"latest")?
            .expect("victim latest anchor")
            .hash,
        genesis.hash
    );

    endpoint.close(0u32.into(), b"test-finished");
    endpoint.wait_idle().await;
    net_victim.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_mesh_archive_provider_discovery_and_shard_sync() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let db_a_seed = Store::open(&dir_a.path().to_string_lossy())?;
    let db_b_seed = Store::open(&dir_b.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&db_a_seed, &committee)?;
    seed_genesis(&db_b_seed, &committee)?;

    let archived = ArchivedNullifierEpoch::new(1, vec![[11u8; 32], [22u8; 32], [33u8; 32]]);
    let mut ledger = NullifierRootLedger::default();
    ledger.remember_epoch(&archived);
    db_a_seed.store_shielded_root_ledger(&ledger)?;
    db_b_seed.store_shielded_root_ledger(&ledger)?;
    db_a_seed.store_shielded_nullifier_epoch(&archived)?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let (_, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(genesis.hash), vec![addr_a.clone()])?;
    provision_runtime_identity(&dir_b, Some(genesis.hash), vec![addr_b.clone()])?;

    drop(db_a_seed);
    drop(db_b_seed);

    let (_db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;

    wait_for_peers(&net_a, 1, "archive node A").await;
    wait_for_peers(&net_b, 1, "archive node B").await;

    net_b.ensure_archive_epochs(&[1]).await?;

    wait_for_condition(
        "archived nullifier epoch sync over PQ mesh",
        Duration::from_secs(10),
        || {
            db_b.load_shielded_nullifier_epoch(1)
                .ok()
                .flatten()
                .map(|stored| stored == archived)
                .unwrap_or(false)
        },
    )
    .await;

    let providers = db_b.load_shielded_archive_providers()?;
    assert!(
        !providers.is_empty(),
        "archive provider manifest was not persisted on the receiving node"
    );

    net_b.shutdown().await;
    net_a.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_mesh_remote_checkpoint_batch_service() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let db_a_seed = Store::open(&dir_a.path().to_string_lossy())?;
    let db_b_seed = Store::open(&dir_b.path().to_string_lossy())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(&db_a_seed, &committee)?;
    seed_genesis(&db_b_seed, &committee)?;

    let archived = ArchivedNullifierEpoch::new(1, vec![[11u8; 32], [22u8; 32], [33u8; 32]]);
    let mut ledger = NullifierRootLedger::default();
    ledger.remember_epoch(&archived);
    db_a_seed.store_shielded_root_ledger(&ledger)?;
    db_b_seed.store_shielded_root_ledger(&ledger)?;
    db_a_seed.store_shielded_nullifier_epoch(&archived)?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");

    let (_, bootstrap_a) =
        provision_runtime_identity(&dir_a, Some(genesis.hash), vec![addr_a.clone()])?;
    let (node_id_b_hex, _) =
        provision_runtime_identity(&dir_b, Some(genesis.hash), vec![addr_b.clone()])?;
    let provider_record_a = node_identity::NodeRecordV2::decode_compact(&bootstrap_a)?;
    let node_id_b = hex::decode(node_id_b_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid node id length"))?;

    drop(db_a_seed);
    drop(db_b_seed);

    let (_db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;

    wait_for_peers(&net_a, 1, "checkpoint node A").await;
    wait_for_peers(&net_b, 1, "checkpoint node B").await;

    wait_for_condition(
        "archive provider manifest discovery",
        Duration::from_secs(10),
        || {
            db_b.load_shielded_archive_providers()
                .map(|providers| {
                    providers
                        .iter()
                        .any(|manifest| manifest.provider_id == provider_record_a.node_id)
                })
                .unwrap_or(false)
        },
    )
    .await;

    let ledger = db_b
        .load_shielded_root_ledger()?
        .ok_or_else(|| anyhow::anyhow!("missing shielded root ledger"))?;
    let mut providers = db_b.load_shielded_archive_providers()?;
    let local_manifest = local_archive_provider_manifest(
        node_id_b,
        &ledger,
        PROTOCOL.archive_shard_epoch_span,
        &transaction::local_available_archive_epochs(&db_b, &ledger)?,
    )?;
    if let Some(existing) = providers
        .iter_mut()
        .find(|existing| existing.provider_id == local_manifest.provider_id)
    {
        *existing = local_manifest.clone();
    } else {
        providers.push(local_manifest.clone());
    }
    let base_directory = ArchiveDirectory::from_root_ledger_and_providers(
        &ledger,
        PROTOCOL.archive_shard_epoch_span,
        providers.clone(),
    )?;
    let mut replicas =
        local_archive_replica_attestations(provider_record_a.node_id, &base_directory, 32)?;
    replicas.extend(local_archive_replica_attestations(
        local_manifest.provider_id,
        &base_directory,
        32,
    )?);
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas(
        &ledger,
        PROTOCOL.archive_shard_epoch_span,
        providers,
        replicas,
    )?;

    let rotation_round = 7u64;
    let checkpoint = (0u64..10_000)
        .find_map(|counter| {
            let note_commitment = *blake3::hash(&counter.to_le_bytes()).as_bytes();
            let checkpoint = HistoricalUnspentCheckpoint::genesis(note_commitment, 1);
            let blinding = *blake3::hash(&counter.to_le_bytes()).as_bytes();
            route_checkpoint_requests(
                &directory,
                &[CheckpointExtensionRequest::new(
                    checkpoint.clone(),
                    vec![EvolvingNullifierQuery {
                        epoch: 1,
                        nullifier: [44u8; 32],
                    }],
                    blinding,
                )],
                rotation_round,
                PROTOCOL.oblivious_sync_min_batch as usize,
                PROTOCOL.max_historical_nullifier_batch as usize,
            )
            .ok()
            .and_then(|batches| batches.first().map(|batch| batch.provider_id))
            .filter(|provider_id| *provider_id == provider_record_a.node_id)
            .map(|_| checkpoint)
        })
        .ok_or_else(|| anyhow::anyhow!("could not route checkpoint request to remote provider"))?;

    let extensions = net_b
        .request_historical_extensions(
            &[CheckpointExtensionRequest::new(
                checkpoint.clone(),
                vec![EvolvingNullifierQuery {
                    epoch: 1,
                    nullifier: [44u8; 32],
                }],
                [55u8; 32],
            )],
            rotation_round,
        )
        .await?;
    assert_eq!(extensions.len(), 1);
    assert_eq!(extensions[0].strata.len(), 1);
    assert_eq!(extensions[0].strata[0].packets.len(), 1);
    assert_eq!(extensions[0].strata[0].packets[0].segments.len(), 1);
    let serving_provider = extensions[0].strata[0].packets[0].segments[0].provider_id;
    assert!(serving_provider == provider_record_a.node_id || serving_provider == node_id_b);
    if serving_provider == node_id_b {
        assert!(db_b.load_shielded_nullifier_epoch(1)?.is_some());
    }

    let updated = checkpoint.apply_extension(&extensions[0], &ledger)?;
    assert_eq!(updated.covered_through_epoch, 1);
    assert_eq!(updated.verified_epoch_count, 1);

    net_b.shutdown().await;
    net_a.shutdown().await;
    Ok(())
}
