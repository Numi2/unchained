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
use unchained::config::{Net, P2p};
use unchained::consensus::{OrderingPath, Validator, ValidatorKeys};
use unchained::crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign};
use unchained::epoch::Anchor;
use unchained::evidence::{LivenessFaultProof, SlashableEvidence};
use unchained::network::{self, NetHandle};
use unchained::node_identity::{self, validator_from_record, NodeIdentity};
use unchained::proof;
use unchained::protocol::CURRENT as PROTOCOL;
use unchained::shielded::{
    CheckpointExtensionRequest, EvolvingNullifierQuery, HistoricalUnspentCheckpoint,
};
use unchained::staking::{
    ValidatorAccountability, ValidatorMetadata, ValidatorPool, ValidatorProfileUpdate,
    ValidatorReactivation, ValidatorStatus,
};
use unchained::storage::{protocol_chain_id, Store};
use unchained::sync::SyncState;
use unchained::transaction::{self, PenaltyEvidenceAdmission, SharedStateAction, Tx};
use unchained::{storage::WalletStore, wallet::Wallet};

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
    wallet: &Wallet,
    action: SharedStateAction,
    cold_key: &aws_lc_rs::unstable::signature::PqdsaKeyPair,
) -> anyhow::Result<Tx> {
    let signable = Tx::shared_state_signing_bytes(store.effective_chain_id(), &action)
        .expect("encode shared-state signing message");
    let signature = ml_dsa_65_sign(cold_key, &signable).expect("sign shared-state action");
    finality_support::fee_paid_shared_state_tx(store, wallet, action, signature)
}

fn build_single_action_fee_wallet(
    tempdir: &TempDir,
    store: &Store,
    genesis: &Anchor,
) -> anyhow::Result<Wallet> {
    std::env::set_var("WALLET_PASSPHRASE", "pq-network-passphrase");
    std::env::set_var(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        finality_support::proof_fixture_dir(),
    );
    let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let wallet = finality_support::deterministic_wallet(wallet_store)?;
    let _ = finality_support::seed_wallet_with_coin_values(store, &wallet, genesis, &[2])?;
    Ok(wallet)
}

fn mirror_wallet_coin_state(
    stores: &[&Store],
    wallet: &Wallet,
    genesis: &Anchor,
    values: &[u64],
) -> anyhow::Result<()> {
    for store in stores {
        let _ = finality_support::seed_wallet_with_coin_values(store, wallet, genesis, values)?;
    }
    Ok(())
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

fn build_net(port: u16, bootstrap: Vec<String>) -> Net {
    Net {
        listen_port: port,
        bootstrap,
        trust_updates: Vec::new(),
        strict_trust: false,
        peer_exchange: true,
        max_peers: 16,
        connection_timeout_secs: 5,
        idle_timeout_secs: 30,
        keep_alive_interval_secs: 2,
        public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()),
        sync_timeout_secs: 5,
        banned_peer_ids: Vec::new(),
        quiet_by_default: true,
    }
}

fn bootstrap_to_leader(
    local_validator_id: unchained::consensus::ValidatorId,
    leader_id: unchained::consensus::ValidatorId,
    leader_bootstrap: &str,
) -> Vec<String> {
    if local_validator_id == leader_id {
        Vec::new()
    } else {
        vec![leader_bootstrap.to_string()]
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

fn provision_deterministic_runtime_identity(
    tempdir: &TempDir,
    chain_id: Option<[u8; 32]>,
    addresses: Vec<String>,
    slot: usize,
) -> anyhow::Result<(String, String)> {
    finality_support::install_deterministic_node_identity_keys(tempdir.path(), slot)?;
    provision_runtime_identity(tempdir, chain_id, addresses)
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
    let deadline = Instant::now() + Duration::from_secs(30);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deterministic_multivalidator_fee_paid_control_fixture_id_stays_stable(
) -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let dir_c = TempDir::new()?;
    let chain_id = protocol_chain_id();
    let addr_a = "127.0.0.1:41001".to_string();
    let addr_b = "127.0.0.1:41002".to_string();
    let addr_c = "127.0.0.1:41003".to_string();

    provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

    let identity_a = NodeIdentity::load_runtime_in_dir(
        dir_a.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_a],
    )?;
    let identity_b = NodeIdentity::load_runtime_in_dir(
        dir_b.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_b],
    )?;
    let identity_c = NodeIdentity::load_runtime_in_dir(
        dir_c.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_c],
    )?;

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a, 101),
        (identity_b, 101),
        (identity_c, 100),
    ]);
    let genesis = committee.genesis_anchor();
    let db = Arc::new(Store::open(&dir_a.path().to_string_lossy())?);
    committee.seed_validator_state(db.as_ref(), genesis.position.epoch)?;
    store_anchor(db.as_ref(), &genesis)?;
    let wallet = build_single_action_fee_wallet(&dir_a, db.as_ref(), &genesis)?;
    let snapshot = unchained::node_control::build_shielded_runtime_snapshot(db.as_ref())?;
    let prepared = wallet
        .prepare_fee_payment_for_snapshot(&snapshot, PROTOCOL.validator_profile_update_fee)?;
    let fixture_id = proof::shielded_tx_fixture_id(prepared.witness())?;
    assert_eq!(
        hex::encode(fixture_id),
        "f1e522879e8df1ff55a6b78d43b37ef6aea02f0cce2bb905d06bbb77cd2e5695"
    );
    let (_receipt, journal) = proof::prove_shielded_tx(prepared.witness())?;
    assert_eq!(journal.fee_amount, PROTOCOL.validator_profile_update_fee);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fixture mint for multivalidator fee-paid control submission proof"]
async fn mint_multivalidator_fee_paid_control_submission_fixture() -> anyhow::Result<()> {
    let _guard = test_guard();
    std::env::set_var(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        finality_support::proof_fixture_dir(),
    );
    std::env::set_var("UNCHAINED_ALLOW_PROOF_FIXTURE_MINT", "1");
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let dir_c = TempDir::new()?;
    let chain_id = protocol_chain_id();
    let addr_a = "127.0.0.1:41001".to_string();
    let addr_b = "127.0.0.1:41002".to_string();
    let addr_c = "127.0.0.1:41003".to_string();

    provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

    let identity_a = NodeIdentity::load_runtime_in_dir(
        dir_a.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_a],
    )?;
    let identity_b = NodeIdentity::load_runtime_in_dir(
        dir_b.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_b],
    )?;
    let identity_c = NodeIdentity::load_runtime_in_dir(
        dir_c.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![addr_c],
    )?;

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a, 101),
        (identity_b, 101),
        (identity_c, 100),
    ]);
    let genesis = committee.genesis_anchor();
    let db = Arc::new(Store::open(&dir_a.path().to_string_lossy())?);
    committee.seed_validator_state(db.as_ref(), genesis.position.epoch)?;
    store_anchor(db.as_ref(), &genesis)?;
    let wallet = build_single_action_fee_wallet(&dir_a, db.as_ref(), &genesis)?;
    let snapshot = unchained::node_control::build_shielded_runtime_snapshot(db.as_ref())?;
    let prepared = wallet
        .prepare_fee_payment_for_snapshot(&snapshot, PROTOCOL.validator_profile_update_fee)?;
    let fixture_id = proof::shielded_tx_fixture_id(prepared.witness())?;
    let fixture_path = std::path::Path::new(&finality_support::proof_fixture_dir())
        .join("shielded-spend")
        .join(format!("{}.bin", hex::encode(fixture_id)));
    let (_receipt, journal) = proof::prove_shielded_tx(prepared.witness())?;
    assert_eq!(journal.fee_amount, PROTOCOL.validator_profile_update_fee);
    assert!(fixture_path.exists());
    std::env::remove_var("UNCHAINED_ALLOW_PROOF_FIXTURE_MINT");

    Ok(())
}

fn finalized_fast_path_anchor_from_identities(
    num: u64,
    parent: Option<&Anchor>,
    validator_set: &unchained::consensus::ValidatorSet,
    signers: &[&NodeIdentity],
) -> anyhow::Result<Anchor> {
    let position = Anchor::position_for_num(num);
    let parent_hash = parent.map(|anchor| anchor.hash);
    let target = unchained::consensus::VoteTarget {
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
    let votes = signers
        .iter()
        .map(|identity| {
            anyhow::Ok(unchained::consensus::ValidatorVote {
                voter: validator_from_record(identity.record(), 1)?.id,
                target: target.clone(),
                signature: identity.sign_consensus_message(&target_bytes)?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let qc = unchained::consensus::QuorumCertificate::from_votes(validator_set, target, votes)?;
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

async fn finalize_single_shared_state_action(
    parent_anchor: &Anchor,
    committee: &finality_support::TestCommittee,
    identity_a: &NodeIdentity,
    identity_b: &NodeIdentity,
    _identity_c: &NodeIdentity,
    db_a: &Arc<Store>,
    db_b: &Arc<Store>,
    db_c: &Arc<Store>,
    net_a: &NetHandle,
    net_b: &NetHandle,
    net_c: &NetHandle,
    tx: &Tx,
) -> anyhow::Result<([u8; 32], Anchor)> {
    tx.validate(db_a.as_ref()).map_err(|err| {
        anyhow::anyhow!("shared-state tx invalid on node A before submission: {err}")
    })?;
    tx.validate(db_b.as_ref()).map_err(|err| {
        anyhow::anyhow!("shared-state tx invalid on node B before propagation: {err}")
    })?;
    tx.validate(db_c.as_ref()).map_err(|err| {
        anyhow::anyhow!("shared-state tx invalid on node C before propagation: {err}")
    })?;
    let tx_id = net_a.submit_tx(tx).await?;
    anyhow::ensure!(
        db_a.load_shared_state_pending_tx(&tx_id)?.is_some(),
        "shared-state tx was not staged on node A after submission"
    );
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

    net_a.author_local_shared_state_batch(&batch_a).await?;
    net_b.author_local_shared_state_batch(&batch_b).await?;
    net_c.author_local_shared_state_batch(&batch_c).await?;

    wait_for_condition(
        "round-1 DAG batch availability on node A",
        Duration::from_secs(10),
        || {
            db_a.load_shared_state_dag_round(parent_anchor.position.epoch, 1)
                .map(|batches| batches.len() == 3)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "round-1 DAG batch availability on node B",
        Duration::from_secs(10),
        || {
            db_b.load_shared_state_dag_round(parent_anchor.position.epoch, 1)
                .map(|batches| batches.len() == 3)
                .unwrap_or(false)
        },
    )
    .await;
    wait_for_condition(
        "round-1 DAG batch availability on node C",
        Duration::from_secs(10),
        || {
            db_c.load_shared_state_dag_round(parent_anchor.position.epoch, 1)
                .map(|batches| batches.len() == 3)
                .unwrap_or(false)
        },
    )
    .await;

    let leader_id = committee.leader_for(parent_anchor.num + 1);
    let (leader_db, leader_net) = if validator_from_record(identity_a.record(), 1)?.id == leader_id
    {
        (db_a.clone(), net_a.clone())
    } else if validator_from_record(identity_b.record(), 1)?.id == leader_id {
        (db_b.clone(), net_b.clone())
    } else {
        (db_c.clone(), net_c.clone())
    };

    wait_for_condition(
        "round-1 DAG batch availability on leader",
        Duration::from_secs(10),
        || {
            leader_db
                .load_shared_state_dag_round(parent_anchor.position.epoch, 1)
                .map(|batches| batches.len() == 3)
                .unwrap_or(false)
        },
    )
    .await;

    let anchor = leader_net
        .finalize_available_shared_state_anchor()
        .await?
        .expect("finalized shared-state anchor");
    anchor.validate_against_parent(Some(parent_anchor))?;
    assert_eq!(anchor.ordering_path, OrderingPath::DagBftSharedState);

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

    Ok((tx_id, anchor))
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
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    let (_, bootstrap_b) =
        provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    let (_, bootstrap_c) =
        provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

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

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a.clone(), 101),
        (identity_b.clone(), 101),
        (identity_c.clone(), 100),
    ]);
    let genesis = committee.genesis_anchor();
    let validator_a = validator_from_record(identity_a.record(), 101)?;
    let validator_id_b = validator_from_record(identity_b.record(), 101)?.id;
    let validator_id_c = validator_from_record(identity_c.record(), 100)?.id;
    let leader_id = committee.leader_for(genesis.num + 1);
    let leader_bootstrap = if validator_a.id == leader_id {
        bootstrap_a.clone()
    } else if validator_id_b == leader_id {
        bootstrap_b.clone()
    } else {
        bootstrap_c.clone()
    };

    let (db_a, net_a, _) = spawn_test_node(
        &dir_a,
        build_net(
            port_a,
            bootstrap_to_leader(validator_a.id, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_b, net_b, _) = spawn_test_node(
        &dir_b,
        build_net(
            port_b,
            bootstrap_to_leader(validator_id_b, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_c, net_c, _) = spawn_test_node(
        &dir_c,
        build_net(
            port_c,
            bootstrap_to_leader(validator_id_c, leader_id, &leader_bootstrap),
        ),
    )
    .await?;

    wait_for_peers(
        &net_a,
        if validator_a.id == leader_id { 2 } else { 1 },
        "node A",
    )
    .await;
    wait_for_peers(
        &net_b,
        if validator_id_b == leader_id { 2 } else { 1 },
        "node B",
    )
    .await;
    wait_for_peers(
        &net_c,
        if validator_id_c == leader_id { 2 } else { 1 },
        "node C",
    )
    .await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;
    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref(), db_c.as_ref()], &wallet_a, &genesis, &[2])?;

    let action = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: validator_a.id,
        commission_bps: 275,
        metadata: ValidatorMetadata {
            display_name: "deterministic leader".to_string(),
            website: Some("https://leader.unchained.example".to_string()),
            description: Some("qc-collection profile update".to_string()),
        },
    });
    let signable = Tx::shared_state_signing_bytes(db_a.effective_chain_id(), &action)?;
    let tx = finality_support::fee_paid_shared_state_tx(
        db_a.as_ref(),
        &wallet_a,
        action,
        node_identity::sign_with_local_root_in_dir(dir_a.path(), &signable)?,
    )?;
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
    net_a.author_local_shared_state_batch(&batch_a).await?;
    net_b.author_local_shared_state_batch(&batch_b).await?;
    net_c.author_local_shared_state_batch(&batch_c).await?;

    let leader_id = committee.leader_for(1);
    let (leader_db, leader_net) = if validator_from_record(identity_a.record(), 1)?.id == leader_id
    {
        (db_a.clone(), net_a.clone())
    } else if validator_from_record(identity_b.record(), 1)?.id == leader_id {
        (db_b.clone(), net_b.clone())
    } else {
        (db_c.clone(), net_c.clone())
    };

    wait_for_condition(
        "round-1 DAG batch availability on leader",
        Duration::from_secs(10),
        || {
            leader_db
                .load_shared_state_dag_round(genesis.position.epoch, 1)
                .map(|batches| batches.len() == 3)
                .unwrap_or(false)
        },
    )
    .await;

    let anchor = leader_net
        .finalize_available_shared_state_anchor()
        .await?
        .expect("finalized shared-state anchor");
    anchor.validate_against_parent(Some(&genesis))?;
    assert_eq!(anchor.ordering_path, OrderingPath::DagBftSharedState);
    assert!(anchor.qc.votes.len() >= 2);
    assert!(anchor.qc.votes.len() <= 3);
    assert!(
        anchor.qc.signed_voting_power >= genesis.validator_set.quorum_threshold,
        "qc signed voting power {} is below threshold {}",
        anchor.qc.signed_voting_power,
        genesis.validator_set.quorum_threshold
    );

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
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    let (_, bootstrap_b) =
        provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    let (_, bootstrap_c) =
        provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

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

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a.clone(), 101),
        (identity_b.clone(), 101),
        (identity_c.clone(), 100),
    ]);
    let genesis = committee.genesis_anchor();
    let validator_a = validator_from_record(identity_a.record(), 101)?;
    let validator_id_b = validator_from_record(identity_b.record(), 101)?.id;
    let validator_id_c = validator_from_record(identity_c.record(), 100)?.id;
    let leader_id = committee.leader_for(genesis.num + 1);
    let leader_bootstrap = if validator_a.id == leader_id {
        bootstrap_a.clone()
    } else if validator_id_b == leader_id {
        bootstrap_b.clone()
    } else {
        bootstrap_c.clone()
    };

    let (db_a, net_a, _) = spawn_test_node(
        &dir_a,
        build_net(
            port_a,
            bootstrap_to_leader(validator_a.id, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_b, net_b, _) = spawn_test_node(
        &dir_b,
        build_net(
            port_b,
            bootstrap_to_leader(validator_id_b, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_c, net_c, _) = spawn_test_node(
        &dir_c,
        build_net(
            port_c,
            bootstrap_to_leader(validator_id_c, leader_id, &leader_bootstrap),
        ),
    )
    .await?;

    wait_for_peers(
        &net_a,
        if validator_a.id == leader_id { 2 } else { 1 },
        "node A",
    )
    .await;
    wait_for_peers(
        &net_b,
        if validator_id_b == leader_id { 2 } else { 1 },
        "node B",
    )
    .await;
    wait_for_peers(
        &net_c,
        if validator_id_c == leader_id { 2 } else { 1 },
        "node C",
    )
    .await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;
    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref(), db_c.as_ref()], &wallet_a, &genesis, &[2])?;

    let action = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: validator_a.id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "dag frontier validator".to_string(),
            website: Some("https://dag-frontier.unchained.example".to_string()),
            description: Some("ordered shared-state dag frontier update".to_string()),
        },
    });
    let signable = Tx::shared_state_signing_bytes(db_a.effective_chain_id(), &action)?;
    let tx = finality_support::fee_paid_shared_state_tx(
        db_a.as_ref(),
        &wallet_a,
        action,
        node_identity::sign_with_local_root_in_dir(dir_a.path(), &signable)?,
    )?;
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
    for db in [&db_a, &db_b, &db_c] {
        let pool = db
            .load_validator_pool(&validator_a.id)?
            .expect("updated validator pool");
        assert_eq!(pool.commission_bps, 325);
        assert_eq!(pool.metadata.display_name, "dag frontier validator");
    }

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_bootstrap_anchor_recovery_and_proof_roundtrip() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        finality_support::proof_fixture_dir(),
    );

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
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;
    let committee = finality_support::TestCommittee::single_validator();
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
    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref(), db_c.as_ref()], &wallet_a, &genesis, &[2])?;
    let dummy_action = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: genesis.validator_set.validators[0].id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "bootstrap validator".to_string(),
            website: Some("https://bootstrap.example".to_string()),
            description: Some("bootstrap-recovered validator".to_string()),
        },
    });
    let ordinary =
        finality_support::fee_payment_transfer_for_action(db_a.as_ref(), &wallet_a, &dummy_action)?;
    let tx = Tx::OrdinaryPrivateTransfer(ordinary);
    let tx_id = net_a.submit_tx(&tx).await?;
    let batch = net_a
        .select_pending_fast_path_batch()?
        .expect("pending fast-path batch");
    assert_eq!(batch.ordered_tx_count()?, 1);
    net_a.publish_fast_path_batch(&batch).await?;
    let anchor1 = committee.anchor(
        1,
        Some(&genesis),
        batch.ordered_tx_root,
        batch.ordered_tx_count()?,
        OrderingPath::FastPathPrivateTransfer,
    );
    store_anchor(db_a.as_ref(), &anchor1)?;
    net_a.gossip_anchor(&anchor1).await;

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
    assert!(db_b.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_c.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_b.load_fast_path_batch(&batch.ordered_tx_root)?.is_some());
    assert!(db_c.load_fast_path_batch(&batch.ordered_tx_root)?.is_some());

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_finalizes_fee_paid_profile_update_from_fresh_wallet() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(false);

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
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    let (_, bootstrap_b) =
        provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    let (_, bootstrap_c) =
        provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

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

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a.clone(), 101),
        (identity_b.clone(), 101),
        (identity_c.clone(), 100),
    ]);
    let genesis = committee.genesis_anchor();
    let (pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;

    let validator_id_a = validator_from_record(identity_a.record(), 1)?.id;
    let validator_id_b = validator_from_record(identity_b.record(), 1)?.id;
    let validator_id_c = validator_from_record(identity_c.record(), 1)?.id;
    let leader_id = committee.leader_for(genesis.num + 1);
    let leader_bootstrap = if validator_id_a == leader_id {
        bootstrap_a.clone()
    } else if validator_id_b == leader_id {
        bootstrap_b.clone()
    } else {
        bootstrap_c.clone()
    };

    let (db_a, net_a, _) = spawn_test_node(
        &dir_a,
        build_net(
            port_a,
            bootstrap_to_leader(validator_id_a, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_b, net_b, _) = spawn_test_node(
        &dir_b,
        build_net(
            port_b,
            bootstrap_to_leader(validator_id_b, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_c, net_c, _) = spawn_test_node(
        &dir_c,
        build_net(
            port_c,
            bootstrap_to_leader(validator_id_c, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    network::set_quiet_logging(false);

    wait_for_peers(
        &net_a,
        if validator_id_a == leader_id { 2 } else { 1 },
        "node A",
    )
    .await;
    wait_for_peers(
        &net_b,
        if validator_id_b == leader_id { 2 } else { 1 },
        "node B",
    )
    .await;
    wait_for_peers(
        &net_c,
        if validator_id_c == leader_id { 2 } else { 1 },
        "node C",
    )
    .await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;
    db_a.store_validator_pool(&pool)?;
    db_b.store_validator_pool(&pool)?;
    db_c.store_validator_pool(&pool)?;

    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref(), db_c.as_ref()], &wallet_a, &genesis, &[2])?;
    let update = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: pool.validator.id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "deterministic validator".to_string(),
            website: Some("https://deterministic.example".to_string()),
            description: Some("deterministic fresh-wallet profile update".to_string()),
        },
    });
    let tx = signed_shared_state_tx(db_a.as_ref(), &wallet_a, update, &cold_key)?;
    let (tx_id, _anchor) = finalize_single_shared_state_action(
        &genesis,
        &committee,
        &identity_a,
        &identity_b,
        &identity_c,
        &db_a,
        &db_b,
        &db_c,
        &net_a,
        &net_b,
        &net_c,
        &tx,
    )
    .await?;

    assert!(db_a.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_b.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_c.get_raw_bytes("tx", &tx_id)?.is_some());
    for db in [&db_a, &db_b, &db_c] {
        let stored = db
            .load_validator_pool(&pool.validator.id)?
            .expect("updated validator pool");
        assert_eq!(stored.commission_bps, 325);
        assert_eq!(stored.metadata.display_name, "deterministic validator");
        assert_eq!(
            stored.metadata.website.as_deref(),
            Some("https://deterministic.example")
        );
    }

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_finalizes_fee_paid_reactivation_from_fresh_wallet() -> anyhow::Result<()> {
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
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    let (_, bootstrap_b) =
        provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    let (_, bootstrap_c) =
        provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

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

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a.clone(), 101),
        (identity_b.clone(), 101),
        (identity_c.clone(), 100),
    ]);
    let genesis = committee.genesis_anchor();
    let (base_pool, cold_key) = build_pending_validator_pool(9, genesis.position.epoch + 1)?;
    let jailed_pool = ValidatorPool {
        activation_epoch: genesis.position.epoch,
        status: ValidatorStatus::Jailed,
        accountability: ValidatorAccountability {
            liveness_faults: PROTOCOL.liveness_fault_jail_threshold,
            safety_faults: 0,
            jailed_until_epoch: Some(genesis.position.epoch),
        },
        ..base_pool
    };
    jailed_pool.validate()?;

    let validator_id_a = validator_from_record(identity_a.record(), 1)?.id;
    let validator_id_b = validator_from_record(identity_b.record(), 1)?.id;
    let validator_id_c = validator_from_record(identity_c.record(), 1)?.id;
    let leader_id = committee.leader_for(genesis.num + 1);
    let leader_bootstrap = if validator_id_a == leader_id {
        bootstrap_a.clone()
    } else if validator_id_b == leader_id {
        bootstrap_b.clone()
    } else {
        bootstrap_c.clone()
    };

    let (db_a, net_a, _) = spawn_test_node(
        &dir_a,
        build_net(
            port_a,
            bootstrap_to_leader(validator_id_a, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_b, net_b, _) = spawn_test_node(
        &dir_b,
        build_net(
            port_b,
            bootstrap_to_leader(validator_id_b, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_c, net_c, _) = spawn_test_node(
        &dir_c,
        build_net(
            port_c,
            bootstrap_to_leader(validator_id_c, leader_id, &leader_bootstrap),
        ),
    )
    .await?;

    wait_for_peers(
        &net_a,
        if validator_id_a == leader_id { 2 } else { 1 },
        "node A",
    )
    .await;
    wait_for_peers(
        &net_b,
        if validator_id_b == leader_id { 2 } else { 1 },
        "node B",
    )
    .await;
    wait_for_peers(
        &net_c,
        if validator_id_c == leader_id { 2 } else { 1 },
        "node C",
    )
    .await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;
    db_a.store_validator_pool(&jailed_pool)?;
    db_b.store_validator_pool(&jailed_pool)?;
    db_c.store_validator_pool(&jailed_pool)?;

    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref(), db_c.as_ref()], &wallet_a, &genesis, &[2])?;
    let tx = signed_shared_state_tx(
        db_a.as_ref(),
        &wallet_a,
        SharedStateAction::ReactivateValidator(ValidatorReactivation {
            validator_id: jailed_pool.validator.id,
        }),
        &cold_key,
    )?;
    let (tx_id, _anchor) = finalize_single_shared_state_action(
        &genesis,
        &committee,
        &identity_a,
        &identity_b,
        &identity_c,
        &db_a,
        &db_b,
        &db_c,
        &net_a,
        &net_b,
        &net_c,
        &tx,
    )
    .await?;

    assert!(db_a.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_b.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_c.get_raw_bytes("tx", &tx_id)?.is_some());
    for db in [&db_a, &db_b, &db_c] {
        let stored = db
            .load_validator_pool(&jailed_pool.validator.id)?
            .expect("reactivated validator pool");
        assert_eq!(stored.status, ValidatorStatus::PendingActivation);
        assert_eq!(stored.activation_epoch, genesis.position.epoch + 1);
        assert_eq!(
            stored.accountability.liveness_faults,
            jailed_pool.accountability.liveness_faults
        );
        assert_eq!(stored.accountability.jailed_until_epoch, None);
    }

    net_a.shutdown().await;
    net_b.shutdown().await;
    net_c.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pq_network_finalizes_fee_paid_penalty_admission_from_fresh_wallet() -> anyhow::Result<()> {
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
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    let (_, bootstrap_b) =
        provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;
    let (_, bootstrap_c) =
        provision_deterministic_runtime_identity(&dir_c, Some(chain_id), vec![addr_c.clone()], 2)?;

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

    let committee = finality_support::TestCommittee::from_weighted_identities(vec![
        (identity_a.clone(), 101),
        (identity_b.clone(), 101),
        (identity_c.clone(), 100),
    ]);
    let genesis = committee.genesis_anchor();

    let validator_id_a = validator_from_record(identity_a.record(), 1)?.id;
    let validator_id_b = validator_from_record(identity_b.record(), 1)?.id;
    let validator_id_c = validator_from_record(identity_c.record(), 1)?.id;
    let leader_id = committee.leader_for(genesis.num + 1);
    let leader_bootstrap = if validator_id_a == leader_id {
        bootstrap_a.clone()
    } else if validator_id_b == leader_id {
        bootstrap_b.clone()
    } else {
        bootstrap_c.clone()
    };

    let (db_a, net_a, _) = spawn_test_node(
        &dir_a,
        build_net(
            port_a,
            bootstrap_to_leader(validator_id_a, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_b, net_b, _) = spawn_test_node(
        &dir_b,
        build_net(
            port_b,
            bootstrap_to_leader(validator_id_b, leader_id, &leader_bootstrap),
        ),
    )
    .await?;
    let (db_c, net_c, _) = spawn_test_node(
        &dir_c,
        build_net(
            port_c,
            bootstrap_to_leader(validator_id_c, leader_id, &leader_bootstrap),
        ),
    )
    .await?;

    wait_for_peers(
        &net_a,
        if validator_id_a == leader_id { 2 } else { 1 },
        "node A",
    )
    .await;
    wait_for_peers(
        &net_b,
        if validator_id_b == leader_id { 2 } else { 1 },
        "node B",
    )
    .await;
    wait_for_peers(
        &net_c,
        if validator_id_c == leader_id { 2 } else { 1 },
        "node C",
    )
    .await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_c.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    store_anchor(db_c.as_ref(), &genesis)?;

    let anchor1 = finalized_fast_path_anchor_from_identities(
        1,
        Some(&genesis),
        &genesis.validator_set,
        &[&identity_a, &identity_b],
    )?;
    store_anchor(db_a.as_ref(), &anchor1)?;
    store_anchor(db_b.as_ref(), &anchor1)?;
    store_anchor(db_c.as_ref(), &anchor1)?;

    let slashed_validator = validator_from_record(identity_c.record(), 100)?;
    let original_pool = db_a
        .load_validator_pool(&slashed_validator.id)?
        .expect("validator C pool before penalty");
    let fault = LivenessFaultProof::new_missed_vote(&anchor1, slashed_validator.id)?;

    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref(), db_c.as_ref()], &wallet_a, &genesis, &[2])?;
    let evidence_id = SlashableEvidence::Liveness(fault.clone()).evidence_id()?;
    let tx = finality_support::fee_paid_shared_state_tx(
        db_a.as_ref(),
        &wallet_a,
        SharedStateAction::AdmitPenaltyEvidence(PenaltyEvidenceAdmission {
            evidence: SlashableEvidence::Liveness(fault.clone()),
        }),
        Vec::new(),
    )?;
    let (tx_id, anchor) = finalize_single_shared_state_action(
        &anchor1,
        &committee,
        &identity_a,
        &identity_b,
        &identity_c,
        &db_a,
        &db_b,
        &db_c,
        &net_a,
        &net_b,
        &net_c,
        &tx,
    )
    .await?;

    assert!(db_a.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_b.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_c.get_raw_bytes("tx", &tx_id)?.is_some());
    for db in [&db_a, &db_b, &db_c] {
        let stored = db
            .load_validator_pool(&slashed_validator.id)?
            .expect("slashed validator pool");
        let penalty_event = db
            .load_validator_penalty_event(&evidence_id)?
            .expect("stored validator penalty event");
        let reward_event = db
            .load_validator_reward_events_for_anchor(anchor.num)?
            .into_iter()
            .find(|event| event.validator_id == slashed_validator.id)
            .expect("stored slashed validator reward event");
        assert_eq!(
            penalty_event.bonded_stake_before,
            original_pool.total_bonded_stake
        );
        assert_eq!(
            penalty_event.bonded_stake_after,
            original_pool.total_bonded_stake - 1
        );
        assert_eq!(
            stored.total_bonded_stake,
            penalty_event
                .bonded_stake_after
                .checked_add(reward_event.gross_reward)
                .expect("slashed validator reward overflow")
        );
        assert_eq!(stored.status, ValidatorStatus::Active);
        assert_eq!(stored.accountability.liveness_faults, 1);
        assert_eq!(stored.accountability.jailed_until_epoch, None);
        assert_eq!(penalty_event.resulting_status, ValidatorStatus::Active);
        assert_eq!(
            penalty_event.resulting_accountability,
            stored.accountability
        );
        assert_eq!(reward_event.suppression_reason, None);
    }

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
    let bootstrap_record_a = node_identity::NodeRecordV3::decode_compact(&bootstrap_a)?;

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
    std::env::set_var(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        finality_support::proof_fixture_dir(),
    );

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let port_a = pick_udp_port();
    let port_b = pick_udp_port();
    let addr_a = format!("127.0.0.1:{port_a}");
    let addr_b = format!("127.0.0.1:{port_b}");
    let chain_id = protocol_chain_id();
    let (_, bootstrap_a) =
        provision_deterministic_runtime_identity(&dir_a, Some(chain_id), vec![addr_a.clone()], 0)?;
    provision_deterministic_runtime_identity(&dir_b, Some(chain_id), vec![addr_b.clone()], 1)?;

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = committee.genesis_anchor();

    let (db_a, net_a, _) = spawn_test_node(&dir_a, build_net(port_a, vec![])).await?;
    let (db_b, net_b, _) =
        spawn_test_node(&dir_b, build_net(port_b, vec![bootstrap_a.clone()])).await?;

    wait_for_peers(&net_a, 1, "node A before partition").await;
    wait_for_peers(&net_b, 1, "node B before partition").await;

    committee.seed_validator_state(db_a.as_ref(), genesis.position.epoch)?;
    committee.seed_validator_state(db_b.as_ref(), genesis.position.epoch)?;
    store_anchor(db_a.as_ref(), &genesis)?;
    store_anchor(db_b.as_ref(), &genesis)?;
    let wallet_a = build_single_action_fee_wallet(&dir_a, db_a.as_ref(), &genesis)?;
    mirror_wallet_coin_state(&[db_b.as_ref()], &wallet_a, &genesis, &[2])?;

    net_b.shutdown().await;
    db_b.close()?;
    drop(db_b);
    drop(net_b);

    let dummy_action = SharedStateAction::UpdateValidatorProfile(ValidatorProfileUpdate {
        validator_id: genesis.validator_set.validators[0].id,
        commission_bps: 325,
        metadata: ValidatorMetadata {
            display_name: "rejoin proof".to_string(),
            website: Some("https://rejoin.example".to_string()),
            description: Some("rejoined fast-path proof roundtrip".to_string()),
        },
    });
    let ordinary =
        finality_support::fee_payment_transfer_for_action(db_a.as_ref(), &wallet_a, &dummy_action)?;
    let tx = Tx::OrdinaryPrivateTransfer(ordinary);
    let tx_id = net_a.submit_tx(&tx).await?;
    let batch = net_a
        .select_pending_fast_path_batch()?
        .expect("pending fast-path batch");
    assert_eq!(batch.ordered_tx_count()?, 1);
    net_a.publish_fast_path_batch(&batch).await?;
    let anchor1 = committee.anchor(
        1,
        Some(&genesis),
        batch.ordered_tx_root,
        batch.ordered_tx_count()?,
        OrderingPath::FastPathPrivateTransfer,
    );
    store_anchor(db_a.as_ref(), &anchor1)?;

    let (db_b_rejoin, net_b_rejoin, _) = spawn_test_node(&dir_b, build_net(port_b, vec![])).await?;

    wait_for_peers(&net_a, 1, "node A after rejoin").await;
    wait_for_peers(&net_b_rejoin, 1, "node B after rejoin").await;

    let mut anchor_rx = net_b_rejoin.anchor_subscribe();
    net_a.gossip_anchor(&anchor1).await;
    net_b_rejoin.request_latest_epoch().await;
    let adopted_anchor1 = wait_for_anchor(&mut anchor_rx, anchor1.hash).await;
    assert_eq!(adopted_anchor1.hash, anchor1.hash);
    wait_for_condition("rejoined anchor1 adoption", Duration::from_secs(10), || {
        db_b_rejoin
            .get_raw_bytes("tx", &tx_id)
            .ok()
            .flatten()
            .is_some()
    })
    .await;

    wait_for_condition(
        "rejoined latest anchor adoption",
        Duration::from_secs(10),
        || {
            db_b_rejoin
                .get::<Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|anchor| anchor.hash == anchor1.hash)
                .unwrap_or(false)
        },
    )
    .await;
    assert!(db_b_rejoin.get_raw_bytes("tx", &tx_id)?.is_some());
    assert!(db_b_rejoin
        .load_fast_path_batch(&batch.ordered_tx_root)?
        .is_some());

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
    let victim_record = node_identity::NodeRecordV3::decode_compact(&bootstrap_victim)?;

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
