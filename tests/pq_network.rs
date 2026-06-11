mod finality_support;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::Endpoint;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, LazyLock as Lazy, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tokio::time::{sleep, Instant};
use unchained::epoch::Anchor;
use unchained::network::{self, NetHandle};
use unchained::node_identity::{self, NodeIdentity};
use unchained::proof;
use unchained::protocol::CURRENT as PROTOCOL;
use unchained::runtime_profile::NetworkProfile;
use unchained::shielded::{
    local_archive_provider_manifest, local_archive_replica_attestations, route_checkpoint_requests,
    ArchiveDirectory, ArchivedNullifierEpoch, CheckpointExtensionRequest, EvolvingNullifierQuery,
    HistoricalUnspentCheckpoint, NullifierRootLedger,
};
use unchained::storage::{protocol_chain_id, Store};
use unchained::sync::SyncState;
use unchained::transaction;
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

fn build_single_action_fee_wallet(
    tempdir: &TempDir,
    store: &Store,
    genesis: &Anchor,
) -> anyhow::Result<Wallet> {
    std::env::set_var("WALLET_PASSPHRASE", "pq-network-passphrase");
    let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let wallet = finality_support::deterministic_wallet(wallet_store)?;
    let _ =
        finality_support::seed_wallet_with_settlement_unit_values(store, &wallet, genesis, &[2])?;
    Ok(wallet)
}

fn build_net(port: u16, bootstrap: Vec<String>) -> NetworkProfile {
    NetworkProfile {
        listen_port: port,
        bootstrap,
        trust_updates: Vec::new(),
        public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()),
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
    net_cfg: NetworkProfile,
) -> anyhow::Result<(Arc<Store>, NetHandle, Arc<Mutex<SyncState>>)> {
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let net = network::spawn(net_cfg, db.clone(), sync_state.clone()).await?;
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
async fn deterministic_multivalidator_fee_paid_control_witness_digest_stays_stable(
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
    let witness_digest = proof::shielded_tx_witness_digest(prepared.witness())?;
    assert_eq!(
        hex::encode(witness_digest),
        "97c45043894c3b4752e3e3e6a68f980f8510a0731acc4317afee8e45daa6ba2f"
    );
    let err = proof::prove_shielded_tx(prepared.witness())
        .expect_err("native proof backend is intentionally absent");
    assert!(err
        .to_string()
        .contains("native transparent proof backend is not implemented"));

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
        Duration::from_secs(30),
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
