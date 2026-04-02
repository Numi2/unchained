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
use unchained::consensus::{DEFAULT_MEM_KIB, TARGET_LEADING_ZEROS};
use unchained::crypto::TaggedSigningPublicKey;
use unchained::epoch::{Anchor, MerkleTree};
use unchained::network::{self, NetHandle};
use unchained::node_identity;
use unchained::protocol::CURRENT as PROTOCOL;
use unchained::shielded::{
    local_archive_provider_manifest, local_archive_replica_attestations, route_checkpoint_requests,
    ArchiveDirectory, ArchivedNullifierEpoch, CheckpointExtensionRequest, EvolvingNullifierQuery,
    HistoricalUnspentCheckpoint, NullifierRootLedger,
};
use unchained::storage::Store;
use unchained::sync::SyncState;
use unchained::transaction;

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

fn genesis_anchor() -> Anchor {
    let merkle_root = [0u8; 32];
    let hash = *blake3::hash(&merkle_root).as_bytes();
    Anchor {
        num: 0,
        hash,
        merkle_root,
        difficulty: TARGET_LEADING_ZEROS,
        coin_count: 0,
        cumulative_work: Anchor::expected_work_for_difficulty(TARGET_LEADING_ZEROS),
        mem_kib: DEFAULT_MEM_KIB,
    }
}

fn next_anchor(prev: &Anchor, merkle_root: [u8; 32], coin_count: u32) -> Anchor {
    let num = prev.num + 1;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&merkle_root);
    hasher.update(&prev.hash);
    let hash = *hasher.finalize().as_bytes();
    Anchor {
        num,
        hash,
        merkle_root,
        difficulty: prev.difficulty,
        coin_count,
        cumulative_work: prev
            .cumulative_work
            .saturating_add(Anchor::expected_work_for_difficulty(prev.difficulty)),
        mem_kib: prev.mem_kib,
    }
}

fn seed_genesis(store: &Store) -> anyhow::Result<Anchor> {
    let genesis = genesis_anchor();
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
}

fn store_anchor(store: &Store, anchor: &Anchor) -> anyhow::Result<()> {
    store.put("epoch", &anchor.num.to_le_bytes(), anchor)?;
    store.put("epoch", b"latest", anchor)?;
    store.put("anchor", &anchor.hash, anchor)?;
    Ok(())
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
async fn pq_network_bootstrap_anchor_recovery_and_proof_roundtrip() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);

    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let dir_c = TempDir::new()?;

    let db_a_seed = Store::open(&dir_a.path().to_string_lossy())?;
    let db_b_seed = Store::open(&dir_b.path().to_string_lossy())?;
    let db_c_seed = Store::open(&dir_c.path().to_string_lossy())?;

    let genesis = seed_genesis(&db_a_seed)?;
    seed_genesis(&db_b_seed)?;
    seed_genesis(&db_c_seed)?;

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

    let anchor1 = next_anchor(&genesis, [0u8; 32], 0);
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
    let genesis = seed_genesis(&db_a_seed)?;
    seed_genesis(&db_b_seed)?;

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
    let genesis = seed_genesis(&db_a_seed)?;
    seed_genesis(&db_b_seed)?;

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

    let anchor1 = next_anchor(&genesis, [0u8; 32], 0);
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
    let genesis = seed_genesis(&db_seed)?;
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
    let genesis = seed_genesis(&db_a_seed)?;
    seed_genesis(&db_b_seed)?;

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
    let genesis = seed_genesis(&db_a_seed)?;
    seed_genesis(&db_b_seed)?;

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
            route_checkpoint_requests(
                &directory,
                &[CheckpointExtensionRequest {
                    checkpoint: checkpoint.clone(),
                    queries: vec![EvolvingNullifierQuery {
                        epoch: 1,
                        nullifier: [44u8; 32],
                    }],
                }],
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
            &[CheckpointExtensionRequest {
                checkpoint: checkpoint.clone(),
                queries: vec![EvolvingNullifierQuery {
                    epoch: 1,
                    nullifier: [44u8; 32],
                }],
            }],
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
