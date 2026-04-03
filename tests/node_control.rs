use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{timeout, Duration};
use unchained::{
    coin::CoinCandidate,
    config::{Net, P2p},
    consensus::{DEFAULT_MEM_KIB, TARGET_LEADING_ZEROS},
    epoch::Anchor,
    network, node_control, node_identity,
    protocol::CURRENT as PROTOCOL,
    storage::{Store, WalletStore},
    sync::SyncState,
    wallet::Wallet,
};

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

fn child_anchor(parent: &Anchor) -> Anchor {
    let num = parent.num.saturating_add(1);
    let merkle_root = [num as u8; 32];
    let hash = *blake3::hash(&[parent.hash.as_slice(), merkle_root.as_slice()].concat()).as_bytes();
    Anchor {
        num,
        hash,
        merkle_root,
        difficulty: parent.difficulty,
        coin_count: 0,
        cumulative_work: parent
            .cumulative_work
            .saturating_add(Anchor::expected_work_for_difficulty(parent.difficulty)),
        mem_kib: parent.mem_kib,
    }
}

fn seed_genesis(store: &Store) -> Result<Anchor> {
    let genesis = genesis_anchor();
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
}

fn mark_epoch_selected(store: &Store, epoch_num: u64, coin_ids: &[[u8; 32]]) -> Result<()> {
    let sel_cf = store
        .db
        .cf_handle("epoch_selected")
        .expect("epoch_selected column family");
    for coin_id in coin_ids {
        let mut key = Vec::with_capacity(8 + 32);
        key.extend_from_slice(&epoch_num.to_le_bytes());
        key.extend_from_slice(coin_id);
        store.db.put_cf(sel_cf, key, [])?;
    }
    Ok(())
}

fn provision_runtime_identity(
    tempdir: &TempDir,
    chain_id: [u8; 32],
    address: String,
) -> Result<()> {
    let _ = node_identity::init_root_in_dir(tempdir.path())?;
    let (_, request) = node_identity::prepare_auth_request_in_dir(
        tempdir.path(),
        PROTOCOL.version,
        Some(chain_id),
        vec![address],
        None,
    )?;
    let (_, record) = node_identity::sign_auth_request_in_dir(tempdir.path(), &request, 30)?;
    let _ = node_identity::install_node_record_in_dir(tempdir.path(), &record)?;
    Ok(())
}

async fn spawn_network(
    tempdir: &TempDir,
    db: Arc<Store>,
    genesis: &Anchor,
) -> Result<unchained::network::NetHandle> {
    let port = pick_udp_port();
    provision_runtime_identity(tempdir, genesis.hash, format!("127.0.0.1:{port}"))?;
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    network::spawn(build_net(port), build_p2p(), db, sync_state).await
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_control_serves_mining_work_and_accepts_candidates() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "node-control-test-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let wallet_db = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let wallet = Wallet::load_or_create_private(wallet_db)?;
    let genesis = seed_genesis(db.as_ref())?;
    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;

    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let (coin_tx, mut coin_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let server = node_control::NodeControlServer::bind(
        &tempdir.path().to_string_lossy(),
        db.clone(),
        net.clone(),
        sync_state,
        coin_tx,
        false,
    )
    .await?;
    let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

    let client = node_control::NodeControlClient::new(&tempdir.path().to_string_lossy());
    client.ping()?;
    let mut state_rx = client.subscribe_state()?;
    let initial_state = timeout(Duration::from_secs(2), async {
        loop {
            if let Some(state) = state_rx.borrow().clone() {
                return Ok::<_, anyhow::Error>(state);
            }
            state_rx.changed().await?;
        }
    })
    .await??;
    let capability_path =
        node_control::node_control_capability_path(&tempdir.path().to_string_lossy());
    assert!(capability_path.exists());
    let work = client.mining_work()?;
    assert!(work.mining_ready);
    assert_eq!(work.local_tip, genesis.num);
    assert_eq!(
        work.latest_anchor.as_ref().map(|anchor| anchor.hash),
        Some(genesis.hash)
    );

    let candidate = CoinCandidate::new(
        genesis.hash,
        7,
        wallet.address(),
        wallet.public_key().clone(),
        [9u8; 32],
        [0u8; 32],
    );
    let accepted_id = client.submit_coin_candidate(&candidate)?;
    assert_eq!(accepted_id, candidate.id);

    let forwarded_id = timeout(Duration::from_secs(2), coin_rx.recv())
        .await?
        .expect("coin id forwarded");
    assert_eq!(forwarded_id, candidate.id);

    let stored = db
        .get::<CoinCandidate>(
            "coin_candidate",
            &Store::candidate_key(&candidate.epoch_hash, &candidate.id),
        )?
        .expect("candidate persisted");
    assert_eq!(stored.id, candidate.id);

    let next_anchor = child_anchor(&genesis);
    db.put("epoch", &next_anchor.num.to_le_bytes(), &next_anchor)?;
    db.put("epoch", b"latest", &next_anchor)?;
    db.put("anchor", &next_anchor.hash, &next_anchor)?;
    mark_epoch_selected(db.as_ref(), next_anchor.num, &[candidate.id])?;

    let updated_state = timeout(Duration::from_secs(2), async {
        loop {
            state_rx.changed().await?;
            if let Some(state) = state_rx.borrow_and_update().clone() {
                if state.sequence > initial_state.sequence {
                    return Ok::<_, anyhow::Error>(state);
                }
            }
        }
    })
    .await??;
    assert_eq!(updated_state.state.mining_work.local_tip, next_anchor.num);
    assert_eq!(
        updated_state
            .state
            .mining_work
            .latest_anchor
            .as_ref()
            .map(|anchor| anchor.hash),
        Some(next_anchor.hash)
    );
    let finalized = updated_state
        .state
        .mining_work
        .recent_finalized_selections
        .iter()
        .find(|selection| selection.anchor_epoch == next_anchor.num)
        .expect("latest finalized selection carried in stream");
    assert_eq!(finalized.candidate_epoch, genesis.num);
    assert_eq!(finalized.coin_ids, vec![candidate.id]);

    std::fs::write(&capability_path, [0u8; 32])?;
    assert!(client.ping().is_err());

    let _ = shutdown_tx.send(());
    server_task.await??;
    net.shutdown().await;
    Ok(())
}
