mod finality_support;

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use unchained::{
    config::{Net, P2p},
    epoch::Anchor,
    network, node_control, node_identity,
    protocol::CURRENT as PROTOCOL,
    storage::{Store, WalletStore},
    sync::SyncState,
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

fn child_anchor(committee: &finality_support::TestCommittee, parent: &Anchor) -> Anchor {
    let num = parent.num.saturating_add(1);
    let merkle_root = [num as u8; 32];
    committee.child_anchor(parent, merkle_root, 0)
}

fn seed_genesis(store: &Store, committee: &finality_support::TestCommittee) -> Result<Anchor> {
    let genesis = committee.genesis_anchor();
    committee.seed_validator_state(store, genesis.position.epoch)?;
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
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
async fn node_control_serves_consensus_status() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "node-control-test-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let _wallet_db = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;

    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let server = node_control::NodeControlServer::bind(
        &tempdir.path().to_string_lossy(),
        db.clone(),
        net.clone(),
        sync_state,
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
    let status = client.consensus_status()?;
    assert!(status.settlement_ready);
    assert_eq!(status.local_tip, genesis.num);
    assert_eq!(
        status
            .active_validator_set
            .as_ref()
            .map(|validator_set| validator_set.epoch),
        Some(genesis.position.epoch)
    );
    assert_eq!(status.registered_validator_pools.len(), 1);
    assert_eq!(
        status
            .latest_finalized_anchor
            .as_ref()
            .map(|anchor| anchor.hash),
        Some(genesis.hash)
    );

    let next_anchor = child_anchor(&committee, &genesis);
    db.put("epoch", &next_anchor.num.to_le_bytes(), &next_anchor)?;
    db.put("epoch", b"latest", &next_anchor)?;
    db.put("anchor", &next_anchor.hash, &next_anchor)?;

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
    assert_eq!(
        updated_state.state.consensus_status.local_tip,
        next_anchor.num
    );
    assert_eq!(
        updated_state
            .state
            .consensus_status
            .latest_finalized_anchor
            .as_ref()
            .map(|anchor| anchor.hash),
        Some(next_anchor.hash)
    );

    std::fs::write(&capability_path, [0u8; 32])?;
    assert!(client.ping().is_err());

    let _ = shutdown_tx.send(());
    server_task.await??;
    net.shutdown().await;
    Ok(())
}
