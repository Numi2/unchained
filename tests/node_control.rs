mod finality_support;

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use unchained::{
    config::{Net, P2p},
    consensus::{ConsensusPosition, OrderingPath, ValidatorVote, VoteTarget},
    crypto::ML_KEM_768_CT_BYTES,
    epoch::Anchor,
    evidence, network, node_control, node_identity,
    protocol::CURRENT as PROTOCOL,
    staking::ValidatorRewardEvent,
    storage::{Store, WalletStore},
    sync::SyncState,
    transaction::{self, ShieldedOutput},
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
        strict_trust: false,
        peer_exchange: true,
        max_peers: 8,
        connection_timeout_secs: 5,
        idle_timeout_secs: 30,
        keep_alive_interval_secs: 2,
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

fn mutate_shielded_note_tree(store: &Store, commitment: [u8; 32]) -> Result<()> {
    let mut tree = store.load_shielded_note_tree()?.unwrap_or_default();
    tree.append(commitment)?;
    store.store_shielded_note_tree(&tree)?;
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
    assert_eq!(status.consensus_evidence_count, 0);
    assert!(status.recent_consensus_evidence.is_empty());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_control_streams_compact_wallet_state_only() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "node-control-compact-passphrase");
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
    let initial_runtime = client.shielded_runtime_snapshot()?;

    mutate_shielded_note_tree(db.as_ref(), [0xabu8; 32])?;
    let advanced_runtime = client.shielded_runtime_snapshot()?;
    assert_ne!(
        advanced_runtime.note_tree.root(),
        initial_runtime.note_tree.root()
    );
    assert!(
        timeout(Duration::from_millis(600), state_rx.changed())
            .await
            .is_err(),
        "compact wallet state stream should ignore note-tree-only changes"
    );
    assert_eq!(
        client.state()?.state.compact_wallet_sync,
        initial_state.state.compact_wallet_sync
    );

    let _ = shutdown_tx.send(());
    server_task.await??;
    net.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_control_serves_compact_wallet_sync_deltas_by_cursor() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "node-control-delta-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let wallet = Wallet::load_or_create_private(wallet_store)?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let seeded_coins =
        finality_support::seed_wallet_with_coin_values(db.as_ref(), &wallet, &genesis, &[11, 13])?;
    let mut expected_coins = seeded_coins.clone();
    expected_coins.sort_by(|a, b| a.id.cmp(&b.id));
    transaction::ensure_shielded_runtime_state(db.as_ref())?;
    let first_output = ShieldedOutput {
        note_commitment: [0x11u8; 32],
        kem_ct: [0x22u8; ML_KEM_768_CT_BYTES],
        nonce: [0x33u8; 24],
        view_tag: 7,
        ciphertext: vec![0x44u8; 8],
    };
    let second_output = ShieldedOutput {
        note_commitment: [0x55u8; 32],
        kem_ct: [0x66u8; ML_KEM_768_CT_BYTES],
        nonce: [0x77u8; 24],
        view_tag: 9,
        ciphertext: vec![0x88u8; 12],
    };
    db.store_shielded_output(&[0x01u8; 32], 0, &first_output)?;
    db.store_shielded_output(&[0x02u8; 32], 1, &second_output)?;

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
    let head = client.compact_wallet_sync_head()?;
    assert_eq!(head.chain_id, genesis.hash);
    assert_eq!(head.committed_coin_count, 2);
    assert_eq!(head.shielded_output_count, 2);

    let first_delta = client.request_compact_wallet_sync_delta(0, 0, 1, 1)?;
    assert_eq!(first_delta.head, head);
    assert_eq!(first_delta.committed_coins.len(), 1);
    assert_eq!(first_delta.committed_coins[0].scan_index, 0);
    assert_eq!(first_delta.committed_coins[0].coin.id, expected_coins[0].id);
    assert_eq!(
        first_delta.committed_coins[0].coin.value,
        expected_coins[0].value
    );
    assert_eq!(first_delta.shielded_outputs.len(), 1);
    assert_eq!(first_delta.shielded_outputs[0].scan_index, 0);
    assert_eq!(
        first_delta.shielded_outputs[0].note_commitment,
        first_output.note_commitment
    );
    assert_eq!(
        first_delta.shielded_outputs[0].detection_tag,
        first_output.view_tag
    );

    let second_delta = client.request_compact_wallet_sync_delta(1, 1, 4, 4)?;
    assert_eq!(second_delta.head, head);
    assert_eq!(second_delta.committed_coins.len(), 1);
    assert_eq!(second_delta.committed_coins[0].scan_index, 1);
    assert_eq!(
        second_delta.committed_coins[0].coin.id,
        expected_coins[1].id
    );
    assert_eq!(
        second_delta.committed_coins[0].coin.value,
        expected_coins[1].value
    );
    assert_eq!(second_delta.shielded_outputs.len(), 1);
    assert_eq!(second_delta.shielded_outputs[0].scan_index, 1);
    assert_eq!(
        second_delta.shielded_outputs[0].note_commitment,
        second_output.note_commitment
    );
    assert_eq!(
        second_delta.shielded_outputs[0].detection_tag,
        second_output.view_tag
    );

    let empty_delta = client.request_compact_wallet_sync_delta(2, 2, 4, 4)?;
    assert_eq!(empty_delta.head, head);
    assert!(empty_delta.committed_coins.is_empty());
    assert!(empty_delta.shielded_outputs.is_empty());

    let _ = shutdown_tx.send(());
    server_task.await??;
    net.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_control_surfaces_recent_consensus_evidence() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "node-control-evidence-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let _wallet_db = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let validator = committee
        .validator_set_for_epoch(genesis.position.epoch)
        .validators[0]
        .clone();
    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;

    let first_vote = ValidatorVote {
        voter: validator.id,
        target: VoteTarget {
            position: ConsensusPosition {
                epoch: genesis.position.epoch,
                slot: genesis.position.slot.saturating_add(1),
            },
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: [1u8; 32],
        },
        signature: vec![1u8; 16],
    };
    let second_vote = ValidatorVote {
        voter: validator.id,
        target: VoteTarget {
            block_digest: [2u8; 32],
            ..first_vote.target.clone()
        },
        signature: vec![2u8; 16],
    };
    assert!(evidence::observe_validator_vote(db.as_ref(), &first_vote)?.is_none());
    let evidence_record = evidence::observe_validator_vote(db.as_ref(), &second_vote)?
        .expect("store vote equivocation evidence");

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
    let status = client.consensus_status()?;
    assert_eq!(status.consensus_evidence_count, 1);
    assert_eq!(status.recent_consensus_evidence.len(), 1);
    assert_eq!(
        status.recent_consensus_evidence[0].evidence_id,
        evidence_record.evidence_id
    );

    let _ = shutdown_tx.send(());
    server_task.await??;
    net.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_control_surfaces_latest_anchor_reward_split() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "node-control-reward-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);
    let _wallet_db = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let validator = committee
        .validator_set_for_epoch(genesis.position.epoch)
        .validators[0]
        .clone();
    db.store_validator_reward_event(&ValidatorRewardEvent {
        anchor_hash: genesis.hash,
        anchor_num: genesis.num,
        validator_id: validator.id,
        validator_voting_power: validator.voting_power,
        total_rewarded_voting_power: validator.voting_power,
        protocol_reward: 5,
        fee_reward: 7,
        gross_reward: 12,
        commission_reward: 1,
        share_backed_reward: 11,
        bonded_stake_before: validator.voting_power,
        bonded_stake_after: validator.voting_power + 12,
        pending_commission_before: 0,
        pending_commission_after: 1,
        resulting_status: unchained::staking::ValidatorStatus::Active,
        suppression_reason: None,
    })?;

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
    let status = client.consensus_status()?;
    assert_eq!(status.latest_anchor_protocol_reward_total, 5);
    assert_eq!(status.latest_anchor_fee_reward_total, 7);
    assert_eq!(status.latest_anchor_reward_events.len(), 1);
    assert_eq!(status.latest_anchor_reward_events[0].gross_reward, 12);

    let _ = shutdown_tx.send(());
    server_task.await??;
    net.shutdown().await;
    Ok(())
}
