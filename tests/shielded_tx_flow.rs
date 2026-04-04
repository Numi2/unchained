mod finality_support;

use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use tokio::sync::{broadcast, watch};
use tokio::time::{timeout, Duration};
use unchained::coin::Coin;
use unchained::config::{Net, P2p};
use unchained::consensus::OrderingPath;
use unchained::epoch::Anchor;
use unchained::network;
use unchained::node_control;
use unchained::node_identity;
use unchained::proof::{TransparentProof, TransparentProofStatement};
use unchained::protocol::CURRENT as PROTOCOL;
use unchained::shielded::ShieldedNoteKind;
use unchained::storage::{Store, WalletStore};
use unchained::sync::SyncState;
use unchained::transaction::Tx;
use unchained::wallet::Wallet;

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

fn dummy_proof(statement: TransparentProofStatement) -> TransparentProof {
    TransparentProof::new(statement, Vec::new())
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

fn seed_sender_coins(
    store: &Store,
    wallet: &Wallet,
    genesis: &Anchor,
    count: u64,
) -> anyhow::Result<Vec<Coin>> {
    let chain_id = genesis.hash;
    let mut coins = Vec::with_capacity(count as usize);
    for nonce in 7..(7 + count) {
        let candidate_id = Coin::calculate_id(&genesis.hash, nonce, &wallet.address());
        let lock_secret = wallet.compute_genesis_lock_secret(&candidate_id, &chain_id);
        let lock_hash =
            unchained::crypto::lock_hash_from_preimage(&chain_id, &candidate_id, &lock_secret);
        let coin = Coin::new_with_creator_pk_and_lock(
            genesis.hash,
            nonce,
            wallet.address(),
            wallet.public_key().clone(),
            lock_hash,
        );
        store.put("coin", &coin.id, &coin)?;
        store.put_coin_epoch(&coin.id, genesis.num)?;
        store.put_coin_epoch_rev(genesis.num, &coin.id)?;
        coins.push(coin);
    }
    Ok(coins)
}

fn mutate_shielded_note_tree(store: &Store, commitment: [u8; 32]) -> anyhow::Result<()> {
    let mut tree = store.load_shielded_note_tree()?.unwrap_or_default();
    tree.append(commitment)?;
    store.store_shielded_note_tree(&tree)?;
    Ok(())
}

fn provision_runtime_identity(
    tempdir: &TempDir,
    chain_id: [u8; 32],
    address: String,
) -> anyhow::Result<()> {
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

async fn spawn_sender_network(
    sender_dir: &TempDir,
    sender_db: Arc<Store>,
    genesis: &Anchor,
) -> anyhow::Result<unchained::network::NetHandle> {
    let port = pick_udp_port();
    provision_runtime_identity(sender_dir, genesis.hash, format!("127.0.0.1:{port}"))?;
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    network::spawn(build_net(port), build_p2p(), sender_db, sync_state).await
}

async fn spawn_node_control(
    base_path: &str,
    db: Arc<Store>,
    net: unchained::network::NetHandle,
) -> anyhow::Result<(
    broadcast::Sender<()>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
)> {
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let server =
        node_control::NodeControlServer::bind(base_path, db, net, sync_state, false).await?;
    let task = tokio::spawn(async move { server.serve(shutdown_rx).await });
    Ok((shutdown_tx, task))
}

fn apply_scanned_tx_locally(
    store: &Store,
    wallet_db: &WalletStore,
    wallet: &Wallet,
    tx: &Tx,
    inputs: &[proof_core::ProofShieldedInputWitness],
) -> anyhow::Result<()> {
    let tx_id = tx.id()?;
    let mut tree = store.load_shielded_note_tree()?.unwrap_or_default();
    for (index, output) in tx.outputs().iter().enumerate() {
        tree.append(output.note_commitment)?;
        store.store_shielded_output(&tx_id, index as u32, output)?;
    }
    store.store_shielded_note_tree(&tree)?;
    let current_epoch = unchained::transaction::current_nullifier_epoch(store)?;
    let mut active = store
        .load_shielded_active_nullifier_epoch()?
        .unwrap_or_else(|| unchained::shielded::ActiveNullifierEpoch::new(current_epoch));
    for input in inputs {
        active.insert(input.current_nullifier)?;
        store.mark_shielded_note_spent(&input.note.commitment, &input.current_nullifier)?;
    }
    store.store_shielded_active_nullifier_epoch(&active)?;
    wallet.scan_tx_for_me(tx)?;
    for input in inputs {
        wallet_db.put_raw_bytes(
            "wallet_spent_note",
            &input.note.commitment,
            &input.current_nullifier,
        )?;
    }
    Ok(())
}

async fn wait_for_state_update<F>(
    state_rx: &mut watch::Receiver<Option<node_control::NodeControlStateEnvelope>>,
    min_sequence: u64,
    predicate: F,
) -> anyhow::Result<node_control::NodeControlStateEnvelope>
where
    F: Fn(&node_control::NodeControlStateEnvelope) -> bool,
{
    if let Some(state) = state_rx.borrow().clone() {
        if state.sequence >= min_sequence && predicate(&state) {
            return Ok(state);
        }
    }
    timeout(Duration::from_secs(3), async {
        loop {
            state_rx.changed().await?;
            if let Some(state) = state_rx.borrow_and_update().clone() {
                if state.sequence > min_sequence && predicate(&state) {
                    return Ok::<_, anyhow::Error>(state);
                }
            }
        }
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shielded_wallet_prepare_is_deterministic_and_receiver_visible() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let receiver_dir = TempDir::new()?;

    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);
    let receiver_wallet_db = Arc::new(WalletStore::open(&receiver_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let receiver_wallet = Wallet::load_or_create_private(receiver_wallet_db)?;

    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 2)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let sender_wallet = Arc::new(sender_wallet.with_node_client(node_client.clone()));
    let receiver_wallet = Arc::new(receiver_wallet.with_node_client(node_client));
    let recipient_handle = receiver_wallet.mint_invoice()?;
    let recipient_handle_repeat = receiver_wallet.mint_invoice()?;
    let (_recipient_addr, recipient_signing_pk, recipient_kem_pk) =
        Wallet::parse_invoice(&recipient_handle)?;
    let (_recipient_addr_repeat, recipient_signing_pk_repeat, recipient_kem_pk_repeat) =
        Wallet::parse_invoice(&recipient_handle_repeat)?;

    assert_ne!(recipient_signing_pk, recipient_signing_pk_repeat);
    assert_ne!(recipient_kem_pk, recipient_kem_pk_repeat);
    assert_ne!(recipient_signing_pk, receiver_wallet.public_key().clone());
    assert_ne!(
        recipient_signing_pk_repeat,
        receiver_wallet.public_key().clone()
    );

    assert_eq!(sender_wallet.balance()?, 2);
    assert_eq!(receiver_wallet.balance()?, 0);

    let prepared_a = sender_wallet
        .prepare_shielded_send(&recipient_handle, 1)
        .await?;
    let prepared_b = sender_wallet
        .prepare_shielded_send(&recipient_handle, 1)
        .await?;

    assert_eq!(prepared_a.input_count(), 2);
    assert_eq!(prepared_a.output_count(), 1);
    assert_eq!(
        bincode::serialize(prepared_a.witness())?,
        bincode::serialize(prepared_b.witness())?
    );

    let initial_runtime = node_control::build_shielded_runtime_snapshot(sender_db.as_ref())?;
    mutate_shielded_note_tree(sender_db.as_ref(), [0xabu8; 32])?;
    let advanced_runtime = node_control::build_shielded_runtime_snapshot(sender_db.as_ref())?;
    assert_ne!(
        advanced_runtime.note_tree.root(),
        initial_runtime.note_tree.root()
    );
    let stale_submit = sender_wallet
        .submit_prepared_shielded_send(
            prepared_b,
            dummy_proof(TransparentProofStatement::ShieldedTransfer),
        )
        .await;
    assert!(stale_submit
        .err()
        .map(|err| err.to_string())
        .unwrap_or_default()
        .contains("prepared shielded transaction is stale"));

    let journal = proof_core::validate_shielded_tx_witness(prepared_a.witness())?;
    assert_eq!(journal.inputs.len(), 2);
    assert_eq!(journal.fee_amount, PROTOCOL.ordinary_private_transfer_fee);
    assert_eq!(journal.outputs.len(), 1);

    let tx = prepared_a.tx_with_proof(dummy_proof(TransparentProofStatement::ShieldedTransfer));
    receiver_wallet.scan_tx_for_me(&tx)?;

    assert_eq!(sender_wallet.balance()?, 2);
    assert_eq!(receiver_wallet.balance()?, 1);
    assert_eq!(receiver_wallet.list_owned_shielded_notes()?.len(), 1);

    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_can_sync_compact_state_over_remote_ingress_without_node_control(
) -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let wallet_dir = TempDir::new()?;
    let base_path = wallet_dir.path().to_string_lossy().to_string();
    let db = Arc::new(Store::open(&base_path)?);
    let wallet_store = Arc::new(WalletStore::open(&base_path)?);
    let wallet = Wallet::load_or_create_private(wallet_store.clone())?;

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let _seeded = finality_support::seed_wallet_with_coins(db.as_ref(), &wallet, &genesis, 260)?;

    let net = spawn_sender_network(&wallet_dir, db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) =
        spawn_node_control(&base_path, db.clone(), net.clone()).await?;
    let ingress =
        finality_support::spawn_test_ingress(wallet_dir.path(), genesis.hash, &base_path).await?;

    let remote_wallet =
        Wallet::load_or_create_private(wallet_store)?.with_ingress_client(ingress.client.clone());

    assert_eq!(remote_wallet.balance()?, 260);
    assert_eq!(remote_wallet.list_owned_shielded_notes()?.len(), 260);
    assert!(remote_wallet.mint_invoice().is_ok());

    ingress.shutdown().await?;
    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_can_prepare_shielded_send_over_remote_ingress_without_node_control(
) -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let receiver_dir = TempDir::new()?;

    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);
    let receiver_wallet_db = Arc::new(WalletStore::open(&receiver_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let receiver_wallet = Wallet::load_or_create_private(receiver_wallet_db)?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 2)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let ingress = finality_support::spawn_test_ingress(
        sender_dir.path(),
        genesis.hash,
        &sender_dir.path().to_string_lossy(),
    )
    .await?;

    let sender_wallet = Arc::new(sender_wallet.with_ingress_client(ingress.client.clone()));
    let receiver_wallet = Arc::new(receiver_wallet.with_ingress_client(ingress.client.clone()));
    let recipient_handle = receiver_wallet.mint_invoice()?;

    let prepared = sender_wallet
        .prepare_shielded_send(&recipient_handle, 1)
        .await?;
    let journal = proof_core::validate_shielded_tx_witness(prepared.witness())?;
    assert_eq!(journal.inputs.len(), 2);
    assert_eq!(journal.outputs.len(), 1);
    assert_eq!(journal.fee_amount, PROTOCOL.ordinary_private_transfer_fee);

    ingress.shutdown().await?;
    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "expensive zkVM proving soak"]
async fn shielded_wallet_send_and_receive_roundtrip_soak() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let receiver_dir = TempDir::new()?;

    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);
    let receiver_wallet_db = Arc::new(WalletStore::open(&receiver_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let receiver_wallet = Wallet::load_or_create_private(receiver_wallet_db)?;

    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 2)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let ingress = finality_support::spawn_test_ingress(
        sender_dir.path(),
        genesis.hash,
        &sender_dir.path().to_string_lossy(),
    )
    .await?;
    let sender_wallet = Arc::new(
        sender_wallet
            .with_node_client(node_client.clone())
            .with_ingress_client(ingress.client.clone()),
    );
    let receiver_wallet = Arc::new(receiver_wallet.with_node_client(node_client));
    let recipient_handle = receiver_wallet.mint_invoice()?;
    let _ = Wallet::parse_invoice(&recipient_handle)?;

    assert_eq!(sender_wallet.balance()?, 2);
    assert_eq!(receiver_wallet.balance()?, 0);

    let outcome = sender_wallet.send_to_invoice(&recipient_handle, 1).await?;
    let tx_id = outcome.tx_id;
    assert_eq!(outcome.input_count, 2);
    assert_eq!(outcome.output_count, 1);

    let tx_bytes = sender_db
        .get_raw_bytes("tx", &tx_id)?
        .expect("persisted tx bytes");
    let tx = unchained::canonical::decode_tx(&tx_bytes)?;
    assert_eq!(tx.input_count(), 2);
    assert_eq!(tx.output_count(), 1);
    assert!(sender_db.load_fast_path_pending_tx(&tx_id)?.is_none());
    assert!(sender_db.load_shared_state_pending_tx(&tx_id)?.is_none());
    assert_eq!(
        sender_db
            .get::<Anchor>("epoch", b"latest")?
            .expect("latest finalized anchor")
            .ordering_path,
        OrderingPath::FastPathPrivateTransfer
    );

    assert_eq!(sender_wallet.balance()?, 0);
    assert_eq!(receiver_wallet.balance()?, 1);
    assert_eq!(receiver_wallet.list_owned_shielded_notes()?.len(), 1);

    net.shutdown().await;
    ingress.shutdown().await?;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_can_prepare_private_delegation_over_remote_ingress_without_node_control(
) -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 2)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let ingress = finality_support::spawn_test_ingress(
        sender_dir.path(),
        genesis.hash,
        &sender_dir.path().to_string_lossy(),
    )
    .await?;
    let sender_wallet = Arc::new(sender_wallet.with_ingress_client(ingress.client.clone()));

    let validator_set = sender_db
        .load_validator_committee(genesis.position.epoch)?
        .expect("genesis validator committee");
    let validator_id = validator_set.validators[0].id;

    let prepared = sender_wallet
        .prepare_private_delegation(validator_id, 1)
        .await?;
    let journal = proof_core::validate_private_delegation_witness(prepared.witness())?;
    assert_eq!(journal.validator_id, validator_id.0);
    assert_eq!(journal.delegated_amount, 1);
    assert_eq!(journal.delegation_share_value, 1);

    ingress.shutdown().await?;
    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_delegation_updates_validator_pool_and_wallet_note_state() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 2)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let sender_wallet = Arc::new(sender_wallet.with_node_client(node_client));

    let validator_set = sender_db
        .load_validator_committee(genesis.position.epoch)?
        .expect("genesis validator committee");
    let validator_id = validator_set.validators[0].id;

    let prepared = sender_wallet
        .prepare_private_delegation(validator_id, 1)
        .await?;
    let journal = proof_core::validate_private_delegation_witness(prepared.witness())?;
    assert_eq!(journal.validator_id, validator_id.0);
    assert_eq!(journal.delegated_amount, 1);
    assert_eq!(journal.delegation_share_value, 1);
    let tx = prepared.tx_with_proof(dummy_proof(TransparentProofStatement::PrivateDelegation));
    assert!(!tx.is_fast_path_eligible());

    let prior_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("validator pool");
    let updated_pool =
        prior_pool.apply_delegation(journal.delegated_amount, journal.delegation_share_value)?;
    sender_db.store_validator_pool(&updated_pool)?;
    apply_scanned_tx_locally(
        sender_db.as_ref(),
        sender_wallet_db.as_ref(),
        sender_wallet.as_ref(),
        &tx,
        &prepared.witness().shielded.inputs,
    )?;

    let updated_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("updated validator pool");
    assert_eq!(updated_pool.total_bonded_stake, 2);
    assert_eq!(updated_pool.total_delegation_shares, 2);

    let owned_notes = sender_wallet.list_owned_shielded_notes()?;
    assert_eq!(sender_wallet.balance()?, 0);
    assert_eq!(owned_notes.len(), 1);
    assert!(matches!(
        owned_notes[0].note.kind,
        ShieldedNoteKind::DelegationShare {
            validator_id: note_validator_id
        } if note_validator_id == validator_id.0
    ));
    assert_eq!(owned_notes[0].note.value, 1);

    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_undelegation_updates_pool_and_wallet_note_state() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 3)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let mut state_rx = node_client.subscribe_state()?;
    let state_client = node_client.clone();
    let sender_wallet = Arc::new(sender_wallet.with_node_client(node_client));

    let validator_set = sender_db
        .load_validator_committee(genesis.position.epoch)?
        .expect("genesis validator committee");
    let validator_id = validator_set.validators[0].id;

    let delegated = sender_wallet
        .prepare_private_delegation(validator_id, 2)
        .await?;
    let delegation_journal = proof_core::validate_private_delegation_witness(delegated.witness())?;
    let delegation_tx =
        delegated.tx_with_proof(dummy_proof(TransparentProofStatement::PrivateDelegation));
    let updated_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("validator pool")
        .apply_delegation(
            delegation_journal.delegated_amount,
            delegation_journal.delegation_share_value,
        )?;
    sender_db.store_validator_pool(&updated_pool)?;
    apply_scanned_tx_locally(
        sender_db.as_ref(),
        sender_wallet_db.as_ref(),
        sender_wallet.as_ref(),
        &delegation_tx,
        &delegated.witness().shielded.inputs,
    )?;

    let baseline_state = state_client.state()?;
    let _ = wait_for_state_update(&mut state_rx, baseline_state.sequence, |state| {
        state
            .state
            .consensus_status
            .registered_validator_pools
            .iter()
            .any(|pool| pool.validator.id == validator_id && pool.total_bonded_stake == 3)
    })
    .await?;

    let undelegated = sender_wallet
        .prepare_private_undelegation(validator_id, 2)
        .await?;
    let undelegation_journal =
        proof_core::validate_private_undelegation_witness(undelegated.witness())?;
    assert_eq!(undelegation_journal.validator_id, validator_id.0);
    assert_eq!(undelegation_journal.burned_share_value, 2);
    assert_eq!(undelegation_journal.gross_claim_amount, 2);
    assert_eq!(undelegation_journal.claim_value, 1);
    assert_eq!(
        undelegation_journal.release_epoch,
        undelegation_journal.current_epoch + PROTOCOL.stake_unbonding_epochs
    );
    let undelegation_tx =
        undelegated.tx_with_proof(dummy_proof(TransparentProofStatement::PrivateUndelegation));
    assert!(!undelegation_tx.is_fast_path_eligible());

    let updated_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("delegated validator pool")
        .apply_undelegation(
            undelegation_journal.burned_share_value,
            undelegation_journal.gross_claim_amount,
            undelegation_journal.current_epoch,
            undelegation_journal.release_epoch,
            PROTOCOL.stake_unbonding_epochs,
        )?;
    sender_db.store_validator_pool(&updated_pool)?;
    apply_scanned_tx_locally(
        sender_db.as_ref(),
        sender_wallet_db.as_ref(),
        sender_wallet.as_ref(),
        &undelegation_tx,
        &undelegated.witness().shielded.inputs,
    )?;

    let claim_notes = sender_wallet.list_owned_shielded_notes()?;
    assert_eq!(sender_wallet.balance()?, 0);
    assert_eq!(claim_notes.len(), 1);
    assert!(matches!(
        claim_notes[0].note.kind,
        ShieldedNoteKind::UnbondingClaim {
            validator_id: note_validator_id,
            release_epoch
        } if note_validator_id == validator_id.0
            && release_epoch == undelegation_journal.release_epoch
    ));
    assert_eq!(claim_notes[0].note.value, 1);

    let updated_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("final validator pool");
    assert_eq!(updated_pool.total_bonded_stake, 1);
    assert_eq!(updated_pool.total_delegation_shares, 1);

    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_cover_traffic_loop_does_not_persist_transactions_or_advance_finality(
) -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 1)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let ingress = finality_support::spawn_test_ingress(
        sender_dir.path(),
        genesis.hash,
        &sender_dir.path().to_string_lossy(),
    )
    .await?;
    let sender_wallet = Arc::new(
        sender_wallet
            .with_node_client(node_client)
            .with_ingress_client(ingress.client.clone()),
    );

    let (cover_shutdown_tx, cover_shutdown_rx) = broadcast::channel::<()>(1);
    let cover_task = tokio::spawn({
        let wallet = sender_wallet.clone();
        async move { wallet.run_cover_traffic_loop(1, cover_shutdown_rx).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = cover_shutdown_tx.send(());
    cover_task.await??;

    let latest_anchor = sender_db
        .get::<Anchor>("epoch", b"latest")?
        .expect("latest finalized anchor");
    assert_eq!(latest_anchor.hash, genesis.hash);

    let tx_cf = sender_db
        .db
        .cf_handle("tx")
        .ok_or_else(|| anyhow::anyhow!("'tx' column family missing"))?;
    let tx_count = sender_db
        .db
        .iterator_cf(tx_cf, rocksdb::IteratorMode::Start)
        .count();
    assert_eq!(tx_count, 0);

    ingress.shutdown().await?;
    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "expensive private staking proving plus ordered-finality soak"]
async fn private_staking_flows_finalize_through_ordered_shared_state_checkpoints(
) -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 3)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let mut state_rx = node_client.subscribe_state()?;
    let state_client = node_client.clone();
    let sender_wallet = Arc::new(sender_wallet.with_node_client(node_client));

    let validator_set = sender_db
        .load_validator_committee(genesis.position.epoch)?
        .expect("genesis validator committee");
    let validator_id = validator_set.validators[0].id;

    let delegation_state = state_client.state()?;
    let delegation_tx_id = sender_wallet.delegate_to_validator(validator_id, 2).await?;
    assert!(sender_db.get_raw_bytes("tx", &delegation_tx_id)?.is_none());
    assert!(sender_db
        .load_shared_state_pending_tx(&delegation_tx_id)?
        .is_some());

    let delegation_batch = net
        .select_pending_shared_state_batch()?
        .expect("pending delegation batch");
    assert_eq!(delegation_batch.ordered_tx_count()?, 1);
    let delegation_anchor = net
        .finalize_local_shared_state_batch(&delegation_batch)
        .await?;
    assert_eq!(
        delegation_anchor.ordering_path,
        OrderingPath::DagBftSharedState
    );
    assert_eq!(
        delegation_anchor.ordered_tx_root,
        delegation_batch.ordered_tx_root
    );
    assert_eq!(
        delegation_anchor.ordered_tx_count,
        delegation_batch.ordered_tx_count()?
    );
    let delegated_state =
        wait_for_state_update(&mut state_rx, delegation_state.sequence, |state| {
            state
                .state
                .consensus_status
                .latest_finalized_anchor
                .as_ref()
                .map(|anchor| anchor.hash == delegation_anchor.hash)
                .unwrap_or(false)
                && state
                    .state
                    .consensus_status
                    .registered_validator_pools
                    .iter()
                    .any(|pool| pool.validator.id == validator_id && pool.total_bonded_stake == 3)
        })
        .await?;
    assert_eq!(
        delegated_state
            .state
            .consensus_status
            .latest_finalized_anchor
            .as_ref()
            .map(|anchor| anchor.ordering_path),
        Some(OrderingPath::DagBftSharedState)
    );
    assert!(sender_db.get_raw_bytes("tx", &delegation_tx_id)?.is_some());
    assert!(sender_db
        .load_shared_state_pending_tx(&delegation_tx_id)?
        .is_none());

    let undelegation_state = state_client.state()?;
    let undelegation_tx_id = sender_wallet
        .undelegate_from_validator(validator_id, 2)
        .await?;
    assert!(sender_db
        .get_raw_bytes("tx", &undelegation_tx_id)?
        .is_none());
    assert!(sender_db
        .load_shared_state_pending_tx(&undelegation_tx_id)?
        .is_some());

    let undelegation_batch = net
        .select_pending_shared_state_batch()?
        .expect("pending undelegation batch");
    assert_eq!(undelegation_batch.ordered_tx_count()?, 1);
    let undelegation_anchor = net
        .finalize_local_shared_state_batch(&undelegation_batch)
        .await?;
    assert_eq!(
        undelegation_anchor.ordering_path,
        OrderingPath::DagBftSharedState
    );
    let undelegated_state =
        wait_for_state_update(&mut state_rx, undelegation_state.sequence, |state| {
            state
                .state
                .consensus_status
                .latest_finalized_anchor
                .as_ref()
                .map(|anchor| anchor.hash == undelegation_anchor.hash)
                .unwrap_or(false)
                && state
                    .state
                    .consensus_status
                    .registered_validator_pools
                    .iter()
                    .any(|pool| pool.validator.id == validator_id && pool.total_bonded_stake == 1)
        })
        .await?;
    assert_eq!(
        undelegated_state
            .state
            .consensus_status
            .latest_finalized_anchor
            .as_ref()
            .map(|anchor| anchor.ordering_path),
        Some(OrderingPath::DagBftSharedState)
    );
    assert!(sender_db
        .get_raw_bytes("tx", &undelegation_tx_id)?
        .is_some());
    assert!(sender_db
        .load_shared_state_pending_tx(&undelegation_tx_id)?
        .is_none());

    let owned_notes = sender_wallet.list_owned_shielded_notes()?;
    assert_eq!(sender_wallet.balance()?, 0);
    assert_eq!(owned_notes.len(), 1);
    assert!(matches!(
        owned_notes[0].note.kind,
        ShieldedNoteKind::UnbondingClaim {
            validator_id: note_validator_id,
            ..
        } if note_validator_id == validator_id.0
    ));

    let final_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("final validator pool");
    assert_eq!(final_pool.total_bonded_stake, 1);
    assert_eq!(final_pool.total_delegation_shares, 1);

    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "expensive zkVM proving soak"]
async fn private_delegation_end_to_end_proving_soak() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let sender_wallet_db = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);

    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(sender_db.as_ref(), &committee)?;
    let sender_wallet = Wallet::load_or_create_private(sender_wallet_db.clone())?;
    let _sender_coins = seed_sender_coins(sender_db.as_ref(), &sender_wallet, &genesis, 2)?;

    let net = spawn_sender_network(&sender_dir, sender_db.clone(), &genesis).await?;
    let (node_control_shutdown, node_control_task) = spawn_node_control(
        &sender_dir.path().to_string_lossy(),
        sender_db.clone(),
        net.clone(),
    )
    .await?;
    let node_client = node_control::NodeControlClient::new(&sender_dir.path().to_string_lossy());
    node_client.ping()?;
    let sender_wallet = Arc::new(sender_wallet.with_node_client(node_client));

    let validator_set = sender_db
        .load_validator_committee(genesis.position.epoch)?
        .expect("genesis validator committee");
    let validator_id = validator_set.validators[0].id;

    let tx_id = sender_wallet.delegate_to_validator(validator_id, 1).await?;
    let batch = net
        .select_pending_shared_state_batch()?
        .expect("pending delegation batch");
    let _anchor = net.finalize_local_shared_state_batch(&batch).await?;
    let tx_bytes = sender_db
        .get_raw_bytes("tx", &tx_id)?
        .expect("persisted delegation tx bytes");
    let tx = unchained::canonical::decode_tx(&tx_bytes)?;
    assert!(!tx.is_fast_path_eligible());

    let updated_pool = sender_db
        .load_validator_pool(&validator_id)?
        .expect("updated validator pool");
    assert_eq!(updated_pool.total_bonded_stake, 2);
    assert_eq!(updated_pool.total_delegation_shares, 2);

    let owned_notes = sender_wallet.list_owned_shielded_notes()?;
    assert_eq!(sender_wallet.balance()?, 0);
    assert_eq!(owned_notes.len(), 1);
    assert!(matches!(
        owned_notes[0].note.kind,
        ShieldedNoteKind::DelegationShare {
            validator_id: note_validator_id
        } if note_validator_id == validator_id.0
    ));
    assert_eq!(owned_notes[0].note.value, 1);

    net.shutdown().await;
    let _ = node_control_shutdown.send(());
    node_control_task.await??;
    Ok(())
}
