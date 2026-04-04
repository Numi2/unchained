mod finality_support;

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::broadcast;
use unchained::{
    coin::Coin,
    config::{Net, P2p},
    epoch::Anchor,
    network, node_control, node_identity, proof,
    protocol::CURRENT as PROTOCOL,
    staking::{ValidatorMetadata, ValidatorPool, ValidatorRegistration, ValidatorStatus},
    storage::{Store, WalletStore},
    sync::SyncState,
    transaction::{SharedStateAction, SharedStateControlDocument, Tx},
    wallet::Wallet,
    wallet_control::{wallet_control_capability_path, WalletControlClient, WalletControlServer},
};

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

fn seed_genesis(store: &Store, committee: &finality_support::TestCommittee) -> Result<Anchor> {
    let genesis = committee.genesis_anchor();
    committee.seed_validator_state(store, genesis.position.epoch)?;
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
}

fn seed_sender_coin(store: &Store, wallet: &Wallet, genesis: &Anchor) -> Result<Coin> {
    let chain_id = genesis.hash;
    let nonce = 7;
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
    Ok(coin)
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

fn deterministic_fee_payment_fixture_components(
    tempdir: &TempDir,
) -> Result<(Arc<Store>, Arc<WalletStore>, Wallet, Anchor)> {
    let base_path = tempdir.path().to_string_lossy().to_string();
    let db = Arc::new(Store::open(&base_path)?);
    let wallet_store = Arc::new(WalletStore::open(&base_path)?);
    let wallet = finality_support::deterministic_wallet(wallet_store.clone())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let _coins =
        finality_support::seed_wallet_with_coin_values(db.as_ref(), &wallet, &genesis, &[2])?;
    Ok((db, wallet_store, wallet, genesis))
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_control_serves_state_and_wallet_identity() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-test-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let base_path = tempdir.path().to_string_lossy().to_string();
    let db = Arc::new(Store::open(&base_path)?);
    let wallet_store = Arc::new(WalletStore::open(&base_path)?);
    let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
    let committee = finality_support::TestCommittee::single_validator();
    let genesis = seed_genesis(db.as_ref(), &committee)?;
    let _coin = seed_sender_coin(db.as_ref(), &wallet, &genesis)?;

    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let (node_shutdown_tx, node_shutdown_rx) = broadcast::channel::<()>(1);
    let node_server = node_control::NodeControlServer::bind(
        &base_path,
        db.clone(),
        net.clone(),
        sync_state,
        false,
    )
    .await?;
    let node_server_task = tokio::spawn(async move { node_server.serve(node_shutdown_rx).await });

    let node_client = node_control::NodeControlClient::new(&base_path);
    node_client.ping()?;
    let wallet = Arc::new(wallet.with_node_client(node_client));

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let server = WalletControlServer::bind(&base_path, wallet.clone()).await?;
    let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

    let client = WalletControlClient::new(&base_path);
    client.ping().await?;
    let capability_path = wallet_control_capability_path(&base_path);
    assert!(capability_path.exists());

    let state = client.state().await?;
    assert_eq!(state.state.balance, 1);
    assert_eq!(state.state.spendable_outputs, 1);
    assert_eq!(state.state.chain_id, genesis.hash);
    assert_eq!(state.identity.address, wallet.address());
    assert_eq!(state.identity.signing_pk, wallet.public_key().clone());

    let receive_handle = client.mint_receive_handle().await?;
    let (receive_address, receive_signing_pk, _receive_kem_pk) =
        Wallet::parse_address(&receive_handle)?;
    assert_ne!(receive_address, wallet.address());
    assert_ne!(receive_signing_pk, wallet.public_key().clone());

    let coin_id = [3u8; 32];
    let chain_id = [7u8; 32];
    let derived = client.derive_genesis_lock_secret(coin_id, chain_id).await?;
    assert_eq!(
        derived,
        wallet.compute_genesis_lock_secret(&coin_id, &chain_id)
    );

    client.force_sync().await?;

    std::fs::write(&capability_path, [0u8; 32])?;
    assert!(client.ping().await.is_err());
    assert!(client.state().await.is_err());

    let _ = shutdown_tx.send(());
    server_task.await??;
    let _ = node_shutdown_tx.send(());
    node_server_task.await??;
    net.shutdown().await;
    drop(wallet);
    wallet_store.close()?;
    db.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn deterministic_fee_paid_control_fixture_id_stays_stable() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-control-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let (db, wallet_store, wallet, _genesis) =
        deterministic_fee_payment_fixture_components(&tempdir)?;
    let snapshot = node_control::build_shielded_runtime_snapshot(db.as_ref())?;
    let prepared =
        wallet.prepare_fee_payment_for_snapshot(&snapshot, PROTOCOL.validator_registration_fee)?;
    let fixture_id = proof::shielded_tx_fixture_id(prepared.witness())?;
    assert_eq!(
        hex::encode(fixture_id),
        "37e79586d0327c93cb173ed1c42abde48907cf15ea393359adb9342579e08075"
    );

    drop(wallet);
    wallet_store.close()?;
    db.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "fixture mint for fee-paid control submission proof"]
async fn mint_fee_paid_control_submission_fixture() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-control-passphrase");
    let _proof_fixture_dir = EnvGuard::set(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        &finality_support::proof_fixture_dir(),
    );
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let (db, wallet_store, wallet, _genesis) =
        deterministic_fee_payment_fixture_components(&tempdir)?;
    let snapshot = node_control::build_shielded_runtime_snapshot(db.as_ref())?;
    let prepared =
        wallet.prepare_fee_payment_for_snapshot(&snapshot, PROTOCOL.validator_registration_fee)?;
    let fixture_id = proof::shielded_tx_fixture_id(prepared.witness())?;
    let fixture_path = std::path::Path::new(&finality_support::proof_fixture_dir())
        .join("shielded-spend")
        .join(format!("{}.bin", hex::encode(fixture_id)));
    let (_receipt, journal) = proof::prove_shielded_tx(prepared.witness())?;
    assert_eq!(journal.fee_amount, PROTOCOL.validator_registration_fee);
    assert!(fixture_path.exists());

    drop(wallet);
    wallet_store.close()?;
    db.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_can_submit_fee_paid_validator_registration_over_ingress_without_node_control(
) -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-control-passphrase");
    let _proof_fixture_dir = EnvGuard::set(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        &finality_support::proof_fixture_dir(),
    );
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let base_path = tempdir.path().to_string_lossy().to_string();
    let (db, wallet_store, wallet, genesis) =
        deterministic_fee_payment_fixture_components(&tempdir)?;

    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let (node_shutdown_tx, node_shutdown_rx) = broadcast::channel::<()>(1);
    let node_server = node_control::NodeControlServer::bind(
        &base_path,
        db.clone(),
        net.clone(),
        sync_state,
        false,
    )
    .await?;
    let mut node_server_task =
        tokio::spawn(async move { node_server.serve(node_shutdown_rx).await });

    let node_client = node_control::NodeControlClient::new(&base_path);
    node_client.ping()?;
    let ingress =
        finality_support::spawn_test_ingress(tempdir.path(), genesis.hash, &base_path).await?;
    let proof_assistant =
        finality_support::spawn_test_proof_assistant(tempdir.path(), genesis.hash).await?;
    let wallet = Arc::new(
        wallet
            .with_ingress_client(ingress.client.clone())
            .with_proof_assistant_client(proof_assistant.client.clone()),
    );

    let record = node_identity::load_node_record(
        &tempdir
            .path()
            .join("node_identity")
            .join("node_record.bin")
            .display()
            .to_string(),
    )?;
    let pool = ValidatorPool::from_node_record(
        &record,
        150,
        3,
        1,
        ValidatorStatus::PendingActivation,
        ValidatorMetadata {
            display_name: "wallet-control-validator".to_string(),
            website: Some("https://wallet-control.example".to_string()),
            description: Some("fee-paid shared-state control submission".to_string()),
        },
    )?;
    let action = SharedStateAction::RegisterValidator(ValidatorRegistration { pool });
    let signable = Tx::shared_state_signing_bytes(genesis.hash, &action)?;
    let authorization_signature =
        node_identity::sign_with_local_root_in_dir(tempdir.path(), &signable)?;
    let document = SharedStateControlDocument::new(genesis.hash, action, authorization_signature);

    let outcome = wallet
        .submit_shared_state_control_document(document)
        .await?;
    assert_eq!(outcome.fee_amount, PROTOCOL.validator_registration_fee);
    assert!(outcome.input_count >= 1);
    assert_eq!(outcome.output_count, 1);
    assert_eq!(wallet.balance()?, 1);
    assert!(wallet_store
        .get_raw_bytes("wallet_sent_tx", &outcome.tx_id)?
        .is_some());

    ingress.shutdown().await?;
    proof_assistant.shutdown().await?;
    let _ = node_shutdown_tx.send(());
    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut node_server_task).await {
        Ok(result) => result??,
        Err(_) => {
            node_server_task.abort();
            let _ = node_server_task.await;
        }
    }
    net.shutdown().await;
    drop(wallet);
    wallet_store.close()?;
    db.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_control_submits_fee_paid_validator_registration_documents() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-control-passphrase");
    let _proof_fixture_dir = EnvGuard::set(
        "UNCHAINED_PROOF_FIXTURE_DIR",
        &finality_support::proof_fixture_dir(),
    );
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let base_path = tempdir.path().to_string_lossy().to_string();
    let (db, wallet_store, wallet, genesis) =
        deterministic_fee_payment_fixture_components(&tempdir)?;

    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let (node_shutdown_tx, node_shutdown_rx) = broadcast::channel::<()>(1);
    let node_server = node_control::NodeControlServer::bind(
        &base_path,
        db.clone(),
        net.clone(),
        sync_state,
        false,
    )
    .await?;
    let mut node_server_task =
        tokio::spawn(async move { node_server.serve(node_shutdown_rx).await });

    let ingress =
        finality_support::spawn_test_ingress(tempdir.path(), genesis.hash, &base_path).await?;
    let proof_assistant =
        finality_support::spawn_test_proof_assistant(tempdir.path(), genesis.hash).await?;
    let wallet = Arc::new(
        wallet
            .with_ingress_client(ingress.client.clone())
            .with_proof_assistant_client(proof_assistant.client.clone()),
    );

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let server = WalletControlServer::bind(&base_path, wallet.clone()).await?;
    let mut server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

    let record = node_identity::load_node_record(
        &tempdir
            .path()
            .join("node_identity")
            .join("node_record.bin")
            .display()
            .to_string(),
    )?;
    let pool = ValidatorPool::from_node_record(
        &record,
        150,
        3,
        1,
        ValidatorStatus::PendingActivation,
        ValidatorMetadata {
            display_name: "wallet-control-validator".to_string(),
            website: Some("https://wallet-control.example".to_string()),
            description: Some("fee-paid shared-state control submission".to_string()),
        },
    )?;
    let action = SharedStateAction::RegisterValidator(ValidatorRegistration { pool });
    let signable = Tx::shared_state_signing_bytes(genesis.hash, &action)?;
    let authorization_signature =
        node_identity::sign_with_local_root_in_dir(tempdir.path(), &signable)?;
    let document = SharedStateControlDocument::new(genesis.hash, action, authorization_signature);

    let client = WalletControlClient::new(&base_path);
    let outcome = client.submit_shared_state_control(document).await?;
    assert_eq!(outcome.fee_amount, PROTOCOL.validator_registration_fee);
    assert!(outcome.input_count >= 1);
    assert_eq!(outcome.output_count, 1);
    assert!(wallet_store
        .get_raw_bytes("wallet_sent_tx", &outcome.tx_id)?
        .is_some());

    drop(client);
    ingress.shutdown().await?;
    proof_assistant.shutdown().await?;
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut server_task).await {
        Ok(result) => result??,
        Err(_) => {
            server_task.abort();
            let _ = server_task.await;
        }
    }
    let _ = node_shutdown_tx.send(());
    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut node_server_task).await {
        Ok(result) => result??,
        Err(_) => {
            node_server_task.abort();
            let _ = node_server_task.await;
        }
    }
    drop(wallet);
    net.shutdown().await;
    wallet_store.close()?;
    db.close()?;
    Ok(())
}
