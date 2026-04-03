use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use unchained::{
    coin::Coin,
    config::{Net, P2p},
    consensus::{DEFAULT_MEM_KIB, TARGET_LEADING_ZEROS},
    epoch::Anchor,
    network, node_control, node_identity,
    protocol::CURRENT as PROTOCOL,
    storage::{Store, WalletStore},
    sync::SyncState,
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

fn seed_genesis(store: &Store) -> Result<Anchor> {
    let genesis = genesis_anchor();
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

#[tokio::test(flavor = "multi_thread")]
async fn wallet_control_serves_state_and_mining_identity() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-test-passphrase");
    network::set_quiet_logging(true);

    let tempdir = TempDir::new()?;
    let base_path = tempdir.path().to_string_lossy().to_string();
    let db = Arc::new(Store::open(&base_path)?);
    let wallet_store = Arc::new(WalletStore::open(&base_path)?);
    let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
    let genesis = seed_genesis(db.as_ref())?;
    let _coin = seed_sender_coin(db.as_ref(), &wallet, &genesis)?;

    let net = spawn_network(&tempdir, db.clone(), &genesis).await?;
    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let (coin_tx, _coin_rx) = mpsc::unbounded_channel();
    let (node_shutdown_tx, node_shutdown_rx) = broadcast::channel::<()>(1);
    let node_server = node_control::NodeControlServer::bind(
        &base_path,
        db.clone(),
        net.clone(),
        sync_state,
        coin_tx,
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
    assert_eq!(receive_address, wallet.address());
    assert_eq!(receive_signing_pk, wallet.public_key().clone());

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
