use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use unchained::coin::Coin;
use unchained::config::{Net, P2p};
use unchained::consensus::{DEFAULT_MEM_KIB, TARGET_LEADING_ZEROS};
use unchained::epoch::Anchor;
use unchained::network;
use unchained::node_identity;
use unchained::protocol::CURRENT as PROTOCOL;
use unchained::storage::Store;
use unchained::sync::SyncState;
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

fn seed_genesis(store: &Store) -> anyhow::Result<Anchor> {
    let genesis = genesis_anchor();
    store.put("epoch", &0u64.to_le_bytes(), &genesis)?;
    store.put("epoch", b"latest", &genesis)?;
    store.put("anchor", &genesis.hash, &genesis)?;
    Ok(genesis)
}

fn seed_sender_coin(store: &Store, wallet: &Wallet, genesis: &Anchor) -> anyhow::Result<Coin> {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shielded_wallet_send_and_receive_roundtrip() -> anyhow::Result<()> {
    let _guard = test_guard();
    network::set_quiet_logging(true);
    std::env::set_var("WALLET_PASSPHRASE", "shielded-test-passphrase");

    let sender_dir = TempDir::new()?;
    let receiver_dir = TempDir::new()?;

    let sender_db = Arc::new(Store::open(&sender_dir.path().to_string_lossy())?);
    let receiver_db = Arc::new(Store::open(&receiver_dir.path().to_string_lossy())?);

    let genesis = seed_genesis(sender_db.as_ref())?;
    seed_genesis(receiver_db.as_ref())?;

    let sender_wallet = Arc::new(Wallet::load_or_create(sender_db.clone())?);
    let receiver_wallet = Arc::new(Wallet::load_or_create(receiver_db.clone())?);

    let sender_coin = seed_sender_coin(sender_db.as_ref(), sender_wallet.as_ref(), &genesis)?;
    receiver_db.put("coin", &sender_coin.id, &sender_coin)?;
    receiver_db.put_coin_epoch(&sender_coin.id, genesis.num)?;
    receiver_db.put_coin_epoch_rev(genesis.num, &sender_coin.id)?;

    let port = pick_udp_port();
    provision_runtime_identity(&sender_dir, genesis.hash, format!("127.0.0.1:{port}"))?;

    let sync_state = Arc::new(Mutex::new(SyncState::default()));
    let net = network::spawn(build_net(port), build_p2p(), sender_db.clone(), sync_state).await?;

    let recipient_handle = receiver_wallet.export_address()?;
    assert_eq!(sender_wallet.balance()?, 1);
    assert_eq!(receiver_wallet.balance()?, 0);

    let outcome = sender_wallet.pay(&recipient_handle, 1, &net).await?;
    let tx_id = outcome.tx_id;
    assert_eq!(outcome.input_count, 1);
    assert_eq!(outcome.output_count, 1);

    let tx_bytes = sender_db
        .get_raw_bytes("tx", &tx_id)?
        .expect("persisted tx bytes");
    let tx = unchained::canonical::decode_tx(&tx_bytes)?;
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);

    tx.apply(receiver_db.as_ref())?;
    receiver_wallet.scan_tx_for_me(&tx)?;

    assert_eq!(sender_wallet.balance()?, 0);
    assert_eq!(receiver_wallet.balance()?, 1);
    assert_eq!(receiver_wallet.list_owned_shielded_notes()?.len(), 1);

    net.shutdown().await;
    Ok(())
}
