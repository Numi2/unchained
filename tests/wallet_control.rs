use anyhow::Result;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::broadcast;
use unchained::{
    storage::WalletStore,
    wallet::Wallet,
    wallet_control::{WalletControlClient, WalletControlServer},
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

#[tokio::test(flavor = "multi_thread")]
async fn wallet_control_serves_mining_identity_and_lock_derivation() -> Result<()> {
    let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "wallet-control-test-passphrase");
    let tempdir = tempdir()?;
    let base_path = tempdir.path().to_string_lossy().to_string();
    let wallet_store = Arc::new(WalletStore::open(&base_path)?);
    let wallet = Arc::new(Wallet::load_or_create_private(wallet_store.clone())?);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let server = WalletControlServer::bind(&base_path, wallet.clone()).await?;
    let server_task = tokio::spawn(async move { server.serve(shutdown_rx).await });

    let client = WalletControlClient::new(&base_path);
    client.ping().await?;

    let identity = client.mining_identity().await?;
    assert_eq!(identity.address, wallet.address());
    assert_eq!(identity.signing_pk, wallet.public_key().clone());

    let coin_id = [3u8; 32];
    let chain_id = [7u8; 32];
    let derived = client.derive_genesis_lock_secret(coin_id, chain_id).await?;
    assert_eq!(
        derived,
        wallet.compute_genesis_lock_secret(&coin_id, &chain_id)
    );

    let _ = shutdown_tx.send(());
    server_task.await??;
    drop(wallet);
    wallet_store.close()?;
    Ok(())
}
