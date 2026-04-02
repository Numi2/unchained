use crate::{
    crypto::{Address, TaggedSigningPublicKey},
    storage::wallet_store_path,
    wallet::Wallet,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::broadcast,
};

const WALLET_CONTROL_SOCKET_FILE: &str = "wallet-control.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WalletControlRequest {
    Ping,
    GetMiningIdentity,
    DeriveGenesisLockSecret {
        coin_id: [u8; 32],
        chain_id: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WalletControlResponse {
    Pong,
    MiningIdentity {
        address: Address,
        signing_pk: TaggedSigningPublicKey,
    },
    GenesisLockSecret {
        secret: [u8; 32],
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningIdentity {
    pub address: Address,
    pub signing_pk: TaggedSigningPublicKey,
}

pub fn wallet_control_socket_path(base_path: &str) -> PathBuf {
    Path::new(&wallet_store_path(base_path)).join(WALLET_CONTROL_SOCKET_FILE)
}

#[derive(Debug, Clone)]
pub struct WalletControlClient {
    socket_path: PathBuf,
}

impl WalletControlClient {
    pub fn new(base_path: &str) -> Self {
        Self {
            socket_path: wallet_control_socket_path(base_path),
        }
    }

    async fn call(&self, request: WalletControlRequest) -> Result<WalletControlResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).await.with_context(|| {
            format!(
                "failed to connect to wallet control socket at {}. Start `unchained_wallet serve` first",
                self.socket_path.display()
            )
        })?;

        let mut request_line =
            serde_json::to_vec(&request).context("failed to encode wallet control request")?;
        request_line.push(b'\n');
        stream
            .write_all(&request_line)
            .await
            .context("failed to send wallet control request")?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .context("failed to read wallet control response")?;
        if read == 0 {
            bail!("wallet control server closed the connection without a response");
        }

        let response: WalletControlResponse = serde_json::from_str(line.trim())
            .context("failed to decode wallet control response")?;
        match response {
            WalletControlResponse::Error { message } => Err(anyhow!(message)),
            other => Ok(other),
        }
    }

    pub async fn ping(&self) -> Result<()> {
        match self.call(WalletControlRequest::Ping).await? {
            WalletControlResponse::Pong => Ok(()),
            other => bail!("unexpected wallet control ping response: {other:?}"),
        }
    }

    pub async fn mining_identity(&self) -> Result<MiningIdentity> {
        match self.call(WalletControlRequest::GetMiningIdentity).await? {
            WalletControlResponse::MiningIdentity {
                address,
                signing_pk,
            } => Ok(MiningIdentity {
                address,
                signing_pk,
            }),
            other => bail!("unexpected wallet control mining identity response: {other:?}"),
        }
    }

    pub async fn derive_genesis_lock_secret(
        &self,
        coin_id: [u8; 32],
        chain_id: [u8; 32],
    ) -> Result<[u8; 32]> {
        match self
            .call(WalletControlRequest::DeriveGenesisLockSecret { coin_id, chain_id })
            .await?
        {
            WalletControlResponse::GenesisLockSecret { secret } => Ok(secret),
            other => bail!("unexpected wallet control lock-secret response: {other:?}"),
        }
    }
}

pub struct WalletControlServer {
    socket_path: PathBuf,
    listener: UnixListener,
    wallet: Arc<Wallet>,
}

impl WalletControlServer {
    pub async fn bind(base_path: &str, wallet: Arc<Wallet>) -> Result<Self> {
        let socket_path = wallet_control_socket_path(base_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create wallet control directory at {}",
                    parent.display()
                )
            })?;
        }

        if socket_path.exists() {
            match UnixStream::connect(&socket_path).await {
                Ok(_) => {
                    bail!(
                        "wallet control socket already active at {}",
                        socket_path.display()
                    );
                }
                Err(_) => {
                    std::fs::remove_file(&socket_path).with_context(|| {
                        format!(
                            "failed to remove stale wallet control socket at {}",
                            socket_path.display()
                        )
                    })?;
                }
            }
        }

        let listener = UnixListener::bind(&socket_path).with_context(|| {
            format!(
                "failed to bind wallet control socket at {}",
                socket_path.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&socket_path, permissions).with_context(|| {
                format!(
                    "failed to lock down wallet control socket permissions at {}",
                    socket_path.display()
                )
            })?;
        }

        Ok(Self {
            socket_path,
            listener,
            wallet,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn serve(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                accept_result = self.listener.accept() => {
                    let (stream, _) = accept_result.context("wallet control accept failed")?;
                    let wallet = self.wallet.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(wallet, stream).await {
                            eprintln!("wallet control connection failed: {err}");
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

impl Drop for WalletControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn handle_connection(wallet: Arc<Wallet>, stream: UnixStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .context("failed to read wallet control request")?;
    if read == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<WalletControlRequest>(line.trim()) {
        Ok(request) => handle_request(wallet.as_ref(), request),
        Err(err) => WalletControlResponse::Error {
            message: format!("invalid wallet control request: {err}"),
        },
    };

    let mut response_line =
        serde_json::to_vec(&response).context("failed to encode wallet control response")?;
    response_line.push(b'\n');
    write_half
        .write_all(&response_line)
        .await
        .context("failed to write wallet control response")?;
    write_half
        .shutdown()
        .await
        .context("failed to close wallet control connection")?;
    Ok(())
}

fn handle_request(wallet: &Wallet, request: WalletControlRequest) -> WalletControlResponse {
    match request {
        WalletControlRequest::Ping => WalletControlResponse::Pong,
        WalletControlRequest::GetMiningIdentity => WalletControlResponse::MiningIdentity {
            address: wallet.address(),
            signing_pk: wallet.public_key().clone(),
        },
        WalletControlRequest::DeriveGenesisLockSecret { coin_id, chain_id } => {
            WalletControlResponse::GenesisLockSecret {
                secret: wallet.compute_genesis_lock_secret(&coin_id, &chain_id),
            }
        }
    }
}
