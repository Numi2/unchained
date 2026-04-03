use crate::{
    coin::{Coin, CoinCandidate},
    crypto,
    epoch::Anchor,
    network::NetHandle,
    shielded::{CheckpointExtensionRequest, HistoricalUnspentExtension, NoteCommitmentTree, NullifierRootLedger},
    storage::Store,
    transaction::{self, ShieldedOutput, Tx},
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc},
};

use crate::sync::SyncState;

const NODE_CONTROL_SOCKET_FILE: &str = "node-control.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedRuntimeSnapshot {
    pub chain_id: [u8; 32],
    pub current_nullifier_epoch: u64,
    pub committed_coins: Vec<(u64, Coin)>,
    pub shielded_outputs: Vec<([u8; 32], u32, ShieldedOutput)>,
    pub note_tree: NoteCommitmentTree,
    pub root_ledger: NullifierRootLedger,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningWork {
    pub chain_id: [u8; 32],
    pub latest_anchor: Option<Anchor>,
    pub local_tip: u64,
    pub highest_seen_epoch: u64,
    pub peer_confirmed_tip: bool,
    pub synced: bool,
    pub mining_ready: bool,
}

pub fn build_shielded_runtime_snapshot(db: &Store) -> Result<ShieldedRuntimeSnapshot> {
    transaction::ensure_shielded_runtime_state(db)?;
    Ok(ShieldedRuntimeSnapshot {
        chain_id: db.effective_chain_id(),
        current_nullifier_epoch: transaction::current_nullifier_epoch(db)?,
        committed_coins: db.iterate_committed_coins()?,
        shielded_outputs: db.iterate_shielded_outputs()?,
        note_tree: db.load_shielded_note_tree()?.unwrap_or_default(),
        root_ledger: db.load_shielded_root_ledger()?.unwrap_or_default(),
    })
}

fn build_mining_work(
    db: &Store,
    sync_state: &Arc<Mutex<SyncState>>,
    bootstrap_configured: bool,
) -> Result<MiningWork> {
    let latest_anchor = db.get::<Anchor>("epoch", b"latest")?;
    let local_tip = latest_anchor.as_ref().map(|anchor| anchor.num).unwrap_or(0);
    let (synced, highest_seen_epoch, peer_confirmed_tip) = sync_state
        .lock()
        .map(|state| {
            (
                state.synced,
                state.highest_seen_epoch,
                state.peer_confirmed_tip,
            )
        })
        .unwrap_or((false, 0, false));
    let mining_ready = if bootstrap_configured {
        synced && highest_seen_epoch > 0 && local_tip >= highest_seen_epoch && peer_confirmed_tip
    } else {
        latest_anchor.is_some()
    };
    Ok(MiningWork {
        chain_id: db.effective_chain_id(),
        latest_anchor,
        local_tip,
        highest_seen_epoch,
        peer_confirmed_tip,
        synced,
        mining_ready,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlRequest {
    Ping,
    GetChainId,
    GetShieldedRuntimeSnapshot,
    GetMiningWork,
    GetSelectedCoinIdsForEpoch {
        epoch_num: u64,
    },
    RequestHistoricalExtensions {
        requests: Vec<CheckpointExtensionRequest>,
        rotation_round: u64,
    },
    SubmitCoinCandidate {
        candidate: CoinCandidate,
    },
    SubmitTx {
        tx: Tx,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlResponse {
    Pong,
    ChainId {
        chain_id: [u8; 32],
    },
    ShieldedRuntimeSnapshot {
        snapshot: ShieldedRuntimeSnapshot,
    },
    MiningWork {
        work: MiningWork,
    },
    SelectedCoinIds {
        epoch_num: u64,
        coin_ids: Vec<[u8; 32]>,
    },
    HistoricalExtensions {
        extensions: Vec<HistoricalUnspentExtension>,
    },
    SubmittedCoinCandidate {
        coin_id: [u8; 32],
    },
    SubmittedTx {
        tx_id: [u8; 32],
    },
    Error {
        message: String,
    },
}

pub fn node_control_socket_path(base_path: &str) -> PathBuf {
    Path::new(base_path).join(NODE_CONTROL_SOCKET_FILE)
}

#[derive(Debug, Clone)]
pub struct NodeControlClient {
    socket_path: PathBuf,
}

impl NodeControlClient {
    pub fn new(base_path: &str) -> Self {
        Self {
            socket_path: node_control_socket_path(base_path),
        }
    }

    fn call(&self, request: NodeControlRequest) -> Result<NodeControlResponse> {
        let mut stream = StdUnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "failed to connect to node control socket at {}. Start `unchained_node start` first",
                self.socket_path.display()
            )
        })?;

        let request_bytes =
            bincode::serialize(&request).context("failed to encode node control request")?;
        let request_len = u32::try_from(request_bytes.len())
            .map_err(|_| anyhow!("node control request too large"))?;
        stream
            .write_all(&request_len.to_le_bytes())
            .context("failed to send node control request length")?;
        stream
            .write_all(&request_bytes)
            .context("failed to send node control request")?;

        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .context("failed to read node control response length")?;
        let response_len = u32::from_le_bytes(len_bytes) as usize;
        let mut response_bytes = vec![0u8; response_len];
        stream
            .read_exact(&mut response_bytes)
            .context("failed to read node control response")?;

        let response: NodeControlResponse = bincode::deserialize(&response_bytes)
            .context("failed to decode node control response")?;
        match response {
            NodeControlResponse::Error { message } => Err(anyhow!(message)),
            other => Ok(other),
        }
    }

    pub fn ping(&self) -> Result<()> {
        match self.call(NodeControlRequest::Ping)? {
            NodeControlResponse::Pong => Ok(()),
            other => bail!("unexpected node control ping response: {other:?}"),
        }
    }

    pub fn chain_id(&self) -> Result<[u8; 32]> {
        match self.call(NodeControlRequest::GetChainId)? {
            NodeControlResponse::ChainId { chain_id } => Ok(chain_id),
            other => bail!("unexpected node control chain-id response: {other:?}"),
        }
    }

    pub fn shielded_runtime_snapshot(&self) -> Result<ShieldedRuntimeSnapshot> {
        match self.call(NodeControlRequest::GetShieldedRuntimeSnapshot)? {
            NodeControlResponse::ShieldedRuntimeSnapshot { snapshot } => Ok(snapshot),
            other => bail!("unexpected node control snapshot response: {other:?}"),
        }
    }

    pub fn mining_work(&self) -> Result<MiningWork> {
        match self.call(NodeControlRequest::GetMiningWork)? {
            NodeControlResponse::MiningWork { work } => Ok(work),
            other => bail!("unexpected node control mining-work response: {other:?}"),
        }
    }

    pub fn selected_coin_ids_for_epoch(&self, epoch_num: u64) -> Result<Vec<[u8; 32]>> {
        match self.call(NodeControlRequest::GetSelectedCoinIdsForEpoch { epoch_num })? {
            NodeControlResponse::SelectedCoinIds {
                epoch_num: response_epoch,
                coin_ids,
            } if response_epoch == epoch_num => Ok(coin_ids),
            other => bail!("unexpected node control selected-ids response: {other:?}"),
        }
    }

    pub fn request_historical_extensions(
        &self,
        requests: &[CheckpointExtensionRequest],
        rotation_round: u64,
    ) -> Result<Vec<HistoricalUnspentExtension>> {
        match self.call(NodeControlRequest::RequestHistoricalExtensions {
            requests: requests.to_vec(),
            rotation_round,
        })? {
            NodeControlResponse::HistoricalExtensions { extensions } => Ok(extensions),
            other => bail!("unexpected node control historical-extension response: {other:?}"),
        }
    }

    pub fn submit_coin_candidate(&self, candidate: &CoinCandidate) -> Result<[u8; 32]> {
        match self.call(NodeControlRequest::SubmitCoinCandidate {
            candidate: candidate.clone(),
        })? {
            NodeControlResponse::SubmittedCoinCandidate { coin_id } => Ok(coin_id),
            other => bail!("unexpected node control coin-candidate response: {other:?}"),
        }
    }

    pub fn submit_tx(&self, tx: &Tx) -> Result<[u8; 32]> {
        match self.call(NodeControlRequest::SubmitTx { tx: tx.clone() })? {
            NodeControlResponse::SubmittedTx { tx_id } => Ok(tx_id),
            other => bail!("unexpected node control submit response: {other:?}"),
        }
    }
}

pub struct NodeControlServer {
    socket_path: PathBuf,
    listener: UnixListener,
    db: Arc<Store>,
    net: NetHandle,
    sync_state: Arc<Mutex<SyncState>>,
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
    bootstrap_configured: bool,
}

impl NodeControlServer {
    pub async fn bind(
        base_path: &str,
        db: Arc<Store>,
        net: NetHandle,
        sync_state: Arc<Mutex<SyncState>>,
        coin_tx: mpsc::UnboundedSender<[u8; 32]>,
        bootstrap_configured: bool,
    ) -> Result<Self> {
        let socket_path = node_control_socket_path(base_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create node control directory at {}",
                    parent.display()
                )
            })?;
        }

        if socket_path.exists() {
            match UnixStream::connect(&socket_path).await {
                Ok(_) => {
                    bail!(
                        "node control socket already active at {}",
                        socket_path.display()
                    );
                }
                Err(_) => {
                    std::fs::remove_file(&socket_path).with_context(|| {
                        format!(
                            "failed to remove stale node control socket at {}",
                            socket_path.display()
                        )
                    })?;
                }
            }
        }

        let listener = UnixListener::bind(&socket_path).with_context(|| {
            format!(
                "failed to bind node control socket at {}",
                socket_path.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| {
                    format!(
                        "failed to lock down node control socket permissions at {}",
                        socket_path.display()
                    )
                })?;
        }

        Ok(Self {
            socket_path,
            listener,
            db,
            net,
            sync_state,
            coin_tx,
            bootstrap_configured,
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
                    let (stream, _) = accept_result.context("node control accept failed")?;
                    let db = self.db.clone();
                    let net = self.net.clone();
                    let sync_state = self.sync_state.clone();
                    let coin_tx = self.coin_tx.clone();
                    let bootstrap_configured = self.bootstrap_configured;
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(
                            db,
                            net,
                            sync_state,
                            coin_tx,
                            bootstrap_configured,
                            stream,
                        )
                        .await
                        {
                            eprintln!("node control connection failed: {err}");
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_candidate_submission(db: &Store, candidate: &CoinCandidate) -> Result<()> {
    if candidate.id
        != Coin::calculate_id(&candidate.epoch_hash, candidate.nonce, &candidate.creator_address)
    {
        bail!("coin candidate id mismatch");
    }
    if crypto::address_from_pk(&candidate.creator_pk) != candidate.creator_address {
        bail!("coin candidate creator public key does not match creator address");
    }
    let latest_anchor = db
        .get::<Anchor>("epoch", b"latest")?
        .ok_or_else(|| anyhow!("missing latest anchor"))?;
    if candidate.epoch_hash != latest_anchor.hash {
        bail!("coin candidate targets a stale or unknown epoch");
    }
    if latest_anchor.difficulty > 0
        && !candidate
            .pow_hash
            .iter()
            .take(latest_anchor.difficulty)
            .all(|byte| *byte == 0)
    {
        bail!("coin candidate pow hash does not satisfy current difficulty");
    }
    Ok(())
}

async fn accept_coin_candidate(
    db: &Store,
    net: &NetHandle,
    coin_tx: &mpsc::UnboundedSender<[u8; 32]>,
    candidate: CoinCandidate,
) -> Result<[u8; 32]> {
    validate_candidate_submission(db, &candidate)?;
    let key = Store::candidate_key(&candidate.epoch_hash, &candidate.id);
    db.put("coin_candidate", &key, &candidate)?;
    db.flush()?;
    coin_tx
        .send(candidate.id)
        .map_err(|_| anyhow!("epoch manager candidate channel dropped"))?;
    net.gossip_coin(&candidate).await;
    Ok(candidate.id)
}

impl Drop for NodeControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn handle_connection(
    db: Arc<Store>,
    net: NetHandle,
    sync_state: Arc<Mutex<SyncState>>,
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
    bootstrap_configured: bool,
    stream: UnixStream,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut len_bytes = [0u8; 4];
    if read_half.read_exact(&mut len_bytes).await.is_err() {
        return Ok(());
    }
    let request_len = u32::from_le_bytes(len_bytes) as usize;
    let mut request_bytes = vec![0u8; request_len];
    read_half
        .read_exact(&mut request_bytes)
        .await
        .context("failed to read node control request")?;

    let response = match bincode::deserialize::<NodeControlRequest>(&request_bytes) {
        Ok(request) => {
            handle_request(
                db.as_ref(),
                &net,
                &sync_state,
                &coin_tx,
                bootstrap_configured,
                request,
            )
            .await
        }
        Err(err) => NodeControlResponse::Error {
            message: format!("invalid node control request: {err}"),
        },
    };

    let response_bytes =
        bincode::serialize(&response).context("failed to encode node control response")?;
    let response_len = u32::try_from(response_bytes.len())
        .map_err(|_| anyhow!("node control response too large"))?;
    write_half
        .write_all(&response_len.to_le_bytes())
        .await
        .context("failed to write node control response length")?;
    write_half
        .write_all(&response_bytes)
        .await
        .context("failed to write node control response")?;
    write_half
        .shutdown()
        .await
        .context("failed to close node control connection")?;
    Ok(())
}

async fn handle_request(
    db: &Store,
    net: &NetHandle,
    sync_state: &Arc<Mutex<SyncState>>,
    coin_tx: &mpsc::UnboundedSender<[u8; 32]>,
    bootstrap_configured: bool,
    request: NodeControlRequest,
) -> NodeControlResponse {
    let result: Result<NodeControlResponse> = async {
        match request {
            NodeControlRequest::Ping => Ok(NodeControlResponse::Pong),
            NodeControlRequest::GetChainId => Ok(NodeControlResponse::ChainId {
                chain_id: db.effective_chain_id(),
            }),
            NodeControlRequest::GetShieldedRuntimeSnapshot => build_shielded_runtime_snapshot(db)
                .map(|snapshot| NodeControlResponse::ShieldedRuntimeSnapshot { snapshot }),
            NodeControlRequest::GetMiningWork => build_mining_work(db, sync_state, bootstrap_configured)
                .map(|work| NodeControlResponse::MiningWork { work }),
            NodeControlRequest::GetSelectedCoinIdsForEpoch { epoch_num } => {
                let coin_ids = db.get_selected_coin_ids_for_epoch(epoch_num)?;
                Ok(NodeControlResponse::SelectedCoinIds { epoch_num, coin_ids })
            }
            NodeControlRequest::RequestHistoricalExtensions {
                requests,
                rotation_round,
            } => {
                let extensions = net
                    .request_historical_extensions(&requests, rotation_round)
                    .await?;
                Ok(NodeControlResponse::HistoricalExtensions { extensions })
            }
            NodeControlRequest::SubmitCoinCandidate { candidate } => {
                let coin_id = accept_coin_candidate(db, net, coin_tx, candidate).await?;
                Ok(NodeControlResponse::SubmittedCoinCandidate { coin_id })
            }
            NodeControlRequest::SubmitTx { tx } => {
                let tx_id = tx.apply(db)?;
                net.gossip_tx(&tx).await;
                Ok(NodeControlResponse::SubmittedTx { tx_id })
            }
        }
    }
    .await;

    match result {
        Ok(response) => response,
        Err(err) => NodeControlResponse::Error {
            message: err.to_string(),
        },
    }
}
