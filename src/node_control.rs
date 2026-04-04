use crate::{
    coin::Coin,
    consensus::ValidatorSet,
    crypto::ML_KEM_768_CT_BYTES,
    epoch::Anchor,
    evidence::ConsensusEvidenceRecord,
    local_control::{self, AuthenticatedControlMessage, ControlCapability},
    network::NetHandle,
    shielded::{ArchivedNullifierEpoch, NoteCommitmentTree, NullifierRootLedger},
    staking::{ValidatorPool, ValidatorRewardEvent},
    storage::Store,
    transaction::{self, ShieldedOutput, Tx},
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::time::Duration as StdDuration;
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc, watch},
    time::{self, Duration, MissedTickBehavior},
};

use crate::sync::SyncState;

const NODE_CONTROL_SOCKET_FILE: &str = "node-control.sock";
const NODE_CONTROL_CAPABILITY_FILE: &str = "node-control.cap";
const COMPACT_SHIELDED_OUTPUT_NONCE_LEN: usize = 24;
const NODE_CONTROL_MAX_COMPACT_COINS_PER_DELTA: u32 = 512;
const NODE_CONTROL_MAX_COMPACT_OUTPUTS_PER_DELTA: u32 = 2048;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedRuntimeSnapshot {
    pub chain_id: [u8; 32],
    pub current_nullifier_epoch: u64,
    pub committed_coins: Vec<(u64, Coin)>,
    pub shielded_outputs: Vec<([u8; 32], u32, ShieldedOutput)>,
    pub note_tree: NoteCommitmentTree,
    pub root_ledger: NullifierRootLedger,
    pub archived_nullifier_epochs: Vec<ArchivedNullifierEpoch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactCommittedCoin {
    pub scan_index: u64,
    pub birth_epoch: u64,
    pub coin: Coin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactShieldedOutput {
    pub scan_index: u64,
    pub tx_id: [u8; 32],
    pub output_index: u32,
    pub note_commitment: [u8; 32],
    #[serde(with = "BigArray")]
    pub kem_ct: [u8; ML_KEM_768_CT_BYTES],
    #[serde(with = "BigArray")]
    pub nonce: [u8; COMPACT_SHIELDED_OUTPUT_NONCE_LEN],
    pub detection_tag: u8,
    pub ciphertext: Vec<u8>,
}

impl CompactShieldedOutput {
    fn from_shielded_output(
        scan_index: u64,
        tx_id: [u8; 32],
        output_index: u32,
        output: ShieldedOutput,
    ) -> Self {
        Self {
            scan_index,
            tx_id,
            output_index,
            note_commitment: output.note_commitment,
            kem_ct: output.kem_ct,
            nonce: output.nonce,
            detection_tag: output.view_tag,
            ciphertext: output.ciphertext,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactWalletSyncHead {
    pub chain_id: [u8; 32],
    pub current_nullifier_epoch: u64,
    pub latest_finalized_anchor_num: u64,
    pub committed_coin_count: u64,
    pub shielded_output_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactWalletSyncDelta {
    pub head: CompactWalletSyncHead,
    pub committed_coins: Vec<CompactCommittedCoin>,
    pub shielded_outputs: Vec<CompactShieldedOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletSendRuntimeMaterial {
    pub compact_wallet_sync: CompactWalletSyncHead,
    pub latest_finalized_anchor_epoch: u64,
    pub registered_validator_pools: Vec<ValidatorPool>,
    pub note_tree: NoteCommitmentTree,
    pub root_ledger: NullifierRootLedger,
    pub archived_nullifier_epochs: Vec<ArchivedNullifierEpoch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusStatus {
    pub chain_id: [u8; 32],
    pub latest_finalized_anchor: Option<Anchor>,
    pub active_validator_set: Option<ValidatorSet>,
    pub registered_validator_pools: Vec<ValidatorPool>,
    pub latest_anchor_reward_events: Vec<ValidatorRewardEvent>,
    pub latest_anchor_protocol_reward_total: u64,
    pub latest_anchor_fee_reward_total: u64,
    pub consensus_evidence_count: usize,
    pub recent_consensus_evidence: Vec<ConsensusEvidenceRecord>,
    pub local_tip: u64,
    pub highest_seen_epoch: u64,
    pub peer_confirmed_tip: bool,
    pub synced: bool,
    pub settlement_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeControlState {
    pub compact_wallet_sync: CompactWalletSyncHead,
    pub consensus_status: ConsensusStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeControlStateEnvelope {
    pub sequence: u64,
    pub state: NodeControlState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeControlStreamMessage {
    State { envelope: NodeControlStateEnvelope },
    Error { message: String },
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
        archived_nullifier_epochs: db.iterate_shielded_nullifier_epochs()?,
    })
}

pub fn build_compact_wallet_sync_head(db: &Store) -> Result<CompactWalletSyncHead> {
    transaction::ensure_shielded_runtime_state(db)?;
    let latest_finalized_anchor_num = db
        .get::<Anchor>("epoch", b"latest")?
        .map(|anchor| anchor.num)
        .unwrap_or(0);
    Ok(CompactWalletSyncHead {
        chain_id: db.effective_chain_id(),
        current_nullifier_epoch: transaction::current_nullifier_epoch(db)?,
        latest_finalized_anchor_num,
        committed_coin_count: db.count_committed_coins()?,
        shielded_output_count: db.count_shielded_outputs()?,
    })
}

pub fn build_compact_wallet_sync_delta(
    db: &Store,
    next_coin_index: u64,
    next_output_index: u64,
    max_coins: u32,
    max_outputs: u32,
) -> Result<CompactWalletSyncDelta> {
    let head = build_compact_wallet_sync_head(db)?;
    let committed_coins = db
        .load_committed_coin_slice(next_coin_index, max_coins as usize)?
        .into_iter()
        .enumerate()
        .map(|(offset, (birth_epoch, coin))| CompactCommittedCoin {
            scan_index: next_coin_index.saturating_add(offset as u64),
            birth_epoch,
            coin,
        })
        .collect();
    let shielded_outputs = db
        .load_shielded_output_slice(next_output_index, max_outputs as usize)?
        .into_iter()
        .enumerate()
        .map(|(offset, (tx_id, output_index, output))| {
            CompactShieldedOutput::from_shielded_output(
                next_output_index.saturating_add(offset as u64),
                tx_id,
                output_index,
                output,
            )
        })
        .collect();
    Ok(CompactWalletSyncDelta {
        head,
        committed_coins,
        shielded_outputs,
    })
}

pub fn build_wallet_send_runtime_material(db: &Store) -> Result<WalletSendRuntimeMaterial> {
    transaction::ensure_shielded_runtime_state(db)?;
    Ok(WalletSendRuntimeMaterial {
        compact_wallet_sync: build_compact_wallet_sync_head(db)?,
        latest_finalized_anchor_epoch: db
            .get::<Anchor>("epoch", b"latest")?
            .map(|anchor| anchor.position.epoch)
            .unwrap_or(0),
        registered_validator_pools: db.load_validator_pools()?,
        note_tree: db.load_shielded_note_tree()?.unwrap_or_default(),
        root_ledger: db.load_shielded_root_ledger()?.unwrap_or_default(),
        archived_nullifier_epochs: db.iterate_shielded_nullifier_epochs()?,
    })
}

fn build_consensus_status(
    db: &Store,
    sync_state: &Arc<Mutex<SyncState>>,
    bootstrap_configured: bool,
) -> Result<ConsensusStatus> {
    let latest_finalized_anchor = db.get::<Anchor>("epoch", b"latest")?;
    let active_validator_set = latest_finalized_anchor
        .as_ref()
        .map(|anchor| db.load_validator_committee(anchor.position.epoch))
        .transpose()?
        .flatten();
    let registered_validator_pools = db.load_validator_pools()?;
    let latest_anchor_reward_events = latest_finalized_anchor
        .as_ref()
        .map(|anchor| db.load_validator_reward_events_for_anchor(anchor.num))
        .transpose()?
        .unwrap_or_default();
    let latest_anchor_protocol_reward_total = latest_anchor_reward_events
        .iter()
        .fold(0u64, |sum, event| sum.saturating_add(event.protocol_reward));
    let latest_anchor_fee_reward_total = latest_anchor_reward_events
        .iter()
        .fold(0u64, |sum, event| sum.saturating_add(event.fee_reward));
    let mut consensus_evidence = db.load_consensus_evidence()?;
    let consensus_evidence_count = consensus_evidence.len();
    if consensus_evidence.len() > 16 {
        consensus_evidence.truncate(16);
    }
    let local_tip = latest_finalized_anchor
        .as_ref()
        .map(|anchor| anchor.num)
        .unwrap_or(0);
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
    let settlement_ready = if bootstrap_configured {
        synced && highest_seen_epoch > 0 && local_tip >= highest_seen_epoch && peer_confirmed_tip
    } else {
        latest_finalized_anchor.is_some()
    };
    Ok(ConsensusStatus {
        chain_id: db.effective_chain_id(),
        latest_finalized_anchor,
        active_validator_set,
        registered_validator_pools,
        latest_anchor_reward_events,
        latest_anchor_protocol_reward_total,
        latest_anchor_fee_reward_total,
        consensus_evidence_count,
        recent_consensus_evidence: consensus_evidence,
        local_tip,
        highest_seen_epoch,
        peer_confirmed_tip,
        synced,
        settlement_ready,
    })
}

fn build_node_control_state(
    db: &Store,
    sync_state: &Arc<Mutex<SyncState>>,
    bootstrap_configured: bool,
) -> Result<NodeControlState> {
    Ok(NodeControlState {
        compact_wallet_sync: build_compact_wallet_sync_head(db)?,
        consensus_status: build_consensus_status(db, sync_state, bootstrap_configured)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlRequest {
    Ping,
    SubscribeState,
    RuntimeSnapshot,
    WalletSendRuntimeMaterial,
    CompactWalletSyncDelta {
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    },
    SubmitTx {
        tx: Tx,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlResponse {
    Pong,
    RuntimeSnapshot { snapshot: ShieldedRuntimeSnapshot },
    WalletSendRuntimeMaterial { material: WalletSendRuntimeMaterial },
    CompactWalletSyncDelta { delta: CompactWalletSyncDelta },
    SubmittedTx { tx_id: [u8; 32] },
    Error { message: String },
}

pub fn node_control_socket_path(base_path: &str) -> PathBuf {
    Path::new(base_path).join(NODE_CONTROL_SOCKET_FILE)
}

pub fn node_control_capability_path(base_path: &str) -> PathBuf {
    Path::new(base_path).join(NODE_CONTROL_CAPABILITY_FILE)
}

#[derive(Clone)]
pub struct NodeControlClient {
    inner: Arc<NodeControlClientInner>,
}

struct NodeControlClientInner {
    socket_path: PathBuf,
    capability_path: PathBuf,
    state_tx: watch::Sender<Option<NodeControlStateEnvelope>>,
    state_status: Mutex<NodeControlClientStateStatus>,
    state_ready: Condvar,
    shutdown_requested: AtomicBool,
}

#[derive(Default)]
struct NodeControlClientStateStatus {
    worker_started: bool,
    latest_state: Option<NodeControlStateEnvelope>,
    last_error: Option<String>,
}

impl NodeControlClient {
    pub fn new(base_path: &str) -> Self {
        let (state_tx, _) = watch::channel(None);
        Self {
            inner: Arc::new(NodeControlClientInner {
                socket_path: node_control_socket_path(base_path),
                capability_path: node_control_capability_path(base_path),
                state_tx,
                state_status: Mutex::new(NodeControlClientStateStatus::default()),
                state_ready: Condvar::new(),
                shutdown_requested: AtomicBool::new(false),
            }),
        }
    }

    fn call(&self, request: NodeControlRequest) -> Result<NodeControlResponse> {
        let mut stream = StdUnixStream::connect(&self.inner.socket_path).with_context(|| {
            format!(
                "failed to connect to node control socket at {}. Start `unchained_node start` first",
                self.inner.socket_path.display()
            )
        })?;
        let capability =
            local_control::read_capability_file(&self.inner.capability_path, "node control")?;

        local_control::write_sync_frame(
            &mut stream,
            &AuthenticatedControlMessage::new(capability, request),
            "node control request",
        )?;
        let response: NodeControlResponse =
            local_control::read_sync_frame(&mut stream, "node control response")?;
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
        Ok(self.current_state()?.state.compact_wallet_sync.chain_id)
    }

    pub fn compact_wallet_sync_head(&self) -> Result<CompactWalletSyncHead> {
        Ok(self.current_state()?.state.compact_wallet_sync)
    }

    pub async fn compact_wallet_sync_head_async(&self) -> Result<CompactWalletSyncHead> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || client.compact_wallet_sync_head())
            .await
            .map_err(|err| anyhow!("node control compact-wallet-sync-head task failed: {err}"))?
    }

    pub fn request_compact_wallet_sync_delta(
        &self,
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    ) -> Result<CompactWalletSyncDelta> {
        match self.call(NodeControlRequest::CompactWalletSyncDelta {
            next_coin_index,
            next_output_index,
            max_coins,
            max_outputs,
        })? {
            NodeControlResponse::CompactWalletSyncDelta { delta } => Ok(delta),
            other => bail!("unexpected node control compact-wallet-sync response: {other:?}"),
        }
    }

    pub async fn request_compact_wallet_sync_delta_async(
        &self,
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    ) -> Result<CompactWalletSyncDelta> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            client.request_compact_wallet_sync_delta(
                next_coin_index,
                next_output_index,
                max_coins,
                max_outputs,
            )
        })
        .await
        .map_err(|err| anyhow!("node control compact-wallet-sync task failed: {err}"))?
    }

    pub fn shielded_runtime_snapshot(&self) -> Result<ShieldedRuntimeSnapshot> {
        match self.call(NodeControlRequest::RuntimeSnapshot)? {
            NodeControlResponse::RuntimeSnapshot { snapshot } => Ok(snapshot),
            other => bail!("unexpected node control runtime-snapshot response: {other:?}"),
        }
    }

    pub async fn shielded_runtime_snapshot_async(&self) -> Result<ShieldedRuntimeSnapshot> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || client.shielded_runtime_snapshot())
            .await
            .map_err(|err| anyhow!("node control runtime-snapshot task failed: {err}"))?
    }

    pub fn wallet_send_runtime_material(&self) -> Result<WalletSendRuntimeMaterial> {
        match self.call(NodeControlRequest::WalletSendRuntimeMaterial)? {
            NodeControlResponse::WalletSendRuntimeMaterial { material } => Ok(material),
            other => bail!("unexpected node control send-runtime-material response: {other:?}"),
        }
    }

    pub async fn wallet_send_runtime_material_async(&self) -> Result<WalletSendRuntimeMaterial> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || client.wallet_send_runtime_material())
            .await
            .map_err(|err| anyhow!("node control send-runtime-material task failed: {err}"))?
    }

    pub fn consensus_status(&self) -> Result<ConsensusStatus> {
        Ok(self.current_state()?.state.consensus_status)
    }

    pub fn submit_tx(&self, tx: &Tx) -> Result<[u8; 32]> {
        match self.call(NodeControlRequest::SubmitTx { tx: tx.clone() })? {
            NodeControlResponse::SubmittedTx { tx_id } => Ok(tx_id),
            other => bail!("unexpected node control submit response: {other:?}"),
        }
    }

    pub async fn submit_tx_async(&self, tx: &Tx) -> Result<[u8; 32]> {
        let client = self.clone();
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || client.submit_tx(&tx))
            .await
            .map_err(|err| anyhow!("node control async submit task failed: {err}"))?
    }

    pub fn state(&self) -> Result<NodeControlStateEnvelope> {
        self.current_state()
    }

    pub fn subscribe_state(&self) -> Result<watch::Receiver<Option<NodeControlStateEnvelope>>> {
        self.ensure_state_worker()?;
        Ok(self.inner.state_tx.subscribe())
    }

    fn current_state(&self) -> Result<NodeControlStateEnvelope> {
        self.ensure_state_worker()?;
        let mut guard = self
            .inner
            .state_status
            .lock()
            .map_err(|_| anyhow!("node control state cache poisoned"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(state) = guard.latest_state.clone() {
                return Ok(state);
            }
            if let Some(err) = guard.last_error.clone() {
                bail!(err);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                bail!("timed out waiting for node control state stream");
            }
            let wait_for = deadline.saturating_duration_since(now);
            let (next_guard, _) = self
                .inner
                .state_ready
                .wait_timeout(guard, wait_for)
                .map_err(|_| anyhow!("node control state wait poisoned"))?;
            guard = next_guard;
        }
    }

    fn ensure_state_worker(&self) -> Result<()> {
        let mut guard = self
            .inner
            .state_status
            .lock()
            .map_err(|_| anyhow!("node control state cache poisoned"))?;
        if guard.worker_started {
            return Ok(());
        }
        guard.worker_started = true;
        drop(guard);

        let inner = Arc::downgrade(&self.inner);
        std::thread::Builder::new()
            .name("node-control-state".into())
            .spawn(move || NodeControlClientInner::run_state_stream_worker(inner))
            .context("failed to spawn node control state worker")?;
        Ok(())
    }
}

impl Drop for NodeControlClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.shutdown_requested.store(true, Ordering::SeqCst);
            self.inner.state_ready.notify_all();
        }
    }
}

impl NodeControlClientInner {
    fn run_state_stream_worker(inner: Weak<Self>) {
        loop {
            let Some(inner) = inner.upgrade() else {
                break;
            };
            if inner.shutdown_requested.load(Ordering::SeqCst) {
                break;
            }
            if let Err(err) = inner.run_state_stream_once() {
                if inner.shutdown_requested.load(Ordering::SeqCst) && is_timeout_io_error(&err) {
                    break;
                }
                inner.publish_stream_error(err.to_string());
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    fn run_state_stream_once(&self) -> Result<()> {
        let mut stream = StdUnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "failed to connect to node control socket at {}. Start `unchained_node start` first",
                self.socket_path.display()
            )
        })?;
        stream
            .set_read_timeout(Some(StdDuration::from_millis(250)))
            .with_context(|| {
                format!(
                    "failed to configure node control state stream timeout for {}",
                    self.socket_path.display()
                )
            })?;
        let capability =
            local_control::read_capability_file(&self.capability_path, "node control")?;
        local_control::write_sync_frame(
            &mut stream,
            &AuthenticatedControlMessage::new(capability, NodeControlRequest::SubscribeState),
            "node control subscribe request",
        )?;
        loop {
            if self.shutdown_requested.load(Ordering::SeqCst) {
                return Ok(());
            }
            let message: NodeControlStreamMessage =
                match local_control::read_sync_frame(&mut stream, "node control state stream") {
                    Ok(message) => message,
                    Err(err) if is_timeout_io_error(&err) => {
                        if self.shutdown_requested.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            match message {
                NodeControlStreamMessage::State { envelope } => {
                    self.publish_state(envelope);
                }
                NodeControlStreamMessage::Error { message } => bail!(message),
            }
        }
    }

    fn publish_state(&self, latest_state: NodeControlStateEnvelope) {
        if let Ok(mut guard) = self.state_status.lock() {
            guard.latest_state = Some(latest_state.clone());
            guard.last_error = None;
            self.state_ready.notify_all();
        }
        let _ = self.state_tx.send(Some(latest_state));
    }

    fn publish_stream_error(&self, last_error: String) {
        if let Ok(mut guard) = self.state_status.lock() {
            guard.last_error = Some(last_error);
            self.state_ready.notify_all();
        }
    }
}

fn is_timeout_io_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                )
            })
            .unwrap_or(false)
    })
}

pub struct NodeControlServer {
    socket_path: PathBuf,
    capability_path: PathBuf,
    listener: UnixListener,
    capability: ControlCapability,
    db: Arc<Store>,
    net: NetHandle,
    sync_state: Arc<Mutex<SyncState>>,
    bootstrap_configured: bool,
    state_tx: watch::Sender<NodeControlStateEnvelope>,
    state_refresh_tx: mpsc::UnboundedSender<()>,
    state_refresh_rx: mpsc::UnboundedReceiver<()>,
}

impl NodeControlServer {
    pub async fn bind(
        base_path: &str,
        db: Arc<Store>,
        net: NetHandle,
        sync_state: Arc<Mutex<SyncState>>,
        bootstrap_configured: bool,
    ) -> Result<Self> {
        let socket_path = node_control_socket_path(base_path);
        let capability_path = node_control_capability_path(base_path);
        let listener = local_control::bind_local_listener(&socket_path, "node control").await?;
        let capability = local_control::write_capability_file(&capability_path, "node control")?;
        let initial_state = NodeControlStateEnvelope {
            sequence: 0,
            state: build_node_control_state(db.as_ref(), &sync_state, bootstrap_configured)?,
        };
        let (state_tx, _) = watch::channel(initial_state);
        let (state_refresh_tx, state_refresh_rx) = mpsc::unbounded_channel();

        Ok(Self {
            socket_path,
            capability_path,
            listener,
            capability,
            db,
            net,
            sync_state,
            bootstrap_configured,
            state_tx,
            state_refresh_tx,
            state_refresh_rx,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn serve(mut self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let publisher_shutdown = shutdown_rx.resubscribe();
        let publisher = tokio::spawn(run_state_publisher(
            self.db.clone(),
            self.sync_state.clone(),
            self.bootstrap_configured,
            self.state_tx.clone(),
            std::mem::replace(&mut self.state_refresh_rx, mpsc::unbounded_channel().1),
            publisher_shutdown,
        ));
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                accept_result = self.listener.accept() => {
                    let (stream, _) = accept_result.context("node control accept failed")?;
                    let db = self.db.clone();
                    let net = self.net.clone();
                    let capability = self.capability;
                    let state_rx = self.state_tx.subscribe();
                    let state_refresh_tx = self.state_refresh_tx.clone();
                    let connection_shutdown = shutdown_rx.resubscribe();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(
                            capability,
                            db,
                            net,
                            state_rx,
                            state_refresh_tx,
                            connection_shutdown,
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
        publisher.await.map_err(|err| anyhow!(err))??;
        Ok(())
    }
}

impl Drop for NodeControlServer {
    fn drop(&mut self) {
        local_control::remove_local_artifacts(&self.socket_path, &self.capability_path);
    }
}

async fn handle_connection(
    capability: ControlCapability,
    db: Arc<Store>,
    net: NetHandle,
    mut state_rx: watch::Receiver<NodeControlStateEnvelope>,
    state_refresh_tx: mpsc::UnboundedSender<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
    stream: UnixStream,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let Some(request) = local_control::read_async_frame::<
        AuthenticatedControlMessage<NodeControlRequest>,
        _,
    >(&mut read_half, "node control request")
    .await?
    else {
        return Ok(());
    };
    let request_body = request.body;
    let is_subscription = matches!(&request_body, NodeControlRequest::SubscribeState);

    if let Err(err) =
        local_control::verify_capability(&capability, &request.capability, "node control")
    {
        if is_subscription {
            local_control::write_async_frame(
                &mut write_half,
                &NodeControlStreamMessage::Error {
                    message: err.to_string(),
                },
                "node control state stream",
            )
            .await?;
            write_half
                .shutdown()
                .await
                .context("failed to close node control subscription")?;
            return Ok(());
        }
        local_control::write_async_frame(
            &mut write_half,
            &NodeControlResponse::Error {
                message: err.to_string(),
            },
            "node control response",
        )
        .await?;
        write_half
            .shutdown()
            .await
            .context("failed to close node control connection")?;
        return Ok(());
    }

    if is_subscription {
        let initial_envelope = state_rx.borrow().clone();
        local_control::write_async_frame(
            &mut write_half,
            &NodeControlStreamMessage::State {
                envelope: initial_envelope,
            },
            "node control state stream",
        )
        .await?;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let next_envelope = state_rx.borrow_and_update().clone();
                    local_control::write_async_frame(
                        &mut write_half,
                        &NodeControlStreamMessage::State {
                            envelope: next_envelope,
                        },
                        "node control state stream",
                    )
                    .await?;
                }
            }
        }
        write_half
            .shutdown()
            .await
            .context("failed to close node control subscription")?;
        return Ok(());
    }
    let response = handle_request(db.as_ref(), &net, &state_refresh_tx, request_body).await;

    local_control::write_async_frame(&mut write_half, &response, "node control response").await?;
    write_half
        .shutdown()
        .await
        .context("failed to close node control connection")?;
    Ok(())
}

async fn handle_request(
    db: &Store,
    net: &NetHandle,
    state_refresh_tx: &mpsc::UnboundedSender<()>,
    request: NodeControlRequest,
) -> NodeControlResponse {
    let result: Result<NodeControlResponse> = async {
        match request {
            NodeControlRequest::Ping => Ok(NodeControlResponse::Pong),
            NodeControlRequest::SubscribeState => {
                bail!("subscribe requests are handled by the node control stream transport")
            }
            NodeControlRequest::RuntimeSnapshot => Ok(NodeControlResponse::RuntimeSnapshot {
                snapshot: build_shielded_runtime_snapshot(db)?,
            }),
            NodeControlRequest::WalletSendRuntimeMaterial => {
                Ok(NodeControlResponse::WalletSendRuntimeMaterial {
                    material: build_wallet_send_runtime_material(db)?,
                })
            }
            NodeControlRequest::CompactWalletSyncDelta {
                next_coin_index,
                next_output_index,
                max_coins,
                max_outputs,
            } => Ok(NodeControlResponse::CompactWalletSyncDelta {
                delta: build_compact_wallet_sync_delta(
                    db,
                    next_coin_index,
                    next_output_index,
                    max_coins.min(NODE_CONTROL_MAX_COMPACT_COINS_PER_DELTA),
                    max_outputs.min(NODE_CONTROL_MAX_COMPACT_OUTPUTS_PER_DELTA),
                )?,
            }),
            NodeControlRequest::SubmitTx { tx } => {
                let tx_id = net.submit_tx(&tx).await?;
                let _ = state_refresh_tx.send(());
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

async fn run_state_publisher(
    db: Arc<Store>,
    sync_state: Arc<Mutex<SyncState>>,
    bootstrap_configured: bool,
    state_tx: watch::Sender<NodeControlStateEnvelope>,
    mut state_refresh_rx: mpsc::UnboundedReceiver<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    let mut latest = state_tx.borrow().clone();
    let mut next_sequence = latest.sequence.saturating_add(1);
    let mut interval = time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                break;
            }
            _ = interval.tick() => {}
            refresh = state_refresh_rx.recv() => {
                if refresh.is_none() {
                    break;
                }
            }
        }
        let next_state =
            match build_node_control_state(db.as_ref(), &sync_state, bootstrap_configured) {
                Ok(state) => state,
                Err(err) => {
                    eprintln!("node control state publisher failed to rebuild state: {err}");
                    continue;
                }
            };
        if next_state != latest.state {
            latest = NodeControlStateEnvelope {
                sequence: next_sequence,
                state: next_state,
            };
            next_sequence = next_sequence.saturating_add(1);
            let _ = state_tx.send(latest.clone());
        }
    }
    Ok(())
}
