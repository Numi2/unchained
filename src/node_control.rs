use crate::{
    coin::Coin,
    consensus::ValidatorSet,
    epoch::Anchor,
    evidence::ConsensusEvidenceRecord,
    local_control::{self, AuthenticatedControlMessage, ControlCapability},
    network::NetHandle,
    shielded::{
        CheckpointExtensionRequest, HistoricalUnspentExtension, NoteCommitmentTree,
        NullifierRootLedger,
    },
    staking::{ValidatorPool, ValidatorRewardEvent},
    storage::Store,
    transaction::{self, ShieldedOutput, Tx},
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc, watch},
    time::{self, Duration, MissedTickBehavior},
};

use crate::sync::SyncState;

const NODE_CONTROL_SOCKET_FILE: &str = "node-control.sock";
const NODE_CONTROL_CAPABILITY_FILE: &str = "node-control.cap";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedRuntimeSnapshot {
    pub chain_id: [u8; 32],
    pub current_nullifier_epoch: u64,
    pub committed_coins: Vec<(u64, Coin)>,
    pub shielded_outputs: Vec<([u8; 32], u32, ShieldedOutput)>,
    pub note_tree: NoteCommitmentTree,
    pub root_ledger: NullifierRootLedger,
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
    pub shielded_runtime: ShieldedRuntimeSnapshot,
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
        shielded_runtime: build_shielded_runtime_snapshot(db)?,
        consensus_status: build_consensus_status(db, sync_state, bootstrap_configured)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlRequest {
    Ping,
    SubscribeState,
    RequestHistoricalExtensions {
        requests: Vec<CheckpointExtensionRequest>,
        rotation_round: u64,
    },
    SubmitTx {
        tx: Tx,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeControlResponse {
    Pong,
    HistoricalExtensions {
        extensions: Vec<HistoricalUnspentExtension>,
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
        Ok(self.current_state()?.state.shielded_runtime.chain_id)
    }

    pub fn shielded_runtime_snapshot(&self) -> Result<ShieldedRuntimeSnapshot> {
        Ok(self.current_state()?.state.shielded_runtime)
    }

    pub fn consensus_status(&self) -> Result<ConsensusStatus> {
        Ok(self.current_state()?.state.consensus_status)
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

    pub fn submit_tx(&self, tx: &Tx) -> Result<[u8; 32]> {
        match self.call(NodeControlRequest::SubmitTx { tx: tx.clone() })? {
            NodeControlResponse::SubmittedTx { tx_id } => Ok(tx_id),
            other => bail!("unexpected node control submit response: {other:?}"),
        }
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

        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name("node-control-state".into())
            .spawn(move || inner.run_state_stream_worker())
            .context("failed to spawn node control state worker")?;
        Ok(())
    }
}

impl NodeControlClientInner {
    fn run_state_stream_worker(self: Arc<Self>) {
        loop {
            if let Err(err) = self.run_state_stream_once() {
                self.publish_stream_error(err.to_string());
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
        let capability =
            local_control::read_capability_file(&self.capability_path, "node control")?;
        local_control::write_sync_frame(
            &mut stream,
            &AuthenticatedControlMessage::new(capability, NodeControlRequest::SubscribeState),
            "node control subscribe request",
        )?;
        loop {
            let message: NodeControlStreamMessage =
                local_control::read_sync_frame(&mut stream, "node control state stream")?;
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
    _db: &Store,
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
            NodeControlRequest::RequestHistoricalExtensions {
                requests,
                rotation_round,
            } => {
                let extensions = net
                    .request_historical_extensions(&requests, rotation_round)
                    .await?;
                Ok(NodeControlResponse::HistoricalExtensions { extensions })
            }
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
