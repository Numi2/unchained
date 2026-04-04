use crate::{
    crypto::{Address, TaggedSigningPublicKey},
    local_control::{self, AuthenticatedControlMessage, ControlCapability},
    node_control::NodeControlStateEnvelope,
    storage::wallet_store_path,
    transaction::SharedStateControlDocument,
    wallet::{SendOutcome, Wallet, WalletObservedState},
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex as StdMutex, Weak,
};
use std::time::Duration;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc, watch, Mutex as AsyncMutex},
    time,
};

const WALLET_CONTROL_SOCKET_FILE: &str = "wallet-control.sock";
const WALLET_CONTROL_CAPABILITY_FILE: &str = "wallet-control.cap";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletControlRequest {
    Ping,
    SubscribeState,
    ForceSync,
    MintReceiveHandle,
    DeriveGenesisLockSecret {
        coin_id: [u8; 32],
        chain_id: [u8; 32],
    },
    Send {
        recipient_handle: String,
        amount: u64,
    },
    SubmitSharedStateControl {
        document: SharedStateControlDocument,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletControlResponse {
    Pong,
    Synced,
    ReceiveHandle { handle: String },
    GenesisLockSecret { secret: [u8; 32] },
    Sent { outcome: SendOutcome },
    Submitted { outcome: SendOutcome },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletControlStateEnvelope {
    pub sequence: u64,
    pub node_state_sequence: u64,
    pub identity: WalletIdentity,
    pub state: WalletObservedState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WalletControlStreamMessage {
    State {
        envelope: WalletControlStateEnvelope,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletIdentity {
    pub address: Address,
    pub signing_pk: TaggedSigningPublicKey,
}

pub fn wallet_control_socket_path(base_path: &str) -> PathBuf {
    Path::new(&wallet_store_path(base_path)).join(WALLET_CONTROL_SOCKET_FILE)
}

pub fn wallet_control_capability_path(base_path: &str) -> PathBuf {
    Path::new(&wallet_store_path(base_path)).join(WALLET_CONTROL_CAPABILITY_FILE)
}

#[derive(Clone)]
pub struct WalletControlClient {
    inner: Arc<WalletControlClientInner>,
}

struct WalletControlClientInner {
    socket_path: PathBuf,
    capability_path: PathBuf,
    state_tx: watch::Sender<Option<WalletControlStateEnvelope>>,
    state_status: StdMutex<WalletControlClientStateStatus>,
    state_ready: Condvar,
    shutdown_requested: AtomicBool,
}

#[derive(Default)]
struct WalletControlClientStateStatus {
    worker_started: bool,
    latest_state: Option<WalletControlStateEnvelope>,
    last_error: Option<String>,
    stream_capability: Option<ControlCapability>,
}

impl WalletControlClient {
    pub fn new(base_path: &str) -> Self {
        let (state_tx, _) = watch::channel(None);
        Self {
            inner: Arc::new(WalletControlClientInner {
                socket_path: wallet_control_socket_path(base_path),
                capability_path: wallet_control_capability_path(base_path),
                state_tx,
                state_status: StdMutex::new(WalletControlClientStateStatus::default()),
                state_ready: Condvar::new(),
                shutdown_requested: AtomicBool::new(false),
            }),
        }
    }

    async fn connect(&self) -> Result<(UnixStream, ControlCapability)> {
        let stream = UnixStream::connect(&self.inner.socket_path)
            .await
            .with_context(|| {
            format!(
                "failed to connect to wallet control socket at {}. Start `unchained_wallet serve` first",
                self.inner.socket_path.display()
            )
        })?;
        let capability =
            local_control::read_capability_file(&self.inner.capability_path, "wallet control")?;
        Ok((stream, capability))
    }

    async fn call(&self, request: WalletControlRequest) -> Result<WalletControlResponse> {
        let (mut stream, capability) = self.connect().await?;

        local_control::write_async_frame(
            &mut stream,
            &AuthenticatedControlMessage::new(capability, request),
            "wallet control request",
        )
        .await?;

        let response = local_control::read_async_frame::<WalletControlResponse, _>(
            &mut stream,
            "wallet control response",
        )
        .await?
        .ok_or_else(|| anyhow!("wallet control server closed the connection without a response"))?;
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

    pub async fn state(&self) -> Result<WalletControlStateEnvelope> {
        self.current_state()
    }

    pub fn subscribe_state(&self) -> Result<watch::Receiver<Option<WalletControlStateEnvelope>>> {
        self.ensure_state_worker()?;
        Ok(self.inner.state_tx.subscribe())
    }

    pub async fn force_sync(&self) -> Result<()> {
        match self.call(WalletControlRequest::ForceSync).await? {
            WalletControlResponse::Synced => Ok(()),
            other => bail!("unexpected wallet control sync response: {other:?}"),
        }
    }

    pub async fn mint_receive_handle(&self) -> Result<String> {
        match self.call(WalletControlRequest::MintReceiveHandle).await? {
            WalletControlResponse::ReceiveHandle { handle } => Ok(handle),
            other => bail!("unexpected wallet control receive-handle response: {other:?}"),
        }
    }

    pub async fn identity(&self) -> Result<WalletIdentity> {
        Ok(self.state().await?.identity)
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

    pub async fn send(&self, recipient_handle: &str, amount: u64) -> Result<SendOutcome> {
        match self
            .call(WalletControlRequest::Send {
                recipient_handle: recipient_handle.to_string(),
                amount,
            })
            .await?
        {
            WalletControlResponse::Sent { outcome } => Ok(outcome),
            other => bail!("unexpected wallet control send response: {other:?}"),
        }
    }

    pub async fn submit_shared_state_control(
        &self,
        document: SharedStateControlDocument,
    ) -> Result<SendOutcome> {
        match self
            .call(WalletControlRequest::SubmitSharedStateControl { document })
            .await?
        {
            WalletControlResponse::Submitted { outcome } => Ok(outcome),
            other => bail!("unexpected wallet control shared-state submit response: {other:?}"),
        }
    }

    fn current_state(&self) -> Result<WalletControlStateEnvelope> {
        self.ensure_state_worker()?;
        let current_capability =
            local_control::read_capability_file(&self.inner.capability_path, "wallet control")?;
        let mut guard = self
            .inner
            .state_status
            .lock()
            .map_err(|_| anyhow!("wallet control state cache poisoned"))?;
        if let Some(stream_capability) = guard.stream_capability {
            if stream_capability != current_capability {
                bail!(
                    "wallet control capability changed; reconnect the client after restarting `unchained_wallet serve`"
                );
            }
        }
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
                bail!("timed out waiting for wallet control state stream");
            }
            let wait_for = deadline.saturating_duration_since(now);
            let (next_guard, _) = self
                .inner
                .state_ready
                .wait_timeout(guard, wait_for)
                .map_err(|_| anyhow!("wallet control state wait poisoned"))?;
            guard = next_guard;
        }
    }

    fn ensure_state_worker(&self) -> Result<()> {
        let mut guard = self
            .inner
            .state_status
            .lock()
            .map_err(|_| anyhow!("wallet control state cache poisoned"))?;
        if guard.worker_started {
            return Ok(());
        }
        guard.worker_started = true;
        drop(guard);

        let inner = Arc::downgrade(&self.inner);
        std::thread::Builder::new()
            .name("wallet-control-state".into())
            .spawn(move || WalletControlClientInner::run_state_stream_worker(inner))
            .context("failed to spawn wallet control state worker")?;
        Ok(())
    }
}

impl Drop for WalletControlClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.shutdown_requested.store(true, Ordering::SeqCst);
            self.inner.state_ready.notify_all();
        }
    }
}

impl WalletControlClientInner {
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
                "failed to connect to wallet control socket at {}. Start `unchained_wallet serve` first",
                self.socket_path.display()
            )
        })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .with_context(|| {
                format!(
                    "failed to configure wallet control state stream timeout for {}",
                    self.socket_path.display()
                )
            })?;
        let capability =
            local_control::read_capability_file(&self.capability_path, "wallet control")?;
        local_control::write_sync_frame(
            &mut stream,
            &AuthenticatedControlMessage::new(capability, WalletControlRequest::SubscribeState),
            "wallet control subscribe request",
        )?;
        loop {
            if self.shutdown_requested.load(Ordering::SeqCst) {
                return Ok(());
            }
            let message: WalletControlStreamMessage =
                match local_control::read_sync_frame(&mut stream, "wallet control state stream") {
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
                WalletControlStreamMessage::State { envelope } => {
                    self.publish_state(capability, envelope);
                }
                WalletControlStreamMessage::Error { message } => bail!(message),
            }
        }
    }

    fn publish_state(
        &self,
        stream_capability: ControlCapability,
        latest_state: WalletControlStateEnvelope,
    ) {
        if let Ok(mut guard) = self.state_status.lock() {
            guard.latest_state = Some(latest_state.clone());
            guard.last_error = None;
            guard.stream_capability = Some(stream_capability);
            self.state_ready.notify_all();
        }
        let _ = self.state_tx.send(Some(latest_state));
    }

    fn publish_stream_error(&self, last_error: String) {
        if let Ok(mut guard) = self.state_status.lock() {
            guard.last_error = Some(last_error);
            guard.stream_capability = None;
            self.state_ready.notify_all();
        }
    }
}

fn is_timeout_io_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io| matches!(io.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock))
            .unwrap_or(false)
    })
}

#[derive(Clone)]
struct WalletControlService {
    wallet: Arc<Wallet>,
    node_state: Option<crate::node_control::NodeControlClient>,
    op_lock: Arc<AsyncMutex<()>>,
}

impl WalletControlService {
    fn new(wallet: Arc<Wallet>) -> Result<Self> {
        Ok(Self {
            node_state: wallet.node_client().ok(),
            wallet,
            op_lock: Arc::new(AsyncMutex::new(())),
        })
    }

    fn identity(&self) -> WalletIdentity {
        WalletIdentity {
            address: self.wallet.address(),
            signing_pk: self.wallet.public_key().clone(),
        }
    }

    async fn observed_state_from_node(
        &self,
        node_state: &NodeControlStateEnvelope,
    ) -> Result<WalletObservedState> {
        let _guard = self.op_lock.lock().await;
        let wallet = self.wallet.clone();
        let head = node_state.state.compact_wallet_sync.clone();
        tokio::task::spawn_blocking(move || wallet.observed_state_for_compact_head(&head))
            .await
            .map_err(|err| anyhow!("wallet observed-state task failed: {err}"))?
    }

    async fn observed_state_from_compact_head(
        &self,
        head: &crate::node_control::CompactWalletSyncHead,
    ) -> Result<WalletObservedState> {
        let _guard = self.op_lock.lock().await;
        let wallet = self.wallet.clone();
        let head = head.clone();
        tokio::task::spawn_blocking(move || wallet.observed_state_for_compact_head(&head))
            .await
            .map_err(|err| anyhow!("wallet observed-state task failed: {err}"))?
    }

    async fn current_compact_head_and_state(
        &self,
    ) -> Result<(
        crate::node_control::CompactWalletSyncHead,
        WalletObservedState,
    )> {
        let wallet = self.wallet.clone();
        let head =
            tokio::task::spawn_blocking(move || wallet.compact_wallet_sync_head_for_control())
                .await
                .map_err(|err| anyhow!("wallet compact-head task failed: {err}"))??;
        let state = self.observed_state_from_compact_head(&head).await?;
        Ok((head, state))
    }

    async fn force_sync(&self) -> Result<()> {
        if let Some(node_state) = &self.node_state {
            let node_state = node_state.state()?;
            let _guard = self.op_lock.lock().await;
            let wallet = self.wallet.clone();
            let head = node_state.state.compact_wallet_sync.clone();
            tokio::task::spawn_blocking(move || wallet.observed_state_for_compact_head(&head))
                .await
                .map_err(|err| anyhow!("wallet force-sync task failed: {err}"))??;
        } else {
            let _ = self.current_compact_head_and_state().await?;
        }
        Ok(())
    }

    async fn mint_receive_handle(&self) -> Result<String> {
        let _guard = self.op_lock.lock().await;
        self.wallet.export_address()
    }

    async fn send(&self, recipient_handle: String, amount: u64) -> Result<SendOutcome> {
        let _guard = self.op_lock.lock().await;
        self.wallet
            .send_to_recipient_handle(&recipient_handle, amount)
            .await
    }

    async fn submit_shared_state_control(
        &self,
        document: SharedStateControlDocument,
    ) -> Result<SendOutcome> {
        let _guard = self.op_lock.lock().await;
        self.wallet
            .submit_shared_state_control_document(document)
            .await
    }
}

pub struct WalletControlServer {
    socket_path: PathBuf,
    capability_path: PathBuf,
    listener: UnixListener,
    capability: ControlCapability,
    service: Arc<WalletControlService>,
    state_tx: watch::Sender<WalletControlStateEnvelope>,
    state_refresh_tx: mpsc::UnboundedSender<()>,
    state_refresh_rx: mpsc::UnboundedReceiver<()>,
}

impl WalletControlServer {
    pub async fn bind(base_path: &str, wallet: Arc<Wallet>) -> Result<Self> {
        let socket_path = wallet_control_socket_path(base_path);
        let capability_path = wallet_control_capability_path(base_path);
        let listener = local_control::bind_local_listener(&socket_path, "wallet control").await?;
        let capability = local_control::write_capability_file(&capability_path, "wallet control")?;
        let service = Arc::new(WalletControlService::new(wallet)?);
        let (initial_state, initial_node_state_sequence) =
            if let Some(node_state) = service.node_state.as_ref() {
                let initial_node_state = node_state.state()?;
                let state = service
                    .observed_state_from_node(&initial_node_state)
                    .await?;
                (state, initial_node_state.sequence)
            } else {
                let (head, state) = service.current_compact_head_and_state().await?;
                (state, head.latest_finalized_anchor_num)
            };
        let initial_state = WalletControlStateEnvelope {
            sequence: 0,
            node_state_sequence: initial_node_state_sequence,
            identity: service.identity(),
            state: initial_state,
        };
        let (state_tx, _) = watch::channel(initial_state);
        let (state_refresh_tx, state_refresh_rx) = mpsc::unbounded_channel();

        Ok(Self {
            socket_path,
            capability_path,
            listener,
            capability,
            service,
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
        let publisher = tokio::spawn(run_wallet_state_publisher(
            self.service.clone(),
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
                    let (stream, _) = accept_result.context("wallet control accept failed")?;
                    let capability = self.capability;
                    let service = self.service.clone();
                    let state_rx = self.state_tx.subscribe();
                    let state_refresh_tx = self.state_refresh_tx.clone();
                    let connection_shutdown = shutdown_rx.resubscribe();
                    tokio::spawn(async move {
                        if let Err(err) = handle_connection(
                            capability,
                            service,
                            state_rx,
                            state_refresh_tx,
                            connection_shutdown,
                            stream,
                        )
                        .await
                        {
                            eprintln!("wallet control connection failed: {err}");
                        }
                    });
                }
            }
        }
        publisher.await.map_err(|err| anyhow!(err))??;
        Ok(())
    }
}

impl Drop for WalletControlServer {
    fn drop(&mut self) {
        local_control::remove_local_artifacts(&self.socket_path, &self.capability_path);
    }
}

async fn close_wallet_control_writer<W: AsyncWrite + Unpin>(
    writer: &mut W,
    label: &str,
) -> Result<()> {
    match writer.shutdown().await {
        Ok(()) => Ok(()),
        Err(err) if matches!(err.kind(), ErrorKind::BrokenPipe | ErrorKind::NotConnected) => Ok(()),
        Err(err) => Err(err).context(label.to_string()),
    }
}

async fn handle_connection(
    capability: ControlCapability,
    service: Arc<WalletControlService>,
    mut state_rx: watch::Receiver<WalletControlStateEnvelope>,
    state_refresh_tx: mpsc::UnboundedSender<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
    stream: UnixStream,
) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();
    let Some(request) = local_control::read_async_frame::<
        AuthenticatedControlMessage<WalletControlRequest>,
        _,
    >(&mut read_half, "wallet control request")
    .await?
    else {
        return Ok(());
    };
    let request_body = request.body;
    let is_subscription = matches!(&request_body, WalletControlRequest::SubscribeState);

    if let Err(err) =
        local_control::verify_capability(&capability, &request.capability, "wallet control")
    {
        if is_subscription {
            local_control::write_async_frame(
                &mut write_half,
                &WalletControlStreamMessage::Error {
                    message: err.to_string(),
                },
                "wallet control state stream",
            )
            .await?;
            close_wallet_control_writer(
                &mut write_half,
                "failed to close wallet control subscription",
            )
            .await?;
            return Ok(());
        }
        local_control::write_async_frame(
            &mut write_half,
            &WalletControlResponse::Error {
                message: err.to_string(),
            },
            "wallet control response",
        )
        .await?;
        close_wallet_control_writer(&mut write_half, "failed to close wallet control connection")
            .await?;
        return Ok(());
    }

    if is_subscription {
        let initial_envelope = state_rx.borrow().clone();
        local_control::write_async_frame(
            &mut write_half,
            &WalletControlStreamMessage::State {
                envelope: initial_envelope,
            },
            "wallet control state stream",
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
                        &WalletControlStreamMessage::State {
                            envelope: next_envelope,
                        },
                        "wallet control state stream",
                    )
                    .await?;
                }
            }
        }
        close_wallet_control_writer(
            &mut write_half,
            "failed to close wallet control subscription",
        )
        .await?;
        return Ok(());
    }

    let response = handle_request(service.as_ref(), &state_refresh_tx, request_body).await;
    local_control::write_async_frame(&mut write_half, &response, "wallet control response").await?;
    close_wallet_control_writer(&mut write_half, "failed to close wallet control connection")
        .await?;
    Ok(())
}

async fn handle_request(
    service: &WalletControlService,
    state_refresh_tx: &mpsc::UnboundedSender<()>,
    request: WalletControlRequest,
) -> WalletControlResponse {
    let result: Result<WalletControlResponse> = async {
        match request {
            WalletControlRequest::Ping => Ok(WalletControlResponse::Pong),
            WalletControlRequest::SubscribeState => {
                bail!("subscribe requests are handled by the wallet control stream transport")
            }
            WalletControlRequest::ForceSync => {
                service.force_sync().await?;
                let _ = state_refresh_tx.send(());
                Ok(WalletControlResponse::Synced)
            }
            WalletControlRequest::MintReceiveHandle => Ok(WalletControlResponse::ReceiveHandle {
                handle: service.mint_receive_handle().await?,
            }),
            WalletControlRequest::DeriveGenesisLockSecret { coin_id, chain_id } => {
                Ok(WalletControlResponse::GenesisLockSecret {
                    secret: service
                        .wallet
                        .compute_genesis_lock_secret(&coin_id, &chain_id),
                })
            }
            WalletControlRequest::Send {
                recipient_handle,
                amount,
            } => {
                let outcome = service.send(recipient_handle, amount).await?;
                let _ = state_refresh_tx.send(());
                Ok(WalletControlResponse::Sent { outcome })
            }
            WalletControlRequest::SubmitSharedStateControl { document } => {
                let outcome = service.submit_shared_state_control(document).await?;
                let _ = state_refresh_tx.send(());
                Ok(WalletControlResponse::Submitted { outcome })
            }
        }
    }
    .await;

    match result {
        Ok(response) => response,
        Err(err) => WalletControlResponse::Error {
            message: err.to_string(),
        },
    }
}

async fn run_wallet_state_publisher(
    service: Arc<WalletControlService>,
    state_tx: watch::Sender<WalletControlStateEnvelope>,
    mut state_refresh_rx: mpsc::UnboundedReceiver<()>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    let mut latest = state_tx.borrow().clone();
    let mut next_sequence = latest.sequence.saturating_add(1);
    if let Some(node_state) = service.node_state.as_ref() {
        let mut node_state_rx = node_state.subscribe_state()?;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                changed = node_state_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                refresh = state_refresh_rx.recv() => {
                    if refresh.is_none() {
                        break;
                    }
                }
            }

            let Some(node_state) = node_state_rx.borrow_and_update().clone() else {
                continue;
            };
            let next_state = match service.observed_state_from_node(&node_state).await {
                Ok(state) => state,
                Err(err) => {
                    eprintln!("wallet control state publisher failed to rebuild state: {err}");
                    continue;
                }
            };
            if next_state != latest.state || node_state.sequence != latest.node_state_sequence {
                latest = WalletControlStateEnvelope {
                    sequence: next_sequence,
                    node_state_sequence: node_state.sequence,
                    identity: service.identity(),
                    state: next_state,
                };
                next_sequence = next_sequence.saturating_add(1);
                let _ = state_tx.send(latest.clone());
            }
        }
    } else {
        let mut interval = time::interval(Duration::from_secs(1));
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
            let (head, next_state) = match service.current_compact_head_and_state().await {
                Ok(state) => state,
                Err(err) => {
                    eprintln!("wallet control state publisher failed to rebuild state: {err}");
                    continue;
                }
            };
            let node_state_sequence = head.latest_finalized_anchor_num;
            if next_state != latest.state || node_state_sequence != latest.node_state_sequence {
                latest = WalletControlStateEnvelope {
                    sequence: next_sequence,
                    node_state_sequence,
                    identity: service.identity(),
                    state: next_state,
                };
                next_sequence = next_sequence.saturating_add(1);
                let _ = state_tx.send(latest.clone());
            }
        }
    }
    Ok(())
}
