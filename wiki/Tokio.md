# Tokio

Tokio is an asynchronous runtime for Rust that provides the foundation for building reliable, scalable network applications. It enables high-performance concurrent operations without traditional threading overhead.

## Role in Unchained

Tokio serves as the core async runtime for all Unchained operations, managing concurrent tasks for networking, mining, storage, and blockchain operations.

### Async Architecture
- **Single-threaded Efficiency**: Handles thousands of connections without thread overhead
- **Work-stealing Scheduler**: Automatic load balancing across CPU cores
- **Non-blocking I/O**: Network and disk operations don't block other tasks
- **Structured Concurrency**: Clear task lifecycle management

### Key Components Used

#### Runtime
```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Multi-threaded runtime for CPU-intensive operations
    let rt = tokio::runtime::Runtime::new()?;
    
    // Spawn concurrent tasks for different subsystems
    tokio::spawn(network_task());
    tokio::spawn(mining_task());
    tokio::spawn(sync_task());
    
    Ok(())
}
```

#### Channels
- **mpsc**: Multi-producer, single-consumer channels for task communication
- **broadcast**: One-to-many message distribution
- **oneshot**: Single-value request-response patterns
- **watch**: Shared state updates with change notifications

#### Networking
- **TcpListener/TcpStream**: Async TCP connections
- **UdpSocket**: Async UDP for QUIC transport
- **Timer**: Interval tasks and timeouts
- **DNS Resolution**: Async hostname resolution

## Implementation in Unchained

### Concurrent Task Structure

```rust
// Main service orchestration
pub async fn run_node(config: Config) -> Result<()> {
    let (anchor_tx, anchor_rx) = tokio::sync::mpsc::unbounded_channel();
    let (coin_tx, coin_rx) = tokio::sync::mpsc::unbounded_channel();
    let (spend_tx, spend_rx) = tokio::sync::mpsc::unbounded_channel();

    // Spawn concurrent subsystems
    let network_handle = tokio::spawn(network::spawn(config.net, db.clone()));
    let miner_handle = tokio::spawn(miner::run(config.mining, anchor_rx));
    let epoch_handle = tokio::spawn(epoch::manager(db.clone(), coin_rx));
    
    // Coordinate shutdown and handle errors
    tokio::select! {
        result = network_handle => handle_network_result(result),
        result = miner_handle => handle_miner_result(result),
        result = epoch_handle => handle_epoch_result(result),
        _ = tokio::signal::ctrl_c() => shutdown_gracefully().await,
    }
}
```

### Async Mining
```rust
pub async fn mine_epoch(
    anchor: &Anchor,
    config: &MiningConfig,
    shutdown: CancellationToken
) -> Result<Option<CoinCandidate>> {
    let workers = config.workers;
    let (result_tx, mut result_rx) = mpsc::channel(workers);
    
    // Spawn parallel mining workers
    for worker_id in 0..workers {
        let tx = result_tx.clone();
        let anchor = anchor.clone();
        let shutdown = shutdown.clone();
        
        tokio::spawn(async move {
            mine_worker(worker_id, &anchor, tx, shutdown).await
        });
    }
    
    // Wait for first successful result or shutdown
    tokio::select! {
        result = result_rx.recv() => Ok(result.flatten()),
        _ = shutdown.cancelled() => Ok(None),
    }
}
```

### Network Event Loop
```rust
pub async fn network_event_loop(
    mut swarm: Swarm<Behaviour>,
    coin_tx: UnboundedSender<CoinCandidate>,
    spend_tx: UnboundedSender<Spend>,
) {
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(event) => handle_network_event(event).await,
                    SwarmEvent::ConnectionEstablished { .. } => update_peer_count(),
                    SwarmEvent::ConnectionClosed { .. } => update_peer_count(),
                    _ => {}
                }
            },
            Some(coin) = coin_rx.recv() => {
                broadcast_coin_candidate(&mut swarm, coin).await;
            },
            Some(spend) = spend_rx.recv() => {
                broadcast_spend(&mut swarm, spend).await;
            },
        }
    }
}
```

## Performance Benefits

### Concurrency Model
- **Cooperative Multitasking**: Tasks yield control voluntarily
- **No Context Switching**: Minimal overhead compared to OS threads
- **Scalable**: Handles thousands of concurrent operations
- **Memory Efficient**: Small stack size per task

### I/O Efficiency
- **Event-driven**: Based on epoll/kqueue for optimal OS integration
- **Zero-copy**: Minimizes data copying in network operations
- **Batching**: Groups I/O operations for efficiency
- **Backpressure**: Automatic flow control prevents memory exhaustion

## Configuration and Tuning

### Runtime Configuration
```rust
// Custom runtime for fine-tuned performance
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(num_cpus::get())
    .thread_name("unchained-worker")
    .thread_stack_size(2 * 1024 * 1024)
    .enable_all()
    .build()?;
```

### Task Management
- **Spawn**: Create new async tasks
- **JoinHandle**: Track task completion and results
- **Select**: Wait for first of multiple async operations
- **Timeout**: Add time limits to operations

## Error Handling

### Graceful Shutdown
```rust
async fn shutdown_gracefully() -> Result<()> {
    // Signal all tasks to stop
    shutdown_token.cancel();
    
    // Wait for cleanup with timeout
    tokio::time::timeout(
        Duration::from_secs(30),
        join_all(task_handles)
    ).await?;
    
    // Final cleanup
    flush_databases().await?;
    close_network_connections().await?;
    
    Ok(())
}
```

### Error Propagation
- **Result Types**: Structured error handling with `anyhow`
- **Panic Handling**: Isolate panics to individual tasks
- **Recovery**: Restart failed subsystems automatically
- **Logging**: Comprehensive error reporting

## Integration Points

### Database Operations
```rust
// Async database operations
async fn store_anchor(db: &Store, anchor: &Anchor) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        db.put_anchor(anchor)
    }).await?
}
```

### Networking
- **libp2p Integration**: Full async network stack
- **QUIC Transport**: Async UDP-based transport
- **HTTP Services**: Async web servers for metrics and admin
- **DNS Resolution**: Async hostname lookups

### Cryptographic Operations
```rust
// Offload CPU-intensive crypto to thread pool
async fn verify_signature_async(
    signature: DetachedSignature,
    message: Vec<u8>,
    public_key: PublicKey
) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        public_key.verify_detached_signature(&signature, &message)
    }).await?
}
```

## Monitoring and Debugging

### Metrics Collection
```rust
// Async metrics reporting
async fn metrics_server(bind_addr: SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(prometheus_metrics));
    
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await
}
```

### Task Monitoring
- **Task Names**: Descriptive names for debugging
- **Resource Usage**: Memory and CPU tracking per task
- **Blocking Detection**: Identify tasks that block the runtime
- **Async Stack Traces**: Debug async operation chains

## Best Practices

### Task Design
- **Small Tasks**: Keep individual tasks focused and lightweight
- **Yield Points**: Use `.await` regularly to allow other tasks to run
- **Cancellation**: Respect cancellation tokens for clean shutdown
- **Error Isolation**: Handle errors within tasks to prevent propagation

### Resource Management
- **Connection Pooling**: Reuse expensive resources like database connections
- **Bounded Channels**: Prevent unbounded memory growth
- **Timeouts**: Add timeouts to prevent hanging operations
- **Backpressure**: Implement flow control for high-throughput operations

### Debugging
- **Tracing**: Use `tracing` crate for async-aware logging
- **Task Names**: Assign meaningful names to spawned tasks
- **Panic Hooks**: Custom panic handlers for better error reporting
- **Performance Profiling**: Use tokio-console for runtime analysis