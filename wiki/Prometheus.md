# Prometheus

Prometheus is an open-source monitoring and alerting toolkit designed for reliability and scalability. It collects metrics from applications and provides powerful querying capabilities.

## Role in Unchained

Prometheus provides comprehensive monitoring and observability for the Unchained blockchain node, tracking performance metrics, system health, and operational statistics.

### Metrics Collection
- **Node Performance**: CPU, memory, and disk usage
- **Blockchain Operations**: Block processing, transaction validation
- **Network Statistics**: Peer connections, message rates, bandwidth
- **Mining Metrics**: Hash rates, difficulty adjustments, coin production
- **Database Performance**: RocksDB operations, storage efficiency

### Implementation

```rust
use prometheus::{Counter, Histogram, Gauge, Registry, Encoder, TextEncoder};

// Define metrics for different subsystems
pub struct UnchainedMetrics {
    pub connected_peers: Gauge,
    pub processed_anchors: Counter,
    pub mining_attempts: Counter,
    pub validation_duration: Histogram,
    pub sync_progress: Gauge,
    pub database_operations: Counter,
}

impl UnchainedMetrics {
    pub fn new() -> Self {
        Self {
            connected_peers: Gauge::new("connected_peers", "Number of connected peers").unwrap(),
            processed_anchors: Counter::new("processed_anchors_total", "Total anchors processed").unwrap(),
            mining_attempts: Counter::new("mining_attempts_total", "Total mining attempts").unwrap(),
            validation_duration: Histogram::new("validation_duration_seconds", "Time spent validating").unwrap(),
            sync_progress: Gauge::new("sync_progress_percent", "Synchronization progress").unwrap(),
            database_operations: Counter::new("database_operations_total", "Database operations count").unwrap(),
        }
    }
}
```

## Configuration

```toml
[metrics]
bind = "127.0.0.1:9090"    # Metrics server address
```

### HTTP Metrics Endpoint

```rust
use tiny_http::{Server, Response, Method};

async fn metrics_server(bind_addr: String, metrics: Arc<UnchainedMetrics>) -> Result<()> {
    let server = Server::http(&bind_addr)?;
    
    for request in server.incoming_requests() {
        match request.method() {
            &Method::Get if request.url() == "/metrics" => {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer)?;
                
                let response = Response::from_string(String::from_utf8(buffer)?)
                    .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap());
                request.respond(response)?;
            },
            _ => {
                let response = Response::from_string("404 Not Found").with_status_code(404);
                request.respond(response)?;
            }
        }
    }
    Ok(())
}
```

## Key Metrics Categories

### Network Metrics
```rust
// Peer and network statistics
connected_peers_total          // Current peer count
network_messages_received      // Incoming message count
network_messages_sent         // Outgoing message count
network_bytes_received        // Incoming bandwidth
network_bytes_sent           // Outgoing bandwidth
peer_validation_failures     // Failed message validations
peer_connections_established // New peer connections
peer_connections_dropped     // Lost peer connections
```

### Blockchain Metrics
```rust
// Consensus and blockchain operations
current_epoch_number         // Latest epoch
anchors_processed_total      // Anchor processing count
coins_mined_total           // Coins successfully mined
difficulty_current          // Current mining difficulty
memory_kib_current          // Current Argon2 memory setting
chain_work_total           // Cumulative proof-of-work
reorg_events_total         // Blockchain reorganizations
```

### Mining Metrics
```rust
// Mining performance and statistics
mining_attempts_total       // Total mining attempts
mining_successes_total     // Successful coin mining
mining_workers_active      // Active mining threads
mining_hashrate_current    // Current hash rate
mining_difficulty_target   // Target difficulty bytes
mining_memory_usage_mb     // Memory usage for Argon2
mining_duration_seconds    // Time spent mining
```

### Storage Metrics
```rust
// Database and storage performance
database_operations_total   // RocksDB operations count
database_read_duration     // Read operation latency
database_write_duration    // Write operation latency
database_size_bytes       // Total database size
database_compactions_total // Compaction operations
storage_sync_progress     // Sync completion percentage
```

### System Metrics
```rust
// System resource utilization
process_cpu_usage_percent  // CPU utilization
process_memory_usage_bytes // Memory consumption
process_open_fds          // File descriptor count
process_threads_total     // Thread count
system_load_average       // System load
disk_usage_percent        // Disk space utilization
```

## Metrics Integration

### In Network Layer
```rust
impl NetworkHandler {
    async fn handle_anchor(&self, anchor: Anchor) -> Result<()> {
        let _timer = self.metrics.validation_duration.start_timer();
        
        // Validate anchor
        if self.validate_anchor(&anchor)? {
            self.metrics.processed_anchors.inc();
            self.store_anchor(anchor).await?;
        } else {
            self.metrics.validation_failures.inc();
        }
        
        Ok(())
    }
    
    async fn update_peer_count(&self, count: usize) {
        self.metrics.connected_peers.set(count as f64);
    }
}
```

### In Mining Subsystem
```rust
impl Miner {
    async fn mine_epoch(&self, anchor: &Anchor) -> Result<Option<CoinCandidate>> {
        let start_time = std::time::Instant::now();
        self.metrics.mining_attempts.inc();
        
        let result = self.perform_mining(anchor).await;
        
        if result.is_ok() {
            self.metrics.mining_successes.inc();
        }
        
        let duration = start_time.elapsed();
        self.metrics.mining_duration.observe(duration.as_secs_f64());
        
        result
    }
}
```

### In Storage Layer
```rust
impl Store {
    pub fn put_anchor(&self, anchor: &Anchor) -> Result<()> {
        let _timer = self.metrics.database_write_duration.start_timer();
        self.metrics.database_operations.inc();
        
        // Perform database operation
        let result = self.db.put_cf(self.epoch_cf, &key, &value);
        
        if result.is_err() {
            self.metrics.database_errors.inc();
        }
        
        result
    }
}
```

## Observability Features

### Custom Dashboards
```promql
# Example Prometheus queries for monitoring

# Network health
rate(network_messages_received[5m])
connected_peers_total

# Mining performance
rate(mining_successes_total[1h])
mining_hashrate_current

# Sync progress
sync_progress_percent
rate(anchors_processed_total[5m])

# System health
process_cpu_usage_percent
process_memory_usage_bytes / (1024 * 1024 * 1024)  # Convert to GB
```

### Alerting Rules
```yaml
# Example alerting rules
groups:
  - name: unchained_alerts
    rules:
      - alert: LowPeerCount
        expr: connected_peers_total < 3
        for: 5m
        annotations:
          summary: "Low peer count detected"
          
      - alert: HighValidationFailures
        expr: rate(validation_failures_total[5m]) > 0.1
        for: 2m
        annotations:
          summary: "High validation failure rate"
          
      - alert: SyncStalled
        expr: increase(anchors_processed_total[10m]) == 0
        for: 10m
        annotations:
          summary: "Sync appears to be stalled"
```

## Performance Monitoring

### Latency Tracking
```rust
// Histogram for operation latencies
let validation_histogram = Histogram::with_opts(
    HistogramOpts::new("validation_duration_seconds", "Validation latency")
        .buckets(vec![0.001, 0.01, 0.1, 1.0, 10.0])
)?;

// Usage
let timer = validation_histogram.start_timer();
validate_transaction(&transaction)?;
timer.observe_duration();
```

### Rate Limiting Monitoring
```rust
// Track rate limiting effectiveness
pub struct RateLimitMetrics {
    pub requests_allowed: Counter,
    pub requests_denied: Counter,
    pub rate_limit_resets: Counter,
}

impl RateLimiter {
    pub fn check_limit(&self, peer_id: &PeerId) -> bool {
        if self.within_limit(peer_id) {
            self.metrics.requests_allowed.inc();
            true
        } else {
            self.metrics.requests_denied.inc();
            false
        }
    }
}
```

## Security and Privacy

### Metric Sanitization
- No sensitive data (private keys, preimages) in metrics
- Aggregate statistics only, no individual transaction details
- Rate limiting on metrics endpoint to prevent abuse
- Optional authentication for metrics access

### Operational Security
```rust
// Secure metrics collection
pub fn sanitize_peer_id(peer_id: &PeerId) -> String {
    // Hash peer ID to prevent correlation
    let hash = blake3::hash(peer_id.to_bytes());
    hex::encode(&hash.as_bytes()[..8])
}

// Usage in metrics
let peer_hash = sanitize_peer_id(&peer_id);
metrics.peer_operations.with_label_values(&[&peer_hash]).inc();
```

## Integration with External Tools

### Grafana Integration
- Pre-built dashboards for Unchained metrics
- Visual representation of blockchain health
- Historical trend analysis
- Alert visualization and management

### Export Formats
- **Prometheus Format**: Native text-based exposition format
- **JSON Export**: For custom integrations
- **CSV Export**: For data analysis and reporting
- **OpenMetrics**: Industry-standard metrics format

### Third-party Integration
```rust
// Export metrics to external systems
pub async fn export_to_external(metrics: &UnchainedMetrics) -> Result<()> {
    let data = serde_json::json!({
        "timestamp": chrono::Utc::now().timestamp(),
        "connected_peers": metrics.connected_peers.get(),
        "current_epoch": metrics.current_epoch.get(),
        "mining_hashrate": metrics.mining_hashrate.get(),
    });
    
    // Send to external monitoring system
    send_to_external_api(data).await
}
```