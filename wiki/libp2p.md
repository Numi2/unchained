# libp2p

libp2p is a modular network stack for building peer-to-peer applications. It provides the networking foundation for Unchained's distributed blockchain protocol.

## Role in Unchained

libp2p handles all peer-to-peer networking operations, including peer discovery, message gossiping, and request-response protocols.

### Network Architecture

- **Transport**: QUIC over UDP for low-latency, multiplexed connections
- **Gossip Protocol**: Efficient broadcast of anchors, coins, and transfers
- **Request-Response**: Direct peer queries for specific data
- **Peer Discovery**: Bootstrap nodes and peer exchange
- **Connection Management**: Automatic peer lifecycle management

### Key Components

#### Transport Layer
```rust
// QUIC transport with post-quantum preferences
let transport = quic::tokio::Transport::new(quic::Config::new(&keypair))
    .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));
```

#### Gossipsub
- **Topics**: Separate channels for anchors, coins, and spends
- **Message Validation**: Strict validation with peer scoring
- **Flood Protection**: Rate limiting and quotas per peer
- **Mesh Network**: Maintains optimal peer connections

#### Request-Response
- **Proof Service**: On-demand Merkle proof retrieval
- **Sync Protocol**: Range requests for catching up
- **Latest Anchor**: Quick queries for current chain state

## Configuration

```toml
[net]
listen_port = 7667                    # UDP port for QUIC
bootstrap = []                        # Bootstrap peer multiaddrs
peer_exchange = true                  # Enable peer discovery
max_peers = 50                        # Maximum connected peers
public_ip = "1.2.3.4"                # Public IP if behind NAT
connection_timeout_secs = 30          # Connection timeout
sync_timeout_secs = 60               # Sync operation timeout

[p2p]
max_validation_failures_per_peer = 10 # Validation failure threshold
peer_ban_duration_secs = 3600        # Ban duration for bad peers
rate_limit_window_secs = 60          # Rate limiting window
max_messages_per_window = 1000       # Message rate limit
```

## Network Protocols

### Gossipsub Topics

1. **Anchors**: `/unchained/anchors/1.0.0`
   - Broadcasts finalized epoch anchors
   - Critical for chain synchronization
   - Validated for PoW and chain work

2. **Coins**: `/unchained/coins/1.0.0`
   - Provisional coin candidates during epochs
   - Used for mining coordination
   - Validated for PoW difficulty

3. **Spends**: `/unchained/spends/1.0.0`
   - V3 hashlock spend transactions
   - Enables mempool coordination
   - Validated for signatures and nullifiers

### Request-Response Protocols

#### Proof Service
```rust
// Request coin inclusion proof
pub struct ProofRequest {
    pub coin_id: [u8; 32],
    pub epoch_num: u64,
}

pub struct ProofResponse {
    pub merkle_path: Vec<[u8; 32]>,
    pub leaf_index: u32,
}
```

#### Sync Protocol
```rust
// Request epoch range for synchronization
pub struct SyncRequest {
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub max_anchors: u32,
}
```

## Security Features

### Peer Validation
- **Message Validation**: Cryptographic verification before gossip
- **Peer Scoring**: Track validation failures and ban bad actors
- **Rate Limiting**: Prevent spam and DoS attacks
- **Exponential Backoff**: Gradually increase penalties for repeated failures

### Connection Security
- **Identity Verification**: Cryptographic peer IDs
- **Transport Security**: QUIC provides encryption and authentication
- **Firewall Friendly**: Works through NAT with minimal configuration

## Performance Optimizations

### QUIC Benefits
- **Multiplexing**: Multiple streams over single connection
- **0-RTT**: Reduced connection establishment time
- **Loss Recovery**: Built-in congestion control
- **Head-of-line Blocking**: Eliminated via stream independence

### Gossip Efficiency
- **Mesh Topology**: Optimal message propagation
- **Message Deduplication**: Prevents redundant broadcasts
- **Selective Forwarding**: Intelligent peer selection
- **Compression**: Reduced bandwidth usage

## Implementation Details

### Network Spawning
```rust
pub async fn spawn(
    net_cfg: config::Net,
    p2p_cfg: config::P2p,
    db: Arc<Store>,
    sync_state: Arc<Mutex<SyncState>>,
) -> Result<NetHandle> {
    // Setup transport, gossipsub, and request-response
    // Handle incoming messages and peer events
    // Maintain sync state and peer connections
}
```

### Message Handling
- **Anchor Processing**: Validate PoW, update chain state, trigger sync
- **Coin Processing**: Add to candidate pool, validate difficulty
- **Spend Processing**: Check signatures, update mempool, broadcast

### Peer Management
- **Bootstrap**: Connect to configured bootstrap nodes
- **Discovery**: Learn about new peers through peer exchange
- **Maintenance**: Monitor connection health and replace failed peers
- **Limits**: Enforce maximum peer counts and connection rates

## Monitoring and Observability

### Metrics
- Connected peer count
- Message rates per topic
- Validation failure rates
- Bandwidth usage statistics
- Sync progress indicators

### Debugging
- Verbose network logging with `--quiet-net` flag
- Peer connection status
- Message validation details
- Sync state information

## NAT and Firewall Considerations

### Configuration
- **Public IP**: Set `public_ip` if behind NAT
- **Port Forwarding**: Open UDP port specified in `listen_port`
- **STUN/TURN**: Automatic NAT traversal when possible
- **Bootstrap Nodes**: Ensure connectivity to initial peers

### Troubleshooting
- Check firewall rules for UDP traffic
- Verify bootstrap node accessibility
- Monitor peer connection success rates
- Use network diagnostics for connectivity issues