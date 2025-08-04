# Unchained Blockchain - Technical Overview

## Project Summary

**Unchained** is a post-quantum blockchain implementation written in Rust that uses Dilithium3 signatures and Argon2id proof-of-work. It's designed to be quantum-resistant while maintaining high performance and security.

## Architecture Overview

### Core Components

1. **Blockchain Node** (`src/`) - Rust backend implementing the core blockchain logic
2. **Desktop UI** (`unchained-ui/`) - Tauri-based desktop application with React frontend
3. **Network Layer** - libp2p-based P2P networking with QUIC transport
4. **Storage Layer** - RocksDB for persistent blockchain data

### Key Technologies

- **Language**: Rust (2021 edition)
- **UI Framework**: Tauri 2.0 + React 18 + TypeScript
- **Styling**: Tailwind CSS 4.1
- **Networking**: libp2p with QUIC transport
- **Database**: RocksDB
- **Cryptography**: 
  - Dilithium3 for post-quantum signatures
  - Argon2id for memory-hard proof-of-work
  - BLAKE3 for hashing
  - X25519 + Kyber for quantum-resistant key exchange

## Core Data Structures

### Coin
```rust
pub struct Coin {
    pub id: [u8; 32],                    // BLAKE3 hash of epoch_hash + nonce + creator + pow_hash
    pub value: u64,                      // Always 1 for new coins
    pub epoch_hash: [u8; 32],            // Hash of the epoch anchor
    pub nonce: u64,                      // Mining nonce
    pub creator_address: Address,        // 32-byte address derived from public key
    pub pow_hash: [u8; 32],              // Argon2id hash result
}
```

### Transfer (Transaction)
```rust
pub struct Transfer {
    pub coin_id: [u8; 32],              // ID of the coin being spent
    pub sender_pk: [u8; DILITHIUM3_PK_BYTES], // Sender's public key
    pub to: Address,                     // Recipient address
    pub prev_tx_hash: [u8; 32],         // Hash of previous transaction (UTXO chain)
    pub sig: [u8; DILITHIUM3_SIG_BYTES], // Dilithium3 signature
}
```

### Anchor (Block)
```rust
pub struct Anchor {
    pub num: u64,                        // Epoch number
    pub hash: [u8; 32],                  // Merkle root of coins
    pub difficulty: usize,               // PoW difficulty (leading zeros)
    pub coin_count: u32,                 // Number of coins in epoch
    pub cumulative_work: u128,           // Total work done
    pub mem_kib: u32,                    // Argon2 memory parameter
}
```

## Consensus Mechanism

### Proof-of-Work
- **Algorithm**: Argon2id (memory-hard)
- **Target**: Configurable leading zeros (default: 1)
- **Memory**: Configurable (default: 16 MiB, adjustable 16-512 MiB)
- **Lanes**: Parallel processing (default: 2)

### Epoch System
- **Duration**: 22 seconds per epoch
- **Retargeting**: Every 2000 epochs
- **Target**: 3 coins per epoch
- **Chain Selection**: Highest cumulative work wins

### Mining Process
1. Generate epoch hash from previous anchor
2. Try nonces with Argon2id hashing
3. Check for required leading zeros
4. Create coin when difficulty target is met
5. Broadcast coin to network

## Network Protocol

### Transport Layer
- **Protocol**: QUIC over UDP
- **Port**: Configurable (default: 7777)
- **TLS**: Rustls with post-quantum support
- **Authentication**: Self-signed certificates

### P2P Networking
- **Framework**: libp2p
- **Discovery**: mDNS for local peers
- **Gossip**: Gossipsub for message propagation
- **Topics**:
  - `unchained/anchor/v1` - New anchors
  - `unchained/coin/v1` - New coins
  - `unchained/tx/v1` - New transfers
  - `unchained/epoch_request/v1` - Epoch sync requests
  - `unchained/coin_request/v1` - Coin sync requests

### Peer Management
- **Max Peers**: 10,000 (configurable)
- **Rate Limiting**: 100 messages per 60-second window
- **Peer Scoring**: Ban peers with >10 validation failures
- **Ban Duration**: 1 hour

## Storage Layer

### Database Schema
- **Engine**: RocksDB
- **Storage Path**: Configurable (default: `../blockchain_data`)
- **Key-Value Structure**:
  - Coins by ID
  - Transfers by hash
  - Anchors by epoch number
  - Wallet data
  - Network state

### Data Persistence
- **Serialization**: Bincode for Rust types
- **Compression**: Zstandard
- **Atomic Operations**: Write batches for consistency

## Cryptography Implementation

### Post-Quantum Signatures
- **Algorithm**: Dilithium3
- **Key Sizes**: 
  - Public Key: 1952 bytes
  - Secret Key: 4000 bytes
  - Signature: 3293 bytes
- **Security Level**: NIST Level 3

### Address Generation
```rust
pub type Address = [u8; 32];

pub fn address_from_pk(pk: &PublicKey) -> Address {
    *Hasher::new_derive_key("unchainedcoin-address")
        .update(pk.as_bytes())
        .finalize()
        .as_bytes()
}
```

### Proof-of-Work Hashing
```rust
pub fn argon2id_pow(input: &[u8], mem_kib: u32, lanes: u32) -> Result<[u8; 32] {
    let params = Params::new(mem_kib, 1, lanes, None)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = &blake3_hash(input)[..16];
    // ... hash computation
}
```

## Wallet System

### Key Management
- **Key Generation**: Dilithium3 keypairs
- **Storage**: Encrypted with ChaCha20-Poly1305
- **Password**: User-provided with Argon2id derivation
- **Backup**: Private keys stored locally

### Transaction Creation
1. Select unspent coins (UTXOs)
2. Create transfer with recipient address
3. Sign with Dilithium3
4. Broadcast to network

## UI Architecture

### Frontend Stack
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite 6.0
- **Styling**: Tailwind CSS 4.1
- **UI Components**: Radix UI primitives
- **Charts**: Recharts for data visualization
- **Forms**: React Hook Form with Zod validation

### Desktop Integration
- **Framework**: Tauri 2.0
- **Backend Communication**: Tauri commands
- **Security**: CSP disabled for development
- **Distribution**: Cross-platform builds

## Configuration System

### Network Configuration
```toml
[net]
listen_port = 7777
max_peers = 10000
connection_timeout_secs = 30
bootstrap = ["/ip4/192.168.1.101/udp/7777/quic-v1/p2p/PEER_ID"]
```

### Mining Configuration
```toml
[mining]
enabled = true
mem_kib = 16192
lanes = 2
min_mem_kib = 16192
max_mem_kib = 512007
max_memory_adjustment = 1.02
heartbeat_interval_secs = 140
max_consecutive_failures = 3
max_mining_attempts = 50000
```

### Epoch Configuration
```toml
[epoch]
seconds = 22
target_leading_zeros = 1
target_coins_per_epoch = 3
retarget_interval = 2000
max_difficulty_adjustment = 1.05
```

## Testing Strategy

### Test Coverage
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end blockchain operations
- **Adversarial Tests**: Security and attack vector testing
- **Performance Tests**: Mining and network performance

### Test Categories
- `blockchain_tests.rs` - Core blockchain logic
- `crypto_tests.rs` - Cryptographic operations
- `epoch_tests.rs` - Epoch management and consensus
- `miner_tests.rs` - Mining operations
- `network_tests.rs` - P2P networking
- `storage_tests.rs` - Database operations
- `wallet_tests.rs` - Wallet functionality

## Deployment & Operations

### Build Process
```bash
# Build blockchain node
cargo build --release

# Build desktop application
cd unchained-ui
npm install
npm run tauri build
```

### Node Operation
```bash
# Start mining node
cargo run --release --bin unchainedcoin mine

# Start non-mining node
cargo run --release --bin unchainedcoin
```

### Metrics & Monitoring
- **Endpoint**: `0.0.0.0:9100` (configurable)
- **Framework**: Prometheus
- **Metrics**: Mining rate, network peers, epoch progress

## Security Considerations

### Quantum Resistance
- **Signatures**: Dilithium3 (NIST PQC finalist)
- **Key Exchange**: X25519 + Kyber hybrid
- **Hash Functions**: BLAKE3 (quantum-resistant design)

### Network Security
- **Transport**: QUIC with TLS 1.3
- **Authentication**: Certificate-based peer verification
- **Rate Limiting**: Prevents DoS attacks
- **Peer Scoring**: Bans malicious peers

### Consensus Security
- **Memory-Hard PoW**: Resists ASIC mining
- **Difficulty Adjustment**: Dynamic based on network hash rate
- **Chain Selection**: Work-based fork resolution

## Development Guidelines

### Code Organization
- **Modular Design**: Each component in separate module
- **Error Handling**: Comprehensive Result types
- **Async/Await**: Tokio runtime for concurrency
- **Memory Safety**: Rust's ownership system

### Performance Considerations
- **Database**: RocksDB for high-throughput storage
- **Networking**: QUIC for low-latency communication
- **Mining**: Parallel Argon2id lanes
- **Serialization**: Efficient bincode encoding

### Future Enhancements
- **Lightning Network**: Layer 2 scaling
- **Smart Contracts**: WASM-based execution
- **Privacy**: Zero-knowledge proofs
- **Governance**: On-chain voting mechanisms

## Dependencies

### Core Dependencies
- `tokio` - Async runtime
- `libp2p` - P2P networking
- `rocksdb` - Database
- `pqcrypto-dilithium` - Post-quantum signatures
- `argon2` - Memory-hard hashing
- `blake3` - Fast hashing
- `rustls` - TLS implementation

### UI Dependencies
- `@tauri-apps/api` - Desktop integration
- `react` - UI framework
- `tailwindcss` - Styling
- `recharts` - Data visualization
- `zod` - Schema validation

This technical overview provides the essential context for understanding the Unchained blockchain project's architecture, implementation details, and operational considerations.