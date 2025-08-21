# Rust

Rust is a systems programming language focused on safety, speed, and concurrency. It prevents common programming errors through its ownership system while providing zero-cost abstractions.

## Role in Unchained

Rust serves as the primary programming language for the entire Unchained blockchain implementation, providing memory safety and performance critical for blockchain applications.

### Why Rust for Blockchain

- **Memory Safety**: Prevents buffer overflows, use-after-free, and data races
- **Performance**: Zero-cost abstractions with C/C++ level performance
- **Concurrency**: Safe concurrent programming with ownership guarantees
- **Cryptography**: Constant-time implementations prevent side-channel attacks
- **Reliability**: Compile-time error prevention reduces runtime failures

### Language Features Used

#### Ownership System
```rust
// Ownership prevents double-free and use-after-free
pub struct Anchor {
    pub num: u64,
    pub hash: [u8; 32],
    pub merkle_root: [u8; 32],
    // ... other fields
}

// Automatic cleanup when anchor goes out of scope
fn process_anchor(anchor: Anchor) {
    // anchor is moved here, preventing dangling references
    store_anchor_to_db(anchor);
} // anchor is automatically dropped
```

#### Type Safety
```rust
// Strong typing prevents common errors
pub struct CoinId([u8; 32]);
pub struct AnchorHash([u8; 32]);
pub struct EpochNum(u64);

// Compiler prevents mixing different hash types
fn verify_coin_inclusion(
    coin_id: &CoinId,          // Cannot pass AnchorHash here
    anchor_hash: &AnchorHash,  // Type safety guaranteed
    epoch: EpochNum            // Clear intent and type safety
) -> Result<bool> { ... }
```

#### Error Handling
```rust
use anyhow::{Result, Context};

// Explicit error handling without exceptions
pub fn load_anchor(epoch_num: u64) -> Result<Anchor> {
    let cf = self.db.cf_handle("epoch")
        .ok_or_else(|| anyhow!("Missing epoch column family"))?;
    
    let key = epoch_num.to_le_bytes();
    let bytes = self.db.get_cf(cf, &key)
        .with_context(|| format!("Failed to read epoch {}", epoch_num))?
        .ok_or_else(|| anyhow!("Epoch {} not found", epoch_num))?;
    
    bincode::deserialize(&bytes)
        .with_context(|| "Failed to deserialize anchor")
}
```

## Memory Management

### Zero-Copy Operations
```rust
// Efficient memory usage without garbage collection
pub fn verify_merkle_proof(
    leaf: &[u8; 32],        // Borrowed reference, no copy
    proof: &[[u8; 32]],     // Slice of hashes, no allocation
    root: &[u8; 32]         // Reference to expected root
) -> bool {
    let mut current = *leaf;
    for sibling in proof {
        // In-place computation, minimal allocations
        current = blake3_pair(&current, sibling);
    }
    current == *root
}
```

### RAII (Resource Acquisition Is Initialization)
```rust
// Automatic resource cleanup
impl Store {
    pub fn transaction(&self) -> Result<Transaction> {
        let batch = rocksdb::WriteBatch::default();
        Ok(Transaction { db: &self.db, batch })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // Automatic cleanup when transaction goes out of scope
        if !self.batch.is_empty() {
            eprintln!("Warning: Transaction dropped without commit");
        }
    }
}
```

## Concurrency and Safety

### Thread Safety
```rust
use std::sync::{Arc, Mutex};

// Shared state with compile-time race condition prevention
#[derive(Clone)]
pub struct SyncState {
    inner: Arc<Mutex<SyncStateInner>>,
}

impl SyncState {
    pub fn update_latest_epoch(&self, epoch: u64) {
        let mut state = self.inner.lock().unwrap();
        state.latest_epoch = epoch.max(state.latest_epoch);
    } // Mutex automatically unlocked
}
```

### Async Programming
```rust
// Safe async operations without data races
pub async fn sync_with_peer(
    peer_id: PeerId,
    start_epoch: u64,
    end_epoch: u64
) -> Result<Vec<Anchor>> {
    let request = SyncRequest { start_epoch, end_epoch };
    
    // Async operation with compile-time safety
    let response = network.request_response(peer_id, request).await?;
    
    // Process response safely
    validate_sync_response(response)
}
```

## Performance Characteristics

### Zero-Cost Abstractions
```rust
// High-level code compiles to efficient machine code
let anchors: Vec<Anchor> = epochs
    .iter()                           // Iterator trait
    .filter(|e| e.is_finalized())    // Functional programming
    .map(|e| e.anchor.clone())       // Transform
    .collect();                      // Collect results

// Compiles to tight loop with no runtime overhead
```

### Memory Layout Control
```rust
#[repr(C)]
pub struct CoinCandidate {
    pub coin_id: [u8; 32],      // Exact memory layout
    pub epoch_hash: [u8; 32],   // No padding or reordering
    pub pow_hash: [u8; 32],     // Compatible with C/FFI
    pub nonce: u64,
    pub creator_address: [u8; 32],
}
```

## Cryptographic Safety

### Constant-Time Operations
```rust
use subtle::ConstantTimeEq;

// Prevents timing attacks
pub fn verify_preimage(
    preimage: &[u8; 32],
    expected_hash: &[u8; 32]
) -> bool {
    let computed_hash = blake3::hash(preimage);
    // Constant-time comparison prevents side-channel attacks
    computed_hash.as_bytes().ct_eq(expected_hash).into()
}
```

### Secure Memory Handling
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct PrivateKey {
    key_material: [u8; 32],
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Automatically zero sensitive memory
        self.key_material.zeroize();
    }
}
```

## Development Toolchain

### Cargo Package Manager
```toml
[dependencies]
# Cryptography
blake3 = "1.5"
argon2 = "0.5"
pqcrypto-dilithium = "0.5.0"
pqcrypto-kyber = "0.8"

# Networking
libp2p = { git = "...", features = ["quic", "gossipsub"] }
tokio = { version = "1.36", features = ["full"] }

# Storage
rocksdb = "0.21"
serde = { version = "1.0", features = ["derive"] }
```

### Build Configuration
```rust
// Conditional compilation for different features
#[cfg(feature = "mining")]
pub mod miner;

#[cfg(target_os = "linux")]
pub fn optimize_for_linux() { ... }

#[cfg(test)]
mod tests {
    // Unit tests compiled only for testing
}
```

## Error Handling Philosophy

### Result Type
```rust
// Explicit error handling without exceptions
pub enum BlockchainError {
    InvalidSignature,
    DuplicateNullifier,
    InsufficientPoW,
    DatabaseError(String),
}

pub fn validate_spend(spend: &Spend) -> Result<(), BlockchainError> {
    verify_signature(&spend.signature)?;
    check_nullifier_uniqueness(&spend.nullifier)?;
    validate_unlock_preimage(&spend.unlock_preimage)?;
    Ok(())
}
```

### Error Context
```rust
use anyhow::{Context, Result};

// Rich error context for debugging
pub fn process_transaction(tx_bytes: &[u8]) -> Result<()> {
    let transaction = deserialize_transaction(tx_bytes)
        .context("Failed to deserialize transaction")?;
    
    validate_transaction(&transaction)
        .with_context(|| format!("Transaction validation failed for ID: {}", 
                                transaction.id()))?;
    
    apply_transaction(transaction)
        .context("Failed to apply transaction to state")
}
```

## Testing and Quality Assurance

### Unit Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_proof_verification() {
        let leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"];
        let tree = MerkleTree::new(&leaves);
        
        let proof = tree.generate_proof(0).unwrap();
        assert!(verify_merkle_proof(&leaves[0], &proof, &tree.root()));
    }
    
    #[tokio::test]
    async fn test_async_network_operation() {
        let result = sync_with_peer(test_peer_id(), 0, 10).await;
        assert!(result.is_ok());
    }
}
```

### Documentation Tests
```rust
/// Computes BLAKE3 hash with domain separation
/// 
/// # Examples
/// 
/// ```
/// use unchained::crypto::domain_hash;
/// 
/// let hash = domain_hash("test.domain", b"data");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn domain_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    // Implementation automatically tested
}
```

## Integration with Blockchain Requirements

### Deterministic Execution
- No undefined behavior or nondeterministic operations
- Reproducible builds across different environments
- Consistent results across different hardware platforms
- Explicit handling of all edge cases

### Performance Requirements
- Zero-cost abstractions for hot code paths
- Minimal memory allocations in consensus-critical code
- Efficient serialization and deserialization
- Optimal memory layout for cache efficiency

### Security Requirements
- Memory safety prevents exploitation of buffer overflows
- Type safety prevents confusion between different hash types
- Ownership prevents use-after-free vulnerabilities
- Explicit error handling prevents silent failures