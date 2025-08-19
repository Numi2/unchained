# BLAKE3

BLAKE3 is a cryptographic hash function that provides fast, secure hashing with additional features like keyed hashing and key derivation.

## Role in Unchained

BLAKE3 serves as the primary cryptographic hash function throughout Unchained, providing:

### Domain Separation
- **Nullifiers**: `BLAKE3("nfV3" || chain_id32 || coin_id32 || unlock_preimage32)`
- **Lock Hashes**: `BLAKE3("unchained.lock.v1", preimage)`
- **Coin IDs**: `BLAKE3(epoch_hash, nonce, creator_address)`
- **Anchor Hashes**: `BLAKE3(merkle_root, prev_anchor.hash)`

### Commitment Schemes
- Binds outputs to immutable data via BLAKE3 commitments
- Avoids circular dependencies in transactions
- Ensures deterministic verification across all nodes

### Merkle Tree Construction
- Used for epoch Merkle root calculation
- Provides compact inclusion proofs
- Supports efficient light client verification

## Implementation Details

```rust
use blake3::Hasher;

// Domain-separated hashing
pub fn domain_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(data);
    hasher.finalize().into()
}
```

## Key Properties

- **Speed**: Significantly faster than SHA-256
- **Security**: Based on ChaCha permutation, cryptographically secure
- **Parallelism**: Inherently parallel design
- **Domain Separation**: Built-in support for different use cases
- **Determinism**: Identical inputs always produce identical outputs

## Configuration

BLAKE3 requires no configuration in Unchained - it uses default parameters for optimal security and performance.

## Security Model

- Provides 128-bit security level
- Resistant to length extension attacks
- Suitable for all cryptographic applications in Unchained
- Used extensively for ensuring data integrity and authenticity