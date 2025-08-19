# Argon2id

Argon2id is a memory-hard key derivation function designed to be resistant to both side-channel attacks and time-memory trade-off attacks. It won the Password Hashing Competition in 2015.

## Role in Unchained

Argon2id serves as the proof-of-work algorithm in Unchained, providing memory-hard mining that resists specialized hardware advantages.

### Proof-of-Work Properties
- **Memory-hard**: Requires significant memory allocation, reducing ASIC advantages
- **Tunable difficulty**: Adjustable memory requirements and difficulty targets
- **Consensus-locked parameters**: Fixed lanes=1 for network consensus
- **Retargeting**: Memory and difficulty adjust based on recent performance

### Implementation Details

```rust
use argon2::{Argon2, Params, Version, Algorithm};

// Consensus-critical PoW parameters
let params = Params::new(
    mem_kib,        // From previous anchor
    1,              // time_cost - fixed
    1,              // lanes - consensus locked
    None            // version - default
).unwrap();

let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
```

### Mining Process

1. **Header Construction**: `epoch_hash || nonce || miner_address`
2. **Salt Generation**: `BLAKE3(header)` truncated to 16 bytes
3. **PoW Computation**: Argon2id with consensus parameters
4. **Difficulty Check**: First N bytes of output must be zero

### Parameters

- **Memory (mem_kib)**: Adjustable from previous anchor (typically 64MB+)
- **Time Cost**: Fixed at 1 for consistent timing
- **Parallelism (lanes)**: Fixed at 1 for consensus determinism
- **Algorithm**: Argon2id (hybrid of Argon2i and Argon2d)

## Configuration

```toml
[mining]
enabled = true
mem_kib = 65536              # 64MB default
min_mem_kib = 32768          # 32MB minimum
max_mem_kib = 1048576        # 1GB maximum
workers = 4                  # Parallel mining threads
```

## Retargeting Algorithm

The network automatically adjusts mining parameters:

- **Difficulty**: ±1 byte steps, bounded [1,12]
- **Memory**: Clamped ratio adjustment within [min_mem_kib, max_mem_kib]
- **Target**: Aims for `target_coins_per_epoch` configuration
- **Interval**: Recalculates every `retarget_interval` epochs

## Security Properties

- **ASIC Resistance**: Memory requirements make specialized hardware expensive
- **Side-Channel Resistance**: Argon2id variant resists timing attacks
- **Quantum Resistance**: Classical algorithm unaffected by quantum computers
- **Progressive Difficulty**: Network maintains stable coin production rate

## Performance Characteristics

- **Memory-bound**: Primary bottleneck is memory bandwidth, not computation
- **Scalable**: Works across different hardware configurations
- **Predictable**: Consistent verification times across the network
- **Efficient**: Fast verification for non-mining nodes