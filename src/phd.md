# Unchained: A Post-Quantum Secure Blockchain with Epoch-Based Consensus and Privacy-Preserving Transactions

## Abstract

This paper presents a comprehensive analysis of Unchained, a novel blockchain architecture designed specifically for post-quantum security and privacy preservation. The system implements a unique combination of quantum-safe cryptographic primitives, memory-hard proof-of-work consensus, and stealth-based transaction privacy. We examine the technical innovations, security properties, and performance characteristics of this epoch-based blockchain system.

## 1. Introduction

### 1.1 Background and Motivation

The advent of quantum computing poses significant threats to existing blockchain systems that rely on classical cryptographic assumptions. Current blockchain networks predominantly use ECDSA signatures and SHA-256 hashing, both of which are vulnerable to quantum attacks. Unchained represents a pioneering effort to address these challenges by implementing quantum-safe cryptography from the ground up.

### 1.2 Key Contributions

Unchained introduces several novel contributions to the blockchain space:

1. **Post-Quantum Cryptographic Suite**: Integration of CRYSTALS-Kyber (ML-KEM) for key encapsulation and CRYSTALS-Dilithium (ML-DSA) for digital signatures (see `crypto.rs:3-5`, `crypto.rs:390-391`)
2. **Epoch-Based Consensus with Memory-Hard PoW**: Argon2id-based proof-of-work with adaptive difficulty adjustment (see `consensus.rs:11-42`, `crypto.rs:86-101`)
3. **Stealth Transaction System**: Privacy-preserving transfers using one-time keys and hashlock authorizations (see `transfer.rs:33-98`, `crypto.rs:166-182`)
4. **Compact Merkle Proof System**: Efficient inclusion proofs for transaction validation (see `epoch.rs:47-215`, `coin.rs:103-106`)
5. **Domain-Separated Hash Functions**: BLAKE3-based cryptographic primitives with explicit domain separation (see `crypto.rs:103-106`, `crypto.rs:246-248`)

## 2. System Architecture

### 2.1 Core Components

#### 2.1.1 Cryptographic Primitives

The system employs a carefully selected suite of post-quantum secure algorithms:

**Key Encapsulation Mechanism (KEM)**:
- **Algorithm**: CRYSTALS-Kyber (Kyber768) (see `crypto.rs:28-31`)
- **Security Level**: NIST Level 1 (128-bit classical, 64-bit quantum security)
- **Key Sizes**: Public key: 1184 bytes, Secret key: 2400 bytes, Ciphertext: 1088 bytes
- **Usage**: Stealth address generation and shared secret establishment (see `crypto.rs:419-433`)

**Digital Signature Scheme**:
- **Algorithm**: CRYSTALS-Dilithium (Dilithium3) (see `crypto.rs:24-26`)
- **Security Level**: NIST Level 2 (128-bit classical, 96-bit quantum security)
- **Key Sizes**: Public key: 1952 bytes, Secret key: 4000 bytes, Signature: 3293 bytes
- **Usage**: Transaction authorization and proof-of-work validation (see `crypto.rs:108-125`)

**Hash Functions**:
- **Primary Algorithm**: BLAKE3 (32-byte output) (see `crypto.rs:104-106`)
- **Memory-Hard PoW**: Argon2id with configurable memory parameters (see `crypto.rs:86-101`)
- **Domain Separation**: Explicit key derivation for different contexts (see `crypto.rs:103-106`)

#### 2.1.2 Consensus Mechanism

Unchained implements an epoch-based consensus mechanism with the following characteristics:

**Epoch Structure**:
- **Duration**: 222 seconds (configurable) (see `config.toml:42-43`)
- **Coin Capacity**: Maximum 11 coins per epoch (default) (see `consensus.rs:17`)
- **Difficulty Adjustment**: Every 2000 epochs with adaptive retargeting (see `consensus.rs:16`)
- **Memory Requirements**: 16,192 KiB minimum (adjustable) (see `consensus.rs:11-14`)

**Proof-of-Work Algorithm**:
```rust
pub fn argon2id_pow(input: &[u8], mem_kib: u32) -> Result<[u8; 32]> {
    let params = Params::new(mem_kib, 1, 1, None)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; 32];
    let full_salt = blake3::hash(input);
    let salt = &full_salt.as_bytes()[..16];
    a2.hash_password_into(input, salt, &mut hash)?;
    Ok(hash)
}
```

### 2.2 Data Structures

#### 2.2.1 Coin Representation

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Coin {
    pub id: [u8; 32],                    // BLAKE3(epoch_hash || nonce || creator_address)
    pub value: u64,                      // Always 1 in current implementation
    pub epoch_hash: [u8; 32],           // Hash of parent epoch anchor
    pub nonce: u64,                     // PoW solution nonce
    pub creator_address: Address,       // BLAKE3 hash of creator's public key
    pub creator_pk: [u8; DILITHIUM3_PK_BYTES], // Full Dilithium public key
    pub lock_hash: [u8; 32],            // Current unlock condition hash
}
```
(see `coin.rs:7-20`)

#### 2.2.2 Anchor Structure

```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Anchor {
    pub num: u64,                       // Epoch number
    pub hash: [u8; 32],                // Anchor hash
    pub merkle_root: [u8; 32],         // Merkle root of selected coins
    pub difficulty: usize,              // Current PoW difficulty target
    pub coin_count: u32,               // Number of coins in epoch
    pub cumulative_work: u128,         // Total cumulative work
    pub mem_kib: u32,                  // Memory requirement for PoW
}
```
(see `epoch.rs:14-23`)

## 3. Cryptographic Protocols

### 3.1 Stealth Address System

#### 3.1.1 Address Derivation

The stealth address system enables private receiving without revealing recipient identity:

```rust
pub fn address_from_pk(pk: &PublicKey) -> Address {
    *Hasher::new_derive_key("unchained-address")
        .update(pk.as_bytes())
        .finalize()
        .as_bytes()
}
```
(see `crypto.rs:68-73`)

#### 3.1.2 Key Encapsulation for Privacy

The system uses Kyber768 KEM for establishing shared secrets:

```rust
pub fn kem_encapsulate_to_kyber(pk: &KyberPk) -> ([u8; KYBER768_CT_BYTES], [u8; 32]) {
    let (shared, ct) = pqcrypto_kyber::kyber768::encapsulate(pk);
    let mut kem_ct = [0u8; KYBER768_CT_BYTES];
    kem_ct.copy_from_slice(ct.as_bytes());
    (kem_ct, derive_meta_authz_aead_key(shared.as_bytes()))
}
```
(see `crypto.rs:419-433`)

### 3.2 Transaction Authorization

#### 3.2.1 Hashlock Authorization

Unchained uses hashlock-based authorization instead of traditional signatures:

```rust
pub fn lock_hash(preimage: &[u8]) -> [u8; 32] {
    *Hasher::new_derive_key("unchained.lock.v1")
        .update(preimage)
        .finalize()
        .as_bytes()
}
```
(see `crypto.rs:246-248`)

#### 3.2.2 Nullifier Generation

Double-spend prevention through deterministic nullifier computation:

```rust
pub fn compute_nullifier_v3(preimage: &[u8], coin_id: &[u8; 32], chain_id32: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"unchained.nullifier.v3");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(preimage);
    *h.finalize().as_bytes()
}
```
(see `crypto.rs:251-258`)

### 3.3 Merkle Tree Construction

#### 3.3.1 Tree Building

The system uses a deterministic Merkle tree for efficient inclusion proofs:

```rust
impl MerkleTree {
    pub fn build_root(coin_ids: &HashSet<[u8; 32]>) -> [u8; 32] {
        if coin_ids.is_empty() { return [0u8; 32]; }
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter()
            .map(Coin::id_to_leaf_hash)
            .collect();
        leaves.sort();
        Self::compute_root_from_sorted_leaves(&leaves)
    }
}
```
(see `epoch.rs:88-97`)

#### 3.3.2 Proof Generation

Compact proofs enable efficient verification:

```rust
pub fn build_proof_from_leaves(
    sorted_leaves: &[[u8; 32]],
    target_leaf: &[u8; 32],
) -> Option<Vec<([u8; 32], bool)>> {
    // Implementation builds authentication path
    // Returns sibling hashes and position indicators
}
```
(see `epoch.rs:150-180`)

## 4. Consensus Algorithm

### 4.1 Difficulty Adjustment

The system implements adaptive difficulty adjustment based on coin production rates:

```rust
fn calculate_retarget_params(recent_anchors: &[Anchor]) -> Params {
    let avg_coins_x = (total_coins.saturating_mul(PRECISION)) / epochs;
    let target_x = TARGET_COINS_PER_EPOCH.saturating_mul(PRECISION);

    let mut new_diff = if avg_coins_x > upper {
        last_params.difficulty.saturating_add(1)
    } else if avg_coins_x < lower {
        last_params.difficulty.saturating_sub(1)
    } else {
        last_params.difficulty
    };
    new_diff = new_diff.clamp(DIFFICULTY_MIN, DIFFICULTY_MAX);
    // Memory adjustment based on coin production rate
}
```
(see `consensus.rs:83-132`)

### 4.2 Anchor Selection

Epoch finalization involves deterministic coin selection:

```rust
pub fn select_candidates_for_epoch(
    db: &crate::storage::Store,
    parent: &Anchor,
    cap: usize,
    buffer: Option<&std::collections::HashSet<[u8; 32]>>,
) -> (Vec<crate::coin::CoinCandidate>, usize) {
    // Filter by PoW difficulty
    let mut filtered: Vec<crate::coin::CoinCandidate> = Vec::new();
    for cand in candidates.into_iter() {
        if parent.difficulty > 0 &&
           !cand.pow_hash.iter().take(parent.difficulty).all(|b| *b == 0) {
            continue;
        }
        filtered.push(cand);
    }

    // Fair, round-based selection across creators
    // Global order by pow_hash, then id (deterministic)
    filtered.sort_by(|a, b| a.pow_hash.cmp(&b.pow_hash)
        .then_with(|| a.id.cmp(&b.id)));

    // Round-robin selection across creators
}
```
(see `epoch.rs:536-607`)

## 5. Privacy Analysis

### 5.1 Stealth Transaction Privacy

The stealth address system provides strong privacy guarantees:

1. **Recipient Privacy**: One-time keys prevent address reuse
2. **Unlinkability**: Kyber KEM ensures each transaction uses different shared secrets
3. **Forward Security**: Compromise of one key doesn't affect past transactions

### 5.2 Transaction Unlinkability

Hashlock-based authorization provides additional privacy:

```rust
pub fn commitment_of_stealth_ct(kyber_ct_bytes: &[u8]) -> [u8; 32] {
    blake3_hash(kyber_ct_bytes)
}
```
(see `crypto.rs:144-146`)

This commitment scheme binds transactions to ciphertexts without revealing plaintexts.

### 5.3 Balance Privacy

The system maintains balance privacy through:

1. **No transparent balances**: All balances require private key knowledge
2. **No amount correlation**: Fixed denomination (value = 1) prevents amount-based analysis
3. **Compact proofs**: Merkle proofs enable verification without revealing wallet contents

## 6. Security Analysis

### 6.1 Post-Quantum Security

**Kyber768 Security**:
- **Classical Security**: 128 bits
- **Quantum Security**: 64 bits
- **IND-CCA2 Secure**: Provides authenticated key encapsulation

**Dilithium3 Security**:
- **Classical Security**: 128 bits
- **Quantum Security**: 96 bits
- **EUF-CMA Secure**: Existentially unforgeable under chosen message attacks

**BLAKE3 Security**:
- **Preimage Resistance**: 256 bits
- **Collision Resistance**: 128 bits
- **Domain Separation**: Prevents cross-protocol attacks

### 6.2 Consensus Security

The memory-hard proof-of-work provides resistance against:

1. **ASIC Optimization**: Argon2id's memory requirements prevent efficient hardware acceleration
2. **GPU Attacks**: Memory bandwidth limitations reduce parallel attack efficiency
3. **Quantum Attacks**: PoW difficulty provides additional security layer

### 6.3 Network Security

The gossipsub-based network provides:

1. **DoS Resistance**: Rate limiting and peer scoring (see `network.rs:32-35`)
2. **Eclipse Attack Resistance**: Multiple bootstrap nodes and peer diversity (see `config.toml:23-27`)
3. **Sybil Attack Resistance**: Proof-of-work based peer reputation (see `miner.rs:355-520`)

## 7. Performance Analysis

### 7.1 Transaction Throughput

**Epoch-based Design**:
- **Block Time**: 222 seconds (see `config.toml:42-43`)
- **Coins per Epoch**: Up to 11 (see `consensus.rs:17`)
- **Transactions per Second**: ~0.05 (limited by epoch structure)

### 7.2 Verification Efficiency

**Merkle Proofs**:
- **Proof Size**: O(log n) where n is epoch size
- **Verification Time**: O(log n) hash operations
- **Storage Requirements**: Minimal for light clients

### 7.3 Mining Performance

**Argon2id Parameters**:
- **Memory**: 16,192 KiB minimum (see `consensus.rs:13`)
- **Iterations**: Configurable (see `crypto.rs:86-101`)
- **Parallelism**: Single lane (consensus rule) (see `crypto.rs:90`)

## 8. Implementation Analysis

### 8.1 Code Quality

The implementation demonstrates several software engineering best practices:

1. **Type Safety**: Strong typing prevents common cryptographic errors
2. **Memory Safety**: Rust's ownership system prevents memory corruption
3. **Error Handling**: Comprehensive error propagation and handling
4. **Testing**: Unit tests for critical cryptographic functions

### 8.2 Storage Architecture

RocksDB integration provides:

1. **Column Families**: Organized storage for different data types (see `storage.rs:50-200`)
2. **Atomic Operations**: Batch writes ensure consistency (see `storage.rs:300-400`)
3. **Compaction**: Efficient storage of historical data (see `storage.rs:1000-1044`)

## 9. Future Research Directions

### 9.1 Scalability Improvements

1. **Sharding**: Horizontal scaling through epoch-based partitioning
2. **Layer 2**: Payment channels and state channels for higher throughput
3. **Zero-Knowledge Proofs**: Enhanced privacy without trusted setups

### 9.2 Advanced Cryptography

1. **Threshold Cryptography**: Distributed key generation and signing
2. **Homomorphic Encryption**: Private smart contracts
3. **Post-Quantum Signatures**: Integration of newer NIST candidates

### 9.3 Consensus Evolution

1. **Proof-of-Stake Hybrid**: Combining PoW security with PoS efficiency
2. **DAG Structure**: Alternative to linear epoch chains
3. **Cross-Chain Interoperability**: Bridges to other quantum-safe networks

## 10. Conclusion

Unchained represents a significant advancement in blockchain technology by addressing the critical challenges of quantum computing threats and privacy preservation. The system's innovative combination of post-quantum cryptography, memory-hard consensus, and stealth transactions provides a robust foundation for secure digital asset transfers in the post-quantum era.

The implementation demonstrates that it's possible to build production-ready blockchain systems with quantum-safe cryptography while maintaining practical performance characteristics. The epoch-based design, while limiting throughput, provides excellent security guarantees and serves as an important stepping stone toward more scalable post-quantum blockchain architectures.

## References

1. CRYSTALS-Kyber: A CCA-secure module-lattice-based KEM
2. CRYSTALS-Dilithium: A lattice-based signature scheme
3. BLAKE3: A cryptographic hash function
4. Argon2: Password hashing and proof-of-work function
5. Merkle Trees and Their Applications in Cryptography
6. Post-Quantum Cryptography Standardization (NIST)

## Acknowledgments

This research analyzes the Unchained blockchain system, an open-source implementation of post-quantum secure blockchain technology. The system's design demonstrates practical application of cutting-edge cryptographic research in distributed ledger technology.

## Appendix A: Code References

### Cryptographic Primitives
- **Kyber768 KEM**: `crypto.rs:28-31`, `crypto.rs:419-433`
- **Dilithium3 Signatures**: `crypto.rs:24-26`, `crypto.rs:108-125`
- **BLAKE3 Hashing**: `crypto.rs:104-106`, `crypto.rs:246-248`
- **Argon2id PoW**: `crypto.rs:86-101`

### Data Structures
- **Coin Structure**: `coin.rs:7-20`
- **Anchor Structure**: `epoch.rs:14-23`
- **StealthOutput**: `transfer.rs:33-98`

### Consensus Implementation
- **Epoch Management**: `epoch.rs:217-532`
- **Difficulty Adjustment**: `consensus.rs:83-132`
- **Candidate Selection**: `epoch.rs:536-607`
- **Mining Algorithm**: `miner.rs:355-520`

### Network and Synchronization
- **P2P Networking**: `network.rs:1-500`
- **Synchronization**: `sync.rs:50-200`
- **Bootstrap Peers**: `config.toml:23-27`

### Storage Architecture
- **RocksDB Integration**: `storage.rs:1-1044`
- **Column Families**: `storage.rs:50-200`
- **Batch Operations**: `storage.rs:300-400`

This comprehensive analysis demonstrates the practical implementation of post-quantum cryptography in blockchain systems, with specific code references providing concrete evidence of the technical innovations described.
