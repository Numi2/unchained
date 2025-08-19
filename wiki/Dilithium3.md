# Dilithium3

Dilithium3 is a post-quantum digital signature scheme standardized by NIST as ML-DSA. It provides quantum-resistant digital signatures based on lattice cryptography and the learning-with-errors problem.

## Role in Unchained

Dilithium3 provides post-quantum digital signatures for transfer authorization and ownership verification in the blockchain.

### Digital Signature Applications
- **Transfer Authorization**: Signs spending transactions
- **Ownership Verification**: Proves control over funds
- **Identity Binding**: Links signatures to specific addresses
- **Non-repudiation**: Cryptographic proof of transaction authorization

### Signature Process

1. **Key Generation**: Create Dilithium3 keypair for address
2. **Message Preparation**: Construct authorization bytes for transaction
3. **Signing**: Generate quantum-resistant signature
4. **Verification**: Validate signature against public key and message
5. **Ownership Check**: Confirm signer controls referenced coins

### Implementation

```rust
use pqcrypto_dilithium::dilithium3::{PublicKey, SecretKey, DetachedSignature};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

// Key generation
let (public_key, secret_key) = dilithium3::keypair();

// Signing
let signature = secret_key.detached_sign(&authorization_bytes);

// Verification
let is_valid = public_key.verify_detached_signature(&signature, &authorization_bytes);
```

## Security Properties

### Post-Quantum Security
- **Quantum Resistant**: Based on lattice problems hard for quantum computers
- **NIST Standardized**: ML-DSA-65 provides security level 3
- **Conservative Parameters**: 65 parameter set for long-term security
- **Proven Security**: Formal security proofs under lattice assumptions

### Signature Properties
- **Unforgeability**: Cannot forge signatures without secret key
- **Non-malleability**: Signatures cannot be modified to remain valid
- **Strong Security**: Secure against adaptive chosen message attacks
- **Deterministic**: Same message always produces same signature

## Technical Specifications

### Key and Signature Sizes
- **Public Key**: 1,952 bytes
- **Secret Key**: 4,000 bytes  
- **Signature**: ~3,293 bytes (variable length)
- **Security Level**: Category 3 (equivalent to AES-192)

### Algorithm Parameters
- **Dilithium3**: Parameter set with moderate size/security trade-off
- **Ring Dimension**: n = 256
- **Modulus**: q = 8,380,417
- **Standard Deviation**: η = 4

## Integration with Unchained

### Transfer Structure
```rust
pub struct Transfer {
    pub spend: Spend,
    pub signature: DetachedSignature,
    pub public_key: PublicKey,
}

pub struct Spend {
    pub coin_id: [u8; 32],
    pub unlock_preimage: [u8; 32],
    pub next_lock_hash: [u8; 32],
    pub nullifier: [u8; 32],
}
```

### Verification Process
1. **Signature Check**: Verify Dilithium3 signature against authorization data
2. **Ownership Verification**: Confirm public key matches coin ownership
3. **Nullifier Validation**: Ensure spend hasn't been used before
4. **Lock Hash Verification**: Validate unlock preimage matches previous lock

## Performance Characteristics

- **Key Generation**: ~50,000 ops/sec
- **Signing**: ~15,000 ops/sec
- **Verification**: ~30,000 ops/sec
- **Memory Usage**: Moderate for post-quantum scheme
- **Deterministic**: Consistent performance across platforms

## Configuration

Dilithium3 parameters are standardized and require no configuration:

```rust
// Fixed algorithm parameters
pub const DILITHIUM3_PK_BYTES: usize = 1952;
pub const DILITHIUM3_SK_BYTES: usize = 4000;
pub const DILITHIUM3_SIG_BYTES: usize = 3293; // Maximum size
```

## Security Considerations

- **Key Management**: Secure storage of secret keys is critical
- **Randomness**: Requires high-quality random number generation
- **Side Channels**: Implementation includes protections against timing attacks
- **Future-Proof**: Designed to resist both classical and quantum attacks

## Comparison with Classical Signatures

| Property | Dilithium3 | ECDSA (P-256) |
|----------|------------|---------------|
| Quantum Security | ✓ Resistant | ✗ Vulnerable |
| Public Key Size | 1,952 bytes | 64 bytes |
| Signature Size | ~3,293 bytes | ~64 bytes |
| Performance | Good | Excellent |
| Standardization | NIST ML-DSA | NIST/SECG |
| Security Level | ~192-bit | ~128-bit |