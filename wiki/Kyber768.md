# Kyber768 / ML-KEM

Kyber768 (also known as ML-KEM-768) is a post-quantum key encapsulation mechanism standardized by NIST. It provides quantum-resistant public key encryption based on the learning-with-errors problem.

## Role in Unchained

Kyber768 enables private receiving through stealth outputs, ensuring recipient privacy and unlinkability.

### Stealth Address System
- **Stealth Addresses**: Contains recipient's address and Kyber768 public key
- **One-time Outputs**: Each payment creates a unique, unlinkable output
- **Shared Secrets**: Sender and receiver derive matching secrets via KEM
- **Deterministic Derivation**: Consistent key and lock secret generation

### Private Receiving Process

1. **Address Generation**: Recipient creates Kyber768 keypair
2. **Stealth Address**: Encodes address + public key as base64-url string
3. **Encapsulation**: Sender encapsulates to recipient's public key
4. **Derivation**: Both parties derive one-time key and next-hop lock secret
5. **Decapsulation**: Recipient recovers secrets without revealing identity

### Implementation

```rust
use pqcrypto_kyber::kyber768::{PublicKey, SecretKey, Ciphertext};
use ml_kem::{KemCore, EncapKey, DecapKey};

// Key generation for stealth addresses
let (public_key, secret_key) = kyber768::keypair();

// Sender: encapsulate shared secret
let (ciphertext, shared_secret) = public_key.encapsulate(&mut rng);

// Recipient: decapsulate to recover secret
let recovered_secret = secret_key.decapsulate(&ciphertext);
```

## Security Properties

### Post-Quantum Security
- **Quantum Resistant**: Based on lattice problems hard for quantum computers
- **NIST Standardized**: ML-KEM-768 provides security level 3
- **Conservative Parameters**: 768-bit parameter set for long-term security
- **Proven Security**: Formal security proofs under learning-with-errors

### Privacy Guarantees
- **Unlinkability**: Outputs cannot be linked to recipient identity
- **Forward Secrecy**: Past communications remain secure if keys are compromised
- **Metadata Protection**: No long-term keys exposed in transactions
- **Stealth Properties**: External observers cannot identify recipients

## Configuration

Kyber768 parameters are fixed by the NIST standard:
- **Security Level**: Category 3 (equivalent to AES-192)
- **Public Key Size**: 1,184 bytes
- **Secret Key Size**: 2,400 bytes
- **Ciphertext Size**: 1,088 bytes
- **Shared Secret Size**: 32 bytes

## Integration with Unchained

### Stealth Output Structure
```rust
pub struct StealthOutput {
    pub ciphertext: [u8; 1088],     // Kyber768 ciphertext
    pub commitment: [u8; 32],       // BLAKE3 commitment
    pub amount: u64,                // Coin value
}
```

### Address Format
- Base64-url encoded string containing:
  - Recipient's regular address
  - Kyber768 public key (1,184 bytes)
  - Version and checksum information

## Performance Characteristics

- **Key Generation**: ~200,000 ops/sec
- **Encapsulation**: ~150,000 ops/sec  
- **Decapsulation**: ~100,000 ops/sec
- **Memory Usage**: Moderate compared to other PQ schemes
- **Bandwidth**: Reasonable ciphertext size for blockchain use

## Comparison with Classical Cryptography

| Property | Kyber768 | ECDH (P-256) |
|----------|----------|--------------|
| Quantum Security | ✓ Resistant | ✗ Vulnerable |
| Public Key Size | 1,184 bytes | 64 bytes |
| Performance | Good | Excellent |
| Standardization | NIST ML-KEM | NIST/SECG |
| Security Level | ~192-bit | ~128-bit |