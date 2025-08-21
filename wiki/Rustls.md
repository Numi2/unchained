# Rustls

Rustls is a modern TLS library written in Rust, providing memory-safe and performant TLS/SSL implementations with post-quantum cryptography support.

## Role in Unchained

Rustls provides TLS encryption for secure communications in Unchained, with specific focus on post-quantum cryptographic algorithms.

### Post-Quantum TLS
- **AWS-LC Provider**: Uses AWS LibCrypto for post-quantum algorithms
- **Hybrid KEX**: Combines classical and post-quantum key exchange
- **TLS 1.3**: Modern protocol version with enhanced security
- **Certificate Management**: Self-signed certificates for node communication

### Implementation

```rust
use rustls::{ClientConfig, ServerConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// Create post-quantum aware client configuration
pub fn create_pq_client_config() -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder_with_provider(
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(root_store)
    .with_no_client_auth();
    
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
```

## Key Features

### Post-Quantum Cryptography
- **Hybrid Algorithms**: Combines classical ECDH with post-quantum KEM
- **AWS-LC Integration**: Uses AWS LibCrypto for PQ implementations
- **Future-Proof**: Prepares for quantum computer threats
- **Standards Compliance**: Follows emerging PQ TLS standards

### Memory Safety
- **Rust Implementation**: Memory-safe by design
- **No Unsafe Code**: Minimal unsafe blocks with careful review
- **Buffer Overflow Protection**: Compile-time memory safety guarantees
- **Type Safety**: Strong typing prevents common TLS vulnerabilities

### Performance
- **Zero-Copy**: Minimal data copying in hot paths
- **Async Support**: Full integration with Tokio async runtime
- **Optimized Crypto**: Fast implementations of cryptographic primitives
- **Connection Reuse**: Efficient session resumption

## Configuration

### Server Configuration
```rust
pub fn create_pq_server_config(
    cert_der: Vec<u8>, 
    private_key_der: Vec<u8>
) -> Result<Arc<ServerConfig>> {
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::try_from(private_key_der)?;

    let mut config = ServerConfig::builder_with_provider(
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
```

### Certificate Generation
```rust
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress(std::net::IpAddr::V4([127, 0, 0, 1].into())),
    ]);
    
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
    
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = Certificate::from_params(params)?;
    
    Ok((cert.serialize_der()?, key_pair.serialize_der()))
}
```

## Security Properties

### Protocol Security
- **TLS 1.3 Only**: Latest protocol version with improved security
- **Perfect Forward Secrecy**: Session keys are ephemeral
- **AEAD Ciphers**: Authenticated encryption prevents tampering
- **Certificate Validation**: Strong certificate chain verification

### Post-Quantum Readiness
- **Hybrid Mode**: Combines classical and PQ algorithms
- **Algorithm Agility**: Easy to update when standards evolve
- **Implementation Maturity**: Based on NIST-standardized algorithms
- **Backwards Compatibility**: Graceful fallback to classical crypto

### Attack Resistance
- **Side-Channel Protection**: Constant-time implementations
- **Timing Attack Resistance**: Careful implementation of crypto operations
- **Memory Safety**: Rust prevents buffer overflows and use-after-free
- **Protocol Attacks**: Resistant to known TLS vulnerabilities

## Integration with Unchained

### HTTPS Services
- **Metrics Endpoint**: Secure Prometheus metrics collection
- **Admin Interface**: Protected management endpoints
- **API Services**: Secure REST/RPC interfaces
- **Health Checks**: Authenticated monitoring endpoints

### Internal Communication
- **Node-to-Node**: Secure inter-node communication
- **Wallet Communication**: Protected wallet-to-node connections
- **Admin Tools**: Secure command and control interfaces
- **Backup Services**: Encrypted backup transmission

## Performance Characteristics

### Benchmarks
- **Handshake Speed**: Fast connection establishment
- **Throughput**: High-bandwidth data transfer
- **CPU Usage**: Efficient cryptographic operations
- **Memory Usage**: Minimal runtime overhead

### Optimization Features
- **Session Resumption**: Reuse established security context
- **Connection Pooling**: Efficient connection management
- **Zero-Copy**: Minimal data copying in protocol handling
- **Async Integration**: Full Tokio compatibility

## Monitoring and Debugging

### Observability
```rust
// TLS connection metrics
pub struct TlsMetrics {
    pub connections_established: Counter,
    pub handshake_duration: Histogram,
    pub bytes_transferred: Counter,
    pub protocol_errors: Counter,
}
```

### Debugging Features
- **Connection Logging**: Detailed TLS handshake information
- **Certificate Debugging**: Validation chain inspection
- **Protocol Analysis**: TLS message flow tracing
- **Error Reporting**: Detailed error context for failures

## Security Considerations

### Certificate Management
- **Self-Signed Certificates**: For internal node communication
- **Certificate Rotation**: Regular renewal of TLS certificates
- **Trust Anchors**: Proper root certificate management
- **Revocation**: Certificate revocation handling

### Key Management
- **Private Key Protection**: Secure storage of TLS private keys
- **Key Generation**: Strong random number generation
- **Key Exchange**: Secure ephemeral key establishment
- **Perfect Forward Secrecy**: Session key independence

### Operational Security
- **Protocol Versions**: Only TLS 1.3 enabled
- **Cipher Suites**: Approved post-quantum algorithms only
- **Certificate Validation**: Strict certificate chain verification
- **Attack Mitigation**: Protection against known TLS attacks