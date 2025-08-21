# Unchained Technology Wiki

This wiki documents the key technologies used in the Unchained blockchain project, providing detailed information about each component and its role in the system.

## Technologies

### Core Cryptography
- [BLAKE3](BLAKE3.md) - Fast cryptographic hashing and domain separation
- [Argon2id](Argon2id.md) - Memory-hard proof-of-work algorithm
- [Kyber768/ML-KEM](Kyber768.md) - Post-quantum key encapsulation mechanism
- [Dilithium3](Dilithium3.md) - Post-quantum digital signatures

### Networking & Transport
- [libp2p](libp2p.md) - Peer-to-peer networking with QUIC transport
- [Rustls](Rustls.md) - TLS implementation with post-quantum support

### Storage & Runtime
- [RocksDB](RocksDB.md) - High-performance embedded database
- [Tokio](Tokio.md) - Asynchronous runtime for Rust

### Development & Monitoring
- [Rust](Rust.md) - Systems programming language
- [Prometheus](Prometheus.md) - Metrics collection and monitoring

## Overview

Unchained is built with a focus on post-quantum security, privacy preservation, and practical deployment. The technology stack is carefully chosen to provide:

- **Post-quantum resistance**: Using Kyber768 and Dilithium3 for future-proof cryptography
- **Privacy by design**: Stealth outputs and minimal metadata leakage
- **Performance**: Memory-hard PoW with efficient verification
- **Reliability**: Robust storage and networking infrastructure

Each technology page provides implementation details, configuration options, and how it integrates with the overall Unchained architecture.