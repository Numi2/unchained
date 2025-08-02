# unchainedcoin

post-quantum blockchain implementation using dilithium3 signatures and argon2id proof-of-work, kem pqs

## features

- memory-hard proof-of-work with configurable difficulty
- libp2p gossipsub for transaction propagation  
- comprehensive validation of coins and transfers
- rocksdb persistence layer
- hybrid x25519+kyber key exchange for quantum resistance

## usage

```bash
cargo build --release
cargo run --release --bin unchainedcoin mine
```

generates wallet on first run, begins mining and network participation.

## network protocol

- quic transport over udp port (configurable)
- rustls 0.23.22 with aws-lc-rs cryptographic provider
- post-quantum handshakes via prefer-post-quantum feature
- backward compatibility with classical x25519-only peers

## data structures

- coins: blake3(epoch_hash + nonce + creator + pow_hash) identifier
- transfers: dilithium3 signatures with double-spend prevention
- epochs: 10-block difficulty retargeting with memory parameter scaling

## configuration

modify config.toml for network settings, bootstrap peers, mining parameters, and storage location.