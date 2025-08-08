# unchained

post-quantum blockchain implementation using dilithium3 signatures and argon2id proof-of-work, kem pqs

## features

- memory-hard proof-of-work with argon2
- libp2p gossipsub for transaction propagation  
- dilithium3 sigs
- comprehensive validation of coins and transfers
- rocksdb persistence layer
- hybrid x25519+kyber key exchange for quantum resistance

## usage

```bash
cargo build --release
cargo run --release --bin unchained mine
```

generates wallet on first run, begins mining and network participation.

### show your peer id

Print the local libp2p Peer ID (and your full multiaddr if `net.public_ip` is set in `config.toml`):

```bash
cargo run --release --bin unchained -- peer-id
```

Example output:

```text
🆔 Peer ID: 12D3KooW...
📫 Multiaddr: /ip4/203.0.113.10/udp/31000/quic-v1/p2p/12D3KooW...
```

Notes
- The peer identity is persisted in `peer_identity.key` (created on first run). Keep it to retain the same Peer ID across restarts.
- The node also logs the peer ID at startup unless `--quiet-net` is used.

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