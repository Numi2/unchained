# unchained

post-quantum blockchain implementation using dilithium3 signatures and argon2id proof-of-work, kem pqs

## features

- epoch-based consensus with fixed-length time periods
- memory-hard proof-of-work with argon2id (lanes=1)
- libp2p gossipsub for transaction propagation  
- dilithium3 signatures for transfers
- comprehensive validation of coins and transfers
- rocksdb persistence layer with column families
- hybrid x25519+kyber key exchange for quantum resistance
- merkle tree proofs for light verification
- automatic difficulty and memory retargeting
- prometheus metrics and monitoring

## consensus model

- **epochs**: fixed-length time periods with anchor finalization
- **coins**: self-contained units created via PoW during epochs
- **anchors**: merkle roots committing to selected coins per epoch
- **fork choice**: highest cumulative work, tiebreak by epoch number
- **selection**: deterministic coin selection by smallest PoW hash

## usage

```bash
cargo build --release
cargo run --release --bin unchained mine
```

generates wallet on first run, begins mining and network participation.

additional commands:
- `--proof --coin-id <hex32>` - request and verify coin proof
- `--proof-server --bind 0.0.0.0:9090` - start HTTP proof API
- `--send --to <addr_hex32> --amount <u64>` - send transfers
- `--balance`, `--history` - wallet operations

## network protocol

- quic transport over udp port (configurable)
- rustls 0.23.22 with aws-lc-rs cryptographic provider
- post-quantum handshakes via prefer-post-quantum feature
- backward compatibility with classical x25519-only peers
- gossip topics: anchors, coin candidates, transfers
- request/response: epoch sync, coin proofs, latest state

## data structures

- **coins**: blake3(epoch_hash + nonce + creator_address) identifier
- **transfers**: dilithium3 signatures with double-spend prevention
- **anchors**: {num, hash, merkle_root, difficulty, coin_count, cumulative_work, mem_kib}
- **epochs**: configurable retargeting with memory parameter scaling
- **proofs**: merkle certificates for independent coin verification

## storage

- rocksdb with column families for efficient queries
- prefix keys for epoch-based coin candidate scanning
- merkle leaf storage for fast proof generation
- wallet encryption with xchacha20-poly1305
- production tuning: wal durability, batch writes, compaction


## security

- post-quantum signatures (dilithium3) and key exchange
- memory-hard PoW resistant to asic mining
- rate limiting and peer failure scoring
- encrypted wallet storage with passphrase derivation
- proof request deduplication and ip rate limiting
