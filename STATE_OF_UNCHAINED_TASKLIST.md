# State Of Unchained

This file is a short status note for the current repository rather than a
feature wish list.

## Implemented In The Checked-In Code

- PQ node identity with offline root, delegated runtime auth key, trust-update
  documents, and raw-public-key TLS transport
- epoch-based proof of work with Argon2id and BLAKE3
- RocksDB-backed persistence for anchors, transactions, shielded state, and
  archive metadata
- shielded notes, evolving nullifiers, archived nullifier epochs, and the
  nullifier root ledger
- signed KeyDoc recipient documents and ML-KEM-encrypted shielded outputs
- proof-carrying shielded sends using RISC Zero succinct receipts
- fixed-cadence wallet checkpoint refresh with cover traffic
- archive provider manifests, replicas, custody commitments, retrieval receipts,
  availability certificates, and operator scorecards
- checkpoint and archive traffic carried over the PQ mesh runtime

## Verified By Repository Tests

- `tests/shielded_pool.rs`
- `tests/shielded_tx_flow.rs`
- `tests/pq_network.rs`

## Still Better Treated As Design Frontier

- stronger operator economics and incentives
- longer-horizon archive durability assumptions
- deeper proof-system compression above the current accumulator design
