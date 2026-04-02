# Unchained

Unchained is a Rust node and CLI wallet for a post-quantum shielded asset system.
The checked-in runtime path is PQ-only: node identity, peer transport, wallet
recipient documents, and shielded outputs all use ML-KEM-768 and ML-DSA-65 in
the live code.

This README is aligned to the current implementation in `src/`, `proof-core/`,
`methods/`, and `tests/`.

## Verified Runtime Properties

- Consensus is epoch-based proof of work with Argon2id work and BLAKE3 hashing
  (`src/consensus.rs`, `src/epoch.rs`, `src/crypto.rs`).
- Peer transport is QUIC over TLS 1.3 raw public keys with ML-KEM-768 key
  exchange and ML-DSA-65 authentication
  (`src/network.rs`, `src/node_identity.rs`).
- Wire objects and signed documents use an explicit canonical byte codec rather
  than relying on Serde or `bincode` layout for protocol compatibility
  (`src/canonical.rs`, `src/node_identity.rs`).
- Persistence uses RocksDB, including dedicated column families for anchors,
  transactions, shielded state, and archive metadata (`src/storage.rs`).
- Wallet recipient handles are signed KeyDoc JSON documents that bind a chain ID
  to ML-DSA and ML-KEM public keys (`src/wallet.rs`).
- Shielded outputs are ML-KEM-768 encrypted and carry opaque ciphertext plus a
  public note commitment (`src/wallet.rs`, `src/transaction.rs`).
- `Tx` is the canonical gossip, validation, and persistence unit
  (`src/transaction.rs`).

## Shielded State Model

- Protocol constants are locked in `src/protocol.rs` and consumed by consensus,
  nullifier rollover, archive routing, and wallet refresh.
- Mined coins can be deterministically lifted into genesis shielded notes and
  appended to the global note commitment tree
  (`src/transaction.rs`, `src/wallet.rs`, `src/shielded.rs`).
- Canonical ownership is represented by the note commitment tree plus the active
  and archived nullifier epochs (`src/transaction.rs`, `src/shielded.rs`).
- Shielded transactions carry a succinct proof. Validators check the proof
  journal against live chain state and only persist current nullifiers, outputs,
  and the transaction itself (`src/proof.rs`, `src/transaction.rs`,
  `proof-core/src/lib.rs`).
- Historical unspent state is tracked as checkpoints and checkpoint
  accumulators, not as an ever-growing validator nullifier table
  (`src/wallet.rs`, `src/proof.rs`, `src/transaction.rs`).

## Wallet Refresh And Archive Layer

- `node start` spawns a fixed-cadence oblivious refresh loop for wallet
  checkpoints (`src/main.rs`, `src/wallet.rs`).
- Each refresh can issue real checkpoint requests for owned notes and synthetic
  cover requests even when no spend is pending (`src/wallet.rs`).
- Checkpoint queries are segmented by archive shard, routed across providers,
  padded with cover traffic to power-of-two batch sizes, rerandomized, and
  aggregated into packets and strata before checkpoint accumulator proving
  (`src/shielded.rs`, `src/network.rs`, `src/proof.rs`).
- The live runtime persists and exchanges archive provider manifests, replica
  attestations, service ledgers, custody commitments, retrieval receipts,
  availability certificates, and operator scorecards
  (`src/network.rs`, `src/shielded.rs`, `src/storage.rs`).
- Archive shard repair and replica rebalancing are wired into the network
  runtime (`src/network.rs`).

## Service Boundary

- The product runs as a single PQ mesh node. Remote interaction happens through
  signed envelopes on the node-to-node transport
  (`src/network.rs`, `src/node_identity.rs`).
- The only HTTP surface in the checked-in runtime is the local metrics/log
  stream, and the code enforces a loopback bind for it (`src/metrics.rs`).
- Node identity supports an offline-root ceremony through
  `unchained node init-root`, `unchained node auth-prepare`,
  `unchained node auth-sign`, and `unchained node auth-install`
  (`src/main.rs`, `src/node_identity.rs`).
- Runtime operation only needs the installed auth key and signed node record;
  the offline root is not required by `NodeIdentity::load_runtime_in_dir`
  (`src/node_identity.rs`).

## Proofs

- `proof-core` defines the canonical shielded witness, checkpoint accumulator
  journal, and public binding semantics (`proof-core/src/lib.rs`).
- `methods/guest` validates shielded spend witnesses in the zkVM
  (`methods/guest/src/main.rs`).
- `methods/checkpoint-guest` validates checkpoint accumulator steps in the zkVM
  (`methods/checkpoint-guest/src/main.rs`).
- `src/proof.rs` generates and verifies succinct receipts, and wallet sends call
  into that live path (`src/wallet.rs`, `src/proof.rs`).
- The project code uses `risc0_zkvm::default_prover()`; Unchained does not
  define a separate project-specific Metal proving path (`src/proof.rs`).

## Build

Use a current stable Rust toolchain.

```bash
rustup update
cargo build --release
```

Useful commands:

```bash
cargo fmt
cargo check
cargo test
cargo test --test shielded_tx_flow -- --nocapture
cargo run --release --bin unchained -- node start
cargo run --release --bin unchained -- wallet receive
```

The default test suite includes:

- `tests/shielded_tx_flow.rs`: end-to-end succinct-proof wallet send/receive
  roundtrip
- `tests/shielded_pool.rs`: shielded note, checkpoint, archive, and
  rerandomization coverage
- `tests/pq_network.rs`: PQ bootstrap, anchor recovery, and network
  archive/proof flows

`shielded_tx_flow` is materially slower than the rest of the suite on CPU-only
proving hosts.

## CLI

Primary commands in the current binary:

- `node start`
- `node init-root`
- `node auth-prepare`
- `node auth-sign`
- `node auth-install`
- `node trust-revoke`
- `node trust-replace`
- `node trust-approve`
- `node peer-id`
- `wallet receive`
- `wallet send`
- `wallet balance`
- `wallet history`
- `message send`
- `message listen`
- `advanced replay-transactions`
- `advanced rescan-wallet`
- `advanced export-anchors --out <FILE>`
- `advanced import-anchors --input <FILE>`

`wallet receive` exports a signed KeyDoc JSON recipient document, and
`wallet send` validates that document before constructing a proof-backed
shielded transaction (`src/wallet.rs`).

`message send` and `message listen` operate on a shared text topic rather than a
direct wallet-to-wallet transport (`src/main.rs`, `src/network.rs`).

## Docs

- `README.md`: current project summary
- `ARCHITECTURE.md`: broader design notes for the same runtime
- `SHIELDED_POOL_V1.md`: shielded pool and archive/checkpoint model with the
  terminology used by the code
