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
- Persistence uses RocksDB with separate chain and wallet-private stores. Chain
  state lives in the main node database, while wallet secrets, owned notes,
  sent-transaction history, spent-note markers, checkpoints, and wallet-local
  metadata live under a dedicated private store rooted at `wallet_private/`
  with explicit wallet-only column families (`src/storage.rs`, `src/wallet.rs`).
- Raw coin mirroring to loose files is opt-in only; the checked-in runtime does
  not mirror canonical coin data unless `COIN_MIRRORING=1` is set explicitly
  (`src/storage.rs`).
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

- `unchained_wallet send` uses the wallet-private store for owned note state,
  while `unchained_wallet serve` exposes only the narrow mining-identity and
  lock-derivation surface the miner needs (`src/app.rs`, `src/wallet.rs`,
  `src/storage.rs`, `src/wallet_control.rs`).
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

- The checked-in runtime is split into three binaries: `unchained_node`,
  `unchained_wallet`, and `unchained_miner` (`src/app.rs`,
  `src/bin/unchained_node.rs`, `src/bin/unchained_wallet.rs`,
  `src/bin/unchained_miner.rs`).
- `unchained_wallet serve` owns the wallet-private store and exposes a local
  Unix-domain control socket for mining identity and lock derivation
  (`src/app.rs`, `src/wallet_control.rs`).
- `unchained_node start` owns chain state and the live network runtime and now
  exposes a separate local Unix-domain control socket for shielded state
  snapshots, checkpoint relay, and tx submission (`src/app.rs`,
  `src/node_control.rs`).
- `unchained_node start` also owns epoch management and candidate admission; the
  miner no longer embeds an epoch manager or opens the chain database
  (`src/app.rs`, `src/epoch.rs`, `src/node_control.rs`, `src/miner.rs`).
- Remote interaction happens through signed envelopes on the node-to-node
  transport (`src/network.rs`, `src/node_identity.rs`).
- The only HTTP surface in the checked-in runtime is the local metrics/log
  stream, and the code enforces a loopback bind for it (`src/metrics.rs`).
- Node identity supports an offline-root ceremony through
  `unchained_node init-root`, `unchained_node auth-prepare`,
  `unchained_node auth-sign`, and `unchained_node auth-install`
  (`src/app.rs`, `src/node_identity.rs`).
- Runtime operation only needs the installed auth key and signed node record;
  the offline root is not required by `NodeIdentity::load_runtime_in_dir`
  (`src/node_identity.rs`).
- The checked-in CLI no longer falls back to embedded config blobs; operators
  are expected to run the binaries with an explicit on-disk config
  (`src/app.rs`, `src/config.rs`, `src/bin/inspect_db.rs`,
  `src/bin/list_epochs.rs`).

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
cargo run --release --bin unchained_node -- start
cargo run --release --bin unchained_wallet -- serve
cargo run --release --bin unchained_wallet -- receive
cargo run --release --bin unchained_miner
```

The default test suite includes:

- `tests/shielded_tx_flow.rs`: deterministic prepared-send CI coverage through
  the node control socket plus an ignored live-proving soak roundtrip
- `tests/shielded_pool.rs`: shielded note, checkpoint, archive, and
  rerandomization coverage
- `tests/pq_network.rs`: PQ bootstrap, anchor recovery, and network
  archive/proof flows
- `tests/wallet_control.rs`: local wallet control socket coverage for miner-facing
  identity and lock derivation

Run `cargo test --test shielded_tx_flow -- --ignored --nocapture` when you want
the full zkVM proving soak on CPU-only proving hosts.

## CLI

Primary binaries:

- `unchained_node`: node runtime, identity ceremony, message topic, anchor import/export, replay
- `unchained_wallet`: wallet control service, receive, send, balance, history, rescan
- `unchained_miner`: dedicated mining runtime that consumes node-control mining work and the wallet control socket

`unchained_wallet receive` exports a signed KeyDoc JSON recipient document, and
`unchained_wallet send` validates that document before constructing a proof-backed
shielded transaction (`src/wallet.rs`).

Run `unchained_wallet serve` before `unchained_miner`; the miner no longer opens
the wallet-private database or loads wallet secrets directly (`src/wallet_control.rs`,
`src/miner.rs`).

Run `unchained_node start` before `unchained_miner`; the miner no longer opens
the chain database, owns a QUIC endpoint, or runs the epoch manager locally
(`src/node_control.rs`, `src/miner.rs`, `src/app.rs`).

Run `unchained_node start` before wallet receive/send/balance/history/rescan;
the wallet role now reads canonical chain and network state through the node
control socket rather than opening the chain database directly
(`src/node_control.rs`, `src/wallet.rs`, `src/app.rs`).

Wallet chain-aware actions now require the node control socket; there is no
direct wallet-to-chain fallback path in the checked-in runtime
(`src/node_control.rs`, `src/wallet.rs`).

`unchained_node message send` and `unchained_node message listen` operate on a
shared text topic rather than a direct wallet-to-wallet transport
(`src/app.rs`, `src/network.rs`).

## Docs

- `README.md`: current project summary
- `ARCHITECTURE.md`: broader design notes for the same runtime
- `SHIELDED_POOL_V1.md`: shielded pool and archive/checkpoint model with the
  terminology used by the code
