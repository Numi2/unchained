# Unchained

Unchained is a post-quantum private asset node with a PQ-only default build.

## Tech Choices

- Consensus: epoch-based proof of work
- Proof of work: Argon2id
- Hashing: BLAKE3
- Network transport: QUIC over TLS 1.3 raw public keys with ML-KEM-768 key exchange and ML-DSA-65 authentication
- Wire and signed-doc encoding: explicit canonical byte codec in [`src/canonical.rs`](/Users/home/unchgit/unchained/src/canonical.rs)
- Persistence: RocksDB
- Recipient privacy: ML-KEM-768-based private recipient docs and opaque one-time outputs
- Signatures: ML-DSA-65
- Canonical state transition: [`Tx`](/Users/home/unchgit/unchained/src/transaction.rs)

## Protocol Posture

- Consensus rules are protocol-locked in [`src/protocol.rs`](/Users/home/unchgit/unchained/src/protocol.rs).
- Epoch anchors commit mined coins.
- Mined coins are deterministically materialized into genesis shielded notes.
- Canonical ownership now lives in the shielded note tree plus the active and archived evolving-nullifier epochs.
- Canonical transaction propagation happens on `unchained/tx/v1`.
- Historical unspent state is represented by checkpoint and extension objects rather than a perpetually growing validator nullifier table.

The runtime is shielded-state-native, but it is not yet a full zero-knowledge spend system. Current transactions still reveal note openings to validators while the protocol waits for transparent recursive PQ proof replacement.

## Architecture

- `protocol / consensus core`
- `wallet / privacy client`
- `pq mesh runtime`

The product is now a single PQ-only runtime. Remote interaction happens over the signed PQ mesh, while wallet and messaging flows are expressed through the CLI and the node-to-node protocol rather than separate HTTP perimeter services.

The only remaining HTTP surface is the metrics/log stream, and it is loopback-only for local observability.

Node identity is provisioned through an offline-root ceremony:

- `node init-root`
- `node auth-prepare`
- `node auth-sign`
- `node auth-install`

The runtime only requires the installed ML-DSA auth key and signed node record. The root key is not needed online after provisioning.

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
cargo run --release --bin unchained -- node start
cargo run --release --bin unchained -- wallet receive
```

## CLI

The primary user journeys are:

- `node start`
- `node init-root`
- `node auth-prepare`
- `node auth-sign`
- `node auth-install`
- `wallet receive`
- `wallet send`
- `wallet balance`
- `wallet history`
- `message send`
- `message listen`
- `advanced replay-transactions`
- `advanced rescan-wallet`

Operational and protocol-maintenance workflows live under `advanced`.

## Docs

- [README.md](/Users/home/unchgit/unchained/README.md): concise project summary
- [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md): system boundaries and current design
- [SHIELDED_POOL_V1.md](/Users/home/unchgit/unchained/SHIELDED_POOL_V1.md): shielded-pool successor design and currently landed core

Older Markdown files are archival unless rewritten to match the live code.
