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
- Canonical transactions carry a succinct STARK receipt over a private witness, while validators only see the current nullifiers, encrypted outputs, and the proof journal bindings required to update state.
- Historical unspent state is represented by checkpoint and extension objects rather than a perpetually growing validator nullifier table.
- Wallet checkpoint refresh now batches note queries by epoch and pads them with cover requests, so archive sync is less one-note-at-a-time and less directly spend-shaped.

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

Proof generation is now part of the live wallet path:

- `proof-core` defines the canonical shielded witness and public journal contract
- `methods/guest` is the zkVM guest that validates that witness
- [`src/proof.rs`](/Users/home/unchgit/unchained/src/proof.rs) generates and verifies succinct STARK receipts

On Apple Silicon, the repository treats CPU proving as the stable default. The build does not depend on a functioning Metal proving path.

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
cargo test --test shielded_tx_flow -- --ignored --nocapture
cargo run --release --bin unchained -- node start
cargo run --release --bin unchained -- wallet receive
```

`cargo test` is the fast default suite. The ignored `shielded_tx_flow` integration runs the full end-to-end succinct-proof wallet roundtrip.

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
- [SHIELDED_POOL_V1.md](/Users/home/unchgit/unchained/SHIELDED_POOL_V1.md): live shielded-pool and proof-carrying state model

Older Markdown files are archival unless rewritten to match the live code.
