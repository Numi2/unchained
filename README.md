# Unchained

Unchained is a post-quantum private asset node with a PQ-only default build.

## Tech Choices

- Consensus: epoch-based proof of work
- Proof of work: Argon2id
- Hashing: BLAKE3
- Network transport: QUIC over TLS 1.3 raw public keys with ML-KEM-768 key exchange and ML-DSA-65 authentication
- Persistence: RocksDB
- Recipient privacy: ML-KEM-768-based private recipient docs and opaque one-time outputs
- Signatures: ML-DSA-65
- Canonical state transition: [`Tx`](/Users/home/unchgit/unchained/src/transaction.rs)

## Protocol Posture

- Consensus rules are protocol-locked in [`src/protocol.rs`](/Users/home/unchgit/unchained/src/protocol.rs).
- Coins are committed by epoch anchors.
- Spends validate inclusion against the epoch that committed the coin.
- Ownership is serialized by `coin_id -> latest spend`, not by an append-only note pool.
- Each spend still carries a deterministic nullifier on the wire, but the node does not persist a global nullifier set for replay prevention in the current spend-chain model.
- Canonical transaction propagation happens on `unchained/tx/v1`.

This is a private transfer system, but it is not yet a full global shielded-note tree with zero-knowledge spend proofs. The public CLI therefore leads with wallet user journeys such as `wallet receive` and `wallet send`, while retaining older flat aliases for compatibility.

## Architecture

- `protocol / consensus core`
- `wallet / privacy client`
- `edge services`

Edge services include `offers` and `message`. The classical perimeter (`bridge` and `x402`) is built separately behind `--features classical_perimeter` and is not part of consensus.

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
- `wallet receive`
- `wallet send`
- `wallet balance`
- `wallet history`
- `offers watch`
- `message send`
- `message listen`

Operational and protocol-maintenance workflows live under `advanced`.

Compatibility aliases are retained for older workflows, including `mine`, `peer-id`, `address`, `send`, `balance`, `history`, `stealth-address`, `offer-watch`, and message aliases. `x402-pay` exists only in classical-perimeter builds.

## Docs

- [README.md](/Users/home/unchgit/unchained/README.md): concise project summary
- [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md): system boundaries and current design

Older Markdown files are archival unless rewritten to match the live code.
