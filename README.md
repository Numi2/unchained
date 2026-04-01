# Unchained

Unchained is a post-quantum private asset node.

## Tech Choices

- Consensus: epoch-based proof of work
- Proof of work: Argon2id
- Hashing: BLAKE3
- Network transport: libp2p over QUIC
- Persistence: RocksDB
- Recipient privacy: Kyber768-based private addresses and opaque one-time outputs
- Signatures: Dilithium3
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

Edge services include `offers`, `message`, `bridge`, and `x402`. They are opt-in and not part of consensus.

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
- `x402 pay`

Operational and protocol-maintenance workflows live under `advanced`.

Compatibility aliases are retained for older workflows, including `mine`, `peer-id`, `address`, `send`, `balance`, `history`, `stealth-address`, `offer-watch`, `msg-send`, `msg-listen`, and `x402-pay`.

## Docs

- [README.md](/Users/home/unchgit/unchained/README.md): concise project summary
- [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md): system boundaries and current design

Older Markdown files are archival unless rewritten to match the live code.
