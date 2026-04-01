# Unchained

Unchained is a post-quantum private asset node.

## Tech Choices

- Consensus: epoch-based proof of work
- Proof of work: Argon2id
- Hashing: BLAKE3
- Network transport: libp2p over QUIC
- Persistence: RocksDB
- Recipient privacy: Kyber768-based stealth outputs
- Signatures: Dilithium3
- Canonical state transition: [`Tx`](/Users/home/unchgit/unchained/src/transaction.rs)

## Protocol

- Consensus rules are protocol-locked in [`src/protocol.rs`](/Users/home/unchgit/unchained/src/protocol.rs).
- Runtime config does not redefine consensus parameters.
- Coins are committed by epoch anchors.
- Spend validation is commit-epoch aware.
- Transaction propagation uses `unchained/tx/v1`.
- `Tx` is the canonical wire, validation, and persistence unit.
- Spend records are internal derived indexes, not the protocol surface.

## Architecture

- `protocol / consensus core`
- `wallet / privacy client`
- `edge services`

Edge services include `bridge`, `offers`, and `x402`. They are opt-in and not part of consensus.

## Current Defaults

- No legacy wire compatibility
- No ambient bridge API by default
- No ambient offers API by default
- No consensus tuning through config

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
cargo run --release --bin unchained
cargo run --release --bin unchained mine
```

## CLI

Current operator and wallet commands include:

- `mine`
- `peer-id`
- `stealth-address`
- `proof`
- `send`
- `balance`
- `history`
- `offer-watch`
- `msg-send`
- `msg-listen`
- `x402-pay`

## Docs

- [README.md](/Users/home/unchgit/unchained/README.md): concise project summary
- [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md): system boundaries and current design

Older Markdown files are archival unless rewritten to match the live code.
