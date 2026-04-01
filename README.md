# Unchained

Unchained is a post-quantum private asset node built around a narrow protocol core:

- protocol-locked epoch consensus
- canonical transaction batches
- commit-epoch-aware inclusion proofs
- wallet-side private ownership discovery
- opt-in edge services such as bridge, offers, and x402

The repository has been reset around a single rule: the canonical state transition is `Tx`.

## Current Architecture

The system is split into three layers:

1. `protocol / consensus core`
2. `wallet / privacy client`
3. `edge services`

`Tx` is the canonical wire, validation, and persistence unit.

- Network propagation uses `unchained/tx/v1`
- Validators apply transactions against protocol-locked rules in [src/protocol.rs](/Users/home/unchgit/unchained/src/protocol.rs)
- Inclusion checks resolve against the epoch that committed the coin
- Spend records exist only as an internal derived index for wallet and state queries

More detail lives in [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md).

## Repository Status

This codebase is in active protocol redesign. The current repo intentionally rejects several older patterns:

- no legacy wire compatibility
- no consensus tuning through runtime config
- no ambient bridge or offers APIs by default
- no assumption that old research documents still describe the implementation

If a document disagrees with the code, the code wins. If a non-README document disagrees with [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md), `ARCHITECTURE.md` wins.

## Build

Use a current stable Rust toolchain with Cargo support for Edition 2024 era dependencies.

```bash
rustup update
cargo build --release
```

Common local workflows:

```bash
cargo fmt
cargo run --release --bin unchained
cargo run --release --bin unchained mine
```

## Operating Model

At a high level:

1. miners produce coin candidates for an epoch
2. an anchor commits the selected set for that epoch
3. wallets construct canonical transactions from confirmed coins
4. validators check transaction structure, nullifier uniqueness, and commit-epoch Merkle inclusion
5. wallets discover relevant outputs locally

Consensus-critical policy is versioned in code, not in `config.toml`.

## Services

The node can expose additional service layers, but they are not part of the protocol core:

- `offers`
- `bridge`
- `x402`

These services are operationally opt-in and should be treated as separate trust domains even when they currently run in the same binary.

## CLI Surface

The binary currently exposes operator and wallet commands including:

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

Treat the CLI as an operator interface, not as the protocol definition.

## Docs

The documentation set has been normalized:

- [README.md](/Users/home/unchgit/unchained/README.md) is the entry point
- [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md) defines the current system boundaries
- older Markdown files are archival unless explicitly rewritten to match the current protocol

## Direction

The repo is moving toward:

- epoch sealing over explicit transaction batches
- clearer global state commitments
- stronger separation between consensus, wallet, and service processes
- removal of remaining spend-era internal assumptions

The goal is a smaller and more rigorous protocol core, not more feature surface.
