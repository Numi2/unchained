# Unchained Architecture

This repository now treats the system as three separate concerns:

- `protocol / consensus core`
- `wallet / privacy client`
- `edge services` such as bridge, offers, and x402

## Canonical Rules

Consensus policy is versioned and protocol-locked in [src/protocol.rs](/Users/home/unchgit/unchained/src/protocol.rs).

Runtime config may tune operational behavior, but it does not redefine:

- genesis parameters
- retarget interval
- target and maximum selected coins per epoch
- difficulty and memory bounds
- retarget bands

## Validation Model

Spend validation is commit-epoch aware:

- each coin is bound to the epoch that committed it
- spends validate inclusion against that epoch's Merkle root
- wallets and validators share the same Merkle proof model

This replaces the previous genesis-only validation path, which was incompatible with the epoch-root design.

## Canonical Transactions

State transitions now flow through a canonical transaction object in [src/transaction.rs](/Users/home/unchgit/unchained/src/transaction.rs).

- `Tx` is the canonical persistence unit
- wallet, bridge, and network ingress all validate and persist through `Tx`
- canonical transaction propagation happens on `unchained/tx/v1`
- spend records are retained only as an internal derived index for wallet/state queries

This is the protocol model. There is no compatibility layer.

## Documentation Policy

The authoritative documents are:

- [README.md](/Users/home/unchgit/unchained/README.md) for operators and contributors
- [ARCHITECTURE.md](/Users/home/unchgit/unchained/ARCHITECTURE.md) for system boundaries

Older design notes, research essays, and feature-specific guides are archival material unless they are explicitly rewritten to match the live code.

## Service Boundary

Auxiliary HTTP surfaces are opt-in:

- offers API requires `[offers].api_enabled = true`
- bridge/x402 RPC requires `[bridge].bridge_enabled = true` or `[bridge].x402_enabled = true`

The node should not expose non-consensus APIs by default.

## Next Steps

- replace chained spend records with canonical transaction batches
- move bridge execution to an external relayer boundary
- define a global note commitment tree and nullifier set as the canonical state root
- split signer authority from consensus node runtime
