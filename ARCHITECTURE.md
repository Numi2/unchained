# Unchained Architecture

This repository treats the system as three separate concerns:

- `protocol / consensus core`
- `wallet / privacy client`
- `pq mesh runtime`

## Canonical Rules

Consensus policy is versioned and protocol-locked in [src/protocol.rs](/Users/home/unchgit/unchained/src/protocol.rs).

All signed remote objects and mesh payloads use an explicit canonical byte codec in [src/canonical.rs](/Users/home/unchgit/unchained/src/canonical.rs). The live protocol does not depend on serde or `bincode` layout choices for node records, trust updates, envelopes, or wire topics.

Runtime config may tune operational behavior, but it does not redefine:

- genesis parameters
- retarget interval
- target and maximum selected coins per epoch
- difficulty and memory bounds
- retarget bands

## Canonical State

The live protocol model is:

- epoch anchors commit mined coins
- `coin_epoch` binds each coin to the epoch that committed it
- each committed coin is deterministically lifted into a genesis shielded note
- shielded note commitments are appended to the global note tree
- current ownership is represented by unspent notes plus evolving-nullifier history
- `Tx` is the canonical persistence, validation, and gossip unit

The current system is therefore a shielded note runtime rooted in an append-only note commitment tree rather than a `coin_id -> latest spend` chain.

## Privacy Model

Wallet privacy comes from private recipient documents, ML-KEM-derived one-time outputs, and evolving nullifiers over shielded notes.

Important consequence:

- deterministic nullifiers remain in the transaction data for domain-separated spend identity
- the node does not persist a global historic nullifier set as canonical validator state
- replay prevention comes from the active nullifier epoch plus historical unspent checkpoint validation

This removes flat nullifier-set growth from the live path. In the current model, persisting every historic nullifier is redundant state.

## Validation Model

Shielded validation is epoch-aware:

- each input note proves membership in the global note commitment tree
- each input carries a historical-unspent checkpoint plus extension up to the prior nullifier epoch
- validators enforce uniqueness in the current active nullifier epoch
- validators can prune historic nullifier contents once the archived epoch commitments are fixed on chain

## Service Boundary

The product boundary is PQ-only by construction:

- node-to-node communication runs over the signed PQ mesh
- the mesh trust root is an offline ML-DSA node root that signs time-bounded runtime node records
- the online runtime presents only its delegated ML-DSA auth key plus installed signed node record
- wallet and message workflows are driven through the CLI and protocol messages
- no bridge, x402, offer market, or separate HTTP perimeter exists in the product
- the metrics/log stream is loopback-only and not part of the remote protocol surface

## Product Surface

The public CLI is intentionally phrased in product terms:

- `node init-root`, `node auth-prepare`, `node auth-sign`, and `node auth-install` implement the offline-root provisioning flow
- `node start` is the explicit runtime entrypoint
- `wallet receive`, `wallet send`, `wallet balance`, and `wallet history` are the primary wallet journeys
- `message` is the mesh-native user command
- `advanced` contains protocol and maintenance tooling

## If Re-Architecting Further

The shielded-pool successor is now being defined in [SHIELDED_POOL_V1.md](/Users/home/unchgit/unchained/SHIELDED_POOL_V1.md) and implemented in [src/shielded.rs](/Users/home/unchgit/unchained/src/shielded.rs).

The target remains:

- one global note commitment tree
- one compact spent-set commitment or accumulator
- zero-knowledge spend proofs that prove note inclusion and spent-set non-membership

That future design should not reintroduce an unbounded RocksDB nullifier column as the canonical state root. A real note-pool architecture needs a committed spent-set design, not flat storage growth.
