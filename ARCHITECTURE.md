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
- a spend proves inclusion against that committing epoch
- the latest spend stored under `coin_id` defines current ownership
- `Tx` is the canonical persistence, validation, and gossip unit

The current system is therefore a private spend chain over stable coin identities. It is not yet a global note commitment tree with append-only note creation.

## Privacy Model

Wallet privacy comes from private recipient addresses, ML-KEM-derived one-time outputs, and hashlock-based ownership transfer.

Important consequence:

- deterministic nullifiers remain in the transaction data for domain-separated spend identity
- the node does not persist a global nullifier set as canonical state
- replay prevention comes from the current lock state on the coin plus the latest confirmed spend record

This removes flat nullifier-set growth from the live path. In the current model, persisting every historic nullifier is redundant state.

## Validation Model

Spend validation is commit-epoch aware:

- each coin is bound to the epoch that committed it
- spends validate inclusion against that epoch's Merkle root
- wallets and validators share the same Merkle proof model
- when local proof material is missing, clients can request a proof from peers and verify it against the stored committing anchor

## Service Boundary

The product boundary is PQ-only by construction:

- node-to-node communication runs over the signed PQ mesh
- the mesh trust root is an offline ML-DSA node root that signs time-bounded runtime node records
- the online runtime presents only its delegated ML-DSA auth key plus installed signed node record
- wallet, offer, and message workflows are driven through the CLI and protocol messages
- no bridge, x402, or separate offers HTTP perimeter exists in the default product
- the metrics/log stream is loopback-only and not part of the remote protocol surface

## Product Surface

The public CLI is intentionally phrased in product terms:

- `node init-root`, `node auth-prepare`, `node auth-sign`, and `node auth-install` implement the offline-root provisioning flow
- `node start` is the explicit runtime entrypoint
- `wallet receive`, `wallet send`, `wallet balance`, and `wallet history` are the primary wallet journeys
- `offers` and `message` are mesh-native product commands
- `advanced` contains protocol and maintenance tooling
- older flat command names remain only as compatibility aliases

## If Re-Architecting Further

The shielded-pool successor is now being defined in [SHIELDED_POOL_V1.md](/Users/home/unchgit/unchained/SHIELDED_POOL_V1.md) and implemented in [src/shielded.rs](/Users/home/unchgit/unchained/src/shielded.rs).

The target remains:

- one global note commitment tree
- one compact spent-set commitment or accumulator
- zero-knowledge spend proofs that prove note inclusion and spent-set non-membership

That future design should not reintroduce an unbounded RocksDB nullifier column as the canonical state root. A real note-pool architecture needs a committed spent-set design, not flat storage growth.
