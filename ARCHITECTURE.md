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

- each input note proves membership in the global note commitment tree inside a private witness
- each input carries a historical-unspent checkpoint plus extension up to the prior nullifier epoch inside that same private witness
- validators enforce uniqueness in the current active nullifier epoch
- validators verify a succinct STARK receipt and only consume its public journal bindings
- validators can prune historic nullifier contents once the archived epoch commitments are fixed on chain

The proof-carrying contract is split deliberately:

- [`proof-core`](/Users/home/unchgit/unchained/proof-core/src/lib.rs) defines the canonical witness and public journal semantics
- [`methods/guest`](/Users/home/unchgit/unchained/methods/guest/src/main.rs) validates the witness inside the zkVM
- [`src/proof.rs`](/Users/home/unchgit/unchained/src/proof.rs) produces and verifies succinct receipts
- [`src/transaction.rs`](/Users/home/unchgit/unchained/src/transaction.rs) binds those public journal fields to live chain state before applying updates

This means historical absence records, note membership paths, and note plaintexts are no longer transaction fields. They are witness material hidden behind the receipt.

On the client side, checkpoint refresh is now routed through a replica-aware mesh archive directory. Nodes gossip node records over the PQ mesh, dial newly discovered operators directly, ingest provider-authored archive manifests plus replica attestations, request missing epoch shards over the same PQ transport, and answer checkpoint batch requests over that same PQ mesh. The wallet no longer treats a historical refresh as one provider, one proof. It runs a fixed-cadence refresh loop, splits each note history into shard-aligned checkpoint segments, routes those segments across multiple providers, pads provider/shard buckets with cover traffic, rerandomizes every provider segment reply, compresses those segments into packet-level checkpoint accumulators, and only then aggregates the packets into one checkpoint extension. That means no single provider needs to see the full note history for a refresh, spend timing is less query-shaped, and the durable checkpoint transcript root is not byte-identical to what any provider produced.

## Service Boundary

The product boundary is PQ-only by construction:

- node-to-node communication runs over the signed PQ mesh
- the mesh trust root is an offline ML-DSA node root that signs time-bounded runtime node records
- the online runtime presents only its delegated ML-DSA auth key plus installed signed node record
- wallet and message workflows are driven through the CLI and protocol messages
- no bridge, x402, offer market, or separate HTTP perimeter exists in the product
- the metrics/log stream is loopback-only and not part of the remote protocol surface

On Apple Silicon/macOS, the proving path is intentionally CPU-first. Metal kernels are not part of the correctness boundary and are not required for a working node or test run.

## Product Surface

The public CLI is intentionally phrased in product terms:

- `node init-root`, `node auth-prepare`, `node auth-sign`, and `node auth-install` implement the offline-root provisioning flow
- `node start` is the explicit runtime entrypoint
- `wallet receive`, `wallet send`, `wallet balance`, and `wallet history` are the primary wallet journeys
- `message` is the mesh-native user command
- `advanced` contains protocol and maintenance tooling

## Archive Layer

The live runtime already proves shielded spends with succinct STARK receipts, avoids validator nullifier bloat, rotates checkpoint queries across mesh-discovered archive providers, exchanges archived shards directly over the PQ mesh, serves remote checkpoint batches over that same transport, rerandomizes provider responses before they enter the proof witness, packetizes those rerandomized segment batches one layer deeper inside the checkpoint witness, computes deterministic operator scorecards for long-horizon archive custody, and rebalances deterministic shard custody toward the protocol replica target.

That leaves a narrower remaining frontier:

- stronger operator economics beyond deterministic scorecards and route bias
- archive DA that survives very long historical horizons without relying on a small operator set
- proof-system-level accumulation that turns packet-level checkpoint witnesses into even smaller recursive witness objects

It still must not reintroduce an unbounded RocksDB nullifier column as canonical state.
