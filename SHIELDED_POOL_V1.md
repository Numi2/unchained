# Shielded Pool

This document describes the live shielded-pool architecture now implemented as
the canonical state model for Unchained.

It is designed around four constraints:

1. end-to-end post-quantum safety
2. no perpetual validator nullifier bloat
3. no safety dependence on sync/archive providers
4. a clean path to stronger privacy without reintroducing flat global state

## Core Model

`src/shielded.rs` defines the new core types:

- `ShieldedNote`
- `NoteCommitmentTree`
- `ArchivedNullifierEpoch`
- `ArchiveShard`
- `ArchiveProviderManifest`
- `ArchiveReplicaAttestation`
- `ArchiveDirectory`
- `NullifierRootLedger`
- `HistoricalUnspentCheckpoint`
- `HistoricalUnspentServiceResponse`
- `HistoricalUnspentSegment`
- `HistoricalUnspentExtension`
- `ShieldedSyncServer`

The model separates three concerns:

- note existence: handled by note commitments and a note tree
- current-epoch double-spend prevention: handled by the current evolving nullifier
- prior-epoch double-spend prevention: handled by historical absence proofs and
  portable checkpoints

## Notes

A note is a private object with:

- value
- birth epoch
- owner PQ signing key
- owner PQ KEM key
- note randomness
- `rho`
- a commitment to the note key

The chain only needs the note commitment. The note key is not stored in public
state.

`ShieldedNote::derive_evolving_nullifier()` uses:

- the private note key
- `rho`
- the chain id
- the epoch number

This ensures nullifiers change across epochs while remaining deterministic for a
single note within a single epoch.

## Historical Nullifiers

Each closed nullifier epoch is represented by:

- the sorted nullifier list
- a Merkle root over leaf hashes of that list

The chain only needs the root. Archive providers may keep the full per-epoch
nullifier contents.

`ArchivedNullifierEpoch::prove_absence()` produces a non-membership proof by
showing authenticated predecessor/successor boundaries in the sorted set. This
is not recursive compression and it is not zero knowledge. It is the minimal
authenticated history layer required to move nullifier bulk state off the
validator hot path without weakening safety.

## Portable Checkpoints

`HistoricalUnspentCheckpoint` is a client-portable digest that says:

- which note it belongs to
- where verification started
- which historical epochs are already covered
- a transcript root over all previously verified historical-absence steps

`ShieldedSyncServer::serve_checkpoint()` defines the provider-side service logic
for a contiguous checkpoint range. In the live runtime, that service is exposed
over the PQ mesh as batched checkpoint request/response messages rather than as
a local-only helper.

The live wallet no longer uses this in a one-note-at-a-time pattern. It runs a
fixed-cadence background refresh loop, builds batched checkpoint-extension
requests across many owned notes, splits each note history into shard-aligned
segments, routes those segments through a rotating multi-provider schedule,
pads each provider/shard bucket with cover requests up to a power-of-two
bucket, rerandomizes every provider response segment, packetizes those
rerandomized segments into a deeper checkpoint compression layer, and only then
aggregates the packets into the checkpoint extension that becomes durable local
state.

`HistoricalUnspentCheckpoint::apply_extension()` verifies those records against
the `NullifierRootLedger` and advances the checkpoint without requiring the
client to download the full historical nullifier database.

This makes provider switching possible. A checkpoint extended by one provider
can be continued by another, as long as both agree on the same root ledger.

## Archive Directory

Historical roots are also organized into content-addressed archive shards.

`ArchiveDirectory::from_root_ledger_and_providers_and_replicas()` derives:

- contiguous epoch-root shards
- provider manifests learned from the PQ mesh
- replica attestations and retention horizons per shard
- deterministic operator scorecards from public custody and retention data
- a provider-selection schedule for checkpoint refresh
- deterministic shard-custody assignments for replication repair

The live runtime no longer treats archive operators as a purely local replica
directory. Nodes now:

- gossip node records over the PQ mesh
- dial newly discovered operators directly
- ingest provider-authored archive manifests into the local directory
- ingest provider-authored replica attestations into the local directory
- request missing archive shards from the serving provider over the PQ mesh
- send remote checkpoint batch requests to the selected provider over the PQ mesh
- rebalance shard custody toward the protocol replica target when they are a
  deterministic assignee for an under-held shard

That makes the archive layer a real multi-operator network while preserving the
same provider-routing and rerandomization contract for checkpoint updates.

## Presentation Binding

`CheckpointPresentation` is a client-side blinded presentation handle over a
checkpoint transcript root.

`HistoricalUnspentServiceResponse::rerandomize()` is the stronger privacy step.
It takes a deterministic provider response segment and folds in client-only
blinding, the provider manifest digest, and the segment historical root digest
before that segment becomes durable state.

`HistoricalUnspentExtension::aggregate()` is the next step. It takes many
rerandomized provider segments, compresses them into packet-level accumulators,
and then compresses those packets into one checkpoint extension with:

- one note commitment
- one prior checkpoint root
- one aggregate historical-root digest
- one packet-commitment root
- one final aggregate rerandomization step

The checkpoint layer is no longer a public transaction field. It is private
witness material carried into the succinct spend proof, so validators consume
only the resulting public journal bindings rather than raw absence records.

## Storage

`src/storage.rs` now includes dedicated column families for the shielded pool:

- `shielded_note_tree`
- `shielded_nullifier_epoch`
- `shielded_root_ledger`
- `shielded_checkpoint`
- `shielded_archive_provider`
- `shielded_archive_replica`

These are persisted via canonical encodings in `src/canonical.rs`.

## Proof-Carrying Spend Path

The live spend path is proof-carrying:

- `proof-core` defines the private witness and public journal contract
- `methods/guest` validates that witness inside the zkVM
- `src/proof.rs` produces and verifies succinct STARK receipts
- `src/transaction.rs` accepts only transactions whose receipt journal matches
  the live note tree root, chain id, current nullifier epoch, and output
  bindings
- `src/wallet.rs` now constructs witness data locally, proves it, and only
  broadcasts the proof-carrying transaction object

What stays private inside the witness:

- input note plaintexts
- note membership paths
- historical checkpoint state
- historical absence extension records
- recipient note plaintexts and note keys

What remains public:

- current-epoch nullifiers
- encrypted output envelopes
- the succinct receipt
- the receipt journal bindings needed for state transition

## Operational Notes

The proving backend is CPU-first on Apple Silicon/macOS. Metal proving is not
part of the correctness contract for this repository.

## Current Frontier

The live runtime now already has:

1. segmented multi-provider checkpoint retrieval
2. rerandomized checkpoint-segment accumulation
3. fixed-cadence background checkpoint refresh with cover traffic
4. packet-level checkpoint compression above raw segments
5. mesh-discovered archive providers and shard exchange
6. replica attestations, deterministic operator scorecards, and shard-custody rebalancing

What remains is narrower:

1. stronger operator economics beyond deterministic scorecards and routing bias
2. archive-DA durability for very long historical horizons
3. deeper recursive compression across packet-level checkpoint accumulators
