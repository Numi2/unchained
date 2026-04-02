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
- `NullifierRootLedger`
- `HistoricalUnspentCheckpoint`
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

`ShieldedSyncServer::extend_checkpoint()` extends that checkpoint over a
contiguous range of epochs by producing authenticated absence records.

The live wallet no longer uses this in a one-note-at-a-time pattern. It builds
batched checkpoint-extension requests across many owned notes, groups them by
epoch, and pads each epoch batch with cover requests up to a power-of-two
bucket. That improves both scale and query-shape privacy without changing
consensus semantics.

`HistoricalUnspentCheckpoint::apply_extension()` verifies those records against
the `NullifierRootLedger` and advances the checkpoint without requiring the
client to download the full historical nullifier database.

This makes provider switching possible. A checkpoint extended by one provider
can be continued by another, as long as both agree on the same root ledger.

## Presentation Binding

`CheckpointPresentation` is a client-side blinded presentation handle over a
checkpoint transcript root.

The checkpoint layer is no longer a public transaction field. It is private
witness material carried into the succinct spend proof, so validators consume
only the resulting public journal bindings rather than raw absence records.

## Storage

`src/storage.rs` now includes dedicated column families for the shielded pool:

- `shielded_note_tree`
- `shielded_nullifier_epoch`
- `shielded_root_ledger`
- `shielded_checkpoint`

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

## Next Frontier

The remaining frontier is sync/privacy efficiency, not shielded spend
correctness:

1. batched checkpoint extension across many notes
2. stronger provider-oblivious synchronization beyond padded batching
3. content-addressed archival distribution for historical nullifier epochs
4. proof-system-level rerandomization and accumulation schemes where they
   improve privacy or amortized proving cost without weakening PQ safety
