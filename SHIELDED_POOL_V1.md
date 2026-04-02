# Shielded Pool V1

This document defines the shielded-pool architecture being introduced as the
successor to the current coin/spend-chain model.

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

`HistoricalUnspentCheckpoint::apply_extension()` verifies those records against
the `NullifierRootLedger` and advances the checkpoint without requiring the
client to download the full historical nullifier database.

This makes provider switching possible. A checkpoint extended by one provider
can be continued by another, as long as both agree on the same root ledger.

## Presentation Binding

`CheckpointPresentation` is a client-side blinded presentation handle over a
checkpoint transcript root.

This is intentionally not yet a rerandomizable recursive ZK proof. It is a
presentation-layer binding that lets the client separate the provider-issued
checkpoint from the client-issued presentation identifier. The next proof-system
cutover should replace this with true rerandomization at the proof layer.

## Storage

`src/storage.rs` now includes dedicated column families for the shielded pool:

- `shielded_note_tree`
- `shielded_nullifier_epoch`
- `shielded_root_ledger`
- `shielded_checkpoint`

These are persisted via canonical encodings in `src/canonical.rs`.

## Current Status

Implemented now:

- canonical shielded note representation
- note commitment tree and membership proofs
- evolving nullifier derivation
- per-epoch historical nullifier archives
- authenticated non-membership proofs
- provider-portable checkpoint extension
- checkpoint persistence in RocksDB

Not yet cut over:

- replacement of the live transaction runtime with shielded spends
- recursive compression of historical absence proofs
- transparent PQ proof verification inside block validation
- wallet note management and note scanning on top of the new pool

## Next Cutover

The next protocol tranche should:

1. define a new shielded transaction object that carries:
   - note membership proof
   - current evolving nullifier
   - historical checkpoint root
   - output note commitments
2. replace `coin_id -> latest spend` ownership with the note tree plus current
   epoch nullifier uniqueness
3. move historical-unspent verification into a transparent PQ proof system
4. delete the old spend-chain path after the shielded runtime is live
