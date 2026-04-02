# Shielded Pool V1

This file describes the current shielded-pool model used by the repository.
The terminology here matches the code in `src/shielded.rs`, `src/wallet.rs`,
`src/transaction.rs`, `src/proof.rs`, and `proof-core/src/lib.rs`.

## Core Types

The main shielded-pool objects implemented in `src/shielded.rs` are:

- `ShieldedNote`
- `NoteCommitmentTree`
- `ActiveNullifierEpoch`
- `ArchivedNullifierEpoch`
- `NullifierRootLedger`
- `ArchiveShard`
- `ArchiveProviderManifest`
- `ArchiveReplicaAttestation`
- `ArchiveCustodyCommitment`
- `ArchiveServiceLedger`
- `ArchiveAvailabilityCertificate`
- `ArchiveOperatorScorecard`
- `HistoricalUnspentCheckpoint`
- `HistoricalUnspentServiceResponse`
- `HistoricalUnspentSegment`
- `HistoricalUnspentPacket`
- `HistoricalUnspentStratum`
- `HistoricalUnspentExtension`
- `ShieldedSyncServer`

## State Separation

The model separates three concerns:

- note existence: the note commitment tree
- current-epoch replay prevention: the active nullifier epoch
- prior-epoch replay prevention: archived nullifier epochs plus portable
  checkpoints

This is why validators do not need a perpetually growing flat historic
nullifier table in canonical hot state.

## Notes And Nullifiers

`ShieldedNote` carries:

- value
- birth epoch
- owner signing key
- owner KEM key
- `rho`
- note randomness
- a commitment to the note key

The public chain state only needs the note commitment.

`ShieldedNote::derive_evolving_nullifier()` binds a nullifier to:

- the private note key
- `rho`
- the chain ID
- the target epoch

So the same note produces distinct deterministic nullifiers across epochs.

## Archived Nullifier Epochs

Each closed nullifier epoch is stored as an `ArchivedNullifierEpoch` with:

- the epoch number
- the sorted nullifier set
- a root over that set

`NullifierRootLedger` keeps the compact epoch-to-root mapping that validators
and wallets use for historical binding.

`ArchivedNullifierEpoch::prove_absence()` produces authenticated absence proofs
based on predecessor/successor boundaries in the sorted set.

## Portable Checkpoints

`HistoricalUnspentCheckpoint` is the wallet-portable summary of historical
verification for one note. It records:

- the note commitment
- the note birth epoch
- the highest epoch already covered
- a transcript root over prior verified historical steps
- a verified epoch count

Provider-side checkpoint service logic is implemented by `ShieldedSyncServer`.
On the network path, those responses move as checkpoint batch requests and
responses over the PQ transport rather than as a local-only helper.

## Checkpoint Aggregation

The current wallet and network code implement a multi-stage checkpoint flow:

1. Build checkpoint extension requests from owned notes.
2. Segment requests by archive shard.
3. Route segments across providers from `ArchiveDirectory`.
4. Pad provider/shard buckets with synthetic cover requests.
5. Rerandomize provider responses.
6. Compress rerandomized segments into packets.
7. Compress packets into strata.
8. Aggregate strata into one `HistoricalUnspentExtension`.
9. Prove checkpoint accumulator updates with succinct receipts.

The relevant code lives in:

- `src/wallet.rs`
- `src/shielded.rs`
- `src/network.rs`
- `src/proof.rs`

`HistoricalUnspentCheckpoint::apply_extension()` and
`HistoricalUnspentCheckpoint::apply_accumulator()` advance local checkpoint
state against the `NullifierRootLedger`.

## Archive Directory

`ArchiveDirectory` derives a routing and scoring view from:

- the root ledger
- provider manifests
- replica attestations
- service ledgers
- custody commitments
- retrieval receipts

From those inputs it computes:

- contiguous archive shards
- provider coverage over shard ranges
- replica reports
- availability certificates
- operator scorecards
- custody assignments
- provider selection for checkpoint segments and shard repair

The network runtime persists and exchanges those archive objects through the
column families defined in `src/storage.rs`.

## Proof-Carrying Spend Path

The spend path is proof-carrying in the checked-in runtime:

- `proof-core` defines the witness and journal schema
- `methods/guest` verifies shielded spend witnesses in the zkVM
- `methods/checkpoint-guest` verifies checkpoint accumulator steps
- `src/proof.rs` produces and verifies succinct receipts
- `src/wallet.rs` assembles witness data and produces the spend proof
- `src/transaction.rs` accepts the transaction only if the receipt journal
  matches live chain state

Private witness material includes:

- input note plaintexts
- note membership paths
- checkpoint accumulator state
- historical absence records
- recipient note plaintext and note keys

Public transaction material includes:

- current-epoch nullifiers
- encrypted shielded outputs
- the succinct receipt bytes
- the receipt journal bindings validated against local state

## Storage

The shielded pool uses dedicated RocksDB column families in `src/storage.rs`,
including:

- `shielded_note_tree`
- `shielded_nullifier_epoch`
- `shielded_root_ledger`
- `shielded_checkpoint`
- `shielded_output`
- `shielded_owned_note`
- `shielded_active_nullifier`
- `shielded_spent_note`
- `shielded_archive_provider`
- `shielded_archive_replica`
- `shielded_archive_operator`
- `shielded_archive_accounting`
- `shielded_archive_custody`
- `shielded_archive_receipt`

## Runtime Scope

The live runtime already includes:

1. deterministic genesis-note materialization
2. evolving-nullifier epochs and root-ledger rollover
3. signed KeyDoc recipient documents
4. fixed-cadence wallet refresh with cover requests
5. segmented multi-provider checkpoint routing
6. response rerandomization plus packet/stratum aggregation
7. checkpoint accumulator proving
8. archive manifests, replica attestations, custody commitments, retrieval
   receipts, availability certificates, and operator scorecards
9. archive shard repair and deterministic custody rebalancing in the network
   runtime

Areas that still read as frontier work in the current design are:

1. stronger operator economics beyond deterministic score and routing weights
2. very long-horizon archive durability assumptions
3. deeper recursive compression above the current stratum/accumulator layer
