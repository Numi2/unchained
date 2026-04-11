# Shielded Pool V1

This file describes the current shielded-pool model used by the repository.
The terminology here matches the canonicalized code in `src/shielded.rs`,
`src/wallet.rs`, `src/transaction.rs`, `src/proof.rs`, and
`proof-core/src/lib.rs`.

## Core Types

The main shielded-pool objects implemented in `src/shielded.rs` are:

- `ShieldedNote`
- `NoteCommitmentTree`
- `ActiveNullifierEpoch`
- `HistoricalNullifierWindow`
- `NullifierRootLedger`
- `FinalizedHistoryShard`
- `FinalizedHistoryDirectory`
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
- prior-epoch replay prevention: finalized historical nullifier windows plus
  portable checkpoints

Validators do not need a perpetually growing flat historic nullifier table in
canonical hot state. Finalized history is consensus-derived local state, not an
external data market.

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

The same note therefore produces distinct deterministic nullifiers across
epochs.

## Historical Nullifier Windows

Each closed nullifier epoch is stored as a `HistoricalNullifierWindow` with:

- the epoch number
- the sorted nullifier set
- a root over that set

`NullifierRootLedger` keeps the compact epoch-to-root mapping that validators
and wallets use for historical binding.

`HistoricalNullifierWindow::prove_absence()` produces authenticated absence
proofs based on predecessor/successor boundaries in the sorted set.

## Portable Checkpoints

`HistoricalUnspentCheckpoint` is the wallet-portable summary of historical
verification for one note. It records:

- the note commitment
- the note birth epoch
- the highest epoch already covered
- a transcript root over prior verified historical steps
- a verified epoch count

Checkpoint service logic is implemented by `ShieldedSyncServer` over local
finalized history. Network and node-control callers exchange checkpoint batch
requests and responses without provider manifests or external shard discovery.

## Checkpoint Aggregation

The current wallet and network code implement a local finalized-history flow:

1. Build checkpoint extension requests from owned notes.
2. Serve absence records from local finalized nullifier windows.
3. Rerandomize service responses.
4. Compress rerandomized segments into packets.
5. Compress packets into strata.
6. Aggregate strata into one `HistoricalUnspentExtension`.
7. Prove checkpoint accumulator updates with native-proof-capability plumbing.

The relevant code lives in:

- `src/wallet.rs`
- `src/shielded.rs`
- `src/network.rs`
- `src/proof.rs`

`HistoricalUnspentCheckpoint::apply_extension()` and
`HistoricalUnspentCheckpoint::apply_accumulator()` advance local checkpoint
state against the `NullifierRootLedger`.

## Proof-Carrying Spend Path

The spend path is proof-carrying in the checked-in runtime:

- `proof-core` defines the witness and journal schema
- `src/proof.rs` produces and verifies native proof envelopes
- `src/wallet.rs` assembles witness data and produces the spend proof
- `src/transaction.rs` accepts the transaction only if the public journal
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
- proof seal bytes
- public journal bindings validated against local state

## Storage

The shielded pool uses dedicated RocksDB column families in `src/storage.rs`,
including:

- `shielded_note_tree`
- `shielded_nullifier_epoch`
- `shielded_root_ledger`
- `shielded_output`
- `shielded_active_nullifier`
- `shielded_spent_note`

Legacy local wallet state is kept in the wallet database. Removed provider
column families are dropped during schema opening if an old dev database still
contains them.

## Runtime Scope

The live runtime includes:

1. deterministic genesis-note materialization
2. evolving-nullifier epochs and root-ledger rollover
3. signed KeyDoc recipient documents
4. fixed-cadence wallet refresh with local finalized-history requests
5. response rerandomization plus packet/stratum aggregation
6. checkpoint accumulator API surfaces that now fail clearly until native
   circuits are implemented
7. native ordinary-transfer proof envelope generation and verification

Areas that still read as frontier work in the current design are:

1. full Plonky3 AIR constraints for ordinary transfer
2. native checkpoint accumulator, staking, issuance, and redemption circuits
3. deeper recursive compression above the current stratum/accumulator layer
