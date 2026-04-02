# Unchained Architecture

This document describes the current repository architecture as implemented in
the checked-in code.

The runtime is easiest to reason about as three connected areas:

- `protocol / consensus core`
- `wallet / shielded client`
- `pq mesh runtime`

## Canonical Rules

Consensus and protocol constants are locked in `src/protocol.rs` and then
consumed by the rest of the system:

- proof-of-work and retarget rules in `src/consensus.rs`
- epoch production and anchor handling in `src/epoch.rs`
- nullifier rollover, archive shard sizing, and checkpoint routing in
  `src/transaction.rs`, `src/shielded.rs`, and `src/network.rs`
- wallet refresh cadence and cover-query behavior in `src/wallet.rs`

Remote objects do not rely on Serde or `bincode` field layout for network
compatibility. Canonical wire and signed-document encodings live in
`src/canonical.rs` and are used for:

- node records and trust updates
- signed envelopes
- transactions and shielded outputs
- archive manifests, replica attestations, custody commitments, and receipts

Runtime config changes operational behavior, but the protocol constants used by
validation come from code rather than from `config.toml`.

## State Model

The live shielded state transition is centered on these persisted objects:

- anchors in the epoch store
- the global shielded note commitment tree
- the current active nullifier epoch
- archived nullifier epochs plus the root ledger
- proof-carrying `Tx` objects

Concrete flow:

1. Coins are committed by epoch anchors.
2. `coin_epoch` binds a coin to the epoch that committed it.
3. Committed coins can be deterministically materialized into genesis shielded
   notes.
4. Shielded note commitments are appended to the global note tree.
5. Transactions spend by presenting current-epoch nullifiers plus a proof whose
   journal binds historical and output state to the live chain.

That means the canonical model is no longer a public `coin_id -> latest spend`
table. Current ownership is represented by unspent shielded notes plus the
active and archived nullifier structures.

## Validation Path

Shielded validation in the current code has two layers.

Public validator checks in `src/transaction.rs`:

- transaction shape is sane
- active nullifier uniqueness holds for the current epoch
- the proof receipt verifies
- the proof journal chain ID, epoch, note-tree root, nullifiers, and output
  bindings match local state
- the historical root digest named by the proof matches the local
  `NullifierRootLedger`

Private witness checks in `proof-core` and the zkVM guests:

- note membership proofs
- historical checkpoint accumulator steps
- hidden note plaintext and note-key material
- historical absence records carried behind the receipt

The proof split is:

- `proof-core/src/lib.rs`: witness and journal contract
- `methods/guest/src/main.rs`: shielded spend guest
- `methods/checkpoint-guest/src/main.rs`: checkpoint accumulator guest
- `src/proof.rs`: proving and local verification glue

## Wallet And Archive Flow

The wallet owns the client-side shielded lifecycle in `src/wallet.rs`.

Implemented behavior:

- recipient export uses signed KeyDoc JSON documents
- owned genesis notes and received outputs are materialized locally
- wallet balance and history derive from owned shielded notes and recorded sent
  transactions
- sends refresh checkpoints, build a witness, produce a succinct receipt, apply
  the transaction locally, and then gossip it

When `node start` runs, the binary also spawns a fixed-cadence oblivious wallet
refresh loop from `src/main.rs`.

That refresh loop and the archive path are implemented across `src/wallet.rs`,
`src/shielded.rs`, and `src/network.rs`:

- requests are segmented by archive shard
- segments are routed across providers chosen from the archive directory
- provider/shard buckets are padded with synthetic cover traffic
- service responses are rerandomized client-side
- rerandomized segments are compressed into packets and strata
- checkpoint accumulators are proved with succinct receipts
- manifests, replicas, service ledgers, custody commitments, retrieval receipts,
  availability certificates, and operator scorecards are persisted locally
- the network runtime repairs missing archive shards and rebalances local shard
  custody toward the configured replica target

## Network Boundary

The remote service boundary is PQ-only in the project-owned runtime:

- QUIC transport lives in `src/network.rs`
- TLS setup and node identity ceremony live in `src/node_identity.rs`
- runtime identities use ML-DSA raw public keys and ML-KEM-768 key exchange
- node-to-node messages move through signed envelopes and canonical wire topics

The CLI in `src/main.rs` is the user-facing surface for:

- node provisioning
- node start/peer identity
- wallet receive/send/balance/history
- message send/listen
- maintenance tasks under `advanced`

The only HTTP endpoint in the repository runtime is the local metrics/log stream
in `src/metrics.rs`, and the server rejects non-loopback bind addresses.

## Persistence Layout

RocksDB is the canonical persistence layer (`src/storage.rs`).

Relevant shielded/archive column families include:

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

## Verification Coverage

The checked-in tests exercise the architecture at several levels:

- `tests/shielded_pool.rs` covers note commitments, evolving nullifiers,
  checkpoints, rerandomization, archive directory logic, and operator scoring
- `tests/shielded_tx_flow.rs` covers end-to-end wallet send/receive with the
  succinct proof path
- `tests/pq_network.rs` covers PQ bootstrap, anchor propagation, archive shard
  handling, and checkpoint request routing on the network side
