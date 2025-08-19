## Unchained: Epoch-based, PoW-minted, PQ-secure blockchain

### Goal and high-level model
Unchained divides time into fixed-length epochs. Miners generate self-contained coins via memory-hard PoW during an epoch. At the epoch boundary the network finalizes an anchor that commits to the set of selected coins via a Merkle aroot. Each coin can be verified independently using its epoch anchor and a Merkle proof, enabling light verification and efficient sync.

### Consensus primitives
- **Epochs**: Fixed seconds per epoch from config. Anchors form a chain: each new anchor commits to the previous anchor hash and to the Merkle root of selected coin IDs for the epoch that just ended.
- **Coin creation (PoW)**:
  - Header bytes = `epoch_hash || nonce || miner_address`.
  - PoW = Argon2id(header, mem_kib from previous anchor; lanes fixed to 1 in consensus).
  - Difficulty = number of leading zero BYTES required in the 32-byte PoW hash (coarse, consensus rule).
  - Coin ID = BLAKE3(`epoch_hash`, `nonce`, `creator_address`) – independent of PoW hash.
- **Selection (mint cap)**:
  - Config defines a per-epoch target and a hard cap `max_coins_per_epoch`.
  - All valid coin candidates for the epoch compete; the node deterministically selects up to N coins with the smallest PoW hashes (ties broken by coin_id) and commits only those.
- **Anchor** (`src/epoch.rs::Anchor`): `{ num, hash, merkle_root, difficulty, coin_count, cumulative_work, mem_kib }`.
  - `hash` = BLAKE3(`merkle_root`, `prev_anchor.hash` if any).
  - `merkle_root` hashes BLAKE3-leaves of selected coin IDs; leaves are sorted; pairs are hashed upward (duplicate last on odd level).
  - `cumulative_work` is the sum of per-epoch work by difficulty bytes (deterministic, integer).
- **Fork choice**: Prefer higher `cumulative_work`, break ties by higher epoch number.

### Intentionally off-by-one epoch binding
- Miners bind a coin to the previous anchor’s hash (the current epoch’s parent). The epoch manager, when finalizing epoch `k`, selects from candidates whose `epoch_hash` equals anchor `k-1`’s hash.
- This guarantees a stable, globally-known PoW target and mem_kib for the entire epoch and avoids mid-epoch parameter ambiguity.

### PoW details (consensus-critical)
- Argon2id parameters: `mem_kib` from previous anchor, `lanes = 1`, `time_cost = 1` (via `Params::new(mem_kib, 1, 1, None)`).
- Salt: unkeyed `BLAKE3(header)` truncated to 16 bytes (binds PoW to the exact header).
- Difficulty rule: first `difficulty` bytes of `pow_hash` must be zero.

### Retargeting
- At `config.epoch.retarget_interval`, difficulty and `mem_kib` are recalculated from recent anchors to target `target_coins_per_epoch`.
- Difficulty adjusts by ±1 byte step (bounded to [1,12]). `mem_kib` adjusts with a clamped ratio and is bounded by `[min_mem_kib, max_mem_kib]`.

### Data model and storage
RocksDB with column families (CF):
- `epoch`: epoch number → `Anchor` and a `latest` pointer.
- `anchor`: anchor hash → `Anchor` (reverse lookup).
- `coin_candidate`: indexed by prefix key `epoch_hash || coin_id` → `CoinCandidate` (includes `pow_hash`; efficient prefix iteration per epoch).
- `coin`: confirmed (selected) coin_id → `Coin` (no `pow_hash`).
- `epoch_selected`: key `epoch_num (LE 8 bytes) || coin_id` → empty (index of selected per epoch).
- `epoch_leaves`: epoch_num → `Vec<[u8;32]>` of sorted leaf hashes (speeds proof building).
- `transfer`: coin_id → `Transfer` (marks coin spent).
- `wallet`: encrypted wallet blob.

Production tuning is applied (WAL-based durability, larger buffers, moderate compaction, increased file limits). Writes rely on WAL instead of per-write fsync; batch writes are used for epoch finalization.

### Network and gossip
Transport is QUIC (libp2p). Gossip topics:
- `unchained/anchor/v1` – anchors
- `unchained/coin/v1` – coin candidates
- `unchained/tx/v1` – transfers
- Requests: `epoch_request`, `coin_request`, `latest_request`, `coin_proof_request`, `coin_proof_response`

Validation at receipt:
- Anchors: structure, cumulative_work, parent existence (or buffered as orphan), adopt if better chain.
- Coins: recompute PoW with consensus params from referenced anchor, check difficulty, check coin ID (validate `CoinCandidate`).
- Transfers: check coin exists and unspent; signature (Dilithium3) matches coin creator; recipient non-zero.

Gossipsub: strict validation mode, mesh tuned conservatively, no flood publish.

Sync:
- A background task keeps `highest_seen_epoch` and requests missing epochs in parallel with a semaphore cap.
- Orphan anchors are buffered and processed once parents arrive; buffer length is capped and exported to metrics.

### Mining
- Miner subscribes to anchors, waits until synced, then mines for the tip’s next epoch using the anchor’s `difficulty` and `mem_kib` (lanes=1).
- On success, the coin is stored as a candidate under key `epoch_hash || coin_id`, gossiped, and the current mining loop ends.
- Progress logs are throttled to reduce noise.

### Finalization and selection
- Every `config.epoch.seconds`, the epoch manager:
  - Collects candidates by prefix scan from `coin_candidate` for the previous anchor hash.
  - Sorts by PoW hash ascending (tie-break by `coin_id`) and truncates to `max_coins_per_epoch`.
  - Computes `merkle_root`, writes the new `Anchor` and updates `latest`.
  - Commits selected candidates as confirmed `Coin` (no `pow_hash`) into `coin`, writes `epoch_selected` index, stores sorted leaves into `epoch_leaves`.
  - Prunes old candidates by deleting all `coin_candidate` entries whose prefix does not match the current epoch’s parent.

### Proofs
- A coin is independently verifiable with a certificate `{coin, anchor, merkle_proof}`. Leaf = BLAKE3(coin_id). Proof order encodes sibling position.
- Build-time: Merkle utilities in `src/epoch.rs` and pre-stored `epoch_leaves` speed proof building.
- Request/response: `coin_proof_request`/`coin_proof_response` gossip topics.


### Wallet and security
- address = BLAKE3(public key) (domain-keyed) → 32-byte `Address`.
- At-rest encryption: XChaCha20-Poly1305, key derived via Argon2id with strong parameters (default: 256 MiB, time_cost=3, lanes=1); keying material is wiped after use.
- Non-interactive mode requires `WALLET_PASSPHRASE` (fails fast if missing). Interactive uses hidden prompt.
- Peer identity is persisted in `peer_identity.key` and set to `0600` permissions on Unix.

### Configuration (selected keys)
- `net.listen_port`, `net.public_ip`, `net.bootstrap[]`
- `p2p.max_validation_failures_per_peer`, `peer_ban_duration_secs`, `rate_limit_window_secs`, `max_messages_per_window`
- `storage.path`
- `epoch.seconds`, `epoch.target_leading_zeros`, `epoch.target_coins_per_epoch`, `epoch.max_coins_per_epoch`, `epoch.retarget_interval`
- `mining.enabled`, `mining.mem_kib`, `mining.min_mem_kib`, `mining.max_mem_kib`
- `metrics.bind`


### File guide (selected)
- `src/main.rs` – CLI entry, service orchestration, proof server
- `src/epoch.rs` – `Anchor`, Merkle utilities, epoch manager (selection, finalization)
- `src/miner.rs` – miner loop (Argon2id lanes=1, difficulty)
- `src/network.rs` – libp2p QUIC + gossip, validation, sync, proof service
- `src/storage.rs` – RocksDB store, CF layout, candidate prefix keys, leaves storage
- `src/transfer.rs` – transfers, signatures (Dilithium3), validation/apply
- `src/wallet.rs` – encrypted wallet, passphrase rules, UTXO helpers

