## Unchained: Epoch-based, PoW-minted, PQ-secure blockchain

### Goal and high-level model
Unchained divides time into fixed-length epochs. Miners generate self-contained coins via memory-hard PoW during an epoch. At the epoch boundary the network finalizes an anchor that commits to the set of selected coins via a Merkle root. Each coin can be verified independently using its epoch anchor and a Merkle proof, enabling light verification and efficient sync.

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
- Proof server: async HTTP (Hyper) endpoint `GET /proof/<coin_id_hex>` with optional `x-auth-token` auth and per-IP rate limiting. It requests the proof on gossip, waits for response (timeout), verifies, and returns JSON `{ ok, response }`. Default bind `127.0.0.1:9090`.

### Wallet and security
- Wallet uses Dilithium3 keys; address = BLAKE3(public key) (domain-keyed) → 32-byte `Address`.
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

Notes:
- Unknown config keys are warned and ignored. If `storage.path` is relative, it resolves to `${HOME}/.unchained/unchained_data`.

### Metrics (Prometheus)
- `unchained_peer_count` (gauge) – libp2p peers
- `unchained_epoch_height` (gauge) – latest epoch
- `unchained_candidate_coins` (gauge) – in-epoch buffer size (local)
- `unchained_selected_coins` (gauge) – selected count at finalization
- `unchained_orphan_buffer_len` (gauge) – buffered orphan anchors
- `unchained_coin_proofs_served_total` (counter)
- `unchained_coin_proof_latency_ms` (histogram)
- `unchained_validation_failures_anchor_total` (counter)
- `unchained_validation_failures_coin_total` (counter)
- `unchained_validation_failures_transfer_total` (counter)
- `unchained_db_write_failures_total` (counter)
- `unchained_pruned_candidates_total` (counter)
- `unchained_selection_threshold_u64` (gauge)

### CLI
- `unchained --mine` – start mining (or enabled by config)
- `unchained --proof --coin-id <hex32>` – request and verify a proof; blocks up to 30s
- `unchained --proof-server --bind <addr:port>` – start HTTP proof API (default `127.0.0.1:9090`); set `PROOF_SERVER_TOKEN` for simple auth
- `unchained --send --to <addr_hex32> --amount <u64>` – send transfers (1-value coins)
- `unchained --balance` – display wallet balance
- `unchained --history` – display wallet transfer history

### Validation rules (non-obvious, consensus-critical)
- PoW lanes are fixed to 1 in both mining and validation; any deviation is invalid.
- Difficulty is leading zero bytes (coarse). All nodes must treat difficulty as byte count.
- Coin ID excludes `pow_hash` and only depends on `(epoch_hash, nonce, creator_address)`.
- A coin binds to the previous anchor’s hash, not the new anchor.

### Performance considerations
- Candidate CF uses prefix keys for O(prefix) scans and pruning by prefix.
- `epoch_leaves` stores sorted leaves for faster proofs.
- RocksDB tuned for throughput: WAL-based durability, higher buffers, fewer fsyncs, moderate compaction.

### Security and DoS resistance
- Gossip-level validation is strict in code paths; rate limiting and per-peer failure scoring used.
- Proof request deduplication guards against spam; HTTP API offers header-token auth and IP rate limiting.
- Wallet passphrase handling is safe for headless deployments.

### Limitations and roadmap
- Difficulty byte-steps are coarse; future work may switch to target-based difficulty for finer control.
- Transfers currently allow only the first spend per coin (no chain of spends or fees yet). A UTXO fee market and multi-hop spend history are natural extensions.
- Pubsub validation can be hardened further with stricter modes and quotas per topic and byte rate.
- Additional metrics: selection threshold (Nth PoW hash), DB latencies, full mempool stats (if implemented).

### File guide (selected)
- `src/main.rs` – CLI entry, service orchestration, proof server
- `src/epoch.rs` – `Anchor`, Merkle utilities, epoch manager (selection, finalization)
- `src/miner.rs` – miner loop (Argon2id lanes=1, difficulty)
- `src/network.rs` – libp2p QUIC + gossip, validation, sync, proof service
- `src/storage.rs` – RocksDB store, CF layout, candidate prefix keys, leaves storage
- `src/transfer.rs` – transfers, signatures (Dilithium3), validation/apply
- `src/wallet.rs` – encrypted wallet, passphrase rules, UTXO helpers
- `src/metrics.rs` – Prometheus registry and gauges/counters

### Deployment notes
- Provide `WALLET_PASSPHRASE` in the environment for headless nodes; secure file permissions.
- Expose QUIC port and optionally the proof API port; protect the proof API via `PROOF_SERVER_TOKEN` or reverse proxy auth.
- Use durable disks for `storage.path` and monitor metrics for health. If `storage.path` is relative, state is stored at `${HOME}/.unchained/unchained_data`.


