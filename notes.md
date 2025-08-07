The core issue is that the gossipsub protocol in libp2p requires at least one peer in the mesh to publish messages. When running a single node, the miner can't broadcast newly created anchors, which stalls the mining process since the miner is waiting for the next anchor to begin mining the next epoch.

Consider changing gossipsub validation to Strict and add quotas.
Expand ProofServer to actually respond with CoinProofResponse by wiring a request to the network and awaiting a response before replying HTTP.
Tune RocksDB options for throughput/durability on the VM.
Add sync metrics for orphan buffer size and range request progress; bound orphan map by MAX_ORPHAN_ANCHORS.

### Core consensus (epoch-first, coin-lottery)
- **Epochs as time buckets**:
  - Fixed-length epochs (on-chain enforced duration).
  - Each epoch publishes an anchor committing to exactly the coins that “won” for that epoch.
- **Hard coin cap per epoch**:
  - Configured `max_coins_per_epoch` is a consensus parameter.
  - During an epoch, miners submit PoW coins; at finalization the protocol selects the top N coins (N = cap) by a deterministic score (e.g., smallest PoW hash as uint256). Others are orphaned.
  - This enforces a predictable mint rate and fairly resolves races.

### Coins and PoW (independently verifiable)
- **Coin header**:
  - Fields: `epoch_hash`, `miner_address`, `nonce`, `version`, `pow_params`.
  - Salt = blake3(epoch_hash || miner_address || nonce). Consensus-fix lanes=1.
- **PoW validity**:
  - Use target-based difficulty: `pow_hash <= target`. Work = ⌊2^256/(target+1)⌋; enables fine-grained retarget.
  - Memory-hard via Argon2id with epoch-committed `mem_kib`. Adjust slowly at retarget boundaries with strict integer math and caps.
- **Self-contained coins via certificates**:
  - Define `CoinCertificate = { coin, anchor_header, merkle_proof }`.
  - Anyone can verify a coin with just the certificate: check PoW, anchor chain-work, and inclusion proof.

### Anchor formation (finalization and proofs)
- **Anchor header**:
  - `epoch_num, prev_anchor_hash, merkle_root_coin_ids, target(nBits), mem_kib, max_coins_per_epoch, coin_count_selected, cumulative_work, epoch_start_time, epoch_duration, version`.
- **Deterministic selection**:
  - From all valid coin IDs observed in the epoch, select the N with the lowest PoW hash (ties broken by coin_id).
  - Compute the Merkle root over the selected set (sorted leaves = blake3(coin_id)).
  - Persist the selected list (or a compact commitment) so proofs can be served deterministically.
- **Finality semantics**:
  - A coin is “confirmed” only if included in the epoch anchor’s selected set. Wallets should spend only confirmed coins.
  - Reorg can invalidate inclusion; SPV spenders must reference the anchor.

### Retargeting (hit the coin budget, not just time)
- **Goal**: keep expected winners per epoch ≈ `max_coins_per_epoch`.
- **Mechanics**:
  - Difficulty (target) adjusts using LWMA/ASERT-like integer algorithm based on observed selected coin count. Clamp change per retarget to avoid oscillations.
  - `mem_kib` adjusts with wide hysteresis and strong clamps; avoid flapping. Commit both in the next epoch’s header.
- **Result**: network tends to produce only slightly more candidates than the cap; the “top N by quality” selection resolves contention fairly.

### Networking (gossip + RPC that scales)
- **Gossip topics**:
  - Coins (provisional), Anchors (final), Requests: latest anchor, specific epoch, coin proof.
- **Strict validation and quotas**:
  - Strict pubsub validation; per-peer quotas (messages/second, bytes), invalid-penalty scoring, exponential bans.
- **Proof service**:
  - Add request/response protocol to fetch a `CoinCertificate` by `coin_id` after finalization.
- **Orphan handling**:
  - Buffer out-of-order anchors; process once parents arrive; cap buffers.

### Sync (anchors-first, proof-on-demand)
- **Anchors-first**:
  - Download and verify anchor headers (PoW/chain-work); pick best chain.
  - Fetch only proofs for coins you need (wallet addresses, mempool referencing inputs).
- **Range sync**:
  - Parallel, bounded requests for epochs between local and best.
- **Reorg safety**:
  - Maintain short reorg window; rollback inclusion-dependent state if the best chain changes.

### Transfers and spends
- **Spend rules**:
  - A `Transfer` references a confirmed coin (requires inclusion proof at spend time).
  - Signature: Dilithium3 over canonical bytes; `prev_tx_hash` should refer to the last transfer (enable multi-hop spend chains), not just `coin_id`.
- **Mempool**:
  - Accept only transfers that spend confirmed coins and pass sig/ownership checks.
  - Fee optional; if you keep fee-less, rate-limit and prioritize by age/size to prevent spam.

### Storage and data layout
- **Column families**:
  - `anchors`, `coin_candidates` (per-epoch, all seen), `coin_selected` (confirmed), `proof_index` (optional precomputed paths), `transfer`, `wallet`.
- **Proofs**:
  - Store per-epoch sorted leaf array (or a succinct commitment). Generate proofs on demand; cache results.
- **Reasonable RocksDB tuning**:
  - Drop extreme fsync settings; use batched writes + WAL with periodic fsyncs; expose DB health.

### Wallet and UX
- **Confirmed-only balance**:
  - Balance/UTXO set computed from `coin_selected` only.
- **Send flow**:
  - Only spend confirmed coins; include the coin’s anchor hash in the unsigned transfer so relays can quickly pre-check.
- **Security**:
  - Keep XChaCha20-Poly1305 with Argon2id KDF; require non-interactive passphrase provisioning for headless nodes.

### Observability
- **Metrics**:
  - epoch height, best hash, cumulative work, target, mem_kib, buffer size, candidate_count, selected_count, Nth-winner score threshold, peer counts, proofs served, reorg depth, DB latency.
- **Tracing**:
  - Structured logs; sampling for hot paths.

### Concrete changes from the current code
- **Consensus/validation**:
  - Replace byte-prefix difficulty with target-based checks and cumulative work calculation.
  - Commit `max_coins_per_epoch` and `mem_kib` in anchors; enforce lanes=1; remove non-consensus `lanes` from config.
- **Epoch manager**:
  - Keep buffering coin IDs, but on tick:
    - Sort by PoW hash; select top N; compute Merkle over selected; record selection; discard rest.
    - Persist per-epoch sorted leaves to enable proofs; or store a compact structure to recompute.
- **Network**:
  - Tighten pubsub validation; add RPC for coin proof retrieval; rate-limit coin candidate gossip.
- **Wallet**:
  - Only treat “selected” coins as spendable; expose confirmations tied to anchor.
- **Transfers**:
  - Upgrade `prev_tx_hash` to refer to the last transfer, enabling multi-hop chains.

Why this fits unchained’s ethos
- **Epoch-first minting with hard caps**: predictable issuance, fair competition via “top N wins” per epoch.
- **Independent coin verification**: coin + anchor + proof yields self-contained validation.
- **PQ and memory-hardness**: retained and made consensus-clear.
- **Decentralized sync**: anchors-first minimizes bandwidth; proofs are fetched only when needed.

- Defined a perfect epoch-centric design: hard per-epoch mint cap with deterministic top-N selection, anchor-committed proofs, and target-based PoW.
- Specified concrete consensus fields/rules, selection, proofs, retargeting, and reorg handling.
- Outlined exact module-level changes to reach this design while preserving your core principles.