# unchained

A fair, private, and post-quantum blockchain. We keep it simple: memory-hard PoW to mint coins, anchors to finalize epochs, BLAKE3 commitments for verifiability, and post-quantum signatures across the board.

## Ethos
- **Fairness**: Argon2id PoW (memory-hard) levels the playing field. Deterministic selection per epoch prevents lottery antics. Mempool rules are fee-less and resource-bound.
- **Privacy**: Optional post-quantum ring spends hide the real input among decoys. Linkability tags prevent double-spends without sacrificing anonymity.
- **Quantum safety**: Transfers use Dilithium3. Hash/commitments use BLAKE3-256. Symmetric crypto sticks to 256-bit. Transport can go hybrid PQ as stacks mature.

## What’s inside (high-level)
- Epochs with anchors: each anchor commits to selected coin IDs and to a `transfers_root` of accepted transfers for that epoch. Fork-choice is cumulative work.
- Coins via PoW: Argon2id(header, mem_kib, lanes=1) at epoch params. Coin IDs are BLAKE3 over `(epoch_hash, nonce, creator_address)`.
- Transfers (public): multi-hop spends with prev-hash links; atomic append to per-coin history; finalized by inclusion in anchors.
- Transfers (private): ring-signature spends (LLRS backend pluggable; mock present). Default ring size = 5 (1 real + 4 decoys). Real input mixed with decoys; linkability tags enforce one-spend.
- Proofs: Merkle proofs for coins; hash-list proofs for ring transfers.
- Storage: RocksDB with column families for coins, candidates, anchors, transfer history/tips, ring outputs/tags, per-epoch transfer indexes.

## Commands (CLI)
- Mine (default):
  - `cargo run --release --bin unchained` or `-- mine`
- Show peer id:
  - `-- peer-id`
- Request and verify a coin proof (gossip-backed):
  - `-- proof --coin-id <hex32>`
- Serve a local proof API (HTTP):
  - `-- proof-server --bind 127.0.0.1:9090`
    - GET `/proof/<coin_id_hex>` → coin inclusion against epoch Merkle root
    - GET `/ring/<tx_hash_hex>` → ring transfer inclusion against `transfers_root`
- Send public transfers (multi-hop UTXO-style):
  - `-- send --to <addr_hex32> --amount <u64>`
- Send private ring transfer (demo, spends a specific owned output):
  - `-- ring-send --to <addr_hex32> --output-id <hex32>`
- Inspect balance/history:
  - `-- balance`, `-- history`
- Rebuild ring state after a reorg (deterministic replay):
  - `-- rebuild-ring`

## API (HTTP)
- `GET /proof/<coin_id_hex>`: returns coin proof `{ ok, response: { coin, epoch, merkle_root, proof_len } }`.
- `GET /ring/<tx_hash_hex>`: returns ring inclusion `{ ok, response: { tx_hash, epoch, transfers_root, proof_len } }`.
- Auth: optional `PROOF_SERVER_TOKEN` → send `x-auth-token` header.

## Transport & identity (pragmatic PQ posture)
- QUIC/TLS gives confidentiality; we run with modern TLS defaults (PQ-hybrid when provider supports it) and keep classical fallback for interop.
- Application-layer PQ identity proof: on connect, peers exchange a Dilithium3-signed session binding (PeerId || nonce). We verify and cache; optional strict mode drops peers without a valid PQ proof.
- Config: `net.require_pq_identity = true` to enforce strict mode (default false).

## Data model (selected CFs)
- `epoch`: `epoch_num` → Anchor; `latest` pointer
- `anchor`: `anchor_hash` → Anchor
- `coin_candidate`: `epoch_hash || coin_id` → candidate (with pow_hash)
- `coin`: `coin_id` → Coin
- `epoch_selected`: `epoch_num || coin_id` → index
- `epoch_leaves`: `epoch_num` → sorted coin leaf hashes
- `transfer`: `coin_id || seq` → Transfer (history)
- `transfer_tip`: `coin_id` → { last_hash, last_seq }
- `transfer_epoch`: `transfer_hash` → { transfer, epoch_num }
- `tx_mempool`: pending transfers (public + ring)
- `outputs`: `output_id` → RingOutput { pubkey, epoch }
- `ring_tag`: `link_tag` → epoch (spent)
- `epoch_ring_transfers`: `epoch_num` → sorted list of accepted ring tx hashes
- `ring_tx`: `tx_hash` → RingTransfer (for rebuilds)
- `addr_utxo`: `address || output_id` → empty (index of owned outputs)
- `addr_transfers`: `address || epoch || tx_hash` → empty (index of received transfers)

## Finality & consensus
- Anchors commit to both `merkle_root` (coins) and `transfers_root` (accepted transfers). Nodes recompute both deterministically and reject mismatches.
- Inclusion finalizes spends; reorgs trigger deterministic replay to rebuild state.

## Privacy mechanics (ring spends)
- Build a ring of size 5 (1 real + 4 decoys), stratified decoy selection.
- Sign with a linkable ring signature (LLRS backend). The included mock uses Dilithium3 only for scaffolding; replace with a vetted LLRS for production.
- Store a linkability tag (key image analog) to prevent double-spends; anchors include the transfer hash in `transfers_root` for verifiability.

## Feature flags
- `ring_mock` (default): development mock for ring verification.
- `llrs_ffi`: enable real lattice-based LRS via FFI (e.g., Raptor). Requires linking an audited C library that exposes the expected symbols.

## Mempool & DoS
- Fee-less, deterministic inclusion policy. One spend per coin/link_tag per epoch; conflicts resolved by lowest hash.
- Caps and TTLs for mempool; optional Argon2id stamp (configurable) to raise spam cost without fees.

## Build & run
```bash
cargo build --release
cargo run --release --bin unchained -- --config config.toml
```
- First run generates an encrypted wallet; set `WALLET_PASSPHRASE` for headless.
- Metrics are served (Prometheus) per `config.toml`.

## Security posture
- Signatures: Dilithium3 for public spends; LLRS for ring spends (pluggable). No classical-only signatures in consensus.
- Hashing: BLAKE3-256 everywhere. Symmetric: 256-bit keys (Grover-safe margin).
- Transport: QUIC/libp2p; PQ-hybrid confidentiality where supported. Application-layer Dilithium3 identity proof available; `net.require_pq_identity` can enforce it.

## Roadmap
- Swap mock LLRS for audited lattice-based ring signatures.
- Per-address indices for faster wallet queries without scanning.
- Richer policy knobs for mempool and ring decoy selection.