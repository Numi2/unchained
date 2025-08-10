# unchained

Post-quantum, epoch-based blockchain with Argon2id PoW, Dilithium3 signatures, and Kyber768-secured RPC.

every coin is its own object, and time is the chain.

## Key features

- Epoch finality; fork choice = highest cumulative work (tie-break by height)
- Memory-hard PoW (Argon2id, lanes=1); auto difficulty + memory retargeting
- Anchor commitments include: selected coin set, transfers, per-coin work Merkle, retarget params, and cumulative work
- PQ networking: Kyber768 KEM + AEAD (AES-GCM-SIV) for encrypted RPC; gossipsub carries IDs only
- Transport-layer PQ for P2P: QUIC over rustls 0.23 with `aws-lc-rs` + `prefer-post-quantum` (ML‑KEM hybrids when supported);
  gossip remains announcements-only and carries no sensitive payloads
- Verifiable light clients: Merkle proofs for coins and per-coin work
- Probabilistic verification mode: sample 690 coins to detect 1% fraud with 99.9% confidence
- RocksDB storage (CFs) with proof-friendly indices; Prometheus metrics
- Canonical compact-target encoding and validation (Bitcoin-style nBits): anchors must use normalized form

## Anchor structure (v4)

`Anchor { num, hash, merkle_root, transfers_root, work_root, target_nbits, mem_kib, t_cost, coin_count, cumulative_work }`

- `hash` = BLAKE3("unchained/anchor/v4", merkle_root, transfers_root, prev_hash?, work_root, target_nbits, mem_kib, t_cost, coin_count, cumulative_work)
- `work_root` = Merkle over leaves `BLAKE3("workleaf", coin_id, work_value)`; internal nodes domain-separated `"worknode"`

## Quickstart

```bash
cargo build --release
cargo run --release -- mine
```

- Generates wallet on first run and starts networking. Configure via `config.toml`.

Peer ID:
```bash
cargo run --release -- peer-id
```

## Networking

- QUIC transport; PQ TLS negotiation preferred (rustls `prefer-post-quantum` with `aws-lc-rs` provider).
  Falls back to classical when a peer doesn’t support PQ; no protocol changes required.
- PQ handshake (Dilithium3 + Ed25519 cross-sign) on `unchained/auth/v1`
- Gossip: announcements only (anchor {num,hash}, coin {epoch_hash,coin_id}, transfer {tx_id})
- RPC methods: `LatestAnchor`, `EpochSummary(n)`, `EpochSelectedIds(n)`, `Coin(id)`, `CoinProof(id)`
  - Full validation path: fetch `EpochSummary` then recompute all commitments
  - Probabilistic path: fetch `EpochSelectedIds`; recompute `merkle_root`; sample 690 coins; verify inclusion and per-coin work proofs against `work_root`

RPC response authenticity (client-side):
- Verify `ServerHelloUnsigned` signatures `sig_ed25519` and `sig_dilithium` against pinned server keys learned during `TOP_AUTH`.
- Enforce binding: `local_peer_id` = remote peer, `remote_peer_id` = local peer, `suites` = `PINNED_SUITES`, `expiry` is fresh.
- Enforce key equality: `ed25519_pk` and `dilithium_pk` in `ServerHelloUnsigned` must equal pinned keys; reject on mismatch.
- Check `server_hello.unsigned.kyber_ct` equals outer `kyber_ct` before decryption.

## Storage layout

Column families:
- `epoch`, `anchor`, `coin`, `coin_candidate`, `transfer`, `tx_pool`
- `epoch_selected` (selected coin IDs), `epoch_leaves` (sorted coin leaf hashes)
- `epoch_work_leaves` (sorted per-coin work leaf hashes), `epoch_transfers`
- `wallet`, `replay`, `head`

## Security

- Dilithium3 signatures for transfers and node auth; Kyber768 for RPC key exchange.
- P2P transport: rustls 0.23 + `aws-lc-rs` with `prefer-post-quantum` enabled to negotiate ML‑KEM hybrids on QUIC
  when supported by both peers (graceful fallback otherwise).
- RPC AEAD keys derive per-request subkeys from transcript masters using `(request_id, dir)`; nonces derive from Kyber ciphertexts. Invariants: monotonic `request_id` per stream; fresh Kyber ciphertext per request.
- Server authenticity on responses: dual-signature verification against pinned keys; peer-ID/suite/expiry/ct binding checks prior to AEAD open.
- PoW validation: Argon2id with salt = prev_anchor_hash (first 16 bytes), lanes=1, t_cost=1.
- Compact-target (nBits) normalization enforced: exponent in [1,32], mantissa high-bit cleared; anchors must be canonical; emission normalized at genesis/retarget.
- Anchor pre-validation before persistence/broadcast; metrics on rejection.
- Encrypted at-rest keys; wallet/node identities use Argon2id + XChaCha20-Poly1305.

### Limits
- Request cap: 128 KiB; Response cap: 4 MiB (anchors/proofs). Caps enforced in codec read/write.

## Config highlights (`config.toml`)

- `net`: listen port, bootstrap peers, sync timeout
- `epoch`: seconds per epoch, target coins, retarget interval (compact-target difficulty; `target_nbits` in anchors)
- `mining`: mem_kib bounds, enabled flag
- `metrics`: bind address (`127.0.0.1:9100`)
- `storage`: database path

## Ops

- Headless env var: `QUANTUM_PASSPHRASE`.
- Proof server is loopback-only by default; front with TLS reverse proxy for external access
- Monitor Prometheus metrics for health and sync state

## Quick commands

```bash
# Build & run
cargo build --release
cargo run --release -- mine                       # start node (networking); mining per config

# Show peer ID / multiaddr
cargo run --release -- peer-id

# Ask a proof for a coin (verifies locally)
cargo run --release -- proof --coin-id <hex32>

# Serve HTTP proof endpoint (loopback only)
cargo run --release -- proof-server --bind 127.0.0.1:9090

# Metrics (default)
curl -s http://127.0.0.1:9100/ | head

# Edit configuration
$EDITOR config.toml   # tune net.listen_port, epoch.seconds, mining.mem_kib, epoch.retarget_interval

# Database path (resolved to absolute in main)
ls -la ~/.unchained/unchained_data

# Sampling target (probabilistic)
# Detect 1% cheating with 99.9% confidence: n >= ln(1-0.999)/ln(1-0.01) ≈ 690
```

## Architecture (overview)

```mermaid
flowchart TD
  subgraph P2P
    GS[Gossipsub (IDs only)]
    RPC[Request/Response (Kyber768 + AEAD)]
  end

  NET[Network]:::node
  EM[Epoch Manager]:::node
  ST[(RocksDB CFs\nepoch, anchor, coin,\nepoch_selected, epoch_leaves,\nepoch_work_leaves, epoch_transfers)]:::store
  MINER[Miner]:::node
  METRICS[Prometheus]:::io
  WALLET[Wallet]:::node

  GS --> NET
  RPC --> NET
  NET --> EM
  EM --> ST
  EM --> METRICS
  EM --> GS
  MINER --> GS
  WALLET --> GS

  subgraph AnchorCommit[v4 Anchor Commitments]
    MR[merkle_root]
    TR[transfers_root]
    WR[work_root (per-coin work Merkle)]
    RT[target_nbits, mem_kib, t_cost]
    CNT[coin_count]
    CW[cumulative_work]
  end

  AnchorCommit --> EM

  classDef node fill:#eef,stroke:#446,stroke-width:1px;
  classDef store fill:#efe,stroke:#484,stroke-width:1px;
  classDef io fill:#fee,stroke:#844,stroke-width:1px;
```