# Unchained Whitepaper (Deployment-Ready)

## Executive Summary
Unchained is a post-quantum, memory-hard proof-of-work blockchain. Time is divided into epochs; at each epoch boundary, the network finalizes an anchor that commits to the set of selected coins via a Merkle root. Coins are independently verifiable with a proof, enabling light clients and efficient sync. Ownership is tracked with Dilithium3 signatures. Receivers use Kyber768-based stealth addresses for privacy by default. The stack is implemented in Rust, uses libp2p over QUIC for networking, and RocksDB for storage. A built-in proof server and Prometheus metrics support production operations.

- Security: memory-hard Argon2id PoW; Dilithium3 signatures; Kyber768 stealth; BLAKE3 hashing.
- Predictable issuance: deterministic top-N coin selection per epoch; anchor commits to the selected set.
- Operational readiness: CLI, HTTP proof API, metrics, sensible defaults, environment-based secrets.

## Problem and Approach
- Classical signatures (ECDSA) and DH-based stealth are vulnerable to quantum attacks. Unchained avoids legacy curves by using NIST-selected PQ schemes.
- Compute-bound PoW favors specialized hardware. Memory-hard Argon2id increases the cost of gaining an advantage without proportional memory bandwidth.
- Syncing full transaction history is expensive. Unchained’s per-epoch Merkle commitment yields compact proofs so clients fetch only what they need.

## Architecture Overview
- Epochs: fixed-length intervals. At each epoch boundary an anchor is finalized: `hash = BLAKE3(merkle_root || prev_hash)`.
- Mining: during an epoch, miners produce coin candidates bound to the previous anchor’s hash. PoW = Argon2id with lanes=1 and epoch-committed memory.
- Selection: nodes deterministically select up to `max_coins_per_epoch` with the lowest PoW hashes and commit their IDs in a Merkle root.
- Ownership: Dilithium3 signatures prove control of coins. Nullifiers prevent double-spend.
- Stealth receiving: recipients publish a signed stealth address bundling their Dilithium address and a Kyber768 public key; senders encrypt a one-time key via Kyber.
- Networking: libp2p over QUIC; gossipsub topics for anchors, coin candidates, transfers, requests (epoch/coin/proof). Strict validation and rate limits.
- Storage: RocksDB with column families for epochs, anchors, candidates, confirmed coins, transfers/spends/nullifiers, and per-epoch sorted Merkle leaves.

## Consensus and Validation (Operator View)
- Difficulty: consensus rule checks leading zero bytes in the 32-byte PoW hash; retarget adjusts difficulty and `mem_kib` every `retarget_interval` epochs within bounds.
- Determinism: selection sorts candidates by PoW hash, tie-breaking by `coin_id`. Only selected coins are confirmed.
- Fork choice: prefer higher cumulative work; tie-break on higher epoch.
- Proofs: a coin certificate `{ coin, anchor, proof }` verifies inclusion under the Merkle root.

## Security Properties
- PQ resilience: Dilithium3 and Kyber768 mitigate quantum threats to signatures and DH/KEM. BLAKE3 + Argon2id remain robust against known quantum speedups in practical parameters.
- Double-spend resistance: nullifiers and inclusion proofs prevent reuse and fraud.
- DoS resistance: gossip validation, per-peer failure scoring, rate limiting, proof deduplication, and optional HTTP token auth.
- Privacy: default stealth receiving with one-time keys limits linkability; no long-term key reuse on-chain.

## On-Chain Objects (Simplified)
- Anchor: `{ num, hash, merkle_root, difficulty, coin_count, cumulative_work, mem_kib }`
- Coin ID: `BLAKE3(epoch_hash, nonce, creator_address)`
- Spend (V2): fields include `coin_id`, `root`, `proof`, `to{ one_time_pk, kyber_ct, enc_one_time_sk, enc_sk_nonce }`, `commitment`, `nullifier`, `sig`.

## Installation and Configuration
1) Build
```bash
cargo build --release
```
2) Configure `config.toml` (excerpt)
```toml
[net]
listen_port = 31000
bootstrap = ["/ip4/<ip>/udp/31000/quic-v1/p2p/<peer-id>"]
public_ip = "<optional-public-ip>"

[p2p]
max_validation_failures_per_peer = 10
peer_ban_duration_secs = 3600
rate_limit_window_secs = 60
max_messages_per_window = 100

[storage]
path = "data" # if relative -> ~/.unchained/unchained_data

[epoch]
seconds = 333
target_leading_zeros = 1
target_coins_per_epoch = 100
max_coins_per_epoch = 100
retarget_interval = 10

[mining]
enabled = true
mem_kib = 16192
min_mem_kib = 16384
max_mem_kib = 262144
max_memory_adjustment = 1.5

[metrics]
bind = "127.0.0.1:9100"
```
3) Run
```bash
# start node (reads mining.enabled)
cargo run --release --bin unchained

# or force mining now
cargo run --release --bin unchained -- mine
```

## Wallet, Stealth, and Transfers
- Wallet: first run prompts for a passphrase; at-rest encryption uses XChaCha20‑Poly1305 with Argon2id KDF. Non-interactive: set `WALLET_PASSPHRASE`.
- Stealth address (publish to get paid privately):
```bash
cargo run --release --bin unchained -- stealth-address
```
- Send to stealth address:
```bash
cargo run --release --bin unchained -- send --stealth <STEALTH_ADDR> --amount 1
```
- Balance and history:
```bash
cargo run --release --bin unchained -- balance
cargo run --release --bin unchained -- history
```

## Proofs and Light Verification
- Verify a coin’s inclusion proof:
```bash
cargo run --release --bin unchained -- proof --coin-id <hex32>
```
- Serve proofs to external clients (HTTPS, optional header token):
```bash
export PROOF_SERVER_TOKEN=<token>
cargo run --release --bin unchained -- proof-server --bind 127.0.0.1:9090
```
- Example client request:
```bash
curl -s -H "x-auth-token: $PROOF_SERVER_TOKEN" https://127.0.0.1:9090/proof/<COIN_ID_HEX> | jq .
```

## Networking and Peering
- Transport: QUIC over UDP; announce `public_ip` for inbound peers.
- Bootstrap: add reachable peers to `net.bootstrap` (multiaddr form).
- Firewalls: open UDP `listen_port`.

## Observability
- Prometheus metrics on `metrics.bind` (auto-increments on conflict). Notable series: `unchained_peer_count`, `unchained_epoch_height`, `unchained_selected_coins`, `unchained_coin_proofs_served_total`, `unchained_mining_*`.
- Quick check:
```bash
curl http://127.0.0.1:9100
```

## Operational Hardening Checklist
- Provide `WALLET_PASSPHRASE` via secret management; set file perms 0600 for `peer_identity.key`.
- Bind proof server to a private interface; require `PROOF_SERVER_TOKEN` or front with authenticated reverse proxy.
- Persist `storage.path` on durable disks; back up `<db>/backups/<timestamp>/`.
- Monitor peer counts, epoch height, selection counts, proof latency, and DB failures.
- Rate-limit and ban misbehaving peers (defaults provided).

## Roadmap (Forward Compatibility)
- Replace coarse leading-zero difficulty with target-based difficulty to improve work accounting and retarget stability.
- Introduce fee market and multi-hop spends (reference prev transfer), enabling richer UTXO logic.
- Harden pubsub quotas and per-topic byte-rate limits.
- Expand metrics to include selection thresholds and DB latencies.

## Summary
Unchained delivers a PQ-secure, memory-hard PoW chain with deterministic epoch-finalized issuance and privacy-by-default receiving. The implementation, CLI, proof server, and metrics make it deployable today while leaving room for iterative consensus and networking improvements.