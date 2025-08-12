# Unchained: An Epoch-First, Memory-Hard, Post-Quantum Blockchain with Merkle-Anchored Minting and Stealth Transfers

## Abstract
We present Unchained, a permissionless blockchain that couples memory-hard proof-of-work with post-quantum (PQ) cryptography and an epoch-first issuance model. Time is divided into fixed-length epochs; miners submit coin candidates throughout an epoch using Argon2id. At the epoch boundary, the network finalizes an anchor that commits to up to N selected coins via a Merkle root, enabling independent verification and efficient synchronization. Ownership is tracked with Dilithium3 signatures; receivers obtain privacy via Kyber768-based stealth receiving with one-time keys. Unchained uses libp2p over QUIC for gossip and exposes a proof service and Prometheus metrics for operability. We formalize the consensus rules, analyze security under classical and near-term quantum adversaries, discuss DoS and reorg resilience, and present an implementation in Rust with RocksDB-backed storage. We outline an evaluation methodology and identify limitations and future work, including more granular difficulty and multi-hop spend chains.

## 1 Introduction
Classical blockchains rely on ECDSA and SHA-family hashing, which risk long-term breakage or migration friction under quantum advances. Concurrently, commodity GPUs and ASICs skew mining economics toward compute-bound PoW. Unchained addresses both concerns by:
- adopting PQ primitives (Dilithium3 signatures; Kyber768 KEM for stealth receiving),
- employing memory-hard PoW (Argon2id) to raise the cost of specialized hardware advantages,
- structuring consensus around time-bucketed epochs whose anchors commit to a deterministic, bounded mint set.

This design yields self-contained, independently verifiable coins through anchor-committed Merkle proofs, enabling light verification and fast sync while preserving a simple PoW security model. Our contributions are:
- a formalization of epoch-first issuance with deterministic top-N coin selection,
- a concrete, implementable consensus and storage design with RocksDB and libp2p QUIC gossip,
- a PQ end-to-end wallet and transfer scheme with stealth receiving and blinded nullifiers,
- an implementation and operations interface (HTTP proof server, Prometheus metrics) suitable for deployment and study.

## 2 Background and Related Work
- Proof-of-Work and memory hardness: Bitcoin’s SHA-256 PoW is compute-bound. Argon2id introduces tunable memory cost to penalize specialized compute without proportional memory bandwidth. Memory-hard PoW has been explored for ASIC resistance and fairness.
- Post-quantum cryptography: Lattice-based schemes such as CRYSTALS-Dilithium and Kyber are NIST-selected standards for signatures and KEM, respectively. They mitigate Shor’s algorithm threats for ECDSA and DH-based schemes.
- Merkle trees and SPV: Inclusion proofs enable stateless or light clients. Anchoring selected coin IDs yields compact certificates for independently verifiable coins.
- Privacy and stealth: One-time key derivation and KEM-based envelopes have been used to unlink receivers from public keys while enabling selective decryption by intended recipients.

## 3 Threat Model
We assume a partially synchronous network with Byzantine adversaries who can:
- DoS by flooding gossip, send malformed messages, or amplify proof requests;
- attempt double-spends via conflicting transfers or reorgs;
- mine with disproportionate resources and attempt censorship;
- run quantum-capable adversaries able to break classical signatures but not PQ schemes.
We assume standard cryptographic hardness for Dilithium3, Kyber768, BLAKE3 collision resistance, and Argon2id preimage resistance with configured memory costs. Adversaries cannot break AEAD (XChaCha20-Poly1305) for encrypted wallets or AES-GCM-SIV for stealth envelopes.

## 4 System Overview
Unchained divides time into epochs of configurable length. During epoch k, miners generate coin candidates bound to the previous anchor’s hash (anchor k−1). At epoch end, nodes select up to N coins with the smallest PoW hashes, compute a Merkle root of the selected coin IDs, and finalize anchor k. Each confirmed coin is then independently verifiable with {coin, anchor, Merkle proof}.

- Networking: libp2p QUIC transports gossip topics for anchors, coin candidates, transfers/spends, and proof requests/responses. Validation is strict and rate-limited.
- Storage: RocksDB column families store anchors, coin candidates, confirmed coins, transfers, nullifiers, and per-epoch sorted Merkle leaves for efficient proof construction.
- Wallet: Dilithium3 keys; address = domain-separated BLAKE3(public_key). Wallets are encrypted at rest (XChaCha20‑Poly1305) with Argon2id-based passphrase derivation.
- Stealth receiving: Receivers publish a Kyber768 public key bound to their address. Senders encrypt a one-time Dilithium secret key via Kyber; recipients decrypt to spend without linking long-term keys.

## 5 Consensus and Data Structures
### 5.1 Anchors
An anchor A_k summarizes epoch k:
- fields: number, hash, merkle_root, difficulty (byte prefix), coin_count, cumulative_work, mem_kib;
- hash: BLAKE3(merkle_root || prev_hash?);
- fork choice: prefer higher cumulative_work, tie-break by higher epoch.

### 5.2 Coin Candidates and IDs
- Header: epoch_hash (prev anchor hash), miner_address, nonce.
- PoW: Argon2id with lanes=1, mem_kib derived from previous anchor; salt = truncated BLAKE3(header).
- Difficulty: consensus rule is first d bytes of pow_hash must be zero (coarse step); selection ranks by pow_hash as an integer, ascending; ties broken by coin_id.
- Coin ID: BLAKE3(epoch_hash, nonce, creator_address); independent of pow_hash.

### 5.3 Deterministic Selection and Merkle Commitment
At finalization:
- gather all valid candidates bound to epoch_hash;
- sort by pow_hash ascending (tie coin_id) and keep up to max_coins_per_epoch;
- compute merkle_root over sorted leaf hashes BLAKE3(coin_id);
- commit selected coins, persist epoch_leaves for proof generation, prune old candidates.

### 5.4 Retargeting and Memory Tuning
Every retarget_interval epochs, difficulty adjusts by ±1 byte within bounds [1,12]; mem_kib adjusts within [min_mem_kib, max_mem_kib] with clamped ratios. This targets a configured expected selection count.

## 6 Transfers, Stealth Receiving, and Nullifiers
Transfers move ownership of 1-value coins. The V2 spend format includes:
- coin_id, root (epoch Merkle root), proof (inclusion), to = {one_time_pk, kyber_ct, enc_one_time_sk, enc_sk_nonce},
- commitment = BLAKE3(to.canonical_bytes()),
- nullifier = BLAKE3("nullifier_v2" || spend_sk || coin_id),
- sig = Dilithium3 over auth_bytes = root || nullifier || commitment || coin_id.
Validation checks coin existence under root, verifies the Merkle proof, confirms unseen nullifier, and verifies the signature under the current owner’s one-time public key.

## 7 Networking, Validation, and Sync
- Gossip topics: anchors, coin candidates, transfers, spends; requests: epoch, coin, latest, proof.
- Validation: strict structure checks and consensus recomputation on receipt; per-peer failure scoring and rate limiting.
- Sync: background range requests for missing anchors with bounded parallelism; orphan buffer for out-of-order anchors; proofs fetched on demand via gossip or HTTP.
- Proof server: HTTPS API GET /proof/<coin_id_hex> with optional header-token auth; verifies proofs before responding.

## 8 Storage Layout and Proofs
RocksDB column families include epoch, anchor, coin_candidate (prefixed by epoch_hash || coin_id), coin (confirmed), epoch_selected index, epoch_leaves (sorted leaves), transfer, spend/nullifier. Proofs are Merkle paths over BLAKE3 leaves; proof order encodes sibling positions.

## 9 Security Analysis
- Double-spend resistance: blinded nullifiers prevent reuse; anchors commit inclusion; fork choice resolves conflicts.
- Reorgs: coins are spendable only after inclusion under an anchor; short reorgs may invalidate unconfirmed spends; wallets should reference the root at spend time.
- DoS: rate limits at gossip and HTTP layers; per-peer failure scoring; bounded orphan buffers.
- Privacy: stealth receiving hides receiver linkability; one-time keys prevent reuse correlation; metadata leakage limited to proof fetches, which can be proxied.
- PQ resilience: signatures (Dilithium3) and KEM (Kyber768) mitigate quantum attacks on ECDSA/DH; BLAKE3 and Argon2id have no known catastrophic quantum speedups beyond Grover-like quadratics, which are impractical given memory binding.

## 10 Performance Considerations
- Candidate indexing with prefix keys supports O(prefix) scans per epoch and pruning by prefix.
- Persisted epoch_leaves accelerates proof generation.
- WAL-based durability and batched writes reduce fsync overhead.
- Gossipsub mesh parameters are tuned to avoid publication floods.

## 11 Implementation Overview
Unchained is implemented in Rust. Key modules: `src/epoch.rs` (anchors, Merkle, finalization), `src/miner.rs` (Argon2id PoW miner), `src/network.rs` (libp2p QUIC + gossipsub, validation, sync, proof service), `src/storage.rs` (RocksDB column families and CRUD), `src/transfer.rs` (transfers and validation), `src/wallet.rs` (encrypted wallet and stealth), `src/metrics.rs` (Prometheus), `src/main.rs` (CLI, proof server).

## 12 Evaluation Methodology
We propose:
- Throughput/latency: measure epoch finalization time, proof latency distribution, and transfer confirmation delay across varying epoch.seconds.
- Resource usage: CPU/memory per PoW attempt vs mem_kib; miner scalability with workers; DB write/read latencies during finalization.
- Network robustness: peer churn and partition experiments; orphan buffer behavior.
- Security stress: adversarial malformed inputs; proof request amplification; nullifier collision searches (infeasible but instrumentation).
- Retarget dynamics: convergence of selected coin count to target; oscillation under variable miner participation.

## 13 Limitations and Future Work
- Difficulty granularity: replace leading-zero byte rule with target-based difficulty for finer control and more accurate cumulative work accounting.
- Spend chains and fees: enable multi-hop spends with prev_tx references and fee markets to discourage spam.
- Stronger pubsub quotas and per-topic byte-rate enforcement.
- Formal verification of consensus-critical paths and constant-time reviews for key handling.

## 14 Ethical and Operational Considerations
- Proof endpoints should employ authentication if exposed; bind defaults are localhost.
- Wallet passphrases should be provisioned via environment for headless nodes and never logged.
- Prometheus endpoints should not be publicly exposed without ACLs.

## 15 Conclusion
Unchained combines PQ cryptography, memory-hard PoW, and epoch-anchored coin selection to realize a verifiable, scalable PoW chain with practical deployability. The architecture preserves simple security assumptions while enabling independent coin verification and privacy-preserving receiving. The reference implementation demonstrates viability and provides a platform for further research on memory-hard PoW economics and PQ-ready blockchain systems.