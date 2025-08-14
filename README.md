# unchained


1. install git + anything else u might need : 

sudo apt install build-essential git curl cmake libclang-dev libssl-dev pkg-config -y

2. download + install rust: 
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

3. git clone https://github.com/Numi2/unchained.git

4. cd unchained

5. cargo build --release && cargo run --release --bin unchained mine

if u get any errors just ask AI for the commands to fix

Unchained, a permissionless blockchain. Time is divided into 222s epochs; miners submit coin candidates throughout an epoch using Argon2id. At the end of an epoch, the network finalizes an anchor that commits to up to x nr selected coins via a Merkle root, enabling independent verification and efficient synchronization. 

Ownership is tracked with Dilithium3 signatures; receivers obtain privacy via Kyber768-based stealth receiving with one-time keys. Unchained uses libp2p (quantum prefer branch) over QUIC for gossip

Post‑quantum blockchain implementation - Dilithium3 for signatures, Kyber768 for stealth receiving, BLAKE3 for hashing, Argon2id for PoW. libp2p over QUIC does the gossip (libp2p prefer pq aws). 

- Memory‑hard PoW  Argon2id; David balanced to Goliath
- End‑to‑end PQ: Dilithium3 signatures, Kyber768 for stealth, BLAKE3 throughout the merkles
- rocksdb

Nullifiers (double‑spend protection):
- v1 (legacy): BLAKE3("nullifier_v1" || coin_id || sig)
- v2 (current): BLAKE3("nullifier_v2" || spend_sk || coin_id)

## Quick start


```bash
cargo build --release
cargo run --release --bin unchained mine
```

What happens on first run:
- A wallet is created and encrypted with your passphrase
- A persistent P2P identity is generated (`peer_identity.key`)
- The node syncs, then starts mining (if enabled in `config.toml`)

Stop with Ctrl+C.

### Show your Peer ID (for peering/firewall rules)

```bash
cargo run --release --bin unchained -- peer-id
```

If `net.public_ip` is set in `config.toml`, you’ll also see your full multiaddr for others to dial.

## CLI (no surprises)

All commands accept `--config <path>` (default `config.toml`) and `--quiet-net`.

- `mine` — start mining immediately (overrides `mining.enabled`)
- `peer-id` — print local libp2p Peer ID (and multiaddr if `net.public_ip` is set)
- `stealth-address` — print your stealth receiving address (base64-url)
- `proof --coin-id <HEX>` — request and verify a Merkle proof for a coin
- `proof-server [--bind HOST:PORT]` — HTTPS server that returns proofs
- `send --stealth <ADDRESS> --amount <N>` — send to a stealth address
- `balance` — show wallet balance + address
- `history` — print simple tx history

Examples:

```bash
# Send 1 coin to a recipient’s stealth address (base64‑url string)
cargo run --release --bin unchained send --stealth <STEALTH_ADDR> --amount 1



Nullifiers (double‑spend protection):
- v1 (legacy): BLAKE3("nullifier_v1" || coin_id || sig)
- v2 (current): BLAKE3("nullifier_v2" || spend_sk || coin_id)

## Quick start


```bash
cargo build --release
cargo run --release --bin unchained mine
```

What happens on first run:
- A wallet is created and encrypted with your passphrase
- A persistent P2P identity is generated (`peer_identity.key`)
- The node syncs, then starts mining (if enabled in `config.toml`)

Stop with Ctrl+C.

### Show your Peer ID (for peering/firewall rules)

```bash
cargo run --release --bin unchained -- peer-id
```

If `net.public_ip` is set in `config.toml`, you’ll also see your full multiaddr for others to dial.

## CLI (no surprises)

All commands accept `--config <path>` (default `config.toml`) and `--quiet-net`.

- `mine` — start mining immediately (overrides `mining.enabled`)
- `peer-id` — print local libp2p Peer ID (and multiaddr if `net.public_ip` is set)
- `stealth-address` — print your stealth receiving address (base64-url)
- `proof --coin-id <HEX>` — request and verify a Merkle proof for a coin
- `proof-server [--bind HOST:PORT]` — HTTPS server that returns proofs
- `send --stealth <ADDRESS> --amount <N>` — send to a stealth address
- `balance` — show wallet balance + address
- `history` — print simple tx history

Examples:

```bash
# Send 1 coin to a recipient’s stealth address (base64‑url string)
cargo run --release --bin unchained send --stealth <STEALTH_ADDR> --amount 1

EXAMPLE: cargo run --release --bin unchained send --stealth 

Unchained, a permissionless blockchain that couples memory-hard proof-of-work with post-quantum (PQ) cryptography and an epoch-first issuance model. Time is divided into fixed-length epochs; miners submit coin candidates throughout an epoch using Argon2id. At the epoch boundary, the network finalizes an anchor that commits to up to N selected coins via a Merkle root, enabling independent verification and efficient synchronization. Ownership is tracked with Dilithium3 signatures; receivers obtain privacy via Kyber768-based stealth receiving with one-time keys. Unchained uses libp2p over QUIC for gossip

- Memory‑hard PoW  Argon2id; memory target retunes across epochs
- End‑to‑end PQ: Dilithium3 signatures, Kyber768 for stealth, BLAKE3 everywhere
- Spends don’t shout who you are: one‑time keys and blinded nullifiers (V2)
- rocksdb

Nullifiers (double‑spend protection):
- v1 (legacy): BLAKE3("nullifier_v1" || coin_id || sig)
- v2 (current): BLAKE3("nullifier_v2" || spend_sk || coin_id)

## Quick start


```bash
cargo build --release
cargo run --release --bin unchained mine
```

What happens on first run:
- A wallet is created and encrypted with your passphrase
- A persistent P2P identity is generated (`peer_identity.key`)
- The node syncs, then starts mining (if enabled in `config.toml`)

Stop with Ctrl+C.

### Show your Peer ID (for peering/firewall rules)

```bash
cargo run --release --bin unchained -- peer-id
```

If `net.public_ip` is set in `config.toml`, you’ll also see your full multiaddr for others to dial.

## CLI (no surprises)

All commands accept `--config <path>` (default `config.toml`) and `--quiet-net`.

- `mine` — start mining immediately (overrides `mining.enabled`)
- `peer-id` — print local libp2p Peer ID (and multiaddr if `net.public_ip` is set)
- `stealth-address` — print your stealth receiving address (base64-url)
- `proof --coin-id <HEX>` — request and verify a Merkle proof for a coin
- `proof-server [--bind HOST:PORT]` — HTTPS server that returns proofs
- `send --stealth <ADDRESS> --amount <N>` — send to a stealth address
- `balance` — show wallet balance + address
- `history` — print simple tx history

Examples:

```bash
# Send 1 coin to a recipient’s stealth address (base64‑url string)
cargo run --release --bin unchained send --stealth <STEALTH_ADDR> --amount 1

EXAMPLE: cargo run --release --bin unchained send --stealth ADRESSgoesHERE --amount 1

# Verify a coin’s inclusion proof by id (hex)
cargo run --release --bin unchained -- proof --coin-id <64-hex>
```

## Configuration (edit `config.toml`)

- `[net]`: P2P port, bootstrap peers, optional `public_ip` (for NAT)
- `[p2p]`: rate limits and ban windows for chatty/bad peers
- `[storage]`: database path
- `[epoch]`: epoch length, difficulty bounds, retarget tuning
- `[mining]`: Argon2id memory bounds, attempts, workers, offload
- `[metrics]`: Prometheus bind address

Notes:
- If `storage.path` is relative, the node stores data under `~/.unchained/unchained_data`
- The shipped `config.toml` is a decent starting point

## Wallet and security

- Dilithium3 wallet keys are encrypted at rest with XChaCha20‑Poly1305
- Keys come from your passphrase via Argon2id (large memory, slow to brute‑force)
- Non‑interactive mode requires `WALLET_PASSPHRASE`
- Legacy plaintext wallets (if found) are migrated to encrypted format

Env vars that matter:
- `WALLET_PASSPHRASE` — passphrase for non‑interactive runs
- `PROOF_SERVER_TOKEN` — require `x-auth-token` for the proof server
- `COIN_MIRRORING=0` — disable writing `<db>/coins/coin-*.bin`

## Stealth receiving (how to get paid privately)

1) Export your stealth address (a signed bundle that binds your normal address to your Kyber768 public key):

```bash
cargo run --release --bin unchained -- stealth-address
```

Share this base64‑url string with senders. They’ll encrypt a one‑time Dilithium key to your Kyber PK. Your wallet can decrypt it, nobody else can.

2) Senders use the CLI:

```bash
cargo run --release --bin unchained -- send --stealth <STEALTH_ADDR> --amount 1
```

The wallet will:
- Use a legacy V1 transfer once for any coin that has never moved (to establish an owner one‑time key)
- Use V2 spends thereafter (Merkle‑anchored, blinded nullifier)

## V2 spend (PQ and practical)

Fields:
- `coin_id` — 32 bytes
- `root` — epoch Merkle root
- `proof` — inclusion proof for `coin_id` leaf
- `to` — stealth output `{ one_time_pk, kyber_ct, enc_one_time_sk, enc_sk_nonce }`
- `commitment` — BLAKE3(to.canonical_bytes())
- `nullifier` — BLAKE3("nullifier_v2" || spend_sk || coin_id)
- `sig` — Dilithium3 over `auth_bytes`

Authorization bytes: `auth_bytes = root || nullifier || commitment || coin_id`

Node checks:
1) Coin exists and the epoch anchor matches `root`
2) Merkle proof verifies
3) Nullifier hasn’t been seen
4) Signature verifies under current owner’s one‑time Dilithium public key

## Network and protocol

- Transport: QUIC over UDP (libp2p)
- Gossip: gossipsub topics (anchors, coins, transfers, spends, proofs)
- TLS: rustls + aws‑lc‑rs; prefers PQ/hybrid TLS 1.3

Peer identity lives in `peer_identity.key`. Keep it if you want a stable Peer ID.

## Proof server (HTTPS)

Run a local HTTPS endpoint to fetch proofs by coin id:

```bash
cargo run --release --bin unchained -- proof-server --bind 127.0.0.1:9090
```

Optional auth: set `PROOF_SERVER_TOKEN` and send `x-auth-token` header.

Example request:

```bash
curl -s \
  -H "x-auth-token: $PROOF_SERVER_TOKEN" \
  https://127.0.0.1:9090/proof/<COIN_ID_HEX> | jq .
```

Response (example):

```json
{
  "ok": true,
  "response": {
    "coin": "…",
    "epoch": 123,
    "merkle_root": "…",
    "proof_len": 17
  }
}
```


Notables: `unchained_peer_count`, `unchained_epoch_height`, `unchained_selected_coins`, `unchained_coin_proofs_served_total`, `unchained_mining_*`.

## Data storage

- RocksDB column families: `epoch`, `coin`, `coin_candidate`, `anchor`, `transfer`, `spend`, `nullifier`, …
- Optional coin mirroring: `<db>/coins/coin-<id>.bin` (set `COIN_MIRRORING=0` to disable)
- Simple backups: `<db>/backups/<timestamp>/`

## Mining and epochs (how blocks happen)

- Time is chunked into epochs (`[epoch].seconds`)
- Miners produce coin candidates by meeting Argon2id difficulty
- Each epoch selects up to `[epoch].max_coins_per_epoch` (best PoW) and commits IDs into a Merkle root
- Difficulty and Argon2 memory adjust to aim for `[epoch].target_coins_per_epoch`

## Troubleshooting

- DB locked: don’t share `storage.path` across processes; only delete `LOCK` if the node is stopped
- No peers: add at least one good `[net].bootstrap` multiaddr; open the UDP port or set `public_ip`
- NAT: forward UDP `listen_port`; set `public_ip`
- Non‑interactive: export `WALLET_PASSPHRASE`
- Metrics port busy: it will try the next port; check logs for the new bind
- Too chatty: pass `--quiet-net`

## What makes it post‑quantum?

- Dilithium3 for signatures and addresses (no classical curves)
- Kyber768 for KEM (stealth receiving without leaking long‑term keys)
- BLAKE3 + Argon2id (fast, modern, and not obviously broken by near‑term quantum)

Net effect: you run a normal node and use normal commands, but the cryptography underneath is built for the long haul.

---

Unchained, a permissionless blockchain that couples memory-hard proof-of-work with post-quantum (PQ) cryptography and an epoch-first issuance model. Time is divided into fixed-length epochs; miners submit coin candidates throughout an epoch using Argon2id. At the epoch boundary, the network finalizes an anchor that commits to up to N selected coins via a Merkle root, enabling independent verification and efficient synchronization. Ownership is tracked with Dilithium3 signatures; receivers obtain privacy via Kyber768-based stealth receiving with one-time keys. Unchained uses libp2p over QUIC for gossip

- Memory‑hard PoW  Argon2id; memory target retunes across epochs
- End‑to‑end PQ: Dilithium3 signatures, Kyber768 for stealth, BLAKE3 everywhere
- Spends don’t shout who you are: one‑time keys and blinded nullifiers (V2)
- rocksdb

Nullifiers (double‑spend protection):
- v1 (legacy): BLAKE3("nullifier_v1" || coin_id || sig)
- v2 (current): BLAKE3("nullifier_v2" || spend_sk || coin_id)

## Quick start


```bash
cargo build --release
cargo run --release --bin unchained mine
```

What happens on first run:
- A wallet is created and encrypted with your passphrase
- A persistent P2P identity is generated (`peer_identity.key`)
- The node syncs, then starts mining (if enabled in `config.toml`)

Stop with Ctrl+C.

### Show your Peer ID (for peering/firewall rules)

```bash
cargo run --release --bin unchained -- peer-id
```

If `net.public_ip` is set in `config.toml`, you’ll also see your full multiaddr for others to dial.

## CLI 

All commands accept `--config <path>` (default `config.toml`) and `--quiet-net`.

- `mine` — start mining immediately (overrides `mining.enabled`)
- `peer-id` — print local libp2p Peer ID (and multiaddr if `net.public_ip` is set)
- `stealth-address` — print your stealth receiving address (base64-url)
- `proof --coin-id <HEX>` — request and verify a Merkle proof for a coin
- `proof-server [--bind HOST:PORT]` — HTTPS server that returns proofs
- `send --stealth <ADDRESS> --amount <N>` — send to a stealth address
- `balance` — show wallet balance + address
- `history` — print simple tx history

Examples:

```bash
# Send 1 coin to a recipient’s stealth address (base64‑url string)
cargo run --release --bin unchained send --stealth <STEALTH_ADDR> --amount 1

EXAMPLE: cargo run --release --bin unchained send --stealth 

# Verify a coin’s inclusion proof by id (hex)
cargo run --release --bin unchained -- proof --coin-id <64-hex>
```

## Configuration (edit `config.toml`)

- `[net]`: P2P port, bootstrap peers, optional `public_ip` (for NAT)
- `[p2p]`: rate limits and ban windows for chatty/bad peers
- `[storage]`: database path
- `[epoch]`: epoch length, difficulty bounds, retarget tuning
- `[mining]`: Argon2id memory bounds, attempts, workers, offload
- `[metrics]`: Prometheus bind address

Notes:
- If `storage.path` is relative, the node stores data under `~/.unchained/unchained_data`
- The shipped `config.toml` is a decent starting point

## Wallet and security

- Dilithium3 wallet keys are encrypted at rest with XChaCha20‑Poly1305
- Keys come from your passphrase via Argon2id (large memory, slow to brute‑force)
- Non‑interactive mode requires `WALLET_PASSPHRASE`
- Legacy plaintext wallets (if found) are migrated to encrypted format

Env vars that matter:
- `WALLET_PASSPHRASE` — passphrase for non‑interactive runs
- `PROOF_SERVER_TOKEN` — require `x-auth-token` for the proof server
- `COIN_MIRRORING=0` — disable writing `<db>/coins/coin-*.bin`

## Stealth receiving (how to get paid privately)

1) Export your stealth address (a signed bundle that binds your normal address to your Kyber768 public key):

```bash
cargo run --release --bin unchained -- stealth-address
```

Share this base64‑url string with senders. They’ll encrypt a one‑time Dilithium key to your Kyber PK. Your wallet can decrypt it, nobody else can.

2) Senders use the CLI:

```bash
cargo run --release --bin unchained -- send --stealth <STEALTH_ADDR> --amount 1
```

The wallet will:
- Use a legacy V1 transfer once for any coin that has never moved (to establish an owner one‑time key)
- Use V2 spends thereafter (Merkle‑anchored, blinded nullifier)

## V2 spend (PQ and practical)

Fields:
- `coin_id` — 32 bytes
- `root` — epoch Merkle root
- `proof` — inclusion proof for `coin_id` leaf
- `to` — stealth output `{ one_time_pk, kyber_ct, enc_one_time_sk, enc_sk_nonce }`
- `commitment` — BLAKE3(to.canonical_bytes())
- `nullifier` — BLAKE3("nullifier_v2" || spend_sk || coin_id)
- `sig` — Dilithium3 over `auth_bytes`

Authorization bytes: `auth_bytes = root || nullifier || commitment || coin_id`

Node checks:
1) Coin exists and the epoch anchor matches `root`
2) Merkle proof verifies
3) Nullifier hasn’t been seen
4) Signature verifies under current owner’s one‑time Dilithium public key

## Network and protocol

- Transport: QUIC over UDP (libp2p)
- Gossip: gossipsub topics (anchors, coins, transfers, spends, proofs)
- TLS: rustls + aws‑lc‑rs; prefers PQ/hybrid TLS 1.3

Peer identity lives in `peer_identity.key`. Keep it if you want a stable Peer ID.

## Proof server (HTTPS)

Run a local HTTPS endpoint to fetch proofs by coin id:

```bash
cargo run --release --bin unchained -- proof-server --bind 127.0.0.1:9090
```

Optional auth: set `PROOF_SERVER_TOKEN` and send `x-auth-token` header.

Example request:

```bash
curl -s \
  -H "x-auth-token: $PROOF_SERVER_TOKEN" \
  https://127.0.0.1:9090/proof/<COIN_ID_HEX> | jq .
```

Response (example):

```json
{
  "ok": true,
  "response": {
    "coin": "…",
    "epoch": 123,
    "merkle_root": "…",
    "proof_len": 17
  }
}
```


Notables: `unchained_peer_count`, `unchained_epoch_height`, `unchained_selected_coins`, `unchained_coin_proofs_served_total`, `unchained_mining_*`.

## Data storage

- RocksDB column families: `epoch`, `coin`, `coin_candidate`, `anchor`, `transfer`, `spend`, `nullifier`, …
- Optional coin mirroring: `<db>/coins/coin-<id>.bin` (set `COIN_MIRRORING=0` to disable)
- Simple backups: `<db>/backups/<timestamp>/`

## Mining and epochs (how blocks happen)

- Time is chunked into epochs (`[epoch].seconds`)
- Miners produce coin candidates by meeting Argon2id difficulty
- Each epoch selects up to `[epoch].max_coins_per_epoch` (best PoW) and commits IDs into a Merkle root
- Difficulty and Argon2 memory adjust to aim for `[epoch].target_coins_per_epoch`

## Troubleshooting

- DB locked: don’t share `storage.path` across processes; only delete `LOCK` if the node is stopped
- No peers: add at least one good `[net].bootstrap` multiaddr; open the UDP port or set `public_ip`
- NAT: forward UDP `listen_port`; set `public_ip`
- Non‑interactive: export `WALLET_PASSPHRASE`
- Metrics port busy: it will try the next port; check logs for the new bind
- Too chatty: pass `--quiet-net`

## What makes it post‑quantum?

- Dilithium3 for signatures and addresses (no classical curves)
- Kyber768 for KEM (stealth receiving without leaking long‑term keys)
- BLAKE3 + Argon2id (fast, modern, and not obviously broken by near‑term quantum)

Net effect: you run a normal node and use normal commands, but the cryptography underneath is built for the long haul.

---

I'll scan the core modules to understand PoW, coin structure, epoch selection, transfers, and stealth addresses, then provide a concise audit with risks and recommendations. Fetching key source files in batches.
Ran tool
Ran tool
Ran tool
Ran tool
Ran tool

Scanning remaining core modules for PoW, transfers, stealth addresses, storage, and networking details before writing the audit.
Ran tool
Ran tool
Ran tool
Ran tool
Ran tool

Ran tool

I'll quickly open the remaining core modules `metrics.rs`, `sync.rs`, and the utility `src/bin/inspect_db.rs` to complete the audit context.
Ran tool
Ran tool

Ran tool

### Scope
I reviewed all modules in `src/` with focus on PoW, epoch coin selection, coin/transfer data models, stealth addresses, and consensus/networking behavior.

### Core design overview
- PoW is per-coin, not per-block: miners search nonces over a header composed of `(prev epoch hash || nonce || creator_address)`, compute Argon2id with fixed lanes=1 and a BLAKE3-derived salt, and submit solutions as coin candidates. Epochs (anchors) are time-based and select the best coins from the previous epoch’s candidates.
- Anchors carry the epoch’s coin commitments (Merkle root) and policy parameters (`difficulty`, `mem_kib`), plus a cumulative_work counter used to choose the best chain.

### Proof-of-Work details
- Hash function:
```74:89:/Users/numan/unchained/src/crypto.rs
pub fn argon2id_pow(input: &[u8], mem_kib: u32) -> Result<[u8; 32]> {
    // lanes fixed to 1 as per consensus rules
    let params = Params::new(mem_kib, 1, 1, None)
        .map_err(|e| anyhow!("Invalid Argon2id parameters: {}", e))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; 32];
    // Unkeyed BLAKE3 over header bytes; first 16 bytes as salt
    let full_salt = blake3::hash(input);
    let salt = &full_salt.as_bytes()[..16];

    a2.hash_password_into(input, salt, &mut hash)
        .map_err(|e| anyhow!("Argon2id hashing failed: {}", e))?;
    Ok(hash)
}
```
- Coin header and mining solution check:
```304:340:/Users/numan/unchained/src/miner.rs
let header = Coin::header_bytes(&anchor.hash, nonce, &creator_address);
let pow_hash = crypto::argon2id_pow(&header, mem_kib)?;
...
if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
    ...
    let candidate = CoinCandidate::new(
        anchor.hash, nonce, creator_address, creator_pk, pow_hash,
    );
    ...
}
```
- Difficulty criterion is “leading zero bytes,” not bits. Memory parameter `mem_kib` is part of consensus and can be retargeted.

### Epoch coin selection
- The epoch manager collects all candidates whose `epoch_hash` matches the previous anchor, filters by the previous epoch’s difficulty requirement, then selects up to `max_coins_per_epoch` by smallest `pow_hash` (tie-break by `coin_id`), building a sorted-leaf BLAKE3 Merkle root:
```316:350:/Users/numan/unchained/src/epoch.rs
let required_difficulty = prev.difficulty;
candidates
    .into_iter()
    .filter(|c| c.pow_hash.iter().take(required_difficulty).all(|b| *b == 0))
    .collect::<Vec<_>>();
...
// select top-k by smallest pow_hash, then sort top-k deterministically
```
- Retargeting adjusts both `difficulty` (up or down by 1 clamped in a range) and `mem_kib` based on average coins per epoch vs target:
```46:94:/Users/numan/unchained/src/epoch.rs
pub fn calculate_retarget(...) -> (usize, u32) { ... }
```
- Anchor hash = BLAKE3(merkle_root || prev.hash). Cumulative work is computed as `prev.cumulative_work + 2^(difficulty*8)`.

### Consensus and networking
- Anchor validation checks structure, the cumulative_work arithmetic, and the anchor hash linkage, but does not enforce that `difficulty` equals the deterministic retarget policy:
```193:221:/Users/numan/unchained/src/network.rs
fn validate_anchor(anchor: &Anchor, db: &Store) -> Result<(), String> {
    ...
    let prev: Anchor = db.get("epoch", &(anchor.num - 1).to_le_bytes())?.ok_or(...)?;
    let expected_work = Anchor::expected_work_for_difficulty(anchor.difficulty);
    let expected_cum = prev.cumulative_work.saturating_add(expected_work);
    if anchor.cumulative_work != expected_cum { return Err(...); }
    // Recompute anchor hash: BLAKE3(merkle_root || prev.hash)
    ...
}
```
- Reorg logic selects the branch with greater cumulative_work. There’s best-effort reconstruction of selected coins, but anchors are adoptable even if the local node cannot reconstruct their Merkle root (it will skip populating per-epoch indexes and continue).

### Transfers and stealth addresses
- Stealth address format exports `(recipient_addr, Dilithium pk, Kyber pk, signature over "stealth_addr_v1" || addr || kyber_pk)`. Parsing validates the sig and reconstructs the Kyber pk.
- Legacy Transfer (V1): sender reveals Dilithium pk and signs over the transfer body; publishes a stealth output that includes a one-time Dilithium key and a Kyber ciphertext encrypting the one-time SK under the shared secret (KEM+AEAD).
- V2 Spend: replaces V1 with a proof-bearing spend that commits to the stealth output and includes a nullifier bound to the spending secret and coin id, plus a Merkle proof of inclusion.

Key parts:
```142:216:/Users/numan/unchained/src/transfer.rs
pub fn create_stealth(...) -> Result<Self> { ... }  // V1 legacy transfer
...
pub fn validate(&self, db: &Store) -> Result<()> { ... }  // signature, ownership, prev-tx, nullifier uniqueness
```

```362:513:/Users/numan/unchained/src/transfer.rs
pub struct Spend { coin_id, root, proof, commitment, nullifier, sig, to }
...
pub fn create(...) -> Result<Self> {
    // to = new stealth output, commitment = H(to), nullifier = H_v2(spend_sk || coin_id), sig over auth_bytes
}
pub fn validate(&self, db: &Store) -> Result<()> {
    // coin exists; anchor exists; proof verifies; nullifier unseen; signature by current owner (one-time pk from last transfer, or creator pk for genesis); sanity of 'to'
}
```

- Wallet sending flow prefers V2 spends for each selected input, requests a coin proof from the network, determines the current owner secret key (last incoming stealth one-time SK or creator SK for genesis), creates and gossips the spend.

### Coins and data model
- `Coin` (confirmed): `id = blake3(epoch_hash || nonce || creator_address)`, `value: u64` (minted as 1), `epoch_hash`, `nonce`, `creator_address`, and `creator_pk` to enable genesis V2 spends. A `CoinCandidate` adds `pow_hash`.
```6:17:/Users/numan/unchained/src/coin.rs
pub struct Coin { id, value, epoch_hash, nonce, creator_address, creator_pk }
```

### Security audit: strengths and issues

- Strengths
  - Memory-hard Argon2id PoW with fixed lanes and deterministic salt prevents trivial parallelization changes.
  - Merkle proofs for per-epoch coin commitments; proof serving and verification are implemented end-to-end.
  - Stealth output uses Kyber768 KEM + AES-GCM-SIV with AAD binding to prevent ciphertext swapping; one-time Dilithium keys for recipients.
  - V2 spends hide sender pk and bind nullifier to the spend key and coin id; only the current owner can authorize spends.
  - Wallet uses Argon2id KDF with large memory for encryption; passphrase handling and zeroization included.

- Critical issues to fix urgently
  - Anchor difficulty not enforced by consensus rules:
    - Any peer can fabricate an anchor with arbitrarily high `difficulty` and consistent `cumulative_work`, and it will pass `validate_anchor` because only linkage and arithmetic are checked. This can instantly win cumulative work without doing any work, causing reorgs and chain takeover.
    - Anchor hash does not commit to `difficulty`, `mem_kib`, or `coin_count` fields, only `merkle_root` and parent hash, so even if you added checks later, tampering risks remain.
    - Required fixes:
      - Make anchor hash commit to the entire header (merkle_root, parent_hash, difficulty, mem_kib, epoch number, timestamp, etc.).
      - Enforce determinism of `difficulty`/`mem_kib` by recomputing retarget in `validate_anchor` and rejecting anchors that deviate from the rule.
      - Alternatively or additionally, introduce anchor-level PoW or compute cumulative work from actual selected coins’ PoW (e.g., sum of per-coin work derived from pow_hash) instead of a free-form `difficulty` field.
  - V2 genesis spend validation inconsistency:
    - `Spend::validate` supports genesis spends by verifying signature under `coin.creator_pk` when no previous transfer exists.
    - Network validator rejects genesis spends if there is no previous transfer:
```186:191:/Users/numan/unchained/src/network.rs
    } else {
        return Err("Cannot validate spend without previous owner pk (genesis spend requires legacy transfer)".into());
    }
```
    - Consequence: peers will reject wallet-generated V2 genesis spends that your local node accepts, causing divergence and censorship of genesis spends.
    - Fix: align `validate_spend` in `network.rs` with `Spend::validate` (allow creator_pk-based verification for genesis).

- Other observations and risks
  - Leading zero BYTES criterion is coarse; consider leading zero bits or thresholding on pow_hash interpreted as a large integer for smoother difficulty control.
  - Epochs are time-triggered; anchors themselves are not mined. Consider incentives/fees, anti-censorship for epoch production, and anchoring rate controls.
  - Memory retargeting (`mem_kib`) is configurable and adjusted per retarget window; abrupt changes can cause denial-of-service on low-memory miners. Clamp deltas tightly and announce transitions clearly in the anchor header (and commit them in the hash).
  - Selection fairness: picking the k smallest pow_hash among valid solutions is fine, but keep an eye on tie-breaking and candidate flooding. Per-epoch caps and filtering by prev difficulty are in place.

### Recommendations and roadmap
- Consensus hardening
  - Commit anchor header fields (difficulty, mem_kib, epoch number, maybe timestamp) into `anchor.hash`.
  - Validate retarget deterministically in `validate_anchor`; reject anchors with unexpected `difficulty`/`mem_kib`.
  - Consider anchor-level PoW or define cumulative work as a function of actually selected coins (e.g., sum of −log2(pow_hash/2^256) or equivalent).
  - Enforce minimum non-empty epochs after genesis to prevent empty-epoch grinding, or discount empty epochs in cumulative work.
- Transaction model
  - Complete migration to V2 spends; keep V1 only for backward-compat. Add fees and change outputs or coin-splitting to handle arbitrary amounts and reduce UTXO bloat if values >1 are used.
  - Add replay protection across reorgs: ensure nullifiers remain unique across forks (e.g., commit epoch root or anchor hash into nullifier preimage or nullifier set semantics).
- Privacy
  - For V1, sender_pk leaks identity. Encourage V2 by default and deprecate V1 in networking accept rules over time.
  - Consider decoy mechanisms or batching if stronger privacy is desired.
- Networking
  - Add signature checks for anchors by the producer if you introduce an anchor producer role, or keep strictly objective validation to avoid centralization.
  - Rate-limit and ban policies exist; keep telemetry on invalid anchors/coins to spot attacks.
- Wallet and UX
  - Encrypt and persist Kyber keys in the wallet file (the v2 format hint exists but isn’t used to store Kyber yet).
  - Improve input selection (avoid dust; consider deterministic ordering).
- Performance
  - Continue using offloaded blocking for Argon2; tune `mem_kib` ranges for typical hardware.

### Real use cases
- Micropayments with privacy: 1-value coins and stealth outputs suit streaming or small payments where each coin represents a discrete unit.
- Private asset transfers: Kyber+Dilithium stealth outputs with PQ security are future-proof for long-term confidentiality.
- Proof of useful work integration: the per-coin PoW model is amenable to swapping the header function or salt derivation for future “useful work” primitives while keeping selection logic.

### Quick answers to your focal questions
- PoW performed: Argon2id over header (prev epoch hash, nonce, creator address), lanes=1, salt from BLAKE3(header). Solution criterion: leading zero bytes equal to difficulty.
- Coin selection per epoch: from candidates referencing prev anchor, filter by prev difficulty, choose up to cap smallest pow_hash, commit their ids via a sorted-leaf BLAKE3 Merkle tree into the anchor.
- Transfers: Legacy V1 reveals sender pk and uses stealth output; V2 Spend proves coin inclusion, authorizes with current owner SK, commits to new stealth output, and publishes a nullifier to prevent double spends.
- Stealth addresses/transfers: Recipient publishes Dilithium+Kyber pair with a signed descriptor; sender KEM-encapsulates to recipient’s Kyber pk and delivers a one-time Dilithium key encrypted under AEAD; recipient decapsulates to recover the SK. Address for recipient is derived from the one-time pk.
- Coin structure: `Coin{id, value, epoch_hash, nonce, creator_address, creator_pk}`, minted with `value=1` by convention; `CoinCandidate` adds `pow_hash`.

- Most important fixes:
  - Enforce deterministic retarget in validation and commit difficulty/mem_kib into `anchor.hash`.
  - Align network spend validation with `Spend::validate` for genesis spends.