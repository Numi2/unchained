# unchained

Post‑quantum blockchain implementation - Dilithium3 for signatures, Kyber768 for stealth receiving, BLAKE3 for hashing, Argon2id for PoW. libp2p over QUIC does the gossip (libp2p prefer pq aws). 

miners find Argon2id solutions, coins get committed into epoch Merkle roots, and ownership moves with Dilithium signatures. Receivers sends use one‑time keys (stealth) by default.

## Highlights (why this isn’t just another toy chain)

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
- `proof --coin-id <HEX>` — request and verify a Merkle proof for a coin
- `proof-server [--bind HOST:PORT]` — HTTPS server that returns proofs
- `send --stealth <ADDRESS> --amount <N>` — send to a stealth address
- `balance` — show wallet balance + address
- `history` — print simple tx history

Examples:

```bash
# Send 1 coin to a recipient’s stealth address (base64‑url string)
cargo run --release --bin unchained -- send --stealth <STEALTH_ADDR> --amount 1

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

```rust
use std::sync::Arc;
use unchained::{storage::Store, wallet::Wallet};

fn main() -> anyhow::Result<()> {
    let db = Arc::new(Store::open("./data")?);
    let wallet = Wallet::load_or_create(db)?;
    println!("{}", wallet.export_stealth_address());
    Ok(())
}
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
