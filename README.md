# unchained

Post-quantum blockchain: Dilithium3 signatures, BLAKE3 hashing, Argon2id PoW, and stealth transfers using Kyber768.

## features

- **Memory-hard PoW (Argon2id)**
- **BLAKE3** for all hashing/commitments
- **Dilithium3** for signatures and addressing
- **Stealth outputs**: Kyber768 KEM + AES-256-GCM-SIV to encrypt the one-time Dilithium SK
- **Nullifiers**:
  - v1 (legacy): `BLAKE3("nullifier_v1" || coin_id || sig)`
  - v2 (current): `BLAKE3("nullifier_v2" || sk_spend || coin_id)`; stored in `nullifier` CF
- **libp2p gossipsub** for propagation
- **RocksDB** persistence

## usage

```bash
cargo build --release
cargo run --release --bin unchained mine
```

generates wallet on first run, begins mining and network participation.

### show your peer id

Print the local libp2p Peer ID (and your full multiaddr if `net.public_ip` is set in `config.toml`):

```bash
cargo run --release --bin unchained -- peer-id
```

Example output:

```text
🆔 Peer ID: 12D3KooW...
📫 Multiaddr: /ip4/203.0.113.10/udp/31000/quic-v1/p2p/12D3KooW...
```

Notes
- The peer identity is persisted in `peer_identity.key` (created on first run). Keep it to retain the same Peer ID across restarts.
- The node also logs the peer ID at startup unless `--quiet-net` is used.

## network protocol

- QUIC transport over UDP
- rustls 0.23.22 with aws-lc-rs provider
- prefer-post-quantum TLS handshakes

## data structures

- **Coins**: `blake3(epoch_hash || nonce || creator_address)` identifier
- **Transfers**:
  - Signature: Dilithium3 over canonical bytes `coin_id || sender_pk || stealth_output || prev_tx_hash`
  - Stealth output: `{ one_time_pk, kyber_ct, enc_one_time_sk, nonce }`
  - Recipient address: `addr(one_time_pk)` (unlinkable)
  - Nullifier: `BLAKE3("nullifier_v1" || coin_id || sig)`; enforced unique in DB/mempool
- **Epochs**: difficulty/Argon2id memory retargeting

## configuration

Modify `config.toml` for network settings, bootstrap peers, mining parameters, and storage location.

## stealth transfers and spends

### 1) Share your stealth address
Programmatically export a signed stealth address (binds your Dilithium address to your Kyber768 public key):

```rust
use std::sync::Arc;
use unchained::{storage::Store, wallet::Wallet};

fn main() -> anyhow::Result<()> {
    let db = Arc::new(Store::open("./data")?);
    let wallet = Wallet::load_or_create(db)?;
    let stealth = wallet.export_stealth_address();
    println!("{}", stealth);
    Ok(())
}
```

This is a base64-url string. Share it with senders.

### 2) Send coins to a stealth address (CLI)

```bash
cargo run --release --bin unchained -- send --stealth <STEALTH_ADDRESS_STRING> --amount 1
```

This command now sends PQ-ready V2 spends by default where possible:

- If the coin was never transferred before (genesis spend), it falls back to a legacy V1 transfer once to establish the owner’s one-time key.
- Otherwise, it produces a V2 spend with a blinded nullifier and Merkle inclusion proof.

### V2 spend format (no decoys)

- Spend fields:
  - `coin_id`: 32 bytes
  - `root`: epoch Merkle root (32 bytes)
  - `proof`: Merkle inclusion proof for `coin_id` leaf (array of `(sibling_hash, sibling_is_left)`)
  - `to`: stealth output `{ one_time_pk, kyber_ct, enc_one_time_sk, nonce }`
  - `commitment`: `BLAKE3(to.canonical_bytes())`
  - `nullifier`: `BLAKE3("nullifier_v2" || sk_spend || coin_id)` (linkable per coin to prevent double-spend)
  - `sig`: Dilithium3 signature over `auth_bytes`

- Authorization bytes: `auth_bytes = root || nullifier || commitment || coin_id`

- Verification:
  1) Check coin exists and anchor/root match
  2) Verify Merkle proof for `coin_id`
  3) Check nullifier is unseen
  4) Verify Dilithium3 signature against the current owner’s one-time public key (from the previous transfer’s `to.one_time_pk`)

### Notes
- Nullifiers are stored in the `nullifier` column family to prevent double-spends.
- Stealth scanning: recipients can scan spends/transfers and recover the one-time SK with their Kyber secret key.