## Unchained

### A post‑quantum, privacy‑preserving proof‑of‑work chain you can run today

Unchained is a blockchain designed for the next decades of cryptography. It combines:
- memory‑hard Argon2id proof‑of‑work,
- post‑quantum signatures and key exchange,
- Stealth one‑time keys,
- efficient Merkle proofs per epoch,
- and a simple, production‑oriented node you can compile and mine in minutes.

You get a straightforward UTXO‑style system with private receiving, deterministic verification, and a gossip network that favors practicality over ceremony.

### Unchained 
- Post‑quantum by default: we use Dilithium3 (ML‑DSA‑65) for addresses/signatures, Kyber768 (ML‑KEM) for private receiving, and BLAKE3 for fast hashing throughout.
- Private by design: recipients get coins via stealth outputs; senders don’t reveal long‑term keys. Inclusion is proven via Merkle paths, not global scans.
- Simple consensus: memory‑hard Argon2id PoW selects coins per epoch; every epoch commits a Merkle root. No heavy scripting, no fragile dependencies.
- Efficient verification: compact proofs; local nodes verify inclusion, nullifier uniqueness, and commitments deterministically.

---

## Quick start (Linux/macOS)

### Prerequisites
- A recent Rust toolchain (stable)
- Build tools and libraries

Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y build-essential git curl cmake libclang-dev pkg-config
```

macOS:
```bash
xcode-select --install  # if you don’t have developer tools
/bin/bash -c "$(curl -fsSL https://sh.rustup.rs)" -y
```

Install Rust (if you don’t have it):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Build and run a node
```bash
git clone https://github.com/Numi2/unchained.git
cd unchained
cargo build --release
# Start a node; it will create a wallet, sync, and can mine depending on config
target/release/unchained
```

The first run will:
- create and encrypt a wallet using your passphrase,
- set up a persistent P2P identity,
- start the node and print status logs.

To start mining immediately:
```bash
# Using the CLI subcommand
target/release/unchained mine
```

Or enable mining in `config.toml` (set `[mining].enabled = true`) and run without arguments.

### Common CLI commands
```bash
# Show your P2P Peer ID
unchained -- peer-id

# Print your stealth receiving address (base64‑url)
unchained -- stealth-address

# Send coins to a recipient’s stealth address
unchained send --stealth <STEALTH_ADDR> --amount 1

# Check your balance and address
unchained balance

# Show simple transaction history
unchained history
```
Tip: add `--quiet-net` to suppress routine gossip logs.

---

## Installation (Windows)
- Install Rust from rustup (MSVC toolchain): `https://rustup.rs/`
- Ensure CMake is available (Visual Studio Build Tools or standalone CMake)
- Clone the repo and build:
```powershell
git clone https://github.com/Numi2/unchained.git
cd unchained
cargo build --release
.\ttarget\release\unchained.exe
```

If you run behind a firewall/NAT, forward the UDP QUIC port from your `config.toml` and/or configure `net.public_ip`.

---

## What happens when you send/receive

- You copy your stealth receiving address (base64‑url string) and share it with a sender.
- The sender’s wallet derives a private one‑time output for you using Kyber768 and BLAKE3, plus an inclusion proof against the current epoch’s Merkle root.
- Validators check: coin inclusion via Merkle path, output commitment, and that the spend’s nullifier hasn’t been seen before (double‑spend protection).
- The coin leaves the sender’s balance immediately after the spend is validated and applied.
- The recipient’s wallet deterministically recognizes and decrypts the new output; the coin appears in their balance.
- Anyone can verify inclusion using a compact Merkle proof without revealing wallet secrets.

Stealth addresses may include a signature, but the node does not require it. The important part is the recipient’s public keys that enable private output derivation.

---

## Configure your node

Edit `config.toml` (shipped in the repo). Key sections:

- `[[net]]`: P2P networking
  - `listen_port`: UDP port for QUIC
  - `bootstrap`: optional list of peer multiaddrs to join a network
  - `public_ip`: advertise a public IP if you’re behind NAT

- `[storage]`: RocksDB path
  - If relative, the node uses `~/.unchained/unchained_data`

- `[epoch]`: epoch duration, coin cap per epoch
  - `seconds`: epoch length
  - `max_coins_per_epoch`: maximum coin selections per epoch

- `[mining]`: memory‑hard PoW parameters
  - `mem_kib` bounds, `workers`, `heartbeat_interval_secs`

- `[metrics]`: Prometheus exporter bind address

After editing, run `unchained` (or `mine`) to use your settings.

---

## How the technology works

### Epochs, anchors, and Merkle proofs
Time is divided into fixed‑length epochs. Within each epoch, miners produce coin candidates that meet the Argon2id difficulty target. At the boundary:
- the network selects up to `max_coins_per_epoch` candidates (best PoW),
- computes a Merkle root over the chosen coin IDs (sorted leaves for determinism),
- and publishes an anchor that commits to that root (and the previous anchor’s hash).

Anyone can verify a coin’s inclusion using a concise Merkle path against the anchor. We avoid global scans and keep proofs small.

### Memory‑hard PoW
We use Argon2id with consensus‑locked lanes and tuned memory to make hardware advantage more costly. Difficulty and memory targets can retune over time to aim for a desired number of coins per epoch.

### Addresses, signatures, and private receiving
- Addresses are derived from Dilithium3 public keys (or ML‑DSA‑65 when available). The corresponding secret key stays encrypted at rest.
- Private receiving uses Kyber768. A sender encapsulates a shared secret to the recipient’s Kyber public key and derives a one‑time Dilithium public key deterministically. This becomes the recipient’s per‑coin address.
- The stealth output contains only what the recipient needs to recover the one‑time secret key, nothing that links to their long‑term identity.

### Commitments and nullifiers
- Commitments bind outputs to immutable data (e.g., the Kyber ciphertext) via BLAKE3, avoiding circular dependencies and keeping transactions minimal.
- Double‑spend protection uses nullifiers derived from per‑spend secrets bound to each coin ID. Seeing the same nullifier twice means an attempted double spend and is rejected. Because nullifiers are one‑way BLAKE3 hashes, they don’t leak spend keys.

### Privacy without global signatures on path
Instead of embedding large signatures in every authorization path, Unchained relies on:
- Kyber‑derived stealth outputs for receiver privacy,
- BLAKE3 commitments for output integrity,
- nullifiers for uniqueness,
- and Merkle proofs for inclusion.

This keeps transactions compact while preserving verifiability and recipient unlinkability.

### Domain separation and determinism
We use domain‑separated BLAKE3 everywhere (e.g., for addresses, commitments, nullifiers). Deterministic layouts ensure every node recomputes the same values without coordination.

---

## Mining: from zero to first coin
1) Start the node and ensure you are synced (it prints epoch height). If you have bootstrap peers, the node will follow the network. If not, it can produce a local genesis.
2) Enable mining (`mine` or config). The miner tries nonces until the Argon2id hash meets difficulty. When it finds a candidate, it gossips it.
3) At the epoch boundary, the anchor commits the selected coin IDs. Your coin becomes confirmed and visible via the `coin` column family with a Merkle path served by peers.

You’ll see:
- mining attempts and timing stats,
- selected coin count per epoch,
- current epoch height and difficulty.

---

## Operating the wallet
- Wallet secrets are encrypted at rest (XChaCha20‑Poly1305) with a key derived from your passphrase (Argon2id, high memory). Passphrases are prompted interactively; for non‑interactive runs, set `WALLET_PASSPHRASE`.
- To receive, run `stealth-address` and share the base64‑url string. The node accepts addresses with or without embedded signatures.
- To send, run `send --stealth <ADDR> --amount <N>`. The coin leaves your balance when the spend is validated and applied; the recipient’s wallet will detect and show the coin deterministically.

---

## Networking
- Transport: QUIC over UDP (libp2p)
- Gossip: gossipsub topics for anchors, coins, spends, proofs
- TLS: rustls + aws‑lc‑rs (prefers PQ/hybrid TLS 1.3)
- Peer identity is stored in `peer_identity.key` (stable across restarts)

You can print your Peer ID with `peer-id` and share a multiaddr if `net.public_ip` is configured.

---

## Metrics
Exposes Prometheus metrics (e.g., peer count, epoch height, mining timing, proofs served). Configure the bind address in `[metrics]` and scrape from your Prometheus server.

---

## Troubleshooting
- Database locked: ensure a single process uses the storage path; only remove `LOCK` when the node is stopped.
- No peers: add good bootstrap multiaddrs in `config.toml`; open the UDP port; set `public_ip` if behind NAT.
- Non‑interactive runs: set `WALLET_PASSPHRASE`.
- Too chatty logs: use `--quiet-net`.
- Proofs not found: ensure you are synced; request again after peers share epoch leaves.

---

## Security model (summary)
- Signatures and addresses: Dilithium3/ML‑DSA‑65
- Private receiving: Kyber768 (stealth outputs)
- Hashing: BLAKE3 with explicit domain separation
- PoW: Argon2id (memory‑hard), lanes locked by consensus
- Persistence: RocksDB with column families tuned for this workload

The goal is a small, understandable codebase that stays useful in a post‑quantum world while remaining practical for everyday use.
