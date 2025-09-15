## Unchained

### A post‑quantum, privacy‑preserving proof‑of‑work chain you can run today but is still in heavy development -- I tend to push to prod 

Unchained is a blockchain designed for the next decades of cryptography. It combines:
- memory‑hard Argon2id proof‑of‑work,
- post‑quantum signatures and key exchange,
- Stealth one‑time keys,
- efficient Merkle proofs per epoch,
- and a simple, production‑oriented node you can compile and mine in minutes.

You get a straightforward UTXO‑style system with private receiving, deterministic verification, and a gossip network that favors practicality over ceremony.

### Unchained 
- Post‑quantum by default: Kyber768 (ML‑KEM) for private receiving, and BLAKE3 for fast hashing and domain‑separated derivations throughout.
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
unchained peer-id

# Print your stealth receiving address (base64‑url)
unchained stealth-address

# Send coins to a recipient’s stealth address (paycode)
unchained send --paycode <Address> --amount 1

# Request and verify a coin proof by id (hex)
unchained proof --coin-id <hex>

# Check your balance and address
unchained balance

# Show simple transaction history
unchained history

# P2P: Send a short message to the limited topic
unchained msg-send --text "Hello from Unchained"

# P2P: Listen for incoming messages on the limited topic
unchained msg-listen           # run until Ctrl+C
unchained msg-listen --once    # exit after the first message
unchained msg-listen --count 5 # exit after 5 messages
```
Tip: add `--quiet-net` to suppress routine gossip logs.

---

## Offers: APIs and CLI

### SSE stream (live + replay)
```bash
# Tail recent verified offers, redact signatures
curl -N 'http://127.0.0.1:9120/offers?stream=1&redact_sig=1'

# Resume from a millisecond cursor
curl -N 'http://127.0.0.1:9120/offers?stream=1&since=0'

# Or resume using Last-Event-ID header
curl -N -H 'Last-Event-ID: 1690000000000' 'http://127.0.0.1:9120/offers?stream=1&redact_sig=1'
```

### Paginated reads
```bash
curl 'http://127.0.0.1:9120/offers?limit=100&since=0&redact_sig=1'
```

### CLI: watch offers with filters
```bash
# Show up to 10 offers, filter by minimum amount and maker
unchained offer-watch --min-amount 1000 --maker 0x<maker_address_hex> --count 10
```

### CLI: accept a signed offer (deterministic, no secrets printed)
```bash
# Deterministic refunds via a base secret (recommended for prod)
unchained offer-accept \
  --input maker_offer.json \
  --claim-secret <32-byte hex|base64-url> \
  --refund-base <32-byte hex|base64-url>

# Or write per-coin refund secrets to a file (kept secure)
unchained offer-accept \
  --input maker_offer.json \
  --claim-secret <32-byte hex|base64-url> \
  --refund-secrets-out refunds_secrets.json
```

Notes:
- Offers are verified (Dilithium3) and only verified offers are streamed.
- Secrets are never printed; use `--refund-base` for deterministic derivation or `--refund-secrets-out` to persist securely.

---

## Bridge REST

### Status (stable alias)
```bash
curl 'http://127.0.0.1:<bridge_port>/bridge/status'
```

### Quote
```bash
curl 'http://127.0.0.1:<bridge_port>/bridge/quote?amount=100000'
# → { "amount": 100000, "fee_bps": 10, "fee": 1000, "effective": 99000, "min_ok": true, "max_ok": true, ... }
```

Ensure your `config.toml` reflects bridge limits and fees; the quote endpoint enforces min/max and returns fee and effective.

### x402 payments (experimental)
Protected resources under `/paid/*` return HTTP 402 with an Unchained payment challenge when `[bridge].x402_enabled = true`.

Client flow:
1) Request a protected resource → receive 402 JSON challenge.
2) Call wallet helper to pay and get a receipt header:
```rust
// Rust client inside this node
let header = wallet.x402_pay_from_challenge(&challenge_json, &net).await?;
// Resubmit original request with header
let req = reqwest::Client::new()
    .get("http://127.0.0.1:9110/paid/example")
    .header("X-PAYMENT", header)
    .send().await?;
```
3) Server verifies receipt against local state and returns 200.

Config:
```toml
[bridge]
x402_enabled = true
x402_min_confs = 0
x402_invoice_ttl_ms = 300000
x402_protected_prefixes = ["/paid"]
# Optional: set specific recipient KeyDoc or paycode; defaults to server wallet
# x402_recipient_handle = "<stealth or KeyDoc>"
```

---

## Installation (Windows)
- Install Rust from rustup (MSVC toolchain): `https://rustup.rs/`
- Ensure CMake is available (Visual Studio Build Tools or standalone CMake)
- Clone the repo and build:
```powershell
git clone https://github.com/Numi2/unchained.git
cd unchained
cargo build --release
.\target\release\unchained.exe
```

If you run behind a firewall/NAT, forward the UDP QUIC port from your `config.toml` and/or configure `net.public_ip`.

---

## What happens when you send/receive

- You copy your stealth receiving address (base64‑url string) and share it with a sender.
- The sender’s wallet derives a private one‑time output for you using Kyber768 and BLAKE3. Standard V3 spends validate against the genesis anchor (empty proof); HTLC/bridge flows include a Merkle inclusion proof from the coin’s commit epoch.
- Validators check: coin inclusion via Merkle path, output commitment, and that the spend’s nullifier hasn’t been seen before (double‑spend protection).
- The coin leaves the sender’s balance immediately after the spend is validated and applied.
- The recipient’s wallet deterministically recognizes and decrypts the new output; the coin appears in their balance.
- Anyone can verify inclusion using a compact Merkle proof without revealing wallet secrets.

The important part is the recipient’s public keys that enable private output derivation.

---

## Configure your node

Edit `config.toml` (shipped in the repo). Key sections:

- `[net]`: P2P networking
  - `listen_port`: UDP port for QUIC
  - `bootstrap`: optional list of peer multiaddrs to join a network
  - `public_ip`: advertise a public IP if you’re behind NAT



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

### Addresses and private receiving
- A stealth address contains the recipient’s address and Kyber768 public key, encoded as a base64‑url string.
- Private receiving uses Kyber768. A sender encapsulates a shared secret to the recipient’s Kyber public key and deterministically derives a one‑time per‑output key and lock secret for the next hop.
- The stealth output contains what the recipient needs to recover the one‑time secret key and the next‑hop lock secret (via Kyber decapsulation), without linking to their long‑term identity.

### Commitments and nullifiers (hashlock transfers)
- Commitments bind outputs to immutable data (the Kyber ciphertext) via BLAKE3, avoiding circular dependencies and keeping transactions minimal.
- Ownership = knowledge of the current unlock preimage. The previous lock hash is domain‑separated and context‑bound: `LOCK_HASH_prev = BLAKE3("lh" || chain_id32 || coin_id32 || lp(p)||p)`; legacy nodes accept `BLAKE3_k("unchained.lock.v1", p)`.
- Uniqueness is enforced by a nullifier: `nf = BLAKE3("nf" || chain_id32 || coin_id32 || lp(p)||p)`; legacy nodes accept `BLAKE3("unchained.nullifier.v3" || chain_id32 || coin_id32 || p)`. The same `nf` cannot appear twice.
- Each spend supplies `(unlock_preimage, next_lock_hash)`, where `next_lock_hash = BLAKE3("lh" || chain_id32 || coin_id32 || lp(s_next)||s_next)` and `s_next` is derived from Kyber decapsulation (optionally bound to an out‑of‑band note).

### Privacy without signatures on the transfer path
Transfers are authorized by providing the correct unlock preimage for the current lock (hashlock), not by signatures. The system relies on:
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
- To receive, run `stealth-address` and share the base64‑url string.
- To send, run `send --paycode <ADDR> --amount <N>`. The coin leaves your balance when the spend is validated and applied; the recipient’s wallet will detect and show the coin deterministically.

---

### Unified recipient handle (stealth address or KeyDoc JSON)

You can now paste either a stealth address OR a KeyDoc JSON into the same "paycode" input. The wallet will auto‑verify and send; no pre‑import step or public lookup.

- What is a KeyDoc? A short JSON the receiver shares out‑of‑band:
```json
{
  "chain_id": "<32‑byte hex or base64>",
  "dili_pk": "<Dilithium3 public key bytes>",
  "kyber_pk": "<Kyber768 public key bytes>",
  "sig": "sig_dilithium3(\"bind\" | chain_id | dili_pk | kyber_pk)"
}
```
- Privacy: The KeyDoc is never published on‑chain or to the network. Each output remains unlinkable (per‑payment Kyber KEM + view tag + one‑time key) just like stealth addresses.

Examples
- CLI: pass a stealth address or paste a KeyDoc JSON string directly:
```bash
unchained send --paycode '<stealth_or_keydoc_string>' --amount 1
```
- API: use the simple wrapper, which accepts either format and uses an empty note:
```rust
wallet.pay(handle_str, 1, &network).await?;
```


## Networking
- Transport: QUIC over UDP (libp2p)
- Gossip: gossipsub topics for anchors, coins, spends, proofs
- TLS: rustls + aws‑lc‑rs (prefers PQ/hybrid TLS 1.3)
- Peer identity is stored in `peer_identity.key` (stable across restarts)

You can print your Peer ID with `peer-id` and share a multiaddr if `net.public_ip` is configured.

### P2P messages (24h-limited topic)
- Use `msg-send` to publish a short text message to the public 24h‑limited gossip topic.
- Use `msg-listen` to stream incoming messages; they print as simple text lines.
- The node enforces an inbound limit of 2 messages per 24 hours per peer. Outbound is not enforced by the node.
- This is meant for lightweight coordination or testing messages; do not rely on it for durable storage.

---

## Troubleshooting
- Database locked: ensure a single process uses the storage path; only remove `LOCK` when the node is stopped.
- No peers: add good bootstrap multiaddrs in `config.toml`; open the UDP port; set `public_ip` if behind NAT.
- Non‑interactive runs: set `WALLET_PASSPHRASE`.
- Too chatty logs: use `--quiet-net`.
- Proofs not found: ensure you are synced; request again after peers share epoch leaves.

---

## Security model (summary)
- Private receiving: Kyber768 (stealth outputs)
- Authorization: hashlock preimage (ownership), next‑hop lock hash commitment
- Nullifier: `BLAKE3("nf" || chain_id32 || coin_id32 || lp(p)||p)` (legacy `unchained.nullifier.v3` accepted)
- Hashing: BLAKE3 with explicit domain separation
- PoW: Argon2id (memory‑hard), lanes locked by consensus
- Persistence: RocksDB with column families tuned for this workload

-----

How the transfers/ `lock_hash`  on code level:



- Paycode generation
  - `unchained stealth-address` prints a base64 doc with `recipient_addr` and Kyber PK (`wallet.export_stealth_address()`).
- Sending with paycode
  - `unchained send --paycode <code> --amount 2` calls `wallet.send_with_paycode_and_note(...)`.
  - The paycode is parsed to `(recipient_addr, receiver_kyber_pk)`.
  - Inputs are selected to cover the requested amount (`select_inputs(2)`). Since each coin has `value = 1` (`CoinCandidate::new` hardcodes 1), exactly two coins are chosen.
  - For each input coin:
    - Encapsulate to receiver’s Kyber PK → derive `shared`, `ct`.
    - Derive deterministic OTP bytes and view tag; compute `next_lock_hash`.
    - Build `ReceiverLockCommitment` and a V3 hashlock `Spend` with `commitment = H(kyber_ct)`.
    - Enforce `commitment_id_v1` deterministically and mark it used in `apply()`.
    - Nullifier is checked with new-or-legacy scheme.
    - `spend.apply(&store)` updates sender’s local DB immediately, then gossips.
- Balances update correctly
  - Sender (wallet 2): After local `apply()`, the coins now have a recorded spend not addressed to the sender, so they are excluded from `wallet.balance()` → decreased by 2.
  - Receiver (wallet 1): On spend gossip, `scan_spend_for_me()` confirms with `is_for_receiver()` and indexes. `wallet.balance()`:
    - If the coin is present, it credits `coin.value` for spends addressed to receiver.
    - If coin not yet synced, it still credits from `spend.to.amount_le` via the spend CF fallback.
    - Result: increased by 2.

- Preconditions: wallet 2 has ≥ 2 unspent coins; nodes are reasonably synced; network accepts the spends.
- Multiple coins are sent as multiple spends (no change output or merging), which matches value=1 coin model.
