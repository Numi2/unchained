## unchained: User and Miner Onboarding Guide

This guide explains how to build, configure, run, mine, send coins, verify proofs, and monitor an unchained node. It covers single-node (genesis) and multi-node deployments.

### 1) Prerequisites
- Rust (stable) and Cargo
- A machine with sufficient RAM for Argon2id PoW (default mining memory ≥ 16 MiB; configurable)
- Open network access on your chosen QUIC UDP port (default `listen_port = 31000`) if you expect inbound peers

### 2) Build
```
cargo build --release
```

### 3) Configuration (config.toml)
Create or edit `config.toml` at the repo root. Only the following keys are recognized; unknown keys are logged and ignored.

```
[net]
listen_port = 31000                        # UDP port for QUIC/libp2p
bootstrap = [                              # Optional seed peers (multiaddr form)
  # "/ip4/203.0.113.10/udp/31000/quic-v1/p2p/<peer-id>"
]
max_peers = 100
connection_timeout_secs = 30
public_ip = "203.0.113.10"                # Optional, helps peers dial you
sync_timeout_secs = 180

[p2p]
max_validation_failures_per_peer = 10
peer_ban_duration_secs = 3600
rate_limit_window_secs = 60
max_messages_per_window = 100

[storage]
# If relative, the node stores data at ~/.unchained/unchained_data
path = "data"

[epoch]
seconds = 333                              # Epoch length (anchor creation frequency)
target_leading_zeros = 1                   # PoW difficulty (bytes of 0 at start)
target_coins_per_epoch = 100
max_coins_per_epoch = 100
retarget_interval = 10                     # Re-adjust difficulty/memory every N epochs

[mining]
enabled = true
mem_kib = 16192                            # Argon2id memory cost (KiB)
min_mem_kib = 16384                        # Lower bound for auto-retargeting
max_mem_kib = 262144                       # Upper bound for auto-retargeting
max_memory_adjustment = 1.5                # Max ratio per retarget step

[metrics]
bind = "127.0.0.1:9100"                    # Prometheus/OpenMetrics endpoint
```

Notes
- Data path: relative paths are resolved to `~/.unchained/unchained_data`.
- Peer identity: generated at first run, saved as `peer_identity.key` in the repo directory. Keep it to preserve your Peer ID across restarts.
- Multiaddress format for bootstrap peers: `/ip4/<ip>/udp/<port>/quic-v1/p2p/<peer-id>`.

### 4) Running a node
Basic start (mining reads `mining.enabled` from config):
```
cargo run --release --bin unchained
```

Explicit mining command:
```
cargo run --release --bin unchained -- mine
```

Useful flags
- `--config <path>`: Use an alternate config file.
- `--quiet-net`: Reduce routine network gossip logs.

First node (genesis)
- If no peers respond during initial sync, the node proceeds with a local chain and the epoch manager will create genesis on the next epoch tick.
- For faster bootstrapping in testing, you can temporarily lower `epoch.seconds`.

Joining an existing network
- Add one or more `net.bootstrap` entries pointing to reachable peers.
- Ensure that at least one bootstrap peer is publicly reachable and lists its external address (set `net.public_ip` on that node).

Networking and firewall
- QUIC runs over UDP. Open your `listen_port` (default `31000/udp`) on host and cloud firewalls for inbound peers.
- If you set `public_ip`, the node announces it so others can dial you.

### 5) Wallet and basic CLI
On first run, the node creates an encrypted wallet and prompts for a quantum passphrase. In headless mode, set `QUANTUM_PASSPHRASE`.

Show balance
```
cargo run --release --bin unchained -- balance
```

Show history
```
cargo run --release --bin unchained -- history
```

Send coins
```
cargo run --release --bin unchained -- send --to <32-byte-hex-address> --amount <u64>
```

Notes
- The address is a 32-byte hex string (creator address derived from your wallet key).
- Transfers are processed and included in the next epoch anchor.

### 6) Mining
Consensus
- PoW: Argon2id with deterministic parameters (lanes fixed to 1). Winning condition: the PoW hash’s first `target_leading_zeros` bytes are zero.
- Selection: Each epoch selects up to `max_coins_per_epoch` candidates with the smallest hashes.

Parameters
- `mining.mem_kib` controls Argon2id memory cost. Higher memory increases resource usage per attempt.
- Difficulty and memory can retarget around the moving average of selected coins.

Behavior to expect
- Anchors (epoch headers) are created on a periodic ticker (`epoch.seconds`). Even if a coin is found early, the next anchor appears at the tick.
- The miner keeps a heartbeat to ensure liveness; with long epochs, you may occasionally see a reconnect log before the next anchor is produced. This is expected and harmless.

### 7) Proofs
Verify a coin proof (pulls proof via P2P and verifies locally):
```
cargo run --release --bin unchained -- proof --coin-id <32-byte-hex-coin-id>
```

Run a simple HTTP proof server (for external clients):
```
cargo run --release --bin unchained -- proof-server --bind 0.0.0.0:9090
```

Optional auth
- Set `PROOF_SERVER_TOKEN` environment variable. Clients must send header `x-auth-token: <token>`.

Client example
```
curl -s http://127.0.0.1:9090/proof/<coin-hex>
# or with auth
curl -s -H "x-auth-token: $PROOF_SERVER_TOKEN" http://127.0.0.1:9090/proof/<coin-hex>
```

### 8) Metrics
- The node exposes OpenMetrics/Prometheus at `metrics.bind` (default `127.0.0.1:9100`).
- If the port is busy, it auto-increments the port; check logs for the actual bind ("Prometheus metrics serving on http://...").

Quick check
```
curl http://127.0.0.1:9100
```

Common gauges/counters
- `unchained_peer_count`: connected peers
- `unchained_epoch_height`: latest finalized epoch number
- `unchained_candidate_coins`: candidates seen for current epoch
- `unchained_selected_coins`: selected coin count for last epoch
- Validation and DB failure counters

### 9) Data directory and reset
- Default data lives under `~/.unchained/unchained_data` (unless `storage.path` is absolute).
- To reset a node’s chain state: stop the node and remove the directory. Keep your wallet file safe.

### 10) Troubleshooting
- Stuck waiting for tip / no peers
  - Ensure at least one bootstrap peer is reachable, or allow the node to proceed as a standalone chain. The node will create genesis on the epoch tick.
- Metrics not visible at `0.0.0.0:9100`
  - Use `127.0.0.1:9100` locally, or the server’s public IP externally. `0.0.0.0` is a bind address.
  - If the port moved due to conflict, use the new port from logs.
- Heartbeat timeouts before the next anchor
  - Expected with long `epoch.seconds`. To reduce log noise, shorten `epoch.seconds` or run on faster hardware. (Advanced: the miner’s timeout is conservative.)
- Peer connectivity
  - Open UDP `listen_port` in firewalls. Set `public_ip` to a reachable address.
  - Verify your peer is dialable via its multiaddr.

### 11) Security notes
- Protect your quantum passphrase and `peer_identity.key`.
- Prefer binding the proof server to a private address and enable the token header if exposing externally.
- Be cautious when exposing metrics publicly.

### 12) Command reference
```
unchained --config <file> [--quiet-net] <command>

Commands:
  mine                     Start the miner (or rely on mining.enabled)
  proof --coin-id <hex>    Request and verify a coin’s proof
  proof-server [--bind]    Serve HTTP proofs for clients (GET /proof/<coin_hex>)
  send --to <hex> --amount <u64>
  balance                  Show wallet balance
  history                  Show wallet transaction history
```

# This is essential for nodcd es running behind a NAT. 193.71.140.215 -/ip4/34.51.215.84/udp/31000/quic-v1/p2p/12D3KooWMPtzmPYGLq58SeCMv5x2YAEqb8ggc3htDYEjG7XZvy1z",

### 13) Example end-to-end (two nodes)
1. On VM A (public), set `net.public_ip`, open UDP 31000.
2. Start node A; note its Peer ID from logs.
3. On node B, add A’s multiaddr to `net.bootstrap` and start B.
4. Watch logs: B requests epochs, stores anchors, and both begin mining new epochs together.
5. Check metrics at `http://127.0.0.1:9100` on each host (or via Prometheus).


