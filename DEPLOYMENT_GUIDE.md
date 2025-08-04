# 🚀 Unchained Blockchain Deployment Guide
## Idiot-Proof Guide for Running First Node and Connecting Second Node

This guide will walk you through deploying your first blockchain node and connecting a second node from another machine.

---

## 📋 Prerequisites

### For Both Machines:
- **Rust** (latest stable version)
- **Git**
- **Network access** (both machines need to communicate)

### To install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

---

## 🏗️ Step 1: Prepare Your First Node (Genesis Node)

### 1.1 Clone and Build the Project
```bash
# Clone the repository
git clone <your-repo-url>
cd unchainedcoin

# Build the project in release mode
cargo build --release
```

### 1.2 Configure the First Node
Edit `config.toml` to set up your first node:

```toml
[net]
# Port to listen on for P2P connections
listen_port = 7777
# Maximum number of peer connections
max_peers = 10000
# Connection timeout in seconds
connection_timeout_secs = 30

# IMPORTANT: Leave bootstrap empty for the first node
bootstrap = []

[storage]
# Path where blockchain data will be stored
path = "../blockchain_data"

[epoch]
# Duration of each epoch in seconds 
seconds = 22
# Target number of leading zeros for proof-of-work difficulty
target_leading_zeros = 1
# Target number of coins per epoch for difficulty adjustment
target_coins_per_epoch = 3
# How often to retarget (every N epochs)
retarget_interval = 2000
# Maximum difficulty adjustment factor 
max_difficulty_adjustment = 1.05

[mining]
# Enable mining by default
enabled = true
# Memory usage for Argon2 hashing in KiB
mem_kib = 16192
# Number of parallel lanes for Argon2
lanes = 2
# Minimum memory in KiB
min_mem_kib = 16192
# Maximum memory in KiB 
max_mem_kib = 512007
# Memory adjustment factor 
max_memory_adjustment = 1.02
# Heartbeat interval in seconds
heartbeat_interval_secs = 140
# Maximum consecutive failures before restarting miner
max_consecutive_failures = 3
# Maximum mining attempts per epoch
max_mining_attempts = 50000

[metrics]
# Metrics endpoint
bind = "0.0.0.0:9100"
```

### 1.3 Find Your Machine's IP Address
```bash
# On Linux/Mac
ip addr show | grep "inet " | grep -v 127.0.0.1

# Or use this command
hostname -I
```

**Note down your IP address** - you'll need it for the second node.

---

## 🚀 Step 2: Start the First Node

### 2.1 Run the First Node
```bash
# Start the node with mining enabled
cargo run --release --bin unchainedcoin mine
```

### 2.2 What You Should See
```
--- unchained Node ---
🗄️  Database opened at '../blockchain_data'
🔄 Initial network synchronization phase...
   Waiting for peers to share current blockchain state...
   Timeout: 60 seconds
⚠️  Network synchronization timeout after X checks.
   This node will create a new chain.
🚀 unchained node is running!
   📡 P2P listening on port 7777
   📊 Metrics available on http://0.0.0.0:9100
   ⛏️  Mining: enabled
   Press Ctrl+C to stop
```

### 2.3 Let It Mine for a Few Epochs
Wait for the node to create at least 2-3 epochs (about 1-2 minutes). You should see output like:
```
🏭 Creating epoch #0 with X coins in buffer
🏭 Creating epoch #1 with X coins in buffer
🏭 Creating epoch #2 with X coins in buffer
```

### 2.4 Get Your Node's Peer ID
While the first node is running, open a new terminal and run:
```bash
# This will show your node's peer ID
cargo run --release --bin inspect_db
```

Look for output that shows your peer ID. It will look something like:
```
Peer ID: 12D3KooWGGzPNmYnePdAYhAE117hT4ViL8p2negT96MpRjTYjLmV
```

**Note down this Peer ID** - you'll need it for the second node.

---

## 🔗 Step 3: Configure and Start the Second Node

### 3.1 On Your Second Machine (MacBook)
```bash
# Clone the same repository
git clone <your-repo-url>
cd unchainedcoin

# Build the project
cargo build --release
```

### 3.2 Configure the Second Node
Edit `config.toml` on the second machine:

```toml
[net]
# Port to listen on for P2P connections
listen_port = 7778  # Use a different port
# Maximum number of peer connections
max_peers = 10000
# Connection timeout in seconds
connection_timeout_secs = 30

# IMPORTANT: Add the first node as bootstrap peer
# Replace FIRST_NODE_IP with the actual IP address of your first node
# Replace PEER_ID with the actual peer ID from step 2.4
bootstrap = [
    "/ip4/FIRST_NODE_IP/udp/7777/quic-v1/p2p/PEER_ID",
]

[storage]
# Use a different path for the second node
path = "../blockchain_data_node2"

[epoch]
# Same settings as first node
seconds = 22
target_leading_zeros = 1
target_coins_per_epoch = 3
retarget_interval = 2000
max_difficulty_adjustment = 1.05

[mining]
# You can enable or disable mining on the second node
enabled = true
mem_kib = 16192
lanes = 2
min_mem_kib = 16192
max_mem_kib = 512007
max_memory_adjustment = 1.02
heartbeat_interval_secs = 140
max_consecutive_failures = 3
max_mining_attempts = 50000

[metrics]
# Use a different port for metrics
bind = "0.0.0.0:9101"
```

### 3.3 Replace Placeholders
In the `bootstrap` section, replace:
- `FIRST_NODE_IP` with the IP address from step 1.3
- `PEER_ID` with the peer ID from step 2.4

Example:
```toml
bootstrap = [
    "/ip4/192.168.1.100/udp/7777/quic-v1/p2p/12D3KooWGGzPNmYnePdAYhAE117hT4ViL8p2negT96MpRjTYjLmV",
]
```

### 3.4 Start the Second Node
```bash
# Start the second node
cargo run --release --bin unchainedcoin mine
```

### 3.5 What You Should See on the Second Node
```
--- unchained Node ---
🗄️  Database opened at '../blockchain_data_node2'
🔄 Initial network synchronization phase...
   Waiting for peers to share current blockchain state...
   Timeout: 60 seconds
✅ Network synchronization complete! Starting from epoch X
   Received anchor #X with Y coins and Z cumulative work
🚀 unchained node is running!
   📡 P2P listening on port 7778
   📊 Metrics available on http://0.0.0.0:9101
   ⛏️  Mining: enabled
   Press Ctrl+C to stop
```

---

## ✅ Step 4: Verify the Connection

### 4.1 Check Network Status
On both nodes, you should see messages like:
```
📡 Connected to peer: PEER_ID
📡 Gossiping anchor to network
```

### 4.2 Monitor Blockchain Progress
Both nodes should now be creating epochs together. You should see:
- Both nodes creating the same epoch numbers
- Both nodes receiving the same anchors
- Both nodes mining coins for the same epochs

### 4.3 Check Metrics (Optional)
You can check the metrics endpoints:
- First node: `http://FIRST_NODE_IP:9100`
- Second node: `http://SECOND_NODE_IP:9101`

---

## 🔧 Troubleshooting

### Problem: Second node can't connect to first node
**Solutions:**
1. **Check firewall settings** - make sure port 7777 is open on the first node
2. **Verify IP address** - ensure you're using the correct IP address
3. **Check network connectivity** - try pinging the first node from the second machine
4. **Verify peer ID** - make sure the peer ID is correct

### Problem: Second node shows "Network synchronization timeout"
**Solutions:**
1. **Check bootstrap configuration** - verify the bootstrap entry is correct
2. **Restart first node** - sometimes the first node needs to be restarted
3. **Check network connectivity** - ensure both machines can communicate

### Problem: Nodes are not syncing epochs
**Solutions:**
1. **Wait longer** - initial sync can take a few minutes
2. **Check logs** - look for error messages in both terminals
3. **Restart both nodes** - sometimes a clean restart helps

### Problem: Port already in use
**Solutions:**
1. **Change port** - modify `listen_port` in config.toml
2. **Kill existing process** - find and stop any existing node processes

---

## 📊 Monitoring Your Network

### Check Node Status
```bash
# On either machine, check the database
cargo run --release --bin inspect_db
```

### View Network Logs
Both nodes will show real-time logs of:
- Peer connections
- Epoch creation
- Coin mining
- Network synchronization

### Stop Nodes Safely
Press `Ctrl+C` on either node to stop it gracefully. The node will:
- Save current state
- Close database connections
- Shutdown cleanly

---

## 🎉 Congratulations!

You now have a working two-node blockchain network! Both nodes should be:
- ✅ Connected to each other
- ✅ Mining coins together
- ✅ Creating synchronized epochs
- ✅ Sharing blockchain data

The network will automatically:
- Adjust mining difficulty based on coin production
- Retarget memory requirements
- Handle peer discovery and connection
- Maintain consensus across both nodes

---

## 🔄 Next Steps

1. **Add more nodes** - repeat the process for additional machines
2. **Monitor performance** - check metrics endpoints for network health
3. **Adjust configuration** - modify mining parameters as needed
4. **Backup data** - regularly backup the blockchain_data directories

---

## 📞 Need Help?

If you encounter issues:
1. Check the troubleshooting section above
2. Verify all configuration settings
3. Ensure network connectivity between machines
4. Check that ports are not blocked by firewalls
5. Review the logs for specific error messages

Happy mining! 🚀⛏️