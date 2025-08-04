#!/bin/bash

# Unchained Blockchain Node Setup Script
# This script helps you quickly configure a node

set -e

echo "🚀 Unchained Blockchain Node Setup"
echo "=================================="

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust first:"
    echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "   source ~/.cargo/env"
    exit 1
fi

echo "✅ Rust is installed"

# Build the project
echo "🔨 Building project..."
cargo build --release

# Get machine IP
echo "🌐 Getting machine IP address..."
MACHINE_IP=$(hostname -I | awk '{print $1}')
echo "   Machine IP: $MACHINE_IP"

# Ask user for node type
echo ""
echo "What type of node are you setting up?"
echo "1) First node (Genesis node)"
echo "2) Second node (Connect to existing network)"
read -p "Enter choice (1 or 2): " NODE_TYPE

if [ "$NODE_TYPE" = "1" ]; then
    echo "🏗️  Setting up Genesis node..."
    
    # Configure for first node
    cat > config.toml << EOF
# unchained Configuration File - Genesis Node

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
EOF

    echo "✅ Genesis node configured!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Start the node: cargo run --release --bin unchainedcoin mine"
    echo "2. Let it mine for 2-3 epochs"
    echo "3. Get your peer ID: cargo run --release --bin inspect_db"
    echo "4. Share your IP ($MACHINE_IP) and peer ID with the second node"

elif [ "$NODE_TYPE" = "2" ]; then
    echo "🔗 Setting up Second node..."
    
    # Get connection details
    read -p "Enter the IP address of the first node: " FIRST_NODE_IP
    read -p "Enter the peer ID of the first node: " PEER_ID
    
    # Configure for second node
    cat > config.toml << EOF
# unchained Configuration File - Second Node

[net]
# Port to listen on for P2P connections
listen_port = 7778
# Maximum number of peer connections
max_peers = 10000
# Connection timeout in seconds
connection_timeout_secs = 30

# IMPORTANT: Add the first node as bootstrap peer
bootstrap = [
    "/ip4/$FIRST_NODE_IP/udp/7777/quic-v1/p2p/$PEER_ID",
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
EOF

    echo "✅ Second node configured!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Make sure the first node is running"
    echo "2. Start this node: cargo run --release --bin unchainedcoin mine"
    echo "3. Watch for successful connection messages"

else
    echo "❌ Invalid choice. Please run the script again and choose 1 or 2."
    exit 1
fi

echo ""
echo "🎉 Setup complete! Check DEPLOYMENT_GUIDE.md for detailed instructions."