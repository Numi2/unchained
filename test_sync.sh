#!/bin/bash

echo "=== unchained Network Synchronization Test ==="
echo ""

# Check if config.toml exists
if [ ! -f "config.toml" ]; then
    echo "❌ Error: config.toml not found in current directory"
    echo "   Please run this script from the unchainedcoin_full directory"
    exit 1
fi

# Check if the binary exists
if [ ! -f "target/debug/unchainedcoin" ]; then
    echo "❌ Error: unchainedcoin binary not found"
    echo "   Please run 'cargo build' first"
    exit 1
fi

echo "✅ Found config.toml and binary"
echo ""

# Check bootstrap configuration
echo "📋 Checking bootstrap configuration..."
BOOTSTRAP_COUNT=$(grep -c "bootstrap" config.toml)
if [ "$BOOTSTRAP_COUNT" -eq 0 ]; then
    echo "❌ No bootstrap peers configured in config.toml"
    echo "   Please add bootstrap peers to join an existing network"
    exit 1
else
    echo "✅ Found $BOOTSTRAP_COUNT bootstrap peer(s) configured"
fi

echo ""
echo "🔍 Bootstrap peers:"
grep -A 5 "bootstrap" config.toml | grep -E "(bootstrap|#)" | sed 's/^/   /'

echo ""
echo "📡 Network configuration:"
grep -A 3 "\[net\]" config.toml | grep -E "(listen_port|max_peers)" | sed 's/^/   /'

echo ""
echo "=== Test Instructions ==="
echo ""
echo "1. First, start the bootstrap peer (the one with the peer ID in config.toml):"
echo "   cargo run"
echo ""
echo "2. Wait for it to start mining and create some epochs"
echo ""
echo "3. Then start this node in a new terminal:"
echo "   cargo run"
echo ""
echo "4. Watch for the synchronization messages:"
echo "   - '🔄 Initial network synchronization phase...'"
echo "   - '✅ Network synchronization complete!'"
echo "   - '🤝 Connected to peer...'"
echo ""
echo "5. If synchronization fails, check:"
echo "   - Bootstrap peer is running and accessible"
echo "   - Peer ID in config.toml matches the running peer"
echo "   - Port 7777 is open and accessible"
echo "   - Firewall settings allow the connection"
echo ""
echo "=== Expected Behavior ==="
echo ""
echo "✅ SUCCESS: New node should start from the same epoch as the bootstrap peer"
echo "❌ FAILURE: New node starts from epoch 0 (creates its own chain)"
echo ""
echo "The synchronization timeout is 30 seconds. If it times out, the node will"
echo "start its own chain from epoch 0." 