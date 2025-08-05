#!/bin/bash

echo "=== Network Connectivity Test ==="
echo ""

# Get local IP
LOCAL_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | head -1 | awk '{print $2}')
echo "🔍 Local IP: $LOCAL_IP"

# Check if port 7777 is open
echo ""
echo "📡 Checking port 7777..."
if lsof -i :7777 > /dev/null 2>&1; then
    echo "✅ Port 7777 is currently in use"
    lsof -i :7777
else
    echo "❌ Port 7777 is not currently in use"
fi

echo ""
echo "🌐 Network interfaces:"
ifconfig | grep "inet " | grep -v 127.0.0.1

echo ""
echo "=== Manual Network Tests ==="
echo ""
echo "To test connectivity between MacBooks:"
echo ""
echo "1. On MacBook 1 (this one), run:"
echo "   nc -l 7777"
echo ""
echo "2. On MacBook 2, run:"
echo "   nc -v $LOCAL_IP 7777"
echo ""
echo "3. If connection succeeds, you should see:"
echo "   - MacBook 1: 'Connection from [IP]'"
echo "   - MacBook 2: 'Connection to [IP] port 7777 succeeded'"
echo ""
echo "4. If connection fails, check:"
echo "   - Firewall settings on both MacBooks"
echo "   - Network connectivity (ping test)"
echo "   - Router settings"
echo ""
echo "=== Firewall Check ==="
echo ""
echo "Check if port 7777 is blocked by firewall:"
echo "sudo pfctl -s rules | grep 7777"
echo ""
echo "If no rules found, port 7777 should be open by default." 