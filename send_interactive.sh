#!/bin/bash

echo "💰 Interactive Send Helper"
echo "=========================="
echo ""

# Function to read long address
read_long_address() {
    echo "📤 Enter the stealth address:"
    echo "   (You can paste it in parts if it's very long)"
    echo "   (Press Enter twice when done)"
    echo ""
    
    local address=""
    local line_count=0
    
    while true; do
        line_count=$((line_count + 1))
        read -p "   Line $line_count: " line
        
        if [ -z "$line" ]; then
            if [ $line_count -eq 1 ]; then
                echo "   ❌ Address cannot be empty"
                exit 1
            fi
            break
        fi
        
        address="$address$line"
        echo "   📝 Added line $line_count (${#address} chars total)"
    done
    
    echo "$address"
}

# Read the address
STEALTH_ADDRESS=$(read_long_address)

# Read the amount
echo ""
read -p "💰 Enter amount to send: " AMOUNT

# Validate amount
if ! [[ "$AMOUNT" =~ ^[0-9]+$ ]] || [ "$AMOUNT" -eq 0 ]; then
    echo "❌ Invalid amount. Please enter a positive number."
    exit 1
fi

# Show summary
echo ""
echo "📋 Transaction Summary:"
echo "  Recipient: ${STEALTH_ADDRESS:0:50}..."
echo "  Amount: $AMOUNT coins"
echo ""

read -p "✅ Press Enter to confirm and send, or Ctrl+C to cancel: " confirm

# Save address to temporary file
echo "$STEALTH_ADDRESS" > /tmp/stealth_address_temp.txt

# Run the send command
echo ""
echo "🚀 Sending transaction..."
cargo run --release --bin unchained send << EOF
file:/tmp/stealth_address_temp.txt
$AMOUNT

EOF

# Clean up
rm -f /tmp/stealth_address_temp.txt
