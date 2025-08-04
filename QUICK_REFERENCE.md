# 🚀 Quick Reference Card
## Unchained Blockchain Node Commands

---

## 🏗️ First Node (Genesis Node)

### Setup
```bash
# Run setup script
./setup_node.sh
# Choose option 1 for Genesis node

# Or manually configure config.toml with empty bootstrap = []
```

### Start First Node
```bash
cargo run --release --bin unchainedcoin mine
```

### Get Your Peer ID
```bash
# In a new terminal while first node is running
cargo run --release --bin inspect_db
```

---

## 🔗 Second Node

### Setup
```bash
# Run setup script
./setup_node.sh
# Choose option 2 for Second node
# Enter first node's IP and Peer ID when prompted
```

### Start Second Node
```bash
cargo run --release --bin unchainedcoin mine
```

---

## 📊 Monitoring

### Check Node Status
```bash
cargo run --release --bin inspect_db
```

### View Metrics
- First node: `http://FIRST_NODE_IP:9100`
- Second node: `http://SECOND_NODE_IP:9101`

### Stop Node Safely
```bash
# Press Ctrl+C in the terminal running the node
```

---

## 🔧 Troubleshooting

### Common Issues
1. **Can't connect**: Check firewall, verify IP and Peer ID
2. **Port in use**: Change `listen_port` in config.toml
3. **Sync timeout**: Restart first node, check network connectivity

### Network Commands
```bash
# Check if port is open
netstat -tuln | grep 7777

# Test connectivity
ping FIRST_NODE_IP

# Check firewall (Ubuntu/Debian)
sudo ufw status
```

---

## 📋 Important Information

### Default Ports
- **P2P**: 7777 (first node), 7778 (second node)
- **Metrics**: 9100 (first node), 9101 (second node)

### Data Locations
- **First node**: `../blockchain_data`
- **Second node**: `../blockchain_data_node2`

### Expected Output
- **First node**: "Network synchronization timeout" → "Creating epoch #0"
- **Second node**: "Network synchronization complete" → "Starting from epoch X"

---

## 🎯 Success Indicators

✅ **Both nodes show same epoch numbers**  
✅ **Both nodes receive same anchors**  
✅ **Connection messages appear**  
✅ **Mining activity on both nodes**  

---

## 📞 Emergency Commands

### Kill All Node Processes
```bash
pkill -f unchainedcoin
```

### Reset Database (DANGER - loses all data)
```bash
rm -rf ../blockchain_data*
```

### Check Logs
```bash
# Look for error messages in terminal output
# Check for connection issues, mining problems, etc.
```