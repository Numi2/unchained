#!/bin/bash

# UnchainedCoin Cross-Platform Release Builder
# This script creates distribution-ready binaries for multiple platforms

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if cross compilation tools are available
check_cross_compilation() {
    if ! command -v cross &> /dev/null; then
        print_warning "cross not found. Installing..."
        cargo install cross --git https://github.com/cross-rs/cross
    fi
}

# Build for a specific target
build_target() {
    local target=$1
    local output_name=$2
    
    print_status "Building for $target..."
    
    if command -v cross &> /dev/null; then
        cross build --release --target $target
    else
        print_warning "Using regular cargo build (may not work for all targets)"
        cargo build --release --target $target
    fi
    
    # Copy and rename binary
    local src_path="target/$target/release/"
    local binary_name="unchainedcoin"
    
    if [[ "$target" == *"windows"* ]]; then
        binary_name="unchainedcoin.exe"
    fi
    
    if [ -f "$src_path$binary_name" ]; then
        mkdir -p "releases/$target"
        cp "$src_path$binary_name" "releases/$target/$output_name"
        print_status "✅ Built $output_name for $target"
    else
        print_error "❌ Failed to build for $target"
        return 1
    fi
}

# Create release packages
create_packages() {
    print_status "Creating release packages..."
    
    # Create release directory
    rm -rf releases
    mkdir -p releases
    
    # Build for different targets
    print_status "🔨 Building cross-platform binaries..."
    
    # macOS (Intel)
    if build_target "x86_64-apple-darwin" "unchainedcoin-macos-intel"; then
        create_macos_package "x86_64-apple-darwin" "intel"
    fi
    
    # macOS (Apple Silicon)
    if build_target "aarch64-apple-darwin" "unchainedcoin-macos-arm64"; then
        create_macos_package "aarch64-apple-darwin" "arm64"
    fi
    
    # Windows (64-bit)
    if build_target "x86_64-pc-windows-gnu" "unchainedcoin-windows-x64.exe"; then
        create_windows_package "x86_64-pc-windows-gnu"
    fi
    
    # Linux (64-bit) - for completeness
    if build_target "x86_64-unknown-linux-gnu" "unchainedcoin-linux-x64"; then
        create_linux_package "x86_64-unknown-linux-gnu"
    fi
    
    print_status "✅ All packages created in releases/ directory"
}

# Create macOS package
create_macos_package() {
    local target=$1
    local arch=$2
    local pkg_dir="releases/unchainedcoin-macos-$arch"
    
    mkdir -p "$pkg_dir"
    
    # Copy binary
    cp "releases/$target/unchainedcoin-macos-$arch" "$pkg_dir/unchainedcoin"
    chmod +x "$pkg_dir/unchainedcoin"
    
    # Copy configuration
    cp config.toml "$pkg_dir/config.toml"
    
    # Create startup script
    cat > "$pkg_dir/start-mining.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🚀 Starting UnchainedCoin Miner..."
echo "📁 Working directory: $(pwd)"

# Create data directory
mkdir -p data

# Check if this is the first run
if [ ! -f "config.toml" ]; then
    echo "❌ Config file not found!"
    exit 1
fi

# Set executable permission
chmod +x ./unchainedcoin

# Start the miner
echo "⛏️  Starting mining process..."
./unchainedcoin --config config.toml

echo "👋 Mining stopped"
EOF
    chmod +x "$pkg_dir/start-mining.sh"
    
    # Create README
    create_readme "$pkg_dir" "macos"
    
    # Create zip package
    cd releases
    zip -r "unchainedcoin-macos-$arch.zip" "unchainedcoin-macos-$arch/"
    cd ..
    
    print_status "📦 Created macOS package: releases/unchainedcoin-macos-$arch.zip"
}

# Create Windows package
create_windows_package() {
    local target=$1
    local pkg_dir="releases/unchainedcoin-windows-x64"
    
    mkdir -p "$pkg_dir"
    
    # Copy binary
    cp "releases/$target/unchainedcoin-windows-x64.exe" "$pkg_dir/unchainedcoin.exe"
    
    # Copy configuration
    cp config.toml "$pkg_dir/config.toml"
    
    # Create startup batch file
    cat > "$pkg_dir/start-mining.bat" << 'EOF'
@echo off
cd /d "%~dp0"

echo 🚀 Starting UnchainedCoin Miner...
echo 📁 Working directory: %CD%

REM Create data directory
if not exist "data" mkdir data

REM Check if config exists
if not exist "config.toml" (
    echo ❌ Config file not found!
    pause
    exit /b 1
)

echo ⛏️ Starting mining process...
unchainedcoin.exe --config config.toml

echo 👋 Mining stopped
pause
EOF
    
    # Create PowerShell script for advanced users
    cat > "$pkg_dir/start-mining.ps1" << 'EOF'
# UnchainedCoin Miner - PowerShell Script
Set-Location $PSScriptRoot

Write-Host "🚀 Starting UnchainedCoin Miner..." -ForegroundColor Green
Write-Host "📁 Working directory: $PWD" -ForegroundColor Yellow

# Create data directory
if (!(Test-Path "data")) {
    New-Item -ItemType Directory -Path "data"
}

# Check if config exists
if (!(Test-Path "config.toml")) {
    Write-Host "❌ Config file not found!" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "⛏️ Starting mining process..." -ForegroundColor Green
& .\unchainedcoin.exe --config config.toml

Write-Host "👋 Mining stopped" -ForegroundColor Yellow
Read-Host "Press Enter to exit"
EOF
    
    # Create README
    create_readme "$pkg_dir" "windows"
    
    # Create zip package
    cd releases
    zip -r "unchainedcoin-windows-x64.zip" "unchainedcoin-windows-x64/"
    cd ..
    
    print_status "📦 Created Windows package: releases/unchainedcoin-windows-x64.zip"
}

# Create Linux package
create_linux_package() {
    local target=$1
    local pkg_dir="releases/unchainedcoin-linux-x64"
    
    mkdir -p "$pkg_dir"
    
    # Copy binary
    cp "releases/$target/unchainedcoin-linux-x64" "$pkg_dir/unchainedcoin"
    chmod +x "$pkg_dir/unchainedcoin"
    
    # Copy configuration
    cp config.toml "$pkg_dir/config.toml"
    
    # Create startup script
    cat > "$pkg_dir/start-mining.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🚀 Starting UnchainedCoin Miner..."
echo "📁 Working directory: $(pwd)"

# Create data directory
mkdir -p data

# Check if this is the first run
if [ ! -f "config.toml" ]; then
    echo "❌ Config file not found!"
    exit 1
fi

# Set executable permission
chmod +x ./unchainedcoin

# Start the miner
echo "⛏️  Starting mining process..."
./unchainedcoin --config config.toml

echo "👋 Mining stopped"
EOF
    chmod +x "$pkg_dir/start-mining.sh"
    
    # Create README
    create_readme "$pkg_dir" "linux"
    
    # Create tar.gz package
    cd releases
    tar -czf "unchainedcoin-linux-x64.tar.gz" "unchainedcoin-linux-x64/"
    cd ..
    
    print_status "📦 Created Linux package: releases/unchainedcoin-linux-x64.tar.gz"
}

# Create platform-specific README
create_readme() {
    local pkg_dir=$1
    local platform=$2
    
    cat > "$pkg_dir/README.txt" << EOF
# UnchainedCoin Miner - $platform Distribution

## Quick Start

### For Bootstrap/Seed Node:
1. Double-click 'start-mining' script
2. Note your Peer ID from the output
3. Share your bootstrap address with other miners

### For Regular Miners:
1. Edit config.toml file
2. Add bootstrap nodes to the [net] section:
   bootstrap = ["/ip4/SEED_IP/udp/7777/quic-v1/p2p/SEED_PEER_ID"]
3. Double-click 'start-mining' script

## Files Included:
- unchainedcoin(.exe) - Main mining program
- config.toml - Configuration file
- start-mining script - Easy startup
- README.txt - This file

## Configuration:

### Basic Settings (config.toml):
- Change mining.enabled to false to run as network node only
- Adjust mining.mem_kib for memory usage (32768 = 32MB)
- Modify epoch.seconds for different block times

### Network Setup:
- Default port: 7777 (UDP) - make sure it's open in firewall
- Metrics available at: http://localhost:9100/metrics

## Troubleshooting:

### Common Issues:
1. "Port already in use" - Another miner is running or port 7777 is blocked
2. "Permission denied" - Run as administrator (Windows) or use chmod +x (Mac/Linux)
3. "Connection failed" - Check bootstrap node addresses and firewall settings

### Performance Tips:
- More CPU cores = increase mining.lanes in config.toml
- More RAM = increase mining.mem_kib (up to max_mem_kib)
- SSD storage recommended for better performance

## Security Notes:
- Wallet files are encrypted and stored in data/ directory
- Backup your data/ directory to preserve your coins
- Use a strong passphrase when prompted

## Support:
- Check logs for detailed error messages
- Metrics dashboard: http://localhost:9100/metrics
- Keep your miner updated for latest security fixes

Happy Mining! ⛏️
EOF
}

# Main execution
main() {
    print_status "🏗️  Building UnchainedCoin release packages..."
    
    # Check prerequisites
    if ! command -v cargo &> /dev/null; then
        print_error "Rust/Cargo not found. Please install Rust first."
        exit 1
    fi
    
    if ! command -v zip &> /dev/null; then
        print_error "zip command not found. Please install zip utility."
        exit 1
    fi
    
    # Optional: check for cross compilation
    check_cross_compilation
    
    # Create packages
    create_packages
    
    print_status "🎉 Release build complete!"
    print_status "📦 Packages available in releases/ directory:"
    ls -la releases/*.zip releases/*.tar.gz 2>/dev/null || true
    
    print_status "🚀 Ready for distribution!"
}

# Run main function
main "$@"
EOF