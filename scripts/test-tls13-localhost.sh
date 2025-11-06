#!/bin/bash
# Test TLS 1.3 against local OpenSSL server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🧪 TLS 1.3 Localhost Testing"
echo "============================="
echo ""

# Check if server is running
if ! nc -z 127.0.0.1 4433 2>/dev/null; then
    echo "⚠️  OpenSSL server not running on port 4433"
    echo ""
    echo "Please start the server first:"
    echo "  ./scripts/setup-tls13-server.sh"
    echo ""
    echo "In another terminal, then run this script again."
    exit 1
fi

echo "✓ Server is running on localhost:4433"
echo ""

# Build the client
echo "🔨 Building TLS 1.3 client..."
cd "$PROJECT_DIR"
cargo build --example tls13-localhost-test --quiet

echo "✓ Client built"
echo ""

# Run the test
echo "🚀 Running TLS 1.3 handshake test..."
echo "===================================="
echo ""

cargo run --example tls13-localhost-test 2>&1

echo ""
echo "===================================="
echo "✅ Test completed!"
echo ""
echo "Check server output for detailed protocol messages."
