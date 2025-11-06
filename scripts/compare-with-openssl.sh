#!/bin/bash
# Complete comparison: OpenSSL vs Our Implementation
# This script runs both and compares the keys

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔬 TLS 1.3 Implementation Comparison"
echo "===================================="
echo ""

# Step 1: Start server
echo "1️⃣  Starting OpenSSL server..."
./scripts/setup-tls13-server.sh > /tmp/openssl_server.log 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > /tmp/server_pid.txt
sleep 2

if ! nc -z 127.0.0.1 4433 2>/dev/null; then
    echo "❌ Server failed to start"
    exit 1
fi
echo "   ✓ Server running (PID: $SERVER_PID)"
echo ""

# Step 2: Run OpenSSL client to capture reference keys
echo "2️⃣  Running OpenSSL client (reference)..."
./scripts/capture-openssl-keys.sh > /tmp/openssl_keys.txt 2>&1
echo "   ✓ OpenSSL keys captured"
echo ""

# Step 3: Run our implementation
echo "3️⃣  Running our TLS 1.3 client..."
cargo run --example tls13-localhost-test 2>&1 | tee /tmp/our_client_output.txt | grep -E "(handshake traffic secret|Transcript hash|Error)" || true
echo ""

# Step 4: Extract and compare
echo "4️⃣  Comparing secrets..."
echo "=================================="
echo ""

# Extract OpenSSL secrets (they're in hex format)
if [ -f /tmp/sslkeylog.txt ]; then
    echo "📋 OpenSSL Secrets (from SSLKEYLOGFILE):"
    cat /tmp/sslkeylog.txt
    echo ""
fi

# Extract our secrets
echo "📋 Our Implementation Secrets:"
grep "Server handshake traffic secret:" /tmp/our_client_output.txt || echo "  (not found)"
grep "Client handshake traffic secret:" /tmp/our_client_output.txt || echo "  (not found)"
grep "Transcript hash:" /tmp/our_client_output.txt || echo "  (not found)"
echo ""

# Show error if any
if grep -q "Error:" /tmp/our_client_output.txt; then
    echo "❌ Our client error:"
    grep "Error:" /tmp/our_client_output.txt
    echo ""
fi

# Step 5: Convert format for easy comparison
echo "5️⃣  Converting for comparison..."
echo "=================================="
echo ""

if [ -f /tmp/sslkeylog.txt ]; then
    # Extract hex strings and convert to byte array format
    if grep -q "SERVER_HANDSHAKE_TRAFFIC_SECRET" /tmp/sslkeylog.txt; then
        SERVER_HS_HEX=$(grep "SERVER_HANDSHAKE_TRAFFIC_SECRET" /tmp/sslkeylog.txt | awk '{print $3}')
        echo "OpenSSL Server Handshake Secret (hex):"
        echo "  $SERVER_HS_HEX"

        # Convert to byte array format
        echo ""
        echo "  As byte array:"
        echo -n "  ["
        echo "$SERVER_HS_HEX" | sed 's/../0x&, /g' | sed 's/, $//'
        echo "]"
        echo ""
    fi

    if grep -q "CLIENT_HANDSHAKE_TRAFFIC_SECRET" /tmp/sslkeylog.txt; then
        CLIENT_HS_HEX=$(grep "CLIENT_HANDSHAKE_TRAFFIC_SECRET" /tmp/sslkeylog.txt | awk '{print $3}')
        echo "OpenSSL Client Handshake Secret (hex):"
        echo "  $CLIENT_HS_HEX"

        echo ""
        echo "  As byte array:"
        echo -n "  ["
        echo "$CLIENT_HS_HEX" | sed 's/../0x&, /g' | sed 's/, $//'
        echo "]"
        echo ""
    fi
fi

# Cleanup
echo ""
echo "6️⃣  Cleanup..."
kill $SERVER_PID 2>/dev/null || true
echo "   ✓ Server stopped"
echo ""

echo "=================================="
echo "✅ Comparison complete!"
echo ""
echo "📁 Output files:"
echo "   - /tmp/sslkeylog.txt - OpenSSL secrets"
echo "   - /tmp/openssl_client_output.txt - OpenSSL messages"
echo "   - /tmp/our_client_output.txt - Our client output"
echo "   - /tmp/openssl_server.log - Server log"
echo ""
echo "🔍 Compare the byte arrays above with our output!"
