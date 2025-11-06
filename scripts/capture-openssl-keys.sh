#!/bin/bash
# Capture TLS keys from OpenSSL client for comparison
# This uses SSLKEYLOGFILE to export all TLS 1.3 secrets

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYLOG_FILE="/tmp/sslkeylog.txt"

echo "🔑 Capturing OpenSSL TLS 1.3 Keys"
echo "================================="
echo ""

# Clean previous keylog
rm -f "$KEYLOG_FILE"

echo "📡 Connecting to localhost:4433 with OpenSSL client..."
echo "   (SSLKEYLOGFILE will capture all secrets)"
echo ""

# Connect with OpenSSL client and capture keys
# -msg shows all protocol messages
# -keylogfile captures secrets
# SSLKEYLOGFILE environment variable exports keys
SSLKEYLOGFILE="$KEYLOG_FILE" echo "" | timeout 5 openssl s_client \
    -connect localhost:4433 \
    -tls1_3 \
    -ciphersuites TLS_AES_128_GCM_SHA256 \
    -msg \
    2>&1 | tee /tmp/openssl_client_output.txt

echo ""
echo "================================="
echo ""

if [ -f "$KEYLOG_FILE" ]; then
    echo "✅ Keys captured to $KEYLOG_FILE"
    echo ""
    cat "$KEYLOG_FILE"
    echo ""

    echo "🔍 Parsing secrets..."
    echo ""

    # Extract CLIENT_HANDSHAKE_TRAFFIC_SECRET
    if grep -q "CLIENT_HANDSHAKE_TRAFFIC_SECRET" "$KEYLOG_FILE"; then
        CLIENT_HS=$(grep "CLIENT_HANDSHAKE_TRAFFIC_SECRET" "$KEYLOG_FILE" | awk '{print $3}')
        echo "CLIENT_HANDSHAKE_TRAFFIC_SECRET:"
        echo "  $CLIENT_HS"
        echo ""
    fi

    # Extract SERVER_HANDSHAKE_TRAFFIC_SECRET
    if grep -q "SERVER_HANDSHAKE_TRAFFIC_SECRET" "$KEYLOG_FILE"; then
        SERVER_HS=$(grep "SERVER_HANDSHAKE_TRAFFIC_SECRET" "$KEYLOG_FILE" | awk '{print $3}')
        echo "SERVER_HANDSHAKE_TRAFFIC_SECRET:"
        echo "  $SERVER_HS"
        echo ""
    fi

    echo "📊 Now compare these with our implementation's output!"
    echo ""
    echo "Our implementation shows:"
    echo "  Server handshake traffic secret: [hex bytes]"
    echo "  Client handshake traffic secret: [hex bytes]"
    echo ""
    echo "Convert OpenSSL's hex string to byte array format to compare."
else
    echo "❌ No keylog file created"
    echo "   Check if server is running: nc -z 127.0.0.1 4433"
fi
