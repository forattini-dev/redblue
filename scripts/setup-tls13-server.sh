#!/bin/bash
# Setup TLS 1.3 test server with OpenSSL
# This creates a controlled environment for testing our TLS 1.3 implementation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../test-certs"

echo "🔐 Setting up TLS 1.3 test server..."

# Create directory for certificates
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Generate self-signed certificate if it doesn't exist
if [ ! -f "server.key" ] || [ ! -f "server.crt" ]; then
    echo "📜 Generating self-signed certificate..."

    # Generate private key
    openssl genrsa -out server.key 2048

    # Generate self-signed certificate (valid for 365 days)
    openssl req -new -x509 -key server.key -out server.crt -days 365 \
        -subj "/C=US/ST=Test/L=Test/O=RedBlue/OU=Security/CN=localhost"

    echo "✅ Certificate created:"
    echo "   Key:  $CERT_DIR/server.key"
    echo "   Cert: $CERT_DIR/server.crt"
else
    echo "✅ Using existing certificate"
fi

echo ""
echo "🚀 Starting OpenSSL TLS 1.3 server..."
echo "   Port: 4433"
echo "   Cipher: TLS_AES_128_GCM_SHA256"
echo ""
echo "Server output will show all TLS messages with -msg flag"
echo "Press Ctrl+C to stop"
echo ""
echo "============================================"

# Start OpenSSL server with TLS 1.3 only
# -msg shows all TLS protocol messages
# -state shows state transitions
# -cipher forces only AES-128-GCM-SHA256
openssl s_server \
    -accept 4433 \
    -cert server.crt \
    -key server.key \
    -tls1_3 \
    -ciphersuites TLS_AES_128_GCM_SHA256 \
    -msg \
    -state \
    -WWW
