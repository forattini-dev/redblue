#!/bin/bash

echo "=========================================="
echo "Testing TLS 1.2 connection to Google"
echo "=========================================="

cat << 'EOF' | cargo run --release --example tls12-google-test 2>&1
EOF

echo ""
echo "=========================================="
echo "Testing TLS 1.3 connection to Google"
echo "=========================================="

cat << 'EOF' | cargo run --release --example tls13-google-test 2>&1
EOF
