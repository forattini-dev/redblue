#!/bin/bash
pkill -f "examples/server" || true
rm -f server.log
RUST_LOG=debug ./docs/quinn/target/debug/examples/server --listen 0.0.0.0:4433 /tmp/www > server.log 2>&1 &
PID=$!
echo "Server PID: $PID"
sleep 2
cargo run --example debug_quic_handshake
sleep 1
echo "--- Server Log ---"
cat server.log
echo "------------------"
kill $PID
