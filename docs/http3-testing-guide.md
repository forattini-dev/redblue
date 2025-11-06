# HTTP/3 Testing Guide

This guide explains how to test the HTTP/3 implementation in redblue.

---

## Current Status

⚠️ **Known Bug**: QUIC Initial packet padding issue prevents handshake completion.
- **Symptom**: Connection timeout after 30s
- **Cause**: Packets sent are only 70 bytes instead of required 1200+ bytes
- **Impact**: Servers ignore malformed packets per RFC 9000 §14.1

---

## Quick Test (Current)

This will demonstrate the bug and show debug output:

```bash
# Test with Google (will timeout, but shows the bug)
./target/release/redblue web asset http3 https://www.google.com

# Expected output:
# [DEBUG] Building ClientHello for QUIC+TLS handshake
# [DEBUG] ClientHello size: 220 bytes
# [DEBUG] Sending QUIC Initial packet to 172.217.29.132:443
# [DEBUG] Payload before padding: 224 bytes
# [DEBUG] Payload after padding: 1199 bytes  ✅ Correct
# [DEBUG] Sending Initial packet: 70 bytes   ❌ BUG HERE!
# ... (spinner for 30s) ...
# Error: QUIC connection timeout after X attempts
```

---

## Testing After Bug Fix

Once the padding bug is fixed, use these tests:

### 1. Basic HTTP/3 Request

```bash
# Test with Google (major HTTP/3 server)
./target/release/redblue web asset http3 https://www.google.com

# Expected output:
# ▸ HTTP/3 Response from www.google.com
# Status: 200 OK
# Headers:
#   content-type: text/html; charset=UTF-8
#   ...
# Body: (HTML content)
```

### 2. Test with Multiple Servers

```bash
# Cloudflare (strong HTTP/3 support)
./target/release/redblue web asset http3 https://cloudflare-quic.com

# Facebook (HTTP/3 enabled)
./target/release/redblue web asset http3 https://www.facebook.com

# Cloudflare blog (known HTTP/3 test endpoint)
./target/release/redblue web asset http3 https://blog.cloudflare.com
```

### 3. Test with Different HTTP Methods

```bash
# POST request
./target/release/redblue web asset http3 https://httpbin.org/post \
  --method POST \
  --body '{"test": "data"}'

# PUT request with file
./target/release/redblue web asset http3 https://httpbin.org/put \
  --method PUT \
  --body-file payload.json
```

### 4. Test JSON Output

```bash
# Get JSON response
./target/release/redblue web asset http3 https://api.github.com -o json

# Expected format:
# {
#   "status": 200,
#   "headers": {...},
#   "body": "..."
# }
```

### 5. Test Timeout Handling

```bash
# Short timeout (should fail quickly)
./target/release/redblue web asset http3 https://slow-server.com --timeout 5

# Expected: Timeout error after 5 seconds
```

---

## Packet Capture Testing

Use Wireshark to verify packets are correctly formatted:

### Setup Wireshark

```bash
# Install Wireshark if not already installed
sudo apt-get install wireshark

# Capture UDP traffic on port 443
sudo wireshark -i any -f "udp port 443" &
```

### Capture QUIC Handshake

```bash
# In another terminal, run HTTP/3 test
./target/release/redblue web asset http3 https://www.google.com
```

### Verify in Wireshark

1. Filter for QUIC: `quic`
2. Check Initial packet size: Should be **≥1200 bytes** ✅
3. Verify ClientHello is present
4. Confirm server responds with Initial packet
5. Check for ServerHello in response

**Expected Packet Sequence**:
```
Client → Server: Initial (1200+ bytes) with ClientHello
Server → Client: Initial with ServerHello
Client → Server: Handshake with Certificate/Finished
Server → Client: Handshake with Finished
Client → Server: 1-RTT with HTTP/3 HEADERS frame
Server → Client: 1-RTT with HTTP/3 HEADERS + DATA frames
```

---

## Local Test Server

For isolated testing, run a local HTTP/3 server:

### Option 1: Using aioquic (Python)

```bash
# Install aioquic
pip3 install aioquic

# Run test server
python3 -m aioquic.examples.http3_server \
  --certificate cert.pem \
  --private-key key.pem \
  --host 127.0.0.1 \
  --port 4433

# Test with redblue
./target/release/redblue web asset http3 https://127.0.0.1:4433
```

### Option 2: Using nginx-quic

```bash
# Build nginx with QUIC support
git clone https://github.com/nginx/nginx-quic
cd nginx-quic
./auto/configure --with-http_v3_module --with-http_ssl_module
make

# Configure nginx.conf:
# server {
#     listen 443 quic reuseport;
#     listen 443 ssl;
#     ssl_certificate     cert.pem;
#     ssl_certificate_key key.pem;
#     ssl_protocols       TLSv1.3;
# }

# Start nginx
./objs/nginx -c nginx.conf

# Test
./target/release/redblue web asset http3 https://localhost:443
```

### Option 3: Using quiche's test server (Rust)

```bash
# Clone quiche
git clone https://github.com/cloudflare/quiche
cd quiche

# Build examples
cargo build --release --examples

# Run HTTP/3 server
./target/release/examples/http3-server \
  --cert examples/cert.crt \
  --key examples/cert.key \
  --listen 127.0.0.1:4433

# Test with redblue
./target/release/redblue web asset http3 https://127.0.0.1:4433
```

---

## Debug Mode Testing

Enable verbose debug output to trace the entire handshake:

```bash
# The debug output is already enabled in current build
./target/release/redblue web asset http3 https://www.google.com 2>&1 | tee http3-debug.log

# Debug output includes:
# - ClientHello construction
# - Payload padding
# - Packet encryption
# - Send/receive operations
# - Connection state transitions
```

---

## Performance Testing

Once working, benchmark HTTP/3 vs HTTP/2:

### Latency Test

```bash
# HTTP/3
time ./target/release/redblue web asset http3 https://www.google.com

# HTTP/2 (for comparison)
time ./target/release/redblue web asset http2 https://www.google.com

# Compare results
```

### Throughput Test

```bash
# Large file download via HTTP/3
time ./target/release/redblue web asset http3 \
  https://speed.cloudflare.com/__down?bytes=100000000 \
  > /dev/null

# HTTP/2 comparison
time ./target/release/redblue web asset http2 \
  https://speed.cloudflare.com/__down?bytes=100000000 \
  > /dev/null
```

---

## Unit Tests (TODO)

After bug fix, add these tests to `tests/http3_integration_test.rs`:

```rust
#[test]
fn test_http3_google() {
    let mut client = Http3Client::new(quic_config, http3_settings).unwrap();
    client.connect().unwrap();
    let stream_id = client.request("GET", "https", "www.google.com", "/", None).unwrap();
    // Poll for response
    // Assert status == 200
}

#[test]
fn test_http3_timeout() {
    // Test connection timeout handling
}

#[test]
fn test_http3_post() {
    // Test POST with body
}

#[test]
fn test_http3_large_response() {
    // Test chunked responses
}
```

Run tests:
```bash
cargo test http3_
```

---

## Known HTTP/3 Servers for Testing

These servers are known to support HTTP/3:

| Server | URL | Notes |
|--------|-----|-------|
| Google | https://www.google.com | Large-scale production |
| Cloudflare | https://cloudflare-quic.com | QUIC test endpoint |
| Facebook | https://www.facebook.com | Major social platform |
| Fastly | https://www.fastly.com | CDN provider |
| Litespeed | https://www.litespeedtech.com | Web server vendor |
| HTTP/3 Check | https://http3check.net | HTTP/3 detection |

---

## Troubleshooting

### Connection Timeout

**Symptom**: `QUIC connection timeout after X attempts`

**Possible Causes**:
1. ❌ Padding bug (current known issue)
2. Server doesn't support HTTP/3
3. UDP port 443 filtered by firewall
4. NAT/routing issues

**Solutions**:
```bash
# Check if server supports HTTP/3
curl --http3 -I https://www.google.com

# Check UDP connectivity
nc -u www.google.com 443

# Try different server
./target/release/redblue web asset http3 https://cloudflare-quic.com
```

### No Packets Received

**Symptom**: `[DEBUG] Sending Initial packet` but no `[DEBUG] Received` messages

**Debugging**:
```bash
# Check firewall
sudo iptables -L -n | grep 443

# Capture packets
sudo tcpdump -i any udp port 443 -w quic.pcap

# Verify DNS resolution
dig www.google.com
```

### Malformed Packet Error

**Symptom**: Server sends CONNECTION_CLOSE frame

**Check**:
- Initial packet size (must be ≥1200 bytes)
- QUIC version (0x00000001 for v1)
- Connection ID format
- Packet number encoding

---

## Comparison with curl

Once working, redblue HTTP/3 should match curl's behavior:

```bash
# curl HTTP/3 request
curl --http3 https://www.google.com

# redblue HTTP/3 request
./target/release/redblue web asset http3 https://www.google.com

# Both should return same response (status, headers, body)
```

---

## Next Steps After Bug Fix

1. ✅ Fix QUIC padding bug
2. ✅ Test with Google, Cloudflare, Facebook
3. ✅ Verify packet capture shows 1200+ byte Initial
4. ✅ Write integration tests
5. ✅ Benchmark performance vs HTTP/2
6. ✅ Add Alt-Svc discovery
7. ✅ Implement connection pooling
8. ✅ Update documentation with real examples

---

## Expected Timeline

- **Bug Fix**: 2-4 hours (debug seal_packet, verify padding)
- **Testing**: 1-2 hours (multiple servers, edge cases)
- **Integration Tests**: 2-3 hours (unit + integration)
- **Performance Tuning**: 1-2 hours (optimize hot paths)

**Total Estimated**: 6-11 hours to production-ready HTTP/3

---

## Success Criteria

HTTP/3 implementation is **production-ready** when:

1. ✅ Successful handshake with Google, Cloudflare, Facebook
2. ✅ GET/POST/PUT requests work correctly
3. ✅ Large responses handled (chunking, flow control)
4. ✅ Timeouts and errors handled gracefully
5. ✅ Packet capture shows RFC-compliant QUIC packets
6. ✅ Performance comparable to curl --http3
7. ✅ Integration tests pass
8. ✅ No memory leaks or crashes

---

## References

- [RFC 9000: QUIC Transport](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 9114: HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)
- [Cloudflare QUIC Blog](https://blog.cloudflare.com/http3-the-past-present-and-future/)
- [curl HTTP/3 Documentation](https://curl.se/docs/http3.html)
- [Wireshark QUIC Wiki](https://wiki.wireshark.org/QUIC)

---

**Status**: 🚧 Waiting for padding bug fix before production testing
**Last Updated**: 2025-11-06
