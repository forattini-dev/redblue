<div align="center">

# 🌐 Network Domain Documentation

## TL;DR
Everything about `rb network`: scanner presets, intelligence collection, netcat replacement status, and the support matrix across ports/hosts/trace.

**Port scanning • Host discovery • Network path tracing**

[Commands](#commands) • [Examples](#examples) • [Config](#configuration) • [Docs Index](./index.md) • [Root Docs](../../README.md)

</div>

---

<div align="right">

[⬆ Back to Top](#-network-domain-documentation)

</div>

## Overview

The `network` domain provides comprehensive network reconnaissance, port scanning, host discovery, and connectivity testing capabilities. It replaces tools like **nmap**, **masscan**, **fping**, **netdiscover**, **arp-scan**, **traceroute**, and **mtr**.

**Domain:** `network`

**Available Resources:**
- `ports` - Port scanning and service detection
- `host` - Host discovery and connectivity testing
- `trace` - Network path tracing and route analysis (traceroute/MTR)

**Tool Replacements:** nmap, masscan, fping, netdiscover, arp-scan, traceroute, mtr

---

<div align="right">

[⬆ Back to Top](#-network-domain-documentation) • [➡️ Next: Commands](#commands)

</div>

## Commands

## Resource: `network ports`

**Description:** Multi-threaded port scanning with intelligent service detection, banner grabbing, and optional intelligence gathering.

### Commands

#### 1. `scan` - Preset-based Port Scanning

Scan a target using predefined port presets (common, full, web).

**Syntax:**
```bash
rb network ports scan <host> [FLAGS]
```

**Arguments:**
- `<host>` - Target hostname, domain, or IP address (required)

**Flags:**
- `-p, --preset <preset>` - Port preset: `common` (100 ports), `full` (65,535 ports), `web` (6 web ports)
  - Default: `common`
- `-t, --threads <n>` - Number of concurrent scanner threads
  - Default: `200` (from config)
- `--timeout <ms>` - Connection timeout in milliseconds
  - Default: `1000` (from config)
- `-f, --fast` - Fast masscan-style mode (1000 threads, 300ms timeout)
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`
  - Default: `text`
- `--persist` - Save scan results to binary database (.rdb file)
- `--no-persist` - Don't save results (overrides config)
- `-i, --intel` - Gather intelligence (timing analysis, banner fingerprinting, OS detection)

**Examples:**

```bash
# Basic common ports scan
rb network ports scan 192.168.1.1

# Scan with specific preset
rb network ports scan example.com --preset common

# Fast aggressive scan (masscan-style)
rb network ports scan 10.0.0.1 --fast

# Custom thread count
rb network ports scan 192.168.1.1 --threads 500 --timeout 500

# Full port scan with persistence
rb network ports scan 192.168.1.1 --preset full --persist

# Intelligence gathering mode
rb network ports scan 192.168.1.1 --preset common --intel

# JSON output for automation
rb network ports scan 127.0.0.1 --preset common -o json
```

**Sample Output (Text):**

```
Scanning 192.168.1.1  [████████████████████████] 100/100 (2.3s)

🚨 Scan: 192.168.1.1 (5 open)
  ● 22/ssh       SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  ● 80/http      HTTP/1.1 200 OK
  ● 443/https    TLS handshake successful
  ● 3306/mysql   5.7.44-0ubuntu0.18.04.1
  ● 8080/http    Apache Tomcat/9.0.75

✓ Results saved to 192.168.1.1.rdb
```

**Sample Output (JSON):**

```json
{
  "target": "192.168.1.1",
  "preset": "common",
  "open_count": 5,
  "ports": [
    {
      "port": 22,
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    },
    {
      "port": 80,
      "service": "http",
      "banner": "HTTP/1.1 200 OK"
    },
    {
      "port": 443,
      "service": "https",
      "banner": null
    }
  ]
}
```

**Sample Output (YAML):**

```yaml
target: 192.168.1.1
preset: common
open_count: 5
ports:
  - port: 22
    service: ssh
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  - port: 80
    service: http
    banner: "HTTP/1.1 200 OK"
  - port: 443
    service: https
    banner: null
```

**Intelligence Gathering Output:**

With `--intel` flag, additional intelligence is gathered:

```
  ● 22/ssh       SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    └─ Vendor: OpenSSH 8.9p1
    └─ OS: Ubuntu
    └─ Timing: conn=12ms, resp=45ms
    └─ Confidence: 95%

  ● 3306/mysql   5.7.44-0ubuntu0.18.04.1
    └─ Vendor: MySQL 5.7.44
    └─ OS: Ubuntu 18.04
    └─ Timing: conn=8ms, resp=23ms
    └─ Confidence: 92%
```

**Intelligence Features:**
- **Vendor Detection**: Identifies software vendor from banners
- **Version Extraction**: Extracts precise version numbers
- **OS Fingerprinting**: Detects operating system from service banners
- **Timing Analysis**: Connection and response time profiling
- **Confidence Score**: Accuracy percentage (0-100%)

**Port Presets:**

| Preset | Ports | Description |
|--------|-------|-------------|
| `common` | 100 | Most common services (SSH, HTTP, HTTPS, FTP, SMTP, MySQL, etc.) |
| `full` | 65,535 | All TCP ports (1-65535) - slow but comprehensive |
| `web` | 6 | Web services only: 80, 443, 8080, 8443, 3000, 5000 |

**Database Persistence:**

When `--persist` is used, results are saved to `./<target>.rdb` in binary format:
- Port scan results
- Service detection
- Banners
- Timestamps
- Intelligence data (if `--intel` used)

Session history can be loaded later using shell: `rb shell <target>.rb-session`

---

#### 2. `range` - Custom Port Range Scanning

Scan a specific port range on a target host.

**Syntax:**
```bash
rb network ports range <host> <start> <end> [FLAGS]
```

**Arguments:**
- `<host>` - Target hostname, domain, or IP address (required)
- `<start>` - Starting port number (1-65535, required)
- `<end>` - Ending port number (start-65535, required)

**Flags:**
- `-t, --threads <n>` - Concurrent threads (default: 200)
- `--timeout <ms>` - Timeout in milliseconds (default: 1000)
- `-f, --fast` - Fast mode (1000 threads, 300ms timeout)
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`

**Examples:**

```bash
# Scan specific range
rb network ports range 192.168.1.1 80 443

# Scan first 1024 ports (privileged)
rb network ports range 192.168.1.1 1 1024

# Full port scan (slow)
rb network ports range 192.168.1.1 1 65535 --timeout 500

# Fast full scan (masscan-style)
rb network ports range 192.168.1.1 1 65535 --fast
```

**Sample Output:**

```
Port Range Scan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:     192.168.1.1
Range:      80-443
Threads:    200
Timeout:    1000ms

Scanning 192.168.1.1  [████████████████████████] 364/364 (0.8s)

Open ports (3):

PORT    STATE   SERVICE     BANNER
80      open    http        nginx/1.24.0
443     open    https       -
8080    open    http-proxy  Apache Tomcat/9.0

✓ Scan completed
```

---

#### 3. `subnet` - Subnet Discovery and Scanning

Discover all alive hosts in a subnet using CIDR notation and scan them for open ports.

**Syntax:**
```bash
rb network ports subnet <cidr> [FLAGS]
```

**Arguments:**
- `<cidr>` - Subnet in CIDR notation (e.g., `192.168.1.0/24`)

**Flags:**
- `-p, --preset <preset>` - Port preset for each discovered host (default: `common`)
- `-t, --threads <n>` - Concurrent scanner threads (default: 200)
- `--timeout <ms>` - Connection timeout (default: 1000)
- `--persist` - Save all results to individual .rdb files
- `--no-persist` - Don't save results
- `-i, --intel` - Gather intelligence for each discovered service

**Examples:**

```bash
# Discover and scan /24 subnet
rb network ports subnet 192.168.1.0/24

# Large subnet with specific preset
rb network ports subnet 10.0.0.0/24 --preset web

# Fast subnet scan with persistence
rb network ports subnet 192.168.1.0/24 --preset common --persist

# Intelligence-gathering subnet scan
rb network ports subnet 192.168.1.0/24 --intel
```

**Sample Output:**

```
Subnet Discovery: 192.168.1.0/24
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Network: 192.168.1.0    Hosts: 254    Preset: common

Phase 1: Host Discovery

Discovering hosts [████████████████████████] 254/254 (12.1s)

✓ Found 8 alive host(s)
  • 192.168.1.1
  • 192.168.1.10
  • 192.168.1.15
  • 192.168.1.20
  • 192.168.1.50
  • 192.168.1.100
  • 192.168.1.150
  • 192.168.1.200

Phase 2: Port Scanning

[1/8] Scanning 192.168.1.1...
  5 open port(s):
    • 22/ssh
    • 80/http
    • 443/https
    • 3306/mysql
    • 8080/http-proxy

[2/8] Scanning 192.168.1.10...
  2 open port(s):
    • 22/ssh
    • 80/http

[... continues for all hosts ...]

✓ Subnet scan completed - 8 host(s) scanned
```

**Subnet Scan Process:**

1. **Phase 1 - Host Discovery:**
   - Performs quick TCP SYN to port 80 on all IPs
   - Timeout: 500ms per host
   - Identifies alive/responsive hosts

2. **Phase 2 - Port Scanning:**
   - Scans each discovered host with chosen preset
   - Uses configured threads and timeout
   - Optional persistence per host
   - Optional intelligence gathering

**CIDR Notation Examples:**

| CIDR | Hosts | Use Case |
|------|-------|----------|
| `/32` | 1 | Single host |
| `/30` | 2 | Point-to-point link |
| `/29` | 6 | Small subnet |
| `/28` | 14 | Very small network |
| `/27` | 30 | Small office |
| `/26` | 62 | Small department |
| `/25` | 126 | Medium network |
| `/24` | 254 | Standard subnet (Class C) |
| `/16` | 65,534 | Large network (Class B) |

**Performance Notes:**

- Subnets > 1024 hosts will show a warning
- Fast mode recommended for large subnets
- Consider using `--preset web` for faster scans
- Each host scan runs in parallel (respects `--threads`)

---

## Resource: `network host`

**Description:** Host connectivity testing, ICMP ping, and network discovery.

### Commands

#### 1. `ping` - ICMP Ping Test

Send ICMP echo requests to test host reachability and measure latency.

**Syntax:**
```bash
rb network host ping <host> [FLAGS]
```

**Arguments:**
- `<host>` - Target hostname, domain, or IP address

**Flags:**
- `-c, --count <n>` - Number of ping packets (default: 4)
- `-t, --timeout <sec>` - Timeout per packet in seconds (default: 1)
- `-i, --interval <sec>` - Interval between packets (default: 1)
- `-s, --size <bytes>` - Packet size in bytes (default: 56)

**Examples:**

```bash
# Basic ping
rb network host ping google.com

# Ping 10 times
rb network host ping 8.8.8.8 --count 10

# Fast ping with short timeout
rb network host ping example.com --timeout 1 --count 3 --interval 0.5

# Large packet size test
rb network host ping 192.168.1.1 --size 1024 --count 5
```

**Sample Output:**

```
ICMP Ping: google.com
Sending 4 packets (size: 56 bytes, timeout: 1s)

⏱️  Pinging...

Ping Statistics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Host:              google.com (142.250.185.78)
  Packets Sent:      4
  Packets Received:  4
  Packet Loss:       0.0%

Round Trip Time (RTT)
  Min:     8.234 ms
  Avg:     9.127 ms
  Max:     11.456 ms

✓ Host is reachable with no packet loss
```

**Packet Loss Interpretation:**

| Loss | Status | Color |
|------|--------|-------|
| 0% | Excellent | Green |
| 1-50% | Degraded | Yellow |
| 51-99% | Severe | Red |
| 100% | Unreachable | Red |

---

#### 2. `discover` - Network Discovery (CIDR)

Discover all alive hosts in a network range using ICMP ping sweeps.

**Syntax:**
```bash
rb network host discover <cidr> [FLAGS]
```

**Arguments:**
- `<cidr>` - Network in CIDR notation (e.g., `192.168.1.0/24`)

**Flags:**
- `-t, --timeout <sec>` - Timeout per host (default: 1)

**Examples:**

```bash
# Discover /24 subnet
rb network host discover 192.168.1.0/24

# Fast discovery with short timeout
rb network host discover 10.0.0.0/24 --timeout 1
```

**Sample Output:**

```
Network Discovery: 192.168.1.0/24
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Range:    192.168.1.1 - 192.168.1.254 (254 hosts)
Method:   ICMP ping sweep
Timeout:  1s per host

⏱️  Scanning... [████████████████████████] 254/254 (12.1s)

✅ Live Hosts (8 found)

IP ADDRESS       LATENCY    STATUS
192.168.1.1      1.2ms      ✓ Responding (likely router)
192.168.1.10     2.4ms      ✓ Responding
192.168.1.15     1.8ms      ✓ Responding
192.168.1.20     3.1ms      ✓ Responding
192.168.1.50     2.7ms      ✓ Responding
192.168.1.100    1.9ms      ✓ Responding
192.168.1.150    4.2ms      ✓ Responding
192.168.1.200    2.3ms      ✓ Responding

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Discovery completed in 12.14s
  8/254 hosts responding (3.15%)
```

**Discovery Methods:**

| Method | Description | Privileges |
|--------|-------------|-----------|
| ICMP Ping Sweep | Echo requests to all IPs | None required |
| ARP Scanning | Layer 2 discovery | Root/Admin (coming soon) |

---

## Resource: `network trace`

**Description:** Network path tracing and route analysis - traceroute and MTR functionality for diagnosing network paths and latency issues.

### Commands

#### 1. `run` - Traceroute

Trace the network path to a destination, showing all router hops along the route (traceroute replacement).

**Syntax:**
```bash
rb network trace run <target> [FLAGS]
```

**Arguments:**
- `<target>` - Target hostname or IP address (required)

**Flags:**
- `-m, --max-hops <n>` - Maximum number of hops to trace
  - Default: `30`
- `-t, --timeout <ms>` - Timeout per hop in milliseconds
  - Default: `2000`
- `-n, --no-dns` - Skip reverse DNS lookups (faster)
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)

**What It Shows:**
- Hop number (TTL)
- Hostname (with reverse DNS lookup)
- IP address of each router
- Round-trip latency in milliseconds
- Complete route from source to destination

**Examples:**

```bash
# Basic traceroute
rb network trace run 8.8.8.8

# Traceroute to domain
rb network trace run google.com

# Fast traceroute without DNS
rb network trace run 1.1.1.1 --no-dns --timeout 1000

# Custom max hops
rb network trace run example.com --max-hops 20

# Save to database
rb network trace run target.com --persist
```

**Sample Output:**

```
🌐 Traceroute

  Target:      8.8.8.8
  Max Hops:    30
  Timeout:     2000ms
  DNS Resolve: Yes

Tracing route to 8.8.8.8... ✓

Route to 8.8.8.8 (14 hops)

  HOP  HOSTNAME                                 IP ADDRESS           LATENCY
  ────────────────────────────────────────────────────────────────────────────
  1    router.local                             192.168.1.1          2.45 ms
  2    10-0-0-1.isp.net                         10.0.0.1             8.32 ms
  3    core1.isp.net                            203.0.113.1          12.87 ms
  4    core2.isp.net                            203.0.113.5          15.23 ms
  5    ix-ae-10-0.tcore1.pao.telepacific.net    209.85.249.158       18.45 ms
  6    108.170.252.193                          108.170.252.193      19.12 ms
  7    142.251.49.158                           142.251.49.158       20.34 ms
  8    dns.google                               8.8.8.8              21.56 ms

✓ Traceroute completed
```

**Sample Output (With Unreachable Hop):**

```
Route to 192.0.2.1 (30 hops)

  HOP  HOSTNAME                                 IP ADDRESS           LATENCY
  ────────────────────────────────────────────────────────────────────────────
  1    router.local                             192.168.1.1          2.12 ms
  2    10-0-0-1.isp.net                         10.0.0.1             7.89 ms
  3    *                                        *                    *
  4    *                                        *                    *
  5    core3.isp.net                            203.0.113.10         25.43 ms
  ...
```

---

#### 2. `mtr` - MTR Network Monitor

Perform continuous MTR-style network path monitoring with statistics (mtr replacement).

**Syntax:**
```bash
rb network trace mtr <target> [FLAGS]
```

**Arguments:**
- `<target>` - Target hostname or IP address (required)

**Flags:**
- `-m, --max-hops <n>` - Maximum number of hops
  - Default: `30`
- `-t, --timeout <ms>` - Timeout per probe in milliseconds
  - Default: `2000`
- `-i, --iterations <n>` - Number of probe iterations
  - Default: `10`
- `-n, --no-dns` - Skip reverse DNS lookups
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`
- `--persist` - Save results to binary database

**What It Shows:**
- All hops in the route
- Packet loss percentage per hop
- Min/Avg/Max latency statistics
- Standard deviation of latency
- Number of probes sent/received

**MTR vs Traceroute:**

| Feature | Traceroute | MTR |
|---------|------------|-----|
| Probes per hop | 1-3 | Configurable (default: 10) |
| Statistics | No | Yes (loss%, avg, stddev) |
| Continuous | No | Yes |
| Best for | Quick path check | Latency analysis |

**Examples:**

```bash
# Basic MTR monitoring
rb network trace mtr 8.8.8.8

# MTR with more iterations
rb network trace mtr google.com --iterations 20

# Fast MTR without DNS
rb network trace mtr 1.1.1.1 --no-dns

# Custom parameters
rb network trace mtr example.com --max-hops 20 --iterations 50

# Save to database
rb network trace mtr target.com --persist
```

**Sample Output:**

```
📊 MTR - Network Path Monitor

  Target:      8.8.8.8
  Max Hops:    30
  Iterations:  10
  Timeout:     2000ms
  DNS Resolve: Yes

Running MTR analysis (10 iterations)... ✓

Network Path Statistics to 8.8.8.8 (8 hops)

  HOP  HOSTNAME                  LOSS%   SENT  RECV  MIN      AVG      MAX      STDDEV
  ──────────────────────────────────────────────────────────────────────────────────────
  1    router.local              0.0%    10    10    1.85ms   2.34ms   3.12ms   0.42ms
  2    10-0-0-1.isp.net          0.0%    10    10    7.23ms   8.45ms   10.23ms  0.89ms
  3    core1.isp.net             0.0%    10    10    11.34ms  12.67ms  15.12ms  1.23ms
  4    core2.isp.net             0.0%    10    10    14.56ms  15.89ms  18.34ms  1.45ms
  5    ix-ae-10-0.tcore1.pao     0.0%    10    10    17.23ms  18.67ms  21.45ms  1.34ms
  6    108.170.252.193           0.0%    10    10    18.12ms  19.45ms  22.12ms  1.23ms
  7    142.251.49.158            0.0%    10    10    19.23ms  20.56ms  23.45ms  1.45ms
  8    dns.google                0.0%    10    10    20.34ms  21.78ms  24.56ms  1.34ms

✓ MTR analysis completed
```

**Sample Output (With Packet Loss):**

```
Network Path Statistics to 192.0.2.1 (15 hops)

  HOP  HOSTNAME                  LOSS%   SENT  RECV  MIN      AVG      MAX      STDDEV
  ──────────────────────────────────────────────────────────────────────────────────────
  1    router.local              0.0%    10    10    1.92ms   2.45ms   3.23ms   0.45ms
  2    10-0-0-1.isp.net          0.0%    10    10    7.45ms   8.67ms   11.23ms  1.12ms
  3    *                         100.0%  10    0     *        *        *        *
  4    core3.isp.net             20.0%   10    8     22.34ms  25.67ms  35.12ms  4.23ms
  5    congested-router.net      50.0%   10    5     45.23ms  78.45ms  125.34ms 32.12ms
  ...
```

---

## Use Cases for TRACE

### 1. **Diagnose Network Latency**

Find which hop is causing high latency:

```bash
# Use MTR for detailed statistics
rb network trace mtr slow-server.com --iterations 20

# Look for:
# - High AVG latency at specific hop
# - High STDDEV (inconsistent latency)
# - Packet loss percentage
```

### 2. **Verify Network Path**

Check the route packets take to a destination:

```bash
# Basic traceroute
rb network trace run target.com

# Verify expected hops (ISP, CDN, destination)
# Look for unexpected routing (could indicate hijacking)
```

### 3. **Debug Connectivity Issues**

Find where packets are being dropped:

```bash
# MTR shows packet loss per hop
rb network trace mtr unreachable.example.com

# 100% loss at hop N = firewall/filter at that hop
# Intermittent loss = congested link
```

### 4. **Compare Different Paths**

Compare routes to different services:

```bash
# Primary server
rb network trace run primary.example.com > route1.txt

# Backup server
rb network trace run backup.example.com > route2.txt

# Compare paths
diff route1.txt route2.txt
```

---

## Configuration

**Configuration File:** `./.redblue.yaml`

**Network Section:**

```yaml
network:
  threads: 200              # Default scanner threads
  timeout_ms: 1000          # Connection timeout
  dns_resolver: "8.8.8.8"   # DNS server for resolution
  request_delay_ms: 0       # Rate limiting delay (stealth)
```

**Environment Variables:**

```bash
export REDBLUE_NETWORK_THREADS=300
export REDBLUE_NETWORK_TIMEOUT_MS=2000
export REDBLUE_NETWORK_DNS_RESOLVER="1.1.1.1"
```

**Precedence:** Flags > Environment > Config File > Defaults

---

## Common Use Cases

### 1. Quick Port Reconnaissance

```bash
# Fast common ports scan
rb network ports scan target.com --preset common

# Web-focused scan
rb network ports scan target.com --preset web
```

### 2. Thorough Network Audit

```bash
# Full port scan with intelligence
rb network ports scan 192.168.1.1 --preset full --intel --persist
```

### 3. Subnet Discovery and Mapping

```bash
# Discover all hosts in subnet
rb network host discover 192.168.1.0/24

# Full subnet scan with persistence
rb network ports subnet 192.168.1.0/24 --preset common --persist
```

### 4. Fast Masscan-Style Scanning

```bash
# Lightning-fast scan
rb network ports scan 10.0.0.1 --fast

# Fast full port scan
rb network ports range 192.168.1.1 1 65535 --fast
```

### 5. Persistent Reconnaissance

```bash
# Scan and save to database
rb network ports scan target.com --preset common --persist

# Load results later in REPL
rb shell target.com.rb-session
```

---

## Performance Tips

**Fast Scanning:**
- Use `--fast` flag for masscan-style speed (1000 threads, 300ms timeout)
- Use `web` preset for focused web scanning
- Lower timeout for unresponsive networks: `--timeout 300`

**Accurate Scanning:**
- Use `common` preset for balanced speed/coverage
- Add `--intel` for detailed service fingerprinting
- Increase timeout for slow networks: `--timeout 2000`

**Stealth Scanning:**
- Reduce thread count: `--threads 10`
- Add delay between requests: configure `request_delay_ms: 100` in config
- Use `common` preset to avoid scanning uncommon ports

**Large Networks:**
- Use subnet scanning for automatic host discovery
- Enable persistence to save incremental results
- Consider breaking into smaller CIDR blocks

---

## Tool Equivalents

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `nmap -sT` | `rb network ports scan` | TCP connect scan |
| `nmap -p-` | `rb network ports range 1 65535` | Full port scan |
| `nmap -Pn` | `rb network ports scan` | No ping (direct scan) |
| `masscan` | `rb network ports scan --fast` | High-speed scanning |
| `fping` | `rb network host ping` | Fast ping utility |
| `netdiscover` | `rb network host discover` | Network discovery |
| `arp-scan` | `rb network host discover` | ARP scanning (planned) |
| `traceroute` | `rb network trace run` | Route tracing |
| `mtr` | `rb network trace mtr` | Live route monitoring |

---

## Technical Details

**Implementation:**
- **Language:** Pure Rust (zero external dependencies)
- **Protocol:** Raw TCP sockets (`std::net::TcpStream`)
- **Architecture:** Multi-threaded connection attempts
- **Service Detection:** Banner grabbing + port-based heuristics
- **Intelligence:** Timing analysis, fingerprinting, OS detection

**Limitations:**
- Currently TCP connect scans only (SYN scans require raw sockets - planned)
- IPv4 only (IPv6 support planned)
- No UDP scanning yet (planned for Phase 2)
- ICMP requires system ping utility (native ICMP planned)

**Database Format:**
- Binary format (.rdb files)
- Efficient segment-oriented storage
- Quick lookups and indexing
- Cross-platform compatibility

---

## Netcat Replacement Summary

### Feature Snapshot
- `rb nc` now unifies classic `nc`, `ncat`, `socat`, and `cryptcat` workflows: TCP/UDP client+listener, port scanning, reverse shells, and file transfer.
- TLS 1.2 handshakes ride on the in-house `src/modules/network/tls.rs` stack (SNI, RSA key exchange, AES-CBC/GCM).
- Proxy support (`src/modules/network/proxy.rs`) covers SOCKS4, SOCKS5 (with auth), and HTTP CONNECT, while ACLs, relays, brokers, PTY shells, Unix sockets, and rate limiting live under `src/modules/network/`.
- Optional Twofish-based symmetric encryption and connection logging give cryptcat-style secure sessions without external binaries.

### Implementation Notes
- Nine new modules (`tls.rs`, `proxy.rs`, `acl.rs`, `broker.rs`, `relay.rs`, `pty.rs`, `unix-socket.rs`, `twofish.rs`, `extras.rs`) account for ~3.7 k lines of Rust.
- CLI surfaces listeners, relays, brokers, encryption, and file transfer through `src/cli/commands/nc.rs`; parser wiring sits in `src/cli/parser.rs`.
- Multi-session chat, port relay, and forked handlers allow simultaneous operators—mirroring `socat`/`ncat --chat`.

### Usage Highlights
```bash
rb nc listen 4444 --ssl --allow 10.0.0.0/24
rb nc connect target.com 80 --proxy socks5://proxy:1080
rb nc relay tcp:8080 tcp:backend:80 --fork
rb nc unix /tmp/app.sock --send-file payload.bin
```

### Pending Enhancements
- Harden automated tests around TLS listeners and encrypted transfers.
- Expose per-session statistics via `rb nc sessions` (planned).
- Extend documentation with end-to-end examples in `docs/examples/`.

---

## Intelligence Extraction

### What We Capture
- Every TCP handshake captures TTL, TCP options, window sizes, timing, and retransmission behavior for passive OS fingerprinting.
- TLS negotiations feed JA3/JA4 fingerprints, certificate chain analysis, and cipher telemetry; HTTP responses surface headers, cookies, error pages, and security posture.
- Infrastructure heuristics call out CDN/WAF/provider hints via response headers, certificate issuers, latency baselines, and cookie patterns.

### Implementation Footprint
- Intelligence engines reside in `src/intelligence/` (`tcp-fingerprint.rs`, `tls-fingerprint.rs`, `http-fingerprint.rs`, etc.) with shared collectors orchestrated by `connection-intel.rs`.
- Detailed methodology lives in `docs/passive-fingerprinting.md`; intelligence-aware CLI output appears when `--intel` is set on network commands.
- `docs/domains/recon.md` cross-refers to the same engine for WHOIS and OSINT enrichment.

### Next Steps
- Wire an explicit `rb intelligence fingerprint` verb for ad-hoc analysis.
- Auto-trigger secondary collection (e.g., wildcard certificate → subdomain enum) via the upcoming Intelligence Graph.
- Persist structured findings into `.rdb` segments so `rb network ports list` surfaces historical intelligence.

---

## Troubleshooting

**No open ports found:**
- Check if host is reachable: `rb network host ping <host>`
- Try increasing timeout: `--timeout 2000`
- Try different preset: `--preset full`
- Check firewall rules on source/destination

**Slow scans:**
- Use `--fast` flag for masscan-style speed
- Reduce port range
- Use `web` preset instead of `common` or `full`
- Check network latency

**Permission denied:**
- Some features require root (raw sockets for SYN scan - future)
- Use TCP connect scan (default, no privileges needed)
- ARP scanning requires root (planned feature)

**Database save fails:**
- Check disk space
- Ensure write permissions in current directory
- Try `--no-persist` to skip database

---

## See Also

- [DNS Domain Documentation](./DNS.md) - Domain reconnaissance
- [WEB Domain Documentation](./WEB.md) - Web application testing
- [TLS Domain Documentation](./TLS.md) - TLS/SSL security
- [RECON Domain Documentation](./RECON.md) - WHOIS and OSINT
