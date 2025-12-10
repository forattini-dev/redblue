# Host Discovery

Host connectivity testing, ICMP ping, and network discovery.

## Quick Start

```bash
# Ping a host
rb network ping host google.com

# Discover hosts in subnet
rb network discover host 192.168.1.0/24

# Ping with count
rb network ping host 8.8.8.8 --count 10
```

## Commands

### ping - ICMP Ping Test

Send ICMP echo requests to test host reachability and measure latency.

```bash
rb network ping host <target> [flags]
```

### discover - Network Discovery

Discover all alive hosts in a network range using ICMP ping sweeps.

```bash
rb network discover host <cidr> [flags]
```

## Options

```rust
// Ping options
struct PingOptions {
    // Number of ping packets to send
    // Range: 1-1000
    // Default: 4
    count: u32,

    // Timeout per packet in seconds
    // Range: 1-30
    // Default: 1
    timeout_secs: u32,

    // Interval between packets in seconds
    // Range: 0.1-10
    // Default: 1.0
    interval_secs: f32,

    // Packet size in bytes
    // Range: 8-65500
    // Default: 56
    size: u32,
}

// Discovery options
struct DiscoverOptions {
    // Timeout per host in seconds
    // Range: 1-30
    // Default: 1
    timeout_secs: u32,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,
}
```

## Flag Reference

### ping

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--count` | `-c` | Number of packets | 4 |
| `--timeout` | `-t` | Timeout per packet (secs) | 1 |
| `--interval` | `-i` | Interval between packets | 1.0 |
| `--size` | `-s` | Packet size in bytes | 56 |

### discover

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--timeout` | `-t` | Timeout per host (secs) | 1 |
| `--output` | `-o` | Output format: text, json | text |

## Examples

### Basic Ping

```bash
# Simple ping
rb network ping host google.com
# → Sends 4 packets, shows RTT statistics

# Custom count
rb network ping host 8.8.8.8 --count 10
# → Sends 10 packets

# Fast ping
rb network ping host example.com --timeout 1 --interval 0.5
# → Quick ping with 0.5s interval
```

### Large Packet Test

```bash
# MTU discovery
rb network ping host 192.168.1.1 --size 1024

# Maximum size test
rb network ping host 192.168.1.1 --size 65500 --count 1
```

### Network Discovery

```bash
# Discover /24 subnet
rb network discover host 192.168.1.0/24
# → Scans 254 hosts

# Fast discovery
rb network discover host 10.0.0.0/24 --timeout 1

# JSON output for automation
rb network discover host 192.168.1.0/24 -o json
```

## Output Examples

### Ping Output

```
ICMP Ping: google.com (142.250.185.78)
Sending 4 packets (size: 56 bytes, timeout: 1s)

Ping Statistics
  Host:              google.com (142.250.185.78)
  Packets Sent:      4
  Packets Received:  4
  Packet Loss:       0.0%

Round Trip Time (RTT)
  Min:     8.234 ms
  Avg:     9.127 ms
  Max:     11.456 ms

Host is reachable
```

### Discovery Output

```
Network Discovery: 192.168.1.0/24
Range: 192.168.1.1 - 192.168.1.254 (254 hosts)

Scanning... [████████████████████████] 254/254 (12.1s)

Live Hosts (8 found)

IP ADDRESS       LATENCY    STATUS
192.168.1.1      1.2ms      Responding (router)
192.168.1.10     2.4ms      Responding
192.168.1.15     1.8ms      Responding
192.168.1.20     3.1ms      Responding
192.168.1.50     2.7ms      Responding
192.168.1.100    1.9ms      Responding
192.168.1.150    4.2ms      Responding
192.168.1.200    2.3ms      Responding

Discovery completed in 12.14s
8/254 hosts responding (3.15%)
```

### JSON Output

```json
{
  "network": "192.168.1.0/24",
  "hosts_scanned": 254,
  "hosts_found": 8,
  "scan_time_ms": 12140,
  "hosts": [
    {
      "ip": "192.168.1.1",
      "latency_ms": 1.2,
      "status": "alive"
    },
    {
      "ip": "192.168.1.10",
      "latency_ms": 2.4,
      "status": "alive"
    }
  ]
}
```

## Packet Loss Interpretation

| Loss | Status | Meaning |
|------|--------|---------|
| 0% | Excellent | Host is fully reachable |
| 1-10% | Acceptable | Minor network issues |
| 11-50% | Degraded | Network congestion |
| 51-99% | Severe | Major connectivity issues |
| 100% | Unreachable | Host down or filtered |

## CIDR Reference

| CIDR | Hosts | Use Case |
|------|-------|----------|
| /32 | 1 | Single host |
| /30 | 2 | Point-to-point link |
| /29 | 6 | Small subnet |
| /28 | 14 | Very small network |
| /27 | 30 | Small office |
| /26 | 62 | Small department |
| /25 | 126 | Medium network |
| /24 | 254 | Standard subnet |
| /16 | 65,534 | Large network |

## Patterns

### Connectivity Check

```bash
# Quick reachability test
rb network ping host target.com --count 3

# Check if all ports respond
rb network ping host target.com && rb network scan ports target.com --preset web
```

### Network Mapping

```bash
# Step 1: Discover alive hosts
rb network discover host 192.168.1.0/24 -o json > hosts.json

# Step 2: Scan each discovered host
cat hosts.json | jq -r '.hosts[].ip' | while read ip; do
  rb network scan ports $ip --preset common
done
```

## Next Steps

- [Port Scanning](01-ports.md) - Scan ports on discovered hosts
- [Path Tracing](03-trace.md) - Trace network routes
- [Configuration](04-configuration.md) - Customize settings
