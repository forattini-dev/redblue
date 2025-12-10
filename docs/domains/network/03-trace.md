# Path Tracing

Network path tracing and route analysis - traceroute and MTR functionality.

## Quick Start

```bash
# Basic traceroute
rb network run trace 8.8.8.8

# MTR monitoring
rb network mtr trace google.com

# Fast trace without DNS
rb network run trace 1.1.1.1 --no-dns
```

## Commands

### run - Traceroute

Trace the network path to a destination, showing all router hops.

```bash
rb network run trace <target> [flags]
```

### mtr - MTR Monitor

Continuous MTR-style monitoring with statistics.

```bash
rb network mtr trace <target> [flags]
```

## Options

```rust
// Traceroute options
struct TraceOptions {
    // Maximum number of hops to trace
    // Range: 1-64
    // Default: 30
    max_hops: u32,

    // Timeout per hop in milliseconds
    // Range: 100-30000
    // Default: 2000
    timeout_ms: u32,

    // Skip reverse DNS lookups (faster)
    // Default: false
    no_dns: bool,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,

    // Save results to database
    // Default: false
    persist: bool,
}

// MTR options
struct MtrOptions {
    // Maximum number of hops
    // Default: 30
    max_hops: u32,

    // Timeout per probe in milliseconds
    // Default: 2000
    timeout_ms: u32,

    // Number of probe iterations
    // Range: 1-1000
    // Default: 10
    iterations: u32,

    // Skip reverse DNS lookups
    // Default: false
    no_dns: bool,
}
```

## Flag Reference

### traceroute

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--max-hops` | `-m` | Maximum hops | 30 |
| `--timeout` | `-t` | Timeout per hop (ms) | 2000 |
| `--no-dns` | `-n` | Skip DNS lookups | false |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to .rdb | false |

### mtr

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--max-hops` | `-m` | Maximum hops | 30 |
| `--timeout` | `-t` | Timeout per probe (ms) | 2000 |
| `--iterations` | `-i` | Number of iterations | 10 |
| `--no-dns` | `-n` | Skip DNS lookups | false |
| `--output` | `-o` | Output format | text |

## Traceroute vs MTR

| Feature | Traceroute | MTR |
|---------|------------|-----|
| Probes per hop | 1 | Configurable (10) |
| Statistics | No | Yes (loss%, avg, stddev) |
| Continuous | No | Yes |
| Best for | Quick path check | Latency analysis |
| Speed | Fast | Slower |

## Examples

### Basic Traceroute

```bash
# Trace to IP
rb network run trace 8.8.8.8

# Trace to domain
rb network run trace google.com

# Fast trace (no DNS)
rb network run trace 1.1.1.1 --no-dns --timeout 1000
```

### Custom Options

```bash
# Custom max hops
rb network run trace example.com --max-hops 20

# Longer timeout for slow networks
rb network run trace 192.0.2.1 --timeout 5000

# Save to database
rb network run trace target.com --persist
```

### MTR Monitoring

```bash
# Basic MTR
rb network mtr trace 8.8.8.8

# More iterations for accurate stats
rb network mtr trace google.com --iterations 50

# Fast MTR
rb network mtr trace 1.1.1.1 --no-dns --iterations 20
```

## Output Examples

### Traceroute Output

```
Traceroute to 8.8.8.8
Max Hops: 30, Timeout: 2000ms

Route to 8.8.8.8 (8 hops)

  HOP  HOSTNAME                          IP ADDRESS        LATENCY
  1    router.local                      192.168.1.1       2.45 ms
  2    10-0-0-1.isp.net                  10.0.0.1          8.32 ms
  3    core1.isp.net                     203.0.113.1       12.87 ms
  4    core2.isp.net                     203.0.113.5       15.23 ms
  5    ix-ae-10-0.tcore1.telecom.net     209.85.249.158    18.45 ms
  6    108.170.252.193                   108.170.252.193   19.12 ms
  7    142.251.49.158                    142.251.49.158    20.34 ms
  8    dns.google                        8.8.8.8           21.56 ms

Traceroute completed
```

### Traceroute with Unreachable Hop

```
Route to 192.0.2.1 (30 hops)

  HOP  HOSTNAME                          IP ADDRESS        LATENCY
  1    router.local                      192.168.1.1       2.12 ms
  2    10-0-0-1.isp.net                  10.0.0.1          7.89 ms
  3    *                                 *                 *
  4    *                                 *                 *
  5    core3.isp.net                     203.0.113.10      25.43 ms
  ...
```

### MTR Output

```
MTR - Network Path Monitor
Target: 8.8.8.8, Iterations: 10

Network Path Statistics (8 hops)

  HOP  HOSTNAME              LOSS%   SENT  RECV  MIN      AVG      MAX      STDDEV
  1    router.local          0.0%    10    10    1.85ms   2.34ms   3.12ms   0.42ms
  2    10-0-0-1.isp.net      0.0%    10    10    7.23ms   8.45ms   10.23ms  0.89ms
  3    core1.isp.net         0.0%    10    10    11.34ms  12.67ms  15.12ms  1.23ms
  4    core2.isp.net         0.0%    10    10    14.56ms  15.89ms  18.34ms  1.45ms
  5    ix-ae-10-0.tcore1     0.0%    10    10    17.23ms  18.67ms  21.45ms  1.34ms
  6    108.170.252.193       0.0%    10    10    18.12ms  19.45ms  22.12ms  1.23ms
  7    142.251.49.158        0.0%    10    10    19.23ms  20.56ms  23.45ms  1.45ms
  8    dns.google            0.0%    10    10    20.34ms  21.78ms  24.56ms  1.34ms

MTR analysis completed
```

### MTR with Packet Loss

```
  HOP  HOSTNAME              LOSS%   SENT  RECV  MIN      AVG      MAX      STDDEV
  1    router.local          0.0%    10    10    1.92ms   2.45ms   3.23ms   0.45ms
  2    10-0-0-1.isp.net      0.0%    10    10    7.45ms   8.67ms   11.23ms  1.12ms
  3    *                     100.0%  10    0     *        *        *        *
  4    core3.isp.net         20.0%   10    8     22.34ms  25.67ms  35.12ms  4.23ms
  5    congested-router      50.0%   10    5     45.23ms  78.45ms  125.34ms 32.12ms
```

## Interpreting Results

### Packet Loss

| Loss | Meaning | Action |
|------|---------|--------|
| 0% | Normal | None needed |
| 1-5% | Minor | Monitor |
| 5-20% | Degraded | Investigate |
| 20-50% | Severe | Contact ISP |
| 50%+ | Critical | Routing issue |
| 100% | Filtered | ICMP blocked |

### High Latency

| Issue | Cause | Solution |
|-------|-------|----------|
| First hop high | Local network | Check router/switch |
| Single hop spike | That router | May be normal (load) |
| All hops high | ISP issue | Contact provider |
| Last hop only | Destination | Server load |

### Asterisks (*)

- **Single hop:** Router doesn't respond to ICMP (common)
- **Multiple consecutive:** Firewall or routing issue
- **All hops:** Target unreachable

## Use Cases

### 1. Diagnose Latency

```bash
# Find which hop causes high latency
rb network mtr trace slow-server.com --iterations 20

# Look for:
# - High AVG at specific hop
# - High STDDEV (inconsistent)
# - Packet loss percentage
```

### 2. Verify Network Path

```bash
# Check route packets take
rb network run trace target.com

# Verify expected hops (ISP, CDN, destination)
```

### 3. Debug Connectivity

```bash
# Find where packets drop
rb network mtr trace unreachable.example.com

# 100% loss at hop N = firewall at that hop
# Intermittent loss = congested link
```

### 4. Compare Routes

```bash
# Primary server
rb network run trace primary.example.com > route1.txt

# Backup server
rb network run trace backup.example.com > route2.txt

# Compare
diff route1.txt route2.txt
```

## Next Steps

- [Port Scanning](01-ports.md) - Scan ports on targets
- [Host Discovery](02-host.md) - Find alive hosts
- [Configuration](04-configuration.md) - Customize settings
