# Port Scanning

Multi-threaded TCP port scanning with service detection and banner grabbing.

## Quick Start

```bash
# Simplest usage - scan common ports
rb network scan ports 192.168.1.1

# Scan with preset
rb network scan ports example.com --preset common

# Fast masscan-style
rb network scan ports 10.0.0.1 --fast

# Custom port range
rb network range ports 192.168.1.1 80 443
```

## Commands

### scan - Preset-based Scanning

Scan a target using predefined port presets.

```bash
rb network scan ports <target> [flags]
```

### range - Custom Port Range

Scan a specific port range on a target.

```bash
rb network range ports <target> <start> <end> [flags]
```

### subnet - Network-wide Scanning

Discover and scan all hosts in a subnet.

```bash
rb network subnet ports <cidr> [flags]
```

## Options

```rust
// Port scanning options
struct PortScanOptions {
    // Port preset to use
    // Values: "common" (100 ports), "full" (65535), "web" (6 ports)
    // Default: "common"
    preset: String,

    // Number of concurrent scanner threads
    // Range: 1-10000
    // Default: 200
    threads: u32,

    // Connection timeout in milliseconds
    // Range: 100-30000
    // Default: 1000
    timeout_ms: u32,

    // Output format
    // Values: "text", "json", "yaml"
    // Default: "text"
    output: String,

    // Save results to binary database (.rdb)
    // Default: false
    persist: bool,

    // Gather intelligence (timing, fingerprinting)
    // Default: false
    intel: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--preset` | `-p` | Port preset: common, full, web | common |
| `--threads` | `-t` | Concurrent threads | 200 |
| `--timeout` | | Timeout in ms | 1000 |
| `--fast` | `-f` | Fast mode (1000 threads, 300ms) | false |
| `--output` | `-o` | Output format: text, json, yaml | text |
| `--persist` | | Save to .rdb file | false |
| `--intel` | `-i` | Gather intelligence | false |

## Port Presets

| Preset | Ports | Description |
|--------|-------|-------------|
| `common` | 100 | SSH, HTTP, HTTPS, FTP, SMTP, MySQL, etc. |
| `full` | 65,535 | All TCP ports (1-65535) |
| `web` | 6 | Web only: 80, 443, 8080, 8443, 3000, 5000 |

## Examples

### Basic Scanning

```bash
# Scan common ports
rb network scan ports 192.168.1.1
# → Scans 100 most common ports

# Scan web ports only
rb network scan ports example.com --preset web
# → Scans: 80, 443, 8080, 8443, 3000, 5000

# Full port scan
rb network scan ports 192.168.1.1 --preset full
# → Scans all 65,535 ports (slow)
```

### Performance Tuning

```bash
# Fast masscan-style (aggressive)
rb network scan ports 10.0.0.1 --fast
# → 1000 threads, 300ms timeout

# Custom thread count
rb network scan ports 192.168.1.1 --threads 500 --timeout 500

# Stealth mode (slow, fewer connections)
rb network scan ports target.com --threads 10 --timeout 2000
```

### Output Formats

```bash
# Default text output
rb network scan ports 192.168.1.1

# JSON for automation
rb network scan ports 192.168.1.1 -o json | jq '.ports'

# YAML output
rb network scan ports 192.168.1.1 -o yaml
```

### Intelligence Gathering

```bash
# Scan with service fingerprinting
rb network scan ports 192.168.1.1 --intel
# → Adds: vendor, version, OS, timing analysis, confidence score

# Full intelligence scan with persistence
rb network scan ports 192.168.1.1 --preset common --intel --persist
```

### Custom Port Ranges

```bash
# Scan range 80-443
rb network range ports 192.168.1.1 80 443

# Scan privileged ports (1-1024)
rb network range ports 192.168.1.1 1 1024

# Scan high ports
rb network range ports 192.168.1.1 8000 9000
```

### Subnet Scanning

```bash
# Discover and scan /24 network
rb network subnet ports 192.168.1.0/24

# Scan subnet with specific preset
rb network subnet ports 10.0.0.0/24 --preset web

# Full subnet scan with persistence
rb network subnet ports 192.168.1.0/24 --preset common --persist
```

## Output Examples

### Text Output

```
Scanning 192.168.1.1  [████████████████████████] 100/100 (2.3s)

Scan: 192.168.1.1 (5 open)
  PORT     STATE   SERVICE     BANNER
  22       open    ssh         SSH-2.0-OpenSSH_8.9p1 Ubuntu
  80       open    http        nginx/1.24.0
  443      open    https       -
  3306     open    mysql       5.7.44-0ubuntu0.18.04.1
  8080     open    http-proxy  Apache Tomcat/9.0.75

Results saved to 192.168.1.1.rdb
```

### JSON Output

```json
{
  "target": "192.168.1.1",
  "preset": "common",
  "scan_time_ms": 2300,
  "open_count": 5,
  "ports": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
    },
    {
      "port": 80,
      "state": "open",
      "service": "http",
      "banner": "nginx/1.24.0"
    }
  ]
}
```

### Intelligence Output

```
  22/ssh       SSH-2.0-OpenSSH_8.9p1 Ubuntu
    Vendor:     OpenSSH 8.9p1
    OS:         Ubuntu
    Timing:     conn=12ms, resp=45ms
    Confidence: 95%

  3306/mysql   5.7.44-0ubuntu0.18.04.1
    Vendor:     MySQL 5.7.44
    OS:         Ubuntu 18.04
    Timing:     conn=8ms, resp=23ms
    Confidence: 92%
```

## Patterns

### Reconnaissance Workflow

```bash
# Step 1: Quick web scan
rb network scan ports target.com --preset web

# Step 2: Common ports if web found
rb network scan ports target.com --preset common

# Step 3: Full scan if needed
rb network scan ports target.com --preset full --intel --persist
```

### Network Discovery

```bash
# Step 1: Find alive hosts
rb network discover host 192.168.1.0/24

# Step 2: Scan discovered hosts
rb network subnet ports 192.168.1.0/24 --preset common
```

### Automation Pipeline

```bash
# Scan and process results
rb network scan ports target.com -o json | jq -r '.ports[] | select(.state == "open") | .port'

# Batch scanning
for ip in $(cat targets.txt); do
  rb network scan ports $ip --preset common -o json >> results.json
done
```

## Performance Tips

| Scenario | Recommendation |
|----------|----------------|
| Fast scan | `--fast` or `--threads 1000 --timeout 300` |
| Accurate | `--threads 200 --timeout 2000` |
| Stealth | `--threads 10 --timeout 3000` |
| Large network | `--preset web` + `--fast` |

## Technical Notes

- **Method:** TCP connect scan (full three-way handshake)
- **Protocol:** IPv4 only (IPv6 planned)
- **Service detection:** Banner grabbing + port-based heuristics
- **Limitations:** SYN scan requires raw sockets (planned)

## Next Steps

- [Host Discovery](02-host.md) - Find alive hosts
- [Path Tracing](03-trace.md) - Trace network routes
- [Configuration](04-configuration.md) - Customize settings
- [Troubleshooting](05-troubleshooting.md) - Common issues
