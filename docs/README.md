# redblue

> The Ultimate Security Arsenal in a Single Binary

**redblue** consolidates 30+ security tools into a single, self-contained executable. Zero dependencies. 100% Rust. One command to rule them all.

## Why redblue?

**Traditional approach:**
```bash
# Installing 30+ tools
apt-get install nmap masscan nikto ffuf subfinder amass...
# Total size: 500+ MB
# Each tool has different CLI syntax
```

**redblue approach:**
```bash
# One binary, does everything
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash
# Total size: ~3MB
# Consistent kubectl-style CLI
```

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash

# Network scanning
rb network scan ports 192.168.1.1 --preset common

# DNS reconnaissance
rb dns lookup record example.com --type MX

# Web security audit
rb web security asset http://example.com

# TLS analysis
rb tls audit security github.com

# Cloud security
rb cloud takeover asset subdomain.example.com
```

## Core Capabilities

### Network Intelligence

Multi-threaded port scanning, host discovery, service fingerprinting, and network path tracing.

```bash
rb network scan ports 192.168.1.1 --preset common
rb network discover host 10.0.0.0/24
rb network run trace 8.8.8.8
rb network mtr trace 8.8.8.8
```

**Replaces:** nmap, masscan, fping, netdiscover, traceroute, mtr

### Reconnaissance & OSINT

DNS enumeration, WHOIS lookups, subdomain discovery, and data harvesting.

```bash
rb dns lookup record example.com --type MX
rb recon whois domain example.com
rb recon subdomains domain example.com
rb recon harvest domain example.com
rb recon urls domain example.com
```

**Replaces:** dig, nslookup, whois, amass, subfinder, theHarvester, waybackurls

### Web & TLS Security

HTTP security testing, CMS scanning, and comprehensive TLS/SSL analysis.

```bash
rb web security asset http://example.com
rb web cms-scan asset http://wordpress-site.com
rb tls audit security example.com
rb tls ciphers security example.com
rb tls vuln security example.com
```

**Replaces:** curl, nikto, wpscan, sslyze, testssl.sh, sslscan

### Cloud Security

Subdomain takeover detection and cloud misconfiguration scanning.

```bash
rb cloud takeover asset subdomain.example.com
rb cloud takeover-scan asset subdomains.txt
rb cloud services asset
```

**Replaces:** tko-subs, subjack, can-i-take-over-xyz

### Exploitation Framework

Reverse shells, privilege escalation scanning, and post-exploitation.

> **AUTHORIZED TESTING ONLY**

```bash
rb exploit shell payload bash 10.0.0.1 4444
rb exploit privesc payload /path/to/target
rb exploit lateral payload
rb exploit persist payload
rb exploit replicate payload --os linux
```

**Replaces:** LinPEAS (partial), reverse shell generators

## Installation

### Quick Install

```bash
# Latest stable
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash

# Latest alpha
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --channel alpha
```

### Manual Download

```bash
# Linux x86_64
wget https://github.com/forattini-dev/redblue/releases/latest/download/rb-linux-x86_64
chmod +x rb-linux-x86_64 && sudo mv rb-linux-x86_64 /usr/local/bin/rb

# macOS Apple Silicon
wget https://github.com/forattini-dev/redblue/releases/latest/download/rb-macos-aarch64
chmod +x rb-macos-aarch64 && sudo mv rb-macos-aarch64 /usr/local/bin/rb
```

### Build from Source

```bash
git clone https://github.com/forattini-dev/redblue
cd redblue
cargo build --release
./target/release/redblue --version
```

## Command Structure

redblue uses a consistent kubectl-style grammar:

```
rb <domain> <verb> <resource> [target] [flags]
```

| Component | Description | Examples |
|-----------|-------------|----------|
| **domain** | Capability area | `network`, `dns`, `web`, `recon`, `tls`, `exploit`, `cloud` |
| **verb** | Action to execute | `scan`, `lookup`, `audit`, `harvest`, `create` |
| **resource** | Dataset or tool | `ports`, `record`, `asset`, `domain`, `shell` |
| **target** | Subject | IP, domain, URL, file path |
| **flags** | Modifiers | `--preset`, `--timeout`, `--output` |

**Examples:**

```bash
rb network scan ports 192.168.1.1 --preset common
rb dns lookup record example.com --type MX
rb web security asset http://example.com
rb recon harvest domain example.com
rb tls audit security github.com
```

## Security & Ethics

**redblue is for authorized security testing only.**

- Authorized penetration testing with written permission
- CTF competitions and training
- Bug bounty programs (with scope approval)
- Your own infrastructure security audits

**Never use on systems you don't own or without proper authorization.**

## Architecture

All network protocols implemented from scratch using only Rust's standard library:

| Protocol | RFC | Status |
|----------|-----|--------|
| **DNS** | RFC 1035 | Complete |
| **HTTP/1.1** | RFC 2616 | Complete |
| **WHOIS** | RFC 3912 | Complete |
| **TLS** | RFC 5246, 8446 | In progress |
| **TCP/UDP** | RFC 793 | Complete |
| **ICMP** | RFC 792 | Complete |

**Binary size:** 2.7MB | **Dependencies:** Zero protocol crates

## Contributing

See [CONTRIBUTING.md](https://github.com/forattini-dev/redblue/blob/main/CONTRIBUTING.md) for guidelines.

```bash
cargo build && cargo test && cargo clippy
```

## License

MIT License - see [LICENSE](https://github.com/forattini-dev/redblue/blob/main/LICENSE)
