# redblue vs Traditional Tools

> Complete comparison of redblue commands to traditional security tools

## Overview

redblue replaces 30+ security tools with a single binary, implementing all protocols from scratch using only Rust's standard library.

**Key Advantages:**
- **Single binary** - No dependencies to install
- **Consistent CLI** - Same syntax across all features
- **Unified storage** - All data in one database
- **Cross-platform** - Works everywhere Rust compiles

## Network Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `nmap -sS` | `rb network ports scan --mode syn` | SYN scan (requires root) |
| `nmap -sT` | `rb network ports scan --mode connect` | Connect scan |
| `nmap -p 80,443` | `rb network ports scan --ports 80,443` | Specific ports |
| `nmap -F` | `rb network ports scan --preset common` | Top 100 ports |
| `nmap -sP` | `rb network host discover` | Host discovery |
| `masscan` | `rb network ports scan --mode syn --rate 10000` | High-speed scanning |
| `hping3` | `rb network ping --mode tcp` | TCP ping |
| `ping` | `rb network ping` | ICMP ping |
| `traceroute` | `rb network trace route` | Route tracing |

### Example: Port Scan Comparison

```bash
# Traditional
nmap -sS -p 1-1000 192.168.1.1

# redblue
sudo rb network ports scan 192.168.1.1 --ports 1-1000 --mode syn
```

## DNS Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `dig A example.com` | `rb dns record lookup example.com` | A record |
| `dig MX example.com` | `rb dns record lookup example.com --type MX` | MX record |
| `dig @8.8.8.8` | `rb dns record lookup example.com --server 8.8.8.8` | Custom resolver |
| `nslookup` | `rb dns record lookup` | DNS lookup |
| `host` | `rb dns record lookup` | Host lookup |
| `dnsrecon` | `rb dns zone transfer` | Zone transfer |

### Example: DNS Query Comparison

```bash
# Traditional
dig +short MX example.com @8.8.8.8

# redblue
rb dns record lookup example.com --type MX --server 8.8.8.8 --short
```

## Web Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `curl` | `rb web asset get` | HTTP requests |
| `wget` | `rb web asset get` | File download |
| `curl -I` | `rb web asset headers` | Headers only |
| `nikto` | `rb web vuln scan` | Vulnerability scan |
| `dirb` | `rb web fuzz dir` | Directory fuzzing |
| `gobuster` | `rb web fuzz dir` | Directory brute |
| `wfuzz` | `rb web fuzz` | General fuzzing |
| `ffuf` | `rb web fuzz dir` | Fast fuzzing |
| `whatweb` | `rb web fingerprint` | Tech detection |
| `wappalyzer` | `rb web fingerprint` | Stack fingerprint |

### Example: Fuzzing Comparison

```bash
# Traditional (gobuster)
gobuster dir -u http://example.com -w wordlist.txt

# redblue
rb web fuzz dir http://example.com/FUZZ --wordlist wordlist.txt
```

## Reconnaissance Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `whois` | `rb recon domain whois` | WHOIS lookup |
| `subfinder` | `rb recon subdomain enum` | Subdomain enum |
| `amass` | `rb recon subdomain enum` | Subdomain discovery |
| `sublist3r` | `rb recon subdomain enum` | Subdomain list |
| `theHarvester` | `rb recon harvest` | Email/name harvest |
| `shodan` | `rb intel search` | Service search |
| `censys` | `rb intel search` | Certificate search |

### Example: Subdomain Enumeration Comparison

```bash
# Traditional (subfinder)
subfinder -d example.com -o subs.txt

# redblue
rb recon subdomain enum example.com --output json > subs.json
```

## TLS/SSL Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `testssl.sh` | `rb tls audit` | Full TLS audit |
| `sslyze` | `rb tls audit` | SSL analysis |
| `sslscan` | `rb tls scan` | SSL enumeration |
| `openssl s_client` | `rb tls cert show` | Certificate view |

### Example: TLS Audit Comparison

```bash
# Traditional
testssl.sh example.com

# redblue
rb tls audit example.com
```

## Intelligence Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `searchsploit` | `rb intel vuln search` | Exploit search |
| `cve-search` | `rb intel vuln cve` | CVE lookup |
| `nvd-cli` | `rb intel vuln search` | NVD query |

### Example: CVE Lookup Comparison

```bash
# Traditional
searchsploit nginx 1.18

# redblue
rb intel vuln search nginx 1.18
```

## Exploitation Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `msfvenom` (shell) | `rb exploit payload shell` | Shell payloads |
| `netcat -lvp` | `rb nc listen` | Listener |
| `netcat host port` | `rb nc connect` | Connect |

### Example: Shell Generation Comparison

```bash
# Traditional
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444

# redblue
rb exploit payload shell bash 10.0.0.1 4444
```

## Screenshot Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `aquatone` | `rb collection screenshot batch --report` | Batch screenshots |
| `eyewitness` | `rb collection screenshot batch` | Visual recon |
| `gowitness` | `rb collection screenshot capture` | Single capture |

### Example: Screenshot Comparison

```bash
# Traditional
cat urls.txt | aquatone

# redblue
rb collection screenshot batch urls.txt --report
```

## Code Analysis Tools

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `gitleaks` | `rb code secrets scan` | Secret detection |
| `trufflehog` | `rb code secrets scan` | Token finding |
| `snyk` | `rb code deps audit` | Dependency audit |
| `npm audit` | `rb code deps audit` | npm vulns |

### Example: Secret Scanning Comparison

```bash
# Traditional
gitleaks detect --source .

# redblue
rb code secrets scan .
```

## Feature Comparison Matrix

| Feature | nmap | masscan | nikto | testssl | redblue |
|---------|------|---------|-------|---------|---------|
| Port scan | Yes | Yes | - | - | Yes |
| Service detect | Yes | - | - | - | Yes |
| Web vuln | - | - | Yes | - | Yes |
| TLS audit | - | - | - | Yes | Yes |
| Single binary | No | No | No | No | **Yes** |
| Unified storage | No | No | No | No | **Yes** |
| MCP support | No | No | No | No | **Yes** |

## Performance Comparison

| Operation | nmap | redblue | Notes |
|-----------|------|---------|-------|
| SYN scan (1000 ports) | ~30s | ~25s | Similar performance |
| Full port scan | ~5min | ~4min | redblue slightly faster |
| Service detection | ~2min | ~1.5min | Parallel probing |

## Migration Guide

### From nmap

```bash
# Common nmap flags to redblue
-sS → --mode syn
-sT → --mode connect
-p  → --ports
-F  → --preset common
-sV → (automatic in redblue)
-oN → --output text
-oJ → --output json
```

### From Burp/ZAP

```bash
# Crawling
rb web crawl http://example.com --depth 3

# Fuzzing
rb web fuzz dir http://example.com/FUZZ

# Vulnerability scan
rb web vuln scan http://example.com
```

## See Also

- [CLI Commands](/cli-commands.md) - Full command reference
- [Architecture](/architecture/00-overview.md) - How redblue works
- [Troubleshooting](troubleshooting.md) - Common issues
