# Quick Start

Get up and running with redblue in 5 minutes.

## First Steps

After [installation](/getting-started/installation.md), verify redblue is working:

```bash
rb --version
rb help
```

## Basic Scanning

### Network Reconnaissance

```bash
# Port scan
rb network scan ports 192.168.1.1 --preset common

# Discover hosts on network
rb network discover host 192.168.1.0/24

# Ping a host
rb network ping host google.com --count 5
```

### DNS Queries

```bash
# Lookup A record
rb dns lookup record example.com

# Lookup MX records
rb dns lookup record example.com --type MX

# Quick resolve
rb dns resolve record github.com
```

### Web Security

```bash
# Security headers audit
rb web security asset http://example.com

# Get HTTP headers
rb web headers asset http://example.com

# CMS detection
rb web cms-scan asset http://wordpress-site.com
```

### TLS Analysis

```bash
# Full TLS audit
rb tls audit security github.com

# Cipher enumeration
rb tls ciphers security example.com

# Vulnerability scan
rb tls vuln security example.com
```

## OSINT & Recon

```bash
# WHOIS lookup
rb recon whois domain example.com

# Subdomain enumeration
rb recon subdomains domain example.com

# Data harvesting
rb recon harvest domain example.com
```

## Cloud Security

```bash
# Check subdomain takeover
rb cloud takeover asset subdomain.example.com

# Batch scan
rb cloud takeover-scan asset subdomains.txt
```

## Real-World Workflow

### 1. Initial Reconnaissance

```bash
# Gather domain intel
rb recon whois domain target.com
rb dns lookup record target.com --type A
rb dns lookup record target.com --type MX
rb dns lookup record target.com --type NS
```

### 2. Subdomain Discovery

```bash
rb recon subdomains domain target.com
```

### 3. Port Scanning

```bash
rb network scan ports target.com --preset common
```

### 4. Web Security Audit

```bash
rb web security asset http://target.com
rb tls audit security target.com
```

## Getting Help

```bash
# Global help
rb help

# Domain help
rb network help
rb dns help

# Command help
rb network scan ports --help
```

## Next Steps

- [CLI Semantics](/cli-semantics.md) - Learn the command structure
- [Domains](/domains/index.md) - Explore all capabilities
- [Guides](/guides/) - Advanced tutorials
