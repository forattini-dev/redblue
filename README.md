<div align="center">

# redblue

**The Ultimate Security Arsenal in a Single Binary**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Size](https://img.shields.io/badge/size-2.7MB-green.svg)](https://github.com/forattini-dev/redblue/releases)
[![CI](https://github.com/forattini-dev/redblue/workflows/CI/badge.svg)](https://github.com/forattini-dev/redblue/actions/workflows/ci.yml)
[![Next Release](https://github.com/forattini-dev/redblue/workflows/Next%20Release/badge.svg)](https://github.com/forattini-dev/redblue/actions/workflows/next-release.yml)
[![GitHub release](https://img.shields.io/github/v/release/forattini-dev/redblue?include_prereleases&label=latest)](https://github.com/forattini-dev/redblue/releases)

*30+ security tools in one binary. Zero dependencies. 100% Rust.*

[**Documentation**](https://forattini-dev.github.io/redblue/) |
[Quick Start](#-quick-start) |
[Install](#-installation)

</div>

---

## What is redblue?

**redblue** replaces your entire security toolkit with a single, self-contained binary.

No installation scripts. No dependency chains. No version conflicts. Just download and execute.

We implement network protocols **from scratch** using only Rust's standard library. Zero external dependencies for protocols like DNS, HTTP, TLS, TCP/UDP, and ICMP.

## Features

| Category | Capabilities |
|----------|-------------|
| **Network** | **Advanced Port Scanning** (SYN/UDP/Stealth), OS fingerprinting, service detection, traceroute |
| **Recon** | **Subdomain Bruteforce** (Active), Passive Discovery (CT/Wayback/HackerTarget), DNS resolution, WHOIS, OSINT (Email/Usernames) |
| **Web** | **Fuzzing** (Dir/Vhost/Param), Vulnerability Scanning, CMS fingerprinting, TLS auditing, crawling, HAR recording |
| **Auth** | **Credential Testing** (Basic/Digest/Form), Brute-force protection awareness, rate limiting |
| **Secrets** | **Secrets Detection** (Git history, files), Entropy checks, API key validation, 800+ signatures |
| **Vuln Intel** | CVE search, CISA KEV catalog, Exploit-DB, NVD/OSV queries, CPE mapping, risk scoring |
| **Scraping** | CSS selectors, DOM parsing, extractors (links, images, forms, tables, meta), rule-based scraping |
| **HAR** | HTTP Archive recording, replay, export to curl/wget/python/httpie |
| **Cloud** | Subdomain takeover detection, cloud service enumeration |
| **Crypto** | File encryption vault (AES-256-GCM), PBKDF2 key derivation, secure storage |

## Quick Start

```bash
# Network reconnaissance
rb network scan ports 192.168.1.1 --type syn
rb network discover host 10.0.0.0/24

# DNS & Subdomain Enumeration
rb recon domain subdomains example.com --passive
rb recon domain bruteforce example.com -w wordlists/subdomains.txt

# Web Fuzzing
rb web fuzz http://example.com/FUZZ -w wordlists/common.txt
rb web fuzz http://example.com/api/FUZZ -mc 200,403

# Credential Testing
rb auth test http://example.com/login -u users.txt -p pass.txt --type form
rb auth test http://example.com/admin --type basic

# Secrets Detection
rb recon domain secrets . --git  # Scan current dir and git history

# Web security audit
rb web security asset http://example.com
rb tls audit security example.com

# Web scraping & HAR
rb web asset scrape http://example.com --select "h1, h2, h3"
rb web asset crawl http://example.com --har crawl.har

# Vulnerability intelligence
rb intel vuln search nginx 1.18.0
rb intel vuln cve CVE-2021-44228

# Crypto vault
rb crypto vault encrypt secrets.txt
```

---

## Web Fuzzing

redblue features a high-performance web fuzzer designed to discover hidden resources, directories, and parameters.

- **Modes**: Directory, File, Parameter, and VHost fuzzing
- **Filters**: Filter by size (`-fs`), code (`-fc`), words (`-fw`), lines (`-fl`)
- **Recursion**: Automatically scan newly discovered directories
- **Smart**: Auto-calibration baseline to reduce false positives
- **Fast**: Multi-threaded architecture

```bash
# Basic directory fuzzing
rb web fuzz http://target.com/FUZZ -w common.txt

# Filter out 404 responses and responses of size 123
rb web fuzz http://target.com/FUZZ -w common.txt -fc 404 -fs 123
```

## Credential Testing

The authentication module supports testing credentials against various services with safety features to prevent lockouts.

- **Protocols**: HTTP Basic, HTTP Digest, HTML Forms
- **Safety**: Rate limiting, jitter (random delay), lockout detection (429/403 backoff)
- **Input**: User/Pass lists, combinations, or single credentials

```bash
# Test HTTP Basic Auth with 500ms delay
rb auth test http://10.10.10.1 -u users.txt -p pass.txt --type basic --delay 500
```


## Installation

### Quick Install (Recommended)

```bash
# Install latest stable release
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash

# Install latest pre-release (next channel)
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --channel next

# Install specific version
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --version v0.1.0

# Install to custom directory
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --install-dir /usr/local/bin

# Static build (for Alpine/Docker)
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --static
```

**Supported Platforms:**
- Linux x86_64, aarch64 (ARM64), armv7
- macOS x86_64 (Intel), aarch64 (Apple Silicon)
- Windows x86_64

### Build from Source

```bash
git clone https://github.com/forattini-dev/redblue
cd redblue && cargo build --release
```

## Documentation

Full documentation, guides, and API reference available at:

**[forattini-dev.github.io/redblue](https://forattini-dev.github.io/redblue/)**

Or run locally:

```bash
cd docs && npx docsify-cli serve
```

---

## Vulnerability Intelligence

redblue includes a comprehensive vulnerability intelligence system that aggregates data from multiple authoritative sources:

### Data Sources

| Source | Description | Data Type |
|--------|-------------|-----------|
| **NVD** | NIST National Vulnerability Database | CVE details, CVSS scores, CPE matches |
| **OSV** | Open Source Vulnerabilities | Package-specific vulns (npm, PyPI, Cargo, etc.) |
| **CISA KEV** | Known Exploited Vulnerabilities | Actively exploited CVEs with remediation deadlines |
| **Exploit-DB** | Exploit Database | Public exploits, PoCs, Metasploit modules |

### Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Fingerprinting  │────▶│ CPE Mapping  │────▶│ Vuln Sources    │
│                 │     │              │     │                 │
│ nginx 1.18.0    │     │ cpe:2.3:a:   │     │ NVD, OSV, KEV   │
│ PHP 8.1         │     │ f5:nginx:... │     │ Exploit-DB      │
└─────────────────┘     └──────────────┘     └────────┬────────┘
                                                      │
                                                      ▼
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Risk Report     │◀────│ Risk Score   │◀────│ Deduplication   │
│                 │     │              │     │                 │
│ CVE-2024-1234   │     │ CVSS + KEV + │     │ Merge by CVE ID │
│ Risk: 95/100    │     │ Exploit      │     │                 │
└─────────────────┘     └──────────────┘     └─────────────────┘
```

### Risk Score Formula

The risk score (0-100) is calculated using multiple factors:

```
Risk = (CVSS × 10) + Exploit Bonus + KEV Bonus + Age Factor + Impact Modifier

Where:
- CVSS × 10:        Base score (0-100 from CVSS 0.0-10.0)
- Exploit Bonus:    +25 if public exploit exists
- KEV Bonus:        +30 if in CISA KEV catalog (actively exploited)
- Age Factor:       -5 to +10 based on CVE age (newer = higher risk)
- Impact Modifier:  Adjusted by severity level
```

### CPE Dictionary

The built-in CPE (Common Platform Enumeration) dictionary maps 60+ technologies to their official CPE identifiers:

| Category | Technologies |
|----------|--------------|
| **Web Servers** | nginx, Apache, IIS, LiteSpeed, Caddy, Tomcat, Jetty |
| **Frameworks** | Express, Django, Flask, Rails, Laravel, Spring, FastAPI |
| **CMS** | WordPress, Drupal, Joomla, Magento, Ghost, Strapi |
| **Runtimes** | PHP, Node.js, Python, Ruby, Java, .NET, Go |
| **Databases** | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| **JS Libraries** | jQuery, React, Vue, Angular, Lodash, Bootstrap |

### CLI Commands

```bash
# Search vulnerabilities for a technology
rb intel vuln search nginx
rb intel vuln search nginx 1.18.0                    # With version
rb intel vuln search lodash --source osv --ecosystem npm  # OSV for packages

# Get detailed CVE information
rb intel vuln cve CVE-2021-44228                     # Log4Shell details
rb intel vuln cve CVE-2024-3400                      # With exploit enrichment

# Check CISA KEV catalog
rb intel vuln kev --stats                            # Catalog statistics
rb intel vuln kev --vendor Microsoft                 # Filter by vendor
rb intel vuln kev --product "Windows Server"         # Filter by product

# Search Exploit-DB
rb intel vuln exploit "Apache Struts"
rb intel vuln exploit "privilege escalation linux"

# List CPE mappings
rb intel vuln cpe                                    # All mappings
rb intel vuln cpe --category webserver               # By category
rb intel vuln cpe --search nginx                     # Search
```

### Example Output

```
Vulnerability Search: nginx 1.18.0
Source: nvd

[✓] Found 12 vulnerabilities from NVD
[✓] Checking CISA KEV...

Results (12 total, showing top 10)

[95] CRIT CVE-2021-23017 - nginx DNS resolver heap buffer overflow [KEV] [EXP]
[87] HIGH CVE-2021-3618  - ALPACA attack allows cross-protocol attacks
[72] HIGH CVE-2019-20372 - HTTP request smuggling via chunked encoding
[68] MED  CVE-2020-12440 - Denial of service via specially crafted request
...
```

### Severity Levels

| Level | CVSS Range | Color | Risk Score Impact |
|-------|------------|-------|-------------------|
| **CRITICAL** | 9.0 - 10.0 | Red | +30 base |
| **HIGH** | 7.0 - 8.9 | Orange | +20 base |
| **MEDIUM** | 4.0 - 6.9 | Yellow | +10 base |
| **LOW** | 0.1 - 3.9 | Cyan | +5 base |
| **NONE** | 0.0 | Gray | 0 base |

### Integration with Fingerprinting

The vulnerability intelligence system integrates with redblue's service fingerprinting:

```bash
# Full recon → fingerprint → vulnerability pipeline (coming soon)
rb recon full example.com --vulns

# Will automatically:
# 1. Enumerate subdomains
# 2. Scan ports & fingerprint services
# 3. Map technologies to CPEs
# 4. Query vulnerability databases
# 5. Calculate risk scores
# 6. Generate prioritized report
```

---

## Crypto Vault

redblue includes a secure file encryption vault for storing sensitive data like credentials, API keys, and configuration files.

### Security Features

| Feature | Implementation |
|---------|---------------|
| **Encryption** | AES-256-GCM (Galois/Counter Mode) - authenticated encryption |
| **Key Derivation** | PBKDF2-HMAC-SHA256 with 100,000 iterations |
| **Salt** | 32 bytes of cryptographic randomness from `/dev/urandom` |
| **Nonce** | 12 bytes of cryptographic randomness (unique per encryption) |
| **Authentication** | 16-byte GCM tag prevents tampering and detects wrong passwords |

### Vault File Format

```
┌──────────┬─────────┬──────────┬───────────┬────────────┬──────────┐
│  MAGIC   │ VERSION │   SALT   │   NONCE   │ CIPHERTEXT │   TAG    │
│  (4B)    │  (1B)   │  (32B)   │   (12B)   │   (var)    │  (16B)   │
└──────────┴─────────┴──────────┴───────────┴────────────┴──────────┘
     │          │         │          │            │           │
     │          │         │          │            │           └─ GCM auth tag
     │          │         │          │            └─ AES-256-GCM encrypted data
     │          │         │          └─ Unique nonce for CTR mode
     │          │         └─ Random salt for PBKDF2
     │          └─ Format version (currently 1)
     └─ "RBVT" magic bytes
```

### CLI Commands

```bash
# Encrypt a file (prompts for password)
rb crypto vault encrypt secrets.txt

# Encrypt with custom output path
rb crypto vault encrypt config.json --output config.vault

# Encrypt with inline password (for scripts)
rb crypto vault encrypt data.json --password "mySecurePassword"

# Decrypt a vault file (prompts for password)
rb crypto vault decrypt secrets.vault

# Decrypt to custom path
rb crypto vault decrypt data.vault --output data.json

# Overwrite existing output file
rb crypto vault decrypt data.vault --force

# Show vault metadata (no password needed)
rb crypto vault info secrets.vault
```

### Example Output

```bash
$ rb crypto vault encrypt api-keys.json

▸ Encrypting File
  Input        api-keys.json
  Output       api-keys.json.vault
  Size         256 bytes

Password: ********
Confirm password: ********
Deriving key from password ✓
Encrypting with AES-256-GCM ✓

✓ Encrypted 256 bytes -> api-keys.json.vault
ℹ Vault size: 321 bytes (overhead: 65 bytes)
```

```bash
$ rb crypto vault info api-keys.json.vault

▸ Vault File Info
  File         api-keys.json.vault
  Total size   321 bytes

Vault Details
  Magic        RBVT (valid)
  Version      1
  Salt size    32 bytes
  Nonce size   12 bytes
  Ciphertext   256 bytes
  Auth tag     16 bytes

Security
  Encryption      AES-256-GCM
  Key derivation  PBKDF2-HMAC-SHA256 (100000 iterations)
  Authentication  GCM (AEAD)
```

### Security Guarantees

- **Confidentiality**: AES-256 encryption protects data from unauthorized access
- **Integrity**: GCM authentication tag detects any tampering or corruption
- **Authentication**: Wrong password is immediately detected (no partial decryption)
- **Key Stretching**: 100,000 PBKDF2 iterations slow down brute-force attacks
- **Unique Keys**: Random salt ensures identical passwords produce different keys
- **Nonce Safety**: Random nonce ensures identical plaintexts produce different ciphertexts

### Use Cases

- Store API keys and credentials securely
- Encrypt configuration files with sensitive data
- Protect SSH keys or certificates for backup
- Secure export of reconnaissance data
- Encrypt session files before sharing

---

<div align="center">

**[Documentation](https://forattini-dev.github.io/redblue/)** |
**[GitHub](https://github.com/forattini-dev/redblue)** |
**[Releases](https://github.com/forattini-dev/redblue/releases)**

*Made with Rust by security engineers, for security engineers*

</div>
