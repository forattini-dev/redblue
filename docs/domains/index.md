<div align="center">

# 📚 redblue Domain Documentation

## TL;DR
Landing page that maps each CLI domain to its detailed guide, quick navigation, and reference material.

Complete reference documentation for all redblue CLI domains.

[Quick Start](#-quick-navigation) • [Domains](#-available-domains) • [Search](#-search-tips) • [Root Docs](/../README.md)

</div>

---

## Release Snapshot (Nov 2025)

- CLI core (`rb [domain] [resource] [verb]`) delivers network, DNS, web, TLS, recon, exploit, database, collection, and benchmarking flows with contextual help, typo suggestions, and semantic coloring.
- Network stack ships multi-threaded port scanning presets, service detection, traceroute/MTR scaffolding, and `.rdb` persistence.
- DNS and recon cover RFC 1035 lookups, WHOIS (multi-TLD), passive/active subdomain collection, and OSINT harvesting.
- Web tooling includes an HTTP/1.1 client, header analysis, CMS scanning, and TLS certificate inspection; TLS domain provides audit/cipher/vulnerability verbs.
- Crypto foundation: pure Rust SHA-256, HMAC, TLS 1.2 PRF, AES-128 (CBC/GCM), RSA PKCS#1 v1.5, BigInt arithmetic, and TLS stream integration—no external crates.
- UX wins: config generator (`rb config init create`), improved error messaging with verb/resource hints, kebab-case module alignment, `.rdb` storage standardization, and intelligence-rich output flags.

---

## 📚 Available Domains

<div align="right">

[⬆ Back to Top](#-redblue-domain-documentation)

</div>

### Network Intelligence

**Commands:** `rb network ports <verb>`, `rb network host <verb>`, `rb network trace run <verb>`

- **[NETWORK.md](/domains/network.md)** - Port scanning, host discovery, network mapping, path tracing
  - Port scanning - `rb network ports scan` (TCP connect, SYN scan) ✅
  - Custom port ranges - `rb network ports range` ✅
  - Host discovery - `rb network host discover` (ICMP ping, CIDR sweeps) ✅
  - Ping testing - `rb network host ping` ✅
  - Network path tracing - `rb network trace run` (traceroute) ✅
  - MTR monitoring - `rb network trace mtr` ✅
  - Service detection and banner grabbing
  - Intelligence gathering (timing, fingerprinting)

<div align="right">

[⬆ Back to Top](#-redblue-domain-documentation) • [➡️ Next: Web Security](#web-security)

</div>

### DNS & Domain Recon

**Commands:** `rb dns record <verb>`, `rb recon domain <verb>`

- **[DNS.md](/domains/dns.md)** - DNS reconnaissance and enumeration
  - DNS lookups - `rb dns record lookup` (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR) ✅
  - Quick resolve - `rb dns record resolve` ✅
  - Parallel queries for speed
  - DNS server fingerprinting (VERSION.BIND)
  - Reverse DNS lookups
  - Subdomain brute force (planned)

- **[RECON.md](/domains/recon.md)** - WHOIS, subdomain discovery, OSINT, data harvesting
  - WHOIS lookups - `rb recon domain whois` (multi-TLD support) ✅
  - Subdomain enumeration - `rb recon domain subdomains` (passive + active) ✅
  - Data harvesting - `rb recon domain harvest` (theHarvester style) ✅
  - Historical URL discovery - `rb recon domain urls` (Wayback, URLScan, OTX) ✅
  - Email reconnaissance - `rb recon domain email` (planned)
  - Username OSINT - `rb recon domain osint` (planned)

<div align="right">

[⬆ Back to Top](#-redblue-domain-documentation) • [⬅️ Previous: DNS & Recon](#dns--domain-recon) • [➡️ Next: Cloud & Code](#cloud-security)

</div>

### Web Security

**Commands:** `rb web asset <verb>`, `rb tls security <verb>`

- **[WEB.md](/domains/web.md)** - HTTP testing, security audits, CMS scanning
  - HTTP requests - `rb web asset get` (GET/POST from scratch) ✅
  - Header analysis - `rb web asset headers` ✅
  - Security audit - `rb web asset security` ✅
  - CMS scanning - `rb web asset scan` (WordPress, Drupal, Joomla) ✅
  - Directory fuzzing - `rb web asset fuzz` (planned)
  - Web crawling - `rb web asset crawl` (planned)
  - JavaScript endpoint extraction

- **[TLS.md](/domains/tls.md)** - TLS/SSL security testing and vulnerability scanning
  - Full TLS audit - `rb tls security audit` (sslyze replacement) ✅
  - Cipher enumeration - `rb tls security ciphers` (sslscan replacement) ✅
  - Vulnerability scan - `rb tls security vuln` (testssl.sh replacement) ✅
  - Certificate validation and chain analysis ✅
  - Protocol version testing (TLS 1.3/1.2/1.1/1.0, SSL 3.0) ✅
  - Known CVEs (POODLE, BEAST, Heartbleed, CRIME, FREAK, Logjam, DROWN, Sweet32) ✅

<div align="right">

[⬆ Back to Top](#-redblue-domain-documentation) • [⬅️ Previous: Web Security](#web-security) • [➡️ Next: Exploitation](#exploitation--post-exploitation)

</div>

### Cloud Security

**Commands:** `rb cloud asset <verb>`, `rb cloud storage <verb>`, `rb code secrets <verb>`, `rb code dependencies <verb>`

- **[CLOUD.md](/domains/cloud.md)** - Cloud storage, subdomain takeover detection
  - Subdomain takeover - `rb cloud asset takeover` (tko-subs/subjack) ✅
  - Batch scanning - `rb cloud asset takeover-scan` ✅
  - Service fingerprints - `rb cloud asset services` (25+ services) ✅
  - Confidence levels (HIGH/MEDIUM/LOW/NONE) ✅
  - S3 bucket enumeration - `rb cloud storage scan` (planned)
  - Azure/GCS testing (planned)

- **[CODE.md](/domains/code.md)** - Secrets scanning, dependency analysis
  - Secret detection - `rb code secrets scan` (gitleaks style, planned)
  - Dependency vulns - `rb code dependencies scan` (planned)
  - SAST (Static Application Security Testing) (planned)
  - API key leakage detection

<div align="right">

[⬆ Back to Top](#-redblue-domain-documentation) • [⬅️ Previous: Cloud Security](#cloud-security) • [➡️ Next: Database & Collection](#database-operations)

</div>

### Exploitation & Post-Exploitation

**Commands:** `rb exploit payload <verb>` ⚠️ **AUTHORIZED USE ONLY**

- **[EXPLOIT.md](/domains/exploit.md)** - Exploitation framework and post-exploitation
  - Privilege escalation - `rb exploit payload privesc` (LinPEAS/WinPEAS) ✅
  - Reverse shells - `rb exploit payload shell` (11 shell types) ✅
  - Listener setup - `rb exploit payload listener` (nc, socat, metasploit) ✅
  - Lateral movement - `rb exploit payload lateral` (11 techniques) ✅
  - Persistence - `rb exploit payload persist` (8 mechanisms) ✅

### Access & Sessions

**Commands:** `rb access shell <verb>`

- **[ACCESS.md](/domains/access.md)** - Shell lifecycle management
  - Session management - `rb access shell sessions` ✅
  - Listeners - `rb access shell listen` (TCP/HTTP) ✅
  - Interaction - `rb access shell connect` ✅
  - HTTP C2 - `rb access shell create --protocol http` ✅

<div align="right">

[⬆ Back to Top](#-redblue-domain-documentation) • [⬅️ Previous: Exploitation](#exploitation--post-exploitation)

</div>

### Database Operations

**Commands:** `rb database data <verb>`

- **[DATABASE.md](/domains/database.md)** - RedDB operations and management
  - Query operations - `rb database data query` ✅
  - CSV export - `rb database data export` ✅
  - List targets - `rb database data list` ✅
  - Subnet analysis - `rb database data subnets` ✅
  - Binary format (.rdb) - 3x smaller than JSON, 5x faster ✅

### Collection & Performance

**Commands:** `rb collection screenshot <verb>`, `rb bench load <verb>`

- **[COLLECTION.md](/domains/collection.md)** - Screenshots, data gathering
  - Screenshot capture - `rb collection screenshot capture` (planned)
  - Batch processing - `rb collection screenshot batch` (planned)
  - Chrome DevTools Protocol (CDP) integration

- **[BENCH.md](/domains/bench.md)** - Load testing, benchmarking
  - HTTP load testing - `rb bench load test` (wrk/k6 style, planned)
  - Performance profiling
  - Stress testing

### MCP Integration

**Commands:** `rb mcp server <verb>`

- **[MCP.md](/domains/mcp.md)** - Model Context Protocol server
  - AI Integration - `rb mcp server start` ✅
  - Semantic Search - Docs and resource search ✅
  - Tool Exposure - `rb.scan_ports`, `rb.lookup_dns`, etc. ✅

---

## 🎯 Quick Navigation by Task

### Reconnaissance
1. DNS lookup → [DNS.md](/domains/dns.md)
2. WHOIS → [RECON.md](/domains/recon.md)
3. Subdomain discovery → [RECON.md](/domains/recon.md)
4. Data harvesting (emails, IPs, URLs) → [RECON.md](/domains/recon.md) ✅
5. Historical URLs (Wayback) → [RECON.md](/domains/recon.md) ✅
6. Network discovery → [NETWORK.md](/domains/network.md)
7. Network path tracing → [NETWORK.md](/domains/network.md) ✅

### Scanning
1. Port scanning → [NETWORK.md](/domains/network.md)
2. Web application → [WEB.md](/domains/web.md)
3. TLS/SSL audit → [TLS.md](/domains/tls.md) ✅
4. TLS vulnerability scan → [TLS.md](/domains/tls.md) ✅
5. Cipher enumeration → [TLS.md](/domains/tls.md) ✅
6. CMS vulnerability → [WEB.md](/domains/web.md)

### Security Testing
1. Security headers → [WEB.md](/domains/web.md)
2. Directory fuzzing → [WEB.md](/domains/web.md)
3. Secret scanning → [CODE.md](/domains/code.md)
4. Subdomain takeover → [CLOUD.md](/domains/cloud.md) ✅
5. TLS vulnerabilities → [TLS.md](/domains/tls.md) ✅

### Intelligence Gathering
1. Service fingerprinting → [NETWORK.md](/domains/network.md)
2. Web technologies → [WEB.md](/domains/web.md)
3. DNS server info → [DNS.md](/domains/dns.md)
4. HTTP server → [WEB.md](/domains/web.md)
5. OSINT data harvesting → [RECON.md](/domains/recon.md) ✅

### Exploitation & Access
1. Privilege escalation → [EXPLOIT.md](/domains/exploit.md) ✅
2. Reverse shell generation → [EXPLOIT.md](/domains/exploit.md) ✅
3. Listener setup → [ACCESS.md](/domains/access.md) ✅
4. Session management → [ACCESS.md](/domains/access.md) ✅
5. Lateral movement → [EXPLOIT.md](/domains/exploit.md) ✅
6. Persistence mechanisms → [EXPLOIT.md](/domains/exploit.md) ✅

### Data Management
1. Query scan results → [DATABASE.md](/domains/database.md) ✅
2. Export to CSV → [DATABASE.md](/domains/database.md) ✅
3. List targets → [DATABASE.md](/domains/database.md) ✅
4. Subnet analysis → [DATABASE.md](/domains/database.md) ✅

---

## 📖 Documentation Structure

Each domain documentation includes:

1. **Overview** - Domain purpose and capabilities
2. **Resources** - Available resources under the domain
3. **Commands** - Detailed command reference with syntax
4. **Flags** - All available flags and options
5. **Examples** - Real-world usage examples
6. **Sample Output** - Expected command output
7. **Configuration** - YAML config examples
8. **Use Cases** - Common scenarios
9. **Performance Tips** - Optimization guidance
10. **Tool Equivalents** - Mapping to traditional tools
11. **Technical Details** - Implementation specifics
12. **Troubleshooting** - Common issues and solutions

---

## 🚀 Getting Started

**New to redblue?**

1. Start with [NETWORK.md](/domains/network.md) for basic port scanning
2. Move to [DNS.md](/domains/dns.md) for domain reconnaissance
3. Explore [WEB.md](/domains/web.md) for web application testing
4. Check [TLS.md](/domains/tls.md) for certificate inspection

**Need specific functionality?**

- Use the Quick Navigation section above
- Search within each domain file
- Check examples in each documentation

---

## 🔍 Search Tips

**Find commands by traditional tool:**
- Each domain doc has "Tool Equivalents" section
- Maps traditional tools to redblue commands
- Example: `nmap` → `rb network ports scan`

**Find commands by task:**
- Use Quick Navigation by Task section
- Each domain overview lists capabilities
- Examples show real-world scenarios

---

## 📝 Contributing

Found an error or want to improve documentation?

1. Check [AGENTS.md](/../AGENTS.md) for contribution guidelines
2. Follow English-only documentation policy
3. Include examples for new commands
4. Update this index when adding new domains

---

## 🔗 Related Documentation

- [README.md](/../README.md) - Project overview and quick start
- [AGENTS.md](/../AGENTS.md) - Developer and contribution guide
-  - Developer experience philosophy
-  - Implementation examples
-  - CLI architecture and patterns

---

**Last Updated:** 2025-11-03
**Version:** Phase 2 (95% Complete)

## 📊 Feature Status

**Implemented Domains:** 12/13 (92%)
- ✅ NETWORK (ports, trace)
- ✅ DNS (record)
- ✅ WEB (asset)
- ✅ RECON (domain)
- ✅ TLS (security)
- ✅ CLOUD (asset takeover)
- ✅ EXPLOIT (payload)
- ✅ ACCESS (shell)
- ✅ DATABASE (data)
- ✅ MCP (server)
- ⏳ CODE (planned)
- ⏳ COLLECTION (planned)
- ⏳ BENCH (planned)

**Total Commands:** 35+ commands across 12 domains

**Tool Replacements:** 30+ security tools replaced by redblue
- nmap, masscan, traceroute, mtr
- dig, nslookup, whois
- subfinder, amass, theHarvester
- waybackurls, gau
- sslyze, testssl.sh, sslscan
- tko-subs, subjack
- LinPEAS, WinPEAS (partial)
- And many more...
