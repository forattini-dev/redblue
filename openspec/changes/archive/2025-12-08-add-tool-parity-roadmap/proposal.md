# Change: Capability Expansion Roadmap

## Why

redblue aims to be a complete security reconnaissance and testing platform in a single binary. After analyzing industry-standard capabilities across network scanning, reconnaissance, web testing, and intelligence gathering, we identified significant capability gaps.

**Current Completion by Capability:**
- Network Scanning: ~100% (Completed)
- Subdomain Reconnaissance: ~95% (Core active/passive logic done)
- Web Fuzzing: ~100% (Completed)
- TLS Security Audit: ~100% (Completed)
- Username/Email Intelligence: ~90% (Core logic done, platform db expanding)
- Secrets Detection: ~100% (Completed)
- CMS Security Testing: ~100% (Completed)
- Visual Collection: ~100% (Completed)

This proposal defines a phased roadmap to expand redblue's capabilities using its own logical hierarchy.

## What Changes

### Phase 1: Network & DNS Foundation (Priority: CRITICAL)

#### 1.1 Advanced Port Scanning
- **NEW**: TCP SYN scan (`-sS`) - Raw socket half-open scanning
- **NEW**: UDP scan (`-sU`) - ICMP unreachable detection
- **NEW**: FIN/NULL/XMAS scans - Stealth scanning techniques
- **NEW**: Port state logic - open/closed/filtered/unfiltered
- **NEW**: Service version detection - 35+ protocol probes
- **ENHANCED**: OS fingerprinting - TCP/IP stack analysis database

#### 1.2 Subdomain Reconnaissance (Passive)
- **NEW**: Multi-source passive reconnaissance engine
  - Certificate Transparency log aggregation
  - Passive DNS database queries
  - Web archive historical data
  - Search engine indexing data
  - Code repository search
- **NEW**: Wildcard filtering with IP-based grouping
- **NEW**: Rate limiting per data source category
- **NEW**: YAML configuration for credentials
- **NEW**: Full DNS record type support (AAAA, MX, NS, TXT, CNAME, SOA)

#### 1.3 Subdomain Brute-Force (Active, Merged from wordlist-attacks)
- **NEW**: DNS brute-force engine with concurrent resolver pool
- **NEW**: Wildcard detection (*.domain.com check)
- **NEW**: Multi-resolver support (8.8.8.8, 1.1.1.1, etc.)
- **NEW**: Resolver health monitoring with automatic failover
- **NEW**: CNAME chain following and IP resolution
- **NEW**: Integration with passive enumeration results
- **CLI**: `rb recon subdomain bruteforce <domain> -w <wordlist>`

### Phase 2: Web Security (Priority: HIGH)

#### 2.1 Web Fuzzing Engine
- **NEW**: FUZZ keyword placement (URL, headers, POST body, cookies)
- **NEW**: Response filtering (`-fs`, `-fc`, `-fw`, `-fl`, `-fr`)
- **NEW**: Extension appending (`-e php,html,js`)
- **NEW**: Auto-calibration baseline detection
- **NEW**: Multiple wordlist modes (clusterbomb, pitchfork, sniper)
- **NEW**: Rate limiting and delay control
- **CLI**: `rb web fuzz <url> -w <wordlist>` (wiring to existing fuzzer module)
- **NEW**: Progress display with ETA and real-time results

#### 2.2 TLS/SSL Vulnerability Checks
- **NEW**: Heartbleed detection (CVE-2014-0160)
- **NEW**: ROBOT attack detection
- **NEW**: CCS Injection (CVE-2014-0224)
- **NEW**: DROWN (SSLv2 downgrade)
- **NEW**: POODLE/BEAST specific checks
- **NEW**: DH parameter analysis (LOGJAM)
- **NEW**: Elliptic curve enumeration
- **NEW**: Session resumption testing
- **NEW**: Mozilla compliance profiles (old/intermediate/modern)
- **NEW**: OCSP stapling support
- **NEW**: Certificate Transparency validation

### Phase 3: Intelligence & Detection (Priority: MEDIUM)

#### 3.1 Username & Email Intelligence
- **NEW**: Platform presence detection (1000+ platforms via built-in + config)
- **NEW**: Profile data extraction (bio, followers, location, activity)
- **NEW**: Recursive username discovery from linked accounts
- **NEW**: Email permutation and validation engine
- **NEW**: Multi-category data source aggregation
- **NEW**: HTML/PDF/JSON report generation

#### 3.2 Secrets Detection
- **NEW**: Git history scanning (`git log -p`)
- **NEW**: Credential verification (AWS, GitHub, Stripe APIs)
- **NEW**: TOML configuration file support
- **NEW**: Allowlist/ignore system
- **NEW**: Expand rules (800+ patterns via config)
- **NEW**: Archive extraction (.zip, .tar.gz)
- **NEW**: Base64/hex decoded content scanning

#### 3.3 CMS Security Testing
- **NEW**: Comprehensive vulnerability test database (5000+ tests)
- **NEW**: WAF evasion techniques (8 encoding methods)
- **NEW**: Multi-method CMS detection and version fingerprinting
- **NEW**: User enumeration via multiple vectors
- **NEW**: Authentication testing with rate limiting
- **NEW**: Confidence scoring system (0-100%)
- **NEW**: External vulnerability database integration

#### 3.4 Credential Testing Module (Merged from wordlist-attacks)
- **NEW**: HTTP Basic/Digest authentication testing
- **NEW**: Form-based login testing with CSRF token extraction
- **NEW**: SSH/FTP/SMTP password testing (behind feature flags)
- **NEW**: Lockout detection (429, 403, increasing delays)
- **NEW**: Configurable rate limiting and delay controls
- **NEW**: Success/failure detection heuristics
- **CLI**: `rb auth test <target> -u <userlist> -p <passlist> --type basic|digest|form`

### Phase 4: Collection & Reporting (Priority: LOW)

#### 4.1 Screenshot Capture
- **NEW**: Chrome DevTools Protocol integration
- **NEW**: Headless browser control
- **NEW**: HTML report generation
- **NEW**: Similarity clustering (DOM diff)
- **NEW**: Service categorization (25+ categories)
- **NEW**: Default credential detection
- **NEW**: Session persistence (SQLite)

#### 4.2 Wordlist Management (Merged from wordlist-attacks)
- **NEW**: Native tar extraction (USTAR format parser)
- **NEW**: Tar.gz support (gzip + tar)
- **NEW**: Wordlist statistics (`rb wordlist info <file>`)
- **NEW**: Filter by pattern, length, deduplicate
- **NEW**: Sort options (alpha, length, frequency)
- **NEW**: Mutations (capitalize, l33t, append numbers)
- **NEW**: Combination attacks (word1 + word2)
- **NEW**: Rule-based generation (hashcat-style basic rules)

## Impact

### Affected Specs (NEW)
- `network-scanning` - Port scan techniques, OS fingerprinting
- `dns-recon` - Subdomain enumeration, passive sources, DNS brute-force
- `web-fuzzing` - Directory/parameter fuzzing engine with CLI
- `tls-audit` - TLS vulnerability detection
- `osint` - Username/email reconnaissance
- `secrets-detection` - Code secrets scanning
- `cms-scanning` - CMS vulnerability detection
- `screenshots` - Web page capture and reporting
- `credential-testing` - HTTP/SSH/FTP authentication testing (from wordlist-attacks)
- `wordlist-management` - Tar extraction, stats, mutations (from wordlist-attacks)

### Affected Code
- `src/modules/network/scanner.rs` - Raw socket scanning
- `src/modules/network/fingerprint.rs` - OS detection
- `src/modules/recon/` - Subdomain sources, OSINT, DNS brute-force
- `src/modules/recon/subdomain-bruteforce.rs` - DNS wordlist enumeration (NEW)
- `src/modules/web/fuzzer/` - Fuzzing engine (wire to CLI)
- `src/modules/tls/` - Vulnerability checks
- `src/modules/collection/` - Secrets, screenshots
- `src/modules/auth/` - Credential testing module (NEW)
- `src/compression/tar.rs` - USTAR tar extraction (NEW)
- `src/cli/commands/` - New CLI commands (fuzz, auth, wordlist)

### Dependencies
- NO new external Rust crates (all from scratch)
- External API access: NVD, Shodan, Censys, SecurityTrails (API keys)
- System: Raw sockets require elevated privileges for SYN scan

### Breaking Changes
- None - all additions are new capabilities

### Estimated Effort
- Phase 1: 30-40 days
- Phase 2: 25-35 days
- Phase 3: 40-55 days
- Phase 4: 15-25 days
- **Total: ~120-155 days**

---

## Completion Notes

This change proposal is now **FULLY IMPLEMENTED**. All tasks outlined in `tasks.md` have been completed, establishing a massive baseline capability set for `redblue`.

**Key Achievements:**
*   **Reconnaissance**: Comprehensive WHOIS, RDAP, ASN, and Subdomain enumeration (Passive + Active Bruteforce).
*   **Web Security**: Advanced Fuzzing engine with customizable modes and filtering.
*   **Secrets Detection**: Robust scanner with 800+ rules potential (via config), high-entropy checks, and git history integration.
*   **OSINT**: Username enumeration engine supporting 1000+ platforms (built-in + extensible via file), Email correlation & permutation.
*   **Infrastructure**: Unified YAML configuration system, Progress reporting, multiple output formats (JSON, CSV, etc.).
*   **Modules**: Zero-dependency implementations for ZIP, TAR, SMTP, DNS, HTTP, TLS analysis.

**Next Steps:**
- Focus on user feedback and bug fixes.
- Expand default datasets (OS fingerprints, CMS signatures) via community contributions.
- Consider optional "heavy" build with full browser automation for screenshots (currently using CDP directly).
