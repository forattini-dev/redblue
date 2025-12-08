# Implementation Tasks

## Phase 1: Network & DNS Foundation

### 1.1 Advanced Port Scanning
- [x] 1.1.1 Implement raw socket packet crafting layer
- [x] 1.1.2 Implement TCP SYN scan (half-open connections)
- [x] 1.1.3 Implement UDP scan with ICMP unreachable detection
- [x] 1.1.4 Implement FIN/NULL/XMAS stealth scans
- [x] 1.1.5 Add port state logic (open/closed/filtered/unfiltered)
- [x] 1.1.6 Expand service detection to 35+ protocols (100+ TCP, 35+ UDP)
- [x] 1.1.7 Build OS fingerprint database (1000+ signatures) - 216 signatures modularized (Linux/Windows/macOS/BSD/Network)
- [x] 1.1.8 Implement TCP/IP stack fingerprinting probes - nmap-style SEQ/ECN/T1-T7/U1 probes
- [x] 1.1.9 Add timing templates (paranoid to insane)
- [x] 1.1.10 Write tests for each scan type
- [x] 1.1.11 Design scripting engine architecture (pure Rust - no Lua/WASM, supports compiled + TOML scripts)
- [x] 1.1.12 Implement script loader and executor (TOML parser from scratch, ScriptEngine with parallel execution)
- [x] 1.1.13 Create 6 built-in discovery/security scripts (http-headers, http-security, ssh-banner, ftp-banner, smtp-banner, tls-info)
- [x] 1.1.14 Create 20+ vulnerability detection scripts (http-vulns, mysql-info, redis-info, mongodb-info, postgres-info, elasticsearch-info, dns-zone-transfer, snmp-info, rdp-info, smb-info, ldap-info, vnc-info, docker-info, telnet-info)
- [x] 1.1.15 Add script category system (14 categories: vuln, discovery, safe, default, intrusive, exploit, brute, auth, dos, info, fuzz, malware, version, banner)

### 1.2 Subdomain Reconnaissance
- [x] 1.2.1 Create data source abstraction interface
- [x] 1.2.2 Implement Certificate Transparency aggregator
- [x] 1.2.3 Implement passive DNS query engine
- [x] 1.2.4 Implement web archive data extractor
- [x] 1.2.5 Implement search engine index scraper
- [x] 1.2.6 Implement code repository search
- [x] 1.2.7 Implement threat intelligence feed client
- [x] 1.2.8 Implement email/domain correlation engine
- [x] 1.2.9 Add YAML configuration loader for credentials
- [x] 1.2.10 Implement per-category rate limiting
- [x] 1.2.11 Implement wildcard IP filtering and grouping
- [x] 1.2.12 Add AAAA, MX, NS, TXT, CNAME, SOA record support
- [x] 1.2.13 Implement result deduplication and merging
- [x] 1.2.14 Add source category filtering (--passive-only, --active-only)
- [x] 1.2.16 Implement D3.js graph export
- [x] 1.2.17 Build relationship detection (shared IPs, CNAME chains)
- [x] 1.2.18 Generate interactive HTML graph visualization

### 1.3 Subdomain Brute-Force (DNS-based)
- [x] 1.3.1 Create `src/modules/recon/subdomain-bruteforce.rs`
- [x] 1.3.2 Implement concurrent DNS resolver pool
- [x] 1.3.3 Wildcard detection (*.domain.com check)
- [x] 1.3.4 Retry logic with exponential backoff
- [x] 1.3.5 Multi-resolver support (8.8.8.8, 1.1.1.1, etc.)
- [x] 1.3.6 Resolver health monitoring
- [x] 1.3.7 Automatic failover on resolver timeout
- [x] 1.3.8 Custom resolver list support
- [x] 1.3.9 IP resolution for found subdomains
- [x] 1.3.10 CNAME chain following
- [x] 1.3.11 Duplicate elimination
- [x] 1.3.12 Integration with passive enumeration results
- [x] 1.3.13 Implement `rb recon subdomain bruteforce <domain> -w <wordlist>`
- [x] 1.3.14 Add `--resolvers` flag for custom DNS servers
- [x] 1.3.15 Add `--wildcard-check` flag
- [x] 1.3.16 Progress display with statistics

## Phase 2: Web Security

### 2.1 Web Fuzzing Engine
- [x] 2.1.1 Implement FUZZ keyword parsing
- [x] 2.1.2 Add FUZZ placement in URL path
- [x] 2.1.3 Add FUZZ placement in query parameters
- [x] 2.1.4 Add FUZZ placement in HTTP headers
- [x] 2.1.5 Add FUZZ placement in POST body
- [x] 2.1.6 Add FUZZ placement in cookies
- [x] 2.1.7 Implement response size filter (`-fs`)
- [x] 2.1.8 Implement response code filter (`-fc`)
- [x] 2.1.9 Implement word count filter (`-fw`)
- [x] 2.1.10 Implement line count filter (`-fl`)
- [x] 2.1.11 Implement regex filter (`-fr`)
- [x] 2.1.12 Implement extension appending (`-e`)
- [x] 2.1.13 Implement auto-calibration baseline
- [x] 2.1.14 Implement clusterbomb mode
- [x] 2.1.15 Implement pitchfork mode
- [x] 2.1.16 Implement sniper mode
- [x] 2.1.17 Add delay/rate limiting controls
- [x] 2.1.18 Add recursion support
- [x] 2.1.19 Write fuzzing integration tests
- [x] 2.1.20 Create `src/cli/commands/fuzz.rs` CLI command
- [x] 2.1.21 Implement `rb web fuzz <url> -w <wordlist>` command
- [x] 2.1.22 Add progress display with ETA
- [x] 2.1.23 Real-time results output
- [x] 2.1.24 Output formats (JSON, CSV, plain)

### 2.2 TLS/SSL Vulnerability Checks
- [x] 2.2.1 Complete Heartbleed detection implementation
- [x] 2.2.2 Implement ROBOT attack detection
- [x] 2.2.3 Implement CCS Injection check
- [x] 2.2.4 Implement DROWN detection
- [x] 2.2.5 Implement POODLE-specific check
- [x] 2.2.6 Implement BEAST-specific check
- [x] 2.2.7 Implement LOGJAM (weak DH) detection
- [x] 2.2.8 Implement Ticketbleed check
- [x] 2.2.9 Implement renegotiation vulnerability check
- [x] 2.2.10 Add DH parameter size analysis
- [x] 2.2.11 Add elliptic curve enumeration
- [x] 2.2.12 Add session resumption testing
- [x] 2.2.13 Implement Mozilla compliance profiles
- [x] 2.2.14 Complete OCSP stapling support
- [x] 2.2.15 Complete Certificate Transparency validation
- [x] 2.2.16 Write TLS security integration tests

## Phase 3: Intelligence & Detection

### 3.1 Username & Email Intelligence
- [x] 3.1.1 Expand platform database to 200+ platforms
- [x] 3.1.2 Expand platform database to 500+ platforms
- [x] 3.1.2a Expand platform database to 1000+ platforms
- [x] 3.1.2b Expand platform database to 3000+ platforms (maigret parity)
- [x] 3.1.3 Implement profile data extraction (HTML parsing)
- [x] 3.1.4 Extract bio, followers, location, activity fields
- [x] 3.1.5 Implement recursive username discovery
- [x] 3.1.6 Implement email permutation engine
- [x] 3.1.7 Implement email validation via SMTP
- [x] 3.1.8 Implement breach database correlation
- [x] 3.1.9 Implement threat intelligence correlation
- [x] 3.1.10 Implement HTML report generation
- [x] 3.1.11 Implement PDF report generation
- [x] 3.1.12 Add anti-detection measures (CAPTCHA, rate limiting)
- [x] 3.1.13 Write OSINT integration tests

### 3.2 Secrets Detection
- [x] 3.2.1 Implement git log parsing
- [x] 3.2.2 Implement git history scanning
- [x] 3.2.3 Implement git branch scanning
- [x] 3.2.4 Add AWS credential verification API
- [x] 3.2.5 Add GitHub token verification API
- [x] 3.2.6 Add Stripe key verification API
- [x] 3.2.7 Add Google API key verification
- [x] 3.2.8 Implement TOML configuration loader
- [x] 3.2.9 Implement allowlist system
- [x] 3.2.10 Implement ignore comments (`gitleaks:allow`)
- [x] 3.2.11 Expand rules to 30+ patterns
- [x] 3.2.12 Expand rules to 60+ patterns
- [x] 3.2.12a Expand rules to 200+ patterns
- [x] 3.2.12b Expand rules to 800+ patterns (trufflehog parity)
- [x] 3.2.13 Implement .zip archive extraction
- [x] 3.2.14 Implement .tar.gz archive extraction
- [x] 3.2.15 Implement base64 content decoding
- [x] 3.2.16 Implement hex content decoding
- [x] 3.2.17 Add JSON output format
- [x] 3.2.18 Add SARIF output format
- [x] 3.2.19 Write secrets detection integration tests

### 3.3 CMS Security Testing
- [x] 3.3.1 Build vulnerability test database (CSV/TOML format)
- [x] 3.3.2 Implement vulnerability test executor
- [x] 3.3.3 Implement 8 WAF evasion techniques
- [x] 3.3.4 Add multi-method plugin detection
- [x] 3.3.5 Add multi-method theme detection
- [x] 3.3.6 Add multi-method user enumeration
- [x] 3.3.7 Add multi-method version fingerprinting
- [x] 3.3.8 Implement authentication endpoint testing
- [x] 3.3.9 Add rate-limited credential testing
- [x] 3.3.10 Add confidence scoring system (0-100%)
- [x] 3.3.11 Integrate external vulnerability database
- [x] 3.3.12 Add favicon and file hash fingerprinting
- [x] 3.3.13 Write CMS scanning integration tests

### 3.4 Credential Testing Module
- [x] 3.4.1 Create `src/modules/auth/mod.rs`
- [x] 3.4.2 Create `src/modules/auth/http-auth.rs` for HTTP auth
- [x] 3.4.3 Implement credential pair iterator (user:pass)
- [x] 3.4.4 Add rate limiting to avoid lockouts
- [x] 3.4.5 HTTP Basic authentication testing
- [x] 3.4.6 HTTP Digest authentication testing
- [x] 3.4.7 Form-based login testing (POST with CSRF token extraction)
- [x] 3.4.8 Success/failure detection heuristics
- [x] 3.4.9 SSH password testing (behind feature flag)
- [x] 3.4.10 FTP authentication testing
- [x] 3.4.11 SMTP authentication testing
- [x] 3.4.12 Lockout detection (429, 403, increasing delays)
- [x] 3.4.13 Account lockout warning
- [x] 3.4.14 Configurable delay between attempts
- [x] 3.4.15 Max attempts per account limit
- [x] 3.4.16 Implement `rb auth test <target> -u <userlist> -p <passlist>`
- [x] 3.4.17 Add `--type` flag (basic, digest, form)
- [x] 3.4.18 Add `--delay` flag for rate limiting
- [x] 3.4.19 Credential found notification
- [x] 3.4.20 Write credential testing integration tests

## Phase 4: Collection & Reporting

### 4.1 Screenshot Capture
- [x] 4.1.1 Implement Chrome DevTools Protocol client
- [x] 4.1.2 Implement WebSocket communication
- [x] 4.1.3 Add headless browser launch/control
- [x] 4.1.4 Implement screenshot capture (PNG)
- [x] 4.1.5 Add viewport configuration
- [x] 4.1.6 Add timeout handling
- [x] 4.1.7 Implement batch URL processing
- [x] 4.1.8 Implement HTML report generation
- [x] 4.1.9 Implement DOM similarity clustering
- [x] 4.1.10 Add service categorization (25+ categories)
- [x] 4.1.11 Add default credential detection database (50+ applications)
- [x] 4.1.11a Implement login form detection
- [x] 4.1.11b Implement authorized credential testing
- [x] 4.1.12 Implement SQLite session persistence
- [x] 4.1.13 Add resume capability
- [x] 4.1.14 Write screenshot capture integration tests

### 4.2 Wordlist Management
- [x] 4.2.1 Create `src/compression/tar.rs` with USTAR format parser
- [x] 4.2.2 Implement tar header parsing (name, size, type)
- [x] 4.2.3 Handle tar.gz files (gzip decompress then tar extract)
- [x] 4.2.4 Single file extraction from archive
- [x] 4.2.5 Implement `rb wordlist info <file>` command
- [x] 4.2.6 Show line count, unique count, avg length
- [x] 4.2.7 Character set analysis (alphanumeric, special)
- [x] 4.2.8 Top N entries preview
- [x] 4.2.9 Filter by pattern (grep-like)
- [x] 4.2.10 Filter by length (min/max)
- [x] 4.2.11 Deduplicate entries
- [x] 4.2.12 Sort options (alpha, length, frequency)
- [x] 4.2.13 Basic mutations (capitalize, l33t, append numbers)
- [x] 4.2.14 Combination attack (word1 + word2)
- [x] 4.2.15 Rule-based generation (hashcat-style basic rules)
- [x] 4.2.16 Custom pattern generation

## Phase 5: Integration & Testing

### 5.1 Integration
- [x] 5.1.1 Add unified configuration system (YAML)
- [x] 5.1.2 Add credential management
- [x] 5.1.3 Update CLI commands for new features
- [x] 5.1.4 Add progress/statistics reporting
- [x] 5.1.5 Add JSON/XML output formats
- [x] 5.1.6 Add CSV export
- [ ] 5.1.7 Update README.md with new features
- [ ] 5.1.8 Update domain documentation

### 5.2 Testing
- [x] 5.2.1 Integration tests for port scanning
- [x] 5.2.2 Integration tests for DNS sources
- [x] 5.2.3 Integration tests for web fuzzing
- [x] 5.2.4 Integration tests for TLS checks
- [x] 5.2.5 Integration tests for OSINT
- [x] 5.2.6 Integration tests for secrets
- [x] 5.2.7 Integration tests for CMS scanning
- [x] 5.2.8 Integration tests for screenshots
- [x] 5.2.9 Benchmark performance tests
- [x] 5.2.10 Tool parity comparison tests
