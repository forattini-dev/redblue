# Tasks: Add Vulnerability Intelligence System

## 1. Enhanced Technology Fingerprinting

### 1.1 Core Fingerprint Infrastructure
- [ ] 1.1.1 Create `src/modules/recon/techstack.rs` - Unified tech stack model
- [ ] 1.1.2 Define `DetectedTech` struct with: name, version, vendor, cpe, confidence, source
- [ ] 1.1.3 Create CPE dictionary mapping (tech name → CPE pattern)
- [ ] 1.1.4 Implement version normalization (semver + vendor-specific)
- [ ] 1.1.5 Add tech category enum: Server, Proxy, CDN, Framework, Runtime, CMS, Library, Database

### 1.2 Server & Infrastructure Detection
- [ ] 1.2.1 Enhance Server header parsing with version extraction
- [ ] 1.2.2 Add X-Powered-By version detection
- [ ] 1.2.3 Implement Via header proxy detection (Cloudflare, Fastly, Akamai, etc.)
- [ ] 1.2.4 Add CDN fingerprinting via headers and DNS
- [ ] 1.2.5 Detect reverse proxies (nginx, HAProxy, Traefik, Envoy)
- [ ] 1.2.6 Add API gateway detection (Kong, AWS API Gateway, Apigee)

### 1.3 Backend Framework Detection
- [ ] 1.3.1 PHP version detection (X-Powered-By, error pages, phpinfo patterns)
- [ ] 1.3.2 Node.js/Express detection (headers, error patterns, package.json)
- [ ] 1.3.3 Python/Django/Flask detection (CSRF tokens, admin URLs, headers)
- [ ] 1.3.4 Ruby/Rails detection (X-Runtime, session cookies, asset paths)
- [ ] 1.3.5 Java/Spring detection (JSESSIONID, error pages, actuator endpoints)
- [ ] 1.3.6 .NET/ASP.NET detection (X-AspNet-Version, ViewState, error pages)
- [ ] 1.3.7 Go detection (response patterns, common frameworks)

### 1.4 Frontend Framework Detection
- [ ] 1.4.1 React detection (DOM patterns, bundle analysis, __NEXT_DATA__)
- [ ] 1.4.2 Vue.js detection (data-v-* attributes, Vue devtools)
- [ ] 1.4.3 Angular detection (ng-* attributes, zone.js)
- [ ] 1.4.4 Svelte detection (svelte-* attributes)
- [ ] 1.4.5 jQuery version extraction from CDN URLs or inline
- [ ] 1.4.6 JavaScript library detection via script src patterns

### 1.5 CMS & Plugin Detection
- [ ] 1.5.1 WordPress plugin enumeration with versions
- [ ] 1.5.2 WordPress theme detection with versions
- [ ] 1.5.3 Drupal module detection
- [ ] 1.5.4 Joomla extension detection
- [ ] 1.5.5 Magento module detection
- [ ] 1.5.6 Shopify app detection

### 1.6 Database Detection
- [ ] 1.6.1 MySQL/MariaDB version from error messages
- [ ] 1.6.2 PostgreSQL detection via error patterns
- [ ] 1.6.3 MongoDB detection via API responses
- [ ] 1.6.4 Redis detection via error messages
- [ ] 1.6.5 Elasticsearch detection via /_cluster/health

## 2. Vulnerability Intelligence Engine

### 2.1 Core Infrastructure
- [ ] 2.1.1 Create `src/modules/recon/vuln/mod.rs` - Module structure
- [ ] 2.1.2 Define `Vulnerability` struct with: id, title, description, cvss, severity, references, exploits, kev
- [ ] 2.1.3 Create `VulnSource` trait for source connectors
- [ ] 2.1.4 Implement deduplication by canonical ID (CVE priority)
- [ ] 2.1.5 Create vulnerability cache (SQLite or in-memory)

### 2.2 NVD Connector
- [ ] 2.2.1 Implement NVD REST API client (no external HTTP crate)
- [ ] 2.2.2 CPE-based vulnerability query
- [ ] 2.2.3 Parse CVE JSON response
- [ ] 2.2.4 Extract CVSS v3 scores
- [ ] 2.2.5 Handle rate limiting (sleep/retry)
- [ ] 2.2.6 Parse version ranges (versionStartIncluding, versionEndExcluding)

### 2.3 OSV Connector
- [ ] 2.3.1 Implement OSV.dev API client
- [ ] 2.3.2 Query by package/ecosystem
- [ ] 2.3.3 Parse OSV JSON response
- [ ] 2.3.4 Map OSV severity to CVSS
- [ ] 2.3.5 Handle pagination

### 2.4 Vulners Connector
- [ ] 2.4.1 Implement Vulners search API
- [ ] 2.4.2 Extract exploit references
- [ ] 2.4.3 Optional API key support
- [ ] 2.4.4 Parse bulletin types

### 2.5 CISA KEV Integration
- [ ] 2.5.1 Fetch CISA KEV JSON/CSV
- [ ] 2.5.2 Parse KEV entries
- [ ] 2.5.3 Cross-reference with found CVEs
- [ ] 2.5.4 Add KEV flag to vulnerabilities

### 2.6 Exploit-DB Integration
- [ ] 2.6.1 Search Exploit-DB by CVE or product
- [ ] 2.6.2 Extract PoC links
- [ ] 2.6.3 Flag exploit availability

### 2.7 GitHub Security Advisories
- [ ] 2.7.1 Query GHSA by package name
- [ ] 2.7.2 Parse advisory JSON
- [ ] 2.7.3 Link to CVE when available

## 3. CLI Commands

### 3.1 Vulnerability Commands
- [ ] 3.1.1 Create `src/cli/commands/vuln.rs`
- [ ] 3.1.2 Implement `rb vuln search <tech> <version>` - Direct lookup
- [ ] 3.1.3 Implement `rb vuln enrich <file>` - Enrich fingerprint JSON
- [ ] 3.1.4 Implement `rb vuln cve <cve-id>` - CVE details lookup
- [ ] 3.1.5 Add `--sources` flag to select sources
- [ ] 3.1.6 Add `--min-cvss` flag for severity filtering
- [ ] 3.1.7 Add `--exploits-only` flag

### 3.2 Integrated Recon
- [ ] 3.2.1 Add `rb recon vuln <target>` - Full recon + vuln correlation
- [ ] 3.2.2 Integrate fingerprinting → CPE → vuln lookup pipeline
- [ ] 3.2.3 Add progress reporting for multi-source queries
- [ ] 3.2.4 Add `--deep` flag for thorough fingerprinting

### 3.3 Output Formats
- [ ] 3.3.1 Implement JSON output for all vuln commands
- [ ] 3.3.2 Implement Markdown report generation
- [ ] 3.3.3 Implement HTML report with severity colors
- [ ] 3.3.4 Add `--output-file` flag

## 4. Risk Scoring & Prioritization

### 4.1 Risk Calculator
- [ ] 4.1.1 Create risk score formula (CVSS + exploit + KEV + age)
- [ ] 4.1.2 Implement priority ranking
- [ ] 4.1.3 Add business impact tags (RCE, Auth Bypass, Info Leak)
- [ ] 4.1.4 Sort vulnerabilities by risk score

## 5. Testing

### 5.1 Unit Tests
- [ ] 5.1.1 Test CPE resolution
- [ ] 5.1.2 Test version range matching
- [ ] 5.1.3 Test deduplication logic
- [ ] 5.1.4 Test JSON parsing for each source

### 5.2 Integration Tests
- [ ] 5.2.1 Test NVD API (with mock responses)
- [ ] 5.2.2 Test full fingerprint → vuln pipeline
- [ ] 5.2.3 Test CLI output formats

## 6. Documentation

- [ ] 6.1 Update README with vuln intelligence features
- [ ] 6.2 Add usage examples for new commands
- [ ] 6.3 Document API rate limits and best practices
