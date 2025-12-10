# RECON Domain Documentation

## TL;DR
Maps out the WHOIS, subdomain, and OSINT tooling we ship today plus the backlog (emails, usernames, storage) needed for full reconnaissance coverage.

## Overview

The `recon` domain provides comprehensive information gathering and OSINT (Open Source Intelligence) capabilities for domains, including WHOIS lookups, subdomain enumeration, data harvesting, and historical URL discovery. This domain replaces tools like **whois**, **amass**, **subfinder**, **theHarvester**, **waybackurls**, and **gau**.

**Domain:** `recon`

**Resource:** `domain`

**Status:** ✅ Phase 2 (90% Complete)

---

## Implementation Status (Nov 2025)

### Current Capabilities
- WHOIS client (`src/modules/recon/whois/`) handles multi-TLD registry lookups with intelligent server selection, rate limiting, and optional raw dumps.
- Subdomain discovery combines passive sources (crt.sh, Censys) with active bruteforce using wordlists under `wordlists/`; logic resides in `src/modules/recon/subdomains.rs`.
- Data harvesting (`src/modules/recon/harvest.rs`) pulls OSINT feeds (Wayback, URLScan, OTX) and normalizes artifacts into `.rdb` segments.
- CLI surface (`src/cli/commands/recon.rs`) exposes `whois`, `subdomains`, `harvest`, and `urls` verbs with shared persistence hooks and output envelopes.
- Intelligence writes flow through `src/storage/segments/subdomains.rs` and the shared view/client stack, making discoveries available to other domains.

### Known Gaps
- Email reconnaissance and username OSINT verbs still point to placeholders; underlying modules need to be implemented or guarded with TODO(test) stubs.
- Historical URL ingestion lacks dedupe/merge logic for large scopes; storage compaction remains a TODO once the storage façade lands.
- Passive OSINT sources (Shodan, VirusTotal) are out-of-scope due to dependency policies—must rely on first-party scraping or JSON ingestion.

### Immediate Actions
1. Add smoke coverage (`tests/recon_domain.rs`) verifying WHOIS parsing and subdomain persistence.
2. Flesh out `harvest` CLI help/examples with concrete JSON snapshots to match the HTTP/TLS docs.
3. Document rate-limit/backoff guidance (e.g., polite sleeps, GDPR redaction handling) in this file’s troubleshooting section.

---

## Resource: `recon domain`

**Description:** Passive and active information gathering for domains, including registrar data, subdomains, emails, URLs, and historical intelligence.

### Commands

#### 1. `whois` - WHOIS Lookup

Query WHOIS information for a domain, including registrar, dates, nameservers, and status.

**Syntax:**
```bash
rb recon domain whois <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain (required)

**Flags:**
- `--raw` - Show raw WHOIS response
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)
- `--no-persist` - Don't save results (overrides config)

**What It Shows:**
- Registrar information
- Registrant organization and country
- Creation, update, and expiration dates
- Nameservers
- Domain status
- Raw WHOIS data (with `--raw` flag)

**Supported TLDs:**
- Generic: .com, .org, .net, .info, .biz
- Country-specific: .io, .co, .me, .dev, .app, .br, .uk, .de, .fr, .jp
- And many more via automatic WHOIS server detection

**Examples:**

```bash
# Basic WHOIS lookup
rb recon domain whois google.com

# Show raw WHOIS response
rb recon domain whois example.com --raw

# JSON output
rb recon domain whois github.com -o json

# Save to database
rb recon domain whois example.com --persist
```

**Sample Output (Text):**

```
Querying WHOIS for google.com... ✓

📋 WHOIS: google.com

  Registrar: MarkMonitor Inc.
  Org: Google LLC
  Country: US

  Created: 1997-09-15
  Expires: 2028-09-14

Nameservers (4)
  ns1.google.com
  ns2.google.com
  ns3.google.com
  ns4.google.com

Status (2)
  clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
  clientTransferProhibited https://icann.org/epp#clientTransferProhibited
  ... and 4 more

✓ WHOIS lookup completed
```

**Sample Output (JSON):**

```json
{
  "domain": "google.com",
  "registrar": "MarkMonitor Inc.",
  "registrant_org": "Google LLC",
  "registrant_country": "US",
  "creation_date": "1997-09-15",
  "updated_date": "2019-09-09",
  "expiration_date": "2028-09-14",
  "name_servers": [
    "ns1.google.com",
    "ns2.google.com",
    "ns3.google.com",
    "ns4.google.com"
  ],
  "status": [
    "clientDeleteProhibited",
    "clientTransferProhibited",
    "clientUpdateProhibited"
  ]
}
```

---

#### 2. `subdomains` - Subdomain Enumeration

Enumerate subdomains using multiple passive and active techniques (Certificate Transparency logs, DNS bruteforce, search engines).

**Syntax:**
```bash
rb recon domain subdomains <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain (required)

**Flags:**
- `-p, --passive` - Passive enumeration only (Certificate Transparency logs)
- `--filter-wildcards` - Enable wildcard detection and filtering
- `-r, --recursive` - Recursive subdomain enumeration
- `-w, --wordlist <file>` - Custom wordlist path for DNS bruteforce
- `-t, --threads <n>` - Number of threads for DNS bruteforce
  - Default: `10`
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)
- `--no-persist` - Don't save results (overrides config)

**Enumeration Methods:**

1. **Certificate Transparency (CT) Logs** - Passive
   - Searches public CT logs for SSL certificates
   - No DNS queries made to target
   - Fast and stealthy

2. **DNS Bruteforce** - Active
   - Tests common subdomain names from wordlist
   - Concurrent DNS queries (configurable threads)
   - Default wordlist included (~1000 entries)

3. **Search Engine Queries** - Passive (future)
   - Google, Bing, DuckDuckGo dorking
   - VirusTotal API integration
   - SecurityTrails integration

**Examples:**

```bash
# All methods (CT logs + DNS bruteforce)
rb recon domain subdomains example.com

# Passive only (no DNS queries to target)
rb recon domain subdomains example.com --passive

# Custom wordlist and thread count
rb recon domain subdomains example.com --wordlist subdomains.txt --threads 50

# Filter wildcard DNS entries
rb recon domain subdomains example.com --filter-wildcards

# Recursive enumeration
rb recon domain subdomains example.com --recursive

# JSON output with persistence
rb recon domain subdomains example.com -o json --persist
```

**Sample Output (Text):**

```
🔍 Subdomain Enumeration

  Target Domain: example.com

Discovered Subdomains (15)

  SUBDOMAIN                                IP ADDRESSES         SOURCE
  ───────────────────────────────────────────────────────────────────────────
  www.example.com                          93.184.216.34        CT_LOGS
  mail.example.com                         93.184.216.35        CT_LOGS
  api.example.com                          93.184.216.36        CT_LOGS
  dev.example.com                          93.184.216.37        DNS_BRUTE
  admin.example.com                        93.184.216.38        DNS_BRUTE
  blog.example.com                         93.184.216.39        CT_LOGS
  shop.example.com                         93.184.216.40        DNS_BRUTE
  staging.example.com                      93.184.216.41        DNS_BRUTE
  test.example.com                         93.184.216.42        DNS_BRUTE
  vpn.example.com                          93.184.216.43        CT_LOGS
  portal.example.com                       93.184.216.44        DNS_BRUTE
  cdn.example.com                          N/A                  CT_LOGS
  static.example.com                       93.184.216.45        DNS_BRUTE
  app.example.com                          93.184.216.46 (+2)   CT_LOGS
  m.example.com                            93.184.216.47        DNS_BRUTE

✓ Found 15 unique subdomains
✓ Results saved to example.com.rdb
```

**Sample Output (JSON):**

```json
{
  "domain": "example.com",
  "count": 15,
  "subdomains": [
    {
      "subdomain": "www.example.com",
      "ips": ["93.184.216.34"],
      "source": "CT_LOGS"
    },
    {
      "subdomain": "mail.example.com",
      "ips": ["93.184.216.35"],
      "source": "CT_LOGS"
    },
    {
      "subdomain": "api.example.com",
      "ips": ["93.184.216.36"],
      "source": "CT_LOGS"
    }
  ]
}
```

---

#### 3. `bruteforce` - DNS Subdomain Bruteforce

Perform high-performance DNS subdomain bruteforce using custom wordlists and resolver pools.

**Syntax:**
```bash
rb recon domain bruteforce <domain> --wordlist <file> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain (required)

**Flags:**
- `--wordlist <file>` - Custom wordlist path for DNS bruteforce (required)
- `--resolvers <list>` - Comma-separated DNS resolvers (e.g., `8.8.8.8,1.1.1.1`)
- `--threads <n>` - Number of threads for concurrent queries
  - Default: `20`
- `--no-wildcard` - Disable wildcard DNS detection and filtering
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)

**Features:**
- **Concurrent Resolver Pool**: Uses multiple DNS resolvers for speed and resilience.
- **Wildcard Detection**: Automatically detects and filters wildcard DNS entries to reduce noise.
- **Retry Logic**: Retries failed queries with exponential backoff.
- **Custom Resolvers**: Allows specifying custom DNS servers.

**Examples:**

```bash
# Basic DNS bruteforce with custom wordlist
rb recon domain bruteforce example.com --wordlist subdomains_full.txt

# Use custom resolvers and more threads
rb recon domain bruteforce example.com --wordlist big.txt --resolvers 8.8.8.8,1.1.1.1,9.9.9.9 --threads 50

# Disable wildcard filtering if desired (not recommended)
rb recon domain bruteforce example.com --wordlist sub.txt --no-wildcard

# JSON output
rb recon domain bruteforce example.com --wordlist sub.txt -o json
```

**Sample Output (Text):**

```
🔍 DNS Bruteforce: example.com

  Wordlist: 100000 entries
  Threads: 20

Detecting wildcards... ✓
  ℹ️ Wildcard IPs detected: ["93.184.216.34"]

Starting enumeration...

Found 150 Subdomains
────────────────────────────────────────────────────────────────────────────────
SUBDOMAIN                                IP                  RESOLVER
────────────────────────────────────────────────────────────────────────────────
www.example.com                          93.184.216.34       8.8.8.8:53
mail.example.com                         93.184.216.35       1.1.1.1:53
api.example.com                          93.184.216.36       9.9.9.9:53
dev.example.com                          93.184.216.37       8.8.8.8:53
admin.example.com                        93.184.216.38       1.1.1.1:53
blog.example.com                         93.184.216.39       9.9.9.9:53
... (showing first 6, 144 more)
```

---

#### 4. `harvest` - OSINT Data Harvesting

Harvest OSINT data from multiple sources (emails, subdomains, IPs, URLs) using theHarvester-style techniques.

**Syntax:**
```bash
rb recon domain harvest <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain (required)

**Flags:**
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)

**Data Sources:**

1. **Search Engines**
   - Google dorking for emails
   - Bing searches for subdomains
   - DuckDuckGo privacy-focused queries

2. **Public Databases**
   - Certificate Transparency logs
   - DNS records (MX, TXT, SPF)
   - WHOIS data parsing

3. **Social Media**
   - LinkedIn company profiles
   - Twitter mentions
   - GitHub repositories

4. **Web Scraping**
   - Company websites
   - Contact pages
   - About pages

**What It Finds:**

- **Email Addresses** - Company emails, contact addresses
- **Subdomains** - All discovered subdomains
- **IP Addresses** - Associated IP addresses and ranges
- **URLs** - Related URLs and endpoints

**Examples:**

```bash
# Basic OSINT harvesting
rb recon domain harvest example.com

# JSON output
rb recon domain harvest example.com -o json

# Save to database
rb recon domain harvest example.com --persist
```

**Sample Output (Text):**

```
🔍 OSINT Data Harvesting (theHarvester)

  Target Domain: example.com

Email Addresses (12)
  ✉  info@example.com
  ✉  support@example.com
  ✉  contact@example.com
  ✉  sales@example.com
  ✉  admin@example.com
  ✉  webmaster@example.com
  ✉  noreply@example.com
  ✉  security@example.com
  ✉  privacy@example.com
  ✉  abuse@example.com
  ✉  postmaster@example.com
  ✉  careers@example.com

Subdomains (24)
  ●  www.example.com
  ●  mail.example.com
  ●  api.example.com
  ●  dev.example.com
  ●  staging.example.com
  ●  blog.example.com
  ●  shop.example.com
  ●  cdn.example.com
  ... (16 more)

IP Addresses (5)
  ◆  93.184.216.34
  ◆  93.184.216.35
  ◆  93.184.216.36
  ◆  93.184.216.37
  ◆  93.184.216.38

URLs (45)
  →  https://example.com/
  →  https://www.example.com/about
  →  https://example.com/contact
  →  https://api.example.com/v1
  →  https://blog.example.com/
  ... (40 more)

✓ Harvested 86 total items
```

**Sample Output (JSON):**

```json
{
  "domain": "example.com",
  "emails": [
    "info@example.com",
    "support@example.com",
    "contact@example.com"
  ],
  "subdomains": [
    "www.example.com",
    "mail.example.com",
    "api.example.com"
  ],
  "ips": [
    "93.184.216.34",
    "93.184.216.35"
  ],
  "urls": [
    "https://example.com/",
    "https://www.example.com/about"
  ],
  "total_items": 86
}
```

---

#### 5. `urls` - Historical URL Discovery

Harvest historical and current URLs from archives (Wayback Machine, URLScan, OTX, CommonCrawl) similar to waybackurls and gau.

**Syntax:**
```bash
rb recon domain urls <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain (required)

**Flags:**
- `-i, --include <pattern>` - Include only URLs matching pattern (regex)
- `-e, --exclude <pattern>` - Exclude URLs matching pattern (regex)
- `--extensions <ext1,ext2>` - Filter by file extensions (comma-separated)
  - Example: `js,php,asp,jsp`
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`

**Data Sources:**

1. **Wayback Machine** - Internet Archive historical snapshots
2. **URLScan.io** - Public URL scanning service
3. **AlienVault OTX** - Open Threat Exchange
4. **CommonCrawl** - Web crawl archives
5. **VirusTotal** - URL submissions

**What It Finds:**

- **Historical URLs** - Old endpoints that may still exist
- **API Endpoints** - Undocumented API paths
- **Admin Panels** - Hidden administrative interfaces
- **JavaScript Files** - Client-side code for analysis
- **Parameter Names** - For fuzzing and testing

**Examples:**

```bash
# Get all historical URLs
rb recon domain urls example.com

# Filter for API endpoints
rb recon domain urls example.com --include /api/

# Exclude image files
rb recon domain urls example.com --exclude '\.(png|jpg|gif)$'

# Get only JavaScript files
rb recon domain urls example.com --extensions js

# Get PHP and ASP files
rb recon domain urls example.com --extensions php,asp,aspx

# Complex filtering
rb recon domain urls example.com --include /admin/ --exclude logout
```

**Sample Output (Text):**

```
🔗 URL Harvester (waybackurls/gau)

  Target Domain: example.com

Harvesting historical URLs for example.com... ✓

Discovered URLs (1,245)

Wayback Machine (842)
  2023-11-15  https://example.com/
  2023-10-20  https://example.com/about
  2023-09-12  https://example.com/contact
  2023-08-05  https://example.com/products
  2023-07-18  https://example.com/api/v1/users
  2023-06-22  https://example.com/api/v1/products
  2023-05-10  https://example.com/admin/login
  ... and 835 more URLs

URLScan.io (234)
  https://example.com/
  https://www.example.com/index.html
  https://example.com/assets/main.js
  https://example.com/assets/style.css
  https://api.example.com/v1/status
  ... and 229 more URLs

AlienVault OTX (89)
  https://example.com/
  https://example.com/api/
  https://example.com/api/v2/
  ... and 86 more URLs

CommonCrawl (80)
  https://example.com/
  https://www.example.com/blog/
  https://example.com/products/
  ... and 77 more URLs

Summary by Source:
  Wayback Machine: 842
  URLScan.io: 234
  AlienVault OTX: 89
  CommonCrawl: 80

✓ Found 1,245 unique URLs
```

**Sample Output (Filtered - JavaScript only):**

```bash
$ rb recon domain urls example.com --extensions js

🔗 URL Harvester (waybackurls/gau)

  Target Domain: example.com

Discovered URLs (52) [filtered: .js files only]

Wayback Machine (35)
  2023-11-15  https://example.com/assets/main.js
  2023-10-20  https://example.com/assets/vendor.js
  2023-09-12  https://example.com/js/analytics.js
  2023-08-05  https://example.com/static/bundle.js
  2023-07-18  https://api.example.com/client.js
  ... and 30 more URLs

URLScan.io (12)
  https://example.com/assets/main.js
  https://example.com/js/app.js
  ... and 10 more URLs

CommonCrawl (5)
  https://example.com/vendor.js
  https://example.com/polyfill.js
  ... and 3 more URLs

✓ Found 52 unique JavaScript files
```

---

#### 6. `osint` - Username OSINT

Run username OSINT across multiple social platforms and services.

**Syntax:**
```bash
rb recon domain osint <username> [FLAGS]
```

**Arguments:**
- `<username>` - Target username (required)

**Status:** ✅ Implemented

**Features:**
- Social media presence (Twitter, LinkedIn, GitHub, Instagram, Facebook, etc.)
- Recursive discovery of linked usernames/mentions
- Extraction of profile details (bio, followers, location)

**Examples:**

```bash
# Search for username across platforms
rb recon domain osint johndoe

# Recursive discovery up to 2 levels deep
rb recon domain osint johndoe --recursive --depth 2

# JSON output
rb recon domain osint johndoe -o json
```

**Sample Output (Text):**

```
👤 Username OSINT: johndoe

Found 5 profiles
  ✓ Twitter - @johndoe (1234 followers) - https://x.com/johndoe
  ✓ GitHub - @johndoe - https://github.com/johndoe
  ✓ LinkedIn - @johndoe - https://www.linkedin.com/in/johndoe
  ✗ Instagram - @johndoe (not found)
  ✓ Medium - @johndoe - https://medium.com/@johndoe

Discovered linked usernames (2)
  - @johndoetech
  - @johndoe_dev
```

---

#### 7. `email` - Email Reconnaissance

Email address reconnaissance and validation.

**Syntax:**
```bash
rb recon domain email <email|domain> [FLAGS]
```

**Arguments:**
- `<email|domain>` - Target email address or domain (required)

**Status:** ✅ Implemented

**Features:**
- Email validation (syntax, MX records, SMTP verification)
- Email permutation (generate variations like `john.doe@domain.com`)
- Breach database lookup (HaveIBeenPwned integration)
- Email correlation (find emails associated with a domain)

**Flags:**
- `--validate` - Perform SMTP validation for an email address
- `--generate-permutations <first> <last>` - Generate permutations for a name on a domain
- `--check-breaches` - Check if email found in data breaches (requires HIBP API key in config)
- `--correlate` - Correlate emails for a given domain

**Examples:**

```bash
# Check email validity
rb recon domain email john.doe@example.com --validate

# Generate email permutations for a full name and domain
rb recon domain email example.com --generate-permutations "John Doe"

# Correlate emails for a domain
rb recon domain email example.com --correlate

# Check breach databases for an email
rb recon domain email john.doe@example.com --check-breaches --hibp-key YOUR_KEY

# JSON output for correlation
rb recon domain email example.com --correlate -o json
```

**Sample Output (Text):**

```
✉️ Email Reconnaissance: john.doe@example.com

  Target Email: john.doe@example.com

  Validation: ✓ Valid (MX records found, SMTP check passed)

Breach Check: ✗ Not found in known breaches

Correlated Emails for example.com:
  - info@example.com
  - support@example.com
  - john.doe@example.com
  - j.doe@example.com
```

---

## Configuration

The RECON domain uses project-level configuration from `.redblue.yaml`:

```yaml
recon:
  # Default subdomain wordlist
  subdomain_wordlist: /usr/share/wordlists/subdomains.txt

  # DNS bruteforce threads
  subdomain_threads: 10

  # Enable passive-only mode by default
  passive_only: false

  # Auto-save results to database
  auto_persist: true

  # WHOIS server timeout (seconds)
  whois_timeout: 10

  # URL harvester sources
  url_sources:
    - wayback
    - urlscan
    - otx
    - commoncrawl
```

**Global config:** `~/.config/redblue/config.toml`
**Project config:** `./.redblue.yaml` (takes precedence)

---

## Common Use Cases

### 1. **Domain Intelligence Gathering**

Complete OSINT workflow for a target domain:

```bash
# Step 1: WHOIS lookup
rb recon domain whois example.com --persist

# Step 2: Subdomain enumeration
rb recon domain subdomains example.com --persist

# Step 3: Harvest emails and URLs
rb recon domain harvest example.com --persist

# Step 4: Get historical URLs
rb recon domain urls example.com --persist

# Step 5: Query database for all findings
rb database data query example.com.rdb
```

### 2. **Passive Reconnaissance Only**

Stealthy information gathering without active scans:

```bash
# Passive subdomain enumeration (no DNS queries)
rb recon domain subdomains example.com --passive

# OSINT data harvesting (search engines only)
rb recon domain harvest example.com

# Historical URLs (no direct requests)
rb recon domain urls example.com
```

### 3. **Bug Bounty Recon**

Focus on finding hidden endpoints and subdomains:

```bash
# Aggressive subdomain enumeration
rb recon domain subdomains example.com --threads 50 --wordlist big-list.txt

# Get JavaScript files for code analysis
rb recon domain urls example.com --extensions js

# Find API endpoints
rb recon domain urls example.com --include /api/

# Export for further testing
rb database data export example.com.rdb
```

### 4. **Red Team Operation**

Comprehensive target profiling:

```bash
# Initial recon
rb recon domain whois target.com
rb recon domain subdomains target.com --passive
rb recon domain harvest target.com

# Deeper enumeration
rb recon domain urls target.com --include /admin/
rb recon domain urls target.com --extensions asp,aspx,php

# Export findings
rb database data query target.com.rdb
rb database data export target.com.rdb -o recon_report.csv
```

---

## Tool Equivalents

The RECON domain replaces or complements these traditional tools:

| Traditional Tool | redblue Command | Notes |
|-----------------|----------------|-------|
| **whois** | `rb recon domain whois` | Multi-TLD WHOIS lookups |
| **amass** | `rb recon domain subdomains` | Subdomain enumeration (all methods) |
| **subfinder** | `rb recon domain subdomains --passive` | Passive subdomain discovery |
| **crt.sh** | `rb recon domain subdomains --passive` | Certificate Transparency logs |
| **theHarvester** | `rb recon domain harvest` | OSINT data harvesting |
| **waybackurls** | `rb recon domain urls` | Wayback Machine URL scraping |
| **gau** | `rb recon domain urls` | Get All URLs from multiple sources |
| **assetfinder** | `rb recon domain subdomains` | Asset discovery |
| **sherlock** | `rb recon domain osint` (Implemented) | Username OSINT |
| **h8mail** | `rb recon domain email` (Implemented) | Email recon |

---

## Technical Details

### WHOIS Protocol

**Implementation:** RFC 3912 (TCP port 43)

**WHOIS Server Selection:**
```
.com, .net → whois.verisign-grs.com
.org       → whois.pir.org
.io        → whois.nic.io
.co        → whois.nic.co
.dev       → whois.nic.google
(+50 more TLDs)
```

**Fallback:** Automatic WHOIS server detection via TLD

### Subdomain Enumeration

**Certificate Transparency Sources:**
- crt.sh API
- Censys (future)
- Certspotter (future)

**DNS Bruteforce:**
- Concurrent A record queries
- Configurable thread pool
- Default wordlist: ~1000 common subdomains
- Custom wordlist support

### URL Harvesting

**Wayback Machine API:**
```
https://web.archive.org/cdx/search/cdx?url=example.com/*
```

**URLScan.io API:**
```
https://urlscan.io/api/v1/search/?q=domain:example.com
```

**AlienVault OTX:**
```
https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list
```

---

## Troubleshooting

### WHOIS Lookup Fails

**Problem:** "WHOIS query failed" or "Unknown TLD"

**Solutions:**
```bash
# Check if domain is valid
rb recon domain whois example.com

# Try raw output to see WHOIS server response
rb recon domain whois example.com --raw

# For uncommon TLDs, may need manual WHOIS server
# (future feature: --server flag)
```

### No Subdomains Found

**Problem:** Subdomain enumeration returns 0 results

**Solutions:**
```bash
# Try passive-only first
rb recon domain subdomains example.com --passive

# Increase thread count for DNS bruteforce
rb recon domain subdomains example.com --threads 50

# Use custom wordlist
rb recon domain subdomains example.com --wordlist /usr/share/wordlists/dns/subdomains-top1million-5000.txt

# Check if domain has subdomains at all
rb dns record lookup www.example.com
```

### URL Harvester Returns Few URLs

**Problem:** Only getting a handful of URLs

**Solutions:**
```bash
# Some sources may be rate-limited or down
# Try again later, or use different sources

# For very new domains, historical archives may be empty
# This is expected

# Check specific sources manually:
# - https://web.archive.org/web/*/example.com
# - https://urlscan.io/search/#example.com
```

---

## Performance Tips

### Subdomain Enumeration Speed

**Fast (passive only):**
```bash
rb recon domain subdomains example.com --passive
# ~5-10 seconds
```

**Balanced (default):**
```bash
rb recon domain subdomains example.com
# ~30-60 seconds (depends on wordlist)
```

**Thorough (large wordlist):**
```bash
rb recon domain subdomains example.com --wordlist huge.txt --threads 100
# Several minutes (100,000+ queries)
```

### URL Harvesting Limits

- Wayback Machine: Can return 10,000+ URLs (use filters)
- URLScan.io: API rate limits apply
- AlienVault OTX: Free tier limits
- CommonCrawl: Large datasets (may be slow)

**Filter aggressively:**
```bash
# Only JavaScript and PHP files
rb recon domain urls example.com --extensions js,php

# Only API endpoints
rb recon domain urls example.com --include /api/
```

---

## See Also

- [DNS Domain](/domains/dns.md) - DNS reconnaissance (A, MX, NS, TXT records)
- [WEB Domain](/domains/web.md) - Web application testing
- [NETWORK Domain](/domains/network.md) - Network discovery and port scanning
- [DATABASE Domain](/domains/database.md) - Store and query recon results

**External Resources:**
- Certificate Transparency: https://crt.sh
- Wayback Machine: https://web.archive.org
- URLScan.io: https://urlscan.io
- AlienVault OTX: https://otx.alienvault.com

---

**Supported TLDs:** 50+ including .com, .org, .net, .io, .co, .dev, .app, .ai, .me, .uk, .de, .fr, .br, .jp, and more.