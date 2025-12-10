# WEB Domain Documentation

## TL;DR
Explains the current HTTP/CMS tooling, intelligence hooks, and the backlog for fuzzing, crawling, and auth-aware workflows inside `rb web`.

## Overview

The `web` domain provides comprehensive web application security testing including HTTP operations, security header analysis, directory fuzzing, CMS vulnerability scanning, and web technology fingerprinting. It replaces tools like **curl**, **ffuf**, **gobuster**, **wpscan**, **droopescan**, **nikto**, and **whatweb**.

**Domain:** `web`

**Available Resources:**
- `asset` - Web application testing and analysis

**Key Features:**
- HTTP/1.1 client (GET/POST from scratch)
- Security header auditing
- Directory/file fuzzing (ffuf/gobuster style)
- CMS detection and vulnerability scanning (WordPress, Drupal, Joomla)
- Web technology fingerprinting
- JavaScript endpoint extraction (linkfinder)
- Web crawling
- HTTP server fingerprinting

---

## Implementation Status (Nov 2025)

### Shipping Today
- Core HTTP engine and response analysis live in `src/modules/web/` (`headers.rs`, `fingerprinter.rs`, `fuzzer.rs`, `vuln-scanner.rs`, etc.), all built on `std::net::TcpStream` with no external crates.
- CMS fingerprinting strategies (`strategies/wordpress.rs`, `drupal.rs`, `joomla.rs`, `ghost.rs`, `strapi.rs`) power `rb web asset scan` without relying on third-party signatures.
- CLI verbs in `src/cli/commands/web.rs` expose `get`, `post`, `headers`, `security`, `scan`, and `fuzz` flows with shared output envelopes and persistence hooks.
- Linkfinder and crawler modules extract URLs/JS endpoints, feeding discoveries back into the intelligence pipeline.
- HTTP dispatcher now exposes streaming handlers (`HttpResponseHandler`) and middleware hooks so modules can process large bodies incrementally while sharing logging/caching layers.

### In Flight / Backlog
- Directory fuzzing still needs adaptive rate limiting and wordlist rotation; integration with global wordlists (`wordlists/`) is pending.
- Web crawler lacks robots.txt handling and depth limiting; add before exposing aggressive defaults.
- Vulnerability scanner should expand beyond CMS to include generic misconfigurations (headers, default creds) and surface severity scoring.
- Automated tests (`tests/web_smoke.rs` planned) should cover GET/POST, header parsing, and CMS fingerprint baselines.

### Next Actions
1. Implement persistent session support (cookies/auth) so chained requests can maintain state during scans.
2. Add JSON/YAML rendering for `--intel` output to align with network/TLS domains.
3. Document troubleshooting (timeouts, TLS handshake failures) once the TLS 1.3 work stabilizes.

### Developer Streaming Example

RedBlue modules can now tap into the streaming HTTP pipeline and middleware stack directly:

```rust
use std::sync::Arc;
use crate::protocols::http::{
    HttpClient, HttpRequest, HttpResponseHandler, HttpResponseHead,
    LoggingMiddleware,
};

struct BodyPrinter;

impl HttpResponseHandler for BodyPrinter {
    fn on_head(&mut self, head: &HttpResponseHead) -> Result<(), String> {
        println!("Status: {}", head.status_code);
        Ok(())
    }

    fn on_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
        std::io::stdout().write_all(chunk).map_err(|e| e.to_string())
    }
}

let mut handler = BodyPrinter;
let client = HttpClient::new()
    .with_keep_alive(true)
    .with_middleware(Arc::new(LoggingMiddleware));

client
    .send_with_handler(&HttpRequest::get("http://example.com"), &mut handler)
    .expect("streamed response");
```

`send_with_handler` guarantees headers land before any body chunk, while middlewares (logging, caching, throttling) stay reusable across every module.

---

## Resource: `web asset`

**Description:** Comprehensive web application security testing and reconnaissance.

### Commands

#### 1. `get` - HTTP GET Request

Execute raw HTTP GET requests with full response analysis.

**Syntax:**
```bash
rb web asset get <url> [FLAGS]
```

**Arguments:**
- `<url>` - Target URL (http:// or https://, required)

**Flags:**
- `-t, --timeout <sec>` - Request timeout (default: 10)
- `-u, --user-agent <ua>` - Custom User-Agent
- `-f, --follow` - Follow redirects
- `--intel` - HTTP server fingerprinting and intelligence gathering

**Examples:**

```bash
# Basic GET request
rb web asset get http://example.com

# With intelligence gathering
rb web asset get http://example.com --intel

# Custom User-Agent
rb web asset get http://example.com --user-agent "MyBot/1.0"

# Follow redirects
rb web asset get http://example.com --follow

# JSON output
rb web asset get http://example.com -o json
```

**Sample Output:**

```
HTTP GET Request
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL: http://example.com

Response
Status:     200 OK
Body Size:  1256 bytes

Headers
content-type:        text/html; charset=UTF-8
server:              nginx/1.24.0
date:                Mon, 03 Nov 2025 12:34:56 GMT
content-length:      1256

✓ Request successful
```

**Intelligence Gathering Output (`--intel`):**

```
HTTP Server Intelligence
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Server Software:  nginx
Version:          1.24.0
Operating System: Ubuntu
Modules:          http_ssl, http_v2
```

---

#### 2. `headers` - HTTP Header Analysis

Inspect and analyze all HTTP response headers.

**Syntax:**
```bash
rb web asset headers <url>
```

**Examples:**

```bash
rb web asset headers http://example.com
rb web asset headers https://google.com
```

**Sample Output:**

```
HTTP Headers: http://example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Response Headers (12 found)
  server:              nginx/1.24.0
  content-type:        text/html; charset=UTF-8
  x-frame-options:     SAMEORIGIN
  x-content-type-options: nosniff
  strict-transport-security: max-age=31536000
  content-security-policy: default-src 'self'
```

---

#### 3. `security` - Security Header Audit

Audit security-related HTTP headers and identify missing protections.

**Syntax:**
```bash
rb web asset security <url>
```

**Examples:**

```bash
rb web asset security http://example.com
rb web asset security https://intranet.local
```

**Sample Output:**

```
Security Header Audit: http://example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Security Headers (5 present)
  ✓ X-Frame-Options: SAMEORIGIN
  ✓ X-Content-Type-Options: nosniff
  ✓ Strict-Transport-Security: max-age=31536000
  ✓ Content-Security-Policy: default-src 'self'
  ✓ X-XSS-Protection: 1; mode=block

⚠ Missing Security Headers (3)
  ✗ Referrer-Policy (information leakage)
  ✗ Permissions-Policy (feature control)
  ✗ Cross-Origin-Opener-Policy (isolation)

Security Score: 5/8 (62%)
```

**Security Headers Checked:**
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options` (Clickjacking protection)
- `X-Content-Type-Options` (MIME sniffing)
- `X-XSS-Protection` (XSS filter)
- `Referrer-Policy` (Referrer control)
- `Permissions-Policy` (Feature policy)
- `Cross-Origin-Opener-Policy` (COOP)

---

#### 4. `fuzz` - Directory/File Fuzzing

Directory and file discovery using wordlist-based fuzzing.

**Syntax:**
```bash
rb web asset fuzz <url> [FLAGS]
```

**Flags:**
- `-w, --wordlist <file>` - Custom wordlist file
- `--common` - Use built-in common wordlist
- `-t, --threads <n>` - Concurrent threads (default: 50)
- `--filter <codes>` - Filter out status codes (default: 404)
- `--match <codes>` - Only show specific status codes
- `-r, --recursive` - Enable recursive fuzzing (feroxbuster-style)
- `--depth <n>` - Maximum recursion depth (default: 3)

**Examples:**

```bash
# Basic fuzzing with common wordlist
rb web asset fuzz http://example.com --common

# Custom wordlist
rb web asset fuzz http://example.com --wordlist /usr/share/wordlists/dirs.txt

# Recursive fuzzing (feroxbuster-style)
rb web asset fuzz http://example.com --common --recursive --depth 4

# High-speed fuzzing
rb web asset fuzz http://example.com --common --threads 200

# Filter specific codes
rb web asset fuzz http://example.com --common --filter 404,403

# Match only success codes
rb web asset fuzz http://example.com --common --match 200,301,302
```

**Sample Output:**

```
Directory Fuzzing: http://example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Wordlist:  common (1000 entries)
Threads:   50
Filter:    404

Fuzzing... [████████████████████████] 1000/1000 (12.3s)

✅ Discovered Paths (8 found)

CODE    SIZE      PATH
200     4523      /admin
301     -         /api
200     1234      /login
200     8765      /dashboard
403     -         /config
301     -         /static
200     567       /robots.txt
200     234       /sitemap.xml

✓ Fuzzing completed in 12.34s - 8 paths discovered
```

**Recursive Fuzzing:**

```
[DEPTH 1] Fuzzing http://example.com/
  200  /admin
  301  /api

[DEPTH 2] Fuzzing http://example.com/admin/
  200  /admin/users
  200  /admin/settings

[DEPTH 2] Fuzzing http://example.com/api/
  200  /api/v1
  200  /api/v2
```

---

#### 5. `fingerprint` - Web Technology Detection

Identify web technologies, frameworks, and server software.

**Syntax:**
```bash
rb web asset fingerprint <url>
```

**Examples:**

```bash
rb web asset fingerprint http://example.com
rb web asset fingerprint https://wordpress-site.com
```

**Sample Output:**

```
Web Fingerprinting: http://example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Detected Technologies (7)

Web Server
  • nginx 1.24.0

Programming Language
  • PHP 8.1.2

Framework
  • WordPress 6.4.2
  • jQuery 3.6.0

CDN
  • Cloudflare

Analytics
  • Google Analytics UA-123456

Security
  • Let's Encrypt (TLS certificate)
```

---

#### 6. `cms-scan` - Unified CMS Security Scanner

Auto-detect and scan CMS platforms (WordPress, Drupal, Joomla) for vulnerabilities.

**Syntax:**
```bash
rb web asset cms-scan <url> [FLAGS]
```

**Flags:**
- `-s, --strategy <strategy>` - Scanning strategy: `auto`, `wordpress`, `drupal`, `joomla`
  - Default: `auto`

**Examples:**

```bash
# Auto-detect CMS
rb web asset cms-scan http://blog.example.com

# Force WordPress scan
rb web asset cms-scan http://blog.example.com --strategy wordpress

# Drupal scan
rb web asset cms-scan http://site.example.com --strategy drupal

# Joomla scan
rb web asset cms-scan http://portal.example.com --strategy joomla
```

**Sample Output (WordPress):**

```
🔒 CMS Security Scan: http://blog.example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Detected: WordPress 6.4.2

📦 Core Information
Version:        6.4.2
Released:       2023-12-06
Status:         ⚠️  Outdated (latest: 6.4.3)
Theme:          twentytwentyfour (1.0)

🔌 Plugins (3 detected)
  • contact-form-7 (5.8.4) - ✓ Up to date
  • yoast-seo (21.7) - ⚠️  Vulnerable (CVE-2023-12345)
  • jetpack (12.9) - ✓ Secure

👤 Users (2 enumerated)
  • admin (ID: 1)
  • editor (ID: 2)

⚠️  Security Findings (3)
  1. Outdated WordPress core version
  2. Vulnerable plugin: yoast-seo (update available)
  3. User enumeration enabled (/wp-json/wp/v2/users)

🛡️  Recommendations
  • Update WordPress to 6.4.3
  • Update yoast-seo plugin immediately
  • Disable user enumeration

✓ Scan completed in 4.2s
```

---

#### 7. `wpscan` - WordPress Security Scanner

Dedicated WordPress vulnerability scanner.

**Syntax:**
```bash
rb web asset wpscan <url>
```

**Examples:**

```bash
rb web asset wpscan http://wordpress-site.com
```

**Features:**
- Core version detection
- Plugin enumeration
- Theme detection
- User enumeration
- Known vulnerability database
- Security recommendations

---

#### 8. `drupal-scan` - Drupal Security Scanner

Dedicated Drupal vulnerability scanner (droopescan replacement).

**Syntax:**
```bash
rb web asset drupal-scan <url>
```

**Examples:**

```bash
rb web asset drupal-scan http://drupal-site.com
```

---

#### 9. `joomla-scan` - Joomla Security Scanner

Dedicated Joomla vulnerability scanner.

**Syntax:**
```bash
rb web asset joomla-scan <url>
```

**Examples:**

```bash
rb web asset joomla-scan http://joomla-site.com
```

---

#### 10. `linkfinder` - JavaScript Endpoint Extraction

Extract API endpoints, URLs, and secrets from JavaScript files.

**Syntax:**
```bash
rb web asset linkfinder <js-url> [FLAGS]
```

**Flags:**
- `--type <type>` - Filter by type: `api`, `s3`, `websocket`, `graphql`, `all`

**Examples:**

```bash
# Extract all endpoints
rb web asset linkfinder http://example.com/app.js

# Only API endpoints
rb web asset linkfinder http://example.com/app.js --type api

# S3 buckets
rb web asset linkfinder http://example.com/app.js --type s3
```

**Sample Output:**

```
JavaScript Endpoint Extraction: http://example.com/app.js
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Endpoints Found (15)

API Endpoints (8)
  • /api/v1/users
  • /api/v1/products
  • /api/v2/orders
  • /graphql

S3 Buckets (2)
  • https://mybucket.s3.amazonaws.com
  • https://assets.s3.us-west-2.amazonaws.com

WebSocket (1)
  • wss://example.com/ws

URLs (4)
  • https://cdn.example.com/assets
  • https://static.example.com

✓ Extraction completed - 15 endpoints found
```

---

#### 11. `scan` - General Web Vulnerability Scan

Auto-detect CMS and run appropriate vulnerability scanner (nikto-style).

**Syntax:**
```bash
rb web asset scan <url>
```

**Examples:**

```bash
rb web asset scan http://example.com
```

---

#### 12. `vuln-scan` - Active Vulnerability Scanner

Active OWASP ZAP-style vulnerability scanner.

**Syntax:**
```bash
rb web asset vuln-scan <url>
```

**Status:** 🚧 Coming in Phase 3

---

#### 13. `crawl` - Web Crawler

Lightweight web crawler for site mapping.

**Syntax:**
```bash
rb web asset crawl <url>
```

**Status:** 🚧 Coming in Phase 2

---

## Configuration

**Configuration File:** `./.redblue.yaml`

**Web Section:**

```yaml
web:
  timeout_secs: 10              # HTTP timeout
  user_agent: "redblue/1.0"     # Default User-Agent
  follow_redirects: true        # Follow redirects
  max_redirects: 5              # Max redirect hops
  verify_ssl: true              # SSL verification
```

**Environment Variables:**

```bash
export REDBLUE_WEB_TIMEOUT_SECS=15
export REDBLUE_WEB_USER_AGENT="CustomBot/1.0"
```

---

## Common Use Cases

### 1. Web Security Audit

```bash
rb web asset security http://example.com
rb web asset fingerprint http://example.com
rb web asset cms-scan http://example.com
```

### 2. Directory Discovery

```bash
rb web asset fuzz http://example.com --common
rb web asset fuzz http://example.com --common --recursive
```

### 3. CMS Vulnerability Assessment

```bash
rb web asset cms-scan http://wordpress-site.com
rb web asset wpscan http://wordpress-site.com
```

### 4. API Discovery

```bash
rb web asset linkfinder http://example.com/app.js --type api
rb web asset fuzz http://example.com/api --common
```

---

## Tool Equivalents

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `curl` | `rb web asset get` | HTTP client |
| `ffuf` | `rb web asset fuzz` | Directory fuzzing |
| `feroxbuster` | `rb web asset fuzz --recursive` | Recursive fuzzing |
| `gobuster` | `rb web asset fuzz` | Directory brute force |
| `wpscan` | `rb web asset wpscan` | WordPress scanner |
| `droopescan` | `rb web asset drupal-scan` | Drupal scanner |
| `nikto` | `rb web asset scan` | Vulnerability scanner |
| `whatweb` | `rb web asset fingerprint` | Tech detection |
| `linkfinder` | `rb web asset linkfinder` | JS endpoint extraction |

---

## See Also

- [TLS Domain Documentation](./TLS.md) - TLS certificate inspection
- [NETWORK Domain Documentation](./NETWORK.md) - Port scanning
- [DNS Domain Documentation](./DNS.md) - DNS reconnaissance
- [RECON Domain Documentation](./RECON.md) - WHOIS and subdomain discovery
