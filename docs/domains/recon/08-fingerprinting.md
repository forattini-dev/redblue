# Technology Fingerprinting

Identify technologies, frameworks, and versions for vulnerability mapping.

> **Know your target's stack.** Every technology has known CVEs - find the version, find the exploit.

## Quick Start

```bash
# HTTP headers reveal server info
rb web headers asset https://target.com

# Security audit shows technologies
rb web security asset https://target.com

# TLS reveals crypto stack
rb tls security audit target.com

# CMS detection
rb web cms-scan asset https://target.com
```

## Why Fingerprinting Matters

```
Technology + Version = CVE Search = Potential Exploit

Example:
  Apache/2.4.49 → CVE-2021-41773 → Path Traversal RCE
  WordPress 5.7.1 → CVE-2021-29447 → XXE Injection
  jQuery 2.1.4 → CVE-2020-11022 → XSS
```

## Detection Methods

### HTTP Headers Analysis

```bash
rb web headers asset https://target.com
```

**Headers that reveal technology:**

| Header | Reveals |
|--------|---------|
| `Server` | Web server (Apache, nginx, IIS) |
| `X-Powered-By` | Backend (PHP, ASP.NET, Express) |
| `X-AspNet-Version` | .NET version |
| `X-Generator` | CMS (WordPress, Drupal) |
| `X-Drupal-Cache` | Drupal CMS |
| `X-Varnish` | Varnish cache |
| `Via` | Proxy servers |
| `Set-Cookie` | Session handling (PHPSESSID, JSESSIONID) |

**Example output:**
```
HTTP Headers: https://target.com

Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-Generator: WordPress 5.8.1
Set-Cookie: PHPSESSID=abc123; path=/
```

**Extracted info:**
- Web Server: Apache 2.4.41
- OS: Ubuntu
- Backend: PHP 7.4.3
- CMS: WordPress 5.8.1

### Response Body Analysis

```bash
# Get full response
rb web get asset https://target.com --show-headers
```

**HTML indicators:**

| Pattern | Technology |
|---------|------------|
| `wp-content/` | WordPress |
| `/sites/default/files` | Drupal |
| `/media/system/` | Joomla |
| `ng-app` | AngularJS |
| `__NEXT_DATA__` | Next.js |
| `data-reactroot` | React |
| `vue` | Vue.js |
| `_nuxt` | Nuxt.js |

### JavaScript Libraries

```bash
# Find JS files
rb recon domain urls target.com --extensions js -o json | \
  jq -r '.urls[].url'
```

**Common library patterns:**

| File Pattern | Library |
|--------------|---------|
| `jquery-3.6.0.min.js` | jQuery 3.6.0 |
| `angular.min.js` | AngularJS |
| `react.production.min.js` | React |
| `vue.min.js` | Vue.js |
| `bootstrap.min.js` | Bootstrap |
| `lodash.min.js` | Lodash |

### CMS Detection

```bash
# Auto-detect CMS
rb web cms-scan asset https://target.com

# Force specific CMS check
rb web cms-scan asset https://target.com --strategy wordpress
rb web cms-scan asset https://target.com --strategy drupal
rb web cms-scan asset https://target.com --strategy joomla
```

**CMS fingerprints:**

| CMS | Detection Points |
|-----|------------------|
| WordPress | `/wp-content/`, `/wp-includes/`, `wp-json` |
| Drupal | `/sites/default/`, `Drupal.settings`, `CHANGELOG.txt` |
| Joomla | `/administrator/`, `/media/system/` |
| Magento | `/skin/frontend/`, `/js/mage/` |
| Shopify | `cdn.shopify.com`, `myshopify.com` |

### TLS/SSL Analysis

```bash
rb tls security audit target.com
rb tls security ciphers target.com
```

**TLS reveals:**
- OpenSSL version (sometimes)
- Server software from certificate
- Supported protocols (TLS 1.0 = old system)
- Cipher suites (weak = legacy system)

## Technology Stack Mapping

### Web Server Layer

```bash
# Headers analysis
rb web headers asset https://target.com -o json | jq '.headers.server'
```

| Server | Typical Stack |
|--------|---------------|
| Apache | PHP, MySQL, Linux |
| nginx | Node.js, Python, Go |
| IIS | ASP.NET, MSSQL, Windows |
| Cloudflare | CDN (real server hidden) |
| Amazon CloudFront | AWS infrastructure |

### Application Layer

```bash
# Cookie-based detection
rb web get asset https://target.com -o json | jq '.headers["set-cookie"]'
```

| Cookie Pattern | Technology |
|----------------|------------|
| `PHPSESSID` | PHP |
| `JSESSIONID` | Java (Tomcat, Spring) |
| `ASP.NET_SessionId` | ASP.NET |
| `connect.sid` | Express.js |
| `_session_id` | Ruby on Rails |
| `csrftoken` | Django |
| `laravel_session` | Laravel |

### Database Layer

**Indicators in errors/responses:**

| Error Pattern | Database |
|---------------|----------|
| `mysql_` functions | MySQL |
| `pg_` functions | PostgreSQL |
| `ORA-` errors | Oracle |
| `MSSQL` errors | SQL Server |
| `MongoDB` in stack | MongoDB |

### Framework Detection

```bash
# Look for framework-specific paths
rb recon domain urls target.com -o json | \
  jq '.urls[].url' | grep -E "rails|django|laravel|spring|express"
```

| URL Pattern | Framework |
|-------------|-----------|
| `/rails/` | Ruby on Rails |
| `/django/` | Django |
| `/api/laravel/` | Laravel |
| `/actuator/` | Spring Boot |
| `/swagger/` | Swagger (API docs) |

## Version Extraction

### From Headers

```bash
# Parse version numbers
rb web headers asset https://target.com -o json | \
  jq -r '.headers | to_entries[] | select(.value | test("[0-9]+\\.[0-9]+")) | "\(.key): \(.value)"'
```

### From Meta Tags

```bash
# WordPress version in generator
rb web get asset https://target.com | grep -i "generator"
# <meta name="generator" content="WordPress 5.8.1" />
```

### From JavaScript

```bash
# jQuery version
rb web get asset https://target.com | grep -oP 'jquery[.-]?(\d+\.\d+\.\d+)'

# From source maps
rb recon domain urls target.com --extensions map -o json
```

### From Specific Files

| File | Information |
|------|-------------|
| `/readme.html` | WordPress version |
| `/CHANGELOG.txt` | Drupal version |
| `/administrator/manifests/files/joomla.xml` | Joomla version |
| `/package.json` | Node.js dependencies |
| `/composer.json` | PHP dependencies |

## CVE Correlation

### Search Pattern

```
1. Identify technology + version
2. Search: "technology version CVE"
3. Check exploit-db, NVD, GitHub

Example:
  Found: Apache 2.4.49
  Search: "Apache 2.4.49 CVE"
  Result: CVE-2021-41773 (Path Traversal)
```

### Common CVE Sources

| Resource | URL |
|----------|-----|
| NVD | nvd.nist.gov |
| Exploit-DB | exploit-db.com |
| CVE Details | cvedetails.com |
| Vulners | vulners.com |
| Snyk | snyk.io/vuln |

### High-Value Targets

| Technology | Known Issues |
|------------|--------------|
| Apache 2.4.49-50 | CVE-2021-41773 (RCE) |
| Log4j < 2.17 | CVE-2021-44228 (RCE) |
| Spring4Shell | CVE-2022-22965 (RCE) |
| jQuery < 3.5.0 | Multiple XSS |
| WordPress < 5.8.3 | Multiple vulns |
| PHP < 8.0 | Various CVEs |

## Automated Fingerprinting Script

```bash
#!/bin/bash
TARGET=$1

echo "=== Technology Fingerprint: $TARGET ==="

echo -e "\n[+] HTTP Headers..."
rb web headers asset https://$TARGET -o json | jq '{
  server: .headers.server,
  powered_by: .headers["x-powered-by"],
  generator: .headers["x-generator"]
}'

echo -e "\n[+] TLS Info..."
rb tls security audit $TARGET -o json | jq '{
  tls_versions: .tls_versions,
  grade: .grade
}'

echo -e "\n[+] CMS Detection..."
rb web cms-scan asset https://$TARGET -o json | jq '{
  cms: .cms.type,
  version: .cms.version
}'

echo -e "\n[+] JavaScript Libraries..."
rb recon domain urls $TARGET --extensions js -o json | \
  jq -r '.urls[].url' | head -10

echo -e "\n[+] Checking CVEs..."
echo "Search these on exploit-db.com and nvd.nist.gov"
```

## Integration with Pentest

```
Fingerprint → CVE Search → Exploit Development

Example Flow:
1. rb web headers asset https://target.com
   → Found: Apache/2.4.49

2. searchsploit apache 2.4.49
   → Apache 2.4.49 - Path Traversal (CVE-2021-41773)

3. curl 'https://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'
   → root:x:0:0:root:/root:/bin/bash
```

## Next Steps

- [Recon Workflow](06-workflow.md) - Complete methodology
- [High-Value Targets](07-targets.md) - What to look for
- [Web Security Audit](../web/02-security.md) - Security headers
- [CMS Scanning](../web/03-cms.md) - CMS detection
