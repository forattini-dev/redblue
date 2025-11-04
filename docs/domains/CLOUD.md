# CLOUD Domain Documentation

## Overview

The `cloud` domain provides cloud security testing including subdomain takeover detection (CNAME hijacking), S3 bucket enumeration, and cloud service misconfiguration detection. This domain replaces tools like **tko-subs**, **subjack**, **s3scanner**, and **cloud_enum**.

**Domain:** `cloud`

**Resource:** `asset`

**Status:** ✅ Phase 2 (70% Complete)

---

## Implementation Status (Nov 2025)

### Current Coverage
- Subdomain takeover engine (`src/modules/cloud/takeover.rs`) fingerprints 20+ SaaS providers and maps confidence levels; it is surfaced through `src/cli/commands/cloud.rs`.
- Early S3 enumeration plumbing exists in `src/modules/cloud/s3-scanner.rs` but is gated pending wordlist integration and rate limiting.
- Findings persist into `.rdb` segments via `src/storage/segments/` so takeover results can be queried alongside DNS/network intel.

### Gaps To Close
- Batch scanning (`takeover-scan`) and CSV import/export remain stubs; need CLI verbs plus concurrency guards.
- Azure/GCP object storage detection requires additional fingerprints and HTTP probe logic.
- No automated tests currently cover cloud modules; add smoke tests hitting local fixtures before expanding provider coverage.
- Remediation guidance (per-provider steps) should be templated for consistent output.

### Recommended Next Steps
1. Finish the S3 bucket scanner with list/get/head flows and add persistence for discovered ACL issues.
2. Implement throttling/backoff to respect provider error responses during bulk scans.
3. Extend documentation with troubleshooting (false positives, geo-blocked endpoints) once batch tooling lands.

---

## Resource: `cloud asset`

**Description:** Cloud asset security testing including subdomain takeover detection and cloud service enumeration.

### Commands

#### 1. `takeover` - Subdomain Takeover Detection

Check a single subdomain for takeover vulnerability by analyzing CNAME records and service responses (tko-subs/subjack replacement).

**Syntax:**
```bash
rb cloud asset takeover <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Subdomain to check (required)

**Flags:**
- `-c, --confidence <level>` - Minimum confidence level: `high`, `medium`, `low`
  - Default: `low` (show all findings)
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)

**What It Checks:**

1. **CNAME Resolution** - Resolves CNAME records for the subdomain
2. **Service Fingerprinting** - Identifies the target cloud service
3. **Dangling CNAME Detection** - Checks if CNAME points to non-existent resource
4. **Vulnerability Assessment** - Determines if subdomain can be taken over

**Vulnerable Services Detected:**

| Service | Fingerprint | Risk |
|---------|-------------|------|
| **AWS S3** | `.s3.amazonaws.com` | HIGH |
| **Heroku** | `.herokuapp.com` | HIGH |
| **GitHub Pages** | `.github.io` | HIGH |
| **Azure** | `.azurewebsites.net` | HIGH |
| **Shopify** | `.myshopify.com` | MEDIUM |
| **Tumblr** | `.tumblr.com` | MEDIUM |
| **WordPress.com** | `.wordpress.com` | MEDIUM |
| **Ghost** | `.ghost.io` | MEDIUM |
| **Bitbucket** | `.bitbucket.io` | MEDIUM |
| **Netlify** | `.netlify.app` | LOW |
| **Vercel** | `.vercel.app` | LOW |
| **Surge.sh** | `.surge.sh` | LOW |

**Confidence Levels:**

- **HIGH** - CNAME points to known vulnerable service with error response
- **MEDIUM** - CNAME points to vulnerable service but needs manual verification
- **LOW** - Dead DNS record (CNAME doesn't resolve)
- **NONE** - Not vulnerable

**Examples:**

```bash
# Check single subdomain
rb cloud asset takeover subdomain.example.com

# Check with high confidence only
rb cloud asset takeover old-app.example.com --confidence high

# JSON output
rb cloud asset takeover test.example.com -o json

# Save to database
rb cloud asset takeover vulnerable.example.com --persist
```

**Sample Output (Vulnerable - HIGH):**

```
🔐 Subdomain Takeover Checker

  Domain: old-app.example.com

Checking old-app.example.com... ✓

  CNAME: old-app-12345.herokuapp.com

⚠️  VULNERABLE - High Confidence
   Service: Heroku
   CNAME points to unclaimed Heroku app - subdomain can be taken over

🚨 ACTION REQUIRED:
   1. Verify the vulnerability manually
   2. Remove the CNAME record OR claim the service
   3. Monitor for unauthorized changes
```

**Sample Output (Vulnerable - MEDIUM):**

```
🔐 Subdomain Takeover Checker

  Domain: blog.example.com

Checking blog.example.com... ✓

  CNAME: example-blog.ghost.io

⚠️  POTENTIALLY VULNERABLE - Medium Confidence
   Service: Ghost
   CNAME points to Ghost service - verify manually

Recommendation: Verify manually by checking HTTP response
```

**Sample Output (Not Vulnerable):**

```
🔐 Subdomain Takeover Checker

  Domain: www.example.com

Checking www.example.com... ✓

  CNAME: www.example.com.cdn.cloudflare.net

✓ Not vulnerable
  Status: CNAME resolves correctly and service is active
```

**Sample Output (JSON):**

```json
{
  "domain": "old-app.example.com",
  "vulnerable": true,
  "confidence": "high",
  "cname": "old-app-12345.herokuapp.com",
  "service": "Heroku",
  "message": "CNAME points to unclaimed Heroku app - subdomain can be taken over"
}
```

---

#### 2. `takeover-scan` - Bulk Subdomain Takeover Scan

Scan multiple subdomains from a wordlist file for takeover vulnerabilities.

**Syntax:**
```bash
rb cloud asset takeover-scan --wordlist <file> [FLAGS]
```

**Arguments:**
- None (all input via flags)

**Flags:**
- `-w, --wordlist <file>` - File containing list of subdomains (one per line) **[REQUIRED]**
- `-c, --confidence <level>` - Minimum confidence to display: `high`, `medium`, `low`
  - Default: `low` (show all)
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)

**Wordlist Format:**

```
subdomain1.example.com
subdomain2.example.com
old-app.example.com
blog.example.com
dev.example.com
```

**Examples:**

```bash
# Scan subdomains from wordlist
rb cloud asset takeover-scan --wordlist subdomains.txt

# Show only high confidence findings
rb cloud asset takeover-scan -w subs.txt --confidence high

# JSON output for automation
rb cloud asset takeover-scan -w discovered.txt -o json

# Save results to database
rb cloud asset takeover-scan -w targets.txt --persist
```

**Sample Output:**

```
🔐 Bulk Subdomain Takeover Scan

  Wordlist: subdomains.txt
  Total domains: 247

Scanning 247 domains... ✓

Scan Summary
  Total domains:       247
  Vulnerable:          5
  High confidence:     2
  Medium confidence:   2
  Low confidence:      1

⚠️  5 VULNERABLE DOMAINS FOUND:

  old-app.example.com | 🔴 HIGH | Heroku
    CNAME: old-app-12345.herokuapp.com
    CNAME points to unclaimed Heroku app - subdomain can be taken over

  staging.example.com | 🔴 HIGH | AWS S3
    CNAME: staging.example.com.s3.amazonaws.com
    S3 bucket does not exist - subdomain can be taken over

  blog.example.com | 🟡 MEDIUM | Ghost
    CNAME: example-blog.ghost.io
    CNAME points to Ghost service - verify manually

  test-shop.example.com | 🟡 MEDIUM | Shopify
    CNAME: test-shop.myshopify.com
    Shopify store not found - verify manually

  abandoned.example.com | 🟢 LOW | Unknown
    CNAME: old-service.example.net
    Dead DNS record - CNAME doesn't resolve

🚨 SECURITY ALERT: Subdomain takeover vulnerabilities detected!
   Review each finding and take appropriate action
```

---

#### 3. `services` - List Vulnerable Service Fingerprints

Display all cloud services that are checked for subdomain takeover vulnerabilities.

**Syntax:**
```bash
rb cloud asset services
```

**Arguments:**
- None

**Flags:**
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`

**Examples:**

```bash
# List all supported services
rb cloud asset services

# JSON output
rb cloud asset services -o json
```

**Sample Output:**

```
🔐 Supported Vulnerable Services

Total Services: 25

  1. AWS S3
  2. Heroku
  3. GitHub Pages
  4. Azure Web Apps
  5. Shopify
  6. Tumblr
  7. WordPress.com
  8. Ghost
  9. Bitbucket
  10. Netlify
  11. Vercel
  12. Surge.sh
  13. Fastly
  14. Pantheon
  15. Acquia
  16. Feedpress
  17. Cargo Collective
  18. StatusPage
  19. UserVoice
  20. Helpjuice
  21. Helpscout
  22. Campaign Monitor
  23. Tictail
  24. Brightcove
  25. BigCartel

ℹ️  These services are checked for subdomain takeover vulnerabilities
```

---

## Configuration

The CLOUD domain uses project-level configuration from `.redblue.yaml`:

```yaml
cloud:
  # Subdomain takeover settings
  takeover:
    # Default confidence level for filtering
    min_confidence: low

    # Timeout for DNS resolution (seconds)
    dns_timeout: 5

    # Timeout for HTTP checks (seconds)
    http_timeout: 10

    # Maximum concurrent checks (bulk scan)
    max_concurrent: 50

  # Auto-save results to database
  auto_persist: false
```

**Global config:** `~/.config/redblue/config.toml`
**Project config:** `./.redblue.yaml` (takes precedence)

---

## Common Use Cases

### 1. **Bug Bounty Reconnaissance**

Check discovered subdomains for takeover vulnerabilities:

```bash
# Step 1: Enumerate subdomains
rb recon domain subdomains example.com --persist

# Step 2: Extract subdomains from database
rb database data export example.com.rdb -o subdomains.csv

# Step 3: Create wordlist from CSV
awk -F',' '{print $1}' subdomains.csv > subs.txt

# Step 4: Scan for takeovers
rb cloud asset takeover-scan -w subs.txt --confidence high
```

### 2. **Continuous Monitoring**

Monitor your own subdomains for dangling CNAMEs:

```bash
# Create wordlist of your subdomains
cat > my-subdomains.txt <<EOF
www.mycompany.com
api.mycompany.com
blog.mycompany.com
staging.mycompany.com
dev.mycompany.com
EOF

# Scan regularly (cron job)
rb cloud asset takeover-scan -w my-subdomains.txt --persist

# Alert on findings
rb cloud asset takeover-scan -w my-subdomains.txt --confidence high | grep -q "VULNERABLE" && notify-admin
```

### 3. **Single Subdomain Verification**

Manually verify a suspicious subdomain:

```bash
# Check specific subdomain
rb cloud asset takeover subdomain.example.com

# If vulnerable, try to claim the service
# Example for Heroku:
# heroku apps:create old-app-12345

# Remove CNAME if not claiming
dig subdomain.example.com CNAME
# Contact DNS admin to remove record
```

### 4. **Red Team Operation**

Find takeover vulnerabilities in target organization:

```bash
# Gather subdomains from multiple sources
rb recon domain subdomains target.com --passive > subs1.txt
rb recon domain urls target.com --include subdomain >> subs2.txt
rb dns record bruteforce target.com >> subs3.txt

# Combine and deduplicate
cat subs*.txt | sort -u > all-subdomains.txt

# Scan for high-confidence takeovers only
rb cloud asset takeover-scan -w all-subdomains.txt --confidence high

# Document findings for responsible disclosure
```

---

## Attack Scenario Example

**Scenario: Abandoned Heroku App**

```bash
# 1. Discover vulnerable subdomain
$ rb cloud asset takeover old-dashboard.example.com

🔐 Subdomain Takeover Checker
  Domain: old-dashboard.example.com

⚠️  VULNERABLE - High Confidence
   Service: Heroku
   CNAME: old-dashboard-prod.herokuapp.com
   Heroku app does not exist - subdomain can be taken over

# 2. Verify CNAME
$ dig old-dashboard.example.com CNAME
old-dashboard.example.com. 300 IN CNAME old-dashboard-prod.herokuapp.com.

# 3. Attempt takeover (ethical testing with authorization)
$ heroku apps:create old-dashboard-prod
Creating ⬢ old-dashboard-prod... done
https://old-dashboard-prod.herokuapp.com/ | https://git.heroku.com/old-dashboard-prod.git

# 4. Verify takeover
$ curl -I https://old-dashboard.example.com
HTTP/1.1 200 OK
Server: Heroku
# SUCCESS - You now control old-dashboard.example.com

# 5. Responsible disclosure
# - Screenshot proof of concept
# - Report to security team
# - DO NOT deploy malicious content
# - Delete Heroku app after confirmation
```

---

## Remediation Guide

### For Security Teams

**When a takeover vulnerability is found:**

1. **Immediate Actions:**
   ```bash
   # Remove the CNAME record
   # Update DNS to point to valid service or remove entirely
   ```

2. **If Service Still Needed:**
   - Claim the service account (Heroku app, S3 bucket, etc.)
   - Update DNS to point to claimed resource
   - Monitor for unauthorized changes

3. **If Service No Longer Needed:**
   - Remove CNAME record from DNS
   - Remove A/AAAA records if present
   - Document removal in change log

4. **Long-term Prevention:**
   - Maintain inventory of all subdomains
   - Monitor DNS changes
   - Regular scans for dangling CNAMEs
   - Automate cleanup when services are decommissioned

### Common Mistakes

❌ **Don't:**
- Leave CNAME records pointing to decommissioned services
- Delete cloud resources without updating DNS
- Ignore low-confidence findings (still worth checking)

✅ **Do:**
- Maintain subdomain inventory
- Scan regularly for vulnerabilities
- Remove DNS records when decommissioning services
- Use automation for monitoring

---

## Tool Equivalents

The CLOUD domain replaces or complements these traditional tools:

| Traditional Tool | redblue Command | Notes |
|-----------------|----------------|-------|
| **tko-subs** | `rb cloud asset takeover` | Single subdomain check |
| **subjack** | `rb cloud asset takeover-scan` | Bulk scanning |
| **s3scanner** | `rb cloud storage scan` (future) | S3 bucket enumeration |
| **cloud_enum** | `rb cloud storage scan` (future) | Multi-cloud enumeration |
| **can-i-take-over-xyz** | `rb cloud asset services` | Service fingerprint database |

---

## Technical Details

### CNAME Validation Logic

```
1. Resolve CNAME for subdomain
   └─ If no CNAME → Not vulnerable

2. Extract target service from CNAME
   └─ Match against known vulnerable services

3. Check if target exists
   ├─ DNS lookup fails → Likely vulnerable (HIGH)
   ├─ HTTP returns 404/error → Possibly vulnerable (MEDIUM)
   └─ HTTP returns 200/normal → Not vulnerable (NONE)

4. Service-specific fingerprinting
   ├─ Heroku: Check for "no such app" error
   ├─ S3: Check for "NoSuchBucket" XML
   ├─ GitHub Pages: Check for "404 - File not found"
   └─ Azure: Check for "404 Web Site not found"
```

### Service Fingerprints

**Heroku Detection:**
```
CNAME: *.herokuapp.com
Error: "There's nothing here, yet."
Confidence: HIGH
```

**AWS S3 Detection:**
```
CNAME: *.s3.amazonaws.com
Error: <Code>NoSuchBucket</Code>
Confidence: HIGH
```

**GitHub Pages Detection:**
```
CNAME: *.github.io
Error: "404 - File not found"
Confidence: HIGH
```

---

## Troubleshooting

### False Positives

**Problem:** Service flagged as vulnerable but isn't

**Solutions:**
```bash
# Verify manually
dig subdomain.example.com CNAME
curl -I https://subdomain.example.com

# Check with multiple tools
tko-subs -domain subdomain.example.com
subjack -d subdomain.example.com

# Report false positive on GitHub
```

### DNS Resolution Issues

**Problem:** "DNS resolution failed" errors

**Solutions:**
```bash
# Check DNS server
dig subdomain.example.com @8.8.8.8

# Try different DNS server
dig subdomain.example.com @1.1.1.1

# Check if domain exists
whois example.com
```

### Wordlist Formatting

**Problem:** Bulk scan fails with "invalid domain"

**Solutions:**
```bash
# Ensure one subdomain per line
cat subdomains.txt
subdomain1.example.com
subdomain2.example.com

# Remove empty lines and whitespace
sed '/^$/d' subdomains.txt | sed 's/^[ \t]*//;s/[ \t]*$//' > clean.txt

# Validate domains
grep -E '^[a-zA-Z0-9.-]+$' subdomains.txt
```

---

## Performance Tips

### Bulk Scanning Speed

**Fast (50 concurrent):**
```bash
rb cloud asset takeover-scan -w subdomains.txt
# ~200 domains/minute (default concurrency: 50)
```

**Slower but Safer (10 concurrent):**
```bash
# Edit .redblue.yaml:
# cloud:
#   takeover:
#     max_concurrent: 10

rb cloud asset takeover-scan -w subdomains.txt
# ~80 domains/minute (lower rate limiting risk)
```

### Filtering Results

**Show only actionable findings:**
```bash
# High confidence only (immediate action needed)
rb cloud asset takeover-scan -w subs.txt --confidence high

# Medium+ confidence (worth investigating)
rb cloud asset takeover-scan -w subs.txt --confidence medium
```

---

## Security & Ethics

**⚠️ CRITICAL: Authorized Testing Only**

**Ethical Use:**
- ✅ Test your own domains
- ✅ Authorized penetration testing
- ✅ Bug bounty programs (in scope)
- ✅ Responsible disclosure

**Prohibited:**
- ❌ Taking over domains you don't own
- ❌ Deploying malicious content
- ❌ Phishing or social engineering
- ❌ Testing without authorization

**Responsible Disclosure:**
1. Document the finding (screenshots, PoC)
2. Report to security team immediately
3. Do NOT deploy any content to taken-over domain
4. Do NOT publicize vulnerability before fix
5. Clean up test artifacts (delete claimed services)

---

## See Also

- [RECON Domain](./RECON.md) - Subdomain enumeration
- [DNS Domain](./DNS.md) - CNAME resolution
- [WEB Domain](./WEB.md) - HTTP response analysis
- [DATABASE Domain](./DATABASE.md) - Store scan results

**External Resources:**
- Can I take over XYZ?: https://github.com/EdOverflow/can-i-take-over-xyz
- Subdomain Takeover: https://owasp.org/www-community/attacks/Subdomain_Takeover
- HackerOne Reports: https://hackerone.com/reports?q=subdomain+takeover

---

## Future Features (Phase 3)

### Cloud Storage Enumeration (Planned)

```bash
# S3 bucket enumeration
rb cloud storage scan company-name

# Azure storage enumeration
rb cloud storage scan company-name --provider azure

# GCS bucket enumeration
rb cloud storage scan company-name --provider gcp
```

**Will replace:** s3scanner, cloud_enum, bucket_finder

---

**Supported Services:** 25+ cloud services including AWS, Heroku, GitHub Pages, Azure, Shopify, and more.
