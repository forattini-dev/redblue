# Recon Workflow

Strategic reconnaissance workflow for penetration testing.

> **Reconnaissance is 90% of a successful pentest.** The more information you gather, the better your attack strategy.

## Quick Start

```bash
# Full target recon (run all)
rb recon domain whois target.com --persist
rb recon domain subdomains target.com --persist
rb recon domain harvest target.com --persist
rb recon domain urls target.com --persist
```

## The Recon Methodology

```
┌─────────────────────────────────────────────────────────────┐
│                    TARGET ACQUISITION                        │
│                      (domain/IP/org)                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   PASSIVE RECON                             │
│  • WHOIS lookup                                             │
│  • DNS records                                              │
│  • Certificate Transparency                                 │
│  • Historical URLs (Wayback)                                │
│  • OSINT harvesting                                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   ACTIVE RECON                              │
│  • Subdomain bruteforce                                     │
│  • Port scanning                                            │
│  • Service fingerprinting                                   │
│  • Technology detection                                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  ATTACK SURFACE MAP                         │
│  • Exposed services                                         │
│  • Potential entry points                                   │
│  • Vulnerability correlation                                │
└─────────────────────────────────────────────────────────────┘
```

## Phase 1: Passive Reconnaissance

**Goal:** Gather maximum information WITHOUT touching the target directly.

### Step 1.1: Domain Intelligence

```bash
# WHOIS - Registration info, dates, contacts
rb recon domain whois target.com --persist

# Extract:
# - Registrar (hosting provider patterns)
# - Creation date (old = more history to search)
# - Nameservers (DNS provider, potential misconfig)
# - Registrant org (parent company, related domains)
```

### Step 1.2: DNS Records

```bash
# All record types
rb dns record lookup target.com --type A
rb dns record lookup target.com --type AAAA
rb dns record lookup target.com --type MX
rb dns record lookup target.com --type NS
rb dns record lookup target.com --type TXT
rb dns record lookup target.com --type CNAME

# Extract from TXT records:
# - SPF records (email infrastructure)
# - DKIM keys (email security)
# - Domain verification (services used)
# - API keys (sometimes leaked!)
```

### Step 1.3: Passive Subdomain Discovery

```bash
# Certificate Transparency logs (no direct queries)
rb recon domain subdomains target.com --passive --persist

# This finds:
# - dev.target.com (development environments)
# - staging.target.com (staging with test data)
# - api.target.com (API endpoints)
# - admin.target.com (admin panels)
# - internal.target.com (internal systems exposed)
```

### Step 1.4: Historical Intelligence

```bash
# Historical URLs from archives
rb recon domain urls target.com --persist

# Look for:
# - Old admin panels (/admin/, /wp-admin/)
# - API endpoints (/api/v1/, /graphql)
# - Backup files (.bak, .old, .backup)
# - Config files (.config, .env, .json)
# - Source maps (.map, .js.map)

# Filter for high-value targets
rb recon domain urls target.com --extensions js,php,asp,aspx,json,xml
rb recon domain urls target.com --include "/api/|/admin/|/backup"
```

### Step 1.5: OSINT Harvesting

```bash
# Comprehensive OSINT
rb recon domain harvest target.com --persist

# Gathered data:
# - Email addresses (for phishing scope)
# - Subdomains (attack surface)
# - IP addresses (infrastructure mapping)
# - URLs (entry points)
```

## Phase 2: Active Reconnaissance

**Goal:** Direct interaction with target to discover services and technologies.

### Step 2.1: Full Subdomain Discovery

```bash
# Active bruteforce + passive
rb recon domain subdomains target.com --threads 50 --persist

# With large wordlist for thorough coverage
rb recon domain subdomains target.com \
  --wordlist /path/to/subdomains-top1million-110000.txt \
  --threads 100
```

### Step 2.2: Port Scanning

```bash
# For each discovered subdomain/IP
rb network ports scan target.com --preset common --persist

# Full scan for critical targets
rb network ports scan target.com --preset full

# Quick web ports
rb network ports scan target.com --preset web
```

### Step 2.3: Service Analysis

```bash
# HTTP headers and technology
rb web headers asset https://target.com

# Security headers audit
rb web security asset https://target.com

# TLS configuration
rb tls security audit target.com
```

### Step 2.4: Cloud Asset Discovery

```bash
# Check for subdomain takeovers
rb cloud asset takeover-scan --wordlist discovered-subs.txt --persist

# This finds abandoned:
# - Heroku apps
# - S3 buckets
# - Azure web apps
# - GitHub pages
```

## Phase 3: Data Correlation

### Combine All Findings

```bash
# Export all gathered data
rb database data query target.com.rdb

# Export for analysis
rb database data export target.com.rdb -o target-recon.csv
```

### Create Attack Surface Map

```bash
# Subdomains + IPs + Services
echo "=== ATTACK SURFACE: target.com ===" > attack-surface.md

echo "\n## Subdomains" >> attack-surface.md
rb recon domain subdomains target.com -o json | \
  jq -r '.subdomains[].subdomain' >> attack-surface.md

echo "\n## Open Ports" >> attack-surface.md
rb network ports scan target.com -o json | \
  jq -r '.open_ports[]' >> attack-surface.md

echo "\n## Historical URLs (High Value)" >> attack-surface.md
rb recon domain urls target.com --include "/api/|/admin/" -o json | \
  jq -r '.urls[].url' >> attack-surface.md
```

## Strategic Analysis

### What to Look For

| Data Point | Strategic Value |
|------------|-----------------|
| Old subdomains | Forgotten systems, outdated software |
| dev/staging | Test data, weaker security |
| API endpoints | Direct backend access |
| Admin panels | Authentication bypass targets |
| Old URLs | Removed but still accessible |
| JS files | Client-side logic, API keys |
| Email addresses | Phishing targets, username patterns |
| IP ranges | Network infrastructure |
| TXT records | Third-party services, misconfigs |

### Priority Targets

```
HIGH PRIORITY:
├── api.target.com (API access)
├── admin.target.com (admin panels)
├── dev.target.com (development)
├── staging.target.com (test data)
├── vpn.target.com (network access)
├── mail.target.com (email systems)
└── internal.target.com (exposed internal)

MEDIUM PRIORITY:
├── blog.target.com (CMS vulnerabilities)
├── shop.target.com (payment systems)
├── portal.target.com (user data)
└── cdn.target.com (file access)

INVESTIGATE:
├── old-*.target.com (deprecated)
├── test*.target.com (test systems)
└── *.target.com.s3.amazonaws.com (cloud storage)
```

## Complete Recon Script

```bash
#!/bin/bash
# Full automated recon for target

TARGET=$1
OUTPUT_DIR="./recon-$TARGET"

mkdir -p $OUTPUT_DIR

echo "[*] Starting recon for $TARGET"

# Phase 1: Passive
echo "[+] WHOIS lookup..."
rb recon domain whois $TARGET -o json > $OUTPUT_DIR/whois.json

echo "[+] DNS records..."
for type in A AAAA MX NS TXT CNAME; do
  rb dns record lookup $TARGET --type $type -o json > $OUTPUT_DIR/dns-$type.json
done

echo "[+] Passive subdomains..."
rb recon domain subdomains $TARGET --passive -o json > $OUTPUT_DIR/subs-passive.json

echo "[+] Historical URLs..."
rb recon domain urls $TARGET -o json > $OUTPUT_DIR/urls.json

echo "[+] OSINT harvest..."
rb recon domain harvest $TARGET -o json > $OUTPUT_DIR/harvest.json

# Phase 2: Active
echo "[+] Active subdomain bruteforce..."
rb recon domain subdomains $TARGET --threads 50 -o json > $OUTPUT_DIR/subs-active.json

echo "[+] Port scanning discovered hosts..."
cat $OUTPUT_DIR/subs-active.json | jq -r '.subdomains[].subdomain' | while read sub; do
  rb network ports scan $sub --preset common -o json >> $OUTPUT_DIR/ports.json
done

echo "[+] Cloud takeover check..."
cat $OUTPUT_DIR/subs-active.json | jq -r '.subdomains[].subdomain' > $OUTPUT_DIR/subs.txt
rb cloud asset takeover-scan -w $OUTPUT_DIR/subs.txt -o json > $OUTPUT_DIR/takeover.json

# Phase 3: Analysis
echo "[+] Generating report..."
echo "# Recon Report: $TARGET" > $OUTPUT_DIR/REPORT.md
echo "Generated: $(date)" >> $OUTPUT_DIR/REPORT.md

echo "\n## Summary" >> $OUTPUT_DIR/REPORT.md
echo "- Subdomains: $(cat $OUTPUT_DIR/subs-active.json | jq '.count')" >> $OUTPUT_DIR/REPORT.md
echo "- URLs: $(cat $OUTPUT_DIR/urls.json | jq '.total')" >> $OUTPUT_DIR/REPORT.md
echo "- Emails: $(cat $OUTPUT_DIR/harvest.json | jq '.emails | length')" >> $OUTPUT_DIR/REPORT.md

echo "[*] Recon complete! Results in $OUTPUT_DIR/"
```

## Integration with Other Domains

### Recon → Web Testing

```bash
# Found admin panel in recon
rb web security asset https://admin.target.com
rb web cms-scan asset https://admin.target.com
```

### Recon → Network Scanning

```bash
# Found IP range in WHOIS
rb network ports scan 192.168.1.0/24 --preset common
```

### Recon → Cloud Testing

```bash
# Found potential S3 buckets
rb cloud asset takeover s3.target.com
```

### Recon → Exploitation

```bash
# Found dev server with old software
rb exploit payload privesc  # After gaining access
```

## Next Steps

- [WHOIS Lookup](01-whois.md) - Domain registration info
- [Subdomain Enumeration](02-subdomains.md) - Find subdomains
- [URL Discovery](03-urls.md) - Historical URLs
- [Data Harvesting](04-harvest.md) - OSINT collection
