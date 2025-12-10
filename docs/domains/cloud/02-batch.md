# Batch Subdomain Takeover Scanning

Scan multiple subdomains from a wordlist for takeover vulnerabilities.

## Quick Start

```bash
# Scan from wordlist
rb cloud asset takeover-scan --wordlist subdomains.txt

# High confidence only
rb cloud asset takeover-scan -w subs.txt --confidence high

# JSON output
rb cloud asset takeover-scan -w subs.txt -o json
```

## Command

### takeover-scan - Bulk Subdomain Scanning

Scan multiple subdomains for takeover vulnerabilities.

```bash
rb cloud asset takeover-scan --wordlist <file> [flags]
```

## Options

```rust
// Bulk scan options
struct TakeoverScanOptions {
    // Wordlist file path (required)
    wordlist: String,

    // Minimum confidence level to display
    // Values: "high", "medium", "low"
    // Default: "low"
    confidence: String,

    // Number of concurrent checks
    // Range: 1-200
    // Default: 50
    concurrency: u32,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,

    // Save results to database
    // Default: false
    persist: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--wordlist` | `-w` | Wordlist file path | required |
| `--confidence` | `-c` | Minimum confidence | low |
| `--concurrency` | `-n` | Concurrent checks | 50 |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |

## Wordlist Format

```
# One subdomain per line
subdomain1.example.com
subdomain2.example.com
old-app.example.com
blog.example.com
dev.example.com
```

## Examples

### Basic Batch Scan

```bash
# Scan all subdomains
rb cloud asset takeover-scan --wordlist subdomains.txt

# Scan with higher concurrency
rb cloud asset takeover-scan -w subs.txt --concurrency 100
```

### Filtered Results

```bash
# Only high confidence (immediate action)
rb cloud asset takeover-scan -w subs.txt --confidence high

# Medium and above
rb cloud asset takeover-scan -w subs.txt --confidence medium
```

### Output Formats

```bash
# Text (default)
rb cloud asset takeover-scan -w subs.txt

# JSON for automation
rb cloud asset takeover-scan -w subs.txt -o json > results.json

# Save to database
rb cloud asset takeover-scan -w subs.txt --persist
```

## Output Examples

### Text Output

```
Bulk Subdomain Takeover Scan

  Wordlist: subdomains.txt
  Total domains: 247

Scanning 247 domains... ✓

Scan Summary
  Total domains:       247
  Vulnerable:          5
  High confidence:     2
  Medium confidence:   2
  Low confidence:      1

5 VULNERABLE DOMAINS FOUND:

  old-app.example.com | HIGH | Heroku
    CNAME: old-app-12345.herokuapp.com
    CNAME points to unclaimed Heroku app

  staging.example.com | HIGH | AWS S3
    CNAME: staging.example.com.s3.amazonaws.com
    S3 bucket does not exist

  blog.example.com | MEDIUM | Ghost
    CNAME: example-blog.ghost.io
    Ghost service - verify manually

  test-shop.example.com | MEDIUM | Shopify
    CNAME: test-shop.myshopify.com
    Shopify store not found

  abandoned.example.com | LOW | Unknown
    CNAME: old-service.example.net
    Dead DNS record

SECURITY ALERT: Subdomain takeover vulnerabilities detected!
```

### JSON Output

```json
{
  "wordlist": "subdomains.txt",
  "total": 247,
  "vulnerable": 5,
  "summary": {
    "high": 2,
    "medium": 2,
    "low": 1
  },
  "results": [
    {
      "domain": "old-app.example.com",
      "vulnerable": true,
      "confidence": "high",
      "cname": "old-app-12345.herokuapp.com",
      "service": "Heroku"
    },
    {
      "domain": "staging.example.com",
      "vulnerable": true,
      "confidence": "high",
      "cname": "staging.example.com.s3.amazonaws.com",
      "service": "AWS S3"
    },
    {
      "domain": "www.example.com",
      "vulnerable": false,
      "confidence": "none",
      "cname": "www.example.com.cdn.cloudflare.net"
    }
  ]
}
```

## Patterns

### From Subdomain Enumeration

```bash
# Step 1: Enumerate subdomains
rb recon domain subdomains target.com --persist

# Step 2: Export to wordlist
rb database data query target.com.rdb | \
  jq -r '.subdomains[]' > subs.txt

# Step 3: Scan for takeovers
rb cloud asset takeover-scan -w subs.txt --persist
```

### Multiple Targets

```bash
# Combine subdomain lists
cat target1-subs.txt target2-subs.txt | sort -u > all-subs.txt

# Scan all
rb cloud asset takeover-scan -w all-subs.txt --confidence medium
```

### Export Vulnerable Only

```bash
# Get only vulnerable subdomains
rb cloud asset takeover-scan -w subs.txt -o json | \
  jq -r '.results[] | select(.vulnerable) | .domain'
```

### Continuous Monitoring

```bash
#!/bin/bash
# Daily takeover scan

WORDLIST="/path/to/our-subdomains.txt"
REPORT="/path/to/reports/$(date +%Y-%m-%d).json"

rb cloud asset takeover-scan -w $WORDLIST -o json > $REPORT

# Check for vulnerabilities
VULNS=$(jq '.vulnerable' $REPORT)
if [ "$VULNS" -gt 0 ]; then
  echo "ALERT: $VULNS vulnerabilities found" | mail -s "Takeover Alert" security@company.com
fi
```

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
name: Security Scan
on:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  takeover-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan for takeovers
        run: |
          rb cloud asset takeover-scan -w subdomains.txt -o json > results.json
          VULNS=$(jq '.vulnerable' results.json)
          if [ "$VULNS" -gt 0 ]; then
            echo "::error::$VULNS subdomain takeover vulnerabilities found!"
            exit 1
          fi
```

## Performance

### Speed Comparison

| Concurrency | Domains/min | Use Case |
|-------------|-------------|----------|
| 10 | ~80 | Slow/safe |
| 50 (default) | ~200 | Standard |
| 100 | ~400 | Fast |
| 200 | ~600 | Aggressive |

### Recommendations

```bash
# Large wordlists (1000+ domains)
rb cloud asset takeover-scan -w large.txt --concurrency 100

# Small/targeted lists
rb cloud asset takeover-scan -w targets.txt --concurrency 20

# Rate-limited environments
rb cloud asset takeover-scan -w subs.txt --concurrency 10
```

## Preparing Wordlists

### From Recon Data

```bash
# From subdomain enumeration
rb recon domain subdomains target.com -o json | \
  jq -r '.subdomains[].subdomain' > subs.txt

# From URL harvesting
rb recon domain urls target.com -o json | \
  jq -r '.urls[].url' | \
  sed 's|https\?://||' | cut -d/ -f1 | sort -u > subs.txt
```

### Cleaning Wordlists

```bash
# Remove duplicates
sort -u raw-subs.txt > clean-subs.txt

# Remove empty lines
sed '/^$/d' subs.txt > clean.txt

# Validate format (FQDN only)
grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' subs.txt > valid.txt
```

## Troubleshooting

### High False Positive Rate

```bash
# Use higher confidence filter
rb cloud asset takeover-scan -w subs.txt --confidence high

# Manually verify flagged domains
rb cloud asset takeover suspicious.example.com
curl -I https://suspicious.example.com
```

### Slow Performance

```bash
# Increase concurrency
rb cloud asset takeover-scan -w subs.txt --concurrency 100

# Filter confidence to reduce checks
rb cloud asset takeover-scan -w subs.txt --confidence medium
```

### Memory Issues

```bash
# For very large wordlists, split into chunks
split -l 1000 huge-list.txt chunk_
for f in chunk_*; do
  rb cloud asset takeover-scan -w $f >> results.txt
done
```

## Next Steps

- [Subdomain Takeover](/domains/cloud/01-takeover.md) - Single subdomain check
- [Configuration](/domains/cloud/03-configuration.md) - Cloud settings
