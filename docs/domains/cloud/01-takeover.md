# Subdomain Takeover Detection

Detect subdomain takeover vulnerabilities by analyzing CNAME records.

## Quick Start

```bash
# Check single subdomain
rb cloud asset takeover subdomain.example.com

# High confidence only
rb cloud asset takeover old-app.example.com --confidence high

# JSON output
rb cloud asset takeover test.example.com -o json
```

## Command

### takeover - Single Subdomain Check

Check a subdomain for takeover vulnerability.

```bash
rb cloud asset takeover <domain> [flags]
```

## Options

```rust
// Takeover check options
struct TakeoverOptions {
    // Minimum confidence level to display
    // Values: "high", "medium", "low"
    // Default: "low"
    confidence: String,

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
| `--confidence` | `-c` | Minimum confidence: high, medium, low | low |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |

## Vulnerable Services

### High Risk

| Service | CNAME Pattern | Fingerprint |
|---------|---------------|-------------|
| AWS S3 | `.s3.amazonaws.com` | NoSuchBucket |
| Heroku | `.herokuapp.com` | "No such app" |
| GitHub Pages | `.github.io` | 404 File not found |
| Azure Web Apps | `.azurewebsites.net` | 404 Web Site not found |

### Medium Risk

| Service | CNAME Pattern | Fingerprint |
|---------|---------------|-------------|
| Shopify | `.myshopify.com` | Store not found |
| Tumblr | `.tumblr.com` | Not found |
| WordPress.com | `.wordpress.com` | Site not found |
| Ghost | `.ghost.io` | Site not available |
| Bitbucket | `.bitbucket.io` | Repository not found |

### Lower Risk

| Service | CNAME Pattern | Notes |
|---------|---------------|-------|
| Netlify | `.netlify.app` | Requires verification |
| Vercel | `.vercel.app` | Requires verification |
| Surge.sh | `.surge.sh` | Easy to claim |

## Examples

### Basic Check

```bash
# Check single subdomain
rb cloud asset takeover app.example.com

# Check with explicit confidence
rb cloud asset takeover old-site.example.com --confidence high
```

### Output Formats

```bash
# Text (default)
rb cloud asset takeover subdomain.example.com

# JSON for automation
rb cloud asset takeover subdomain.example.com -o json

# Save to database
rb cloud asset takeover subdomain.example.com --persist
```

## Output Examples

### Text Output (Vulnerable - HIGH)

```
Subdomain Takeover Checker

  Domain: old-app.example.com

Checking old-app.example.com... ✓

  CNAME: old-app-12345.herokuapp.com

  VULNERABLE - High Confidence
   Service: Heroku
   CNAME points to unclaimed Heroku app

ACTION REQUIRED:
   1. Verify the vulnerability manually
   2. Remove the CNAME record OR claim the service
   3. Monitor for unauthorized changes
```

### Text Output (Vulnerable - MEDIUM)

```
Subdomain Takeover Checker

  Domain: blog.example.com

Checking blog.example.com... ✓

  CNAME: example-blog.ghost.io

  POTENTIALLY VULNERABLE - Medium Confidence
   Service: Ghost
   CNAME points to Ghost service - verify manually

Recommendation: Check HTTP response manually
```

### Text Output (Not Vulnerable)

```
Subdomain Takeover Checker

  Domain: www.example.com

Checking www.example.com... ✓

  CNAME: www.example.com.cdn.cloudflare.net

✓ Not vulnerable
  Status: CNAME resolves correctly and service is active
```

### JSON Output

```json
{
  "domain": "old-app.example.com",
  "vulnerable": true,
  "confidence": "high",
  "cname": "old-app-12345.herokuapp.com",
  "service": "Heroku",
  "message": "CNAME points to unclaimed Heroku app - subdomain can be taken over",
  "remediation": "Remove CNAME record or claim the Heroku app"
}
```

## Detection Logic

### How It Works

```
1. Resolve CNAME for subdomain
   └─ If no CNAME → Not vulnerable

2. Match CNAME against known patterns
   └─ Identify cloud service (Heroku, S3, etc.)

3. Check if target resource exists
   ├─ DNS fails → HIGH confidence
   ├─ HTTP 404/error → MEDIUM confidence
   └─ HTTP 200 → Not vulnerable

4. Return vulnerability status
```

### Service Fingerprinting

**Heroku:**
```
CNAME: *.herokuapp.com
Error page: "There's nothing here, yet."
Status: HIGH confidence
```

**AWS S3:**
```
CNAME: *.s3.amazonaws.com
Error: <Code>NoSuchBucket</Code>
Status: HIGH confidence
```

**GitHub Pages:**
```
CNAME: *.github.io
Error: "404 - There isn't a GitHub Pages site here."
Status: HIGH confidence
```

## Patterns

### Bug Bounty Workflow

```bash
# Step 1: Enumerate subdomains
rb recon domain subdomains target.com -o json > subs.json

# Step 2: Extract subdomain list
cat subs.json | jq -r '.subdomains[].subdomain' > subs.txt

# Step 3: Check each for takeover
while read sub; do
  rb cloud asset takeover "$sub" --confidence high
done < subs.txt
```

### CI/CD Integration

```bash
#!/bin/bash
# Fail if any subdomain is vulnerable

rb cloud asset takeover-scan -w our-subdomains.txt -o json > results.json
VULNS=$(cat results.json | jq '.vulnerable | length')

if [ "$VULNS" -gt 0 ]; then
  echo "SECURITY: $VULNS subdomain takeover vulnerabilities found!"
  exit 1
fi
```

### Manual Verification

```bash
# Step 1: Check with redblue
rb cloud asset takeover suspicious.example.com

# Step 2: Verify CNAME
dig suspicious.example.com CNAME

# Step 3: Check HTTP response
curl -I https://suspicious.example.com

# Step 4: Try to claim (if authorized)
# For Heroku: heroku apps:create app-name
```

## Remediation

### Remove CNAME Record

If the service is no longer needed:

```bash
# 1. Identify the CNAME
dig subdomain.example.com CNAME

# 2. Contact DNS admin to remove record

# 3. Verify removal
dig subdomain.example.com CNAME
# Should return: NXDOMAIN or no CNAME
```

### Claim the Service

If you still need the subdomain:

```bash
# Heroku
heroku apps:create the-app-name

# GitHub Pages
# Create repo with same name

# S3
aws s3 mb s3://the-bucket-name
```

## Troubleshooting

### False Positives

```bash
# Manually verify with HTTP request
curl -v https://subdomain.example.com

# Check DNS resolution
dig subdomain.example.com ANY

# Some services have legitimate 404 pages
```

### DNS Issues

```bash
# Try different DNS servers
dig subdomain.example.com @8.8.8.8
dig subdomain.example.com @1.1.1.1

# Check if domain exists
rb dns record lookup subdomain.example.com
```

## Next Steps

- [Batch Scanning](02-batch.md) - Scan multiple subdomains
- [Configuration](03-configuration.md) - Cloud settings
