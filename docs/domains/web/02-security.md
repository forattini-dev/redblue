# Security Headers Audit

Analyze HTTP security headers and identify misconfigurations.

## Quick Start

```bash
# Full security audit
rb web security asset http://example.com

# JSON output for automation
rb web security asset http://example.com -o json
```

## Command

### security - Security Headers Audit

Analyze security headers and provide recommendations.

```bash
rb web security asset <url> [flags]
```

## Options

```rust
// Security audit options
struct SecurityAuditOptions {
    // Request timeout in seconds
    // Default: 10
    timeout_secs: u32,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,

    // Show recommendations
    // Default: true
    show_recommendations: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--timeout` | `-t` | Request timeout (secs) | 10 |
| `--output` | `-o` | Output format | text |
| `--no-recommendations` | | Hide recommendations | false |

## Security Headers Checked

| Header | Purpose | Risk if Missing |
|--------|---------|-----------------|
| `Strict-Transport-Security` | Force HTTPS | MITM attacks |
| `Content-Security-Policy` | XSS prevention | XSS attacks |
| `X-Content-Type-Options` | MIME sniffing | Content injection |
| `X-Frame-Options` | Clickjacking | UI redressing |
| `X-XSS-Protection` | XSS filter | Reflected XSS |
| `Referrer-Policy` | Referrer leakage | Information disclosure |
| `Permissions-Policy` | Feature control | Privacy leaks |
| `Cache-Control` | Caching rules | Sensitive data exposure |

## Examples

### Basic Audit

```bash
rb web security asset http://example.com
```

### JSON Output

```bash
# For automation/parsing
rb web security asset http://example.com -o json

# Parse specific results
rb web security asset http://example.com -o json | jq '.missing_headers'
```

### Multiple Sites

```bash
# Audit multiple sites
for site in example.com google.com github.com; do
  echo "=== $site ==="
  rb web security asset https://$site
done
```

## Output Examples

### Text Output

```
Security Headers Audit: https://example.com

Status: 200 OK
Score: 65/100

PRESENT HEADERS
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin

MISSING HEADERS
  Content-Security-Policy
    Risk: HIGH - Vulnerable to XSS attacks
    Recommendation: Add CSP header with strict policy

  Permissions-Policy
    Risk: LOW - Browser features not restricted
    Recommendation: Add Permissions-Policy header

  X-XSS-Protection
    Risk: LOW - Legacy header but still useful
    Recommendation: Add "X-XSS-Protection: 1; mode=block"

SUMMARY
  Present: 4/8 (50%)
  Missing: 4/8 (50%)
  Grade: C
```

### JSON Output

```json
{
  "url": "https://example.com",
  "status": 200,
  "score": 65,
  "grade": "C",
  "present_headers": {
    "strict-transport-security": {
      "value": "max-age=31536000; includeSubDomains",
      "valid": true,
      "notes": "Good: includes subdomains"
    },
    "x-content-type-options": {
      "value": "nosniff",
      "valid": true
    },
    "x-frame-options": {
      "value": "DENY",
      "valid": true
    }
  },
  "missing_headers": [
    {
      "name": "content-security-policy",
      "risk": "high",
      "recommendation": "Add CSP header with strict policy"
    },
    {
      "name": "permissions-policy",
      "risk": "low",
      "recommendation": "Add Permissions-Policy header"
    }
  ]
}
```

## Security Grades

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Excellent - All headers present and configured correctly |
| A | 85-94 | Very Good - Minor improvements possible |
| B | 70-84 | Good - Some headers missing |
| C | 55-69 | Fair - Several important headers missing |
| D | 40-54 | Poor - Many headers missing |
| F | 0-39 | Critical - Major security issues |

## Header Details

### Strict-Transport-Security (HSTS)

```
Good:
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Bad:
  Strict-Transport-Security: max-age=300
  (too short, should be at least 1 year)
```

### Content-Security-Policy (CSP)

```
Good:
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

Bad:
  Content-Security-Policy: default-src *
  (too permissive)
```

### X-Frame-Options

```
Good values:
  X-Frame-Options: DENY
  X-Frame-Options: SAMEORIGIN

Bad:
  X-Frame-Options: ALLOW-FROM http://example.com
  (deprecated, use CSP frame-ancestors instead)
```

### X-Content-Type-Options

```
Correct:
  X-Content-Type-Options: nosniff

Purpose: Prevents MIME-type sniffing
```

## Patterns

### Security Baseline Check

```bash
# Quick check for critical headers
rb web security asset https://example.com -o json | \
  jq '.missing_headers[] | select(.risk == "high") | .name'
```

### Compare Before/After

```bash
# Before changes
rb web security asset https://example.com -o json > before.json

# After security improvements
rb web security asset https://example.com -o json > after.json

# Compare scores
echo "Before: $(jq '.score' before.json)"
echo "After: $(jq '.score' after.json)"
```

### CI/CD Integration

```bash
# Fail if score below threshold
SCORE=$(rb web security asset https://example.com -o json | jq '.score')
if [ "$SCORE" -lt 70 ]; then
  echo "Security score too low: $SCORE"
  exit 1
fi
```

## Next Steps

- [HTTP Requests](/domains/web/01-requests.md) - Make HTTP requests
- [CMS Scanning](/domains/web/03-cms.md) - Detect and scan CMS
- [Configuration](/domains/web/04-configuration.md) - HTTP settings
