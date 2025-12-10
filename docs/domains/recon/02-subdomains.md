# Subdomain Enumeration

Discover subdomains using passive and active techniques.

## Quick Start

```bash
# All methods (CT logs + DNS bruteforce)
rb recon domain subdomains example.com

# Passive only (no DNS queries to target)
rb recon domain subdomains example.com --passive

# With custom wordlist
rb recon domain subdomains example.com --wordlist subdomains.txt
```

## Command

### subdomains - Subdomain Discovery

Enumerate subdomains using Certificate Transparency logs and DNS bruteforce.

```bash
rb recon domain subdomains <domain> [flags]
```

## Options

```rust
// Subdomain enumeration options
struct SubdomainOptions {
    // Passive enumeration only (CT logs)
    // Default: false
    passive: bool,

    // Recursive subdomain enumeration
    // Default: false
    recursive: bool,

    // Custom wordlist path for DNS bruteforce
    // Default: built-in (~1000 entries)
    wordlist: Option<String>,

    // Number of concurrent DNS threads
    // Range: 1-1000
    // Default: 10
    threads: u32,

    // Output format
    // Values: "text", "json", "yaml"
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
| `--passive` | `-p` | Passive only (CT logs) | false |
| `--recursive` | `-r` | Recursive enumeration | false |
| `--wordlist` | `-w` | Custom wordlist path | built-in |
| `--threads` | `-t` | Concurrent DNS threads | 10 |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |
| `--no-persist` | | Don't save | - |

## Enumeration Methods

### 1. Certificate Transparency (Passive)

Searches public CT logs for SSL certificates issued to the domain.

| Source | Description |
|--------|-------------|
| crt.sh | Comodo CT log search |
| Censys | Certificate search (planned) |
| Certspotter | CT log aggregator (planned) |

**Advantages:**
- No DNS queries to target
- Stealthy reconnaissance
- Fast results

### 2. DNS Bruteforce (Active)

Tests common subdomain names from wordlist.

| Wordlist | Entries | Speed |
|----------|---------|-------|
| built-in | ~1000 | Fast |
| common | ~5000 | Medium |
| large | ~100000 | Slow |

**Advantages:**
- Finds non-SSL subdomains
- Discovers internal names
- Configurable depth

## Examples

### Passive Enumeration

```bash
# CT logs only - no direct DNS queries
rb recon domain subdomains example.com --passive

# Good for:
# - Initial reconnaissance
# - Stealth requirements
# - Quick results
```

### Active Enumeration

```bash
# CT logs + DNS bruteforce (default)
rb recon domain subdomains example.com

# Increase threads for faster scanning
rb recon domain subdomains example.com --threads 50

# Custom wordlist
rb recon domain subdomains example.com \
  --wordlist /usr/share/wordlists/subdomains-top1million.txt
```

### Recursive Enumeration

```bash
# Find subdomains of subdomains
rb recon domain subdomains example.com --recursive

# Example: finds
# - dev.example.com
# - api.dev.example.com
# - staging.api.dev.example.com
```

### Output Formats

```bash
# Text (default)
rb recon domain subdomains example.com

# JSON for automation
rb recon domain subdomains example.com -o json

# Save to database
rb recon domain subdomains example.com --persist
```

## Output Examples

### Text Output

```
Subdomain Enumeration

  Target Domain: example.com

Discovered Subdomains (15)

  SUBDOMAIN                         IP ADDRESSES         SOURCE
  ─────────────────────────────────────────────────────────────────
  www.example.com                   93.184.216.34        CT_LOGS
  mail.example.com                  93.184.216.35        CT_LOGS
  api.example.com                   93.184.216.36        CT_LOGS
  dev.example.com                   93.184.216.37        DNS_BRUTE
  admin.example.com                 93.184.216.38        DNS_BRUTE
  blog.example.com                  93.184.216.39        CT_LOGS
  shop.example.com                  93.184.216.40        DNS_BRUTE
  staging.example.com               93.184.216.41        DNS_BRUTE
  test.example.com                  93.184.216.42        DNS_BRUTE
  vpn.example.com                   93.184.216.43        CT_LOGS
  portal.example.com                93.184.216.44        DNS_BRUTE
  cdn.example.com                   N/A                  CT_LOGS
  static.example.com                93.184.216.45        DNS_BRUTE
  app.example.com                   93.184.216.46 (+2)   CT_LOGS
  m.example.com                     93.184.216.47        DNS_BRUTE

✓ Found 15 unique subdomains
```

### JSON Output

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
    },
    {
      "subdomain": "dev.example.com",
      "ips": ["93.184.216.37"],
      "source": "DNS_BRUTE"
    }
  ]
}
```

## Subdomain Categories

Common subdomain patterns found:

### Infrastructure

| Pattern | Examples |
|---------|----------|
| Web | www, web, www2 |
| Mail | mail, smtp, imap, pop |
| DNS | ns1, ns2, dns |
| VPN | vpn, remote, gateway |

### Development

| Pattern | Examples |
|---------|----------|
| Staging | staging, stage, stg |
| Development | dev, development, sandbox |
| Testing | test, testing, qa |
| CI/CD | ci, cd, jenkins, gitlab |

### Services

| Pattern | Examples |
|---------|----------|
| API | api, api-v1, api-v2, graphql |
| CDN | cdn, static, assets, media |
| Admin | admin, panel, dashboard |
| Auth | auth, login, sso, oauth |

## Patterns

### Bug Bounty Workflow

```bash
# Step 1: Passive enumeration
rb recon domain subdomains target.com --passive -o json > passive.json

# Step 2: Active with large wordlist
rb recon domain subdomains target.com \
  --wordlist ~/wordlists/dns-large.txt \
  --threads 100 \
  -o json > active.json

# Step 3: Combine and dedupe
cat passive.json active.json | jq -s '.[0].subdomains + .[1].subdomains | unique'
```

### Finding Hidden Services

```bash
# Look for internal/dev subdomains
rb recon domain subdomains target.com -o json | \
  jq '.subdomains[] | select(.subdomain | test("dev|test|staging|internal"))'
```

### IP Range Discovery

```bash
# Extract all IPs for further scanning
rb recon domain subdomains target.com -o json | \
  jq -r '.subdomains[].ips[]' | sort -u

# Feed to port scanner
rb recon domain subdomains target.com -o json | \
  jq -r '.subdomains[].ips[]' | sort -u | \
  xargs -I {} rb network ports scan {} --preset web
```

### Monitoring Changes

```bash
# Save baseline
rb recon domain subdomains target.com -o json > baseline.json

# Later: compare for new subdomains
rb recon domain subdomains target.com -o json > current.json
diff <(jq -r '.subdomains[].subdomain' baseline.json | sort) \
     <(jq -r '.subdomains[].subdomain' current.json | sort)
```

## Performance

### Speed Comparison

| Method | Time (avg domain) | Results |
|--------|------------------|---------|
| Passive only | 5-10 sec | CT certs only |
| Default | 30-60 sec | CT + 1000 words |
| Large wordlist | 5-10 min | CT + 100k words |

### Optimization Tips

```bash
# Fast scan (passive only)
rb recon domain subdomains target.com --passive

# Balanced (default settings)
rb recon domain subdomains target.com

# Thorough (increase threads, large wordlist)
rb recon domain subdomains target.com \
  --threads 100 \
  --wordlist /path/to/large-wordlist.txt
```

## Troubleshooting

### No Results Found

```bash
# 1. Try passive only first
rb recon domain subdomains example.com --passive

# 2. Verify domain exists
rb dns record lookup example.com

# 3. Check if www exists
rb dns record lookup www.example.com
```

### Slow Performance

```bash
# Increase thread count
rb recon domain subdomains example.com --threads 50

# Use smaller wordlist
rb recon domain subdomains example.com --wordlist small.txt
```

### Rate Limiting

```bash
# CT log APIs may rate limit
# Wait and retry, or use passive mode sparingly
rb recon domain subdomains example.com --passive
```

## Next Steps

- [URL Discovery](/domains/recon/03-urls.md) - Historical URLs
- [Data Harvesting](/domains/recon/04-harvest.md) - OSINT collection
- [Configuration](/domains/recon/05-configuration.md) - Recon settings
