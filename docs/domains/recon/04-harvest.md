# OSINT Data Harvesting

Collect intelligence from multiple sources - emails, subdomains, IPs, URLs.

## Quick Start

```bash
# Basic OSINT harvesting
rb recon domain harvest example.com

# JSON output
rb recon domain harvest example.com -o json

# Save to database
rb recon domain harvest example.com --persist
```

## Command

### harvest - OSINT Collection

Harvest data from search engines, public databases, and web scraping.

```bash
rb recon domain harvest <domain> [flags]
```

## Options

```rust
// OSINT harvest options
struct HarvestOptions {
    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,

    // Save results to database
    // Default: false
    persist: bool,

    // Enable verbose output
    // Default: false
    verbose: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |
| `--verbose` | `-v` | Verbose output | false |

## Data Sources

### Search Engines

| Source | Data Type |
|--------|-----------|
| Google | Emails, documents |
| Bing | Subdomains, URLs |
| DuckDuckGo | Privacy-focused queries |

### Public Databases

| Source | Data Type |
|--------|-----------|
| Certificate Transparency | Subdomains |
| DNS Records | MX, TXT, SPF |
| WHOIS | Registrant info |

### Web Scraping

| Source | Data Type |
|--------|-----------|
| Company website | Emails, contacts |
| Contact pages | Staff emails |
| About pages | Company info |

## What It Finds

| Category | Examples |
|----------|----------|
| Emails | info@, support@, admin@ |
| Subdomains | www, mail, api, dev |
| IP Addresses | Server IPs, ranges |
| URLs | Endpoints, pages |

## Examples

### Basic Harvesting

```bash
# Full OSINT harvest
rb recon domain harvest example.com

# With persistence
rb recon domain harvest example.com --persist
```

### Output Formats

```bash
# Text output (default)
rb recon domain harvest example.com

# JSON for automation
rb recon domain harvest example.com -o json

# Pipe to jq
rb recon domain harvest example.com -o json | jq '.emails'
```

### Verbose Mode

```bash
# See source details
rb recon domain harvest example.com --verbose
```

## Output Examples

### Text Output

```
OSINT Data Harvesting (theHarvester)

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

### JSON Output

```json
{
  "domain": "example.com",
  "emails": [
    "info@example.com",
    "support@example.com",
    "contact@example.com",
    "sales@example.com",
    "admin@example.com",
    "webmaster@example.com",
    "security@example.com"
  ],
  "subdomains": [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "dev.example.com",
    "staging.example.com"
  ],
  "ips": [
    "93.184.216.34",
    "93.184.216.35",
    "93.184.216.36"
  ],
  "urls": [
    "https://example.com/",
    "https://www.example.com/about",
    "https://example.com/contact"
  ],
  "total_items": 86
}
```

## Email Patterns

### Common Formats

| Format | Example |
|--------|---------|
| first.last | john.doe@example.com |
| firstlast | johndoe@example.com |
| first | john@example.com |
| flast | jdoe@example.com |
| first_last | john_doe@example.com |

### Role Addresses

| Role | Purpose |
|------|---------|
| info@ | General inquiries |
| support@ | Customer support |
| sales@ | Sales team |
| admin@ | Administration |
| security@ | Security team |
| abuse@ | Abuse reports |
| webmaster@ | Website admin |
| postmaster@ | Mail admin |

## Patterns

### Full Recon Pipeline

```bash
# Step 1: WHOIS for registration info
rb recon domain whois target.com --persist

# Step 2: Harvest all OSINT data
rb recon domain harvest target.com --persist

# Step 3: Enumerate subdomains
rb recon domain subdomains target.com --persist

# Step 4: Get historical URLs
rb recon domain urls target.com --persist

# Step 5: Query all findings
rb database data query target.com.rdb
```

### Email Extraction

```bash
# Extract just emails
rb recon domain harvest target.com -o json | jq -r '.emails[]'

# Save to file
rb recon domain harvest target.com -o json | \
  jq -r '.emails[]' > emails.txt

# Count emails
rb recon domain harvest target.com -o json | \
  jq '.emails | length'
```

### Subdomain Integration

```bash
# Get subdomains from harvest
rb recon domain harvest target.com -o json | jq -r '.subdomains[]'

# Compare with dedicated subdomain scan
diff \
  <(rb recon domain harvest target.com -o json | jq -r '.subdomains[]' | sort) \
  <(rb recon domain subdomains target.com -o json | jq -r '.subdomains[].subdomain' | sort)
```

### IP Range Discovery

```bash
# Extract IPs for network scanning
rb recon domain harvest target.com -o json | \
  jq -r '.ips[]' | \
  xargs -I {} rb network ports scan {} --preset common
```

## Comparison with Tools

| Feature | theHarvester | redblue harvest |
|---------|--------------|-----------------|
| Email discovery | ✅ | ✅ |
| Subdomain discovery | ✅ | ✅ |
| IP discovery | ✅ | ✅ |
| URL discovery | ❌ | ✅ |
| Persistence | ❌ | ✅ (.rdb) |
| Single binary | ❌ | ✅ |

## Troubleshooting

### Few Results

```bash
# Some domains have limited public exposure
# Try verbose mode to see which sources returned data
rb recon domain harvest example.com --verbose

# Combine with other recon commands
rb recon domain subdomains example.com
rb recon domain urls example.com
```

### Rate Limited

```bash
# Search engines may rate limit
# Wait between scans
# Results are cached in .rdb files
```

### No Emails Found

```bash
# Not all domains expose emails publicly
# Check MX records for mail server info
rb dns record lookup example.com --type MX

# Try common patterns manually
# info@, support@, admin@, etc.
```

## Next Steps

- [WHOIS Lookup](/domains/recon/01-whois.md) - Domain registration info
- [Subdomain Enumeration](/domains/recon/02-subdomains.md) - Find subdomains
- [URL Discovery](/domains/recon/03-urls.md) - Historical URLs
- [Configuration](/domains/recon/05-configuration.md) - Recon settings
