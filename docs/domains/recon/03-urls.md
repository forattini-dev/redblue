# Historical URL Discovery

Harvest URLs from web archives and intelligence sources.

## Quick Start

```bash
# Get all historical URLs
rb recon domain urls example.com

# Filter for JavaScript files
rb recon domain urls example.com --extensions js

# Filter for API endpoints
rb recon domain urls example.com --include /api/
```

## Command

### urls - URL Harvesting

Discover historical and current URLs from Wayback Machine, URLScan, and other sources.

```bash
rb recon domain urls <domain> [flags]
```

## Options

```rust
// URL harvesting options
struct UrlHarvestOptions {
    // Include only URLs matching pattern (regex)
    // Default: none
    include: Option<String>,

    // Exclude URLs matching pattern (regex)
    // Default: none
    exclude: Option<String>,

    // Filter by file extensions (comma-separated)
    // Example: "js,php,asp"
    // Default: none
    extensions: Option<String>,

    // Years of history to search
    // Range: 1-20
    // Default: 5
    years: u32,

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
| `--include` | `-i` | Include URLs matching regex | - |
| `--exclude` | `-e` | Exclude URLs matching regex | - |
| `--extensions` | | Filter by extensions | - |
| `--years` | `-y` | Years of history | 5 |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |

## Data Sources

| Source | Description | API |
|--------|-------------|-----|
| Wayback Machine | Internet Archive snapshots | CDX API |
| URLScan.io | Public URL scans | Search API |
| AlienVault OTX | Threat intelligence | URL list API |
| CommonCrawl | Web crawl archives | Index API |

## Examples

### Basic URL Discovery

```bash
# Get all URLs for domain
rb recon domain urls example.com

# Limit to recent history
rb recon domain urls example.com --years 1
```

### Filter by Extension

```bash
# JavaScript files only
rb recon domain urls example.com --extensions js

# PHP and ASP files
rb recon domain urls example.com --extensions php,asp,aspx

# All script files
rb recon domain urls example.com --extensions js,php,asp,aspx,jsp
```

### Pattern Matching

```bash
# API endpoints
rb recon domain urls example.com --include /api/

# Admin pages
rb recon domain urls example.com --include /admin/

# Exclude static assets
rb recon domain urls example.com --exclude '\.(css|png|jpg|gif)$'

# Complex filtering
rb recon domain urls example.com \
  --include /api/ \
  --exclude logout
```

### Output Formats

```bash
# Text (default)
rb recon domain urls example.com

# JSON for parsing
rb recon domain urls example.com -o json

# Pipe to tools
rb recon domain urls example.com -o json | jq '.urls[]'
```

## Output Examples

### Text Output

```
URL Harvester (waybackurls/gau)

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

### JSON Output

```json
{
  "domain": "example.com",
  "total": 1245,
  "sources": {
    "wayback": 842,
    "urlscan": 234,
    "otx": 89,
    "commoncrawl": 80
  },
  "urls": [
    {
      "url": "https://example.com/api/v1/users",
      "source": "wayback",
      "date": "2023-07-18"
    },
    {
      "url": "https://example.com/admin/login",
      "source": "wayback",
      "date": "2023-05-10"
    },
    {
      "url": "https://example.com/assets/main.js",
      "source": "urlscan"
    }
  ]
}
```

### Filtered Output (JS only)

```
URL Harvester (waybackurls/gau)

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

## URL Categories

### High-Value Targets

| Category | Pattern | Why |
|----------|---------|-----|
| API | `/api/`, `/v1/`, `/graphql` | Backend endpoints |
| Admin | `/admin/`, `/panel/`, `/dashboard` | Admin interfaces |
| Auth | `/login`, `/auth/`, `/oauth` | Authentication |
| Config | `.config`, `.env`, `.json` | Configuration files |
| Backup | `.bak`, `.old`, `.backup` | Backup files |

### Code Files

| Extension | Language | Analysis |
|-----------|----------|----------|
| .js | JavaScript | Client logic, API calls |
| .php | PHP | Server endpoints |
| .asp/.aspx | ASP.NET | Server endpoints |
| .jsp | Java | Server endpoints |
| .py | Python | Server endpoints |

### Data Files

| Extension | Type | Risk |
|-----------|------|------|
| .json | Data | API responses, configs |
| .xml | Data | SOAP, configs |
| .sql | Database | DB dumps |
| .csv | Data | Data exports |
| .xlsx | Spreadsheet | Data exports |

## Patterns

### Bug Bounty Recon

```bash
# Step 1: Get all JavaScript for code analysis
rb recon domain urls target.com --extensions js -o json > js_files.json

# Step 2: Get API endpoints
rb recon domain urls target.com --include /api/ -o json > api_endpoints.json

# Step 3: Find potential admin panels
rb recon domain urls target.com --include 'admin|panel|dashboard' -o json > admin.json

# Step 4: Look for sensitive files
rb recon domain urls target.com --extensions config,env,json,xml,sql,bak
```

### Parameter Discovery

```bash
# Find URLs with query parameters
rb recon domain urls target.com -o json | \
  jq -r '.urls[].url' | grep '?' | sort -u

# Extract parameter names
rb recon domain urls target.com -o json | \
  jq -r '.urls[].url' | grep -oP '\?[^#]+' | \
  tr '&' '\n' | cut -d= -f1 | sort -u
```

### Endpoint Mapping

```bash
# Extract unique paths
rb recon domain urls target.com -o json | \
  jq -r '.urls[].url' | \
  sed 's/\?.*//g' | \
  sort -u

# Find versioned APIs
rb recon domain urls target.com --include '/v[0-9]/' -o json
```

### Historical Comparison

```bash
# Find URLs that may no longer exist
rb recon domain urls target.com -o json | \
  jq -r '.urls[] | select(.source == "wayback") | .url' | \
  while read url; do
    curl -s -o /dev/null -w "%{http_code} $url\n" "$url"
  done
```

## Performance

### API Limits

| Source | Rate Limit | Notes |
|--------|-----------|-------|
| Wayback | ~100/min | CDX API |
| URLScan | 100/day (free) | API key available |
| OTX | 1000/day | Free tier |
| CommonCrawl | Varies | Large datasets |

### Optimization

```bash
# For large domains, filter early
rb recon domain urls big-site.com --extensions js,php

# Limit history for faster results
rb recon domain urls big-site.com --years 1

# Use JSON and process locally
rb recon domain urls big-site.com -o json > urls.json
cat urls.json | jq '.urls[] | select(.url | contains("/api/"))'
```

## Troubleshooting

### Few URLs Found

```bash
# Some domains may have limited archive coverage
# Try checking Wayback directly:
# https://web.archive.org/web/*/example.com/*

# Very new domains won't have much history
# Check when domain was created
rb recon domain whois example.com -o json | jq '.creation_date'
```

### Slow Results

```bash
# Limit sources by using extensions filter
rb recon domain urls example.com --extensions js

# Reduce years of history
rb recon domain urls example.com --years 1
```

### Rate Limited

```bash
# Wait and retry
# APIs have daily/hourly limits
# Try again after some time
```

## Next Steps

- [Data Harvesting](/domains/recon/04-harvest.md) - OSINT collection
- [WHOIS Lookup](/domains/recon/01-whois.md) - Domain info
- [Configuration](/domains/recon/05-configuration.md) - Recon settings
