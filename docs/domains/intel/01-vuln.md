# intel vuln

> Vulnerability search, CVE lookup, and exploit discovery

## Commands

```
rb intel vuln <verb> [args] [flags]
```

| Verb | Description |
|------|-------------|
| `search` | Search vulnerabilities by technology/version |
| `cve` | Get detailed CVE information |
| `kev` | Query CISA Known Exploited Vulnerabilities |
| `exploit` | Search Exploit-DB for public exploits |
| `cpe` | List CPE mappings for technologies |
| `correlate` | Correlate detected techs with vulnerabilities |
| `scan` | Full vulnerability scan of a target |
| `report` | Generate vulnerability report |

## Usage Examples

### Search by Technology

```bash
# Search NVD for nginx vulnerabilities
rb intel vuln search nginx 1.18.0

# Search OSV for npm package
rb intel vuln search lodash --source osv --ecosystem npm

# Search with API key for higher rate limits
rb intel vuln search apache --api-key YOUR_KEY
```

### CVE Lookup

```bash
# Get CVE details
rb intel vuln cve CVE-2021-44228

# Output as JSON
rb intel vuln cve CVE-2021-44228 --json
```

### CISA KEV Catalog

```bash
# Show KEV statistics
rb intel vuln kev --stats

# Filter by vendor
rb intel vuln kev --vendor Microsoft

# Filter by product
rb intel vuln kev --product "Windows 10"
```

### Exploit Search

```bash
# Search Exploit-DB
rb intel vuln exploit "Apache Struts"

# Search by CVE
rb intel vuln exploit CVE-2017-5638
```

### Full Scan

```bash
# Scan target for vulnerabilities
rb intel vuln scan https://example.com

# Deep scan (all sources)
rb intel vuln scan https://example.com --deep

# Generate report
rb intel vuln report https://example.com --format markdown
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--source` | Vulnerability source (nvd, osv, all) | nvd |
| `--ecosystem` | Package ecosystem for OSV | - |
| `--vendor` | Filter KEV by vendor | - |
| `--product` | Filter KEV by product | - |
| `--limit` | Max results | 20 |
| `--api-key` | NVD API key | - |
| `--deep` | Deep scan (all sources) | false |
| `--json` | JSON output | false |

## Risk Score

redblue calculates a risk score for each vulnerability:

```
Risk = (CVSS × 10) + Exploit Bonus (+25) + KEV Bonus (+30) + Age Factor + Impact
```

| Score | Severity |
|-------|----------|
| 90+ | Critical |
| 70-89 | High |
| 40-69 | Medium |
| 1-39 | Low |
| 0 | None |
