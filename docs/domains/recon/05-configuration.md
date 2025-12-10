# Recon Configuration

Configure reconnaissance behavior via config file, environment variables, or flags.

## Configuration File

```yaml
# .redblue.yaml
recon:
  # Default subdomain wordlist path
  # Default: built-in (~1000 entries)
  subdomain_wordlist: /usr/share/wordlists/subdomains.txt

  # DNS bruteforce threads
  # Range: 1-1000
  # Default: 10
  subdomain_threads: 10

  # Enable passive-only mode by default
  # Default: false
  passive_only: false

  # Auto-save results to database
  # Default: true
  auto_persist: true

  # WHOIS server timeout (seconds)
  # Range: 1-60
  # Default: 10
  whois_timeout: 10

  # URL harvester sources
  url_sources:
    - wayback
    - urlscan
    - otx
    - commoncrawl

  # Years of URL history to search
  # Range: 1-20
  # Default: 5
  url_history_years: 5
```

## Environment Variables

```bash
# Subdomain settings
export REDBLUE_RECON_SUBDOMAIN_THREADS=50
export REDBLUE_RECON_SUBDOMAIN_WORDLIST=/path/to/wordlist.txt

# WHOIS settings
export REDBLUE_RECON_WHOIS_TIMEOUT=15

# Persistence
export REDBLUE_RECON_AUTO_PERSIST=true

# Passive mode
export REDBLUE_RECON_PASSIVE_ONLY=false
```

## Wordlist Configuration

### Built-in Wordlist

The default wordlist contains ~1000 common subdomain names:

```
www
mail
ftp
localhost
webmail
smtp
pop
ns1
ns2
...
```

### Custom Wordlist

```yaml
# .redblue.yaml
recon:
  subdomain_wordlist: /usr/share/wordlists/subdomains-top1million.txt
```

### Recommended Wordlists

| Wordlist | Entries | Use Case |
|----------|---------|----------|
| built-in | ~1000 | Quick scans |
| subdomains-top1million-5000 | 5000 | Standard |
| subdomains-top1million-20000 | 20000 | Thorough |
| subdomains-top1million-110000 | 110000 | Comprehensive |

### Wordlist Sources

```bash
# SecLists
git clone https://github.com/danielmiessler/SecLists
ls SecLists/Discovery/DNS/

# Assetnote
# https://wordlists.assetnote.io/
```

## Thread Configuration

### Subdomain Threads

```yaml
# .redblue.yaml
recon:
  subdomain_threads: 50  # Increase for faster scans
```

### Recommendations

| Network | Threads | Notes |
|---------|---------|-------|
| Local/Lab | 100-500 | Fast, no limits |
| Corporate | 10-50 | Avoid IDS detection |
| Internet | 10-100 | Respect rate limits |
| Bug Bounty | 20-50 | Be polite |

## URL Source Configuration

### Enable/Disable Sources

```yaml
# .redblue.yaml
recon:
  url_sources:
    - wayback      # Internet Archive
    - urlscan      # URLScan.io
    - otx          # AlienVault OTX
    # - commoncrawl  # Disabled (slow)
```

### Source Characteristics

| Source | Speed | Coverage | API Limit |
|--------|-------|----------|-----------|
| Wayback | Fast | Excellent | ~100/min |
| URLScan | Medium | Good | 100/day (free) |
| OTX | Medium | Good | 1000/day |
| CommonCrawl | Slow | Excellent | Varies |

## Persistence Configuration

### Auto-Persist

```yaml
# .redblue.yaml
recon:
  auto_persist: true  # Always save to .rdb files
```

### Database Location

```yaml
# .redblue.yaml
storage:
  data_dir: ~/.redblue/data
  # Results saved as: ~/.redblue/data/example.com.rdb
```

## WHOIS Configuration

### Timeout

```yaml
# .redblue.yaml
recon:
  whois_timeout: 15  # Increase for slow servers
```

### WHOIS Servers

redblue auto-selects WHOIS servers by TLD. Custom servers not yet supported.

## Rate Limiting

### Subdomain Enumeration

```yaml
# .redblue.yaml
recon:
  # Delay between DNS queries (ms)
  dns_delay_ms: 10

  # Max queries per second
  dns_rate_limit: 100
```

### URL Harvesting

```yaml
# .redblue.yaml
recon:
  # Delay between API requests (ms)
  api_delay_ms: 100

  # Respect API rate limits
  respect_rate_limits: true
```

## Profile Examples

### Bug Bounty (Polite)

```yaml
# .redblue.yaml
recon:
  subdomain_threads: 20
  subdomain_wordlist: /path/to/medium-wordlist.txt
  passive_only: false
  auto_persist: true
  whois_timeout: 10
  url_sources:
    - wayback
    - urlscan
  url_history_years: 3
```

### Red Team (Stealth)

```yaml
# .redblue.yaml
recon:
  subdomain_threads: 5
  passive_only: true  # No active DNS queries
  auto_persist: true
  url_sources:
    - wayback
    - otx
  url_history_years: 5
```

### Comprehensive Scan

```yaml
# .redblue.yaml
recon:
  subdomain_threads: 100
  subdomain_wordlist: /path/to/large-wordlist.txt
  passive_only: false
  auto_persist: true
  whois_timeout: 15
  url_sources:
    - wayback
    - urlscan
    - otx
    - commoncrawl
  url_history_years: 10
```

### Lab/CTF (Fast)

```yaml
# .redblue.yaml
recon:
  subdomain_threads: 500
  subdomain_wordlist: /path/to/huge-wordlist.txt
  passive_only: false
  auto_persist: false  # Don't clutter with files
  whois_timeout: 5
```

## Configuration Precedence

Configuration applies in this order (later overrides earlier):

1. Built-in defaults
2. Global config (`~/.config/redblue/config.yaml`)
3. Project config (`./.redblue.yaml`)
4. Environment variables (`REDBLUE_RECON_*`)
5. Command-line flags (`--threads`, `--passive`, etc.)

```bash
# Config sets threads=10
# Environment sets threads=50
# Flag overrides to 100
export REDBLUE_RECON_SUBDOMAIN_THREADS=50
rb recon domain subdomains example.com --threads 100
# Result: threads = 100
```

## Performance Tuning

### For Speed

```yaml
recon:
  subdomain_threads: 200
  passive_only: false
  url_sources:
    - wayback  # Fastest source
  url_history_years: 1
```

### For Coverage

```yaml
recon:
  subdomain_threads: 50
  subdomain_wordlist: /path/to/comprehensive.txt
  passive_only: false
  url_sources:
    - wayback
    - urlscan
    - otx
    - commoncrawl
  url_history_years: 10
```

### For Stealth

```yaml
recon:
  subdomain_threads: 5
  passive_only: true
  dns_delay_ms: 500
```

## Next Steps

- [WHOIS Lookup](/domains/recon/01-whois.md) - Domain registration info
- [Subdomain Enumeration](/domains/recon/02-subdomains.md) - Find subdomains
- [URL Discovery](/domains/recon/03-urls.md) - Historical URLs
- [Data Harvesting](/domains/recon/04-harvest.md) - OSINT collection
