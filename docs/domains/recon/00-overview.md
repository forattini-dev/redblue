# Recon Domain

Information gathering, OSINT, and domain intelligence.

> **Reconnaissance is 90% of a successful pentest.** The more information you gather, the better your attack strategy.

## Quick Start

```bash
# WHOIS lookup
rb recon domain whois google.com

# Subdomain enumeration
rb recon domain subdomains example.com

# Historical URLs
rb recon domain urls example.com

# OSINT harvest
rb recon domain harvest example.com

# Full recon workflow
rb recon domain whois target.com --persist
rb recon domain subdomains target.com --persist
rb recon domain harvest target.com --persist
rb recon domain urls target.com --persist
```

## Resources

| Resource | Description |
|----------|-------------|
| [domain](01-whois.md) | WHOIS, subdomains, URLs, OSINT |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| whois | `rb recon domain whois` |
| amass | `rb recon domain subdomains` |
| subfinder | `rb recon domain subdomains --passive` |
| theHarvester | `rb recon domain harvest` |
| waybackurls | `rb recon domain urls` |
| gau | `rb recon domain urls` |

## Command Matrix

```
rb recon <verb> <resource> [target] [flags]
         │      │
         │      └── domain
         └───────── whois, subdomains, harvest, urls
```

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| WHOIS | ✅ Done | Multi-TLD support |
| Subdomains | ✅ Done | CT logs + bruteforce |
| URLs | ✅ Done | Wayback, URLScan, OTX |
| Harvest | ✅ Done | Emails, IPs, URLs |
| Username OSINT | ⏳ Planned | Phase 3 |
| Email Recon | ⏳ Planned | Phase 3 |

## Strategic Value

| Data | Pentest Value |
|------|---------------|
| WHOIS | Find related domains, hosting patterns |
| Subdomains | Discover dev/staging, admin panels, APIs |
| URLs | Find old endpoints, backup files, configs |
| Emails | Username patterns, phishing targets |
| IPs | Infrastructure mapping, network scanning |

## Next Steps

- [Recon Workflow](06-workflow.md) - Complete pentest methodology
- [High-Value Targets](07-targets.md) - What to look for
- [Tech Fingerprinting](08-fingerprinting.md) - Technologies & versions → CVEs
- [WHOIS Lookup](01-whois.md) - Domain registration info
- [Subdomain Enumeration](02-subdomains.md) - Find subdomains
- [URL Discovery](03-urls.md) - Historical URLs
- [Data Harvesting](04-harvest.md) - OSINT collection
- [Configuration](05-configuration.md) - Recon settings
