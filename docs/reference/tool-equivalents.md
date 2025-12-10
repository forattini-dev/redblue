# Tool Equivalents

redblue consolidates functionality from 30+ security tools into a single binary.

## Implemented

| Traditional Tool | redblue Command | Status |
|-----------------|-----------------|--------|
| **nmap** | `rb network scan ports` | Complete |
| **masscan** | `rb network scan ports --fast` | Partial |
| **traceroute** | `rb network run trace` | Complete |
| **mtr** | `rb network mtr trace` | Complete |
| **fping** | `rb network ping host` | Complete |
| **netdiscover** | `rb network discover host` | Complete |
| **dig** | `rb dns lookup record` | Complete |
| **nslookup** | `rb dns resolve record` | Complete |
| **whois** | `rb recon whois domain` | Complete |
| **amass** | `rb recon subdomains domain` | Complete |
| **subfinder** | `rb recon subdomains domain --passive` | Complete |
| **theHarvester** | `rb recon harvest domain` | Complete |
| **waybackurls** | `rb recon urls domain` | Complete |
| **gau** | `rb recon urls domain` | Complete |
| **curl** | `rb web get asset` | Complete |
| **wpscan** | `rb web cms-scan asset --strategy wordpress` | Complete |
| **droopescan** | `rb web cms-scan asset --strategy drupal` | Complete |
| **sslyze** | `rb tls audit security` | Complete |
| **testssl.sh** | `rb tls vuln security` | Complete |
| **sslscan** | `rb tls ciphers security` | Complete |
| **tko-subs** | `rb cloud takeover asset` | Complete |
| **subjack** | `rb cloud takeover-scan asset` | Complete |
| **LinPEAS** | `rb exploit privesc payload` | Partial |
| **WinPEAS** | `rb exploit privesc payload --os windows` | Partial |

## In Progress

| Tool | Command | Status |
|------|---------|--------|
| **openssl** | `rb web cert asset` | Temporary external call |
| **aquatone** | `rb collection capture screenshot` | Planned |

## Roadmap

| Tool | Command | Phase |
|------|---------|-------|
| **ffuf** | `rb web fuzz asset` | Phase 3 |
| **feroxbuster** | `rb web fuzz asset --recursive` | Phase 3 |
| **gobuster** | `rb web fuzz asset --wordlist` | Phase 3 |
| **nikto** | `rb web vuln-scan asset` | Phase 3 |
| **gitleaks** | `rb code scan secrets` | Phase 4 |
| **trufflehog** | `rb code scan secrets --deep` | Phase 4 |

## Summary

- **23 tools** fully implemented
- **2 tools** in progress
- **7 tools** planned

**Total binary size:** 2.7MB (vs 500+ MB for all tools combined)
