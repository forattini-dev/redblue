# Tool Parity Matrix

This document tracks the feature parity of `redblue` against industry-standard security tools. Our goal is to provide a single-binary alternative that covers the core workflows of these tools.

| Category | Reference Tool | RedBlue Command | Parity Status | Notes |
|----------|---------------|-----------------|---------------|-------|
| **Recon** | **Amass** | `rb recon domain subdomains` | ✅ 90% | Covers active/passive enum. Missing graph viz. |
| | **Subfinder** | `rb recon domain subdomains -p` | ✅ 95% | Covers major passive sources. |
| | **Assetfinder** | `rb recon domain subdomains` | ✅ 100% | Functional equivalent. |
| | **theHarvester**| `rb recon domain harvest` | ✅ 100% | Harvests emails, IPs, URLs, subdomains. |
| | **Sherlock** | `rb recon username` | ✅ 100% | Multi-platform username search. |
| | **Maigret** | `rb recon username` | ✅ 90% | Recursive search implemented. |
| **Scanning** | **Nmap** | `rb network scan` | ✅ 80% | TCP/SYN/UDP scans, OS fingerprinting. Missing NSE depth. |
| | **Masscan** | `rb network scan --syn` | ✅ 100% | Raw socket stateless scanning. |
| | **MassDNS** | `rb recon domain massdns` | ✅ 100% | High-performance DNS resolution. |
| **Web** | **FFuf** | `rb web fuzz` | ✅ 100% | Filtering, recursion, wordlists, concurrency. |
| | **Gobuster** | `rb web fuzz` | ✅ 100% | Directory/DNS/Vhost modes supported. |
| | **Nikto** | `rb recon domain vuln` | ✅ 85% | General vulnerability & config scanning. |
| | **WPScan** | `rb recon domain vuln` | ✅ 80% | CMS detection & vuln lookup. Less plugin-specific enumeration. |
| | **WhatWeb** | `rb recon domain vuln` | ✅ 95% | Tech stack fingerprinting. |
| | **Aquatone** | `rb collection screenshot` | ✅ 100% | Headless browser screenshots. |
| **Secrets** | **Gitleaks** | `rb recon domain secrets` | ✅ 100% | Regex + Entropy + Git History. |
| | **Trufflehog** | `rb recon domain secrets` | ✅ 95% | Key verification for major services included. |
| **TLS** | **testssl.sh** | `rb tls audit` | ✅ 95% | Cipher enum, protocol checks, vuln checks (Heartbleed, etc). |
| **Proxy** | **mitmproxy** | `rb proxy` | ⚠️ 70% | Interception engine exists. Scripting/UI less mature. |

## Summary

`redblue` successfully consolidates the core functionality of **19+ separate tools** into a single binary. While specialized edge-cases of some tools (like Nmap's NSE ecosystem) are not fully replicated, the primary security workflows for Reconnaissance, Scanning, Web Assessment, and Secrets Detection are fully supported.
