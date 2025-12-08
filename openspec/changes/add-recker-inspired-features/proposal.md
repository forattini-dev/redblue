# Change: Add recker-inspired Features

## Why

The recker HTTP client has several powerful features for network reconnaissance and security auditing that would greatly enhance redblue's capabilities. These features are commonly needed during penetration testing and security assessments, and implementing them would make redblue a more complete replacement for multiple security tools.

## What Changes

### DNS Domain
- **DNS Propagation Check**: Query multiple global DNS providers (Google, Cloudflare, NextDNS) to verify DNS propagation status
- **DNS Email Security**: Validate SPF, DKIM, and DMARC records for email security auditing

### Recon Domain
- **RDAP Lookup**: Modern replacement for WHOIS using JSON API (RFC 7480-7484)
- **IP Intelligence**: GeoIP location, ASN lookup, bogon detection, timezone

### Web Domain
- **Security Grader**: Comprehensive security headers analysis with A-F scoring and CSP deep analysis

### Network Domain
- **ICMP Ping**: Basic ping with statistics (min/avg/max/stddev)

### Shell (TUI)
- **Session Variables**: `set`/`vars` commands to store variables between commands
- **Dynamic Target**: `:target` command to change target without restarting

### Bench Domain (Enhancement)
- **Load Testing TUI**: Enhanced dashboard for load testing visualization

### Future (Web Scraping)
- **CSS Selectors**: jQuery-style `$` commands for DOM manipulation
- **Sourcemap Extractor**: Extract and decode JavaScript sourcemaps

## Impact

- Affected specs: dns, network, web, recon, shell, bench
- Affected code:
  - `src/cli/commands/dns.rs` - DNS propagation and email checks
  - `src/cli/commands/recon.rs` - RDAP and IP intelligence
  - `src/cli/commands/web.rs` - Security grader
  - `src/cli/commands/network.rs` - ICMP ping (new)
  - `src/cli/tui.rs` - Session variables and dynamic target
  - `src/protocols/rdap.rs` - New RDAP protocol implementation
  - `src/protocols/icmp.rs` - ICMP protocol implementation
  - `src/modules/network/geoip.rs` - GeoIP database integration

## Priority Order

1. DNS Propagation (high value, medium effort)
2. DNS Email Security (high value, medium effort)
3. RDAP (medium value, low effort)
4. IP Intelligence (high value, medium effort)
5. Security Grader A-F (high value, medium effort)
6. ICMP Ping (medium value, low effort)
7. Session Variables (high value, low effort)
8. Dynamic Target (high value, low effort)
9. Load Testing TUI (high value, high effort)
10. Web Scraping (medium value, high effort)

## Dependencies

- MaxMind GeoLite2 database for IP Intelligence (optional, graceful degradation)
- No external crates - all implementations from scratch using Rust std
