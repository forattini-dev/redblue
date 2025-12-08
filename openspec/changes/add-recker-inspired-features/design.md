# Design: recker-inspired Features

## Context

redblue aims to be a complete replacement for 30+ security tools. The recker HTTP client has several features that complement redblue's existing capabilities, particularly in DNS analysis, IP intelligence, and security auditing.

**Constraints:**
- ZERO external crates for protocol implementations
- All protocols implemented from scratch using Rust std
- Optional external data (GeoIP) with graceful degradation

## Goals / Non-Goals

### Goals
- Add DNS propagation and email security checks
- Implement RDAP as modern WHOIS alternative
- Add IP intelligence with bogon detection
- Implement security headers grading (A-F)
- Enhance shell with variables and dynamic target

### Non-Goals
- Full AI integration (out of scope for now)
- GraphQL/gRPC support
- HAR recording/playback
- Browser automation

## Decisions

### Decision 1: DNS-over-HTTPS for Propagation
**What:** Use DNS-over-HTTPS (DoH) to query multiple providers
**Why:**
- Works through firewalls (HTTPS port 443)
- JSON response format easy to parse
- No raw UDP socket requirements
- Existing HTTP client can be reused

**Providers:**
- Google DNS: `https://dns.google/resolve`
- Cloudflare: `https://cloudflare-dns.com/dns-query`
- NextDNS: `https://dns.nextdns.io/dns-query`

### Decision 2: RDAP Bootstrap
**What:** Query IANA bootstrap registry first to find correct RDAP server
**Why:**
- RDAP servers vary by TLD/RIR
- Bootstrap provides authoritative server list
- Follows RFC 7484 specification

**Bootstrap URLs:**
- Domain: `https://data.iana.org/rdap/dns.json`
- IPv4: `https://data.iana.org/rdap/ipv4.json`
- IPv6: `https://data.iana.org/rdap/ipv6.json`

### Decision 3: Bogon Detection Without External Data
**What:** Implement bogon detection using hardcoded RFC ranges
**Why:**
- No external dependencies required
- Covers all IANA-reserved ranges
- Instant lookup (no network call)

**IPv4 Bogon Ranges:**
- 0.0.0.0/8 (This Network)
- 10.0.0.0/8 (Private-Use RFC 1918)
- 100.64.0.0/10 (Carrier-Grade NAT)
- 127.0.0.0/8 (Loopback)
- 169.254.0.0/16 (Link-Local)
- 172.16.0.0/12 (Private-Use RFC 1918)
- 192.0.0.0/24 (IETF Protocol)
- 192.0.2.0/24 (TEST-NET-1)
- 192.168.0.0/16 (Private-Use RFC 1918)
- 224.0.0.0/4 (Multicast)
- 240.0.0.0/4 (Reserved)

### Decision 4: Optional GeoIP Integration
**What:** Support MaxMind GeoLite2 database if available
**Why:**
- Rich geolocation data
- Industry standard
- Free tier available
- Graceful degradation when missing

**Implementation:**
- Check for database at `~/.local/share/redblue/GeoLite2-City.mmdb`
- Parse MMDB format natively (no external crate)
- Fall back to bogon-only mode if missing

### Decision 5: Security Grader Scoring Algorithm
**What:** Score 0-100 with letter grades A+ to F
**Scoring:**
```
Base Score: 100

Deductions:
- Missing HSTS: -20
- Missing CSP: -15
- Missing X-Frame-Options: -10
- Missing X-Content-Type-Options: -5
- CSP with 'unsafe-inline': -10
- CSP with 'unsafe-eval': -10
- CSP with *: -5
- HSTS max-age < 1 year: -5

Grades:
- A+ : 100
- A  : 90-99
- B  : 80-89
- C  : 70-79
- D  : 60-69
- F  : < 60
```

### Decision 6: ICMP Ping with TCP Fallback
**What:** Use raw ICMP sockets when available, fall back to TCP
**Why:**
- ICMP requires root/CAP_NET_RAW
- TCP ping works without privileges
- Provides similar RTT information

**Implementation:**
1. Try raw ICMP socket
2. If EPERM, fall back to TCP connect to port 80/443
3. Measure connection time as "ping"

### Decision 7: Shell Variables in Memory Only
**What:** Store variables in HashMap, don't persist to disk
**Why:**
- Simple implementation
- No security concerns (tokens not saved)
- Session-scoped by design
- Consistent with recker behavior

## Risks / Trade-offs

| Risk | Impact | Mitigation |
|------|--------|------------|
| GeoIP database large (~70MB) | Disk space | Optional download, lazy loading |
| ICMP requires root | Limited functionality | TCP fallback |
| DoH providers may block | Incomplete propagation check | Multiple providers, graceful degradation |
| MMDB parsing complex | Development time | Start with bogon-only, add MMDB later |

## Migration Plan

1. **Phase 1**: DNS propagation + email security (no breaking changes)
2. **Phase 2**: RDAP + IP intelligence (no breaking changes)
3. **Phase 3**: Security grader (no breaking changes)
4. **Phase 4**: Shell enhancements (no breaking changes)

No breaking changes - all features are additive.

## Open Questions

1. Should GeoIP database be auto-downloaded or manual install?
   - **Recommendation**: Manual install with `rb setup geoip` command

2. Should shell variables support JSON values?
   - **Recommendation**: Start with strings only, expand later if needed

3. Should security grader support custom scoring profiles?
   - **Recommendation**: Start with fixed scoring, add profiles later
