# Implementation Tasks

## 1. DNS Propagation Check
- [ ] 1.1 Create DNS-over-HTTPS client for multiple providers (Google, Cloudflare, NextDNS)
- [ ] 1.2 Implement `rb dns record propagate <domain>` command
- [ ] 1.3 Add consensus analysis (all agree vs inconsistent)
- [ ] 1.4 Display latency per provider
- [ ] 1.5 Support record types (A, AAAA, MX, TXT, CNAME, NS)

## 2. DNS Email Security Check
- [ ] 2.1 Implement SPF record parser and validator
- [ ] 2.2 Implement DKIM record lookup (with selector)
- [ ] 2.3 Implement DMARC record parser
- [ ] 2.4 Create `rb dns record email <domain>` command
- [ ] 2.5 Add security recommendations for missing/weak records

## 3. RDAP Lookup
- [ ] 3.1 Implement RDAP client (RFC 7480-7484)
- [ ] 3.2 Query bootstrap registry for correct RDAP server
- [ ] 3.3 Create `rb recon domain rdap <domain>` command
- [ ] 3.4 Parse and display registrar, dates, nameservers, status
- [ ] 3.5 Support both domain and IP lookups

## 4. IP Intelligence
- [ ] 4.1 Implement bogon detection (IPv4 and IPv6 private ranges)
- [ ] 4.2 Add optional MaxMind GeoLite2 integration
- [ ] 4.3 Create `rb recon ip intel <ip>` command
- [ ] 4.4 Display: city, region, country, timezone, ASN, bogon status
- [ ] 4.5 Graceful degradation when GeoIP database unavailable

## 5. Security Grader
- [ ] 5.1 Implement comprehensive security headers analysis
- [ ] 5.2 Add CSP parser with directive analysis
- [ ] 5.3 Create scoring algorithm (0-100, A+ to F grade)
- [ ] 5.4 Create `rb web asset grade <url>` command
- [ ] 5.5 Add recommendations for missing/weak headers
- [ ] 5.6 Check: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.

## 6. ICMP Ping
- [ ] 6.1 Implement raw ICMP socket (requires root/capabilities)
- [ ] 6.2 Create `rb network host ping <host>` command (enhance existing)
- [ ] 6.3 Add statistics: min/avg/max/stddev latency
- [ ] 6.4 Support count and interval options
- [ ] 6.5 Fallback to TCP ping when ICMP unavailable

## 7. Shell Session Variables
- [ ] 7.1 Add `variables: HashMap<String, String>` to TuiApp
- [ ] 7.2 Implement `:set <key>=<value>` command
- [ ] 7.3 Implement `:vars` command to list variables
- [ ] 7.4 Implement `:unset <key>` command
- [ ] 7.5 Expand variables in commands with `$key` syntax

## 8. Shell Dynamic Target
- [ ] 8.1 Implement `:target <new_target>` command
- [ ] 8.2 Update session file when target changes
- [ ] 8.3 Reload database for new target
- [ ] 8.4 Update prompt/header to show new target
- [ ] 8.5 Clear cached data when target changes

## 9. Load Testing TUI (Enhancement)
- [ ] 9.1 Create fullscreen dashboard for load testing
- [ ] 9.2 Real-time graphs: RPS, latency, errors
- [ ] 9.3 Live stats: p50, p95, p99 latencies
- [ ] 9.4 Progress bar for duration
- [ ] 9.5 Integrate with existing `rb bench load` command

## 10. Web Scraping & Sourcemaps (Future)
- [ ] 10.1 Implement basic CSS selector engine
- [ ] 10.2 Create `$` command for element selection
- [ ] 10.3 Implement `$text`, `$attr`, `$html` subcommands
- [ ] 10.4 Implement `$links`, `$images`, `$scripts` extractors
- [ ] 10.5 Store scraped document in session for chained queries
- [ ] 10.6 Implement sourcemap extractor (`$sourcemaps`)
- [ ] 10.7 Implement sourcemap decoder (`$unmap`) to reconstruct original source

## Testing
- [ ] T.1 Unit tests for DNS propagation parsing
- [ ] T.2 Unit tests for email security record parsing
- [ ] T.3 Unit tests for RDAP response parsing
- [ ] T.4 Unit tests for bogon detection
- [ ] T.5 Unit tests for security grader scoring
- [ ] T.6 Integration tests for shell commands
