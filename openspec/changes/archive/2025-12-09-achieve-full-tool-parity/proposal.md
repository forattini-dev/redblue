# Change: Achieve Full Tool Parity (v1.0 Release)

## Why

redblue aims to be a **single binary replacement for 30+ security tools**. After comprehensive analysis, we've achieved ~75% of this goal with 15 tools fully replaced and 8 partially implemented. This proposal consolidates all remaining work needed to reach production-ready v1.0 status.

### Current State
- **Fully Working (15)**: nmap, dig, whois, curl, subfinder, amass, sherlock, sslyze, ffuf, gitleaks, HTTP/2 client, SOCKS5 proxy, HTTP CONNECT proxy, basic MITM
- **Partial (8)**: WPScan, testssl.sh, Nikto, Aquatone, mitmproxy, exploit framework
- **Missing (7+)**: OS fingerprinting, full NSE-style scanning, browser exploitation (RBB)

### Key Gaps Identified
1. **CMS Scanning**: WPScan parity incomplete (plugin enum, vuln DB)
2. **TLS Audit**: Code exists but disabled due to compilation errors
3. **Vuln Scanning**: Nikto-style signature scanning partial
4. **MITM Maturity**: CSP/HSTS stripping, streaming injection, WebSocket support
5. **Browser Control**: RBB (RedBlue Browser) C2 framework incomplete
6. **Visualization**: No graph/tree visualization for recon data
7. **OS Fingerprinting**: Nmap-style TCP/IP stack fingerprinting missing

## What Changes

### Phase 1: Core Tool Parity (HIGH PRIORITY)

#### 1.1 CMS Scanning (WPScan/Droopescan Parity)
- Complete WordPress plugin/theme enumeration
- Implement Drupal/Joomla module scanning
- Integrate with vuln intelligence (NVD/WPScan DB)
- Add version detection via changelog/readme parsing

#### 1.2 TLS Audit Completion (testssl.sh Parity)
- Re-enable disabled TLS audit code
- Add Heartbleed, POODLE, BEAST, CRIME, DROWN checks
- Implement certificate chain validation
- Add OCSP stapling verification

#### 1.3 Vuln Scanning (Nikto Parity)
- Implement signature-based vulnerability detection
- Create comprehensive vuln signature database
- Add CGI scanner capabilities
- Integrate with CVE/NVD for real-time lookup

### Phase 2: MITM Engine Hardening

#### 2.1 Header Stripping Engine
- Strip CSP, X-Frame-Options, HSTS headers
- Implement X-XSS-Protection removal
- Add configurable stripping rules

#### 2.2 Advanced Streaming Injection
- Handle chunked transfer encoding
- Implement cross-chunk tag detection
- Reliable `</body>` injection across TCP boundaries
- Proper Content-Length recalculation

#### 2.3 WebSocket Support
- Handle Connection: Upgrade correctly
- Transparent WebSocket proxying
- Optional frame inspection

### Phase 3: RBB (RedBlue Browser) Control Center

#### 3.1 RBB State Management
- Thread-safe zombie (hooked browser) tracking
- Session ID management with heartbeat
- Command queue per zombie

#### 3.2 C2 Endpoints
- `/rbb/register` - Initial hook registration
- `/rbb/poll` - Command polling
- `/rbb/response` - Command output collection

#### 3.3 TUI Integration
- `ViewMode::RBB` tab in shell
- Real-time zombie list with status
- Interactive JS command injection
- Request/response traffic log

### Phase 4: Infrastructure Services

#### 4.1 Built-in HTTP Server
- `rb http serve` command
- Static file hosting from binary
- CORS headers for cross-origin hook loading
- MIME type handling

#### 4.2 Auto-Replication
- Self-binary reading capability
- Transfer strategy selection (SSH/RCE/write access)
- Curl-to-self deployment automation

### Phase 5: Visualization & UX

#### 5.1 ASCII Graph Renderer
- Tree/graph data structure for recon data
- Text-based visualization (domain -> subdomain -> IP -> ASN)
- TUI integration with `ViewMode::Graph`

#### 5.2 Report Generation
- HTML report output
- JSON export for CI/CD integration
- PDF generation (optional)

### Phase 6: Advanced Scanning

#### 6.1 OS Fingerprinting
- TCP/IP stack fingerprinting (TTL, window size, DF bit)
- Nmap-style OS detection signatures
- Service version detection improvements

#### 6.2 Network Discovery
- ARP scanning for local networks
- NetBIOS/SMB enumeration
- mDNS/Bonjour discovery

### Phase 7: Fix Compilation & Technical Debt

#### 7.1 Resolve Build Errors
- Fix `RedBlueConfig.network` field issues
- Fix `Output::raw` function missing
- Re-enable disabled modules (database, monitoring)

#### 7.2 Code Quality
- Add integration tests for all major features
- Improve error handling consistency
- Documentation for all CLI commands

## Impact

### Files Affected (Major)
- `src/modules/proxy/mitm.rs` - MITM engine refactor
- `src/modules/web/cms/` - CMS scanning completion
- `src/modules/tls/` - TLS audit re-enablement
- `src/cli/tui.rs` - RBB dashboard integration
- `src/modules/http_server/` - New module
- `src/modules/exploit/browser/` - RBB C2 completion

### Breaking Changes
- **BREAKING**: MITM proxy API changes for header stripping
- **BREAKING**: Config file format changes for new features

### Dependencies
- No new external dependencies (maintaining zero-dep philosophy)
- May need to expand OpenSSL usage for TLS vuln checks

## Risks

1. **Complexity**: Streaming injection is error-prone; chunked encoding bugs break browsing
2. **Detection**: Aggressive header stripping is noisy to blue teams
3. **Scope Creep**: This is a large proposal; may need phasing
4. **Legal**: Some exploitation features require careful documentation of authorized use only

## Success Criteria

- [ ] All 30+ tools have functional replacements
- [ ] Binary size remains under 5MB
- [ ] Zero external protocol dependencies maintained
- [ ] All features have CLI commands exposed
- [ ] Integration tests pass for core workflows
- [ ] Documentation updated for new features

## Timeline Estimate

- **Phase 1-2**: Core parity + MITM (Foundation)
- **Phase 3-4**: RBB + Infrastructure (C2 capabilities)
- **Phase 5-6**: Visualization + Advanced (Polish)
- **Phase 7**: Technical debt + Release prep

## Related OpenSpecs

### Merged/Archived
- **`enhance-mitm-and-control`**: Archived and merged into this openspec. See `openspec/changes/archive/2025-12-08-enhance-mitm-and-control/`

### Active (Complementary)
- **`add-proxy-mitm-module`**: Infrastructure (Proxy, DNS Server, Certificate Authority) - mostly complete. This openspec builds on top of that foundation.
- **`add-vuln-intelligence`**: Vulnerability intelligence APIs (NVD, OSV, KEV) - complementary to Phase 1.3
- **`add-wordlist-powered-attacks`**: Fuzzing and enumeration wordlists - complementary to Phase 1.1

## References

- Parity matrix: `docs/parity_matrix.md`
- Tool equivalents: `docs/reference/tool-equivalents.md`
