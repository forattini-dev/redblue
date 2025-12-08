# Change: Add Vulnerability Intelligence System

## Why

When performing reconnaissance on a target, redblue already fingerprints technologies (via `rb web asset fingerprint`), but this information stops at detection. Security professionals need to know **what vulnerabilities affect those detected technologies**.

Currently users must:
1. Run fingerprinting to detect technologies
2. Manually search NVD, Exploit-DB, etc. for each technology+version
3. Cross-reference and prioritize findings
4. This is slow, error-prone, and misses connections

This change adds an integrated vulnerability intelligence system that:
- Enhances technology fingerprinting to capture precise versions
- Automatically queries vulnerability databases (NVD, OSV, Vulners, CISA KEV)
- Correlates findings with detected tech stack
- Prioritizes by exploitability and severity

## What Changes

### Phase 1: Enhanced Technology Fingerprinting
- **NEW**: Deep version detection for 50+ technologies
- **NEW**: CPE (Common Platform Enumeration) mapping for detected technologies
- **ENHANCED**: Server/proxy/CDN fingerprinting with version extraction
- **NEW**: Framework detection (React, Vue, Angular, Laravel, Django, Rails, etc.)
- **NEW**: Runtime detection (Node.js, PHP, Python, Ruby, Java, .NET versions)
- **NEW**: CMS/plugin version detection (WordPress plugins, Drupal modules)
- **NEW**: JavaScript library detection with version (jQuery, lodash, etc.)
- **NEW**: Output tech stack as structured data (JSON/YAML)

### Phase 2: Vulnerability Intelligence Engine
- **NEW**: Multi-source vulnerability aggregator:
  - NVD (NIST) - Primary CVE source with CPE matching
  - OSV.dev - Open-source package vulnerabilities
  - Vulners - Aggregator with exploit references
  - CISA KEV - Known Exploited Vulnerabilities catalog
  - Exploit-DB - Proof-of-concept exploits
  - GitHub Security Advisories (GHSA)
- **NEW**: CPE resolution and normalization
- **NEW**: Version range matching (semver + vendor-specific)
- **NEW**: Deduplication by CVE/OSV ID
- **NEW**: Exploit availability flagging
- **NEW**: CVSS scoring and severity classification

### Phase 3: Integrated Workflow
- **NEW**: `rb recon vuln <target>` - Full recon + vuln correlation
- **NEW**: `rb vuln search <tech> <version>` - Direct vulnerability lookup
- **NEW**: `rb vuln enrich <fingerprint.json>` - Enrich existing fingerprint
- **NEW**: Risk score calculation based on:
  - CVSS score
  - Exploit availability
  - CISA KEV status
  - Age of vulnerability
  - Vendor patch status
- **NEW**: HTML/JSON/Markdown report generation
- **NEW**: Integration with TUI for interactive exploration

## Impact

### Affected Specs
- `tech-fingerprint` (NEW) - Technology detection capabilities
- `vuln-intel` (NEW) - Vulnerability intelligence system

### Affected Code
- `src/modules/web/fingerprinter.rs` - Enhance version detection
- `src/modules/web/fingerprint.rs` - Add CPE mapping
- `src/modules/recon/` - New vuln-intel module
- `src/protocols/` - NVD, OSV, Vulners API clients
- `src/cli/commands/vuln.rs` - New CLI commands
- `src/cli/commands/recon.rs` - Integrated recon workflow

### Dependencies
- NO new external Rust crates (all HTTP/JSON parsing from scratch)
- External API access: NVD (public), OSV (public), Vulners (API key optional)

### Breaking Changes
- None - all additions are new capabilities
