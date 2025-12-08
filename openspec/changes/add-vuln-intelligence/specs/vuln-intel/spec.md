# Capability: Vulnerability Intelligence

Multi-source vulnerability aggregation and correlation with detected technologies.

## ADDED Requirements

### Requirement: Multi-Source Vulnerability Query
The system SHALL query multiple vulnerability databases to provide comprehensive coverage:
- NVD (NIST National Vulnerability Database) - Primary CVE source
- OSV.dev - Open-source package vulnerabilities
- CISA KEV - Known Exploited Vulnerabilities catalog
- Vulners - Aggregator with exploit references
- Exploit-DB - Proof-of-concept exploits
- GitHub Security Advisories (GHSA)

#### Scenario: NVD query by CPE
- **WHEN** querying for `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*`
- **THEN** the system SHALL call NVD REST API
- **AND** parse CVE entries with CVSS scores
- **AND** respect rate limits (5 req/30s public, 50 req/30s with API key)

#### Scenario: OSV query for npm package
- **WHEN** detected technology is "express" version "4.17.1" (npm ecosystem)
- **THEN** the system SHALL query OSV API with package name and version
- **AND** return matching vulnerabilities

#### Scenario: CISA KEV cross-reference
- **WHEN** a CVE is found in CISA KEV catalog
- **THEN** the system SHALL flag `cisa_kev: true`
- **AND** include due date and remediation notes

### Requirement: CPE-Based Vulnerability Matching
The system SHALL use CPE identifiers for accurate vulnerability matching.

#### Scenario: Exact version match
- **WHEN** technology version is "1.18.0"
- **AND** CVE affects versions "1.0.0" to "1.19.0"
- **THEN** the CVE SHALL be included in results

#### Scenario: Version range handling
- **WHEN** NVD specifies `versionStartIncluding: 1.0.0, versionEndExcluding: 1.20.0`
- **AND** detected version is "1.18.0"
- **THEN** the system SHALL correctly match the vulnerability

#### Scenario: No CPE available
- **WHEN** technology has no CPE mapping
- **THEN** the system SHALL fallback to text-based search
- **AND** mark results with lower confidence

### Requirement: Vulnerability Deduplication
The system SHALL deduplicate vulnerabilities across sources using canonical identifiers.

#### Scenario: Same CVE from multiple sources
- **WHEN** NVD returns CVE-2024-1234
- **AND** Vulners also returns CVE-2024-1234
- **THEN** the system SHALL merge into single entry
- **AND** combine references from both sources

#### Scenario: OSV to CVE linking
- **WHEN** OSV entry references a CVE
- **THEN** the system SHALL link them as the same vulnerability
- **AND** use CVE ID as canonical identifier

### Requirement: Exploit Availability Detection
The system SHALL detect and flag vulnerabilities with available exploits.

#### Scenario: Exploit-DB PoC found
- **WHEN** CVE-2024-1234 has an Exploit-DB entry
- **THEN** the system SHALL set `exploit_available: true`
- **AND** include Exploit-DB URL in references

#### Scenario: CISA KEV active exploitation
- **WHEN** vulnerability is in CISA KEV catalog
- **THEN** the system SHALL flag `actively_exploited: true`
- **AND** this SHALL increase risk score significantly

### Requirement: Risk Score Calculation
The system SHALL calculate a composite risk score for prioritization.

#### Scenario: Risk score formula
- **WHEN** calculating risk score
- **THEN** the formula SHALL be:
  ```
  risk_score = (cvss_base * 10)
             + (exploit_available ? 25 : 0)
             + (cisa_kev ? 30 : 0)
             + age_penalty(days_since_publish)
             + impact_modifier
  ```
- **AND** score SHALL range from 0-100

#### Scenario: Critical risk classification
- **WHEN** risk_score >= 80
- **THEN** classify as "CRITICAL"

#### Scenario: High risk classification
- **WHEN** risk_score >= 60 AND < 80
- **THEN** classify as "HIGH"

### Requirement: CLI Commands for Vulnerability Lookup
The system SHALL provide CLI commands for vulnerability queries.

#### Scenario: Direct vulnerability search
- **WHEN** user runs `rb vuln search nginx 1.18.0`
- **THEN** the system SHALL:
  1. Resolve CPE for nginx 1.18.0
  2. Query vulnerability sources
  3. Display matching CVEs with severity

#### Scenario: CVE detail lookup
- **WHEN** user runs `rb vuln cve CVE-2024-1234`
- **THEN** the system SHALL display:
  - Title and description
  - CVSS score and severity
  - Affected versions
  - References and exploit links
  - CISA KEV status

#### Scenario: Fingerprint enrichment
- **WHEN** user runs `rb vuln enrich fingerprint.json`
- **THEN** the system SHALL:
  1. Read detected technologies from JSON
  2. Query vulnerabilities for each technology
  3. Output enriched JSON with vulnerabilities

### Requirement: Integrated Recon Workflow
The system SHALL provide an integrated workflow combining fingerprinting and vulnerability lookup.

#### Scenario: Full vulnerability recon
- **WHEN** user runs `rb recon vuln https://example.com`
- **THEN** the system SHALL:
  1. Fingerprint target technologies
  2. Resolve CPEs for detected tech
  3. Query vulnerability databases
  4. Calculate risk scores
  5. Display prioritized vulnerability list

#### Scenario: Deep scan mode
- **WHEN** user runs `rb recon vuln https://example.com --deep`
- **THEN** the system SHALL additionally:
  - Crawl for more technology clues
  - Query all vulnerability sources (not just top 2)
  - Enumerate CMS plugins and check each

### Requirement: Report Generation
The system SHALL generate reports in multiple formats.

#### Scenario: JSON report
- **WHEN** user runs `rb recon vuln https://example.com -o report.json`
- **THEN** output SHALL be valid JSON with:
  - Target information
  - Detected technologies
  - Vulnerabilities per technology
  - Risk scores

#### Scenario: Markdown report
- **WHEN** user runs `rb recon vuln https://example.com --format markdown`
- **THEN** output SHALL be formatted Markdown with:
  - Executive summary
  - Technology inventory table
  - Vulnerability findings by severity
  - Recommendations

#### Scenario: HTML report
- **WHEN** user runs `rb recon vuln https://example.com --format html`
- **THEN** output SHALL be standalone HTML with:
  - Severity-colored styling
  - Sortable tables
  - Expandable vulnerability details

### Requirement: Caching and Rate Limiting
The system SHALL cache vulnerability data and respect API rate limits.

#### Scenario: Cache hit
- **WHEN** vulnerability data for nginx 1.18.0 was fetched within 24 hours
- **THEN** the system SHALL return cached data without API call

#### Scenario: NVD rate limit handling
- **WHEN** NVD rate limit is reached (429 response)
- **THEN** the system SHALL:
  1. Wait with exponential backoff
  2. Retry the request
  3. Inform user of delay

#### Scenario: Offline mode
- **WHEN** user runs with `--offline` flag
- **THEN** the system SHALL only use cached data
- **AND** warn if cache is stale (>7 days)

### Requirement: Source Filtering
The system SHALL allow users to select which vulnerability sources to query.

#### Scenario: NVD only mode
- **WHEN** user runs `rb vuln search nginx 1.18.0 --sources nvd`
- **THEN** the system SHALL only query NVD

#### Scenario: Exclude source
- **WHEN** user runs `rb vuln search nginx 1.18.0 --exclude-sources vulners`
- **THEN** the system SHALL query all sources except Vulners

### Requirement: Severity Filtering
The system SHALL allow filtering by severity.

#### Scenario: Critical and High only
- **WHEN** user runs `rb vuln search nginx 1.18.0 --min-cvss 7.0`
- **THEN** the system SHALL only return vulnerabilities with CVSS >= 7.0

#### Scenario: Exploits only filter
- **WHEN** user runs `rb vuln search nginx 1.18.0 --exploits-only`
- **THEN** the system SHALL only return vulnerabilities with known exploits
