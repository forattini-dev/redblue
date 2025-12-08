# cms-scanning Specification

## Purpose
TBD - created by archiving change add-tool-parity-roadmap. Update Purpose after archive.
## Requirements
### Requirement: CMS Detection and Fingerprinting
The system SHALL detect CMS type and version using multiple detection techniques (meta tags, file hashes, response patterns).

#### Scenario: Detect WordPress
- **WHEN** user runs `rb web asset fingerprint http://example.com`
- **THEN** system probes known WordPress indicators
- **AND** reports "WordPress" with version and confidence score

#### Scenario: Detect multiple CMS types
- **WHEN** scanning a site
- **THEN** system tests for WordPress, Drupal, Joomla, Ghost, Strapi, etc.
- **AND** reports detected CMS with version where determinable

### Requirement: Plugin and Theme Enumeration
The system SHALL enumerate installed plugins and themes for detected CMS platforms.

#### Scenario: Enumerate WordPress plugins
- **WHEN** user runs `rb web asset plugins http://wordpress-site.com`
- **THEN** system checks known plugin paths
- **AND** parses plugin metadata from response
- **AND** reports installed plugins with versions

#### Scenario: Enumerate themes
- **WHEN** user runs `rb web asset themes http://wordpress-site.com`
- **THEN** system detects active and installed themes
- **AND** reports theme names and versions

### Requirement: User Enumeration
The system SHALL enumerate user accounts using multiple techniques (author archives, REST API, login errors).

#### Scenario: Enumerate via REST API
- **WHEN** user runs `rb web asset users http://wordpress-site.com`
- **THEN** system queries `/wp-json/wp/v2/users` endpoint
- **AND** reports discovered usernames and IDs

#### Scenario: Enumerate via author ID brute force
- **WHEN** REST API is disabled
- **THEN** system iterates author IDs via `?author=N`
- **AND** extracts usernames from redirects or content

### Requirement: Vulnerability Test Database
The system SHALL include a database of vulnerability tests covering common web security issues.

#### Scenario: Test for common misconfigurations
- **WHEN** user runs `rb web asset vuln http://example.com`
- **THEN** system tests for exposed admin panels, debug modes, backup files
- **AND** reports findings with severity classification

#### Scenario: Test for known CVEs
- **WHEN** CMS version is detected
- **THEN** system correlates version with known vulnerabilities
- **AND** reports applicable CVEs with references

### Requirement: Evasion Techniques
The system SHALL support multiple evasion techniques for bypassing WAFs and IDS.

#### Scenario: Use encoding evasion
- **WHEN** user runs `rb web asset vuln http://example.com --evasion random-case`
- **THEN** system randomizes URL case
- **AND** attempts to bypass case-sensitive filters

#### Scenario: Use path manipulation
- **WHEN** user runs `rb web asset vuln http://example.com --evasion path-traversal`
- **THEN** system uses `/./../` patterns
- **AND** attempts directory traversal variations

### Requirement: Confidence Scoring
The system SHALL report confidence scores (0-100%) for all detections based on indicator strength.

#### Scenario: High confidence detection
- **WHEN** multiple strong indicators match (meta tag, readme, version file)
- **THEN** system reports 90-100% confidence

#### Scenario: Low confidence detection
- **WHEN** only weak indicators match (similar HTML structure)
- **THEN** system reports 30-60% confidence
- **AND** flags as requiring manual verification

### Requirement: Password Testing
The system SHALL support password testing against CMS login endpoints with rate limiting.

#### Scenario: Test default credentials
- **WHEN** user runs `rb web asset brute http://site.com/wp-login.php --defaults`
- **THEN** system tests common default credentials
- **AND** respects rate limits to avoid lockout
- **AND** reports successful authentications

### Requirement: Security Header Analysis
The system SHALL analyze HTTP security headers and report missing protections.

#### Scenario: Analyze security headers
- **WHEN** user runs `rb web asset headers http://example.com`
- **THEN** system checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **AND** reports missing or misconfigured headers
- **AND** provides remediation recommendations

