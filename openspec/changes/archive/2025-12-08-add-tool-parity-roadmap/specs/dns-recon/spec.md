## ADDED Requirements

### Requirement: Passive Source Integration
The system SHALL integrate 30+ passive subdomain sources including Shodan, Censys, SecurityTrails, VirusTotal, Chaos, FOFA, ZoomEye, PassiveTotal, AlienVault OTX, GitHub, GitLab, and Hunter.io.

#### Scenario: Query multiple sources
- **WHEN** user runs `rb recon domain subdomains example.com --all-sources`
- **THEN** system queries all configured passive sources
- **AND** aggregates and deduplicates results
- **AND** reports source attribution for each subdomain

#### Scenario: Query specific source
- **WHEN** user runs `rb recon domain subdomains example.com --source shodan`
- **THEN** system queries only Shodan API
- **AND** returns subdomains found in Shodan

### Requirement: API Key Configuration
The system SHALL support YAML configuration files for API keys and source-specific settings.

#### Scenario: Load API keys from config
- **WHEN** user has `~/.config/redblue/sources.yaml` with API keys
- **THEN** system loads credentials on startup
- **AND** uses keys for authenticated API requests

#### Scenario: Environment variable fallback
- **WHEN** user sets `SHODAN_API_KEY` environment variable
- **THEN** system uses this key for Shodan queries
- **AND** env vars take precedence over config file

### Requirement: Rate Limiting
The system SHALL implement per-source rate limiting to avoid API bans and detection.

#### Scenario: Respect source rate limits
- **WHEN** user queries SecurityTrails (limit: 10/min)
- **THEN** system throttles requests to stay under limit
- **AND** displays rate limit status in verbose mode

### Requirement: Wildcard Detection
The system SHALL detect and filter wildcard DNS records to reduce false positives.

#### Scenario: Wildcard filtering
- **WHEN** subdomain enumeration finds `*.example.com` resolving to single IP
- **THEN** system detects wildcard pattern
- **AND** filters results resolving to wildcard IP
- **AND** reports wildcard detection to user

### Requirement: Multiple Record Types
The system SHALL support querying A, AAAA, MX, NS, TXT, CNAME, and SOA records.

#### Scenario: Query MX records
- **WHEN** user runs `rb dns record lookup example.com --type MX`
- **THEN** system queries DNS for MX records
- **AND** returns mail server hostnames with priority

#### Scenario: Query all record types
- **WHEN** user runs `rb dns record lookup example.com --type ALL`
- **THEN** system queries all supported record types
- **AND** displays comprehensive DNS profile

### Requirement: Source Filtering
The system SHALL support including and excluding specific sources from enumeration.

#### Scenario: Exclude slow sources
- **WHEN** user runs `rb recon domain subdomains example.com --exclude-sources wayback,commoncrawl`
- **THEN** system skips specified sources
- **AND** queries only remaining sources

#### Scenario: Use only free sources
- **WHEN** user runs `rb recon domain subdomains example.com --free-only`
- **THEN** system uses only sources not requiring API keys

### Requirement: Relationship Graph Visualization
The system SHALL generate relationship graphs showing subdomain connections, shared infrastructure, and DNS hierarchy.

#### Scenario: Generate D3 graph
- **WHEN** user runs `rb recon domain subdomains example.com --graph`
- **THEN** system builds relationship graph from discovered subdomains
- **AND** identifies shared IP addresses and CNAME chains
- **AND** exports as interactive HTML with D3.js visualization

#### Scenario: Export graph data
- **WHEN** user runs `rb recon domain subdomains example.com --graph-export json`
- **THEN** system exports graph nodes and edges as JSON
- **AND** includes metadata (IP, ASN, registrar) per node
