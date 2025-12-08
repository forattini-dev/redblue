# Capability: Technology Fingerprinting

Enhanced technology detection with version extraction and CPE mapping for vulnerability correlation.

## ADDED Requirements

### Requirement: Deep Technology Detection
The system SHALL detect and extract version information for web technologies including:
- Web servers (nginx, Apache, IIS, LiteSpeed, Caddy)
- Reverse proxies (HAProxy, Traefik, Envoy)
- CDNs (Cloudflare, Fastly, Akamai, AWS CloudFront)
- API gateways (Kong, AWS API Gateway, Apigee)
- Backend frameworks (Express, Django, Rails, Spring, Laravel, ASP.NET)
- Frontend frameworks (React, Vue, Angular, Svelte, jQuery)
- CMS platforms (WordPress, Drupal, Joomla, Magento, Ghost, Strapi)
- Programming runtimes (PHP, Node.js, Python, Ruby, Java, .NET)
- Databases (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch)

#### Scenario: Server header version extraction
- **WHEN** the target returns `Server: nginx/1.18.0`
- **THEN** the system SHALL detect technology "nginx" with version "1.18.0"
- **AND** assign CPE `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*`

#### Scenario: X-Powered-By detection
- **WHEN** the target returns `X-Powered-By: PHP/8.1.2`
- **THEN** the system SHALL detect technology "php" with version "8.1.2"

#### Scenario: React detection from DOM
- **WHEN** the HTML contains `<div id="root" data-reactroot>`
- **AND** script tags reference `react.production.min.js`
- **THEN** the system SHALL detect technology "react"
- **AND** extract version from script URL if present

#### Scenario: WordPress plugin enumeration
- **WHEN** scanning a WordPress site
- **THEN** the system SHALL enumerate installed plugins via:
  - `/wp-content/plugins/` directory listing
  - `readme.txt` version extraction
  - `wp-json/wp/v2/plugins` API (if accessible)
- **AND** extract plugin versions where detectable

### Requirement: CPE Mapping
The system SHALL map detected technologies to CPE (Common Platform Enumeration) identifiers for vulnerability database queries.

#### Scenario: Known technology CPE resolution
- **WHEN** technology "nginx" version "1.18.0" is detected
- **THEN** the system SHALL resolve CPE as `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*`

#### Scenario: Unknown technology handling
- **WHEN** a technology cannot be mapped to a CPE
- **THEN** the system SHALL flag it as "no_cpe_mapping"
- **AND** include it in output with a warning

### Requirement: Confidence Scoring
The system SHALL assign a confidence score (0.0-1.0) to each detection based on evidence quality.

#### Scenario: High confidence detection
- **WHEN** version is explicitly stated in headers (e.g., `Server: nginx/1.18.0`)
- **THEN** confidence SHALL be >= 0.9

#### Scenario: Medium confidence detection
- **WHEN** version is inferred from error pages or patterns
- **THEN** confidence SHALL be 0.5-0.8

#### Scenario: Low confidence detection
- **WHEN** technology is detected but version cannot be determined
- **THEN** confidence SHALL be <= 0.4
- **AND** version SHALL be marked as "unknown"

### Requirement: CDN and Proxy Detection
The system SHALL detect CDN and reverse proxy infrastructure from headers and DNS.

#### Scenario: Cloudflare detection
- **WHEN** response includes `cf-ray` header
- **OR** DNS resolves to Cloudflare IP ranges
- **THEN** the system SHALL detect "Cloudflare" as CDN

#### Scenario: Multiple proxy chain detection
- **WHEN** `Via` header indicates multiple proxies
- **THEN** the system SHALL list all detected proxies in order

### Requirement: JavaScript Library Detection
The system SHALL detect frontend JavaScript libraries and their versions from script sources.

#### Scenario: jQuery version from CDN
- **WHEN** page includes `<script src="https://code.jquery.com/jquery-3.6.0.min.js">`
- **THEN** the system SHALL detect "jquery" version "3.6.0"

#### Scenario: Bundled library detection
- **WHEN** JavaScript bundle contains library signatures (e.g., `/*! jQuery v3.6.0`)
- **THEN** the system SHALL extract version from inline comments

### Requirement: Structured Output
The system SHALL output detected technologies as structured data (JSON/YAML).

#### Scenario: JSON output format
- **WHEN** `--output json` flag is used
- **THEN** output SHALL be valid JSON with schema:
```json
{
  "target": "https://example.com",
  "scan_time": "2024-01-01T00:00:00Z",
  "technologies": [
    {
      "name": "nginx",
      "version": "1.18.0",
      "category": "server",
      "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
      "confidence": 0.95,
      "source": "server_header"
    }
  ]
}
```

### Requirement: CLI Integration
The system SHALL provide CLI commands for technology fingerprinting.

#### Scenario: Basic fingerprint command
- **WHEN** user runs `rb web asset fingerprint https://example.com`
- **THEN** the system SHALL scan the target and display detected technologies

#### Scenario: Deep scan mode
- **WHEN** user runs `rb web asset fingerprint https://example.com --deep`
- **THEN** the system SHALL perform additional checks:
  - Crawl multiple pages for technology clues
  - Check common paths (/admin, /wp-admin, /.git)
  - Enumerate plugins/modules for CMS

#### Scenario: JSON export
- **WHEN** user runs `rb web asset fingerprint https://example.com -o fingerprint.json`
- **THEN** the system SHALL save results as JSON file
