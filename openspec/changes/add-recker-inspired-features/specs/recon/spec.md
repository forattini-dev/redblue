## ADDED Requirements

### Requirement: RDAP Lookup
The system SHALL query RDAP (Registration Data Access Protocol) servers for domain and IP registration information as a modern alternative to WHOIS.

#### Scenario: Domain RDAP lookup
- **WHEN** user runs `rb recon domain rdap example.com`
- **THEN** the system queries the appropriate RDAP server via bootstrap
- **AND** displays registrar, registration dates, nameservers, and status
- **AND** outputs structured JSON data

#### Scenario: IP RDAP lookup
- **WHEN** user runs `rb recon ip rdap 8.8.8.8`
- **THEN** the system queries the RIR RDAP server
- **AND** displays network range, organization, and contact info

#### Scenario: RDAP bootstrap resolution
- **WHEN** querying a domain
- **THEN** the system first queries IANA bootstrap registry
- **AND** determines correct RDAP server for the TLD

### Requirement: IP Intelligence
The system SHALL provide comprehensive IP intelligence including geolocation, ASN, and bogon detection.

#### Scenario: Basic IP intelligence
- **WHEN** user runs `rb recon ip intel 8.8.8.8`
- **THEN** the system displays:
  - City, region, country
  - Timezone
  - Coordinates (lat/long)
  - Whether IP is a bogon (private/reserved)

#### Scenario: Bogon detection for private IP
- **WHEN** user runs `rb recon ip intel 192.168.1.1`
- **THEN** the system identifies it as a bogon
- **AND** displays the RFC reference (RFC 1918 Private-Use)

#### Scenario: Bogon detection for IPv6 private
- **WHEN** user runs `rb recon ip intel fd00::1`
- **THEN** the system identifies it as a bogon
- **AND** displays "Unique Local Address (RFC 4193)"

#### Scenario: GeoIP database unavailable
- **WHEN** MaxMind database is not installed
- **THEN** the system still performs bogon detection
- **AND** displays message about limited functionality
- **AND** suggests how to install GeoIP database

#### Scenario: ASN information
- **WHEN** GeoIP ASN database is available
- **THEN** the system displays ASN number and organization name
