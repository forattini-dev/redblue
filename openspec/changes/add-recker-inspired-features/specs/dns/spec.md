## ADDED Requirements

### Requirement: DNS Propagation Check
The system SHALL query multiple global DNS providers to check DNS propagation status for a given domain and record type.

#### Scenario: Check A record propagation
- **WHEN** user runs `rb dns record propagate example.com`
- **THEN** the system queries Google DNS, Cloudflare, and NextDNS
- **AND** displays results from each provider with latency
- **AND** shows consensus status (all agree / inconsistent)

#### Scenario: Check specific record type propagation
- **WHEN** user runs `rb dns record propagate example.com --type MX`
- **THEN** the system queries all providers for MX records
- **AND** displays the MX records returned by each provider

#### Scenario: Propagation incomplete
- **WHEN** DNS providers return different results
- **THEN** the system displays a warning about inconsistent results
- **AND** shows which providers have which values

### Requirement: DNS Email Security Check
The system SHALL analyze email security DNS records (SPF, DKIM, DMARC) for a given domain.

#### Scenario: Full email security check
- **WHEN** user runs `rb dns record email example.com`
- **THEN** the system queries SPF record (TXT with v=spf1)
- **AND** queries DMARC record (_dmarc.example.com TXT)
- **AND** displays security status for each record

#### Scenario: DKIM check with selector
- **WHEN** user runs `rb dns record email example.com --dkim-selector google`
- **THEN** the system queries google._domainkey.example.com TXT
- **AND** displays DKIM record status

#### Scenario: Missing email security records
- **WHEN** a domain has no SPF or DMARC records
- **THEN** the system displays warnings
- **AND** provides recommendations for email security

#### Scenario: SPF record analysis
- **WHEN** SPF record is found
- **THEN** the system parses mechanisms (include, a, mx, ip4, ip6)
- **AND** warns about overly permissive settings (+all)
