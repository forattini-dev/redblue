# network-scanning Specification

## Purpose
TBD - created by archiving change add-tool-parity-roadmap. Update Purpose after archive.
## Requirements
### Requirement: TCP SYN Scan
The system SHALL implement TCP SYN (half-open) scanning using raw sockets. SYN scans send a SYN packet and analyze the response (SYN-ACK = open, RST = closed, no response = filtered).

#### Scenario: SYN scan detects open port
- **WHEN** user runs `rb network ports syn-scan <target> --ports 80`
- **THEN** system sends TCP SYN packet to port 80
- **AND** receives SYN-ACK response
- **AND** sends RST to close connection
- **AND** reports port 80 as "open"

#### Scenario: SYN scan detects closed port
- **WHEN** user runs `rb network ports syn-scan <target> --ports 81`
- **THEN** system sends TCP SYN packet to port 81
- **AND** receives RST response
- **AND** reports port 81 as "closed"

#### Scenario: SYN scan detects filtered port
- **WHEN** user runs `rb network ports syn-scan <target> --ports 82`
- **THEN** system sends TCP SYN packet to port 82
- **AND** receives no response after timeout
- **AND** reports port 82 as "filtered"

### Requirement: UDP Scan
The system SHALL implement UDP scanning with ICMP unreachable detection. UDP scans send empty or protocol-specific payloads and analyze responses.

#### Scenario: UDP scan detects open port
- **WHEN** user runs `rb network ports udp-scan <target> --ports 53`
- **THEN** system sends UDP packet to port 53
- **AND** receives DNS response
- **AND** reports port 53 as "open"

#### Scenario: UDP scan detects closed port
- **WHEN** user runs `rb network ports udp-scan <target> --ports 54`
- **THEN** system sends UDP packet to port 54
- **AND** receives ICMP port unreachable
- **AND** reports port 54 as "closed"

### Requirement: Stealth Scans (FIN/NULL/XMAS)
The system SHALL implement FIN, NULL, and XMAS scans for firewall evasion. These scans exploit RFC-compliant TCP stack behavior.

#### Scenario: FIN scan detects open port
- **WHEN** user runs `rb network ports fin-scan <target> --ports 80`
- **THEN** system sends TCP packet with only FIN flag set
- **AND** receives no response (RFC 793 behavior)
- **AND** reports port 80 as "open|filtered"

#### Scenario: XMAS scan detects closed port
- **WHEN** user runs `rb network ports xmas-scan <target> --ports 81`
- **THEN** system sends TCP packet with FIN+PSH+URG flags
- **AND** receives RST response
- **AND** reports port 81 as "closed"

### Requirement: Port State Classification
The system SHALL classify ports into 6 states: open, closed, filtered, unfiltered, open|filtered, closed|filtered.

#### Scenario: Port state reported with scan type context
- **WHEN** user runs any scan type
- **THEN** system reports port state based on response behavior
- **AND** state reflects the specific scan technique used

### Requirement: Service Version Detection
The system SHALL detect service versions by sending protocol-specific probes and parsing responses. MUST support 35+ protocols.

#### Scenario: SSH version detected
- **WHEN** user runs `rb network ports scan <target> --service-version`
- **THEN** system connects to open ports
- **AND** sends protocol-specific probes
- **AND** parses SSH banner (e.g., "SSH-2.0-OpenSSH_8.4")
- **AND** reports service name and version

### Requirement: OS Fingerprinting
The system SHALL detect operating systems by analyzing TCP/IP stack behavior. MUST include 1000+ OS signatures.

#### Scenario: OS detected from TCP stack behavior
- **WHEN** user runs `rb network ports scan <target> --os-detect`
- **THEN** system sends probing packets (SYN, ACK, ICMP, etc.)
- **AND** analyzes response characteristics (TTL, window size, options)
- **AND** matches against OS fingerprint database
- **AND** reports OS family and version with confidence percentage

### Requirement: Timing Templates
The system SHALL support timing templates from paranoid (T0) to insane (T5) controlling scan speed and stealth.

#### Scenario: Paranoid timing for IDS evasion
- **WHEN** user runs `rb network ports scan <target> -T0`
- **THEN** system waits 5+ minutes between probes
- **AND** randomizes probe order
- **AND** minimizes detection risk

### Requirement: Scripting Engine
The system SHALL support a scripting engine for custom scan logic and vulnerability checks, enabling extensibility without recompilation.

#### Scenario: Run custom scan script
- **WHEN** user runs `rb network ports scan <target> --script http-vuln-check`
- **THEN** system loads script from `~/.config/redblue/scripts/`
- **AND** executes script logic against discovered services
- **AND** reports script output alongside port results

#### Scenario: List available scripts
- **WHEN** user runs `rb network ports scan --list-scripts`
- **THEN** system displays all available scripts with descriptions
- **AND** groups by category (vuln, discovery, auth, brute)

#### Scenario: Script categories
- **WHEN** user runs `rb network ports scan <target> --script-category vuln`
- **THEN** system runs all scripts in the vulnerability category
- **AND** reports findings per script

