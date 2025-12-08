## MODIFIED Requirements

### Requirement: Host Ping
The system SHALL send ICMP echo requests to a host and display round-trip time statistics.

#### Scenario: Basic ping
- **WHEN** user runs `rb network host ping google.com`
- **THEN** the system sends ICMP echo requests
- **AND** displays RTT for each reply
- **AND** shows statistics at the end (min/avg/max/stddev)

#### Scenario: Ping with count
- **WHEN** user runs `rb network host ping google.com --count 5`
- **THEN** the system sends exactly 5 ICMP echo requests
- **AND** stops after receiving 5 replies or timeout

#### Scenario: Ping with interval
- **WHEN** user runs `rb network host ping google.com --interval 2`
- **THEN** the system waits 2 seconds between each request

#### Scenario: Ping without root privileges
- **WHEN** user lacks CAP_NET_RAW capability
- **THEN** the system falls back to TCP ping on port 80/443
- **AND** displays a notice about fallback mode

#### Scenario: Host unreachable
- **WHEN** host does not respond to ICMP
- **THEN** the system displays timeout messages
- **AND** shows 100% packet loss in statistics

#### Scenario: DNS resolution
- **WHEN** hostname is provided
- **THEN** the system resolves it to IP first
- **AND** displays both hostname and IP in output

#### Scenario: Statistics summary
- **WHEN** ping completes
- **THEN** the system displays:
  - Packets transmitted and received
  - Packet loss percentage
  - Round-trip min/avg/max/stddev in ms
