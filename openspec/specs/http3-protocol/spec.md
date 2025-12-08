# http3-protocol Specification

## Purpose
TBD - created by archiving change add-http3-support. Update Purpose after archive.
## Requirements
### Requirement: HTTP/3 Request Execution
The system SHALL execute HTTP/3 requests (GET, POST, PUT, DELETE, HEAD, OPTIONS) over QUIC transport according to RFC 9114.

#### Scenario: Basic GET request
- **WHEN** user executes `rb web asset get https://www.google.com --http3`
- **THEN** system SHALL establish QUIC connection to www.google.com:443
- **AND** send HTTP/3 HEADERS frame with method=GET
- **AND** receive HTTP/3 HEADERS frame with status code
- **AND** receive HTTP/3 DATA frames with response body
- **AND** return complete response to user

#### Scenario: POST request with body
- **WHEN** user executes HTTP/3 POST with request body
- **THEN** system SHALL send HEADERS frame followed by DATA frames
- **AND** respect flow control limits
- **AND** handle server response correctly

#### Scenario: HTTP/3 unavailable fallback
- **WHEN** HTTP/3 connection fails or times out
- **THEN** system SHALL display error message
- **AND** suggest trying HTTP/1.1 as fallback

### Requirement: QUIC Connection Management
The system SHALL manage QUIC connections for HTTP/3 transport, including establishment, reuse, and graceful shutdown.

#### Scenario: New connection establishment
- **WHEN** first request to new host
- **THEN** system SHALL perform QUIC handshake (Initial, Handshake, 1-RTT packets)
- **AND** verify TLS 1.3 certificate
- **AND** exchange HTTP/3 SETTINGS frames
- **AND** establish control stream

#### Scenario: Connection reuse
- **WHEN** second request to same host within timeout
- **THEN** system SHALL reuse existing QUIC connection
- **AND** open new bidirectional stream
- **AND** avoid redundant handshake

#### Scenario: Connection timeout
- **WHEN** connection idle for max_idle_timeout duration
- **THEN** system SHALL close connection gracefully
- **AND** remove from connection pool
- **AND** establish new connection on next request

### Requirement: 0-RTT Session Resumption
The system SHALL support 0-RTT session resumption for safe HTTP methods to reduce latency on repeated connections.

#### Scenario: 0-RTT enabled for GET
- **WHEN** second connection to previously visited host
- **THEN** system SHALL attempt 0-RTT connection
- **AND** send application data in first flight
- **AND** complete handshake in 0 round trips

#### Scenario: 0-RTT disabled for POST
- **WHEN** POST request to previously visited host
- **THEN** system SHALL NOT use 0-RTT (replay attack risk)
- **AND** perform full 1-RTT handshake
- **AND** send request after handshake completes

#### Scenario: 0-RTT rejected by server
- **WHEN** server rejects 0-RTT data
- **THEN** system SHALL retry request in 1-RTT
- **AND** complete transaction successfully
- **AND** not report error to user

### Requirement: Alt-Svc Protocol Upgrade
The system SHALL automatically upgrade from HTTP/1.1 to HTTP/3 when server advertises Alt-Svc header.

#### Scenario: Alt-Svc discovery
- **WHEN** HTTP/1.1 response includes `Alt-Svc: h3=":443"; ma=86400`
- **THEN** system SHALL parse Alt-Svc header
- **AND** cache mapping (hostname → HTTP/3 endpoint)
- **AND** set expiry based on max-age (ma) parameter

#### Scenario: Auto-upgrade on second request
- **WHEN** second request to host with cached Alt-Svc
- **THEN** system SHALL attempt HTTP/3 connection first
- **AND** fallback to HTTP/1.1 on failure
- **AND** display protocol used in output

#### Scenario: Explicit protocol override
- **WHEN** user specifies `--protocol http1`
- **THEN** system SHALL use HTTP/1.1 only
- **AND** ignore cached Alt-Svc entries
- **AND** not attempt HTTP/3 upgrade

### Requirement: Stream Management
The system SHALL manage HTTP/3 streams including state transitions, flow control, and error handling per RFC 9114 Section 6.

#### Scenario: Bidirectional stream lifecycle
- **WHEN** HTTP request initiated
- **THEN** system SHALL open new bidirectional stream
- **AND** transition state: idle → open → half_closed_local → closed
- **AND** release stream resources on close

#### Scenario: Stream flow control
- **WHEN** sending large request body
- **THEN** system SHALL respect stream flow control window
- **AND** wait for WINDOW_UPDATE if blocked
- **AND** not exceed MAX_STREAM_DATA limit

#### Scenario: Stream error handling
- **WHEN** server sends RESET_STREAM frame
- **THEN** system SHALL abort stream gracefully
- **AND** propagate error to user with error code
- **AND** not affect other active streams

### Requirement: QPACK Header Compression
The system SHALL compress and decompress HTTP headers using QPACK (RFC 9204) for efficient transmission.

#### Scenario: Encode request headers
- **WHEN** building HTTP/3 request
- **THEN** system SHALL encode headers using QPACK
- **AND** use static table for common headers (e.g., :method, :path)
- **AND** include Required Insert Count and Base

#### Scenario: Decode response headers
- **WHEN** receiving HTTP/3 HEADERS frame
- **THEN** system SHALL decode QPACK-compressed headers
- **AND** reconstruct header list (name-value pairs)
- **AND** handle dynamic table updates

#### Scenario: QPACK encoder/decoder streams
- **WHEN** HTTP/3 connection established
- **THEN** system SHALL create unidirectional encoder stream
- **AND** create unidirectional decoder stream
- **AND** exchange SETTINGS_QPACK_MAX_TABLE_CAPACITY

### Requirement: HTTP/3 Frame Processing
The system SHALL correctly encode and decode all HTTP/3 frame types per RFC 9114 Section 7.2.

#### Scenario: HEADERS frame
- **WHEN** sending or receiving HTTP request/response
- **THEN** system SHALL encode/decode HEADERS frame
- **AND** include QPACK-compressed header block
- **AND** handle Length field correctly

#### Scenario: DATA frame
- **WHEN** sending or receiving HTTP body
- **THEN** system SHALL encode/decode DATA frame
- **AND** split large bodies into multiple frames
- **AND** handle Length field correctly

#### Scenario: SETTINGS frame
- **WHEN** HTTP/3 connection established
- **THEN** system SHALL send SETTINGS frame on control stream
- **AND** include QPACK_MAX_TABLE_CAPACITY
- **AND** include QPACK_BLOCKED_STREAMS
- **AND** parse server SETTINGS frame

#### Scenario: GOAWAY frame
- **WHEN** server initiates graceful shutdown
- **THEN** system SHALL receive GOAWAY frame
- **AND** stop creating new streams
- **AND** complete in-flight requests
- **AND** close connection gracefully

### Requirement: Error Handling
The system SHALL handle HTTP/3 and QUIC errors gracefully, providing user-friendly error messages.

#### Scenario: Connection error
- **WHEN** QUIC connection fails (e.g., NO_ERROR, PROTOCOL_VIOLATION)
- **THEN** system SHALL display error code and description
- **AND** suggest corrective action if applicable
- **AND** exit with non-zero status code

#### Scenario: Stream error
- **WHEN** HTTP/3 stream fails (e.g., H3_INTERNAL_ERROR, H3_REQUEST_CANCELLED)
- **THEN** system SHALL display HTTP/3 error code
- **AND** explain error in human-readable format
- **AND** not crash or hang

#### Scenario: Timeout error
- **WHEN** request exceeds timeout (default 30s)
- **THEN** system SHALL abort request
- **AND** display "Request timeout" message
- **AND** close stream and connection if needed

### Requirement: CLI Integration
The system SHALL integrate HTTP/3 support into existing web commands with appropriate flags and output.

#### Scenario: HTTP/3 flag on get command
- **WHEN** user executes `rb web asset get <url> --http3`
- **THEN** system SHALL force HTTP/3 protocol
- **AND** display protocol version in output (HTTP/3, h3-29, h3)
- **AND** show connection reuse status

#### Scenario: Protocol auto-detection
- **WHEN** user executes `rb web asset get <url>` without protocol flag
- **THEN** system SHALL check for cached Alt-Svc
- **AND** attempt HTTP/3 if available, else HTTP/1.1
- **AND** display protocol used

#### Scenario: Protocol selection flag
- **WHEN** user specifies `--protocol auto|http1|http2|http3`
- **THEN** system SHALL use specified protocol
- **AND** auto: try HTTP/3 → HTTP/2 → HTTP/1.1
- **AND** http3: HTTP/3 only (error if unavailable)

### Requirement: HTTP/3 Security Audit
The system SHALL audit HTTP/3 connections for security misconfigurations and vulnerabilities.

#### Scenario: TLS 1.3 verification
- **WHEN** auditing HTTP/3 connection
- **THEN** system SHALL verify TLS 1.3 is used
- **AND** report error if TLS 1.2 or older detected
- **AND** check for weak cipher suites

#### Scenario: QUIC transport parameters
- **WHEN** auditing HTTP/3 connection
- **THEN** system SHALL display QUIC transport parameters
- **AND** check max_idle_timeout is reasonable (>30s)
- **AND** verify max_udp_payload_size is sufficient (>=1200)

#### Scenario: 0-RTT replay protection
- **WHEN** auditing HTTP/3 with 0-RTT enabled
- **THEN** system SHALL verify safe methods only (GET, HEAD)
- **AND** warn if 0-RTT used for POST/PUT/DELETE
- **AND** recommend disabling 0-RTT for unsafe methods

### Requirement: Performance Monitoring
The system SHALL measure and display HTTP/3 performance metrics for analysis.

#### Scenario: Request timing
- **WHEN** HTTP/3 request completes
- **THEN** system SHALL display timing breakdown
- **AND** show: DNS lookup, QUIC handshake, request, response
- **AND** total time in milliseconds

#### Scenario: 0-RTT benefit measurement
- **WHEN** 0-RTT used for request
- **THEN** system SHALL display "0-RTT: enabled" in output
- **AND** show time saved vs 1-RTT (estimated)
- **AND** note replay attack risk

#### Scenario: Connection reuse indicator
- **WHEN** connection reused from pool
- **THEN** system SHALL display "Connection: reused" in output
- **AND** show connection age (time since creation)
- **AND** show request count on this connection

### Requirement: RFC 9114 Compliance
The system SHALL comply with all MUST requirements in RFC 9114 (HTTP/3).

#### Scenario: Connection preface
- **WHEN** establishing HTTP/3 connection
- **THEN** system SHALL send SETTINGS frame on control stream (stream 0 or 2)
- **AND** not send HTTP/1.1 connection preface
- **AND** follow HTTP/3 initialization sequence

#### Scenario: Stream type enforcement
- **WHEN** creating streams
- **THEN** system SHALL use bidirectional streams for requests
- **AND** use unidirectional streams for control, QPACK encoder/decoder
- **AND** enforce stream type constraints per RFC 9114 Section 6.2

#### Scenario: Frame type validation
- **WHEN** receiving frames
- **THEN** system SHALL validate frame type is allowed on stream type
- **AND** reject invalid combinations (e.g., DATA on control stream)
- **AND** close connection with H3_FRAME_UNEXPECTED on violation

### Requirement: Interoperability
The system SHALL successfully communicate with major HTTP/3 server implementations.

#### Scenario: Google HTTP/3 compatibility
- **WHEN** requesting https://www.google.com with HTTP/3
- **THEN** system SHALL complete handshake successfully
- **AND** retrieve homepage HTML
- **AND** handle Google's QUIC version (h3-29 or h3)

#### Scenario: Cloudflare HTTP/3 compatibility
- **WHEN** requesting https://cloudflare.com with HTTP/3
- **THEN** system SHALL complete handshake successfully
- **AND** retrieve response correctly
- **AND** handle Cloudflare's QUIC extensions

#### Scenario: Multiple QUIC versions
- **WHEN** server supports multiple QUIC versions (h3-29, h3)
- **THEN** system SHALL negotiate best common version
- **AND** fallback to older version if latest unavailable
- **AND** display negotiated version in output

