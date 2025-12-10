## ADDED Requirements
### Requirement: Protocol Selection for Bench Load
The bench load generator MUST support choosing between HTTP/1.1 and HTTP/2 when driving traffic against HTTPS targets so that operators can stress servers more than the client.

#### Scenario: Default Auto Negotiation
- **GIVEN** the operator runs `rb bench load run https://example.com`
- **WHEN** the target negotiates HTTP/2 via ALPN
- **THEN** the load generator SHOULD reuse an HTTP/2 connection with multiplexed streams
- **AND** the run summary MUST show `Protocol: http2`.

#### Scenario: Explicit HTTP/1.1
- **GIVEN** the operator runs `rb bench load run https://example.com --protocol http1`
- **WHEN** the load generator starts
- **THEN** it MUST send requests using HTTP/1.1 only even if the server supports HTTP/2
- **AND** the summary MUST show `Protocol: http1`.

#### Scenario: Unsupported HTTP/2 Target
- **GIVEN** the operator runs `rb bench load run https://legacy.example.com --protocol auto`
- **WHEN** the server does not negotiate HTTP/2
- **THEN** the load generator MUST fall back to HTTP/1.1 without failing the run
- **AND** the summary MUST show `Protocol: http1 (fallback…)`, including a fallback note.

### Requirement: Request Bodies for Load Tests
The bench load generator MUST be able to send HTTP request bodies so that HTTP/2 workloads can exercise realistic POST/streaming paths.

#### Scenario: POST with Body
- **GIVEN** the operator runs `rb bench load run https://api.example.com --protocol http2 --method POST --body '{"ping":1}'`
- **WHEN** the load generator issues requests
- **THEN** each request MUST send the body payload with the correct `Content-Length`
- **AND** the run summary MUST report `Method: POST` and display the configured body size.

### Requirement: Latency Telemetry Accuracy
The bench load generator MUST separately measure time-to-first-byte (TTFB) and total response time, and MUST flag requests that time out while reading the body so operators can trust the latency dashboards.

#### Scenario: Report TTFB and Total Duration
- **GIVEN** the operator runs `rb bench load run https://example.com --live`
- **WHEN** responses complete normally
- **THEN** the live dashboard summary MUST show both total latency and TTFB percentiles
- **AND** the final summary MUST list TTFB metrics alongside existing latency statistics.

#### Scenario: Read Timeout Warning
- **GIVEN** the operator runs `rb bench load run https://example.com --timeout 5`
- **WHEN** a request receives headers but the body stalls past the timeout
- **THEN** the request MUST be recorded as a warning/error (not a successful latency sample)
- **AND** the summary MUST highlight the timeout so the operator knows the body never completed.
