# Design Document: HTTP/3 Support

## Context

HTTP/3 is the third major version of HTTP protocol, standardized in RFC 9114 (June 2022). Unlike HTTP/1.1 and HTTP/2 which use TCP, HTTP/3 is built on QUIC transport protocol (UDP-based, RFC 9000).

**Current State:**
- ✅ HTTP/1.1 fully implemented (`src/protocols/http.rs`)
- ✅ HTTP/2 partially implemented (`src/protocols/http2/`)
- ✅ QUIC transport implemented (`src/protocols/quic/`)
- 🔨 HTTP/3 scaffolding exists but incomplete (`src/protocols/http3/`)

**Goals:**
- Complete HTTP/3 client implementation from scratch (zero external dependencies)
- Seamless protocol upgrade via Alt-Svc
- Performance on par with native HTTP/3 clients
- Full RFC 9114 compliance

**Constraints:**
- MUST use only Rust std library + libc + openssl (vendored)
- NO external HTTP/3 crates (no quiche, quinn, h3, etc.)
- ZERO mocks or placeholders
- All protocols implemented from scratch

**Stakeholders:**
- Red Team: Modern web application testing
- Blue Team: HTTP/3 security auditing
- DevSecOps: CI/CD integration for HTTP/3 services

## Goals / Non-Goals

### Goals
1. **Complete HTTP/3 client** - Full request/response, streaming, error handling
2. **Auto-upgrade via Alt-Svc** - Transparent HTTP/1.1 → HTTP/3 upgrade
3. **Connection pooling** - Reuse QUIC connections for performance
4. **0-RTT support** - Session resumption for reduced latency
5. **RFC 9114 compliance** - Pass all standard compliance tests
6. **Major site compatibility** - Google, Cloudflare, Facebook, etc.

### Non-Goals
1. **HTTP/3 server** - Only client implementation (server out of scope)
2. **Custom QUIC extensions** - Standard QUIC only (no proprietary features)
3. **HTTP/3 proxy** - Direct client requests only
4. **WebTransport** - HTTP/3-only, no WebTransport API
5. **MASQUE/CONNECT-UDP** - Standard HTTP/3 semantics only

## Decisions

### Decision 1: Leverage Existing QUIC Implementation

**Choice:** Use existing `src/protocols/quic/` as transport layer.

**Rationale:**
- QUIC implementation already exists and handles:
  - Connection establishment (handshake)
  - Stream management
  - Flow control
  - Congestion control
  - Packet loss recovery
- HTTP/3 is just a semantic layer on top of QUIC
- Avoids duplicating complex transport logic

**Alternatives Considered:**
- ❌ Rewrite QUIC from scratch → Unnecessary duplication
- ❌ Use external QUIC crate → Violates zero-dependency policy

**Implementation:**
```rust
pub struct Http3Client {
    quic: QuicConnection,  // Reuse existing QUIC
    encoder: QpackEncoder,
    decoder: QpackDecoder,
    settings: Http3Settings,
    streams: HashMap<StreamId, Stream>,
}
```

### Decision 2: Alt-Svc Based Protocol Upgrade

**Choice:** Implement Alt-Svc header parsing for automatic HTTP/3 upgrade.

**Rationale:**
- Standard mechanism for protocol negotiation (RFC 7838)
- Graceful fallback if HTTP/3 unavailable
- User-transparent upgrade (no manual flags required)
- Matches behavior of browsers and curl

**Flow:**
1. First request: HTTP/1.1 to `https://example.com`
2. Server responds with `Alt-Svc: h3=":443"; ma=86400`
3. Cache Alt-Svc mapping in session
4. Subsequent requests: Try HTTP/3 first, fallback to HTTP/1.1

**Alternatives Considered:**
- ❌ Always require `--http3` flag → Poor UX
- ❌ DNS HTTPS records → Complex, limited adoption
- ✅ Alt-Svc + optional `--http3` flag → Best of both worlds

**Implementation:**
```rust
struct AltSvcCache {
    mappings: HashMap<String, AltSvcEntry>,  // hostname → HTTP/3 endpoint
}

impl HttpClient {
    fn get(&mut self, url: &str) -> Result<Response> {
        // Check cache for HTTP/3 endpoint
        if let Some(h3_endpoint) = self.alt_svc.get(url) {
            match self.get_http3(h3_endpoint) {
                Ok(resp) => return Ok(resp),
                Err(_) => {
                    // Fallback to HTTP/1.1
                }
            }
        }

        // HTTP/1.1 request
        let resp = self.get_http1(url)?;

        // Parse Alt-Svc header
        if let Some(alt_svc) = resp.headers.get("alt-svc") {
            self.alt_svc.parse_and_cache(url, alt_svc);
        }

        Ok(resp)
    }
}
```

### Decision 3: Connection Pool with TTL

**Choice:** Implement connection pool with per-connection TTL tracking.

**Rationale:**
- QUIC connections are expensive to establish (TLS 1.3 handshake)
- Connection reuse provides 50-200ms latency improvement (0-RTT)
- Must respect server max_idle_timeout
- Prevents connection leaks

**Pool Design:**
```rust
struct ConnectionPool {
    connections: HashMap<String, PooledConnection>,
    max_idle_time: Duration,
    max_connections: usize,
}

struct PooledConnection {
    connection: QuicConnection,
    last_used: Instant,
    request_count: u64,
}

impl ConnectionPool {
    fn get_or_create(&mut self, host: &str) -> Result<QuicConnection> {
        // Check for existing connection
        if let Some(conn) = self.connections.get(host) {
            if !conn.is_expired() && conn.is_alive() {
                return Ok(conn.connection.clone());
            }
        }

        // Create new connection
        let conn = QuicConnection::new(host)?;
        self.connections.insert(host.to_string(), PooledConnection {
            connection: conn.clone(),
            last_used: Instant::now(),
            request_count: 0,
        });

        Ok(conn)
    }

    fn cleanup_expired(&mut self) {
        self.connections.retain(|_, conn| !conn.is_expired());
    }
}
```

**Alternatives Considered:**
- ❌ No pooling → 100-300ms overhead per request
- ❌ Infinite connection lifetime → Resource leaks
- ❌ Global pool → Contention, complexity

### Decision 4: Stream-Based Request/Response Model

**Choice:** Map each HTTP request/response to a QUIC stream.

**Rationale:**
- Natural mapping: 1 HTTP transaction = 1 bidirectional QUIC stream
- Parallel requests without head-of-line blocking
- Stream isolation (errors don't affect other streams)
- Matches RFC 9114 design

**Architecture:**
```
HTTP/3 Request Flow:
┌──────────────┐
│ User Request │
└──────┬───────┘
       │
┌──────▼──────────────┐
│ Http3Client         │
│ - encode_request()  │
└──────┬──────────────┘
       │
┌──────▼──────────────┐
│ QUIC Stream         │
│ - open_stream()     │
│ - send_data()       │
└──────┬──────────────┘
       │
┌──────▼──────────────┐
│ QUIC Connection     │
│ - send_packets()    │
└──────┬──────────────┘
       │
       ▼
   [Network]

HTTP/3 Response Flow:
   [Network]
       │
┌──────▼──────────────┐
│ QUIC Connection     │
│ - recv_packets()    │
└──────┬──────────────┘
       │
┌──────▼──────────────┐
│ QUIC Stream         │
│ - recv_data()       │
└──────┬──────────────┘
       │
┌──────▼──────────────┐
│ Http3Client         │
│ - decode_response() │
└──────┬──────────────┘
       │
┌──────▼───────┐
│ User Gets    │
│ Response     │
└──────────────┘
```

**Stream Lifecycle:**
1. Client opens bidirectional stream
2. Send HEADERS frame (request headers)
3. Send DATA frames (request body, if any)
4. Receive HEADERS frame (response headers)
5. Receive DATA frames (response body)
6. Close stream

### Decision 5: QPACK Encoder/Decoder from Scratch

**Choice:** Implement QPACK (RFC 9204) for header compression.

**Rationale:**
- HTTP/3 requires QPACK (not HPACK like HTTP/2)
- Simple implementation (~500 lines of code)
- Critical for performance (headers are ~1-2KB uncompressed)
- Already scaffolded in `src/protocols/http3/qpack.rs`

**QPACK Basics:**
- Static table (predefined common headers)
- Dynamic table (learned headers during connection)
- Encoder stream (table updates)
- Decoder stream (acknowledgments)

**Implementation Strategy:**
1. Start with static table only (simpler, good compression)
2. Add dynamic table for further optimization
3. Support required insert count and base index
4. Handle blocked streams (waiting for table updates)

**Alternatives Considered:**
- ❌ No compression → 5-10x bandwidth waste
- ❌ Use external QPACK crate → Violates zero-dependency policy
- ✅ Minimal QPACK (static table only) → Good enough for v1

## Risks / Trade-offs

### Risk 1: QUIC Implementation Bugs
**Impact:** HIGH - HTTP/3 completely depends on QUIC layer

**Mitigation:**
- Thorough testing against major HTTP/3 servers (Google, Cloudflare)
- Run QUIC interop tests
- Add extensive error handling and logging
- Fallback to HTTP/1.1 on QUIC failures

### Risk 2: 0-RTT Replay Attacks
**Impact:** MEDIUM - Security vulnerability if not handled correctly

**Mitigation:**
- Default: 0-RTT disabled for unsafe methods (POST, PUT, DELETE)
- Safe methods only (GET, HEAD, OPTIONS) use 0-RTT
- Document 0-RTT replay risks in security audit output
- Add `--allow-0rtt-unsafe` flag for advanced users (with warning)

### Risk 3: Binary Size Increase
**Impact:** LOW - Target is <3MB binary, adding HTTP/3 may exceed

**Mitigation:**
- Reuse existing QUIC code (no new transport layer)
- Minimal QPACK implementation (static table focus)
- Profile binary size after each milestone
- Current estimate: +30-50KB (acceptable)

### Risk 4: Compatibility Issues
**Impact:** MEDIUM - HTTP/3 is relatively new, server support varies

**Mitigation:**
- Test against 10+ major HTTP/3 servers
- Implement multiple QUIC versions (h3-29, h3)
- Graceful fallback to HTTP/1.1 on failure
- Clear error messages for unsupported features

### Trade-off 1: Simplicity vs Performance

**Choice:** Prioritize simplicity in v1, optimize in v2.

**Rationale:**
- HTTP/3 is complex (QUIC + QPACK + HTTP semantics)
- Get working implementation first, optimize later
- Measure before optimizing (avoid premature optimization)

**v1 Simplifications:**
- QPACK: Static table only (no dynamic table)
- Connection pool: Simple LRU (no advanced eviction)
- 0-RTT: GET/HEAD only (no POST/PUT)
- Streams: Sequential processing (no parallel)

**v2 Optimizations (future):**
- QPACK: Full dynamic table support
- Connection pool: Advanced eviction strategies
- 0-RTT: Idempotent POST support
- Streams: Parallel request processing

### Trade-off 2: Auto-upgrade vs Explicit Flag

**Choice:** Support both (auto-upgrade by default, `--http3` to force).

**Rationale:**
- **Auto-upgrade:** Better UX, matches browser behavior
- **Explicit flag:** Power users, debugging, testing

**Behavior:**
```bash
# Auto-upgrade (default)
rb web asset get https://www.google.com
# → HTTP/1.1 first, then HTTP/3 if Alt-Svc present

# Force HTTP/3
rb web asset get https://www.google.com --http3
# → HTTP/3 only, error if unavailable

# Disable auto-upgrade
rb web asset get https://www.google.com --no-auto-upgrade
# → HTTP/1.1 only, ignore Alt-Svc
```

## Migration Plan

**No migration required** - This is additive functionality.

### Rollout Phases

**Phase 1: Core Implementation (Week 1-2)**
- Complete HTTP/3 client (request/response)
- Connection pool (basic LRU)
- QPACK encoding/decoding (static table)
- Unit tests

**Phase 2: CLI Integration (Week 3)**
- Add `--http3` flag to web commands
- Implement Alt-Svc parsing and caching
- Auto-upgrade logic
- Manual testing with major sites

**Phase 3: Security Features (Week 4)**
- HTTP/3 security audit
- QUIC parameter inspection
- Version negotiation testing
- Integration tests

**Phase 4: Documentation & Release (Week 5)**
- Update README.md
- Write `docs/domains/web.md` HTTP/3 section
- Create examples
- Release notes

### Rollback Strategy

If critical bugs discovered:
1. **Disable HTTP/3 by default** - Require explicit `--http3` flag
2. **Fix bugs** - Address issues in patch release
3. **Re-enable auto-upgrade** - Once stable

No data loss risk (HTTP/3 is client-only, no persistence).

## Open Questions

### Q1: Support HTTP/3 server-push?
**Status:** DEFERRED - Rarely used, complex to implement

**Decision:** Not in v1. Revisit if user demand.

### Q2: Support QUIC connection migration?
**Status:** OPEN - Useful for mobile scenarios (IP change)

**Decision:** Basic support (detect migration, continue connection). Full mobility optimization deferred to v2.

### Q3: Max number of concurrent streams?
**Status:** OPEN

**Proposal:**
- Default: 100 concurrent streams
- Configurable via `--max-streams <n>`
- Respect server MAX_STREAMS setting

**Need:** Testing to determine optimal value.

### Q4: How to handle HTTP/3-only errors?
**Status:** OPEN

**Proposal:**
- Show HTTP/3 error code (e.g., H3_INTERNAL_ERROR)
- Include human-readable description
- Suggest fallback to HTTP/1.1 if appropriate

**Example:**
```
Error: HTTP/3 request failed (H3_STREAM_CREATION_ERROR)
The server rejected the stream creation.
Try: rb web asset get https://example.com --protocol http1
```

### Q5: Cache Alt-Svc across sessions?
**Status:** OPEN

**Options:**
- **A)** In-memory only (lost on exit)
- **B)** Persist to disk (faster on next run)

**Decision:** Start with A (simpler), add B if users request.
