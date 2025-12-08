# Change: Add Complete HTTP/3 Support

## Why

HTTP/3 is the latest version of HTTP protocol, built on QUIC transport (RFC 9114). Adding HTTP/3 support enables redblue to:

1. **Replace modern web testing tools** - Support HTTP/3-only services (Google, Cloudflare, Facebook)
2. **Complete protocol coverage** - Currently have HTTP/1.1, HTTP/2; HTTP/3 completes the suite
3. **Performance benefits** - QUIC's multiplexing without head-of-line blocking, 0-RTT reconnection
4. **Security testing** - Audit HTTP/3-specific vulnerabilities and misconfigurations
5. **Future-proof** - HTTP/3 adoption is rapidly increasing (25%+ of web traffic)

Currently, redblue has initial HTTP/3 scaffolding (`src/protocols/http3/mod.rs`, `src/protocols/quic/`) but lacks:
- Complete request/response handling
- Connection pooling and reuse
- Error handling and recovery
- CLI integration
- Testing infrastructure

## What Changes

### Protocol Implementation (from scratch using Rust std)
- ✅ **QUIC transport** - Already implemented (`src/protocols/quic/`)
- ✅ **HTTP/3 framing** - Basic frame types (`src/protocols/http3/frame.rs`)
- ✅ **QPACK compression** - Header compression (`src/protocols/http3/qpack.rs`)
- 🔨 **Complete HTTP/3 client** - Request/response, error handling, stream management
- 🔨 **Connection management** - Pooling, reuse, graceful shutdown
- 🔨 **0-RTT support** - Session resumption for performance
- 🔨 **Alt-Svc handling** - Protocol upgrade negotiation (HTTP/1.1 → HTTP/3)

### CLI Integration
- 🔨 Add `--http3` flag to `rb web asset get`
- 🔨 Add `--http3` flag to `rb web asset headers`
- 🔨 Auto-detection via Alt-Svc header
- 🔨 Display protocol version in output (HTTP/3, h3-29, h3)

### Web Security Features
- 🔨 HTTP/3-specific security audits (`rb web asset security`)
- 🔨 QUIC transport parameter inspection
- 🔨 Version negotiation testing
- 🔨 0-RTT replay attack detection

### Testing & Validation
- 🔨 RFC 9114 compliance tests
- 🔨 Interoperability tests (Google, Cloudflare, Facebook)
- 🔨 Performance benchmarks (vs HTTP/1.1, HTTP/2)
- 🔨 Error handling tests (connection failures, timeouts)

### Documentation
- 🔨 Update README.md with HTTP/3 capabilities
- 🔨 Add examples to `docs/domains/web.md`
- 🔨 Document protocol selection logic

## Impact

### Affected Specs
- `http3-protocol` (NEW) - HTTP/3 client implementation requirements
- `web-testing` (MODIFY) - Add HTTP/3 support to web commands
- `protocol-library` (MODIFY) - Document HTTP/3 as available protocol

### Affected Code
- `src/protocols/http3/mod.rs` - Complete client implementation
- `src/protocols/quic/` - Minor enhancements for HTTP/3 usage
- `src/cli/commands/web.rs` - Add HTTP/3 flags and auto-detection
- `src/modules/web/` - HTTP/3-aware security audits
- `tests/http3_*.rs` - New test files

### Breaking Changes
None. This is purely additive functionality.

### Dependencies
**ZERO new external dependencies**. Uses existing:
- Rust std library (TcpStream, UdpSocket, etc.)
- `libc` (for syscalls)
- `openssl` (vendored, temporary - for TLS/QUIC crypto)

### Performance Expectations
- HTTP/3 requests: 50-200ms faster than HTTP/1.1 (0-RTT)
- Binary size increase: <50KB (reuses existing QUIC code)
- Memory: <10MB additional for connection pool

### Tool Equivalents Replaced
- ✅ `curl --http3` - HTTP/3 GET/POST requests
- ✅ `h2spec` - HTTP/3 protocol compliance testing
- ✅ `quiche-client` - QUIC/HTTP/3 client tools

### Completion Criteria
1. Can fetch any HTTP/3 URL (e.g., `rb web asset get https://www.google.com --http3`)
2. Auto-detects HTTP/3 via Alt-Svc header
3. All RFC 9114 compliance tests pass
4. Works with Google, Cloudflare, Facebook (major HTTP/3 providers)
5. Performance within 10% of native `curl --http3`
6. Zero external dependencies maintained
