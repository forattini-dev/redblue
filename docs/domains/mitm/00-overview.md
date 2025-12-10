# MITM Domain

> Full-featured Man-in-the-Middle attack toolkit for authorized penetration testing.

## Overview

The `mitm` domain provides a comprehensive Man-in-the-Middle (MITM) attack stack, combining DNS hijacking with TLS interception to enable complete traffic analysis and manipulation. Built entirely from scratch in Rust with zero external dependencies for protocol implementations.

## Warning

> **AUTHORIZED USE ONLY**: This domain is designed exclusively for authorized penetration testing, red team operations, CTF competitions, and security research. Unauthorized interception of network traffic is illegal in most jurisdictions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      MITM Attack Stack                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐                ┌───────────────────────┐  │
│  │   DNS Server     │                │     MITM Proxy        │  │
│  │  (Port 53)       │                │    (Port 8080)        │  │
│  │                  │                │                       │  │
│  │  • Hijacking     │                │  • TLS Interception   │  │
│  │  • Passthrough   │                │  • Cert Generation    │  │
│  │  • Logging       │                │  • Header Stripping   │  │
│  └────────┬─────────┘                │  • Script Injection   │  │
│           │                          │  • WebSocket Support  │  │
│           │                          └───────────┬───────────┘  │
│           │                                      │              │
│           │ DNS Query                            │ HTTPS        │
│           │ *.target.com → Attacker IP           │              │
│           │                                      │              │
│  ┌────────▼──────────────────────────────────────▼───────────┐  │
│  │                   Network Traffic                          │  │
│  │                                                            │  │
│  │  1. Target DNS query: *.target.com → Our DNS server       │  │
│  │  2. DNS response: target.com → Attacker IP                │  │
│  │  3. Target connects to attacker:443 (HTTPS)               │  │
│  │  4. MITM proxy generates fake certificate                 │  │
│  │  5. Traffic intercepted, decrypted, inspected             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Full MITM attack stack (DNS + TLS proxy)
rb mitm intercept start --target "*.target.com" --proxy-ip 10.0.0.5

# TLS interception proxy only (for browser testing)
rb mitm intercept proxy --proxy-port 8080

# DNS hijacking only
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5

# Interactive shell with real-time traffic viewer
rb mitm intercept shell --proxy-port 8080

# Generate CA certificate for target installation
rb mitm intercept generate-ca --output ./certs

# Export CA for different platforms
rb mitm intercept export-ca --ca-cert ca.pem --format der
```

## Available Resources

| Resource | Description | Key Verbs |
|----------|-------------|-----------|
| [`intercept`](/domains/mitm/01-dns-hijacking.md) | DNS hijacking + TLS interception | `start`, `dns`, `proxy`, `shell` |
| [`certificates`](/domains/mitm/04-certificates.md) | CA certificate management | `generate-ca`, `export-ca` |

## Key Features

### DNS Hijacking
- Custom DNS server with hijacking rules
- Wildcard domain support (`*.target.com`)
- Upstream DNS fallback for non-hijacked queries
- Configurable bind address and upstream servers

### TLS Interception
- On-the-fly certificate generation signed by custom CA
- Full TLS handshake on both client and server sides
- Transparent decryption of HTTPS traffic
- Support for TLS 1.2 and 1.3

### Traffic Manipulation
- Automatic security header stripping (HSTS, CSP, X-Frame-Options)
- JavaScript injection support (RBB hooks)
- **Same-origin hook injection** (stealth mode - no CORS required)
- Request/response inspection and modification
- Accept-Encoding stripping to prevent compression

### WebSocket Support
- WebSocket upgrade detection
- Transparent WebSocket passthrough
- Frame type logging (text, binary, ping, pong, close)

### Interactive Shell
- k9s-style TUI interface
- Real-time request/response streaming
- Filtering by host, method, path, status code
- Request history and search
- Keyboard shortcuts for efficient navigation

### Logging
- Text and JSON format support
- File and stdout logging
- Structured logs for parsing and analysis

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| mitmproxy | `rb mitm intercept proxy` |
| Burp Suite Proxy | `rb mitm intercept shell` |
| sslstrip | `rb mitm intercept proxy` (strips HSTS) |
| Bettercap MITM | `rb mitm intercept start` |
| Browser hooking (external) | `rb mitm intercept proxy --hook URL` |
| Browser hooking (stealth) | `rb mitm intercept proxy --hook-path /assets/js/rb.js --hook-callback URL` |
| dnsspoof | `rb mitm intercept dns` |

## Command Matrix

```
rb mitm intercept <verb> [FLAGS]
                  │
                  ├── start        # Full MITM stack (DNS + proxy)
                  ├── proxy        # TLS interception proxy only
                  ├── dns          # DNS hijacking server only
                  ├── shell        # Interactive TUI shell
                  ├── generate-ca  # Generate CA certificate
                  └── export-ca    # Export CA for installation
```

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| DNS Hijacking | ✅ Done | Wildcard support, upstream fallback |
| TLS Interception | ✅ Done | OpenSSL-based, cert caching |
| Certificate Authority | ✅ Done | ECDSA P-256, RSA 2048/4096 |
| Security Header Stripping | ✅ Done | 11 headers stripped |
| JavaScript Injection | ✅ Done | External + Same-origin modes |
| WebSocket Passthrough | ✅ Done | Full frame type detection |
| Interactive Shell | ✅ Done | k9s-style TUI |
| Traffic Logging | ✅ Done | Text + JSON formats |
| Request Modification | 🚧 Partial | Via interceptor API |

## Attack Flow

```
Client                    MITM Proxy                         Target
  │                           │                                 │
  │── DNS Query ─────────────►│                                 │
  │◄── Hijacked IP ───────────│                                 │
  │                           │                                 │
  │── CONNECT host:443 ──────►│                                 │
  │◄── 200 Connection OK ─────│                                 │
  │                           │                                 │
  │── TLS ClientHello ───────►│                                 │
  │◄── TLS ServerHello ───────│  [Generate fake cert]           │
  │◄── TLS Certificate ───────│                                 │
  │── TLS Finished ──────────►│                                 │
  │                           │── TLS ClientHello ─────────────►│
  │                           │◄── TLS ServerHello ─────────────│
  │                           │◄── TLS Certificate ─────────────│
  │                           │── TLS Finished ────────────────►│
  │                           │                                 │
  │◄═══ Decrypted HTTP ══════►│◄═══ Encrypted TLS ════════════►│
```

## Ethical Guidelines

**ALWAYS:**
- Obtain written authorization before testing
- Stay within the defined scope
- Document all intercepted traffic
- Clean up certificates after testing
- Report vulnerabilities responsibly

**NEVER:**
- Intercept traffic without authorization
- Use on production systems without approval
- Store intercepted credentials longer than necessary
- Share intercepted data outside the engagement

## Prerequisites for Attack

1. **DNS Control**: Traffic must reach your DNS server (ARP spoof, rogue DHCP, network position)
2. **Network Path**: Target traffic must be routable through attacker machine
3. **CA Installation**: Target must trust your CA certificate (or ignore warnings)
4. **Port Access**: Access to port 53 (DNS) and proxy port (8080/8443)

## Next Steps

- [DNS Hijacking](/domains/mitm/01-dns-hijacking.md) - Configure DNS hijacking server
- [TLS Interception](/domains/mitm/02-tls-interception.md) - Set up TLS proxy
- [Interactive Shell](/domains/mitm/03-shell.md) - Use the TUI interface
- [Certificates](/domains/mitm/04-certificates.md) - Manage CA certificates
- [Attack Scenarios](/domains/mitm/05-scenarios.md) - Real-world examples
- [Configuration](/domains/mitm/06-configuration.md) - All options reference
