# Changelog

All notable changes to redblue will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure
- Core CLI framework with kubectl-style commands
- Network scanning capabilities
- DNS resolution and lookup
- Web security testing
- TLS certificate inspection
- WHOIS lookups
- RESTful command structure
- Database persistence with .rdb files
- Configuration system

## [0.1.0] - TBD

### Added
- **Network Module**
  - Port scanner with multi-threading (200 threads default)
  - Service detection for common ports
  - Port presets: common, full, web
  - Traceroute structure (MTR-style)

- **DNS Module**
  - RFC 1035 compliant DNS client
  - Support for A, AAAA, MX, NS, TXT, CNAME records
  - Quick domain resolution

- **Web Module**
  - HTTP/1.1 client (GET/POST)
  - Header analysis
  - Security headers audit
  - TLS certificate inspection

- **Recon Module**
  - WHOIS lookup (RFC 3912)
  - Multi-TLD support

- **Developer Experience**
  - kubectl-style CLI
  - Colored output with semantic colors
  - Smart validation with helpful error messages
  - Contextual help system
  - Auto-suggestions for typos
  - Progress indicators

### Technical
- Zero external dependencies (Rust std only)
- Binary size: ~427KB
- Pure Rust implementations of all protocols
- Multi-platform support (Linux, macOS, Windows)

[Unreleased]: https://github.com/forattini-dev/redblue/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/forattini-dev/redblue/releases/tag/v0.1.0
