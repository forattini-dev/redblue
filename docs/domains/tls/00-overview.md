# TLS Domain

TLS/SSL security auditing, cipher enumeration, and vulnerability scanning.

## Quick Start

```bash
# Full TLS security audit
rb tls security audit google.com

# Enumerate cipher suites
rb tls security ciphers example.com

# Scan for vulnerabilities
rb tls security vuln example.com
```

## Resources

| Resource | Description |
|----------|-------------|
| [security](/domains/tls/01-audit.md) | TLS auditing and testing |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| openssl s_client | `rb tls security audit` |
| testssl.sh | `rb tls security vuln` |
| sslyze | `rb tls security audit` |
| sslscan | `rb tls security ciphers` |

## Command Matrix

```
rb tls <verb> <resource> [target] [flags]
       │      │
       │      └── security
       └───────── audit, ciphers, vuln
```

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| TLS 1.2 handshake | ✅ Done | Pure Rust |
| Certificate parsing | ✅ Done | X.509 support |
| Cipher enumeration | ✅ Done | All standard suites |
| Vulnerability scan | ✅ Done | 8 CVEs checked |
| TLS 1.3 | 🚧 In Progress | Debugging phase |

## Security Grades

| Grade | Meaning |
|-------|---------|
| A+ | Excellent - Best practices |
| A | Very Good - Strong security |
| B | Good - Minor issues |
| C | Fair - Some weaknesses |
| D | Poor - Significant issues |
| F | Critical - Major vulnerabilities |

## Next Steps

- [TLS Audit](/domains/tls/01-audit.md) - Full security audit
- [Cipher Enumeration](/domains/tls/02-ciphers.md) - List cipher suites
- [Vulnerability Scanning](/domains/tls/03-vulnerabilities.md) - Find CVEs
- [Configuration](/domains/tls/04-configuration.md) - TLS settings
