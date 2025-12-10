# TLS Security Audit

Comprehensive TLS/SSL security testing and validation.

## Quick Start

```bash
# Basic TLS audit
rb tls security audit google.com

# Audit custom port
rb tls security audit example.com:8443

# JSON output
rb tls security audit api.example.com -o json
```

## Command

### audit - Full TLS Security Audit

Perform comprehensive TLS security audit including version detection, cipher enumeration, and certificate validation.

```bash
rb tls security audit <host[:port]> [flags]
```

## Options

```rust
// TLS audit options
struct TlsAuditOptions {
    // Target port
    // Default: 443
    port: u16,

    // Connection timeout in seconds
    // Range: 1-60
    // Default: 10
    timeout_secs: u32,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,

    // Save results to database
    // Default: false
    persist: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--port` | `-p` | Target port | 443 |
| `--timeout` | `-t` | Connection timeout (secs) | 10 |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |
| `--no-persist` | | Don't save | - |

## What Gets Audited

### TLS Versions

| Version | Status | Security |
|---------|--------|----------|
| TLS 1.3 | ✅ Good | Secure |
| TLS 1.2 | ✅ Good | Secure |
| TLS 1.1 | ⚠️ Deprecated | Weak |
| TLS 1.0 | ⚠️ Deprecated | Weak |
| SSL 3.0 | ❌ Insecure | Vulnerable |

### Cipher Suites

| Category | Examples |
|----------|----------|
| Strong | AES-GCM, ChaCha20-Poly1305 |
| Medium | AES-CBC with SHA256 |
| Weak | RC4, 3DES, Export ciphers |

### Certificate

| Check | Description |
|-------|-------------|
| Chain validity | Proper certificate chain |
| Expiration | Not expired |
| Self-signed | Warning if self-signed |
| Key size | RSA 2048+, ECDSA 256+ |

## Examples

### Basic Audit

```bash
# Standard HTTPS port
rb tls security audit google.com

# Explicit port
rb tls security audit google.com:443
```

### Different Ports

```bash
# SMTP TLS
rb tls security audit mail.example.com:465

# IMAP TLS
rb tls security audit mail.example.com:993

# Custom application
rb tls security audit app.example.com:8443
```

### Output Formats

```bash
# Text (default)
rb tls security audit example.com

# JSON for automation
rb tls security audit example.com -o json

# Save to database
rb tls security audit example.com --persist
```

## Output Examples

### Text Output (Secure)

```
Running TLS audit... ✓

TLS Security Audit: google.com:443

Supported TLS Versions
  ✓ TLS 1.3
  ✓ TLS 1.2
  ✗ TLS 1.1 (Connection refused)
  ✗ TLS 1.0 (Connection refused)

Supported Cipher Suites (15)
  ● STRONG TLS_AES_128_GCM_SHA256 (0x1301)
  ● STRONG TLS_AES_256_GCM_SHA384 (0x1302)
  ● STRONG TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  ● STRONG TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
  ● STRONG TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
  ... (10 more)

✓ No known vulnerabilities detected

Certificate Validation
  ✓ Certificate chain is valid
  Chain length: 3 certificate(s)

Security Grade: A
```

### Text Output (Issues Found)

```
TLS Security Audit: legacy.example.com:443

Supported TLS Versions
  ✓ TLS 1.3
  ✓ TLS 1.2
  ⚠ TLS 1.1 (Deprecated)
  ⚠ TLS 1.0 (Deprecated)

Supported Cipher Suites (24)
  ● STRONG (12 ciphers)
  ● MEDIUM (8 ciphers)
  ● WEAK (4 ciphers) ⚠

⚠ Warnings
  - TLS 1.0 and 1.1 are deprecated
  - 4 weak cipher suites enabled

Certificate Validation
  ✓ Certificate chain is valid
  ⚠ Certificate expires in 15 days

Security Grade: C
```

### JSON Output

```json
{
  "host": "google.com",
  "port": 443,
  "grade": "A",
  "tls_versions": {
    "tls_1_3": true,
    "tls_1_2": true,
    "tls_1_1": false,
    "tls_1_0": false,
    "ssl_3_0": false
  },
  "cipher_suites": {
    "total": 15,
    "strong": 12,
    "medium": 3,
    "weak": 0,
    "suites": [
      {
        "name": "TLS_AES_128_GCM_SHA256",
        "code": "0x1301",
        "strength": "strong"
      }
    ]
  },
  "vulnerabilities": [],
  "certificate": {
    "valid": true,
    "chain_length": 3,
    "expires_in_days": 89,
    "self_signed": false
  }
}
```

## Security Grades

| Grade | Criteria |
|-------|----------|
| A+ | TLS 1.3 only, strong ciphers, HSTS |
| A | TLS 1.2+, strong ciphers only |
| B | TLS 1.2+, some medium ciphers |
| C | TLS 1.0/1.1 enabled |
| D | Weak ciphers enabled |
| F | Critical vulnerabilities |

## Patterns

### Compliance Audit

```bash
# PCI-DSS compliance check
rb tls security audit payment.example.com -o json | \
  jq '{
    tls_1_0: .tls_versions.tls_1_0,
    tls_1_1: .tls_versions.tls_1_1,
    weak_ciphers: .cipher_suites.weak,
    grade: .grade
  }'

# Fail if TLS 1.0/1.1 enabled
rb tls security audit payment.example.com -o json | \
  jq -e '.tls_versions.tls_1_0 == false and .tls_versions.tls_1_1 == false'
```

### Before/After Hardening

```bash
# Before hardening
rb tls security audit server.example.com -o json > before.json

# Apply hardening...

# After hardening
rb tls security audit server.example.com -o json > after.json

# Compare
diff <(jq '.grade' before.json) <(jq '.grade' after.json)
```

### Batch Audit

```bash
# Audit multiple hosts
for host in $(cat hosts.txt); do
  echo "=== $host ==="
  rb tls security audit "$host" --persist
done

# Export all results
rb database data export all-hosts.rdb
```

### Certificate Monitoring

```bash
# Check certificate expiration
rb tls security audit example.com -o json | \
  jq '.certificate.expires_in_days'

# Alert if expiring soon
DAYS=$(rb tls security audit example.com -o json | jq '.certificate.expires_in_days')
if [ "$DAYS" -lt 30 ]; then
  echo "Certificate expires in $DAYS days!"
fi
```

## Troubleshooting

### Connection Refused

```bash
# Verify port is open
rb network ports scan example.com --preset web

# Try different port
rb tls security audit example.com:8443
```

### Timeout

```bash
# Increase timeout
rb tls security audit slow-server.com --timeout 30
```

### SSL/TLS Mismatch

```bash
# Server might require specific version
# Check what's supported
rb tls security ciphers example.com
```

## Next Steps

- [Cipher Enumeration](/domains/tls/02-ciphers.md) - List cipher suites
- [Vulnerability Scanning](/domains/tls/03-vulnerabilities.md) - Find CVEs
- [Configuration](/domains/tls/04-configuration.md) - TLS settings
