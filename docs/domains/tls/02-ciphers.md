# Cipher Enumeration

List and analyze TLS cipher suites by strength.

## Quick Start

```bash
# Enumerate all ciphers
rb tls security ciphers google.com

# Custom port
rb tls security ciphers example.com:8443

# JSON output
rb tls security ciphers example.com -o json
```

## Command

### ciphers - Cipher Suite Enumeration

Enumerate all supported TLS cipher suites grouped by strength.

```bash
rb tls security ciphers <host[:port]> [flags]
```

## Options

```rust
// Cipher enumeration options
struct CipherOptions {
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

## Cipher Strength Categories

### Strong (Green ✓)

| Cipher | Code | Notes |
|--------|------|-------|
| TLS_AES_128_GCM_SHA256 | 0x1301 | TLS 1.3 |
| TLS_AES_256_GCM_SHA384 | 0x1302 | TLS 1.3 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | TLS 1.3 |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | 0xC02F | AEAD |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | 0xC030 | AEAD |
| TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | 0xC02B | AEAD |
| TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 | 0xCCA8 | AEAD |

### Medium (Yellow ●)

| Cipher | Code | Notes |
|--------|------|-------|
| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 | 0xC027 | CBC mode |
| TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 | 0xC028 | CBC mode |
| TLS_RSA_WITH_AES_128_GCM_SHA256 | 0x009C | No PFS |
| TLS_RSA_WITH_AES_256_GCM_SHA384 | 0x009D | No PFS |

### Weak (Red ✗)

| Cipher | Code | Risk |
|--------|------|------|
| TLS_RSA_WITH_3DES_EDE_CBC_SHA | 0x000A | Sweet32 |
| TLS_RSA_WITH_RC4_128_SHA | 0x0005 | RC4 broken |
| TLS_RSA_EXPORT_WITH_RC4_40_MD5 | 0x0003 | Export |
| TLS_NULL_WITH_NULL_NULL | 0x0000 | No encryption |

## Examples

### Basic Enumeration

```bash
# Default HTTPS port
rb tls security ciphers google.com

# Mail server
rb tls security ciphers mail.example.com:465
```

### Output Formats

```bash
# Text (default)
rb tls security ciphers example.com

# JSON for automation
rb tls security ciphers example.com -o json

# Extract strong ciphers only
rb tls security ciphers example.com -o json | \
  jq '.ciphers[] | select(.strength == "strong")'
```

## Output Examples

### Text Output

```
Enumerating cipher suites... ✓

TLS Cipher Enumeration: google.com:443

Cipher Suites Summary (Total: 15)
  ● Strong:  12
  ● Medium:  3
  ● Weak:    0

Strong Ciphers (12)
  ✓ TLS_AES_128_GCM_SHA256 (0x1301)
  ✓ TLS_AES_256_GCM_SHA384 (0x1302)
  ✓ TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  ✓ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
  ✓ TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)
  ✓ TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
  ✓ TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)
  ✓ TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9)
  ✓ TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8)
  ... (3 more)

Medium Strength Ciphers (3)
  ● TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xC027)
  ● TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xC028)
  ● TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C)

Weak Ciphers (0)
  None - Good!
```

### JSON Output

```json
{
  "host": "google.com",
  "port": 443,
  "summary": {
    "total": 15,
    "strong": 12,
    "medium": 3,
    "weak": 0
  },
  "ciphers": [
    {
      "name": "TLS_AES_128_GCM_SHA256",
      "code": "0x1301",
      "strength": "strong",
      "tls_version": "1.3",
      "key_exchange": null,
      "authentication": null,
      "encryption": "AES-128-GCM",
      "mac": "AEAD"
    },
    {
      "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "code": "0xC02F",
      "strength": "strong",
      "tls_version": "1.2",
      "key_exchange": "ECDHE",
      "authentication": "RSA",
      "encryption": "AES-128-GCM",
      "mac": "AEAD"
    }
  ]
}
```

## Cipher Components

### Key Exchange

| Type | Security | Notes |
|------|----------|-------|
| ECDHE | ✅ Strong | Forward secrecy |
| DHE | ✅ Strong | Forward secrecy |
| RSA | ⚠️ Medium | No forward secrecy |
| EXPORT | ❌ Weak | Broken |

### Authentication

| Type | Security | Notes |
|------|----------|-------|
| ECDSA | ✅ Strong | Elliptic curve |
| RSA | ✅ Strong | Standard |
| anon | ❌ Weak | No authentication |

### Encryption

| Type | Security | Notes |
|------|----------|-------|
| AES-256-GCM | ✅ Strong | AEAD |
| AES-128-GCM | ✅ Strong | AEAD |
| ChaCha20-Poly1305 | ✅ Strong | AEAD |
| AES-256-CBC | ⚠️ Medium | Block cipher |
| AES-128-CBC | ⚠️ Medium | Block cipher |
| 3DES | ❌ Weak | Sweet32 |
| RC4 | ❌ Weak | Broken |
| NULL | ❌ Weak | No encryption |

### MAC

| Type | Security | Notes |
|------|----------|-------|
| AEAD | ✅ Strong | Authenticated encryption |
| SHA384 | ✅ Strong | HMAC |
| SHA256 | ✅ Strong | HMAC |
| SHA1 | ⚠️ Medium | Legacy |
| MD5 | ❌ Weak | Broken |

## Patterns

### Find Weak Ciphers

```bash
# Check for weak ciphers
rb tls security ciphers example.com -o json | \
  jq '.ciphers[] | select(.strength == "weak")'

# Count weak ciphers
rb tls security ciphers example.com -o json | \
  jq '.summary.weak'
```

### Compare Configurations

```bash
# Server A
rb tls security ciphers server-a.com -o json > server-a.json

# Server B
rb tls security ciphers server-b.com -o json > server-b.json

# Compare cipher lists
diff \
  <(jq -r '.ciphers[].name' server-a.json | sort) \
  <(jq -r '.ciphers[].name' server-b.json | sort)
```

### Filter by TLS Version

```bash
# TLS 1.3 ciphers only
rb tls security ciphers example.com -o json | \
  jq '.ciphers[] | select(.tls_version == "1.3")'

# TLS 1.2 ciphers
rb tls security ciphers example.com -o json | \
  jq '.ciphers[] | select(.tls_version == "1.2")'
```

### Forward Secrecy Check

```bash
# Check for PFS
rb tls security ciphers example.com -o json | \
  jq '.ciphers[] | select(.key_exchange | test("ECDHE|DHE"))'

# Non-PFS ciphers
rb tls security ciphers example.com -o json | \
  jq '.ciphers[] | select(.key_exchange == "RSA")'
```

## Recommended Cipher Suites

### Modern (TLS 1.3)

```
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256
```

### Intermediate (TLS 1.2)

```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

## Next Steps

- [TLS Audit](01-audit.md) - Full security audit
- [Vulnerability Scanning](03-vulnerabilities.md) - Find CVEs
- [Configuration](04-configuration.md) - TLS settings
