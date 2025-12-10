# TLS Configuration

Configure TLS scanning behavior via config file, environment variables, or flags.

## Configuration File

```yaml
# .redblue.yaml
tls:
  # Default port for TLS connections
  # Default: 443
  default_port: 443

  # Connection timeout in seconds
  # Range: 1-60
  # Default: 10
  timeout_secs: 10

  # Minimum acceptable TLS version for grading
  # Values: "1.0", "1.1", "1.2", "1.3"
  # Default: "1.2"
  min_tls_version: "1.2"

  # Auto-save results to database
  # Default: false
  auto_persist: false

  # Output format
  # Values: "text", "json"
  # Default: "text"
  output: "text"
```

## Environment Variables

```bash
# Default port
export REDBLUE_TLS_DEFAULT_PORT=443

# Timeout
export REDBLUE_TLS_TIMEOUT=15

# Minimum version
export REDBLUE_TLS_MIN_VERSION="1.2"

# Auto-persist
export REDBLUE_TLS_AUTO_PERSIST=true
```

## Port Presets

### Common TLS Ports

| Port | Service | Command |
|------|---------|---------|
| 443 | HTTPS | `rb tls security audit host` |
| 465 | SMTPS | `rb tls security audit host:465` |
| 993 | IMAPS | `rb tls security audit host:993` |
| 995 | POP3S | `rb tls security audit host:995` |
| 636 | LDAPS | `rb tls security audit host:636` |
| 8443 | Alt HTTPS | `rb tls security audit host:8443` |

### Usage

```bash
# Default (443)
rb tls security audit example.com

# Email services
rb tls security audit mail.example.com:465
rb tls security audit mail.example.com:993

# Custom application
rb tls security audit app.example.com:8443
```

## Timeout Configuration

### Global Timeout

```yaml
# .redblue.yaml
tls:
  timeout_secs: 30  # Increase for slow servers
```

### Per-Command Timeout

```bash
# Override for slow servers
rb tls security audit slow-server.com --timeout 60

# Quick check
rb tls security audit fast-server.com --timeout 5
```

### Recommendations

| Network | Timeout | Notes |
|---------|---------|-------|
| Local | 5 | Fast connections |
| Corporate | 15 | Firewalls may delay |
| Internet | 10 | Default |
| Slow servers | 30-60 | Legacy systems |

## Grading Configuration

### Minimum TLS Version

```yaml
# .redblue.yaml
tls:
  min_tls_version: "1.2"  # Servers with 1.0/1.1 get lower grades
```

### Grade Impact

| Setting | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|---------|---------|
| min: "1.0" | OK | OK | OK | OK |
| min: "1.1" | Warn | OK | OK | OK |
| min: "1.2" | Fail | Warn | OK | OK |
| min: "1.3" | Fail | Fail | Warn | OK |

## Persistence Configuration

### Auto-Persist

```yaml
# .redblue.yaml
tls:
  auto_persist: true  # Always save results
```

### Database Location

```yaml
# .redblue.yaml
storage:
  data_dir: ~/.redblue/data
```

### Per-Command Override

```bash
# Force persist
rb tls security audit example.com --persist

# Force no persist
rb tls security audit example.com --no-persist
```

## Profile Examples

### Security Audit (Strict)

```yaml
# .redblue.yaml
tls:
  timeout_secs: 10
  min_tls_version: "1.2"
  auto_persist: true
  output: "json"
```

### Bug Bounty (Fast)

```yaml
# .redblue.yaml
tls:
  timeout_secs: 5
  min_tls_version: "1.0"  # Check everything
  auto_persist: false
  output: "text"
```

### Compliance (PCI-DSS)

```yaml
# .redblue.yaml
tls:
  timeout_secs: 15
  min_tls_version: "1.2"  # PCI-DSS requirement
  auto_persist: true
  output: "json"
```

### Legacy Systems

```yaml
# .redblue.yaml
tls:
  timeout_secs: 60
  min_tls_version: "1.0"  # Accept old systems
  auto_persist: true
```

## Cipher Configuration

### Cipher Strength Thresholds

```yaml
# .redblue.yaml (future)
tls:
  cipher_policy:
    # Fail if weak ciphers found
    fail_on_weak: true
    # Warn if medium ciphers found
    warn_on_medium: true
    # Minimum key size (bits)
    min_key_size: 2048
```

### Custom Cipher Lists

```yaml
# .redblue.yaml (future)
tls:
  required_ciphers:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  banned_ciphers:
    - TLS_RSA_WITH_3DES_EDE_CBC_SHA
    - TLS_RSA_WITH_RC4_128_SHA
```

## Configuration Precedence

Configuration applies in this order (later overrides earlier):

1. Built-in defaults
2. Global config (`~/.config/redblue/config.yaml`)
3. Project config (`./.redblue.yaml`)
4. Environment variables (`REDBLUE_TLS_*`)
5. Command-line flags (`--timeout`, `--port`, etc.)

```bash
# Config sets timeout=10
# Environment sets timeout=20
# Flag overrides to 30
export REDBLUE_TLS_TIMEOUT=20
rb tls security audit example.com --timeout 30
# Result: timeout = 30
```

## Server Configuration Examples

### Nginx (Recommended)

```nginx
# Modern configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000" always;
```

### Apache (Recommended)

```apache
# Modern configuration
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off

# HSTS
Header always set Strict-Transport-Security "max-age=63072000"
```

### HAProxy (Recommended)

```haproxy
# Modern configuration
ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
```

## Resources

- **Mozilla SSL Config**: https://ssl-config.mozilla.org/
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **CipherSuite.info**: https://ciphersuite.info/

## Next Steps

- [TLS Audit](/domains/tls/01-audit.md) - Full security audit
- [Cipher Enumeration](/domains/tls/02-ciphers.md) - List cipher suites
- [Vulnerability Scanning](/domains/tls/03-vulnerabilities.md) - Find CVEs
