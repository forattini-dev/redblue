# DNS Configuration

Configure DNS query behavior via config file, environment variables, or flags.

## Configuration File

```yaml
# .redblue.yaml
dns:
  # Default DNS server
  # Default: "8.8.8.8"
  default_server: "8.8.8.8"

  # Query timeout in milliseconds
  # Range: 100-30000
  # Default: 5000
  timeout_ms: 5000

  # Retry count on failure
  # Range: 0-10
  # Default: 2
  retry_count: 2

  # Fallback DNS servers
  fallback_servers:
    - "1.1.1.1"
    - "208.67.222.222"
```

## Environment Variables

```bash
# DNS server
export REDBLUE_DNS_SERVER="1.1.1.1"

# Timeout
export REDBLUE_DNS_TIMEOUT_MS=3000
```

## DNS Server Presets

### Public DNS

| Provider | Primary | Secondary |
|----------|---------|-----------|
| Google | 8.8.8.8 | 8.8.4.4 |
| Cloudflare | 1.1.1.1 | 1.0.0.1 |
| OpenDNS | 208.67.222.222 | 208.67.220.220 |
| Quad9 | 9.9.9.9 | 149.112.112.112 |

### Usage

```bash
# Google (default)
rb dns lookup record example.com

# Cloudflare
rb dns lookup record example.com --server 1.1.1.1

# OpenDNS
rb dns lookup record example.com --server 208.67.222.222
```

## Corporate Environment

```yaml
# .redblue.yaml
dns:
  default_server: "10.0.0.53"  # Internal DNS
  timeout_ms: 10000  # Longer timeout
  fallback_servers:
    - "10.0.0.54"
    - "8.8.8.8"  # External fallback
```

## Next Steps

- [DNS Lookups](/domains/dns/01-lookup.md) - Query DNS records
