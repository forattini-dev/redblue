# Web Configuration

Configure HTTP client behavior via config file, environment variables, or flags.

## Configuration File

```yaml
# .redblue.yaml
web:
  # Default request timeout in seconds
  # Range: 1-300
  # Default: 10
  timeout_secs: 10

  # Default User-Agent string
  # Default: "redblue/1.0"
  user_agent: "redblue/1.0"

  # Follow HTTP redirects
  # Default: true
  follow_redirects: true

  # Maximum redirects to follow
  # Range: 0-20
  # Default: 5
  max_redirects: 5

  # Verify SSL certificates
  # Default: true
  verify_ssl: true

  # Default output format
  # Values: "text", "json", "raw"
  # Default: "text"
  output: "text"

  # Proxy configuration
  proxy:
    # HTTP proxy URL
    http: ""
    # HTTPS proxy URL
    https: ""
    # No proxy list
    no_proxy: ["localhost", "127.0.0.1"]
```

## Environment Variables

```bash
# Timeout
export REDBLUE_WEB_TIMEOUT=30

# User-Agent
export REDBLUE_WEB_USER_AGENT="Mozilla/5.0"

# Proxy
export REDBLUE_WEB_PROXY_HTTP="http://proxy.local:8080"
export REDBLUE_WEB_PROXY_HTTPS="http://proxy.local:8080"

# SSL verification
export REDBLUE_WEB_VERIFY_SSL=false
```

## User-Agent Presets

### Common User-Agents

| Preset | Value |
|--------|-------|
| `chrome` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 |
| `firefox` | Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0 |
| `safari` | Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 |
| `curl` | curl/8.4.0 |
| `wget` | Wget/1.21.4 |
| `googlebot` | Googlebot/2.1 (+http://www.google.com/bot.html) |

### Usage

```bash
# Chrome User-Agent
rb web get asset http://example.com -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Googlebot
rb web get asset http://example.com -A "Googlebot/2.1"
```

## Proxy Configuration

### HTTP Proxy

```yaml
# .redblue.yaml
web:
  proxy:
    http: "http://proxy.company.com:8080"
    https: "http://proxy.company.com:8080"
```

### Authenticated Proxy

```yaml
# .redblue.yaml
web:
  proxy:
    http: "http://user:password@proxy.company.com:8080"
```

### SOCKS Proxy

```yaml
# .redblue.yaml
web:
  proxy:
    http: "socks5://127.0.0.1:9050"  # Tor
```

### Bypass Proxy

```yaml
# .redblue.yaml
web:
  proxy:
    no_proxy:
      - "localhost"
      - "127.0.0.1"
      - "*.internal.company.com"
      - "10.0.0.0/8"
```

## SSL/TLS Configuration

### Skip Certificate Verification

```yaml
# .redblue.yaml
web:
  verify_ssl: false  # NOT recommended for production
```

```bash
# Per-command override
rb web get asset https://self-signed.example.com --insecure
```

### Custom CA Certificate

```yaml
# .redblue.yaml
web:
  ca_cert: "/path/to/custom-ca.pem"
```

## Timeout Configuration

### Global Timeout

```yaml
# .redblue.yaml
web:
  timeout_secs: 30
```

### Per-Command Timeout

```bash
# Override for slow servers
rb web get asset http://slow-server.com --timeout 60

# Quick check
rb web headers asset http://example.com --timeout 5
```

## Redirect Configuration

### Follow Redirects

```yaml
# .redblue.yaml
web:
  follow_redirects: true
  max_redirects: 10
```

### Disable Redirects

```bash
# Don't follow redirects
rb web get asset http://example.com --follow=false

# Limit redirects
rb web get asset http://example.com --max-redirects 3
```

## Header Defaults

### Default Headers

```yaml
# .redblue.yaml
web:
  default_headers:
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    Accept-Language: "en-US,en;q=0.5"
    Accept-Encoding: "gzip, deflate"
    Connection: "keep-alive"
```

### Authentication Headers

```yaml
# .redblue.yaml
web:
  default_headers:
    Authorization: "Bearer ${REDBLUE_API_TOKEN}"
```

## Rate Limiting

### Request Throttling

```yaml
# .redblue.yaml
web:
  rate_limit:
    # Requests per second
    # Range: 0.1-1000
    # Default: 10
    requests_per_second: 10

    # Delay between requests (ms)
    # Range: 0-10000
    # Default: 100
    delay_ms: 100
```

## Output Configuration

### Default Output Format

```yaml
# .redblue.yaml
web:
  output: "json"  # Always JSON output
```

### Per-Command Override

```bash
# Override to text
rb web get asset http://example.com -o text

# Override to raw
rb web get asset http://example.com -o raw
```

## Profile Examples

### Penetration Testing

```yaml
# .redblue.yaml
web:
  timeout_secs: 30
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  follow_redirects: true
  max_redirects: 10
  verify_ssl: false  # For testing
  rate_limit:
    requests_per_second: 5
```

### Bug Bounty

```yaml
# .redblue.yaml
web:
  timeout_secs: 15
  user_agent: "BugBountyResearch/1.0 (+https://hackerone.com/yourprofile)"
  follow_redirects: true
  verify_ssl: true
  rate_limit:
    requests_per_second: 2  # Be polite
```

### Corporate Network

```yaml
# .redblue.yaml
web:
  timeout_secs: 60
  proxy:
    http: "http://proxy.corp.local:8080"
    https: "http://proxy.corp.local:8080"
    no_proxy: ["*.corp.local", "10.0.0.0/8"]
  ca_cert: "/etc/ssl/certs/corp-ca.pem"
```

### Tor Network

```yaml
# .redblue.yaml
web:
  proxy:
    http: "socks5://127.0.0.1:9050"
    https: "socks5://127.0.0.1:9050"
  timeout_secs: 60  # Tor is slow
```

## Configuration Precedence

Configuration is applied in this order (later overrides earlier):

1. Default values (built-in)
2. Config file (`~/.redblue.yaml` or `./.redblue.yaml`)
3. Environment variables (`REDBLUE_WEB_*`)
4. Command-line flags (`--timeout`, `-A`, etc.)

```bash
# Config file sets timeout=10
# Environment sets timeout=20
# Flag overrides to 30
export REDBLUE_WEB_TIMEOUT=20
rb web get asset http://example.com --timeout 30
# Result: timeout = 30
```

## Next Steps

- [HTTP Requests](01-requests.md) - Make HTTP requests
- [Security Audit](02-security.md) - Security headers analysis
- [CMS Scanning](03-cms.md) - CMS detection and scanning
