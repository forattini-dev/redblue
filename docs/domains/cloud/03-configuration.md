# Cloud Configuration

Configure cloud security scanning behavior.

## Configuration File

```yaml
# .redblue.yaml
cloud:
  takeover:
    # Default confidence level for filtering
    # Values: "high", "medium", "low"
    # Default: "low"
    min_confidence: low

    # Timeout for DNS resolution (seconds)
    # Range: 1-30
    # Default: 5
    dns_timeout: 5

    # Timeout for HTTP checks (seconds)
    # Range: 1-60
    # Default: 10
    http_timeout: 10

    # Maximum concurrent checks (bulk scan)
    # Range: 1-200
    # Default: 50
    max_concurrent: 50

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
# Confidence level
export REDBLUE_CLOUD_MIN_CONFIDENCE=high

# Timeouts
export REDBLUE_CLOUD_DNS_TIMEOUT=10
export REDBLUE_CLOUD_HTTP_TIMEOUT=15

# Concurrency
export REDBLUE_CLOUD_MAX_CONCURRENT=100

# Persistence
export REDBLUE_CLOUD_AUTO_PERSIST=true
```

## Timeout Configuration

### DNS Timeout

```yaml
# .redblue.yaml
cloud:
  takeover:
    dns_timeout: 10  # Increase for slow DNS
```

### HTTP Timeout

```yaml
# .redblue.yaml
cloud:
  takeover:
    http_timeout: 30  # Increase for slow services
```

### Recommendations

| Network | DNS Timeout | HTTP Timeout |
|---------|-------------|--------------|
| Fast | 5 | 10 |
| Normal | 10 | 15 |
| Slow/Proxy | 15 | 30 |

## Concurrency Configuration

### Global Setting

```yaml
# .redblue.yaml
cloud:
  takeover:
    max_concurrent: 100
```

### Per-Environment

| Environment | Concurrency | Notes |
|-------------|-------------|-------|
| Local/Lab | 100-200 | Fast, no limits |
| Corporate | 20-50 | Avoid detection |
| Bug Bounty | 30-50 | Be polite |
| Rate-limited | 10-20 | Prevent blocking |

## Confidence Configuration

### Default Level

```yaml
# .redblue.yaml
cloud:
  takeover:
    min_confidence: medium  # Only show medium+ findings
```

### Per-Command Override

```bash
# Show all findings
rb cloud asset takeover-scan -w subs.txt --confidence low

# Only high confidence
rb cloud asset takeover-scan -w subs.txt --confidence high
```

## Profile Examples

### Bug Bounty (Balanced)

```yaml
# .redblue.yaml
cloud:
  takeover:
    min_confidence: medium
    dns_timeout: 10
    http_timeout: 15
    max_concurrent: 30
  auto_persist: true
  output: json
```

### Security Audit (Thorough)

```yaml
# .redblue.yaml
cloud:
  takeover:
    min_confidence: low
    dns_timeout: 15
    http_timeout: 30
    max_concurrent: 20
  auto_persist: true
```

### CI/CD Pipeline (Fast)

```yaml
# .redblue.yaml
cloud:
  takeover:
    min_confidence: high
    dns_timeout: 5
    http_timeout: 10
    max_concurrent: 100
  auto_persist: false
  output: json
```

### Internal Network (Careful)

```yaml
# .redblue.yaml
cloud:
  takeover:
    min_confidence: low
    dns_timeout: 15
    http_timeout: 30
    max_concurrent: 10
  auto_persist: true
```

## Custom Service Fingerprints

### Adding Services (Future)

```yaml
# .redblue.yaml (future)
cloud:
  takeover:
    custom_fingerprints:
      - name: "MyService"
        cname_pattern: ".myservice.io"
        error_fingerprint: "Service not found"
        confidence: high
```

## Persistence Configuration

### Auto-Persist

```yaml
# .redblue.yaml
cloud:
  auto_persist: true
```

### Database Location

```yaml
# .redblue.yaml
storage:
  data_dir: ~/.redblue/data
  # Results saved as: ~/.redblue/data/cloud-scan.rdb
```

## Configuration Precedence

Configuration applies in this order (later overrides earlier):

1. Built-in defaults
2. Global config (`~/.config/redblue/config.yaml`)
3. Project config (`./.redblue.yaml`)
4. Environment variables (`REDBLUE_CLOUD_*`)
5. Command-line flags (`--confidence`, `--concurrency`, etc.)

```bash
# Config sets concurrency=50
# Environment sets concurrency=100
# Flag overrides to 200
export REDBLUE_CLOUD_MAX_CONCURRENT=100
rb cloud asset takeover-scan -w subs.txt --concurrency 200
# Result: concurrency = 200
```

## Rate Limiting

### Automatic Backoff

```yaml
# .redblue.yaml (future)
cloud:
  takeover:
    rate_limit:
      # Requests per second
      requests_per_second: 10
      # Backoff on errors
      backoff_enabled: true
      # Initial backoff delay (ms)
      backoff_initial: 1000
      # Maximum backoff delay (ms)
      backoff_max: 30000
```

### Manual Throttling

```bash
# Lower concurrency to reduce rate
rb cloud asset takeover-scan -w subs.txt --concurrency 10
```

## Next Steps

- [Subdomain Takeover](01-takeover.md) - Detect takeover vulnerabilities
- [Batch Scanning](02-batch.md) - Scan multiple subdomains
