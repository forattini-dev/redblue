# Configuration

redblue uses a flexible YAML configuration system with global defaults and per-domain overrides.

## Configuration File

Configuration is **project-based** and loaded from your current working directory:

```
./.redblue.yaml      # Project configuration
./.redblue.yml       # Alternative extension
```

## Quick Setup

```bash
# Generate default configuration
rb config create init --output .redblue.yaml
```

## Full Configuration Example

```yaml
# .redblue.yaml

network:
  threads: 200              # Concurrent scanner threads
  timeout_ms: 1000          # Connection timeout
  dns_resolver: "8.8.8.8"   # Default DNS server
  request_delay_ms: 0       # Rate limiting delay

dns:
  timeout_ms: 2000          # DNS query timeout
  retry_count: 3            # Retries on failure
  default_server: "8.8.8.8"
  fallback_servers:
    - "1.1.1.1"
    - "208.67.222.222"

web:
  timeout_secs: 10          # HTTP timeout
  user_agent: "redblue/1.0"
  follow_redirects: true
  max_redirects: 5
  verify_ssl: true

tls:
  timeout_secs: 5
  min_tls_version: "1.2"    # 1.0, 1.1, 1.2, 1.3

output:
  format: "text"            # text|json|yaml
  color: true
  verbose: false
  timestamps: false

storage:
  database_path: "./data"
  max_size_mb: 1024
  retention_days: 30
```

## Configuration Precedence

```
1. Command-line flags (highest priority)
   rb network scan ports 192.168.1.1 --threads 500

2. Environment variables
   export REDBLUE_NETWORK_THREADS=300

3. Project config file (./.redblue.yaml)

4. Default values (lowest priority)
```

## Environment Variables

```bash
# Network settings
export REDBLUE_NETWORK_THREADS=300
export REDBLUE_NETWORK_TIMEOUT_MS=2000

# Web settings
export REDBLUE_WEB_TIMEOUT_SECS=15

# Output format
export REDBLUE_OUTPUT_FORMAT="json"
```

## Common Presets

### Fast Scanning (Aggressive)

```yaml
network:
  threads: 1000
  timeout_ms: 500
```

### Stealthy Scanning

```yaml
network:
  threads: 10
  timeout_ms: 5000
  request_delay_ms: 100
```

### Corporate Environment

```yaml
network:
  dns_resolver: "10.0.0.1"  # Internal DNS

web:
  verify_ssl: false         # Self-signed certs
  timeout_secs: 30
```

## Per-Project Organization

```bash
~/engagements/
├── client-a/
│   ├── .redblue.yaml      # Client A config
│   └── targets/
├── client-b/
│   └── .redblue.yaml      # Client B config
└── internal-audit/
    └── .redblue.yaml      # Internal config
```

Changes take effect immediately - no restart required.
