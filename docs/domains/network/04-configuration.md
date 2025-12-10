# Network Configuration

Configure network scanning behavior via config file, environment variables, or flags.

## Configuration File

Create `.redblue.yaml` in your project directory:

```yaml
network:
  # Default scanner threads
  # Range: 1-10000
  # Default: 200
  threads: 200

  # Connection timeout in milliseconds
  # Range: 100-30000
  # Default: 1000
  timeout_ms: 1000

  # DNS server for resolution
  # Default: "8.8.8.8"
  dns_resolver: "8.8.8.8"

  # Delay between requests (stealth mode)
  # Range: 0-10000
  # Default: 0
  request_delay_ms: 0
```

## Environment Variables

```bash
# Thread count
export REDBLUE_NETWORK_THREADS=300

# Timeout
export REDBLUE_NETWORK_TIMEOUT_MS=2000

# DNS resolver
export REDBLUE_NETWORK_DNS_RESOLVER="1.1.1.1"

# Request delay
export REDBLUE_NETWORK_REQUEST_DELAY_MS=100
```

## Configuration Precedence

```
1. CLI Flags         (highest)
   rb network scan ports 192.168.1.1 --threads 500

2. Environment Variables
   REDBLUE_NETWORK_THREADS=300

3. Config File
   .redblue.yaml: network.threads: 200

4. Default Values    (lowest)
   threads: 200
```

## Preset Configurations

### Fast Scanning (Aggressive)

```yaml
network:
  threads: 1000
  timeout_ms: 300
  request_delay_ms: 0
```

Or use `--fast` flag:

```bash
rb network scan ports 192.168.1.1 --fast
# Equivalent to: --threads 1000 --timeout 300
```

### Stealth Scanning

```yaml
network:
  threads: 10
  timeout_ms: 3000
  request_delay_ms: 500
```

### Corporate Environment

```yaml
network:
  threads: 100
  timeout_ms: 2000
  dns_resolver: "10.0.0.53"  # Internal DNS
```

### High-Latency Network

```yaml
network:
  threads: 50
  timeout_ms: 5000
  request_delay_ms: 0
```

## Per-Command Configuration

```yaml
commands:
  # Port scanning specific
  network.ports.scan:
    threads: 500
    timeout: 1000
    preset: common

  # Host discovery specific
  network.host.discover:
    timeout: 2

  # Traceroute specific
  network.trace.run:
    max_hops: 30
    timeout: 2000
```

## Usage Examples

### Project-based Config

```bash
# Create project config
cat > .redblue.yaml << 'EOF'
network:
  threads: 300
  timeout_ms: 1500
EOF

# Commands use project config
rb network scan ports 192.168.1.1
# → Uses 300 threads, 1500ms timeout
```

### Override Config

```bash
# Config: threads=300
# Override with flag:
rb network scan ports 192.168.1.1 --threads 500
# → Uses 500 threads (flag wins)
```

### Environment Override

```bash
# Config: threads=300
export REDBLUE_NETWORK_THREADS=400

rb network scan ports 192.168.1.1
# → Uses 400 threads (env wins over config)

rb network scan ports 192.168.1.1 --threads 500
# → Uses 500 threads (flag wins over env)
```

## Best Practices

### 1. Use Config for Defaults

```yaml
# .redblue.yaml
network:
  threads: 200
  timeout_ms: 1000
```

### 2. Use Flags for One-offs

```bash
rb network scan ports 192.168.1.1 --fast
```

### 3. Use Env for Sessions

```bash
export REDBLUE_NETWORK_THREADS=500
# All scans in this shell use 500 threads
```

### 4. Per-Project Configs

```
~/pentests/
├── client-a/
│   └── .redblue.yaml  # Stealth config
├── client-b/
│   └── .redblue.yaml  # Fast config
└── ctf/
    └── .redblue.yaml  # Aggressive config
```

## Next Steps

- [Port Scanning](/domains/network/01-ports.md) - Scan ports on targets
- [Troubleshooting](/domains/network/05-troubleshooting.md) - Common issues
