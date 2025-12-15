# network health

> Port health monitoring and change detection

Monitor port availability, detect changes, and track service uptime.

## Commands

```
rb network health <verb> [target] [flags]
```

| Verb | Description |
|------|-------------|
| `check` | Check port health status |
| `diff` | Compare current state vs baseline |
| `watch` | Continuous monitoring mode |

## Usage Examples

### Health Check

```bash
# Check single port
rb network health check 192.168.1.1:80

# Check multiple ports
rb network health check 192.168.1.1:80,443,8080

# Check with timeout
rb network health check 192.168.1.1:80 --timeout 5
```

### Diff Mode

Compare current port state against a saved baseline:

```bash
# Save baseline
rb network health check 192.168.1.1:80,443 --save-baseline

# Compare against baseline
rb network health diff 192.168.1.1

# Output changes
rb network health diff 192.168.1.1 --json
```

### Watch Mode

Continuous monitoring with alerts:

```bash
# Watch ports continuously
rb network health watch 192.168.1.1:80,443

# Watch with interval
rb network health watch 192.168.1.1:80 --interval 30

# Watch with alert threshold
rb network health watch 192.168.1.1:80 --alert-after 3
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--timeout` | Connection timeout (seconds) | 5 |
| `--interval` | Check interval for watch (seconds) | 60 |
| `--save-baseline` | Save current state as baseline | false |
| `--alert-after` | Alert after N consecutive failures | 3 |
| `--json` | JSON output | false |

## Output

### Check Output

```
Health Check: 192.168.1.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PORT    STATUS    LATENCY    SERVICE
80      UP        12ms       HTTP
443     UP        15ms       HTTPS
8080    DOWN      -          -
```

### Diff Output

```
Port Changes Detected: 192.168.1.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PORT    BASELINE    CURRENT    CHANGE
80      UP          UP         -
443     UP          DOWN       CLOSED
3306    DOWN        UP         OPENED
```

## Use Cases

### Infrastructure Monitoring

```bash
# Monitor critical services
rb network health watch prod-server:80,443,3306 --interval 30
```

### Change Detection

```bash
# Detect unauthorized port changes
rb network health diff firewall-host --json | jq '.opened_ports'
```

### Incident Response

```bash
# Quick health assessment
rb network health check suspected-host:22,80,443,3389,5985
```
