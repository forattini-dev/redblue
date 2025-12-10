# Troubleshooting

Common issues and solutions for network scanning.

## No Open Ports Found

### Symptoms

```
Scanning 192.168.1.1  [████████████████████████] 100/100 (2.3s)

Scan: 192.168.1.1 (0 open)
No open ports found
```

### Causes & Solutions

| Cause | Solution |
|-------|----------|
| Host unreachable | `rb network ping host <target>` |
| Firewall blocking | Try `--preset full` |
| Timeout too short | `--timeout 2000` or higher |
| Wrong IP/hostname | Verify target address |

### Debugging Steps

```bash
# Step 1: Check if host is reachable
rb network ping host 192.168.1.1

# Step 2: Try longer timeout
rb network scan ports 192.168.1.1 --timeout 3000

# Step 3: Try full port scan
rb network scan ports 192.168.1.1 --preset full

# Step 4: Try specific ports manually
rb network range ports 192.168.1.1 80 80
rb network range ports 192.168.1.1 22 22
```

## Slow Scans

### Symptoms

Scan takes much longer than expected.

### Causes & Solutions

| Cause | Solution |
|-------|----------|
| Too many ports | Use `--preset web` or `common` |
| Low thread count | Increase `--threads 500` |
| High timeout | Lower `--timeout 500` |
| Network latency | Use `--fast` mode |

### Optimization

```bash
# Fast mode
rb network scan ports 192.168.1.1 --fast

# Web ports only (fastest)
rb network scan ports 192.168.1.1 --preset web

# Aggressive settings
rb network scan ports 192.168.1.1 --threads 1000 --timeout 300
```

## Connection Refused

### Symptoms

```
Error: Connection refused for all ports
```

### Causes

- Target firewall actively rejecting
- All services stopped
- Network ACL blocking

### Solutions

```bash
# Check host is up
rb network ping host 192.168.1.1

# Check specific known port
rb network range ports 192.168.1.1 22 22

# Try from different network
# (may be ACL-based blocking)
```

## Permission Denied

### Symptoms

```
Error: Permission denied
```

### Causes

- Raw sockets require root (future SYN scan)
- ARP scanning requires root

### Solutions

```bash
# Current TCP connect scan works without root
rb network scan ports 192.168.1.1

# Future SYN scan will require:
sudo rb network scan ports 192.168.1.1 --syn
```

## Database Save Fails

### Symptoms

```
Error: Failed to save results to .rdb file
```

### Causes & Solutions

| Cause | Solution |
|-------|----------|
| No disk space | Free up space |
| No write permission | Check directory permissions |
| Invalid filename | Check target has valid chars |

### Workaround

```bash
# Skip persistence
rb network scan ports 192.168.1.1 --no-persist

# Output to JSON instead
rb network scan ports 192.168.1.1 -o json > results.json
```

## DNS Resolution Fails

### Symptoms

```
Error: Failed to resolve hostname
```

### Solutions

```bash
# Check DNS manually
rb dns lookup record example.com

# Use IP directly
rb network scan ports 192.168.1.1

# Use different DNS server
# In .redblue.yaml:
# network:
#   dns_resolver: "1.1.1.1"
```

## High False Positives

### Symptoms

Many ports show as open but services don't respond.

### Causes

- Firewall with port forwarding
- Load balancer
- Honeypot

### Solutions

```bash
# Add banner grabbing for verification
rb network scan ports 192.168.1.1 --intel

# Verify with web request
rb web get asset http://192.168.1.1:80
```

## Incomplete Results

### Symptoms

Scan finishes but seems to miss ports.

### Causes

- Timeout too short
- Thread contention
- Rate limiting

### Solutions

```bash
# Increase timeout
rb network scan ports 192.168.1.1 --timeout 3000

# Reduce threads (less aggressive)
rb network scan ports 192.168.1.1 --threads 50

# Add delay between requests
# In .redblue.yaml:
# network:
#   request_delay_ms: 100
```

## Getting Help

```bash
# Command help
rb network help
rb network scan ports --help

# Version info
rb --version

# Debug output
rb network scan ports 192.168.1.1 --verbose
```

## Next Steps

- [Configuration](04-configuration.md) - Tune settings
- [Port Scanning](01-ports.md) - Scan reference
