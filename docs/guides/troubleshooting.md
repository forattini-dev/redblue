# Troubleshooting Guide

> Common issues and solutions for redblue

## Installation Issues

### Binary Not Found

```bash
# Check if rb is in PATH
which rb

# If not found, add to PATH
export PATH="$HOME/.local/bin:$PATH"

# Or run directly
./rb --version
```

### Permission Denied

```bash
# Make binary executable
chmod +x ~/.local/bin/rb

# For raw socket operations (port scanning)
sudo setcap cap_net_raw+ep $(which rb)
```

### Raw Sockets Require Root

```
Error: Operation not permitted (os error 1)
```

**Solution:** Raw socket operations (SYN scanning, ICMP) require elevated privileges:

```bash
# Option 1: Use sudo
sudo rb network ports scan 192.168.1.1

# Option 2: Set capabilities (Linux)
sudo setcap cap_net_raw+ep $(which rb)

# Option 3: Use connect scan (no raw sockets)
rb network ports scan 192.168.1.1 --mode connect
```

## Network Issues

### Connection Timeout

```
Error: Connection timed out
```

**Causes:**
- Target is unreachable
- Firewall blocking traffic
- Network congestion

**Solutions:**

```bash
# Increase timeout
rb network ports scan target --timeout 10000

# Check basic connectivity first
rb network ping 192.168.1.1

# Try different port
rb network ports scan 192.168.1.1 --ports 80,443
```

### DNS Resolution Failed

```
Error: Failed to resolve hostname
```

**Solutions:**

```bash
# Use IP directly
rb network ports scan 192.168.1.1

# Check DNS
rb dns record lookup example.com

# Use specific resolver
rb dns record lookup example.com --server 8.8.8.8
```

### SSL/TLS Errors

```
Error: TLS handshake failed
```

**Causes:**
- Self-signed certificate
- Expired certificate
- TLS version mismatch

**Solutions:**

```bash
# Check TLS configuration
rb tls audit example.com

# Check certificate details
rb tls cert show example.com

# For self-signed certs (web requests)
rb web asset get https://example.com --insecure
```

## Storage Issues

### Database Corruption

```
Error: Invalid magic number in database header
```

**Solution:** The database file may be corrupted:

```bash
# Backup corrupted file
mv ~/.redblue/scan.rdb ~/.redblue/scan.rdb.bak

# Start fresh
rb network ports scan 192.168.1.1
```

### Disk Space

```
Error: No space left on device
```

**Solutions:**

```bash
# Check database size
ls -lh ~/.redblue/

# Compact database (if supported)
rb db compact

# Or remove old data
rm ~/.redblue/scan.rdb
```

## Performance Issues

### Slow Scans

**Tips for faster scanning:**

```bash
# Increase concurrency
rb network ports scan 192.168.1.1 --threads 500

# Reduce timeout
rb network ports scan 192.168.1.1 --timeout 1000

# Scan specific ports only
rb network ports scan 192.168.1.1 --preset common

# Use SYN scan (faster than connect)
sudo rb network ports scan 192.168.1.1 --mode syn
```

### High Memory Usage

Large scans can consume memory. Solutions:

```bash
# Reduce batch size
rb web fuzz dir http://example.com/FUZZ --batch-size 100

# Limit results stored
rb recon subdomain enum example.com --max-results 1000
```

## Output Issues

### JSON Parsing Errors

```bash
# Ensure clean JSON output
rb network ports scan 192.168.1.1 --output json 2>/dev/null | jq .

# Check for stderr contamination
rb network ports scan 192.168.1.1 --output json 2>&1 | head
```

### Missing Output

```bash
# Check if results were stored
rb db query "SELECT * FROM ports WHERE target = '192.168.1.1'"

# Verify scan completed
rb network ports scan 192.168.1.1 --verbose
```

## Platform-Specific Issues

### Linux

```bash
# Raw socket permission
sudo setcap cap_net_raw+ep $(which rb)

# SELinux issues
setenforce 0  # Temporary, for testing only
```

### macOS

```bash
# No setcap on macOS, use sudo
sudo rb network ports scan target

# Gatekeeper issues
xattr -d com.apple.quarantine rb
```

### Windows

```bash
# Run as Administrator for raw sockets
# Right-click terminal -> Run as Administrator

# Or use connect scan
rb network ports scan target --mode connect
```

## MCP Server Issues

### Server Won't Start

```bash
# Check if port is available
lsof -i :8787

# Start with debug logging
RUST_LOG=debug rb mcp server start

# Use stdio transport (for Claude Desktop)
rb mcp server start --stdio
```

### Connection Refused

```bash
# Verify server is running
rb mcp server status

# Check firewall
sudo ufw allow 8787/tcp
```

## Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Set log level
RUST_LOG=debug rb network ports scan target

# Trace level (very verbose)
RUST_LOG=trace rb network ports scan target

# Module-specific logging
RUST_LOG=redblue::network=debug rb network ports scan target
```

## Getting Help

If issues persist:

1. **Check version:** `rb --version`
2. **Enable debug logging:** `RUST_LOG=debug`
3. **Check GitHub issues:** [github.com/forattini-dev/redblue/issues](https://github.com/forattini-dev/redblue/issues)

## See Also

- [Installation](/getting-started/installation.md)
- [Quick Start](/getting-started/quickstart.md)
- [CLI Reference](/cli-commands.md)
