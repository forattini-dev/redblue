# Network Domain

Network reconnaissance, port scanning, host discovery, and connectivity testing.

## Quick Start

```bash
# Port scan
rb network scan ports 192.168.1.1

# Host discovery
rb network discover host 192.168.1.0/24

# Ping test
rb network ping host google.com

# Traceroute
rb network run trace 8.8.8.8
```

## Resources

| Resource | Description |
|----------|-------------|
| [ports](01-ports.md) | Port scanning and service detection |
| [host](02-host.md) | Host discovery and connectivity testing |
| [trace](03-trace.md) | Network path tracing (traceroute/MTR) |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| nmap -sT | `rb network scan ports` |
| nmap -p- | `rb network scan ports --preset full` |
| masscan | `rb network scan ports --fast` |
| fping | `rb network ping host` |
| netdiscover | `rb network discover host` |
| traceroute | `rb network run trace` |
| mtr | `rb network mtr trace` |

## Command Matrix

```
rb network <resource> <verb> [target] [flags]
           │          │
           │          └── scan, range, ping, discover, run, mtr
           └───────────── ports, host, trace
```

## Next Steps

- [Port Scanning](01-ports.md) - Scan ports on targets
- [Host Discovery](02-host.md) - Find alive hosts in networks
- [Path Tracing](03-trace.md) - Trace network routes
- [Configuration](04-configuration.md) - Customize network settings
