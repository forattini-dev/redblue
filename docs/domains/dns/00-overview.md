# DNS Domain

DNS reconnaissance and enumeration - RFC 1035 compliant implementation.

## Quick Start

```bash
# Lookup A record
rb dns lookup record example.com

# Lookup MX records
rb dns lookup record example.com --type MX

# Quick resolve
rb dns resolve record github.com
```

## Resources

| Resource | Description |
|----------|-------------|
| [record](01-lookup.md) | DNS record lookups and resolution |

## Supported Record Types

| Type | Description | Example |
|------|-------------|---------|
| A | IPv4 address | `93.184.216.34` |
| AAAA | IPv6 address | `2606:2800:220:1:248:1893:25c8:1946` |
| MX | Mail exchanger | `mail.example.com` (priority 10) |
| NS | Name server | `ns1.example.com` |
| TXT | Text record | `v=spf1 include:_spf.google.com` |
| CNAME | Canonical name | `www.example.com → example.com` |
| SOA | Start of authority | Zone info |
| PTR | Reverse lookup | IP → hostname |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| dig | `rb dns lookup record` |
| nslookup | `rb dns resolve record` |
| host | `rb dns lookup record` |

## Command Matrix

```
rb dns <resource> <verb> [target] [flags]
       │          │
       │          └── lookup, resolve
       └───────────── record
```

## Next Steps

- [DNS Lookups](01-lookup.md) - Query DNS records
- [Configuration](02-configuration.md) - DNS settings
