# Cloud Domain

Cloud security testing - subdomain takeover, storage enumeration.

## Quick Start

```bash
# Check for subdomain takeover
rb cloud asset takeover subdomain.example.com

# Batch scan from wordlist
rb cloud asset takeover-scan --wordlist subdomains.txt

# List supported services
rb cloud asset services
```

## Resources

| Resource | Description |
|----------|-------------|
| [asset](/domains/cloud/01-takeover.md) | Subdomain takeover detection |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| tko-subs | `rb cloud asset takeover` |
| subjack | `rb cloud asset takeover-scan` |
| can-i-take-over-xyz | `rb cloud asset services` |
| s3scanner | `rb cloud storage scan` (planned) |

## Command Matrix

```
rb cloud <verb> <resource> [target] [flags]
         │      │
         │      └── asset, storage
         └───────── takeover, takeover-scan, services, scan
```

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Subdomain Takeover | ✅ Done | 25+ services |
| Batch Scanning | ✅ Done | Concurrent checks |
| S3 Enumeration | 🚧 Planned | Phase 3 |
| Azure Storage | 🚧 Planned | Phase 3 |
| GCP Buckets | 🚧 Planned | Phase 3 |

## Confidence Levels

| Level | Description |
|-------|-------------|
| HIGH | CNAME points to known vulnerable service with error |
| MEDIUM | Service detected, needs manual verification |
| LOW | Dead DNS record, CNAME doesn't resolve |

## Next Steps

- [Subdomain Takeover](/domains/cloud/01-takeover.md) - Detect takeover vulnerabilities
- [Batch Scanning](/domains/cloud/02-batch.md) - Scan multiple subdomains
- [Configuration](/domains/cloud/03-configuration.md) - Cloud settings
