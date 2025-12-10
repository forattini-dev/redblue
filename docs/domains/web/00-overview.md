# Web Domain

HTTP testing, security audits, and CMS scanning.

## Quick Start

```bash
# HTTP GET request
rb web get asset http://example.com

# Security headers audit
rb web security asset http://example.com

# HTTP headers analysis
rb web headers asset http://example.com

# CMS scanning
rb web cms-scan asset http://wordpress-site.com
```

## Resources

| Resource | Description |
|----------|-------------|
| [asset](01-requests.md) | HTTP requests and responses |
| [security](02-security.md) | Security headers analysis |
| [cms](03-cms.md) | CMS detection and scanning |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| curl | `rb web get asset` |
| wget | `rb web get asset` |
| httpie | `rb web get asset` |
| nikto (headers) | `rb web security asset` |
| wpscan | `rb web cms-scan asset --strategy wordpress` |
| droopescan | `rb web cms-scan asset --strategy drupal` |

## Command Matrix

```
rb web <verb> <resource> [target] [flags]
       │      │
       │      └── asset
       └───────── get, headers, security, cms-scan, crawl, fuzz
```

## HTTP Methods Supported

| Method | Command | Description |
|--------|---------|-------------|
| GET | `rb web get asset` | Retrieve resource |
| POST | `rb web post asset` | Submit data |
| HEAD | `rb web headers asset` | Headers only |

## Next Steps

- [HTTP Requests](01-requests.md) - GET, POST, headers
- [Security Audit](02-security.md) - Security headers analysis
- [CMS Scanning](03-cms.md) - WordPress, Drupal, Joomla
- [Configuration](04-configuration.md) - HTTP settings
