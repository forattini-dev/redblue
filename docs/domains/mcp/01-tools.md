# MCP Tools Reference

> 100+ security tools exposed via MCP

Tools are executable operations that the LLM can invoke directly.

## Discovery Tools

| Tool | Description |
|------|-------------|
| `rb.list-domains` | List all CLI domains |
| `rb.list-resources` | List resources for a domain |
| `rb.describe-command` | Get help for a command |
| `rb.search-docs` | Search documentation |

## Network Tools

| Tool | Description |
|------|-------------|
| `rb.network.scan` | Port scan with service detection |
| `rb.network.ping` | Host reachability check |
| `rb.network.health` | Multi-port health check |
| `rb.network.traceroute` | Trace route to target |
| `rb.network.sweep` | Ping sweep a CIDR range |

### Example: Port Scan

```json
{
  "method": "tools/call",
  "params": {
    "name": "rb.network.scan",
    "arguments": {
      "target": "192.168.1.1",
      "ports": "1-1000",
      "timeout": 2000
    }
  }
}
```

## Web Tools

| Tool | Description |
|------|-------------|
| `rb.web.crawl` | Website crawling |
| `rb.web.scrape` | CSS selector scraping |
| `rb.web.links` | Link extraction |
| `rb.web.fingerprint` | Technology detection |
| `rb.har.record` | HTTP traffic recording |

### Example: Web Crawl

```json
{
  "method": "tools/call",
  "params": {
    "name": "rb.web.crawl",
    "arguments": {
      "url": "https://example.com",
      "depth": 2,
      "follow_external": false
    }
  }
}
```

## Vulnerability Tools

| Tool | Description |
|------|-------------|
| `rb.vuln.search` | NVD/OSV vulnerability search |
| `rb.vuln.cve` | Detailed CVE information |
| `rb.vuln.kev` | CISA KEV catalog |
| `rb.vuln.exploit` | Exploit-DB search |

### Example: CVE Lookup

```json
{
  "method": "tools/call",
  "params": {
    "name": "rb.vuln.cve",
    "arguments": {
      "cve_id": "CVE-2021-44228"
    }
  }
}
```

## Reconnaissance Tools

| Tool | Description |
|------|-------------|
| `rb.recon.subdomain` | Subdomain enumeration |
| `rb.recon.whois` | WHOIS lookup |
| `rb.recon.dnsdumpster` | DNS intelligence |
| `rb.dns.lookup` | DNS record queries |

### Example: Subdomain Enum

```json
{
  "method": "tools/call",
  "params": {
    "name": "rb.recon.subdomain",
    "arguments": {
      "domain": "example.com",
      "depth": "deep"
    }
  }
}
```

## TLS Tools

| Tool | Description |
|------|-------------|
| `rb.tls.audit` | Full TLS security audit |
| `rb.tls.cert` | Certificate details |
| `rb.tls.chain` | Certificate chain |
| `rb.tls.vulns` | TLS vulnerability check |

## Intelligence Tools

| Tool | Description |
|------|-------------|
| `rb.intel.mitre.technique` | ATT&CK technique details |
| `rb.intel.mitre.tactics` | ATT&CK tactics list |
| `rb.intel.cpe` | CPE lookup |

## Autonomous Tools

| Tool | Description |
|------|-------------|
| `rb.auto.recon` | Autonomous reconnaissance |
| `rb.auto.assess` | Autonomous vulnerability assessment |

### Example: Autonomous Recon

```json
{
  "method": "tools/call",
  "params": {
    "name": "rb.auto.recon",
    "arguments": {
      "target": "example.com",
      "max_iterations": 5
    }
  }
}
```

## Tool Categories

Tools can be filtered by category to reduce context usage:

```rust
let config = CategoryConfig::new()
    .enable("Network")
    .enable("Vulnerability")
    .disable("Evasion");
```

Available categories:
- `Discovery` - Tool discovery and help
- `Network` - Port scanning, host discovery
- `Web` - Web crawling, fuzzing
- `Vulnerability` - CVE lookup, vuln scanning
- `Reconnaissance` - OSINT, subdomain enum
- `TLS` - SSL/TLS auditing
- `Intelligence` - MITRE, threat intel
- `Autonomous` - LLM-guided operations

## See Also

- [Overview](00-overview.md) - MCP introduction
- [Prompts](02-prompts.md) - Pre-built workflows
- [Integration](05-integration.md) - Setup guide
