# MCP Resources Reference

> 40+ resources exposed via `redblue://` URI scheme

Resources provide access to data, scan results, and intelligence feeds.

## URI Scheme

All resources use the `redblue://` URI scheme:

```
redblue://category/resource[/parameter]
```

## System Resources

| URI | Description |
|-----|-------------|
| `redblue://system/info` | Version and capabilities |
| `redblue://system/capabilities` | Available tools and features |
| `redblue://system/config` | Current configuration |
| `redblue://system/status` | Server status |

### Example: Get System Info

```json
{
  "method": "resources/read",
  "params": {
    "uri": "redblue://system/info"
  }
}
```

**Response:**
```json
{
  "version": "0.2.2",
  "build": "release",
  "capabilities": ["network", "web", "recon", "intel"],
  "tools_count": 100,
  "prompts_count": 35,
  "resources_count": 40
}
```

## Intelligence Feeds

| URI | Description |
|-----|-------------|
| `redblue://intel/kev/catalog` | CISA Known Exploited Vulnerabilities (1200+) |
| `redblue://intel/mitre/tactics` | ATT&CK tactics |
| `redblue://intel/mitre/techniques` | ATT&CK techniques |
| `redblue://intel/mitre/groups` | Threat actor groups |
| `redblue://intel/cpe/dictionary` | CPE mappings |

### Example: Get KEV Catalog

```json
{
  "method": "resources/read",
  "params": {
    "uri": "redblue://intel/kev/catalog"
  }
}
```

## Scan Results

Scan results are accessed using template URIs:

| URI Pattern | Description |
|-------------|-------------|
| `redblue://scans/{target}` | All scan results for target |
| `redblue://scans/{target}/ports` | Port scan results |
| `redblue://scans/{target}/subdomains` | Subdomain results |
| `redblue://scans/{target}/vulns` | Vulnerability findings |
| `redblue://scans/{target}/tls` | TLS audit results |

### Example: Get Port Scan Results

```json
{
  "method": "resources/read",
  "params": {
    "uri": "redblue://scans/192.168.1.1/ports"
  }
}
```

**Response:**
```json
{
  "target": "192.168.1.1",
  "type": "ports",
  "count": 3,
  "results": [
    {"port": 22, "state": "open", "service_id": 1},
    {"port": 80, "state": "open", "service_id": 2},
    {"port": 443, "state": "open", "service_id": 3}
  ]
}
```

## Reference Data

| URI | Description |
|-----|-------------|
| `redblue://reference/owasp-top10` | OWASP Top 10 vulnerabilities |
| `redblue://reference/cwe-top25` | CWE Top 25 weaknesses |
| `redblue://reference/services` | Service port mappings |
| `redblue://wordlists/index` | Available wordlists |
| `redblue://payloads/index` | Payload templates |

## Search Resources

| URI Pattern | Description |
|-------------|-------------|
| `redblue://search/{query}` | Hybrid search (fuzzy + semantic) |
| `redblue://search/cve/{pattern}` | CVE search |
| `redblue://search/technique/{pattern}` | ATT&CK technique search |

### Example: Hybrid Search

```json
{
  "method": "resources/read",
  "params": {
    "uri": "redblue://search/nginx vulnerability"
  }
}
```

## Subscriptions

Resources marked as subscribable support real-time updates:

```json
{
  "method": "resources/subscribe",
  "params": {
    "uri": "redblue://scans/192.168.1.1/ports"
  }
}
```

Subscription updates are delivered via SSE (Server-Sent Events) when using HTTP transport.

### Subscribable Resources

| URI Pattern | Updates |
|-------------|---------|
| `redblue://scans/{target}/ports` | New port discoveries |
| `redblue://scans/{target}/subdomains` | New subdomains |
| `redblue://scans/{target}/vulns` | New vulnerabilities |
| `redblue://intel/kev/catalog` | KEV additions |

## Resource Metadata

Each resource includes metadata in the response:

```json
{
  "uri": "redblue://scans/192.168.1.1/ports",
  "mimeType": "application/json",
  "subscribable": true,
  "cached": false,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## See Also

- [Overview](00-overview.md) - MCP introduction
- [Tools](01-tools.md) - Executable tools
- [Integration](05-integration.md) - Setup guide
