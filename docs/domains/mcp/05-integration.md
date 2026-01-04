# MCP Integration Guide

> How to integrate redblue with LLM clients

## Client Configuration

### Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json` (Linux/macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "redblue": {
      "command": "rb",
      "args": ["mcp", "server", "start"]
    }
  }
}
```

### Custom Client (HTTP)

1. Start the HTTP server:

```bash
rb mcp server start --http-addr 127.0.0.1:8787
```

2. Connect to the endpoint:

```
http://127.0.0.1:8787/mcp
```

## Transport Protocols

### Stdio (Default)

Used by Claude Desktop and similar clients:

```bash
rb mcp server start
```

Communication via stdin/stdout with JSON-RPC 2.0 messages.

### HTTP

REST-like interface:

```bash
rb mcp server start --http-addr 127.0.0.1:8787
```

Endpoints:
- `POST /mcp` - JSON-RPC requests
- `GET /mcp/sse` - Server-sent events (subscriptions)

### SSE Subscriptions

Enable real-time updates:

```bash
rb mcp server start --http-addr 127.0.0.1:8787 --sse
```

## Message Format

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "rb.network.scan",
    "arguments": {
      "target": "192.168.1.1"
    }
  }
}
```

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Scan results..."
      }
    ]
  }
}
```

## Available Methods

| Method | Description |
|--------|-------------|
| `initialize` | Initialize connection |
| `tools/list` | List available tools |
| `tools/call` | Execute a tool |
| `prompts/list` | List available prompts |
| `prompts/get` | Get prompt content |
| `resources/list` | List available resources |
| `resources/read` | Read a resource |
| `resources/subscribe` | Subscribe to updates |
| `resources/unsubscribe` | Unsubscribe from updates |

## Tool Categories

### CLI Filtering

Filter tools at server startup to reduce context and improve LLM focus:

```bash
# Enable only specific categories
rb mcp server start --categories=network,dns,web

# Use a preset
rb mcp server start --preset=blue-team

# Available presets:
#   all         - All 100+ tools (default)
#   core        - Discovery, docs, targets only
#   blue-team   - Defensive: network, recon, vuln, intel
#   red-team    - Offensive: network, recon, evasion, command
#   web-security - Web focus: web, har, tls, recon
#   minimal     - Discovery only
```

### Available Categories

| Category | Description |
|----------|-------------|
| `discovery` | List domains, resources, commands |
| `docs` | Documentation access |
| `targets` | Target management |
| `network` | Port scanning, ping, health |
| `dns` | DNS lookup, resolve |
| `web` | Crawling, scraping |
| `har` | HAR recording/analysis |
| `tls` | Certificate and TLS audit |
| `recon` | WHOIS, subdomains, CT logs |
| `vuln` | NVD, OSV, KEV, Exploit-DB |
| `intel` | MITRE ATT&CK, IOCs |
| `evasion` | Sandbox, obfuscation (⚠️) |
| `fingerprint` | Service fingerprinting |
| `command` | Direct command execution |
| `auto` | Autonomous LLM operations |

### Runtime Query

Filter tools in MCP requests:

```json
{
  "method": "tools/list",
  "params": {
    "categories": ["network", "vuln"]
  }
}
```

## Error Handling

Errors follow JSON-RPC 2.0 format:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "field": "target",
      "reason": "Invalid IP address"
    }
  }
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32000 | Tool execution error |
| -32001 | Resource not found |
| -32002 | Authorization required |

## Rate Limiting

External API calls are rate-limited:

| Resource | Limit |
|----------|-------|
| NVD API | 5/min |
| CISA KEV | 10/min |
| DNS queries | 100/min |

## Logging

Enable debug logging:

```bash
RUST_LOG=debug rb mcp server start
```

Logs include:
- All incoming requests
- Tool executions
- Resource reads
- Subscription updates

## Security

### Authorization

Some tools require explicit authorization:

```json
{
  "method": "tools/call",
  "params": {
    "name": "rb.exploit.shell",
    "arguments": {...},
    "authorization": {
      "scope": "authorized_testing",
      "timestamp": "2024-01-15T10:00:00Z"
    }
  }
}
```

### Audit Trail

All operations are logged with:
- Timestamp
- Tool/resource accessed
- Parameters
- Result summary

## Troubleshooting

### Server Won't Start

```bash
# Check if port is in use
lsof -i :8787

# Try different port
rb mcp server start --http-addr 127.0.0.1:9999
```

### Connection Refused

```bash
# Verify server is running
rb mcp server status

# Check firewall
sudo ufw allow 8787/tcp
```

### Tool Not Found

```bash
# List available tools
rb mcp tools list

# Check tool category is enabled
rb mcp categories
```

## Example Session

1. **Initialize**

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"my-client"}}}
```

2. **List Tools**

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

3. **Execute Tool**

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rb.network.scan","arguments":{"target":"192.168.1.1","ports":"22,80,443"}}}
```

4. **Read Resource**

```json
{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"redblue://scans/192.168.1.1/ports"}}
```

## See Also

- [Overview](00-overview.md) - MCP introduction
- [Tools](01-tools.md) - Available tools
- [Resources](03-resources.md) - Data feeds
