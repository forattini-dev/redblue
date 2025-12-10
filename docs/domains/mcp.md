<div align="center">

# 🤖 MCP Domain Documentation

## TL;DR
Everything about the Model Context Protocol (MCP) server integration, enabling AI assistants to use redblue as a tool.

**AI Integration • Semantic Search • Context Exposure**

[Commands](#commands) • [Docs Index](./index.md) • [Root Docs](../../README.md)

</div>

---

<div align="right">

[⬆ Back to Top](#-mcp-domain-documentation)

</div>

## Overview

The `mcp` domain allows `redblue` to act as a Model Context Protocol (MCP) server. This standard allows AI assistants (like Claude Desktop, or IDE-integrated agents) to connect to `redblue` and use its capabilities directly.

When running as an MCP server, `redblue` exposes:
1. **Tools**: Executable commands like `rb.scan_ports` or `rb.lookup_dns`.
2. **Resources**: Direct access to scan results (`.rdb` files) and logs.
3. **Prompts**: Reusable prompts for security analysis.

**Domain:** `mcp`

**Available Resources:**
- `server` - The MCP server process

---

## Resource: `mcp server`

**Description:** Manage the MCP server process.

### Commands

#### 1. `start` - Start the MCP Server

Start the MCP server, listening on stdio (default) or HTTP/SSE.

**Syntax:**
```bash
rb mcp server start [FLAGS]
```

**Flags:**
- `--stdio` - Use standard input/output (default). Best for local integration with Claude Desktop.
- `--http-addr <addr>` - Bind address for HTTP/SSE server (e.g., `127.0.0.1:8787`).
- `--no-http` - Disable HTTP server (stdio only).
- `--no-sse` - Disable Server-Sent Events endpoint.
- `--no-stream` - Disable chunked HTTP stream endpoint.

**Examples:**

```bash
# Start in stdio mode (for Claude Desktop config)
rb mcp server start

# Start HTTP server on custom port
rb mcp server start --http-addr 127.0.0.1:9090
```

---

## Integration Guide

### Claude Desktop Configuration

To use `redblue` with Claude Desktop, add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "redblue": {
      "command": "/path/to/rb",
      "args": ["mcp", "server", "start"]
    }
  }
}
```

### Available MCP Tools

When connected, the AI assistant will have access to tools like:

- `rb.list-domains`: Enumerate available capability domains.
- `rb.list-resources`: List resources and verbs for a domain.
- `rb.describe-command`: Get help and usage for specific commands.
- `rb.command.run`: Execute any `rb` command (e.g., `rb network scan ports`).
- `rb.search-docs`: Semantic search over the documentation.
- `rb.docs.get`: Retrieve specific documentation sections.
- `rb.targets.list`: List tracked targets.
- `rb.targets.save`: Add/update a tracked target.

### Semantic Search

The MCP server includes a semantic search engine powered by `fastembed`. This allows the AI to answer questions like "How do I scan for vulnerabilities?" by retrieving relevant sections from the `redblue` documentation, even if the keywords don't match exactly.

---

## Security

Running an MCP server exposes the full power of `redblue` to the connected client.
- **Stdio Mode:** Secure by design, as it requires local process execution privileges.
- **HTTP Mode:** Binds to `127.0.0.1` by default. Do **NOT** expose this to public networks without additional authentication (e.g., an authenticating proxy).

---

## See Also

- [Model Context Protocol Website](https://modelcontextprotocol.io)
- [Project README](../../README.md)
