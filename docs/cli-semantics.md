# CLI Command Semantics

## TL;DR
Defines the canonical `rb [domain] [resource] [verb]` grammar, the difference between action vs REST verbs, and the validation rules every new command must follow.

## Command Types: RESTful vs Action

redblue has **two distinct types of commands** with different purposes:

### 1. RESTful Commands (Database Queries)
**Purpose:** Query data that was previously collected and stored in RedDB

**Verbs:** `list`, `get`, `describe`, `delete`, `patch`, `update`

**Characteristics:**
- ❌ Does NOT execute active operations (no network requests, no scanning)
- ✅ Queries the RedDB database (.rdb files)
- ✅ Fast (just reads from disk)
- ✅ Can be run offline
- ✅ Follows HTTP REST semantics

**Examples:**
```bash
# List open ports stored in database
rb network ports list 192.168.1.1

# Get specific port status from database
rb network ports get 192.168.1.1:80

# Describe stored port information
rb network ports describe 192.168.1.1

# List DNS records from database
rb dns record list example.com

# List subdomains from database
rb recon domain list example.com
```

### 2. Action Commands (Active Operations)
**Purpose:** Execute active operations (scanning, querying, testing)

**Verbs:** `scan`, `lookup`, `whois`, `audit`, `ping`, `discover`, `harvest`, `fuzzy`, etc.

**Characteristics:**
- ✅ Executes ACTIVE operations (network requests, API calls, scanning)
- ✅ Can optionally save results to RedDB with `--persist` flag
- ⏱️ Slower (performs real operations)
- 🌐 Requires network connectivity
- ❌ NOT RESTful (action-based)

**Examples:**
```bash
# Execute active port scan
rb network ports scan 192.168.1.1

# Execute DNS lookup
rb dns record lookup example.com

# Execute WHOIS query
rb recon domain whois example.com

# Execute TLS security audit
rb tls security audit google.com

# Execute with persistence
rb network ports scan 192.168.1.1 --persist
```

---

## Command Pattern

```
rb [domain] [resource] [verb] [target] [flags]
   │        │          │       │        └─ Optional flags
   │        │          │       └────────── Target (IP, domain, URL, etc.)
   │        │          └────────────────── Action verb (scan/lookup) OR RESTful verb (list/get)
   │        └───────────────────────────── Resource (ports, record, domain, asset, etc.)
   └────────────────────────────────────── Domain (network, dns, web, recon, etc.)
```

---

## Examples Side-by-Side

### Network Ports

| RESTful (Query DB) | Action (Execute Scan) |
|-------------------|---------------------|
| `rb network ports list 192.168.1.1` | `rb network ports scan 192.168.1.1` |
| Reads from `.rdb` file | Executes TCP connect scan |
| Instant | Takes 2-5 seconds |
| Offline | Requires network |

### DNS Records

| RESTful (Query DB) | Action (Execute Query) |
|-------------------|----------------------|
| `rb dns record list example.com` | `rb dns record lookup example.com` |
| Reads cached DNS data | Queries DNS server |
| Shows historical data | Shows current data |
| Offline | Requires DNS access |

### Subdomains

| RESTful (Query DB) | Action (Execute Discovery) |
|-------------------|---------------------------|
| `rb recon domain list example.com` | `rb recon domain subdomains example.com` |
| Shows discovered subdomains | Discovers new subdomains |
| Instant | Takes minutes/hours |
| Offline | Requires network |

---

## Persistence Flow

```
1. Execute Action Command
   └─> rb network ports scan 192.168.1.1 --persist
       │
       ├─> Executes TCP scan
       ├─> Discovers: 22, 80, 443 open
       └─> Saves to: 192.168.1.1.rdb

2. Query Saved Data (RESTful)
   └─> rb network ports list 192.168.1.1
       │
       ├─> Opens: 192.168.1.1.rdb
       ├─> Reads stored ports
       └─> Displays: 22, 80, 443
```

---

## When to Use Each Type

### Use RESTful Commands When:
- ✅ You want to check previously scanned data
- ✅ You're working offline
- ✅ You need fast queries
- ✅ You're generating reports from stored data
- ✅ You're comparing historical data

### Use Action Commands When:
- ✅ You're performing initial reconnaissance
- ✅ You need current/live data
- ✅ You're actively testing targets
- ✅ You want to save results for later (`--persist`)

---

## Database Files

**Location:** Current working directory (`.rdb` extension)

**Naming:** `{target}.rdb`
- `192.168.1.1.rdb` - IP target
- `example.com.rdb` - Domain target
- `10.0.0.0_24.rdb` - CIDR range

**Format:** Binary RedDB format (compact, fast)

**Management:**
```bash
# List database files
ls *.rdb

# Query specific database
rb network ports list 192.168.1.1 --db target.rdb

# Export to CSV
rb database data export example.com.rdb

# View all targets in database
rb database data list example.com.rdb
```

---

## Complete Command Matrix

| Domain | Resource | RESTful Verbs | Action Verbs |
|--------|----------|--------------|--------------|
| network | ports | list, get, describe | scan, range |
| network | host | list, get | ping, discover |
| network | trace | list, get | run, mtr |
| dns | record | list, get, describe | lookup, resolve |
| recon | domain | list, get, describe | whois, subdomains, harvest, urls |
| web | asset | list, get, describe | get, headers, security, scan |
| tls | security | list, get, describe | audit, ciphers, vuln |
| cloud | asset | list, get, describe | takeover, takeover-scan, services |
| exploit | payload | - | privesc, shell, listener, lateral, persist |
| mcp | server | - | start |
| database | data | - | query, export, list, subnets |

**Note:** Exploit and database domains are special cases that don't follow the RESTful pattern.

---

## Key Takeaway

**RESTful commands** = Query stored data (fast, offline)
**Action commands** = Execute operations (slower, requires network)

The distinction is clear:
- **list/get** → Database
- **scan/lookup** → Active operation

Always use `--persist` with action commands to save data for later querying!

---

## MCP Domain Semantics

The `mcp` domain turns the CLI into a Model Context Protocol server so external agents can reason about redblue capabilities without shelling out. It keeps the classic `domain resource verb` grammar, but there is only one route:

- `rb mcp server start`

### Transport and Behaviour

1. **Transport:** JSON-RPC 2.0 over stdin/stdout with `Content-Length` framing (same envelope as the MCP reference server).
2. **Capabilities:** Advertises `tools.list` and `tools.call` so clients can enumerate and invoke metadata helpers.
3. **Safety:** The server never launches scans or network operations—tool handlers only read in-memory CLI metadata or Markdown files.

### Registered Tools

| Tool | Description | Arguments |
|------|-------------|-----------|
| `rb.list-domains` | Returns every CLI domain currently registered. | `{}` |
| `rb.list-resources` | Lists resources + verbs for a specific domain. | `{ "domain": "network" }` |
| `rb.describe-command` | Structured help with verbs and flags for a domain/resource pair. | `{ "domain": "network", "resource": "ports" }` |
| `rb.search-docs` | Keyword search across `README.md`, root handbooks, and `docs/`. | `{ "query": "tls" }` |
| `rb.docs.index` | Markdown index (title + sections) for every reference file. | `{}` |
| `rb.docs.get` | Return a whole document or a specific heading’s content. | `{ "path": "docs/cli-semantics.md", "section": "MCP Domain Semantics" }` |
| `rb.targets.list` | List all tracked targets managed by the MCP bridge. | `{}` |
| `rb.targets.save` | Create/update a tracked target (stores in `mcp-targets.json`). | `{ "name": "acme-web", "target": "https://acme.example" }` |
| `rb.targets.remove` | Remove a tracked target by name. | `{ "name": "acme-web" }` |
| `rb.command.run` | Execute a RedBlue command and capture stdout/stderr. | `{ "argv": ["network", "ports", "list", "192.168.1.1"] }` |

> Launch the bridge in one terminal, keep it running, and point your MCP-compatible IDE or agent to the stdio pipe. Press `Ctrl+C` to stop.

Tracked targets are persisted in `mcp-targets.json` (repository root). Documentation metadata is generated on demand—no prebuild step is necessary.

### Transports

- **stdio** — default JSON-RPC over stdin/stdout (always on)
- **SSE** — `GET /sse` + `POST /messages?sessionId=...` (enabled unless `--no-sse`)
- **Streamable HTTP** — `GET /stream` (chunked JSON feed) + `POST /stream/send?sessionId=...` (enabled unless `--no-stream`)
- **Status probe** — `GET /status` returns session counts for monitoring

Bind address defaults to `127.0.0.1:8787`; adjust using `--http-addr`. Use `--no-http` to disable all network endpoints.
