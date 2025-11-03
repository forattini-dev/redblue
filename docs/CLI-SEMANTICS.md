# CLI Command Semantics

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
