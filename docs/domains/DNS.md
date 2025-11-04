# DNS Domain Documentation

## Overview

The `dns` domain provides comprehensive DNS reconnaissance capabilities including record lookups, zone enumeration, subdomain discovery, and DNS server fingerprinting. It replaces tools like **dig**, **nslookup**, **host**, and **dnsrecon**.

**Domain:** `dns`

**Available Resources:**
- `record` - DNS record queries, resolution, and enumeration

**Key Features:**
- RFC 1035 compliant DNS protocol implementation (from scratch)
- Support for all major DNS record types
- Parallel queries for maximum speed
- DNS server fingerprinting via VERSION.BIND
- Reverse DNS lookups (PTR records)
- Database persistence for reconnaissance tracking
- Multiple output formats (text, JSON, YAML)

---

## Implementation Status (Nov 2025)

### What Ships Today
- Packet crafting and parsing live under `src/modules/dns/` with zero external crates; lookups, resolution, and fingerprinting reuse the shared networking stack.
- CLI verbs in `src/cli/commands/dns.rs` support `lookup`, `resolve`, and `enum` flows with persistence and intelligence flags; parser wiring resides in `src/cli/parser.rs`.
- `tests/storage_roundtrip.rs` exercises persistence for DNS segments, while smoke coverage comes from `tests/tls_integration_test.rs` and the CLI TUI smoke harness.
- Intelligent VERSION.BIND queries populate TLS/network intelligence segments through `src/storage/segments/dns.rs`.

### Active Backlog
- Parallelized subdomain brute-force and zone transfer helpers (AXFR) tied to wordlists (`wordlists/`) and `--intel` workflows.
- DNSSEC validation primitives (signature verification, chain building) for compliance-focused scans.
- Cached resolver for repeat queries plus rate limiting & exponential backoff against strict authoritative servers.

### Recommended Next Steps
1. Wire a `rb dns record enum` command that batches common record types and persists a unified report.
2. Extend `.rdb` schema with resolver metadata (server IPs, RTT) for cross-domain intelligence.
3. Document a troubleshooting section covering SERVFAIL/REFUSED handling and recursion limits.

---

## Resource: `dns record`

**Description:** Query, enumerate, and analyze DNS records for domain reconnaissance.

### Commands

#### 1. `lookup` - DNS Record Query

Query specific DNS record types for a domain.

**Syntax:**
```bash
rb dns record lookup <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain name (required)

**Flags:**
- `-t, --type <type>` - Record type to query
  - Options: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV`, `ANY`
  - Default: `A`
- `-s, --server <ip>` - DNS server to query
  - Default: `8.8.8.8` (Google DNS)
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`
  - Default: `text`
- `--persist` - Save results to binary database (.rdb file)
- `--no-persist` - Don't save results (overrides config)
- `--intel` - Perform DNS server fingerprinting using VERSION.BIND query

**Examples:**

```bash
# Basic A record lookup
rb dns record lookup google.com

# Lookup specific record type
rb dns record lookup example.com --type MX

# Use different DNS server
rb dns record lookup example.com --server 1.1.1.1

# Multiple record types
rb dns record lookup example.com --type NS
rb dns record lookup example.com --type TXT

# With persistence
rb dns record lookup example.com --type A --persist

# DNS server fingerprinting
rb dns record lookup example.com --intel

# JSON output
rb dns record lookup google.com --type MX -o json
```

**Sample Output (Text):**

```
⏱️  Querying DNS...

DNS: google.com (A) @ 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Records: 6

  A 142.250.185.78 3600s
  A 142.250.185.110 3600s
  A 142.250.185.46 3600s
  A 142.250.185.14 3600s
  A 142.250.185.142 3600s
  A 142.250.185.174 3600s

✓ Results saved to google.com.rdb
```

**Sample Output (MX Records):**

```
DNS: example.com (MX) @ 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Records: 2

  MX 10 mail1.example.com 86400s
  MX 20 mail2.example.com 86400s
```

**Sample Output (NS Records):**

```
DNS: example.com (NS) @ 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Records: 4

  NS ns1.example.com 172800s
  NS ns2.example.com 172800s
  NS ns3.example.com 172800s
  NS ns4.example.com 172800s
```

**Sample Output (TXT Records):**

```
DNS: example.com (TXT) @ 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Records: 3

  TXT v=spf1 include:_spf.example.com ~all 3600s
  TXT google-site-verification=abc123xyz789 3600s
  TXT MS=ms123456789 3600s
```

**Sample Output (JSON):**

```json
{
  "domain": "google.com",
  "record_type": "A",
  "server": "8.8.8.8",
  "count": 6,
  "records": [
    {
      "type": "A",
      "value": "142.250.185.78",
      "ttl": 3600
    },
    {
      "type": "A",
      "value": "142.250.185.110",
      "ttl": 3600
    }
  ]
}
```

**Sample Output (YAML):**

```yaml
domain: google.com
record_type: A
server: 8.8.8.8
count: 6
records:
  - type: A
    value: "142.250.185.78"
    ttl: 3600
  - type: A
    value: "142.250.185.110"
    ttl: 3600
```

**Intelligence Gathering Output (`--intel`):**

```
DNS: example.com (A) @ 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Records: 1

  A 93.184.216.34 86400s

DNS Server Intelligence
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⏱️  Fingerprinting DNS server...

  Vendor:           BIND
  Version:          9.16.48
  Operating System: Ubuntu
  Build:            Ubuntu-1ubuntu5.4
```

**DNS Server Fingerprinting:**

The `--intel` flag queries the special `VERSION.BIND` TXT record to extract DNS server information:

- **Vendor Detection**: Identifies BIND, PowerDNS, Unbound, etc.
- **Version Extraction**: Extracts precise version numbers
- **OS Fingerprinting**: Detects operating system from build info
- **Custom Fields**: Reveals build information and customizations
- **Modified Banner Detection**: Alerts if banner appears to be customized

**Notes on VERSION.BIND:**
- Not all DNS servers respond to VERSION.BIND queries
- Some administrators disable this for security (information disclosure)
- Authoritative servers more likely to reveal version than recursive resolvers
- Can reveal security vulnerabilities if server is outdated

---

#### 2. `all` - Query All Record Types

Query all major DNS record types in parallel for comprehensive reconnaissance.

**Syntax:**
```bash
rb dns record all <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Target domain name (required)

**Flags:**
- `-s, --server <ip>` - DNS server to use (default: 8.8.8.8)
- `-o, --output <format>` - Output format: `text`, `json`, `yaml`

**Examples:**

```bash
# Query all record types
rb dns record all google.com

# Use specific DNS server
rb dns record all example.com --server 1.1.1.1

# JSON output for automation
rb dns record all google.com -o json
```

**Sample Output:**

```
⏱️  Querying 7 record types in parallel...
Fetched 7/7 record types

DNS: google.com (ALL TYPES) @ 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Record Types: 6    Total Records: 24

  A (6 records)
    142.250.185.78 300s
    142.250.185.110 300s
    142.250.185.46 300s
    142.250.185.14 300s
    142.250.185.142 300s
    142.250.185.174 300s

  AAAA (4 records)
    2607:f8b0:4004:c07::8b 300s
    2607:f8b0:4004:c07::71 300s
    2607:f8b0:4004:c07::8a 300s
    2607:f8b0:4004:c07::64 300s

  MX (5 records)
    10 smtp.google.com 3600s
    20 smtp2.google.com 3600s
    30 smtp3.google.com 3600s
    40 smtp4.google.com 3600s
    50 smtp5.google.com 3600s

  NS (4 records)
    ns1.google.com 345600s
    ns2.google.com 345600s
    ns3.google.com 345600s
    ns4.google.com 345600s

  TXT (2 records)
    v=spf1 include:_spf.google.com ~all 3600s
    MS=ms123456789 3600s

  SOA (1 records)
    ns1.google.com hostmaster.google.com 2024110301 900 900 1800 60 86400s
```

**Record Types Queried:**

| Type | Description | Use Case |
|------|-------------|----------|
| `A` | IPv4 address | Main IP addresses for domain |
| `AAAA` | IPv6 address | IPv6 addresses |
| `CNAME` | Canonical name | Aliases and CDN detection |
| `MX` | Mail exchange | Email infrastructure |
| `NS` | Name server | DNS infrastructure |
| `TXT` | Text records | SPF, DKIM, verification codes |
| `SOA` | Start of authority | Zone transfer info, serial numbers |

**Performance:**

- **Parallel Execution**: All 7 record types queried simultaneously
- **Fast Completion**: Typically completes in < 500ms
- **No Rate Limiting**: Queries sent independently
- **Thread-Safe**: Results collected safely from all threads

---

#### 3. `resolve` - Quick DNS Resolution

Fast domain-to-IP resolution for quick lookups.

**Syntax:**
```bash
rb dns record resolve <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Domain name to resolve (required)

**Flags:**
- `-s, --server <ip>` - DNS server (default: 8.8.8.8)

**Examples:**

```bash
# Basic resolution
rb dns record resolve github.com

# Use specific DNS server
rb dns record resolve example.com --server 1.1.1.1
```

**Sample Output:**

```
⏱️  Resolving github.com...

✓ github.com → 140.82.121.4
```

**Multiple IPs:**

```
⏱️  Resolving google.com...

✓ google.com → 142.250.185.78
✓ google.com → 142.250.185.110
✓ google.com → 142.250.185.46
```

**Use Cases:**
- Quick IP lookup for further scanning
- Verify domain resolution
- Check DNS propagation
- Compare resolution across DNS servers

---

#### 4. `reverse` - Reverse DNS Lookup

Perform reverse DNS lookups (PTR records) to find hostnames for IP addresses.

**Syntax:**
```bash
rb dns record reverse <ip> [FLAGS]
```

**Arguments:**
- `<ip>` - IP address (IPv4 or IPv6, required)

**Flags:**
- `-s, --server <ip>` - DNS server (default: 8.8.8.8)

**Examples:**

```bash
# IPv4 reverse lookup
rb dns record reverse 8.8.8.8

# IPv6 reverse lookup
rb dns record reverse 2001:4860:4860::8888

# Use specific DNS server
rb dns record reverse 1.1.1.1 --server 8.8.8.8
```

**Sample Output:**

```
⏱️  Querying PTR for 8.8.8.8...

PTR records for 8.8.8.8:

HOST                    TTL
dns.google              86400
```

**How It Works:**

The tool automatically constructs the proper PTR query format:

**IPv4 Example:**
- Input: `8.8.8.8`
- PTR Query: `8.8.8.8.in-addr.arpa`
- Result: `dns.google`

**IPv6 Example:**
- Input: `2001:4860:4860::8888`
- PTR Query: `8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa`
- Result: Hostname (if configured)

**Use Cases:**
- Identify hostname for suspicious IPs
- Verify mail server configuration
- Map IP ranges to organizations
- Investigate network infrastructure

---

#### 5. `bruteforce` - Subdomain Enumeration

Enumerate subdomains using wordlist-based brute force.

**Syntax:**
```bash
rb dns record bruteforce <domain> [FLAGS]
```

**Arguments:**
- `<domain>` - Base domain to enumerate (required)

**Flags:**
- `-w, --wordlist <file>` - Wordlist file path (required)
- `-t, --threads <n>` - Concurrent threads (default: 50)
- `-s, --server <ip>` - DNS server (default: 8.8.8.8)

**Examples:**

```bash
# Subdomain brute force
rb dns record bruteforce example.com --wordlist common

# Custom wordlist
rb dns record bruteforce target.com --wordlist /usr/share/wordlists/subdomains.txt

# High-speed bruteforce
rb dns record bruteforce example.com --wordlist large.txt --threads 200
```

**Status:** 🚧 Coming in Phase 2

**Planned Features:**
- Wordlist-based enumeration
- Multi-threaded DNS queries
- Smart rate limiting
- Wild card detection
- Zone transfer attempts
- Recursive enumeration

---

## Configuration

**Configuration File:** `./.redblue.yaml`

**DNS Section:**

```yaml
dns:
  timeout_ms: 2000              # DNS query timeout
  retry_count: 3                # Retries on failure
  default_server: "8.8.8.8"     # Default DNS server
  fallback_servers:             # Fallback servers if primary fails
    - "1.1.1.1"
    - "208.67.222.222"
```

**Environment Variables:**

```bash
export REDBLUE_DNS_TIMEOUT_MS=3000
export REDBLUE_DNS_DEFAULT_SERVER="1.1.1.1"
```

**Precedence:** Flags > Environment > Config File > Defaults

---

## DNS Record Types Reference

### A - IPv4 Address

Maps domain name to IPv4 address.

**Example:**
```bash
rb dns record lookup google.com --type A
```

**Output:**
```
A 142.250.185.78 300s
```

**Use Cases:**
- Identify web server IPs
- CDN detection (multiple A records)
- Load balancer configuration

---

### AAAA - IPv6 Address

Maps domain name to IPv6 address.

**Example:**
```bash
rb dns record lookup google.com --type AAAA
```

**Output:**
```
AAAA 2607:f8b0:4004:c07::8b 300s
```

**Use Cases:**
- IPv6 infrastructure mapping
- Dual-stack configuration verification

---

### MX - Mail Exchange

Mail server records with priority.

**Example:**
```bash
rb dns record lookup example.com --type MX
```

**Output:**
```
MX 10 mail1.example.com 3600s
MX 20 mail2.example.com 3600s
```

**Use Cases:**
- Email infrastructure discovery
- Mail server enumeration
- Spam source identification

---

### NS - Name Server

Authoritative nameservers for domain.

**Example:**
```bash
rb dns record lookup example.com --type NS
```

**Output:**
```
NS ns1.example.com 86400s
NS ns2.example.com 86400s
```

**Use Cases:**
- DNS infrastructure mapping
- Zone transfer attempts
- Registrar identification

---

### TXT - Text Records

Arbitrary text data (SPF, DKIM, verification).

**Example:**
```bash
rb dns record lookup example.com --type TXT
```

**Output:**
```
TXT v=spf1 include:_spf.google.com ~all 3600s
TXT google-site-verification=abc123 3600s
```

**Use Cases:**
- SPF/DKIM email authentication
- Domain ownership verification
- Configuration information leakage

---

### CNAME - Canonical Name

Alias to another domain name.

**Example:**
```bash
rb dns record lookup www.example.com --type CNAME
```

**Output:**
```
CNAME example.com 3600s
```

**Use Cases:**
- CDN detection (Cloudflare, Akamai)
- Service mapping (AWS, Azure)
- Subdomain structure

---

### SOA - Start of Authority

Zone information and serial numbers.

**Example:**
```bash
rb dns record lookup example.com --type SOA
```

**Output:**
```
SOA ns1.example.com hostmaster.example.com 2024110301 900 900 1800 60 86400s
```

**Fields:**
- **Primary NS**: `ns1.example.com`
- **Responsible email**: `hostmaster.example.com`
- **Serial**: `2024110301` (zone version)
- **Refresh**: `900` (secondary refresh interval)
- **Retry**: `900` (retry on failure)
- **Expire**: `1800` (zone expiration)
- **Minimum TTL**: `60` (negative cache)

**Use Cases:**
- Zone transfer information
- DNS change tracking (serial number)
- Email contact discovery

---

## Common Use Cases

### 1. Full Domain Reconnaissance

```bash
# Get all DNS records
rb dns record all example.com --persist

# Specific lookups
rb dns record lookup example.com --type A
rb dns record lookup example.com --type MX
rb dns record lookup example.com --type NS
rb dns record lookup example.com --type TXT
```

### 2. DNS Server Comparison

```bash
# Compare responses from different servers
rb dns record lookup example.com --server 8.8.8.8
rb dns record lookup example.com --server 1.1.1.1
rb dns record lookup example.com --server 208.67.222.222
```

### 3. Email Infrastructure Mapping

```bash
# Get mail servers
rb dns record lookup example.com --type MX

# Reverse lookup mail server IPs
rb dns record resolve mail1.example.com
rb dns record reverse <mail_server_ip>

# Check SPF records
rb dns record lookup example.com --type TXT
```

### 4. CDN and Infrastructure Detection

```bash
# Check for multiple A records (load balancing)
rb dns record lookup example.com --type A

# Check CNAME (CDN detection)
rb dns record lookup www.example.com --type CNAME

# Full infrastructure view
rb dns record all example.com
```

### 5. DNS Propagation Testing

```bash
# Check different DNS servers
rb dns record lookup newdomain.com --server 8.8.8.8
rb dns record lookup newdomain.com --server 1.1.1.1

# Compare results
rb dns record all newdomain.com --server 8.8.8.8 -o json > google.json
rb dns record all newdomain.com --server 1.1.1.1 -o json > cloudflare.json
diff google.json cloudflare.json
```

---

## Database Persistence

**File Format:** `./<domain>.rdb`

**What Gets Saved:**
- Domain name
- Record type
- Record values
- TTL values
- Query timestamp
- DNS server used

**Load Results:**
```bash
# Save during query
rb dns record all example.com --persist

# Load later in REPL
rb repl example.com.rb-session
```

---

## Performance Tips

**Fast Queries:**
- Use `resolve` for quick IP lookups
- Use specific `--type` instead of `all` for single record type
- Reduce timeout for faster failures: configure `timeout_ms: 1000`

**Comprehensive Recon:**
- Use `all` verb for parallel queries of all types
- Enable persistence: `--persist`
- Use intelligence gathering: `--intel`

**Reliability:**
- Configure fallback DNS servers in config
- Increase retry count for unreliable networks
- Use multiple DNS servers for comparison

---

## Tool Equivalents

| Traditional Tool | redblue Command | Notes |
|-----------------|-----------------|-------|
| `dig` | `rb dns record lookup` | DNS lookups |
| `dig +short` | `rb dns record resolve` | Quick resolution |
| `dig -x` | `rb dns record reverse` | Reverse DNS |
| `dig ANY` | `rb dns record all` | All records |
| `nslookup` | `rb dns record lookup` | Basic lookup |
| `host` | `rb dns record resolve` | Quick lookup |
| `dnsrecon` | `rb dns record bruteforce` | Subdomain enum (planned) |

---

## Technical Details

**Implementation:**
- **Language:** Pure Rust (zero external dependencies)
- **Protocol:** RFC 1035 compliant binary DNS protocol
- **Transport:** UDP port 53 (raw socket implementation)
- **Fallback:** TCP for truncated responses (coming soon)
- **Architecture:** Thread-safe parallel queries

**DNS Protocol Features:**
- Binary packet construction
- Proper compression handling
- All major record types
- EDNS support (planned)

**Limitations:**
- UDP only (TCP fallback planned for Phase 2)
- No DNSSEC validation yet (planned)
- Zone transfers not implemented (AXFR/IXFR - planned)

---

## Troubleshooting

**Query timeout:**
- Increase timeout: configure `timeout_ms: 3000`
- Try different DNS server: `--server 1.1.1.1`
- Check network connectivity
- Verify DNS server is reachable

**No records found:**
- Verify domain exists: try `resolve` first
- Check record type: use `all` to see what exists
- Try authoritative nameservers directly
- Check for NXDOMAIN vs NOERROR with no records

**VERSION.BIND fails:**
- Not all servers respond (security policy)
- Try direct nameserver instead of resolver
- Some servers hide version information
- This is expected behavior for many servers

**Reverse lookup fails:**
- Not all IPs have PTR records configured
- Check if IP is publicly routable
- Try authoritative nameserver for IP range
- Some organizations don't configure reverse DNS

---

## See Also

- [NETWORK Domain Documentation](./NETWORK.md) - Port scanning and discovery
- [RECON Domain Documentation](./RECON.md) - WHOIS and subdomain enumeration
- [WEB Domain Documentation](./WEB.md) - Web application testing
- [TLS Domain Documentation](./TLS.md) - Certificate inspection
