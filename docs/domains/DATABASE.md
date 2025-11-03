# DATABASE Domain Documentation

## Overview

The `database` domain provides binary database operations for scan result persistence, querying, exporting, and subnet analysis. RedDB (`.rdb` format) is a fast, segment-oriented binary database designed specifically for security reconnaissance data storage.

**Domain:** `database`

**Resource:** `data`

**Status:** ✅ Phase 1 (100% Complete)

**Database Format:** `.rdb` (REDBLUE v1) - Binary segment-oriented database

---

## Resource: `database data`

**Description:** Query, export, list, and analyze binary reconnaissance databases created by redblue scans.

### Commands

#### 1. `query` - Display Database Contents

Query a database file to display contents, statistics, and stored reconnaissance data.

**Syntax:**
```bash
rb database data query <file.rdb>
```

**Arguments:**
- `<file.rdb>` - Path to database file (required)

**Flags:**
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`

**What It Shows:**
- File size and format version
- Total records count
- Port scan results (first 10)
- DNS records count
- Subdomain discoveries
- Timestamps and statistics

**Examples:**

```bash
# Query single host database
rb database data query 192.168.1.1.rdb

# Query domain database
rb database data query example.com.rdb

# JSON output for automation
rb database data query 192.168.1.1.rdb -o json
```

**Sample Output (Text):**

```
Reading database... ✓

📊 Database: 192.168.1.1.rdb

  Size: 24 KB
  Format: REDBLUE v1

Statistics
  Total records: 15
  Port scans: 12
  DNS records: 3
  Subdomains: 0

Port Scans (12) - showing first 10
  192.168.1.1:22 - OPEN (ssh)
  192.168.1.1:80 - OPEN (http)
  192.168.1.1:443 - OPEN (https)
  192.168.1.1:3306 - OPEN (mysql)
  192.168.1.1:8080 - OPEN (http)
  192.168.1.1:21 - CLOSED (ftp)
  192.168.1.1:25 - CLOSED (smtp)
  192.168.1.1:110 - CLOSED (unknown)
  192.168.1.1:143 - CLOSED (unknown)
  192.168.1.1:465 - CLOSED (unknown)
  ... and 2 more

DNS Records (3)
  3 DNS records stored

✓ Query completed
```

**Sample Output (JSON):**

```json
{
  "file": "192.168.1.1.rdb",
  "size_kb": 24,
  "format": "REDBLUE v1",
  "statistics": {
    "total_records": 15,
    "port_scans": 12,
    "dns_records": 3,
    "subdomains": 0
  },
  "port_scans": [
    {
      "ip": "192.168.1.1",
      "port": 22,
      "state": "OPEN",
      "service": "ssh",
      "timestamp": 1730678400
    },
    {
      "ip": "192.168.1.1",
      "port": 80,
      "state": "OPEN",
      "service": "http",
      "timestamp": 1730678400
    }
  ]
}
```

---

#### 2. `export` - Export to CSV

Export database contents to CSV format for analysis in spreadsheet tools, SIEM systems, or custom scripts.

**Syntax:**
```bash
rb database data export <file.rdb> [FLAGS]
```

**Arguments:**
- `<file.rdb>` - Path to database file (required)

**Flags:**
- `-o, --output <file.csv>` - Output CSV file path
  - Default: `<filename>.csv` (auto-generated)

**CSV Format:**

The export creates multi-section CSV with headers:

**Port Scans Section:**
```
# Port Scans
IP,Port,State,Service,Timestamp
192.168.1.1,22,OPEN,ssh,1730678400
192.168.1.1,80,OPEN,http,1730678400
```

**DNS Records Section:**
```
# DNS Records
Domain,Type,TTL,Value
example.com,A,300,93.184.216.34
example.com,MX,3600,10 mail.example.com
```

**Examples:**

```bash
# Export with auto-generated filename
rb database data export 192.168.1.1.rdb

# Export to specific file
rb database data export 192.168.1.1.rdb --output scan_results.csv

# Export domain database
rb database data export example.com.rdb -o dns_results.csv
```

**Sample Output:**

```
Exporting database... ✓

✓ Exported to 192.168.1.1.csv
```

**Sample CSV File (192.168.1.1.csv):**

```csv
# Port Scans
IP,Port,State,Service,Timestamp
192.168.1.1,22,OPEN,ssh,1730678400
192.168.1.1,80,OPEN,http,1730678401
192.168.1.1,443,OPEN,https,1730678402
192.168.1.1,3306,OPEN,mysql,1730678403
192.168.1.1,8080,OPEN,http,1730678404
192.168.1.1,21,CLOSED,ftp,1730678405

# DNS Records
Domain,Type,TTL,Value
example.com,A,300,93.184.216.34
example.com,AAAA,300,2606:2800:220:1:248:1893:25c8:1946
example.com,MX,3600,10 mail.example.com
```

---

#### 3. `list` - List Database Files

List all `.rdb` database files in the current directory with size and record count information.

**Syntax:**
```bash
rb database data list
```

**Arguments:**
- None (scans current directory)

**Flags:**
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`

**Examples:**

```bash
# List all databases in current directory
rb database data list

# JSON output
rb database data list -o json
```

**Sample Output (Text):**

```
📊 Database Files

  192.168.1.1.rdb (24 KB) - 15 records
  192.168.1.2.rdb (18 KB) - 8 records
  192.168.1.10.rdb (32 KB) - 23 records
  example.com.rdb (12 KB) - 6 records
  google.com.rdb (45 KB) - 42 records

✓ Found 5 database(s)
```

**Sample Output (JSON):**

```json
{
  "databases": [
    {
      "file": "192.168.1.1.rdb",
      "size_kb": 24,
      "total_records": 15
    },
    {
      "file": "192.168.1.2.rdb",
      "size_kb": 18,
      "total_records": 8
    },
    {
      "file": "example.com.rdb",
      "size_kb": 12,
      "total_records": 6
    }
  ],
  "total_databases": 5
}
```

---

#### 4. `subnets` - List Discovered Subnets

Analyze all IP-based databases and group them by /24 subnets, showing host counts and reconnaissance coverage.

**Syntax:**
```bash
rb database data subnets
```

**Arguments:**
- None (scans current directory)

**Flags:**
- `-o, --output <format>` - Output format: `text`, `json`
  - Default: `text`

**What It Does:**
- Scans current directory for `.rdb` files
- Parses filenames as IP addresses (e.g., `192.168.1.1.rdb`)
- Groups IPs by /24 subnet (e.g., `192.168.1.0/24`)
- Shows host count per subnet
- Displays stored records (ports, DNS) per host
- Sorts subnets and hosts numerically

**Examples:**

```bash
# List all discovered subnets
rb database data subnets

# JSON output for automation
rb database data subnets -o json
```

**Sample Output (Text):**

```
🌐 Discovered Subnets

  192.168.1.0/24 - 5 host(s)
    • 192.168.1.1 (12 ports, 3 DNS)
    • 192.168.1.2 (8 ports)
    • 192.168.1.10 (23 ports, 5 DNS)
    • 192.168.1.50 (3 ports)
    • 192.168.1.100 (15 ports, 2 DNS)

  10.0.0.0/24 - 3 host(s)
    • 10.0.0.1 (45 ports)
    • 10.0.0.5 (8 ports)
    • 10.0.0.10 (12 ports, 1 DNS)

  172.16.0.0/24 - 2 host(s)
    • 172.16.0.1 (32 ports, 10 DNS)
    • 172.16.0.5 (18 ports)

✓ Found 3 subnet(s) with 10 total host(s)
```

**Sample Output (JSON):**

```json
{
  "subnets": [
    {
      "subnet": "192.168.1.0/24",
      "host_count": 5,
      "hosts": [
        {
          "ip": "192.168.1.1",
          "ports": 12,
          "dns_records": 3
        },
        {
          "ip": "192.168.1.2",
          "ports": 8,
          "dns_records": 0
        }
      ]
    }
  ],
  "total_subnets": 3,
  "total_hosts": 10
}
```

---

## Database Persistence

### How Databases Are Created

Databases are automatically created when using the `--persist` flag with reconnaissance commands:

**Port Scanning:**
```bash
# Save port scan results
rb network ports scan 192.168.1.1 --persist
# Creates: 192.168.1.1.rdb

# Save subnet scan results
rb network ports subnet 192.168.1.0/24 --persist
# Creates: 192.168.1.1.rdb, 192.168.1.2.rdb, ... (one per host)
```

**DNS Queries:**
```bash
# Save DNS records
rb dns record all example.com --persist
# Creates: example.com.rdb

# Save subdomain enumeration
rb dns record bruteforce example.com --persist
# Updates: example.com.rdb (appends subdomains)
```

**Web Scanning:**
```bash
# Save web scan results
rb web asset scan https://example.com --persist
# Updates: example.com.rdb
```

### Configuration

Control persistence behavior via `.redblue.yaml`:

```yaml
database:
  # Auto-save all scans (don't require --persist flag)
  auto_persist: true

  # Database directory (default: current directory)
  db_dir: ./scan_results

  # Database filename pattern
  # {target} = target hostname/IP
  # {date} = current date (YYYY-MM-DD)
  # {time} = current time (HH-MM-SS)
  filename_pattern: "{target}.rdb"
  # OR: filename_pattern: "{target}_{date}.rdb"

  # Compression (future feature)
  compress: false
```

**Global config:** `~/.config/redblue/config.toml`
**Project config:** `./.redblue.yaml` (takes precedence)

---

## Database Format Technical Details

### Binary Structure

RedDB uses a segment-oriented binary format optimized for fast writes and reads:

```
┌─────────────────────────────────────┐
│ HEADER (32 bytes)                   │
│ - Magic: "REDBLUE" (8 bytes)        │
│ - Version: v1 (4 bytes)             │
│ - Record count (8 bytes)            │
│ - Timestamp (8 bytes)               │
│ - Reserved (4 bytes)                │
├─────────────────────────────────────┤
│ SEGMENT 1: Port Scans               │
│ - Segment type (1 byte)             │
│ - Segment size (4 bytes)            │
│ - Record count (4 bytes)            │
│ - Records (variable)                │
├─────────────────────────────────────┤
│ SEGMENT 2: DNS Records              │
│ - Segment type (1 byte)             │
│ - Segment size (4 bytes)            │
│ - Record count (4 bytes)            │
│ - Records (variable)                │
├─────────────────────────────────────┤
│ SEGMENT 3: Subdomains               │
│ - ...                               │
├─────────────────────────────────────┤
│ INDEX (optional, end of file)       │
│ - Fast lookup index                 │
└─────────────────────────────────────┘
```

### Record Types

**Port Scan Record (24 bytes):**
```
┌──────────┬──────┬───────┬────────────┬───────────┐
│ IP (4B)  │Port  │State  │Service ID  │Timestamp  │
│ u32      │u16   │u8     │u16         │u64        │
└──────────┴──────┴───────┴────────────┴───────────┘
```

**DNS Record (variable):**
```
┌────────┬──────────┬─────┬──────┬──────────────┐
│Domain  │Type      │TTL  │Len   │Data          │
│[u8;64] │u16       │u32  │u16   │[u8; variable]│
└────────┴──────────┴─────┴──────┴──────────────┘
```

### Storage Efficiency

**Comparison to JSON:**
```
JSON (example.com with 10 DNS records):
  File size: ~2.5 KB
  Parse time: ~0.5ms
  Memory usage: ~4 KB

RedDB (.rdb with same data):
  File size: ~0.8 KB (3x smaller)
  Parse time: ~0.1ms (5x faster)
  Memory usage: ~1 KB (4x less)
```

**Benefits:**
- ✅ Fast binary reads (no parsing overhead)
- ✅ Compact storage (3-5x smaller than JSON)
- ✅ Append-only writes (no full rewrite needed)
- ✅ Platform-independent (works on Linux, macOS, Windows)
- ✅ Random access via index (future enhancement)

---

## Common Use Cases

### 1. **Post-Scan Analysis**

After running multiple scans, analyze all results:

```bash
# Run scans with persistence
rb network ports scan 192.168.1.1 --persist
rb network ports scan 192.168.1.2 --persist
rb dns record all example.com --persist

# List all databases
rb database data list

# Query specific target
rb database data query 192.168.1.1.rdb

# Export for spreadsheet analysis
rb database data export 192.168.1.1.rdb
```

### 2. **Subnet Reconnaissance Coverage**

Track which hosts in a subnet have been scanned:

```bash
# Scan entire /24 subnet
rb network ports subnet 192.168.1.0/24 --persist

# Check coverage
rb database data subnets

# Expected output:
# 192.168.1.0/24 - 254 host(s)
#   • 192.168.1.1 (12 ports)
#   • 192.168.1.2 (8 ports)
#   • ... (252 more)
```

### 3. **Continuous Monitoring**

Compare scans over time to detect changes:

```bash
# Day 1: Initial scan
rb network ports scan 192.168.1.1 --persist
rb database data export 192.168.1.1.rdb -o day1.csv

# Day 7: Follow-up scan
rb network ports scan 192.168.1.1 --persist
rb database data export 192.168.1.1.rdb -o day7.csv

# Compare CSVs (external tool)
diff day1.csv day7.csv
```

### 4. **Report Generation**

Export data for inclusion in security reports:

```bash
# Export all targets
for db in *.rdb; do
  rb database data export "$db"
done

# Combine CSVs (bash)
cat *.csv > combined_report.csv

# Or use Python/pandas for advanced analysis
```

### 5. **REPL Interactive Exploration**

Open database in interactive REPL mode:

```bash
# Launch REPL with database
rb repl 192.168.1.1.rdb

# Inside REPL:
> show ports
> show dns
> query port 22
> export csv
```

---

## Integration with Other Domains

### Network Domain
```bash
# Port scanning with persistence
rb network ports scan 192.168.1.1 --persist
rb network ports subnet 10.0.0.0/24 --persist --threads 500

# Query results
rb database data query 192.168.1.1.rdb
```

### DNS Domain
```bash
# DNS enumeration with persistence
rb dns record all example.com --persist
rb dns record bruteforce example.com --persist

# Export for analysis
rb database data export example.com.rdb
```

### Web Domain
```bash
# Web scanning with persistence
rb web asset scan https://example.com --persist

# Combined with port scan
rb network ports scan example.com --persist
rb database data query example.com.rdb
```

### RECON Domain
```bash
# WHOIS with persistence
rb recon domain whois example.com --persist

# Subdomain enumeration with persistence
rb recon domain subdomains example.com --persist

# View all recon data
rb database data query example.com.rdb
```

---

## Troubleshooting

### Database Corruption

**Problem:** Database file is corrupted or unreadable

**Solutions:**
```bash
# Check file size (should be > 32 bytes for header)
ls -lh *.rdb

# Try to read with verbose errors
rb database data query example.com.rdb --verbose

# If corrupted, delete and re-scan
rm example.com.rdb
rb network ports scan example.com --persist
```

### Missing Databases

**Problem:** `list` shows no databases but scans were run

**Solutions:**
1. Check if `--persist` flag was used during scans
2. Check configuration: `cat .redblue.yaml | grep auto_persist`
3. Look in configured db_dir if set
4. Files may have `.rdb` extension (old format) - rename to `.rdb`

### Export Fails

**Problem:** CSV export fails or produces empty file

**Solutions:**
```bash
# Check database has records
rb database data query example.com.rdb

# Ensure write permissions
touch test.csv && rm test.csv

# Try different output path
rb database data export example.com.rdb -o /tmp/export.csv
```

### Subnet Detection Not Working

**Problem:** `subnets` command shows "No IP-based databases found"

**Solutions:**
1. Databases must be named like `192.168.1.1.rdb` (IP address as filename)
2. Rename domain databases: `mv example.com.rdb 93.184.216.34.rdb`
3. Only works for IP-based scans, not domain scans

---

## Performance Tips

### Large Databases

For databases > 100MB:

```bash
# Query shows only first 10 records by default
rb database data query large.rdb

# Export to CSV for full analysis (may take time)
rb database data export large.rdb -o full_export.csv

# Use REPL for interactive queries
rb repl large.rdb
```

### Batch Export

Export multiple databases efficiently:

```bash
# Parallel export (requires GNU parallel)
ls *.rdb | parallel rb database data export {}

# Bash loop (sequential)
for db in *.rdb; do
  echo "Exporting $db..."
  rb database data export "$db"
done
```

---

## See Also

- [NETWORK Domain](./NETWORK.md) - Port scanning with `--persist`
- [DNS Domain](./DNS.md) - DNS queries with `--persist`
- [WEB Domain](./WEB.md) - Web scanning with persistence
- [RECON Domain](./RECON.md) - OSINT with persistence

**Configuration:**
- `.redblue.yaml` - Project-level database settings
- `~/.config/redblue/config.toml` - Global configuration

---

**Database Location:** `./<target>.rdb` (current directory by default)
**Format:** Binary segment-oriented (REDBLUE v1)
**Compatibility:** Cross-platform (Linux, macOS, Windows)
