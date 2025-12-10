# DNS Lookups

Query DNS records for domains - A, AAAA, MX, NS, TXT, CNAME, SOA, PTR.

## Quick Start

```bash
# Simplest - lookup A record
rb dns lookup record example.com

# Lookup specific type
rb dns lookup record example.com --type MX

# Quick resolve (A only)
rb dns resolve record github.com
```

## Commands

### lookup - Full DNS Query

Query DNS records with full response details.

```bash
rb dns lookup record <domain> [flags]
```

### resolve - Quick Resolution

Fast A record resolution (IP only).

```bash
rb dns resolve record <domain>
```

## Options

```rust
// DNS lookup options
struct DnsLookupOptions {
    // Record type to query
    // Values: "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"
    // Default: "A"
    record_type: String,

    // DNS server to query
    // Default: "8.8.8.8"
    server: String,

    // Query timeout in milliseconds
    // Range: 100-30000
    // Default: 5000
    timeout_ms: u32,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--type` | `-t` | Record type | A |
| `--server` | `-s` | DNS server | 8.8.8.8 |
| `--timeout` | | Query timeout (ms) | 5000 |
| `--output` | `-o` | Output format | text |

## Record Types

### A - IPv4 Address

```bash
rb dns lookup record example.com --type A

# Output:
# example.com.    A    93.184.216.34
```

### AAAA - IPv6 Address

```bash
rb dns lookup record example.com --type AAAA

# Output:
# example.com.    AAAA    2606:2800:220:1:248:1893:25c8:1946
```

### MX - Mail Exchanger

```bash
rb dns lookup record google.com --type MX

# Output:
# google.com.    MX    10 smtp.google.com.
# google.com.    MX    20 smtp2.google.com.
# google.com.    MX    30 smtp3.google.com.
```

### NS - Name Server

```bash
rb dns lookup record example.com --type NS

# Output:
# example.com.    NS    ns1.example.com.
# example.com.    NS    ns2.example.com.
```

### TXT - Text Record

```bash
rb dns lookup record google.com --type TXT

# Output:
# google.com.    TXT    "v=spf1 include:_spf.google.com ~all"
# google.com.    TXT    "google-site-verification=..."
```

### CNAME - Canonical Name

```bash
rb dns lookup record www.github.com --type CNAME

# Output:
# www.github.com.    CNAME    github.com.
```

### SOA - Start of Authority

```bash
rb dns lookup record example.com --type SOA

# Output:
# example.com.    SOA    ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 3600
```

### PTR - Reverse Lookup

```bash
rb dns lookup record 8.8.8.8 --type PTR

# Output:
# 8.8.8.8.in-addr.arpa.    PTR    dns.google.
```

## Examples

### Basic Lookups

```bash
# A record (default)
rb dns lookup record example.com

# Specific type
rb dns lookup record example.com --type MX

# Quick resolve
rb dns resolve record github.com
# → 140.82.121.4
```

### Custom DNS Server

```bash
# Use Cloudflare
rb dns lookup record example.com --server 1.1.1.1

# Use Google
rb dns lookup record example.com --server 8.8.8.8

# Use local resolver
rb dns lookup record internal.corp --server 10.0.0.53
```

### All Record Types

```bash
# Query all common types
for type in A AAAA MX NS TXT CNAME; do
  echo "=== $type ==="
  rb dns lookup record example.com --type $type
done
```

### JSON Output

```bash
# JSON for automation
rb dns lookup record example.com -o json

# Parse with jq
rb dns lookup record example.com -o json | jq '.records[].value'
```

## Output Examples

### Text Output

```
DNS Lookup: example.com
Server: 8.8.8.8
Type: A

ANSWER SECTION:
example.com.    299    IN    A    93.184.216.34

Query time: 23 ms
```

### JSON Output

```json
{
  "domain": "example.com",
  "server": "8.8.8.8",
  "type": "A",
  "query_time_ms": 23,
  "records": [
    {
      "name": "example.com.",
      "type": "A",
      "ttl": 299,
      "value": "93.184.216.34"
    }
  ]
}
```

### MX Output

```
DNS Lookup: google.com
Server: 8.8.8.8
Type: MX

ANSWER SECTION:
google.com.    299    IN    MX    10 smtp.google.com.
google.com.    299    IN    MX    20 smtp2.google.com.
google.com.    299    IN    MX    30 smtp3.google.com.
google.com.    299    IN    MX    40 smtp4.google.com.
google.com.    299    IN    MX    50 smtp-relay.gmail.com.

Query time: 45 ms
```

## Patterns

### Domain Reconnaissance

```bash
# Step 1: Get mail servers
rb dns lookup record target.com --type MX

# Step 2: Get name servers
rb dns lookup record target.com --type NS

# Step 3: Check SPF/DKIM
rb dns lookup record target.com --type TXT

# Step 4: Get IPs
rb dns lookup record target.com --type A
rb dns lookup record target.com --type AAAA
```

### Email Investigation

```bash
# Find mail servers
rb dns lookup record example.com --type MX

# Check SPF
rb dns lookup record example.com --type TXT | grep spf

# Check DMARC
rb dns lookup record _dmarc.example.com --type TXT

# Check DKIM
rb dns lookup record selector._domainkey.example.com --type TXT
```

### Subdomain to IP

```bash
# Get IPs for subdomains
for sub in www mail ftp api; do
  echo "$sub.example.com:"
  rb dns resolve record $sub.example.com
done
```

## Technical Notes

- **Protocol:** RFC 1035 compliant UDP DNS
- **Default server:** 8.8.8.8 (Google DNS)
- **Port:** 53 (UDP)
- **Implementation:** Pure Rust, no external crates

## Next Steps

- [Configuration](/domains/dns/02-configuration.md) - DNS settings
- [Recon Domain](/domains/recon) - WHOIS and subdomain discovery
