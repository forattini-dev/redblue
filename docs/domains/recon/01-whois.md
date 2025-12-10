# WHOIS Lookup

Query domain registration information - registrar, dates, nameservers.

## Quick Start

```bash
# Basic WHOIS lookup
rb recon domain whois google.com

# Show raw response
rb recon domain whois example.com --raw

# JSON output
rb recon domain whois github.com -o json
```

## Command

### whois - Domain Registration Lookup

Query WHOIS information including registrar, dates, nameservers, and status.

```bash
rb recon domain whois <domain> [flags]
```

## Options

```rust
// WHOIS lookup options
struct WhoisOptions {
    // Show raw WHOIS response
    // Default: false
    raw: bool,

    // Output format
    // Values: "text", "json", "yaml"
    // Default: "text"
    output: String,

    // Save results to database
    // Default: false
    persist: bool,

    // Query timeout in seconds
    // Range: 1-60
    // Default: 10
    timeout_secs: u32,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--raw` | | Show raw WHOIS response | false |
| `--output` | `-o` | Output format: text, json, yaml | text |
| `--persist` | | Save to database (.rdb) | false |
| `--no-persist` | | Don't save (override config) | - |
| `--timeout` | `-t` | Query timeout (secs) | 10 |

## Supported TLDs

### Generic TLDs

| TLD | WHOIS Server |
|-----|--------------|
| .com | whois.verisign-grs.com |
| .net | whois.verisign-grs.com |
| .org | whois.pir.org |
| .info | whois.afilias.net |
| .biz | whois.biz |

### Popular TLDs

| TLD | WHOIS Server |
|-----|--------------|
| .io | whois.nic.io |
| .co | whois.nic.co |
| .dev | whois.nic.google |
| .app | whois.nic.google |
| .ai | whois.nic.ai |
| .me | whois.nic.me |

### Country Code TLDs

| TLD | WHOIS Server |
|-----|--------------|
| .uk | whois.nic.uk |
| .de | whois.denic.de |
| .fr | whois.nic.fr |
| .br | whois.registro.br |
| .jp | whois.jprs.jp |
| .au | whois.auda.org.au |

## Examples

### Basic Lookup

```bash
# Standard WHOIS query
rb recon domain whois google.com

# Different TLDs
rb recon domain whois github.io
rb recon domain whois example.co.uk
```

### Raw Response

```bash
# Show complete WHOIS response
rb recon domain whois example.com --raw
```

### Structured Output

```bash
# JSON for parsing
rb recon domain whois google.com -o json

# YAML output
rb recon domain whois google.com -o yaml

# Pipe to jq
rb recon domain whois google.com -o json | jq '.nameservers'
```

### With Persistence

```bash
# Save to database
rb recon domain whois example.com --persist

# Query saved data later
rb database data query example.com.rdb
```

## Output Examples

### Text Output

```
Querying WHOIS for google.com... ✓

WHOIS: google.com

  Registrar: MarkMonitor Inc.
  Org: Google LLC
  Country: US

  Created: 1997-09-15
  Updated: 2019-09-09
  Expires: 2028-09-14

Nameservers (4)
  ns1.google.com
  ns2.google.com
  ns3.google.com
  ns4.google.com

Status (6)
  clientDeleteProhibited
  clientTransferProhibited
  clientUpdateProhibited
  serverDeleteProhibited
  serverTransferProhibited
  serverUpdateProhibited

✓ WHOIS lookup completed
```

### JSON Output

```json
{
  "domain": "google.com",
  "registrar": "MarkMonitor Inc.",
  "registrant_org": "Google LLC",
  "registrant_country": "US",
  "creation_date": "1997-09-15",
  "updated_date": "2019-09-09",
  "expiration_date": "2028-09-14",
  "name_servers": [
    "ns1.google.com",
    "ns2.google.com",
    "ns3.google.com",
    "ns4.google.com"
  ],
  "status": [
    "clientDeleteProhibited",
    "clientTransferProhibited",
    "clientUpdateProhibited",
    "serverDeleteProhibited",
    "serverTransferProhibited",
    "serverUpdateProhibited"
  ]
}
```

### Raw Output

```
Domain Name: GOOGLE.COM
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2019-09-09T15:39:04Z
Creation Date: 1997-09-15T04:00:00Z
Registry Expiry Date: 2028-09-14T04:00:00Z
Registrar: MarkMonitor Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2086851750
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
...
```

## WHOIS Data Fields

| Field | Description |
|-------|-------------|
| `domain` | Domain name queried |
| `registrar` | Domain registrar company |
| `registrant_org` | Registrant organization |
| `registrant_country` | Registrant country code |
| `creation_date` | Domain creation date |
| `updated_date` | Last update date |
| `expiration_date` | Domain expiration date |
| `name_servers` | Authoritative nameservers |
| `status` | EPP status codes |

## Patterns

### Domain Age Check

```bash
# Check when domain was created
rb recon domain whois example.com -o json | jq '.creation_date'
```

### Expiration Monitoring

```bash
# Check expiration date
rb recon domain whois example.com -o json | jq '.expiration_date'

# Batch check multiple domains
for domain in example.com google.com github.com; do
  echo -n "$domain: "
  rb recon domain whois $domain -o json | jq -r '.expiration_date'
done
```

### Nameserver Analysis

```bash
# Extract nameservers
rb recon domain whois example.com -o json | jq '.name_servers[]'

# Check if using common DNS providers
rb recon domain whois example.com -o json | \
  jq '.name_servers[] | select(contains("cloudflare"))'
```

### Registrar Intelligence

```bash
# Find domains using same registrar
rb recon domain whois target1.com -o json | jq '.registrar'
rb recon domain whois target2.com -o json | jq '.registrar'
```

## Technical Details

### Protocol

- **RFC:** RFC 3912
- **Port:** TCP 43
- **Encoding:** ASCII/UTF-8

### Server Selection

redblue automatically selects the correct WHOIS server based on TLD:

```
example.com → whois.verisign-grs.com
example.org → whois.pir.org
example.io  → whois.nic.io
```

### Rate Limiting

Some WHOIS servers implement rate limiting:

| Server | Limit |
|--------|-------|
| verisign-grs.com | ~50/hour |
| nic.io | ~10/min |
| registro.br | ~5/min |

## Troubleshooting

### WHOIS Query Failed

```bash
# Check with raw output
rb recon domain whois example.com --raw

# Verify domain exists
rb dns record lookup example.com
```

### Unknown TLD

```bash
# Some TLDs may not be supported yet
# Check if domain resolves
rb dns record lookup example.xyz
```

### Rate Limited

```bash
# Wait and retry
# Or use different DNS for verification
rb dns record lookup example.com --server 1.1.1.1
```

## Next Steps

- [Subdomain Enumeration](02-subdomains.md) - Find subdomains
- [URL Discovery](03-urls.md) - Historical URLs
- [Configuration](05-configuration.md) - Recon settings
