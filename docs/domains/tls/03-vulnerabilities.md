# TLS Vulnerability Scanning

Detect known TLS/SSL vulnerabilities and CVEs.

## Quick Start

```bash
# Basic vulnerability scan
rb tls security vuln google.com

# Scan mail server
rb tls security vuln mail.example.com:465

# JSON output
rb tls security vuln example.com -o json
```

## Command

### vuln - Vulnerability Scanner

Scan for known TLS/SSL vulnerabilities.

```bash
rb tls security vuln <host[:port]> [flags]
```

## Options

```rust
// Vulnerability scan options
struct VulnScanOptions {
    // Target port
    // Default: 443
    port: u16,

    // Connection timeout in seconds
    // Range: 1-60
    // Default: 10
    timeout_secs: u32,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,

    // Save results to database
    // Default: false
    persist: bool,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--port` | `-p` | Target port | 443 |
| `--timeout` | `-t` | Connection timeout (secs) | 10 |
| `--output` | `-o` | Output format | text |
| `--persist` | | Save to database | false |

## Vulnerabilities Detected

### Critical

| Vulnerability | CVE | Attack |
|---------------|-----|--------|
| POODLE | CVE-2014-3566 | Padding oracle on SSL 3.0 |
| Heartbleed | CVE-2014-0160 | Memory disclosure |
| DROWN | CVE-2016-0800 | Cross-protocol attack |

### High

| Vulnerability | CVE | Attack |
|---------------|-----|--------|
| BEAST | CVE-2011-3389 | CBC IV attack on TLS 1.0 |
| FREAK | CVE-2015-0204 | Export cipher downgrade |
| Logjam | CVE-2015-4000 | DHE export downgrade |

### Medium

| Vulnerability | CVE | Attack |
|---------------|-----|--------|
| CRIME | CVE-2012-4929 | TLS compression attack |
| Sweet32 | CVE-2016-2183 | Birthday attack on 3DES |
| ROBOT | CVE-2017-13099 | RSA padding oracle |

## Examples

### Basic Scan

```bash
# Default HTTPS
rb tls security vuln google.com

# Custom port
rb tls security vuln example.com:8443
```

### Different Services

```bash
# SMTP with TLS
rb tls security vuln mail.example.com:465

# IMAP with TLS
rb tls security vuln mail.example.com:993

# POP3 with TLS
rb tls security vuln mail.example.com:995
```

### Output Formats

```bash
# Text (default)
rb tls security vuln example.com

# JSON for automation
rb tls security vuln example.com -o json

# Extract critical vulns
rb tls security vuln example.com -o json | \
  jq '.vulnerabilities[] | select(.severity == "critical")'
```

## Output Examples

### Text Output (Secure)

```
Scanning for TLS vulnerabilities... ✓

TLS Vulnerability Scan: google.com:443

✓ No known TLS vulnerabilities detected
  The TLS configuration appears secure

Checks Performed:
  ✓ POODLE (SSL 3.0 disabled)
  ✓ BEAST (TLS 1.0 disabled or mitigated)
  ✓ Heartbleed (Not vulnerable)
  ✓ CRIME (Compression disabled)
  ✓ FREAK (Export ciphers disabled)
  ✓ Logjam (Weak DHE disabled)
  ✓ DROWN (SSLv2 disabled)
  ✓ Sweet32 (3DES disabled)

Security Grade: A
```

### Text Output (Vulnerable)

```
TLS Vulnerability Scan: vulnerable.example.com:443

Vulnerability Summary (Total: 5)
  CRITICAL:  2
  HIGH:      2
  MEDIUM:    1

CRITICAL Vulnerabilities (2)

  POODLE (CVE-2014-3566)
    SSL 3.0 is enabled and vulnerable to padding oracle attack.
    Risk: Attacker can decrypt encrypted traffic
    Remediation: Disable SSL 3.0 entirely

  DROWN (CVE-2016-0800)
    SSLv2 protocol is enabled, allowing cross-protocol attacks.
    Risk: Attacker can decrypt TLS traffic using SSLv2
    Remediation: Disable SSLv2 and SSLv3

HIGH Vulnerabilities (2)

  BEAST (CVE-2011-3389)
    TLS 1.0 with CBC ciphers is vulnerable.
    Risk: Attacker can recover plaintext
    Remediation: Disable TLS 1.0 or use AES-GCM only

  Weak Cipher Suites
    RC4 and 3DES ciphers are enabled.
    Risk: Encrypted data may be compromised
    Remediation: Remove weak ciphers from configuration

MEDIUM Vulnerabilities (1)

  Sweet32 (CVE-2016-2183)
    64-bit block ciphers (3DES) are enabled.
    Risk: Birthday attack after ~32GB of traffic
    Remediation: Disable 3DES cipher suites

Overall Security Grade: F
```

### JSON Output

```json
{
  "host": "vulnerable.example.com",
  "port": 443,
  "grade": "F",
  "summary": {
    "total": 5,
    "critical": 2,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "vulnerabilities": [
    {
      "name": "POODLE",
      "cve": "CVE-2014-3566",
      "severity": "critical",
      "description": "SSL 3.0 is enabled and vulnerable to padding oracle attack",
      "remediation": "Disable SSL 3.0 entirely",
      "affected": "SSL 3.0"
    },
    {
      "name": "DROWN",
      "cve": "CVE-2016-0800",
      "severity": "critical",
      "description": "SSLv2 protocol is enabled",
      "remediation": "Disable SSLv2 and SSLv3",
      "affected": "SSLv2"
    },
    {
      "name": "BEAST",
      "cve": "CVE-2011-3389",
      "severity": "high",
      "description": "TLS 1.0 with CBC ciphers is vulnerable",
      "remediation": "Disable TLS 1.0 or use AES-GCM only",
      "affected": "TLS 1.0 + CBC"
    }
  ],
  "checks": {
    "poodle": {"vulnerable": true, "details": "SSL 3.0 enabled"},
    "beast": {"vulnerable": true, "details": "TLS 1.0 with CBC"},
    "heartbleed": {"vulnerable": false},
    "crime": {"vulnerable": false},
    "freak": {"vulnerable": false},
    "logjam": {"vulnerable": false},
    "drown": {"vulnerable": true, "details": "SSLv2 enabled"},
    "sweet32": {"vulnerable": true, "details": "3DES enabled"}
  }
}
```

## Vulnerability Details

### POODLE (CVE-2014-3566)

**Padding Oracle On Downgraded Legacy Encryption**

```
Affected: SSL 3.0
Attack: Padding oracle attack on CBC mode
Impact: Decrypt encrypted traffic
Fix: Disable SSL 3.0
```

### Heartbleed (CVE-2014-0160)

**OpenSSL Memory Disclosure**

```
Affected: OpenSSL 1.0.1 - 1.0.1f
Attack: Read server memory
Impact: Expose private keys, credentials
Fix: Update OpenSSL
```

### BEAST (CVE-2011-3389)

**Browser Exploit Against SSL/TLS**

```
Affected: TLS 1.0 with CBC
Attack: Chosen-boundary attack
Impact: Decrypt cookies
Fix: TLS 1.2+, prefer GCM ciphers
```

### DROWN (CVE-2016-0800)

**Decrypting RSA with Obsolete and Weakened eNcryption**

```
Affected: SSLv2 enabled anywhere
Attack: Cross-protocol attack
Impact: Decrypt TLS traffic
Fix: Disable SSLv2 everywhere
```

### Sweet32 (CVE-2016-2183)

**Birthday Attack on 64-bit Block Ciphers**

```
Affected: 3DES, Blowfish
Attack: Birthday collision
Impact: Recover plaintext after ~32GB
Fix: Disable 3DES
```

## Patterns

### Compliance Check

```bash
# Check for any critical vulnerabilities
rb tls security vuln payment.example.com -o json | \
  jq -e '.summary.critical == 0'

# PCI-DSS: No SSL 3.0, TLS 1.0
rb tls security vuln payment.example.com -o json | \
  jq '.checks | .poodle.vulnerable == false and .beast.vulnerable == false'
```

### Batch Scanning

```bash
# Scan multiple hosts
for host in $(cat hosts.txt); do
  echo "Scanning $host..."
  rb tls security vuln "$host" --persist
done

# Find vulnerable hosts
rb database data query all-hosts.rdb | grep "CRITICAL"
```

### CI/CD Integration

```bash
#!/bin/bash
# Fail build if critical vulns found

RESULT=$(rb tls security vuln $HOST -o json)
CRITICAL=$(echo $RESULT | jq '.summary.critical')

if [ "$CRITICAL" -gt 0 ]; then
  echo "CRITICAL: $CRITICAL vulnerabilities found!"
  echo $RESULT | jq '.vulnerabilities[] | select(.severity == "critical")'
  exit 1
fi

echo "TLS security check passed"
```

### Remediation Tracking

```bash
# Before fix
rb tls security vuln example.com -o json > before.json

# Apply fix...

# After fix
rb tls security vuln example.com -o json > after.json

# Verify fix
echo "Before: $(jq '.summary.total' before.json) vulnerabilities"
echo "After: $(jq '.summary.total' after.json) vulnerabilities"
```

## Remediation Guide

### Disable Old Protocols

**Nginx:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

**Apache:**
```apache
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
```

### Remove Weak Ciphers

**Nginx:**
```nginx
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
```

### Disable Compression

**Nginx:**
```nginx
ssl_prefer_server_ciphers on;
gzip off;  # For HTTPS
```

## Next Steps

- [TLS Audit](01-audit.md) - Full security audit
- [Cipher Enumeration](02-ciphers.md) - List cipher suites
- [Configuration](04-configuration.md) - TLS settings
