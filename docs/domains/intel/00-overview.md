# intel

> Vulnerability intelligence and threat research

The `intel` domain provides access to vulnerability databases, exploit information, and threat intelligence frameworks.

## Resources

| Resource | Description |
|----------|-------------|
| **vuln** | Vulnerability search and CVE lookup |
| **mitre** | MITRE ATT&CK framework queries |

## Quick Examples

```bash
# Search vulnerabilities by technology
rb intel vuln search nginx 1.18.0

# Get CVE details
rb intel vuln cve CVE-2021-44228

# Query CISA KEV catalog
rb intel vuln kev --stats

# Search Exploit-DB
rb intel vuln exploit "Apache Struts"

# MITRE ATT&CK technique lookup
rb intel mitre technique T1059
```

## Data Sources

| Source | Description |
|--------|-------------|
| **NVD** | NIST National Vulnerability Database |
| **OSV** | Open Source Vulnerabilities (npm, PyPI, Cargo, etc.) |
| **CISA KEV** | Known Exploited Vulnerabilities catalog |
| **Exploit-DB** | Public exploits and PoCs |
| **MITRE ATT&CK** | Adversary tactics and techniques |

## See Also

- [vuln resource](./01-vuln.md) - Vulnerability search and CVE lookup
- [mitre resource](./02-mitre.md) - MITRE ATT&CK framework
