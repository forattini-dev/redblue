# MCP Prompts Reference

> 35+ pre-built security prompt templates

Prompts provide structured templates for common security tasks with typed arguments.

## Reconnaissance Prompts

### recon-strategy

Plan a comprehensive reconnaissance strategy.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `target` | string | Yes | Target domain, IP, or org name |
| `scope` | enum | No | `passive`, `active`, or `full` |
| `time_limit` | string | No | Time limit (e.g., "1h", "4h") |

**Example:**
```json
{
  "method": "prompts/get",
  "params": {
    "name": "recon-strategy",
    "arguments": {
      "target": "example.com",
      "scope": "passive"
    }
  }
}
```

### subdomain-hunt

Enumerate and analyze subdomains.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `domain` | domain | Yes | Target domain |
| `depth` | enum | No | `quick`, `standard`, or `deep` |

## Vulnerability Assessment Prompts

### vuln-assessment

Perform vulnerability assessment and prioritization.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `target` | string | Yes | Target URL, IP, or domain |
| `scan_data` | string | No | Previous scan results |

### cve-analysis

Deep analysis of a specific CVE.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `cve_id` | cve-id | Yes | CVE identifier (e.g., CVE-2024-1234) |
| `context` | string | No | Target environment context |

### patch-priority

Prioritize patches based on risk.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `vulns` | array | Yes | List of vulnerabilities |
| `environment` | enum | No | `production`, `staging`, `dev` |

## Attack Planning Prompts

> **Note:** These prompts are for authorized security testing only.

### attack-plan

Generate an attack plan for a target.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `target` | string | Yes | Target information |
| `scope` | string | Yes | Authorized scope |
| `techniques` | array | No | Preferred techniques |

### exploit-suggest

Suggest exploits for discovered vulnerabilities.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `vulns` | array | Yes | Vulnerability list |
| `os` | string | No | Target OS |

### lateral-movement

Plan lateral movement options.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `current_access` | string | Yes | Current access level |
| `network_info` | string | No | Network topology info |

## Defense Prompts

### threat-model

Create a threat model.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `asset` | string | Yes | Asset to model |
| `scope` | string | No | Scope of analysis |

### detection-rules

Create detection rules.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `technique` | string | Yes | Technique to detect |
| `format` | enum | No | `sigma`, `yara`, `snort` |

### hardening-guide

Generate hardening recommendations.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `system` | string | Yes | System to harden |
| `compliance` | string | No | Compliance framework |

## Reporting Prompts

### pentest-report

Generate a pentest report.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `findings` | array | Yes | List of findings |
| `scope` | string | Yes | Engagement scope |
| `format` | enum | No | `executive`, `technical`, `full` |

### executive-summary

Create executive summary.

**Arguments:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `findings` | array | Yes | Key findings |
| `risk_level` | enum | No | Overall risk level |

## Argument Types

| Type | Description | Validation |
|------|-------------|------------|
| `string` | Free-form text | None |
| `integer` | Whole number | Numeric |
| `boolean` | true/false | Boolean |
| `enum` | One of values | Matches list |
| `array` | List of items | Array format |
| `url` | HTTP/HTTPS URL | URL format |
| `ip-address` | IPv4/IPv6 | IP format |
| `domain` | Domain name | DNS format |
| `cidr` | CIDR range | CIDR format |
| `port` | Port number | 1-65535 |
| `cve-id` | CVE identifier | CVE-YYYY-NNNNN |

## See Also

- [Overview](00-overview.md) - MCP introduction
- [Tools](01-tools.md) - Executable tools
- [Autonomous Operations](04-sampling.md) - LLM-guided ops
