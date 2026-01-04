# code

> Source code security analysis - secrets detection and dependency scanning

The `code` domain provides source code security analysis including secrets detection and dependency vulnerability scanning.

## Resources

| Resource | Description |
|----------|-------------|
| `secrets` | Scan for API keys, tokens, and credentials |
| `deps` | Scan for vulnerable dependencies |

## Quick Reference

```bash
# Secrets scanning
rb code secrets scan .
rb code secrets scan /path/to/repo --output json

# Dependency scanning
rb code deps audit Cargo.toml
rb code deps audit package.json --output json
```

## Tools Replaced

| Traditional Tool | redblue Command |
|-----------------|-----------------|
| gitleaks | `rb code secrets scan` |
| trufflehog | `rb code secrets scan` |
| snyk | `rb code deps audit` |
| npm audit | `rb code deps audit` |
| pip-audit | `rb code deps audit` |
| cargo-audit | `rb code deps audit` |

## Severity Levels

| Level | Description |
|-------|-------------|
| **Critical** | Remote code execution, auth bypass |
| **High** | Privilege escalation, data exposure |
| **Medium** | DoS, limited information disclosure |
| **Low** | Minor issues, hardening recommendations |

## See Also

- [Secrets Detection](01-secrets.md) - API keys, tokens, credentials
- [Dependency Audit](02-deps.md) - Vulnerable dependencies
- [intel vuln](/domains/intel/01-vuln.md) - Vulnerability intelligence
