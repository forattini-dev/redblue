# code

> Source code security analysis - secrets detection and dependency scanning

The `code` domain provides source code security analysis including secrets detection and dependency vulnerability scanning. Replaces **gitleaks**, **trufflehog**, and **snyk**.

## Resources

| Resource | Description |
|----------|-------------|
| `secrets` | Scan for API keys, tokens, and credentials |
| `dependencies` | Scan for vulnerable dependencies |

## Commands

### Secrets Scanning

```
rb code secrets scan <path>
```

Scan directories or files for hardcoded secrets, API keys, tokens, and credentials.

### Dependency Scanning

```
rb code dependencies scan <path>
```

Scan project dependencies for known vulnerabilities.

## Usage Examples

### Secrets Detection

```bash
# Scan current directory
rb code secrets scan .

# Scan specific directory
rb code secrets scan /path/to/repo

# JSON output
rb code secrets scan . --output json
```

### Dependency Scanning

```bash
# Scan current project
rb code dependencies scan .

# Scan specific project
rb code dependencies scan /path/to/project

# JSON output
rb code dependencies scan . --output json

# YAML output
rb code dependencies scan . --output yaml
```

## Flags

### Secrets Scanner

| Flag | Description | Default |
|------|-------------|---------|
| `--min-entropy` | Minimum entropy threshold | `3.5` |
| `--max-file-size` | Max file size in MB | `10` |
| `-o, --output` | Output format: `text`, `json` | `text` |

### Dependencies Scanner

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output format: `text`, `json`, `yaml` | `text` |

## Secrets Detection

The scanner detects various secret types:

| Type | Examples |
|------|----------|
| **API Keys** | AWS, GCP, Azure, Stripe, Twilio |
| **Tokens** | GitHub, GitLab, NPM, PyPI |
| **Credentials** | Passwords, private keys, certificates |
| **Secrets** | JWT tokens, OAuth secrets, webhook secrets |

**Sample Output:**

```
Secret Scanner (Gitleaks)
  Target: /path/to/repo

Found 3 potential secret(s)

/path/to/repo/config.js
  AWS Access Key ID (aws-access-key-id)
    Line 45, Column 15
    Entropy: 4.82
    Secret: AKIA...ABCD
    Context: const accessKey = "AKIAIOSFODNN7EXAMPLE";

  Private Key (private-key)
    Line 89, Column 1
    Secret: ----...KEY-
    Context: -----BEGIN RSA PRIVATE KEY-----

Summary:
  Total findings: 3
  Files affected: 2

By Type:
  AWS Access Key ID: 1
  Private Key: 1
  Generic High Entropy: 1
```

## Dependency Analysis

Supports multiple package managers:

| Manager | Files |
|---------|-------|
| **npm/yarn** | `package.json`, `package-lock.json`, `yarn.lock` |
| **pip** | `requirements.txt`, `Pipfile`, `Pipfile.lock` |
| **Cargo** | `Cargo.toml`, `Cargo.lock` |
| **Go** | `go.mod`, `go.sum` |

**Sample Output:**

```
Dependency Scanner (Snyk)
  Target: /path/to/project

Found 2 dependency files
  /path/to/project/package.json
  /path/to/project/package-lock.json

Summary: 156 total dependencies, 4 vulnerable

CRITICAL Severity:
  lodash (4.17.15)
    CVE: CVE-2021-23337
    Prototype Pollution in lodash
    Fix: Upgrade to 4.17.21

HIGH Severity:
  minimist (1.2.5)
    CVE: CVE-2021-44906
    Prototype Pollution in minimist
    Fix: Upgrade to 1.2.6
```

## Severity Levels

| Level | Description |
|-------|-------------|
| **Critical** | Remote code execution, auth bypass |
| **High** | Privilege escalation, data exposure |
| **Medium** | DoS, limited information disclosure |
| **Low** | Minor issues, hardening recommendations |

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| `gitleaks` | `rb code secrets scan` |
| `trufflehog` | `rb code secrets scan` |
| `snyk` | `rb code dependencies scan` |
| `npm audit` | `rb code dependencies scan` |
| `pip-audit` | `rb code dependencies scan` |

## See Also

- [recon domain](/domains/recon/00-overview.md) - Target reconnaissance
- [intel vuln](/domains/intel/01-vuln.md) - Vulnerability intelligence
