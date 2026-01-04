# Secrets Detection

> Scan source code for hardcoded secrets, API keys, tokens, and credentials

## Command

```
rb code secrets scan <path> [flags]
```

## Usage

```bash
# Scan current directory
rb code secrets scan .

# Scan specific directory
rb code secrets scan /path/to/repo

# JSON output
rb code secrets scan . --output json

# Custom entropy threshold
rb code secrets scan . --min-entropy 4.0
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--min-entropy` | Minimum entropy threshold | `3.5` |
| `--max-file-size` | Max file size in MB | `10` |
| `-o, --output` | Output format: `text`, `json` | `text` |

## Detected Secret Types

| Type | Examples |
|------|----------|
| **AWS** | Access Key ID, Secret Access Key |
| **GCP** | Service account keys, API keys |
| **Azure** | Client secrets, connection strings |
| **GitHub** | Personal access tokens, OAuth tokens |
| **GitLab** | Personal access tokens, runner tokens |
| **Stripe** | Secret keys, publishable keys |
| **Twilio** | Account SID, auth tokens |
| **Private Keys** | RSA, ECDSA, Ed25519 |
| **JWT** | JSON Web Tokens |
| **Generic** | High-entropy strings |

## Detection Patterns

The scanner uses multiple detection methods:

1. **Regex Patterns** - Known secret formats (e.g., `AKIA[0-9A-Z]{16}`)
2. **Entropy Analysis** - High-randomness strings
3. **Contextual Analysis** - Variable names like `password`, `api_key`
4. **File Path Analysis** - Files like `.env`, `credentials.json`

## Sample Output

```
Secret Scanner
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

/path/to/repo/.env.example
  Generic API Key (generic-api-key)
    Line 12, Column 8
    Entropy: 5.21
    Secret: sk_l...xyz9
    Context: STRIPE_KEY=sk_live_...

Summary:
  Total findings: 3
  Files affected: 2

By Type:
  AWS Access Key ID: 1
  Private Key: 1
  Generic API Key: 1
```

## JSON Output

```json
{
  "target": "/path/to/repo",
  "findings": [
    {
      "file": "/path/to/repo/config.js",
      "line": 45,
      "column": 15,
      "rule_id": "aws-access-key-id",
      "description": "AWS Access Key ID",
      "entropy": 4.82,
      "secret": "AKIA...ABCD",
      "context": "const accessKey = \"AKIAIOSFODNN7EXAMPLE\";"
    }
  ],
  "summary": {
    "total": 3,
    "files_affected": 2,
    "by_type": {
      "aws-access-key-id": 1,
      "private-key": 1,
      "generic-api-key": 1
    }
  }
}
```

## Ignoring False Positives

Create `.secretsignore` in your repository root:

```
# Ignore test files
**/test/**
**/*_test.go

# Ignore example files
*.example
*.sample

# Ignore specific patterns
# (one regex per line)
EXAMPLE_KEY_.*
```

## CI/CD Integration

```bash
# Exit with error on findings
rb code secrets scan . || exit 1

# JSON for parsing
rb code secrets scan . --output json > secrets.json

# Check specific severity
rb code secrets scan . --min-severity high
```

## Best Practices

1. **Rotate Exposed Secrets** - If found in git history, rotate immediately
2. **Use Environment Variables** - Never hardcode secrets
3. **Pre-commit Hooks** - Scan before committing
4. **Regular Scans** - Include in CI/CD pipeline

## See Also

- [Dependency Audit](02-deps.md) - Vulnerable dependencies
- [Overview](00-overview.md) - Code domain overview
