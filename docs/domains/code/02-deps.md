# Dependency Audit

> Scan project dependencies for known vulnerabilities

## Command

```
rb code deps audit <manifest> [flags]
```

## Usage

```bash
# Scan Cargo project
rb code deps audit Cargo.toml

# Scan npm project
rb code deps audit package.json

# Scan Python project
rb code deps audit requirements.txt

# JSON output
rb code deps audit Cargo.toml --output json

# YAML output
rb code deps audit package.json --output yaml
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output format: `text`, `json`, `yaml` | `text` |
| `--min-severity` | Minimum severity to report | `low` |
| `--ignore-dev` | Ignore dev dependencies | `false` |

## Supported Package Managers

| Manager | Manifest Files |
|---------|----------------|
| **Cargo** | `Cargo.toml`, `Cargo.lock` |
| **npm/yarn** | `package.json`, `package-lock.json`, `yarn.lock` |
| **pip** | `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml` |
| **Go** | `go.mod`, `go.sum` |
| **Composer** | `composer.json`, `composer.lock` |
| **Maven** | `pom.xml` |
| **Gradle** | `build.gradle`, `build.gradle.kts` |

## Sample Output

```
Dependency Scanner
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
    CVSS: 9.8

HIGH Severity:
  minimist (1.2.5)
    CVE: CVE-2021-44906
    Prototype Pollution in minimist
    Fix: Upgrade to 1.2.6
    CVSS: 7.5

MEDIUM Severity:
  node-fetch (2.6.1)
    CVE: CVE-2022-0235
    Exposure of Sensitive Information
    Fix: Upgrade to 2.6.7
    CVSS: 6.1

  glob-parent (5.1.1)
    CVE: CVE-2020-28469
    Regular Expression Denial of Service
    Fix: Upgrade to 5.1.2
    CVSS: 5.3

Results:
  Critical: 1
  High: 1
  Medium: 2
  Low: 0
```

## JSON Output

```json
{
  "target": "/path/to/project",
  "manifest_files": [
    "/path/to/project/package.json",
    "/path/to/project/package-lock.json"
  ],
  "summary": {
    "total_dependencies": 156,
    "vulnerable": 4,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 2,
      "low": 0
    }
  },
  "vulnerabilities": [
    {
      "package": "lodash",
      "version": "4.17.15",
      "cve": "CVE-2021-23337",
      "severity": "critical",
      "cvss": 9.8,
      "title": "Prototype Pollution in lodash",
      "fix_version": "4.17.21"
    }
  ]
}
```

## Vulnerability Sources

The scanner queries multiple vulnerability databases:

| Source | Coverage |
|--------|----------|
| **NVD** | CVEs across all ecosystems |
| **OSV** | Open Source Vulnerabilities |
| **GitHub Advisory** | GitHub-reported vulnerabilities |
| **RustSec** | Rust ecosystem advisories |
| **npm Advisory** | npm-specific advisories |
| **PyPI Advisory** | Python-specific advisories |

## Ignoring Vulnerabilities

Create `.depsignore` in your repository root:

```
# Ignore specific CVEs (with reason)
CVE-2021-23337  # False positive, not exploitable in our usage

# Ignore specific packages
lodash  # Will fix in next sprint

# Ignore by severity
severity:low  # Only report medium+
```

## CI/CD Integration

```bash
# Fail on critical/high
rb code deps audit Cargo.toml --min-severity high || exit 1

# JSON for SARIF conversion
rb code deps audit package.json --output json > deps.json

# Check all manifests
find . -name "Cargo.toml" -exec rb code deps audit {} \;
```

## Remediation Workflow

1. **Identify** - Run `rb code deps audit`
2. **Assess** - Check if vulnerability applies to your usage
3. **Update** - Upgrade to fixed version
4. **Verify** - Re-run audit to confirm fix
5. **Document** - Note any ignored vulnerabilities with reasons

## See Also

- [Secrets Detection](01-secrets.md) - Hardcoded credentials
- [intel vuln](/domains/intel/01-vuln.md) - CVE details
- [Overview](00-overview.md) - Code domain overview
