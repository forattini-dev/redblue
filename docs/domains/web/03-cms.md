# CMS Scanning

Detect and scan Content Management Systems - WordPress, Drupal, Joomla.

## Quick Start

```bash
# Auto-detect CMS
rb web cms-scan asset http://example.com

# Specific CMS scan
rb web cms-scan asset http://wordpress-site.com --strategy wordpress

# Full scan with plugins
rb web cms-scan asset http://example.com --enumerate all
```

## Command

### cms-scan - CMS Detection & Scanning

Detect CMS type and enumerate plugins, themes, users.

```bash
rb web cms-scan asset <url> [flags]
```

## Options

```rust
// CMS scan options
struct CmsScanOptions {
    // CMS detection strategy
    // Values: "auto", "wordpress", "drupal", "joomla"
    // Default: "auto"
    strategy: String,

    // Enumeration targets
    // Values: "none", "plugins", "themes", "users", "all"
    // Default: "plugins"
    enumerate: String,

    // Request timeout in seconds
    // Range: 1-60
    // Default: 10
    timeout_secs: u32,

    // Aggressive detection mode
    // Default: false
    aggressive: bool,

    // Custom User-Agent
    // Default: "redblue/1.0"
    user_agent: String,

    // Output format
    // Values: "text", "json"
    // Default: "text"
    output: String,
}
```

## Flag Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--strategy` | `-s` | CMS type: auto, wordpress, drupal, joomla | auto |
| `--enumerate` | `-e` | Enumerate: none, plugins, themes, users, all | plugins |
| `--timeout` | `-t` | Request timeout (secs) | 10 |
| `--aggressive` | `-a` | Aggressive detection | false |
| `--user-agent` | `-A` | Custom User-Agent | redblue/1.0 |
| `--output` | `-o` | Output format | text |

## Detection Methods

### WordPress Detection

| Method | Check | Confidence |
|--------|-------|------------|
| Generator meta | `<meta name="generator" content="WordPress">` | HIGH |
| wp-content path | `/wp-content/` in HTML | HIGH |
| wp-includes path | `/wp-includes/` in HTML | HIGH |
| REST API | `/wp-json/` endpoint | MEDIUM |
| Login page | `/wp-login.php` exists | MEDIUM |
| xmlrpc | `/xmlrpc.php` exists | LOW |

### Drupal Detection

| Method | Check | Confidence |
|--------|-------|------------|
| Generator meta | `Drupal` in generator tag | HIGH |
| Drupal.js | `/misc/drupal.js` exists | HIGH |
| CHANGELOG.txt | `/CHANGELOG.txt` exists | MEDIUM |
| Core files | `/core/` directory | MEDIUM |

### Joomla Detection

| Method | Check | Confidence |
|--------|-------|------------|
| Generator meta | `Joomla` in generator tag | HIGH |
| Administrator | `/administrator/` exists | HIGH |
| Media folder | `/media/system/` exists | MEDIUM |
| Language files | `/language/` directory | LOW |

## Examples

### Auto-Detection

```bash
# Let redblue detect CMS type
rb web cms-scan asset http://example.com

# Verbose detection
rb web cms-scan asset http://example.com --aggressive
```

### WordPress Scanning

```bash
# Basic WordPress scan
rb web cms-scan asset http://wordpress.example.com --strategy wordpress

# Enumerate everything
rb web cms-scan asset http://wordpress.example.com \
  --strategy wordpress \
  --enumerate all

# Plugins only
rb web cms-scan asset http://wordpress.example.com \
  --strategy wordpress \
  --enumerate plugins

# Users enumeration
rb web cms-scan asset http://wordpress.example.com \
  --strategy wordpress \
  --enumerate users
```

### Drupal Scanning

```bash
# Drupal scan
rb web cms-scan asset http://drupal.example.com --strategy drupal

# With module enumeration
rb web cms-scan asset http://drupal.example.com \
  --strategy drupal \
  --enumerate all
```

### Joomla Scanning

```bash
# Joomla scan
rb web cms-scan asset http://joomla.example.com --strategy joomla
```

## Output Examples

### Text Output

```
CMS Scan: http://wordpress.example.com

DETECTION
  CMS: WordPress
  Version: 6.4.2
  Confidence: HIGH

ENUMERATION
  Plugins Found: 12
    - akismet (4.2.1)
    - contact-form-7 (5.8.4) [OUTDATED]
    - yoast-seo (21.6)
    - woocommerce (8.3.1)
    - elementor (3.18.2)
    - wordfence (7.11.0)
    - jetpack (12.9)
    - updraftplus (1.23.12)
    - wpforms-lite (1.8.5)
    - classic-editor (1.6.3)
    - all-in-one-seo-pack (4.5.3)
    - really-simple-ssl (7.2.2)

  Themes Found: 3
    - flavor (2.1.0) [ACTIVE]
    - flavor-child (1.0.0)
    - flavor-developer (1.0.0)

  Users Found: 5
    - admin (ID: 1)
    - editor (ID: 2)
    - author (ID: 3)
    - contributor (ID: 4)
    - subscriber (ID: 5)

VULNERABILITIES
  HIGH: contact-form-7 < 5.8.5 - Stored XSS (CVE-2023-XXXX)
  MEDIUM: WordPress < 6.4.3 - SSRF vulnerability

SUMMARY
  CMS: WordPress 6.4.2
  Plugins: 12 (1 outdated)
  Themes: 3
  Users: 5
  Vulnerabilities: 2 (1 HIGH, 1 MEDIUM)
```

### JSON Output

```json
{
  "url": "http://wordpress.example.com",
  "cms": {
    "type": "wordpress",
    "version": "6.4.2",
    "confidence": "high"
  },
  "plugins": [
    {
      "name": "akismet",
      "version": "4.2.1",
      "status": "active",
      "outdated": false
    },
    {
      "name": "contact-form-7",
      "version": "5.8.4",
      "status": "active",
      "outdated": true,
      "latest_version": "5.8.5"
    }
  ],
  "themes": [
    {
      "name": "flavor",
      "version": "2.1.0",
      "active": true
    }
  ],
  "users": [
    {
      "username": "admin",
      "id": 1
    }
  ],
  "vulnerabilities": [
    {
      "severity": "high",
      "component": "contact-form-7",
      "description": "Stored XSS vulnerability",
      "cve": "CVE-2023-XXXX"
    }
  ]
}
```

## Enumeration Details

### Plugin Enumeration

WordPress plugin detection methods:

```
1. Passive: Parse HTML for /wp-content/plugins/
2. Active: Probe known plugin paths
3. REST API: Query /wp-json/wp/v2/plugins (if exposed)
4. Aggressive: Brute force common plugin names
```

### Theme Enumeration

```
1. Parse HTML for /wp-content/themes/
2. Check style.css for active theme
3. Probe common theme paths
```

### User Enumeration

```
1. Author archives: /?author=1, /?author=2, ...
2. REST API: /wp-json/wp/v2/users
3. Login error messages
4. RSS feed author names
```

## Patterns

### Batch CMS Scanning

```bash
# Scan multiple sites
for site in site1.com site2.com site3.com; do
  echo "=== $site ==="
  rb web cms-scan asset https://$site -o json >> cms-results.json
done
```

### Security Audit Pipeline

```bash
# Full CMS security audit
rb web cms-scan asset http://example.com --enumerate all -o json | \
  jq '.vulnerabilities[] | select(.severity == "high")'
```

### Version Checking

```bash
# Check for outdated plugins
rb web cms-scan asset http://example.com -o json | \
  jq '.plugins[] | select(.outdated == true) | .name'
```

## Tool Equivalents

| Tool | redblue Command |
|------|-----------------|
| wpscan | `rb web cms-scan asset --strategy wordpress` |
| droopescan (Drupal) | `rb web cms-scan asset --strategy drupal` |
| droopescan (Joomla) | `rb web cms-scan asset --strategy joomla` |
| whatweb (CMS) | `rb web cms-scan asset --strategy auto` |

## Next Steps

- [HTTP Requests](/domains/web/01-requests.md) - Make HTTP requests
- [Security Audit](/domains/web/02-security.md) - Security headers analysis
- [Configuration](/domains/web/04-configuration.md) - HTTP settings
