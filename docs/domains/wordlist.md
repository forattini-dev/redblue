# wordlist

> Wordlist management for fuzzing and enumeration

The `wordlist` domain provides tools for managing, generating, and manipulating wordlists used in security testing.

## Commands

```
rb wordlist <resource> <verb> [args] [flags]
```

### Resources

| Resource | Description |
|----------|-------------|
| `list` | List available wordlists |
| `file` | Wordlist file operations |

## Usage Examples

### List Wordlists

```bash
# List all available wordlists
rb wordlist list

# List by category
rb wordlist list --category directories

# Show wordlist info
rb wordlist list --verbose
```

### File Operations

```bash
# Download common wordlists
rb wordlist file download

# Generate custom wordlist
rb wordlist file generate --pattern "{user}{year}"

# Merge wordlists
rb wordlist file merge list1.txt list2.txt -o combined.txt

# Deduplicate
rb wordlist file dedupe wordlist.txt
```

## Built-in Wordlists

| Name | Size | Use Case |
|------|------|----------|
| `common-dirs` | 4,614 | Directory fuzzing |
| `common-files` | 2,894 | File discovery |
| `subdomains-top1000` | 1,000 | Subdomain enumeration |
| `passwords-top10000` | 10,000 | Password testing |

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--category` | Filter by category | all |
| `--pattern` | Generation pattern | - |
| `-o, --output` | Output file | stdout |
| `--sort` | Sort output | false |
| `--unique` | Remove duplicates | false |

## Pattern Syntax

For `generate` command:

| Pattern | Description | Example |
|---------|-------------|---------|
| `{user}` | Common usernames | admin, root |
| `{year}` | Years (2020-2025) | 2023, 2024 |
| `{num:3}` | 3-digit numbers | 001-999 |
| `{alpha:2}` | 2-char alpha | aa-zz |

```bash
# Generate username + year combinations
rb wordlist file generate --pattern "{user}{year}" -o custom.txt
```

## Integration

Wordlists work with other commands:

```bash
# Directory fuzzing
rb web asset fuzz http://example.com --wordlist common-dirs

# Subdomain enumeration
rb recon domain subdomains example.com --wordlist subdomains-top1000
```
