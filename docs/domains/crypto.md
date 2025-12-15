# crypto

> Secure file encryption vault with AES-256-GCM

The `crypto` domain provides secure file encryption and decryption using AES-256-GCM with PBKDF2 key derivation.

## Commands

```
rb crypto vault <verb> <file> [flags]
```

| Verb | Description |
|------|-------------|
| `encrypt` | Encrypt a file with password |
| `decrypt` | Decrypt a vault file with password |
| `info` | Show info about an encrypted vault file |

## Usage Examples

### Encrypt Files

```bash
# Encrypt a file (password prompt)
rb crypto vault encrypt secrets.txt

# Encrypt with output path
rb crypto vault encrypt config.json -o config.vault

# Encrypt with password (not recommended - prefer prompt)
rb crypto vault encrypt data.txt --password mypass

# Overwrite existing output
rb crypto vault encrypt file.txt -o existing.vault --force
```

### Decrypt Files

```bash
# Decrypt a vault file (auto-removes .vault extension)
rb crypto vault decrypt secrets.vault

# Decrypt to specific file
rb crypto vault decrypt data.vault -o data.json

# Overwrite existing output
rb crypto vault decrypt file.vault -o existing.txt --force
```

### Vault Info

```bash
# Show vault file details
rb crypto vault info secrets.vault
```

**Sample Output:**

```
Vault File Info
  File: secrets.vault
  Total size: 1284 bytes

Vault Details
  Magic: RBVT (valid)
  Version: 1
  Salt size: 32 bytes
  Nonce size: 12 bytes
  Ciphertext size: 1200 bytes
  Auth tag size: 16 bytes

Security
  Encryption: AES-256-GCM
  Key derivation: PBKDF2-HMAC-SHA256 (100000 iterations)
  Authentication: GCM (AEAD)
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output file path | `<file>.vault` or removes `.vault` |
| `-p, --password` | Password (avoid - prefer prompt) | interactive prompt |
| `-f, --force` | Overwrite existing output file | false |

## Vault File Format

Encrypted files use the `.vault` extension with this structure:

```
┌─────────────────────────────────────┐
│ Magic: "RBVT" (4 bytes)             │
├─────────────────────────────────────┤
│ Version: 1 (1 byte)                 │
├─────────────────────────────────────┤
│ Salt (32 bytes)                     │
├─────────────────────────────────────┤
│ Nonce (12 bytes)                    │
├─────────────────────────────────────┤
│ Ciphertext (variable)               │
├─────────────────────────────────────┤
│ Auth Tag (16 bytes)                 │
└─────────────────────────────────────┘
```

## Security

- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **Salt**: Random 32-byte salt per file
- **Nonce**: Random 12-byte nonce per encryption
- **Authentication**: GCM tag ensures integrity

## Use Cases

### Protect Sensitive Configuration

```bash
# Encrypt API keys
rb crypto vault encrypt .env

# Decrypt when needed
rb crypto vault decrypt .env.vault
```

### Secure Data Transfer

```bash
# Encrypt before transfer
rb crypto vault encrypt sensitive-data.zip

# Decrypt on target system
rb crypto vault decrypt sensitive-data.zip.vault
```

### Protect Scan Results

```bash
# Encrypt recon database
rb crypto vault encrypt target.rdb

# Decrypt for analysis
rb crypto vault decrypt target.rdb.vault
```

## See Also

- [database](/domains/database.md) - RedDB persistence format
