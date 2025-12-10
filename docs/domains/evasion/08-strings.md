# String Encryption

> Compile-time and runtime string encryption to evade static analysis.

## Overview

The `strings` resource provides techniques to hide sensitive strings from:
- `strings` command
- Static analysis tools
- Antivirus signature scanning
- Binary reverse engineering

## Commands

| Command | Description |
|---------|-------------|
| `encrypt` | Encrypt a string with XOR |
| `sensitive` | Show pre-encrypted sensitive strings |
| `demo` | Demo all string encryption techniques |

## Usage

### Encrypt String

```bash
rb evasion strings encrypt "my_secret_api_key"
```

Output:
```
▸ String Encryption

  Original    my_secret_api_key
  Key         0x5A
  Encrypted   [hex bytes...]
  Decrypted   my_secret_api_key

ℹ Rust code:
    const ENCRYPTED: &[u8] = &[0x37, 0x2b, ...];
    let decrypted = decrypt(ENCRYPTED, 0x5A);
```

### Pre-Encrypted Sensitive Strings

```bash
rb evasion strings sensitive
```

Output:
```
▸ Pre-Encrypted Sensitive Strings

ℹ Common strings that would trigger AV if plaintext:

    cmd_exe:         "cmd.exe"
    powershell:      "powershell.exe"
    bash:            "/bin/bash"
    sh:              "/bin/sh"
    nc:              "nc"
    curl:            "curl"
    wget:            "wget"

ℹ These strings are stored encrypted and only decrypted at runtime
```

### Demo All Techniques

```bash
rb evasion strings demo
```

## Encryption Techniques

### 1. XOR Encryption (Runtime)

Simple but effective XOR encryption:

```rust
use redblue::modules::evasion::strings::EncryptedString;

// Encrypt at compile time
let encrypted = EncryptedString::from_plaintext("cmd.exe");

// Decrypt at runtime
let decrypted = encrypted.decrypt();
```

### 2. Stack Strings

Build strings character by character on stack:

```rust
use redblue::modules::evasion::strings::StackString;

let ss = StackString::new();
let cmd = ss.build(&['c', 'm', 'd', '.', 'e', 'x', 'e']);
```

### 3. Build-Key Encryption

Uses build-time generated key (changes each build):

```rust
use redblue::modules::evasion::strings::SensitiveStrings;

// Pre-encrypted with build key
let cmd = SensitiveStrings::cmd_exe();
let shell = cmd.decrypt_with_build_key();
```

## Available Sensitive Strings

| Method | Decrypted Value |
|--------|-----------------|
| `cmd_exe()` | `cmd.exe` |
| `powershell()` | `powershell.exe` |
| `bash()` | `/bin/bash` |
| `sh()` | `/bin/sh` |
| `nc()` | `nc` |
| `curl()` | `curl` |
| `wget()` | `wget` |
| `python()` | `python` |
| `perl()` | `perl` |

## Why String Encryption Matters

Without encryption:
```bash
$ strings malware.exe | grep -i password
GetPassword
PasswordHash
DefaultPassword123
```

With encryption:
```bash
$ strings binary.exe | grep -i password
# Nothing found - strings are encrypted
```

## Best Practices

1. **Never hardcode** sensitive strings in plaintext
2. **Use different keys** for different strings
3. **Decrypt just-in-time** - decrypt only when needed
4. **Clear after use** - zero decrypted strings when done
5. **Combine with SecureVault** for runtime storage

## Related

- [memory](04-memory.md) - SecureVault for runtime storage
- [obfuscate](02-obfuscate.md) - General obfuscation
- [controlflow](07-controlflow.md) - Control flow obfuscation
