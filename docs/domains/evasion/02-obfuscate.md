# Obfuscation

> General string and data obfuscation techniques.

## Overview

The `obfuscate` resource provides basic obfuscation:
- XOR encoding
- Base64 encoding
- Custom key encryption

## Commands

| Command | Description |
|---------|-------------|
| `xor` | XOR obfuscate a string |
| `base64` | Base64 encode data |

## Usage

### XOR Obfuscation

```bash
rb evasion obfuscate xor "secret_string"
```

Output:
```
▸ XOR Obfuscation

  Original    secret_string
  Key         0x5A (random)
  Obfuscated  [29, 3f, 39, ...]
  Recovered   secret_string

ℹ Use the same key to recover
```

With custom key:
```bash
rb evasion obfuscate xor "secret_string" --key 0x41
```

### Base64 Encoding

```bash
rb evasion obfuscate base64 "data to encode"
```

## Programmatic Usage

```rust
use redblue::modules::evasion::obfuscate;

// XOR obfuscation
let obfuscated = obfuscate::xor_obfuscate("secret", 0x5A);
let recovered = obfuscate::xor_deobfuscate(&obfuscated, 0x5A);

// Rolling XOR (different key for each byte)
let rolling = obfuscate::rolling_xor("secret", &[0x5A, 0x3B, 0x1C]);
```

## Use Cases

- **Avoid string signatures** - Hide suspicious strings
- **Basic payload encoding** - Encode shellcode
- **Configuration hiding** - Obfuscate config values

## Limitations

XOR and Base64 are **not encryption**. They provide obfuscation only and can be reversed by anyone who knows the technique.

For real security, use:
- [memory](/domains/evasion/04-memory.md) - SecureVault for runtime protection
- [strings](/domains/evasion/08-strings.md) - Compile-time encryption

## Related

- [strings](/domains/evasion/08-strings.md) - Advanced string encryption
- [memory](/domains/evasion/04-memory.md) - Memory protection
