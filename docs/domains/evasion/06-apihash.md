# API Hashing

> Hash API function names to evade import table analysis.

## Overview

The `apihash` resource provides techniques to resolve Windows API functions dynamically without exposing them in the import table.

## Commands

| Command | Description |
|---------|-------------|
| `hash` | Calculate hash for a function name |
| `lookup` | Find function name by hash |
| `list` | List common API hashes |

## Usage

### Calculate Hash

```bash
rb evasion apihash hash LoadLibraryA
```

Output:
```
▸ API Hash

  Function    LoadLibraryA
  Algorithm   ror13
  Hash        0xEC0E4E8E

ℹ All algorithms for comparison:
    ROR13:  0xEC0E4E8E
    DJB2:   0x5FBFF0FB
    FNV-1a: 0x53B2070F
    CRC32:  0x3FC1BD8D
```

### Lookup by Hash

```bash
rb evasion apihash lookup 0xEC0E4E8E
```

### List Common Hashes

```bash
rb evasion apihash list
```

Output:
```
▸ Common API Hashes (ROR13)

  0xEC0E4E8E  LoadLibraryA
  0x7C0DFCAA  GetProcAddress
  0xE8AFE98   VirtualAlloc
  0x91AFCA54  VirtualProtect
  0x1E380A6A  CreateThread
  0x4FDAF6DA  WaitForSingleObject
  ...
```

## Hash Algorithms

### ROR13 (Rotate Right 13)

Most common in shellcode, used by Metasploit:

```rust
fn ror13_hash(name: &str) -> u32 {
    let mut hash = 0u32;
    for c in name.bytes() {
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(c as u32);
    }
    hash
}
```

### DJB2

Fast and simple:

```rust
fn djb2_hash(name: &str) -> u32 {
    let mut hash = 5381u32;
    for c in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }
    hash
}
```

### FNV-1a

Good distribution:

```rust
fn fnv1a_hash(name: &str) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for c in name.bytes() {
        hash ^= c as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}
```

## Common API Hashes

| Function | ROR13 | Purpose |
|----------|-------|---------|
| `LoadLibraryA` | `0xEC0E4E8E` | Load DLL |
| `GetProcAddress` | `0x7C0DFCAA` | Resolve function |
| `VirtualAlloc` | `0xE8AFE98` | Allocate memory |
| `VirtualProtect` | `0x91AFCA54` | Change memory protection |
| `CreateThread` | `0x1E380A6A` | Create thread |
| `WriteProcessMemory` | `0xD83D6AA1` | Write to process |
| `CreateRemoteThread` | `0x72BD9CDD` | Inject thread |

## Why API Hashing?

**Without hashing:**
```
Import Table:
  kernel32.dll
    - LoadLibraryA
    - VirtualAlloc
    - CreateRemoteThread  <-- Red flag!
```

**With hashing:**
```
Import Table:
  kernel32.dll
    - GetModuleHandleA   <-- Just this, benign
```

The shellcode resolves other functions at runtime using PEB walking and hash comparison.

## Programmatic Usage

```rust
use redblue::modules::evasion::api_hash::{ApiHasher, HashAlgorithm};

// Create hasher
let hasher = ApiHasher::new(HashAlgorithm::Ror13);

// Hash a function name
let hash = hasher.hash("LoadLibraryA");
println!("Hash: 0x{:08X}", hash);

// Lookup by hash
if let Some(name) = hasher.lookup(0xEC0E4E8E) {
    println!("Found: {}", name);
}
```

## Related

- [inject](/domains/evasion/09-inject.md) - Shellcode generation (uses API hashing)
- [strings](/domains/evasion/08-strings.md) - String encryption
- [controlflow](/domains/evasion/07-controlflow.md) - Control flow obfuscation
