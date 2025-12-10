# Memory Encryption

> Protect sensitive data in memory from forensic analysis and memory dumps.

## Overview

The `memory` resource provides techniques to protect sensitive variables from:
- Memory dumps (core dumps, crash reports)
- Process memory inspection
- Swap file leakage
- Debugging tools
- Memory forensics

## Commands

| Command | Description |
|---------|-------------|
| `encrypt` | Encrypt a string in memory |
| `demo` | Demo secure buffer operations |
| `rotate` | Rotate memory encryption key |
| `vault` | Demo SecureVault for protected variable storage |

## SecureVault - Multi-Layer Protection

The `SecureVault` is the recommended way to store sensitive variables like API keys, passwords, and credentials.

### Protection Layers

| Layer | Protection | How It Works |
|-------|-----------|--------------|
| **1. Encryption** | Double XOR encryption | Master key + entry-specific key derived from salt |
| **2. Memory Lock** | Prevents swap | Attempts `mlock` to keep data in RAM |
| **3. Canaries** | Integrity detection | Detects tampering via guard values |
| **4. Decoys** | Forensics confusion | 6 fake credentials mixed with real data |
| **5. Auto-Zero** | Secure cleanup | `write_volatile` + memory fence on drop |
| **6. Access Limit** | Brute-force protection | Auto-locks after 1000 accesses |

### Usage

```rust
use redblue::modules::evasion::memory::{SecureVault, VaultEntry};

// Create vault (generates decoys automatically)
let mut vault = SecureVault::new();

// Store secrets (encrypted immediately)
vault.store("API_KEY", "sk_live_xyz123456789");
vault.store("DB_PASSWORD", "super_secret!");
vault.store("JWT_SECRET", "signing_key_here");

// Access secrets (returns VaultEntry that auto-zeros on drop)
if let Some(key) = vault.get("API_KEY") {
    // VaultEntry.as_str() gives temporary access
    call_api(key.as_str());
    // key automatically zeroed when dropped here
}

// Lock vault when not in use (re-encrypts with new key)
vault.lock();

// Check integrity
if vault.verify_integrity() {
    println!("All entries intact");
}

// Emergency wipe (destroys everything)
vault.emergency_wipe();
```

### VaultEntry Safety

The `VaultEntry` type returned by `vault.get()` ensures sensitive data is never accidentally leaked:

```rust
let entry = vault.get("PASSWORD").unwrap();

// Safe access
let password = entry.as_str();  // Temporary reference

// Display trait shows [REDACTED]
println!("{}", entry);  // Prints: [REDACTED]

// Debug trait shows byte count only
println!("{:?}", entry);  // Prints: VaultEntry([REDACTED 12 bytes])

// Auto-zeroed when entry goes out of scope
```

### Demo Command

```bash
rb evasion memory vault
```

Output:
```
▸ SecureVault Demo

ℹ SecureVault provides multi-layer protection for sensitive variables:
    1. XOR encryption with rotating keys
    2. Memory locking (prevents swap to disk)
    3. Integrity canaries (detect tampering)
    4. Decoy entries (confuse memory forensics)
    5. Automatic zeroing on drop
    6. Access-time-limited decryption

ℹ Creating SecureVault...
    Vault created with 6 decoy entries

ℹ Storing secrets:
    Stored: API_KEY
    Stored: DB_PASSWORD
    Stored: JWT_SECRET
    Total entries: 3

ℹ Retrieving secrets (temporary decryption):
    API_KEY value: sk_live_xyz123456789
    Display trait: [REDACTED]
    Debug trait: VaultEntry([REDACTED 20 bytes])

ℹ Integrity verification:
    All entries intact: true

ℹ Lock/unlock mechanism:
    Locking vault (re-encrypts with new key)...
    Is locked: true
    Access while locked: "denied"
    Unlocking vault...
    Is locked: false
    Access after unlock: "success"

✓ Vault automatically wiped on drop (emergency_wipe)
```

## Other Memory Protections

### SecureString

Encrypted string in memory, zeroed on drop:

```rust
use redblue::modules::evasion::memory::SecureString;

let secret = SecureString::new("my_password");
println!("Length: {}", secret.len());
println!("Valid: {}", secret.is_valid());
let value = secret.get();  // Decrypted on demand
// Automatically zeroed when `secret` is dropped
```

### SecureCredential

Store username/password pairs:

```rust
use redblue::modules::evasion::memory::SecureCredential;

let cred = SecureCredential::new("admin", "super_secret");
println!("User: {}", cred.username());
println!("Pass: {}", cred.password());
println!("Intact: {}", cred.verify());
```

### MemoryGuard

Detect buffer overflows:

```rust
use redblue::modules::evasion::memory::MemoryGuard;

let mut guard = MemoryGuard::new(100);
guard.data_mut()[0] = 0x41;
assert!(guard.check_guards());  // Guards intact
```

### Key Rotation

Rotate encryption keys periodically:

```bash
rb evasion memory rotate
```

```rust
use redblue::modules::evasion::memory::rotate_key;
rotate_key();  // New buffers use new key
```

## Best Practices

1. **Use SecureVault for credentials** - Not raw strings
2. **Lock when idle** - Call `vault.lock()` when not accessing secrets
3. **Minimize access time** - Get value, use it, let VaultEntry drop
4. **Rotate keys periodically** - Call `rotate_key()` or `vault.lock()`
5. **Emergency wipe on threat** - Call `vault.emergency_wipe()`

## Memory Analysis Countermeasures

| Threat | SecureVault Defense |
|--------|---------------------|
| `strings` command | Encrypted, decoys present |
| Memory dump | Encrypted + auto-zero on process exit |
| Swap file | Memory locked (mlock) |
| Debugger attach | Encryption + integrity checks |
| Forensic analysis | Decoy credentials confuse analysis |

## Related

- [strings](/domains/evasion/08-strings.md) - Compile-time string encryption
- [antidebug](/domains/evasion/05-antidebug.md) - Anti-debugging techniques
- [sandbox](/domains/evasion/01-sandbox.md) - Sandbox detection
