# Sandbox Detection

> Detect if running in sandbox, VM, or analysis environment.

## Overview

The `sandbox` resource provides techniques to detect analysis environments:
- Virtual machines (VMware, VirtualBox, Hyper-V, QEMU)
- Sandboxes (Cuckoo, Any.Run, Joe Sandbox)
- Debuggers and analysis tools
- Timing-based detection

## Commands

| Command | Description |
|---------|-------------|
| `check` | Quick check if running in sandbox/VM |
| `score` | Get detailed sandbox detection score (0-100) |
| `delay` | Delay execution if sandbox detected |

## Usage

### Quick Check

```bash
rb evasion sandbox check
```

Output:
```
▸ Sandbox Detection

ℹ Running sandbox checks...

  VM Artifacts    false
  Timing Check    false
  Debug Check     false
  Environment     false

✓ No sandbox detected
```

### Detection Score

```bash
rb evasion sandbox score
```

Output:
```
▸ Sandbox Detection Score

  Score: 15/100

  Checks:
    VM files:        0 (no VM tools found)
    CPU cores:       0 (4 cores - normal)
    Memory:          0 (16GB - normal)
    Timing:          5 (slight deviation)
    Debugger:        0 (not detected)
    Environment:    10 (some variables missing)

ℹ Score < 30: Likely real machine
ℹ Score 30-70: Possibly VM/sandbox
ℹ Score > 70: Likely sandbox/analysis
```

### Conditional Delay

```bash
# Delay 5 minutes if sandbox detected
rb evasion sandbox delay 300000
```

## Detection Techniques

| Technique | What It Checks |
|-----------|---------------|
| **VM Artifacts** | VMware tools, VBox Guest Additions, QEMU files |
| **Hardware** | CPU cores < 2, RAM < 2GB, disk < 50GB |
| **Timing** | Sleep acceleration (sandboxes often speed up) |
| **Registry** | VM-related registry keys (Windows) |
| **Processes** | Analysis tools running |
| **MAC Address** | Known VM vendor prefixes |

## Programmatic Usage

```rust
use redblue::modules::evasion::sandbox;

// Quick check
if sandbox::detect_sandbox() {
    println!("Sandbox detected!");
    return;
}

// Detailed score
let score = sandbox::sandbox_score();
if score > 50 {
    println!("High sandbox probability: {}", score);
}

// Check individual indicators
let indicators = sandbox::check_all_indicators();
for (name, detected) in indicators {
    println!("{}: {}", name, if detected { "DETECTED" } else { "OK" });
}
```

## Evasion Strategies

1. **Delay execution** - Sleep for extended periods (sandboxes have timeouts)
2. **User interaction** - Wait for mouse movement or keyboard input
3. **Resource usage** - Allocate memory, use CPU (sandboxes limit resources)
4. **Environment check** - Verify realistic environment variables

## Related

- [antidebug](/domains/evasion/05-antidebug.md) - Anti-debugging techniques
- [memory](/domains/evasion/04-memory.md) - Memory protection
