# Anti-Debugging

> Detect and evade debuggers and analysis tools.

## Overview

The `antidebug` resource provides techniques to detect:
- Debuggers (GDB, WinDbg, x64dbg, OllyDbg)
- Analysis tools (Process Monitor, Wireshark)
- Timing-based detection
- Platform-specific debugger APIs

## Commands

| Command | Description |
|---------|-------------|
| `quick` | Quick debugger check |
| `full` | Full anti-debugging scan |
| `timing` | Timing-based detection only |

## Usage

### Quick Check

```bash
rb evasion antidebug quick
```

Output:
```
▸ Quick Debugger Check

✓ No debugger detected
```

Or if detected:
```
▸ Quick Debugger Check

⚠ Debugger detected!
```

### Full Scan

```bash
rb evasion antidebug full
```

Output:
```
▸ Full Anti-Debug Scan

  Platform        linux

  Checks:
    ptrace:       OK (not being traced)
    /proc/status: OK (TracerPid: 0)
    timing:       OK (no timing anomaly)
    parent:       OK (normal parent process)
    environment:  OK (no debug vars)

✓ No debugger detected
```

### Timing Check

```bash
rb evasion antidebug timing
```

## Detection Techniques

### Linux

| Technique | How It Works |
|-----------|--------------|
| **ptrace** | `ptrace(PTRACE_TRACEME)` fails if already traced |
| **/proc/self/status** | Check `TracerPid` field |
| **Timing** | RDTSC instruction timing differences |
| **Parent process** | Check if parent is gdb, strace, etc. |

### Windows

| Technique | How It Works |
|-----------|--------------|
| **IsDebuggerPresent** | Direct API check |
| **CheckRemoteDebuggerPresent** | Remote debugger check |
| **NtQueryInformationProcess** | Debug port check |
| **PEB flags** | BeingDebugged, NtGlobalFlag |
| **Timing** | QueryPerformanceCounter anomalies |
| **Hardware breakpoints** | DR registers check |

## Programmatic Usage

```rust
use redblue::modules::evasion::antidebug;

// Quick check
if antidebug::is_debugger_present() {
    println!("Debugger detected!");
    std::process::exit(1);
}

// Full check
let result = antidebug::full_check();
if result.debugger_detected {
    println!("Detected by: {:?}", result.detection_methods);
}

// Timing check
if antidebug::timing_check() {
    println!("Timing anomaly detected");
}
```

## Evasion Strategies

When debugger detected:

1. **Exit silently** - Clean exit, no error message
2. **Corrupt data** - Modify behavior subtly
3. **Infinite loop** - Waste analyst's time
4. **Crash** - Trigger access violation
5. **Anti-anti-debug** - Counter debugging countermeasures

## Related

- [sandbox](01-sandbox.md) - Sandbox detection
- [memory](04-memory.md) - Memory protection
