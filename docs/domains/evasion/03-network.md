# Network Evasion

> Evade network-based detection with jitter and timing.

## Overview

The `network` resource provides techniques to evade network monitoring:
- Beacon jitter (randomize timing)
- Sleep with jitter
- Domain fronting support

## Commands

| Command | Description |
|---------|-------------|
| `jitter` | Calculate jittered delay |
| `beacon` | Show beacon timing configuration |

## Usage

### Calculate Jitter

```bash
rb evasion network jitter 60000
```

Output:
```
▸ Network Jitter

  Base interval   60000ms (1 minute)
  Jitter percent  30%
  Range           42000ms - 78000ms

  Sample delays:
    1: 52341ms
    2: 71823ms
    3: 45219ms
    4: 68432ms
    5: 55678ms

ℹ Randomized timing avoids pattern detection
```

### Beacon Configuration

```bash
rb evasion network beacon
```

Output:
```
▸ Beacon Configuration

  Default interval:  60000ms
  Jitter percent:    30%

  Timing patterns avoided:
    - Exact intervals (every 60s)
    - Regular patterns (detectable by NTA)
    - Predictable callbacks

ℹ Use jittered_sleep() for all beacon operations
```

## Why Jitter Matters

**Without jitter:**
```
Network Traffic:
  00:00:00 - Callback
  00:01:00 - Callback  <- Exact 60s interval
  00:02:00 - Callback  <- Pattern detected!
  00:03:00 - Callback
```

**With 30% jitter:**
```
Network Traffic:
  00:00:00 - Callback
  00:00:47 - Callback  <- Randomized
  00:01:52 - Callback  <- No pattern
  00:02:31 - Callback
```

## Programmatic Usage

```rust
use redblue::modules::evasion::network;

// Sleep with jitter
network::jittered_sleep(60000, 30);  // 60s base, 30% jitter

// Get jittered duration
let delay = network::jittered_duration(60000, 30);
std::thread::sleep(delay);

// Calculate next beacon time
let config = EvasionConfig::default();
let next_beacon = config.next_beacon_delay();
```

## Configuration

```rust
let config = EvasionConfig {
    network_jitter: true,
    beacon_interval_ms: 60_000,  // 1 minute base
    jitter_percent: 30,          // ±30%
    // ...
};
```

### Presets

| Preset | Interval | Jitter |
|--------|----------|--------|
| `default()` | 60s | 30% |
| `stealth()` | 5min | 50% |
| `aggressive()` | 5s | 10% |

## Related

- [sandbox](01-sandbox.md) - Sandbox detection
- [antidebug](05-antidebug.md) - Anti-debugging
