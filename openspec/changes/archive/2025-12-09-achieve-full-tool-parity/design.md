# Technical Design: Full Tool Parity

## Context

redblue is a security toolkit written in pure Rust with a strict zero-external-dependency policy for protocol implementations. This design document captures key technical decisions for achieving full tool parity while maintaining this philosophy.

## Goals

1. **Feature Parity**: Match or exceed capabilities of 30+ security tools
2. **Zero Protocol Dependencies**: All protocols implemented from scratch (DNS, HTTP, TLS inspection, etc.)
3. **Single Binary**: No external files, embedded resources
4. **Performance**: Multi-threaded, async-capable without runtime overhead
5. **Usability**: kubectl-style CLI, real-time TUI

## Non-Goals

1. Full Nmap NSE ecosystem replication (too large, use Lua)
2. Browser automation (use external headless browser when needed)
3. GUI application (terminal-first)
4. Windows GUI payloads (CLI payloads only)

---

## Architecture Decisions

### AD-1: MITM Proxy Architecture

**Decision**: Implement streaming proxy with zero-copy where possible

**Context**: Current MITM proxy buffers entire responses, causing memory issues with large files and breaking streaming media.

**Options Considered**:
1. **Full buffering**: Simple but memory-hungry
2. **Streaming with injection points**: Complex but efficient
3. **Dual-mode**: Buffer small responses, stream large ones

**Choice**: Option 3 (Dual-mode)
- Responses < 1MB: Full buffer, inject freely
- Responses > 1MB: Stream with single-pass injection
- Binary content types: Always stream, no injection

**Implementation**:
```rust
enum ProxyMode {
    Buffer { max_size: usize },
    Stream { inject_point: Option<InjectionPoint> },
}

struct InjectionPoint {
    pattern: &'static [u8], // b"</body>"
    payload: Vec<u8>,
    injected: bool,
}
```

### AD-2: RBB C2 Protocol

**Decision**: Simple HTTP polling with JSON payloads

**Context**: Need browser-to-server communication that works through corporate proxies and firewalls.

**Options Considered**:
1. **WebSocket**: Real-time but blocked by some proxies
2. **HTTP Long Polling**: Works everywhere, slight latency
3. **Server-Sent Events**: One-way only
4. **Custom binary protocol**: Won't work in browsers

**Choice**: Option 2 (HTTP Long Polling) with WebSocket upgrade path

**Protocol**:
```
POST /rbb/register
{
  "ua": "Mozilla/5.0...",
  "url": "https://victim.com/page",
  "capabilities": ["keylog", "screenshot", "form"]
}
Response: { "session_id": "uuid", "poll_interval": 5000 }

GET /rbb/poll?session=uuid
Response: { "commands": [{"id": 1, "type": "exec", "payload": "alert(1)"}] }

POST /rbb/response
{
  "session_id": "uuid",
  "command_id": 1,
  "result": "undefined",
  "error": null
}
```

### AD-3: Signature Database Format

**Decision**: Embedded binary format with runtime indexing

**Context**: Nikto has 7000+ signatures; we need efficient storage and lookup.

**Options Considered**:
1. **JSON embedded**: Simple, but slow parsing
2. **SQLite embedded**: Too heavy
3. **Custom binary**: Fast, compact
4. **Rust const arrays**: Compile-time checked but verbose

**Choice**: Option 4 (Rust const arrays) for core signatures, Option 3 for extensibility

**Format**:
```rust
pub struct VulnSignature {
    pub id: u32,
    pub name: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub match_type: MatchType,
    pub match_pattern: &'static str,
    pub severity: Severity,
    pub cve: Option<&'static str>,
    pub description: &'static str,
}

pub enum MatchType {
    StatusCode(u16),
    HeaderContains(&'static str),
    BodyContains(&'static str),
    BodyRegex(&'static str),
}

// Compile-time signatures
pub const SIGNATURES: &[VulnSignature] = &[
    VulnSignature {
        id: 1,
        name: "Apache Server Status",
        method: "GET",
        path: "/server-status",
        match_type: MatchType::BodyContains("Apache Server Status"),
        severity: Severity::Low,
        cve: None,
        description: "Apache mod_status information disclosure",
    },
    // ... 500+ more
];
```

### AD-4: TLS Vulnerability Detection

**Decision**: Protocol-level testing without OpenSSL internals

**Context**: Need to detect TLS vulnerabilities (Heartbleed, POODLE, etc.) without calling vulnerable code.

**Approach**:
```rust
// Heartbleed: Send malformed heartbeat, check for memory leak
fn test_heartbleed(stream: &mut TlsStream) -> VulnResult {
    // Craft heartbeat with length > payload
    let heartbeat = craft_heartbleed_request();
    stream.write_raw(&heartbeat)?;

    let response = stream.read_raw()?;
    if response.len() > expected_len {
        VulnResult::Vulnerable("CVE-2014-0160")
    } else {
        VulnResult::NotVulnerable
    }
}

// POODLE: Test SSLv3 with CBC
fn test_poodle(host: &str) -> VulnResult {
    // Force SSLv3 connection
    if can_connect_sslv3(host) {
        // Check for CBC cipher usage
        if uses_cbc_cipher(host) {
            VulnResult::Vulnerable("CVE-2014-3566")
        }
    }
    VulnResult::NotVulnerable
}
```

### AD-5: OS Fingerprinting Data Model

**Decision**: Nmap-compatible signature format with Rust parser

**Context**: OS fingerprinting requires matching TCP/IP stack behaviors against known patterns.

**Data Model**:
```rust
pub struct OsFingerprint {
    pub name: &'static str,
    pub vendor: &'static str,
    pub family: OsFamily,
    pub version: Option<&'static str>,
    pub accuracy: u8, // 0-100
    pub tests: FingerprintTests,
}

pub struct FingerprintTests {
    pub seq: SeqTest,      // TCP sequence analysis
    pub ops: OpsTest,      // TCP options
    pub win: WinTest,      // Window size
    pub ecn: EcnTest,      // Explicit Congestion Notification
    pub t1_t7: [TTest; 7], // Probe responses
    pub u1: UTest,         // UDP response
    pub ie: IeTest,        // ICMP echo
}

pub struct SeqTest {
    pub sp: Range<u32>,    // Sequence predictability
    pub gcd: u32,          // GCD of differences
    pub isr: Range<u32>,   // ISN rate
    pub ti: TiValue,       // IP ID sequence
    pub ci: CiValue,       // Closed port IP ID
    pub ii: IiValue,       // ICMP IP ID
    pub ss: SsValue,       // Shared IP ID sequence
    pub ts: TsValue,       // Timestamp option
}
```

### AD-6: Graph Visualization

**Decision**: Custom ASCII renderer without external libraries

**Context**: Need terminal-based graph visualization without ncurses or tui-rs dependencies.

**Renderer Algorithm**:
```rust
pub fn render_tree(root: &Node, depth: usize, prefix: &str, is_last: bool) -> String {
    let mut output = String::new();

    // Current node
    let connector = if depth == 0 {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    output.push_str(&format!("{}{}{}\n", prefix, connector, root.label));

    // Children
    let child_prefix = if depth == 0 {
        ""
    } else if is_last {
        format!("{}    ", prefix)
    } else {
        format!("{}│   ", prefix)
    };

    for (i, child) in root.children.iter().enumerate() {
        let is_last_child = i == root.children.len() - 1;
        output.push_str(&render_tree(child, depth + 1, &child_prefix, is_last_child));
    }

    output
}
```

---

## Data Flow Diagrams

### MITM Proxy Flow

```
┌─────────┐     ┌─────────────┐     ┌────────────────┐     ┌──────────┐
│ Victim  │────▶│ DNS Hijack  │────▶│ MITM Proxy     │────▶│ Target   │
│ Browser │     │ (redirect)  │     │                │     │ Server   │
└─────────┘     └─────────────┘     │ 1. Strip CSP   │     └──────────┘
                                    │ 2. Inject hook │
                                    │ 3. Log traffic │
                                    └───────┬────────┘
                                            │
                                    ┌───────▼────────┐
                                    │ RBB Controller │
                                    │ (TUI/API)      │
                                    └────────────────┘
```

### RBB Communication Flow

```
┌─────────────┐                    ┌─────────────────┐
│   Hooked    │   1. Register      │                 │
│   Browser   │───────────────────▶│   redblue       │
│             │                    │   HTTP Server   │
│             │   2. Poll          │                 │
│             │◀──────────────────▶│   /rbb/poll     │
│             │                    │                 │
│             │   3. Execute       │   ┌───────────┐ │
│             │◀───────────────────│   │  RBB TUI  │ │
│             │                    │   │ Dashboard │ │
│             │   4. Report        │   └───────────┘ │
│             │───────────────────▶│                 │
└─────────────┘                    └─────────────────┘
```

---

## Security Considerations

### Authorized Use Only

All offensive capabilities (MITM, RBB, exploitation) are intended **only for authorized security testing**:
- Penetration testing engagements with written authorization
- Red team exercises
- CTF competitions
- Security research in controlled environments

### Operational Security

- No hardcoded C2 domains
- No phone-home telemetry
- No automatic exfiltration
- All data stored locally by default
- Clear logging of all actions

### Detection Signatures

Document common detection patterns so defenders can identify redblue usage:
- User-Agent strings
- HTTP header patterns
- DNS query patterns
- TLS fingerprints

---

## Migration Plan

### From enhance-mitm-and-control

The existing `enhance-mitm-and-control` openspec is fully absorbed into this proposal:
- Phase 2 (MITM Hardening) covers all header stripping tasks
- Phase 3 (RBB Control) covers all C2 and TUI tasks
- Phase 4.2 (Auto-Replication) covers replication tasks
- Phase 5.1 (ASCII Graphs) covers visualization tasks

### Backward Compatibility

- All existing CLI commands remain functional
- Config file format extended, not changed
- Database schema additions only (no breaking changes)

---

## Open Questions

1. **Should RBB support encrypted C2?**
   - Pro: Avoids detection
   - Con: Adds complexity, may need TLS
   - Decision: Defer to v1.1

2. **How to handle large CMS plugin databases?**
   - Option A: Embed all (increases binary size)
   - Option B: Download on first use
   - Decision: Embed top 1000, download full on demand

3. **OS fingerprinting accuracy target?**
   - Nmap achieves 85-95% accuracy
   - Target: 80% accuracy for v1.0

---

## References

- Nmap OS fingerprinting: https://nmap.org/book/osdetect.html
- testssl.sh vulnerability checks: https://github.com/drwetter/testssl.sh
- WPScan plugin enumeration: https://github.com/wpscanteam/wpscan
