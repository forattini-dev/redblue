# Design: Complete Agent C2 Architecture

## Context

redblue already has extensive C2 capabilities implemented (200K+ lines of exploit/evasion code). The missing piece is the **orchestration layer** - a beacon-based agent-server architecture that unifies all existing capabilities under remote control.

**Existing capabilities to leverage:**
- Crypto: AES-256-GCM, ChaCha20-Poly1305, RSA, X25519, HMAC, HKDF
- Evasion: Jitter, sandbox detection, AMSI bypass, string obfuscation
- Listener: Multi-session, persistence, base64/DNS tunneling
- Payloads: 10+ reverse shell types (TCP, HTTP, DNS, ICMP, WebSocket, Encrypted)
- Proxy: SOCKS5, HTTP, MITM, TCP/UDP relay

**Constraints**:
- Must maintain redblue's zero-dependency philosophy (Rust std only)
- Must be single binary (no external config files required)
- Must leverage existing modules, NOT duplicate them
- Must support both standalone and C2 modes

## Goals / Non-Goals

### Goals
1. Enable remote execution of playbooks across multiple targets
2. Provide system accessors for target interrogation (file, process, network)
3. Implement beacon-based C2 using existing crypto/evasion
4. Unify all existing exploit capabilities under remote control

### Non-Goals
1. Query language (VQL equivalent) - NOT NEEDED, use direct accessors
2. Full GUI management console - CLI-first
3. Duplicate existing capabilities (crypto, evasion, shells, etc.)

## Decisions

### Decision 1: No Query Language

**Decision**: Do NOT implement RQL or any query language.

**Rationale**:
- Direct accessor calls are simpler and more performant
- Query language adds complexity without significant benefit
- Velociraptor's VQL is primarily for forensics; redblue focuses on active operations

**Instead**: Use direct accessor API:
```rust
// Instead of: SELECT * FROM process() WHERE name =~ "chrome"
// Use: ProcessAccessor::list().filter(|p| p.name.contains("chrome"))
```

### Decision 2: Accessor Architecture

```rust
pub trait Accessor: Send + Sync {
    fn name(&self) -> &str;
    fn info(&self) -> AccessorInfo;
    fn execute(&self, args: &Args) -> Result<AccessorOutput>;
}

pub struct AccessorOutput {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}
```

**Core accessors** (Phase 2):
- `file` - File system access (list, read, hash, search)
- `process` - Process listing (list, tree, cmdline)
- `network` - Network state (connections, arp, routes)
- `registry` - Windows registry (conditional compilation)
- `service` - Services/daemons enumeration

**Rationale**: Trait-based accessors allow easy extension while maintaining compile-time safety.

### Decision 3: Beacon Protocol (Leverage Existing Crypto)

Use existing ChaCha20-Poly1305 for session encryption (already implemented):

```
┌─────────────────────────────────────────┐
│              Beacon Message             │
├─────────────────────────────────────────┤
│ magic: u32      = 0x52424C55 ("RBLU")  │
│ version: u8     = 1                     │
│ msg_type: u8    = BEACON|RESPONSE|CMD   │
│ flags: u16      = encrypted|compressed  │
│ session_id: u64 = unique session        │
│ timestamp: u64  = unix epoch            │
│ payload_len: u32                        │
│ payload: [u8]   = ChaCha20 encrypted    │
│ tag: [u8; 16]   = Poly1305 auth tag     │
└─────────────────────────────────────────┘
```

**Key exchange**: Use existing X25519 for ECDH key agreement.
**Session encryption**: Use existing ChaCha20-Poly1305 (AEAD).
**Jitter**: Use existing evasion module's jitter implementation.

**Rationale**: Leverage 5,297 lines of existing crypto code instead of reimplementing.

### Decision 4: Server Mode (Leverage HTTP Server)

Build on existing HTTP server (`src/modules/http_server/`):

```rust
// Server adds routes to existing HTTP server
pub struct AgentServer {
    http_server: HttpServer,
    clients: HashMap<SessionId, ClientState>,
    command_queue: HashMap<SessionId, VecDeque<Command>>,
}
```

**Endpoints**:
- `POST /beacon` - Agent check-in, receive commands
- `POST /result` - Agent returns command results
- `GET /payload` - Download additional payloads (leverage self-serve)

**Rationale**: Reuse existing HTTP server instead of building new transport.

### Decision 5: Agent Mode (Leverage Evasion + Listener)

Agent reuses existing modules:

```rust
pub struct Agent {
    server_url: String,
    session_key: [u8; 32],  // From X25519 key exchange
    interval: Duration,      // Base beacon interval
    jitter: f32,            // From evasion module
    accessors: Vec<Box<dyn Accessor>>,
}
```

**Beacon behavior** (use existing evasion):
- Base interval: configurable (default: 60s)
- Jitter: Use `EvasionConfig::jitter_percent` (0-30%)
- Backoff: exponential on connection failure (max 1 hour)

**Command execution**: Route to existing modules:
- Playbook → `PlaybookExecutor`
- Shell → existing payloads in `src/modules/exploit/payloads.rs`
- PrivEsc → existing scanner in `src/modules/exploit/privesc.rs`
- Accessor → new accessor modules

### Decision 6: Playbook Executor

```rust
pub struct PlaybookExecutor {
    playbooks: Vec<Playbook>,
    recommender: PlaybookRecommender,  // Already implemented
}

pub struct ExecutionContext {
    target: String,
    variables: HashMap<String, String>,
    evidence: Vec<Evidence>,
}
```

**Step execution**:
```rust
pub enum StepAction {
    Shell(ShellConfig),      // Use existing payloads
    Accessor(AccessorCall),  // Use accessor trait
    Command(String),         // Shell command
    Playbook(String),        // Chain to another playbook
}
```

**Rationale**: Executor orchestrates existing capabilities rather than reimplementing them.

## Risks / Trade-offs

### Risk 1: Detection by EDR
**Impact**: High - Modern EDR can detect C2 traffic patterns
**Mitigation**: Use existing evasion module:
- Jitter already implemented
- Sandbox detection already implemented
- HTTP traffic blends with normal web traffic

### Risk 2: Complexity
**Impact**: Medium - Agent architecture adds moving parts
**Mitigation**:
- Leverage existing modules heavily
- Keep protocol simple
- Single binary philosophy maintained

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                        redblue Binary                        │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │   CLI       │  │   Server    │  │   Agent     │          │
│  │ (standalone)│  │   Mode      │  │   Mode      │          │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│         │                │                │                  │
│  ┌──────┴────────────────┴────────────────┴──────┐          │
│  │                 Playbook Executor              │          │
│  └───────────────────────┬───────────────────────┘          │
│                          │                                   │
│  ┌───────────────────────┴───────────────────────┐          │
│  │              EXISTING MODULES                  │          │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │          │
│  │  │ Payloads │  │ Evasion  │  │  Crypto  │    │          │
│  │  │ (79K)    │  │ (13 files)│ │ (5.3K)   │    │          │
│  │  └──────────┘  └──────────┘  └──────────┘    │          │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │          │
│  │  │ Listener │  │  Proxy   │  │Collection│    │          │
│  │  │ (45K)    │  │ (19 files)│ │(secrets) │    │          │
│  │  └──────────┘  └──────────┘  └──────────┘    │          │
│  └───────────────────────────────────────────────┘          │
│                          │                                   │
│  ┌───────────────────────┴───────────────────────┐          │
│  │              NEW MODULES                       │          │
│  │  ┌──────────┐  ┌──────────┐                   │          │
│  │  │Accessors │  │  Agent   │                   │          │
│  │  │(file,proc│  │(server,  │                   │          │
│  │  │network)  │  │ client)  │                   │          │
│  │  └──────────┘  └──────────┘                   │          │
│  └───────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────┘
```

## Migration Plan

### Phase 1: Playbook Executor (No breaking changes)
1. Add `PlaybookExecutor` to existing `src/playbooks/`
2. Leverage existing `PlaybookRecommender`
3. Add new CLI command: `rb exploit payload run`

### Phase 2: System Accessors (New module)
1. Create `src/accessors/` module
2. Implement file, process, network accessors
3. Add new CLI command: `rb access <type> <args>`

### Phase 3: Agent Architecture (New module)
1. Create `src/agent/` module
2. Build on existing HTTP server
3. Add new CLI commands: `rb server`, `rb agent`

**Rollback**: Each phase is additive; removing features requires recompilation with feature flags disabled.

## Open Questions

1. **Transport fallback**: Should we implement DNS tunneling for agent?
   - Option A: HTTP only (simpler, use existing server)
   - Option B: HTTP + DNS (more resilient, more complex)

2. **Session persistence**: In-memory only vs. disk persistence?
   - Option A: In-memory (ephemeral, no traces)
   - Option B: Persist to .rbdb files (existing storage)

3. **Multi-platform agent**: Cross-compile or separate builds?
   - Option A: Cross-compile from one host
   - Option B: Build matrix (Windows, Linux, macOS)
