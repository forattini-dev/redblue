# MITM Interactive Shell - Implementation Plan

## Vision

Create a full-featured, k9s-style interactive TUI for the MITM proxy that provides:
- Real-time request/response streaming
- Request interception and modification
- History browsing and replay
- Split-pane interface with list + details

## User Experience

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ MITM Proxy Shell │ 127.0.0.1:8080 │ Requests: 47 │ Intercept: ON │ Filter: *│
├─────────────────────────────────────────────────────────────────────────────┤
│ # │ Method │ Host                    │ Path              │ Status │ Time   │
├───┼────────┼─────────────────────────┼───────────────────┼────────┼────────┤
│ 47│ GET    │ api.game.com            │ /v1/user/stats    │ 200    │ 45ms   │
│ 46│ POST   │ api.game.com            │ /v1/actions/buy   │ 201    │ 123ms  │
│>45│ GET    │ api.game.com            │ /v1/inventory     │ 200    │ 67ms   │◄
│ 44│ GET    │ cdn.game.com            │ /assets/sprite.png│ 200    │ 234ms  │
│ 43│ POST   │ analytics.game.com      │ /collect          │ 204    │ 89ms   │
├─────────────────────────────────────────────────────────────────────────────┤
│ Request #45: GET /v1/inventory HTTP/1.1                                     │
│─────────────────────────────────────────────────────────────────────────────│
│ Headers:                                                                    │
│   Host: api.game.com                                                        │
│   Authorization: Bearer eyJhbGciOiJIUzI1NiIs...                            │
│   User-Agent: GameClient/2.1.0                                              │
│   Accept: application/json                                                  │
│                                                                             │
│ Response: 200 OK (67ms)                                                     │
│   Content-Type: application/json                                            │
│   {"coins": 1500, "gems": 42, "items": ["sword", "shield"]}                │
├─────────────────────────────────────────────────────────────────────────────┤
│ [i]ntercept [r]eplay [e]dit [d]rop [f]ilter [/]search [q]uit │ j/k:nav     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Architecture

### 1. Core Components

```
src/modules/proxy/
├── mitm.rs              # Existing MITM proxy (keep as-is)
├── shell/               # NEW: Interactive shell module
│   ├── mod.rs           # Module exports
│   ├── app.rs           # Main TUI application state
│   ├── ui.rs            # Rendering logic (split panes)
│   ├── input.rs         # Key handling and commands
│   ├── state.rs         # Request history, filters, selection
│   ├── interceptor.rs   # Interactive request interceptor
│   └── repeater.rs      # Request replay functionality
```

### 2. Data Flow

```
                    ┌─────────────────┐
                    │   MitmProxy     │
                    │  (existing)     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ ShellInterceptor│  ◄── Implements RequestInterceptor
                    │  (channel-based)│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼────┐  ┌──────▼─────┐  ┌─────▼─────┐
     │ Request TX  │  │ Response TX│  │ Command RX│
     │  (mpsc)     │  │  (mpsc)    │  │  (mpsc)   │
     └────────┬────┘  └──────┬─────┘  └─────┬─────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │   MitmShell     │  ◄── TUI Application
                    │  (TUI thread)   │
                    └─────────────────┘
```

### 3. Key Data Structures

```rust
/// A captured HTTP exchange (request + response)
pub struct HttpExchange {
    pub id: u64,
    pub timestamp: SystemTime,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub duration_ms: u64,
    pub intercepted: bool,
    pub modified: bool,
    pub tags: Vec<String>,
}

/// Shell state
pub struct MitmShellState {
    pub exchanges: Vec<HttpExchange>,
    pub selected_idx: usize,
    pub scroll_offset: usize,
    pub filter: RequestFilter,
    pub intercept_enabled: bool,
    pub pending_intercept: Option<PendingIntercept>,
    pub view_mode: ShellViewMode,
}

/// Filter for requests
pub struct RequestFilter {
    pub host_pattern: Option<String>,    // e.g., "*.game.com"
    pub method: Option<String>,          // e.g., "POST"
    pub path_pattern: Option<String>,    // e.g., "/api/*"
    pub status_code: Option<u16>,        // e.g., 200
    pub content_type: Option<String>,    // e.g., "application/json"
}

/// View modes within the shell
pub enum ShellViewMode {
    List,           // Request list (default)
    Details,        // Full request/response details
    Edit,           // Editing a request for replay
    Intercept,      // Intercepting and modifying live request
    Search,         // Searching through history
}

/// Pending intercept (when in intercept mode)
pub struct PendingIntercept {
    pub request: HttpRequest,
    pub response_tx: oneshot::Sender<InterceptDecision>,
}

pub enum InterceptDecision {
    Forward(HttpRequest),  // Forward (possibly modified)
    Drop,                  // Drop the request
}
```

## Implementation Phases

### Phase 1: Foundation (Core Shell)
1. Create `MitmShell` TUI app structure based on existing `TuiApp`
2. Implement basic split-pane layout (request list + details)
3. Add keyboard navigation (j/k, arrows, Enter for details)
4. Create `ShellInterceptor` that sends exchanges to the shell via channels

### Phase 2: Real-time Streaming
1. Add mpsc channels between proxy and shell
2. Stream requests/responses in real-time to the TUI
3. Implement auto-scroll for new requests
4. Add status bar with request count and proxy info

### Phase 3: Request Details View
1. Full request/response display in bottom pane
2. Tab between headers/body/raw views
3. Syntax highlighting for JSON responses
4. Copy to clipboard functionality

### Phase 4: Filtering
1. Implement `RequestFilter` with pattern matching
2. Add filter command (`:filter host:*.game.com`)
3. Visual filter indicator in status bar
4. Quick filters (f1=json, f2=errors, f3=slow)

### Phase 5: Intercept Mode
1. Add intercept toggle (`i` key)
2. When enabled, pause requests and show edit view
3. Allow editing headers/body before forwarding
4. Forward (`f`) or drop (`d`) decision

### Phase 6: Replay/Repeater
1. Select any historical request
2. Open in edit mode (`e` key)
3. Modify and replay (`r` key)
4. Show new response alongside original

### Phase 7: Polish
1. Search functionality (`/` key)
2. Export requests (cURL, raw, JSON)
3. Color coding by status/method
4. Performance optimizations for large histories

## Key Bindings

| Key | Action |
|-----|--------|
| `j`/`↓` | Move selection down |
| `k`/`↑` | Move selection up |
| `Enter` | Toggle details view |
| `i` | Toggle intercept mode |
| `f` | Forward intercepted request |
| `d` | Drop intercepted request |
| `e` | Edit selected request |
| `r` | Replay selected request |
| `/` | Search mode |
| `:` | Command mode |
| `c` | Clear history |
| `x` | Export selected |
| `q` | Quit shell |
| `?` | Help |

## Commands (`:` mode)

```
:filter host:*.example.com    # Filter by host
:filter method:POST           # Filter by method
:filter status:4xx            # Filter by status range
:filter path:/api/*           # Filter by path
:filter clear                 # Clear all filters

:export curl                  # Export as cURL command
:export json                  # Export as JSON
:export raw                   # Export raw HTTP

:intercept on                 # Enable intercept mode
:intercept off                # Disable intercept mode
:intercept host:api.*         # Intercept only matching hosts

:set autoscroll on            # Auto-scroll to new requests
:set details on               # Always show details pane
```

## CLI Integration

New command:
```bash
rb mitm intercept shell [--port PORT] [--log-file FILE]
```

This starts the proxy AND opens the interactive shell.

## Files to Create/Modify

### New Files
- `src/modules/proxy/shell/mod.rs`
- `src/modules/proxy/shell/app.rs`
- `src/modules/proxy/shell/ui.rs`
- `src/modules/proxy/shell/input.rs`
- `src/modules/proxy/shell/state.rs`
- `src/modules/proxy/shell/interceptor.rs`
- `src/modules/proxy/shell/repeater.rs`

### Modified Files
- `src/modules/proxy/mod.rs` - Add shell module export
- `src/cli/commands/mitm.rs` - Add "shell" verb
- `src/modules/proxy/mitm.rs` - Integrate ShellInterceptor

## Estimated Effort

- Phase 1: Foundation - 2-3 hours
- Phase 2: Real-time - 1-2 hours
- Phase 3: Details - 1-2 hours
- Phase 4: Filtering - 1-2 hours
- Phase 5: Intercept - 2-3 hours
- Phase 6: Replay - 1-2 hours
- Phase 7: Polish - 2-3 hours

**Total: ~12-17 hours of implementation**

## Success Criteria

1. User can start shell with `rb mitm intercept shell`
2. Requests appear in real-time as they flow through proxy
3. User can navigate and inspect any request's full details
4. User can enable intercept mode and modify requests
5. User can replay any historical request with modifications
6. Filtering works smoothly with pattern matching
7. Performance is smooth even with 1000+ requests in history
