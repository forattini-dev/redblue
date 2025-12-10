# Interactive Shell

> k9s-style TUI for real-time traffic inspection and manipulation.

## Overview

The MITM shell provides a full-featured terminal user interface for monitoring and interacting with intercepted traffic. Inspired by k9s (Kubernetes CLI), it offers real-time request streaming, filtering, search, and detailed inspection.

## Quick Start

```bash
# Start interactive shell with proxy
rb mitm intercept shell --proxy-port 8080

# With custom CA
rb mitm intercept shell --proxy-port 8080 \
  --ca-cert ./ca.pem --ca-key ./ca-key.pem
```

Then configure your browser to use `127.0.0.1:8080` as HTTP/HTTPS proxy.

## Interface Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  MITM Shell                                        127.0.0.1:8080   │
├─────────────────────────────────────────────────────────────────────┤
│  Filter: *                               Intercept: OFF   [?] Help  │
├──────┬────────┬──────────────────────────┬───────┬─────────┬────────┤
│ Time │ Method │ Host                     │ Path  │ Status  │ Time   │
├──────┼────────┼──────────────────────────┼───────┼─────────┼────────┤
│12:34 │ GET    │ api.example.com          │ /v1/  │ 200     │ 45ms   │
│12:34 │ POST   │ api.example.com          │ /login│ 302     │ 123ms  │
│12:35 │ GET    │ cdn.example.com          │ /app.j│ 200     │ 12ms   │
│12:35 │ GET    │ api.example.com          │ /user │ 200     │ 67ms   │
│▶12:36│ POST   │ api.example.com          │ /data │ ...     │ -      │
├──────┴────────┴──────────────────────────┴───────┴─────────┴────────┤
│ 5 requests | 0 intercepted | Auto-scroll: ON                        │
└─────────────────────────────────────────────────────────────────────┘
```

## Keyboard Shortcuts

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `k` | Move selection up |
| `↓` / `j` | Move selection down |
| `PgUp` | Page up |
| `PgDn` | Page down |
| `g` / `Home` | Go to first request |
| `G` / `End` | Go to last request |

### View Modes

| Key | Action |
|-----|--------|
| `Enter` | Toggle details view |
| `Tab` | Switch detail tab (Headers → Body → Raw) |
| `Shift+Tab` | Previous detail tab |
| `?` | Show help overlay |
| `Esc` | Exit current mode / close overlay |

### Actions

| Key | Action |
|-----|--------|
| `q` | Quit shell |
| `c` | Clear request history |
| `i` | Toggle intercept mode |
| `/` | Enter search mode |
| `:` | Enter command mode |

### Detail View

| Key | Action |
|-----|--------|
| `Tab` | Switch between Headers, Body, Raw tabs |
| `↑` / `↓` | Scroll content |
| `Esc` / `Enter` | Return to list |

## View Modes

### List View (Default)

The main view showing all captured requests:

```
┌──────┬────────┬──────────────────────────┬────────────┬────────┬────────┐
│ Time │ Method │ Host                     │ Path       │ Status │ Time   │
├──────┼────────┼──────────────────────────┼────────────┼────────┼────────┤
│12:34 │ GET    │ api.example.com          │ /v1/users  │ 200    │ 45ms   │
│12:34 │ POST   │ api.example.com          │ /v1/login  │ 302    │ 123ms  │
│12:35 │ GET    │ cdn.example.com          │ /app.js    │ 200    │ 12ms   │
└──────┴────────┴──────────────────────────┴────────────┴────────┴────────┘
```

**Columns:**
- **Time**: Request timestamp (HH:MM:SS)
- **Method**: HTTP method (GET, POST, etc.)
- **Host**: Target hostname
- **Path**: Request path (truncated if long)
- **Status**: Response status code or `...` if pending
- **Time**: Round-trip time

### Details View

Press `Enter` to see full request/response details:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Request Details                                        [Esc] Back  │
├─────────────────────────────────────────────────────────────────────┤
│  GET /api/v1/users HTTP/1.1                                         │
│  Host: api.example.com                                              │
│  Status: 200 OK (45ms)                                              │
├─────────────────────────────────────────────────────────────────────┤
│  [Headers]  [Body]  [Raw]                                           │
├─────────────────────────────────────────────────────────────────────┤
│  Request Headers:                                                   │
│    Host: api.example.com                                            │
│    User-Agent: Mozilla/5.0...                                       │
│    Accept: application/json                                         │
│    Cookie: session=abc123...                                        │
│                                                                     │
│  Response Headers:                                                  │
│    Content-Type: application/json                                   │
│    Content-Length: 1234                                             │
│    Set-Cookie: token=xyz789...                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Tabs:**
- **Headers**: Request and response headers
- **Body**: Parsed body content (JSON formatted)
- **Raw**: Raw HTTP request and response

### Help View

Press `?` to show keyboard shortcuts:

```
┌─────────────────────────────────────────────────────────────────────┐
│                           MITM Shell Help                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Navigation:                                                        │
│    ↑/k, ↓/j    Move up/down                                        │
│    PgUp/PgDn   Page up/down                                        │
│    g/G         First/last request                                  │
│                                                                     │
│  Actions:                                                           │
│    Enter       Toggle details                                       │
│    Tab         Switch detail tab                                    │
│    /           Search                                               │
│    :           Command mode                                         │
│    i           Toggle intercept                                     │
│    c           Clear history                                        │
│    q           Quit                                                 │
│                                                                     │
│  Press any key to close                                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Filtering

### Filter Syntax

Press `:` and type `filter` or `f`:

```
:filter host:*.api.com method:POST status:2xx
```

### Filter Options

| Filter | Example | Description |
|--------|---------|-------------|
| `host:` | `host:*.api.com` | Match hostname (glob) |
| `method:` | `method:POST` | Match HTTP method |
| `path:` | `path:/api/*` | Match path (glob) |
| `status:` | `status:200` | Match exact status |
| `status:` | `status:4xx` | Match status range |
| `type:` | `type:json` | Match content-type |

### Filter Examples

```bash
# Only POST requests
:filter method:POST

# Only API endpoints
:filter host:api.* path:/v1/*

# Only errors
:filter status:4xx

# JSON responses only
:filter type:json

# Combined filters
:filter host:*.corp.com method:POST status:2xx

# Clear filter
:filter clear
```

## Search

Press `/` to enter search mode:

```
/password
```

Search looks in:
- Method
- Host
- Path
- Request body
- Response body

Press `Enter` to find next match, `Esc` to cancel.

## Commands

Press `:` to enter command mode:

| Command | Alias | Description |
|---------|-------|-------------|
| `filter <expr>` | `f` | Set request filter |
| `filter clear` | | Clear filter |
| `clear` | `c` | Clear request history |
| `autoscroll on/off` | `scroll` | Toggle auto-scroll |
| `intercept on/off` | `i` | Toggle intercept mode |
| `quit` | `q` | Exit shell |

### Command Examples

```bash
# Set filter
:filter host:api.example.com

# Clear history
:clear

# Enable intercept mode
:intercept on

# Disable auto-scroll
:autoscroll off

# Exit
:quit
```

## Auto-Scroll

When enabled (default), the view automatically scrolls to show new requests. Toggle with:

- Command: `:autoscroll off`
- Or scroll up manually (disables temporarily)

## Intercept Mode

When intercept is enabled, requests are held for review before forwarding:

```
┌─────────────────────────────────────────────────────────────────────┐
│  INTERCEPTED REQUEST                               [f]orward [d]rop │
├─────────────────────────────────────────────────────────────────────┤
│  POST /api/v1/login HTTP/1.1                                        │
│  Host: api.example.com                                              │
│                                                                     │
│  Request Body:                                                      │
│  {"username": "admin", "password": "secret123"}                     │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  [f] Forward   [d] Drop   [e] Edit   [Esc] Cancel                   │
└─────────────────────────────────────────────────────────────────────┘
```

**Intercept Actions:**
- `f` - Forward request to target
- `d` - Drop request (don't forward)
- `e` - Edit request before forwarding (TODO)
- `Esc` - Cancel and return to list

## Request State Indicators

| Indicator | Meaning |
|-----------|---------|
| `...` | Request pending (waiting for response) |
| `200` | Successful response |
| `4xx` | Client error (red) |
| `5xx` | Server error (red) |
| `DROP` | Request was dropped |
| `MOD` | Request was modified |

## Color Coding

| Color | Meaning |
|-------|---------|
| Green | 2xx success responses |
| Yellow | 3xx redirects |
| Red | 4xx/5xx errors |
| Blue | Selected row |
| Gray | Pending requests |
| Magenta | Modified requests |

## Data Structures

### HttpExchange

Each captured request/response pair:

```rust
HttpExchange {
    id: u64,                        // Unique identifier
    timestamp: SystemTime,          // When received
    source_ip: String,              // Client IP
    method: String,                 // GET, POST, etc.
    host: String,                   // Target host
    path: String,                   // Request path
    version: String,                // HTTP/1.1
    request_headers: HashMap,       // Request headers
    request_body: Vec<u8>,          // Request body
    status_code: Option<u16>,       // Response status
    status_text: Option<String>,    // Status text
    response_headers: HashMap,      // Response headers
    response_body: Vec<u8>,         // Response body
    duration_ms: Option<u64>,       // Round-trip time
    was_modified: bool,             // If edited
    was_dropped: bool,              // If dropped
    tags: Vec<String>,              // Custom tags
}
```

### RequestFilter

Filter configuration:

```rust
RequestFilter {
    host_pattern: Option<String>,   // Glob pattern for host
    method: Option<String>,         // HTTP method
    path_pattern: Option<String>,   // Glob pattern for path
    status_code: Option<u16>,       // Status or range (4 = 4xx)
    content_type: Option<String>,   // Content-type contains
    search_text: Option<String>,    // Full-text search
}
```

## Performance

### Request History

- Default limit: 10,000 requests
- Older requests are removed when limit reached
- Filter indices are cached and updated lazily

### Rendering

- UI renders at 50ms intervals (20 FPS)
- Non-blocking input handling
- Efficient terminal updates (only changed areas)

## Tips and Tricks

### Efficient Workflow

1. Start with broad filter, narrow as needed
2. Use auto-scroll to see new requests
3. Press `Enter` on interesting requests
4. Use `Tab` to see headers, body, raw

### Finding Sensitive Data

```bash
# Find login requests
/login

# Filter POST requests
:filter method:POST

# Find JSON responses
:filter type:json

# Search for passwords
/password
```

### Debugging API Calls

```bash
# Filter to specific API
:filter host:api.myapp.com

# Only errors
:filter status:4xx

# View response body
# Select request → Enter → Tab to Body
```

## Troubleshooting

### Shell Not Rendering

**Problem**: Terminal shows garbage or doesn't render

**Solutions**:
- Ensure terminal supports ANSI colors
- Try different terminal emulator
- Check terminal size (minimum 80x24)

### Input Not Working

**Problem**: Keys don't respond

**Solutions**:
- Check if in text input mode (press `Esc`)
- Verify terminal raw mode support
- Try restarting the shell

### Missing Requests

**Problem**: Some requests not showing

**Possible causes**:
- Active filter hiding them
- Auto-scroll disabled
- Request outside time window

**Solutions**:
```bash
:filter clear
:autoscroll on
```

## Examples

### Basic Session

```bash
# Start shell
rb mitm intercept shell --proxy-port 8080

# Configure browser proxy
# Browse target application

# In shell:
# - Watch requests stream in
# - Press Enter on interesting requests
# - Use / to search for sensitive data
# - Press q to quit
```

### Capturing Credentials

```bash
# Start shell
rb mitm intercept shell --proxy-port 8080

# Filter to login endpoints
:filter path:*login* method:POST

# Browse to login page in browser
# Enter credentials
# View captured data in shell
```

### API Analysis

```bash
# Start shell
rb mitm intercept shell --proxy-port 8080

# Filter to API
:filter host:api.* type:json

# Use target application
# Analyze API structure in shell
```

## Next Steps

- [Certificates](/domains/mitm/04-certificates.md) - CA management
- [Attack Scenarios](/domains/mitm/05-scenarios.md) - Real-world examples
- [Configuration](/domains/mitm/06-configuration.md) - All options
