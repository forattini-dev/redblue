# Agent Capability

## ADDED Requirements

### Requirement: Server Mode
The system SHALL support running as a command-and-control server for managing remote agents.

#### Scenario: Start server (leverage existing HTTP server)
- **WHEN** operator runs `rb server start`
- **THEN** server starts on port 8443 using existing HTTP server module
- **AND** displays client connection endpoint URL

#### Scenario: Manage connected clients
- **WHEN** operator runs `rb server clients list`
- **THEN** displays all connected agents with ID, hostname, IP, last seen

### Requirement: Agent Mode
The system SHALL support running as a lightweight agent that connects to a server.

#### Scenario: Connect agent to server
- **WHEN** operator runs `rb agent connect https://server:8443 --interval 60`
- **THEN** agent establishes encrypted connection (using existing ChaCha20)
- **AND** begins beacon cycle with configured interval
- **AND** uses existing evasion module for jitter

#### Scenario: Reconnection on failure
- **WHEN** connection to server is lost
- **THEN** agent retries with exponential backoff (max 1 hour)

### Requirement: Beacon Protocol
The system SHALL use existing crypto modules for encrypted communications.

#### Scenario: Key exchange
- **WHEN** agent connects for the first time
- **THEN** uses existing X25519 for ECDH key agreement
- **AND** uses existing ChaCha20-Poly1305 for session encryption

#### Scenario: Jitter (use existing evasion)
- **WHEN** agent is connected with `--jitter 30`
- **THEN** uses existing `EvasionConfig::jitter_percent` from evasion module
- **AND** beacon interval varies by 0-30% randomly

### Requirement: Command Routing
The system SHALL route commands to existing modules.

#### Scenario: Execute playbook remotely
- **WHEN** server sends playbook execution command
- **THEN** agent executes via PlaybookExecutor
- **AND** returns results to server

#### Scenario: Execute accessor query
- **WHEN** server sends `file_list("/etc")` accessor command
- **THEN** agent executes via Accessor trait
- **AND** returns structured results to server

#### Scenario: Execute existing exploit commands
- **WHEN** server sends shell/privesc command
- **THEN** agent routes to existing modules:
  - Shells → `src/modules/exploit/payloads.rs`
  - PrivEsc → `src/modules/exploit/privesc.rs`
  - Lateral → `src/modules/exploit/lateral-movement.rs`

## ADDED CLI Routes

### Server Commands
```
rb server start [--port 8443]           # Start C2 server (uses existing HTTP server)
rb server clients list                  # List connected agents
rb server clients send <id> <command>   # Send command to agent
```

### Agent Commands
```
rb agent connect <server> [--interval 60] [--jitter 30]  # Connect to server
rb agent status                                           # Show connection status
```

## Leveraged Existing Modules

The agent architecture reuses these existing modules:

| Capability | Existing Module | Location |
|------------|-----------------|----------|
| HTTP Transport | HTTP Server | `src/modules/http_server/` |
| Session Encryption | ChaCha20-Poly1305 | `src/crypto/chacha20.rs` |
| Key Exchange | X25519 | `src/crypto/x25519.rs` |
| Integrity | HMAC-SHA256 | `src/crypto/hmac.rs` |
| Jitter | Evasion Config | `src/modules/evasion/network.rs` |
| Shells | Payloads | `src/modules/exploit/payloads.rs` |
| PrivEsc | PrivEsc Scanner | `src/modules/exploit/privesc.rs` |
| Lateral | Lateral Movement | `src/modules/exploit/lateral-movement.rs` |
